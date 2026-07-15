//! Canonical redb persistence for confirmed Deadcat chain state.
//!
//! Complete blocks are the physical commit unit. Every contract leg caused by
//! one Liquid transaction is represented by one [`ChainTxDelta`] and is
//! therefore applied atomically with its sibling legs. The append-only event
//! journal is deliberately excluded from reorg undo.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use deadcat_rpc::{RecoveryFamily, SnapshotScope, SyncStatus};
use deadcat_types::{
    BinaryMarketParams, BinaryMarketState, ChainAnchor, ChainPosition, ContractDeclaration,
    ContractDescriptor, ContractId, ContractKind, ContractSyncState, EventCursor, LiquidNetwork,
    MakerOrderParams, MakerOrderState, OrderDirection, OrderSide, RecoveryHintLocation,
};
use elements::hashes::Hash as _;
use elements::{AssetId, BlockHash, OutPoint, Transaction, TxOut, Txid, encode};
use rand::RngCore as _;
use redb::{
    Database, ReadTransaction, ReadableDatabase as _, ReadableTable, TableDefinition,
    WriteTransaction,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const SCHEMA_VERSION: u32 = 1;
pub const UNDO_RETENTION_BLOCKS: u32 = 2;
const RECORD_VERSION: u8 = 1;

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const CHAIN_TIP: TableDefinition<&str, &[u8]> = TableDefinition::new("chain_tip");
const BLOCKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("chain_checkpoints");
const TRANSACTIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("chain_transactions");
const OUTPUTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("outputs");
const CONTRACTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("contracts");
/// Explicit, chain-verified watch intent. Unlike `CONTRACTS`, these normalized
/// declarations survive rollback and destructive rebuild so canonical replay
/// can independently revalidate and rematerialize them.
const RETAINED_DECLARATIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("retained_contract_declarations");
const OUTPOINT_OWNERS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("outpoint_owners");
const CONTRACT_OUTPOINTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("contract_outpoints");
const SCRIPT_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("script_index");
const ASSET_RELATIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("asset_relations");
const MARKET_CHILDREN: TableDefinition<&[u8], &[u8]> = TableDefinition::new("market_children");
const ORDER_BOOK: TableDefinition<&[u8], &[u8]> = TableDefinition::new("order_book");
const RECOVERY_HINTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("recovery_hints");
const CONTRACT_HISTORY: TableDefinition<&[u8], &[u8]> = TableDefinition::new("contract_history");
const BACKFILL_PROGRESS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("backfill_progress");
const UNDO_BLOCKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("undo_transactions");
const EVENTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("events");

const SCHEMA_VERSION_KEY: &str = "schema_version";
const EVENT_EPOCH_KEY: &str = "event_epoch";
const EVENT_SEQUENCE_KEY: &str = "event_sequence";
const SYNC_STATUS_KEY: &str = "sync_status";
const CHAIN_IDENTITY_KEY: &str = "chain_identity";
const ACTIVATION_ANCHOR_KEY: &str = "v1_activation_anchor";
const TIP_KEY: &str = "tip";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainIdentity {
    pub network: LiquidNetwork,
    pub genesis_hash: BlockHash,
    pub policy_asset: AssetId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractParameters {
    BinaryMarket(BinaryMarketParams),
    MakerOrder(MakerOrderParams),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractState {
    BinaryMarket(BinaryMarketState),
    MakerOrder(MakerOrderState),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetRelationKind {
    Collateral,
    YesToken,
    NoToken,
    YesReissuanceToken,
    NoReissuanceToken,
    OrderBase,
    OrderQuote,
}

impl AssetRelationKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Collateral => 0,
            Self::YesToken => 1,
            Self::NoToken => 2,
            Self::YesReissuanceToken => 3,
            Self::NoReissuanceToken => 4,
            Self::OrderBase => 5,
            Self::OrderQuote => 6,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptBinding {
    pub role: u8,
    pub script_pubkey: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetBinding {
    pub asset_id: AssetId,
    pub relation: AssetRelationKind,
    pub role: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackedOutpoint {
    pub role: u8,
    pub outpoint: OutPoint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderBookEntry {
    pub market_id: ContractId,
    pub side: OrderSide,
    pub direction: OrderDirection,
    pub price: u32,
    pub creation_position: ChainPosition,
    pub remaining_base: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractRecord {
    pub contract_id: ContractId,
    pub kind: ContractKind,
    pub params: ContractParameters,
    pub creation_position: ChainPosition,
    pub state: ContractState,
    pub sync_state: ContractSyncState,
    pub parent_market: Option<ContractId>,
    pub outcome_side: Option<OrderSide>,
    pub scripts: Vec<ScriptBinding>,
    pub assets: Vec<AssetBinding>,
    pub outpoints: Vec<TrackedOutpoint>,
    pub order_book: Option<OrderBookEntry>,
}

impl ContractRecord {
    fn validate(&self) -> Result<(), StoreError> {
        let shape_valid = matches!(
            (&self.params, self.state, self.kind),
            (
                ContractParameters::BinaryMarket(_),
                ContractState::BinaryMarket(_),
                ContractKind::BinaryMarketV1
            ) | (
                ContractParameters::MakerOrder(_),
                ContractState::MakerOrder(_),
                ContractKind::MakerOrderV1
            )
        );
        if !shape_valid {
            return Err(StoreError::InvalidContract(
                "kind, parameters, and state variants disagree".to_owned(),
            ));
        }
        let mut roles = HashSet::new();
        let mut outpoints = HashSet::new();
        for tracked in &self.outpoints {
            if !roles.insert(tracked.role) || !outpoints.insert(tracked.outpoint) {
                return Err(StoreError::InvalidContract(
                    "duplicate outpoint role or outpoint".to_owned(),
                ));
            }
        }
        let mut script_roles = HashSet::new();
        let mut script_hashes = HashSet::new();
        for script in &self.scripts {
            if !script_roles.insert(script.role)
                || !script_hashes.insert(script_hash(&script.script_pubkey))
            {
                return Err(StoreError::InvalidContract(
                    "duplicate script role or script".to_owned(),
                ));
            }
        }
        match (
            self.kind,
            self.parent_market,
            self.outcome_side,
            self.order_book,
            self.state,
            &self.params,
        ) {
            (
                ContractKind::BinaryMarketV1,
                None,
                None,
                None,
                ContractState::BinaryMarket(_),
                ContractParameters::BinaryMarket(_),
            ) => {}
            (
                ContractKind::MakerOrderV1,
                Some(parent),
                Some(side),
                Some(book),
                ContractState::MakerOrder(MakerOrderState::Active { remaining_base, .. }),
                ContractParameters::MakerOrder(params),
            ) if parent == book.market_id
                && side == book.side
                && remaining_base == book.remaining_base
                && params.price == book.price
                && params.direction == book.direction => {}
            (
                ContractKind::MakerOrderV1,
                Some(_),
                Some(_),
                None,
                ContractState::MakerOrder(MakerOrderState::Consumed | MakerOrderState::Cancelled),
                ContractParameters::MakerOrder(_),
            ) => {}
            (ContractKind::LmsrV1Reserved, _, _, _, _, _) => {
                return Err(StoreError::InvalidContract(
                    "reserved LMSR contracts cannot be stored in v1".to_owned(),
                ));
            }
            _ => {
                return Err(StoreError::InvalidContract(
                    "parent/order-book metadata disagrees with contract state".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionRecord {
    /// Versioned interpreter-defined transition tag.
    pub kind: u16,
    /// Versioned typed transition payload.
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateUpdate {
    pub contract_id: ContractId,
    pub old_state: ContractState,
    pub new_state: ContractState,
    pub spent_outpoints: Vec<OutPoint>,
    pub new_outpoints: Vec<TrackedOutpoint>,
    /// Required for an active order, absent for markets and terminal orders.
    pub order_remaining_base: Option<u64>,
    pub transition: TransitionRecord,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainTxDelta {
    pub position: ChainPosition,
    pub block_hash: BlockHash,
    pub txid: Txid,
    pub raw_tx: Transaction,
    pub created_contracts: Vec<ContractRecord>,
    pub state_updates: Vec<StateUpdate>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryHintDelta {
    pub location: RecoveryHintLocation,
    pub creation_txid: Txid,
    pub family: RecoveryFamily,
    pub payload: Vec<u8>,
    pub associated_contract: Option<ContractId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockDelta {
    pub anchor: ChainAnchor,
    pub prev_block_hash: BlockHash,
    pub ordered_txids: Vec<Txid>,
    pub relevant_transactions: Vec<ChainTxDelta>,
    pub recovery_hints: Vec<RecoveryHintDelta>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBlock {
    pub anchor: ChainAnchor,
    pub prev_block_hash: BlockHash,
    pub ordered_txids: Vec<Txid>,
    pub delta_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredTransaction {
    pub position: ChainPosition,
    pub block_hash: BlockHash,
    pub txid: Txid,
    /// Consensus serialization, including transaction witness data.
    pub raw_tx: Vec<u8>,
    pub affected_contract_ids: Vec<ContractId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredOutput {
    pub position: ChainPosition,
    pub outpoint: OutPoint,
    pub output: TxOut,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredOutputRef {
    position: ChainPosition,
    outpoint: OutPoint,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRecoveryHint {
    pub location: RecoveryHintLocation,
    pub creation_txid: Txid,
    pub family: RecoveryFamily,
    pub payload: Vec<u8>,
    pub associated_contract: Option<ContractId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredHistoryEntry {
    pub position: ChainPosition,
    pub txid: Txid,
    pub old_state: ContractState,
    pub new_state: ContractState,
    pub transition: TransitionRecord,
}

/// Durable scan cursor for a verified contract that was registered after its
/// creation block had already been indexed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackfillProgress {
    pub contract_id: ContractId,
    /// Tip observed when the current catch-up range was pinned. If the indexed
    /// tip advances, the final block application extends this pin before the
    /// contract can become ready.
    pub pinned_tip: ChainAnchor,
    /// First transaction that has not yet been replayed. A zero transaction
    /// index denotes the beginning of the next block.
    pub next_position: ChainPosition,
    /// Digest of the last atomically applied backfill block, retained to make
    /// exact retries idempotent across caller restarts.
    pub last_applied: Option<(ChainAnchor, [u8; 32])>,
}

/// Canonical creation evidence persisted with a late registration. Keeping the
/// full transaction makes every initial live output recoverable even when the
/// transaction had been irrelevant before registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationEvidence {
    pub anchor: ChainAnchor,
    /// Shared canonical creation transaction. A composed package may register
    /// several contracts from the same transaction without cloning its full
    /// allocation once per declaration.
    pub transaction: Arc<Transaction>,
    /// Advisory recovery metadata only. Contract validity never depends on a
    /// hint being present, unique, or unclaimed in the local hint index.
    pub associated_hint: Option<RecoveryHintLocation>,
}

/// Canonical transaction evidence shared by every registration at one chain
/// position. The serialized bytes and output references are checked and
/// persisted once for the whole group, regardless of how many composed
/// contracts the transaction creates.
struct RegistrationTransactionGroup {
    position: ChainPosition,
    anchor: ChainAnchor,
    transaction: Arc<Transaction>,
    txid: Txid,
    raw_tx: Vec<u8>,
    output_count: u32,
    existing_contract_ids: Vec<ContractId>,
    new_contract_ids: Vec<ContractId>,
}

/// Per-input result from an atomic registration batch. Existing idempotent
/// registrations return their current materialized record rather than the
/// caller's initial `CatchingUp` proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractRegistrationResult {
    pub record: ContractRecord,
    pub inserted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreSnapshotMetadata {
    pub as_of: ChainAnchor,
    pub event_high_watermark: EventCursor,
}

/// One atomic view of the persisted metadata used by status and subscription
/// RPCs. Reading these fields together prevents reporting combinations that
/// never existed across rollback or rebuild-epoch commits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreStatusSnapshot {
    pub indexed_tip: ChainAnchor,
    pub activation_anchor: ChainAnchor,
    pub sync_status: SyncStatus,
    pub event_high_watermark: EventCursor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreSnapshotCursor {
    pub as_of: ChainAnchor,
    pub event_high_watermark: EventCursor,
    pub scope: SnapshotScope,
    pub after_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterializedPage<T> {
    pub snapshot: StoreSnapshotMetadata,
    pub items: Vec<T>,
    pub next: Option<StoreSnapshotCursor>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterializedOrder {
    pub contract: ContractRecord,
    pub entry: OrderBookEntry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssetRelationRecord {
    pub contract_id: ContractId,
    pub binding: AssetBinding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutpointOwner {
    pub contract_id: ContractId,
    pub role: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoredEvent {
    ContractRegistered {
        contract_id: ContractId,
    },
    TransactionApplied {
        anchor: ChainAnchor,
        txid: Txid,
        position: ChainPosition,
        affected_contract_ids: Vec<ContractId>,
        affected_market_ids: Vec<ContractId>,
    },
    BackfillApplied {
        contract_id: ContractId,
        through: ChainAnchor,
        transition_count: u32,
    },
    ContractReady {
        contract_id: ContractId,
        through: ChainAnchor,
    },
    ChainRolledBack {
        old_tip: ChainAnchor,
        new_tip: ChainAnchor,
        orphaned_positions: Vec<ChainPosition>,
        affected_contract_ids: Vec<ContractId>,
        affected_market_ids: Vec<ContractId>,
    },
    SyncStatusChanged {
        status: SyncStatus,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredEventEnvelope {
    pub cursor: EventCursor,
    pub event: StoredEvent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ContractUndo {
    contract_id: ContractId,
    before: Option<ContractRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct UndoBlock {
    previous_tip: ChainAnchor,
    contract_changes: Vec<ContractUndo>,
    transaction_positions: Vec<ChainPosition>,
    output_outpoints: Vec<OutPoint>,
    history_keys: Vec<(ContractId, ChainPosition)>,
    recovery_locations: Vec<RecoveryHintLocation>,
    backfill_progress_changes: Vec<BackfillProgressUndo>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct BackfillProgressUndo {
    contract_id: ContractId,
    before: Option<BackfillProgress>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyBlockResult {
    pub applied: bool,
    pub new_tip: ChainAnchor,
    pub event_high_watermark: EventCursor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RollbackResult {
    Noop {
        tip: ChainAnchor,
    },
    RolledBack {
        old_tip: ChainAnchor,
        new_tip: ChainAnchor,
        orphaned_positions: Vec<ChainPosition>,
        event_high_watermark: EventCursor,
    },
    RebuildRequired {
        old_tip: ChainAnchor,
        requested_ancestor: ChainAnchor,
        new_event_epoch: [u8; 16],
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyBackfillResult {
    pub applied: bool,
    pub through: ChainAnchor,
    pub ready_contracts: Vec<ContractId>,
    pub event_high_watermark: EventCursor,
}

pub struct Store {
    database: Database,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let database = Database::create(path)?;
        let store = Self { database };
        store.initialize_schema()?;
        Ok(store)
    }

    pub fn schema_version(&self) -> Result<u32, StoreError> {
        let read = self.database.begin_read()?;
        let table = read.open_table(META)?;
        let value = table
            .get(SCHEMA_VERSION_KEY)?
            .ok_or(StoreError::MissingMetadata(SCHEMA_VERSION_KEY))?;
        decode_u32(value.value()).map_err(|_| StoreError::CorruptSchemaVersion)
    }

    #[cfg(test)]
    fn bind_chain(&self, identity: ChainIdentity) -> Result<(), StoreError> {
        let write = self.database.begin_write()?;
        {
            let mut meta = write.open_table(META)?;
            let existing = meta
                .get(CHAIN_IDENTITY_KEY)?
                .map(|value| value.value().to_vec());
            match existing {
                Some(value) => {
                    let actual: ChainIdentity = decode_record(&value)?;
                    if actual != identity {
                        return Err(StoreError::ChainIdentityMismatch {
                            expected: Box::new(actual),
                            actual: Box::new(identity),
                        });
                    }
                }
                None => {
                    let encoded = encode_record(&identity)?;
                    meta.insert(CHAIN_IDENTITY_KEY, encoded.as_slice())?;
                }
            }
        }
        write.commit()?;
        Ok(())
    }

    pub fn chain_identity(&self) -> Result<Option<ChainIdentity>, StoreError> {
        self.read_meta_record(CHAIN_IDENTITY_KEY)
    }

    /// Atomically bind a fresh database to one chain and immutable v1
    /// activation checkpoint, or verify an existing binding exactly.
    pub fn initialize_chain(
        &self,
        identity: ChainIdentity,
        activation_anchor: ChainAnchor,
    ) -> Result<(), StoreError> {
        let write = self.database.begin_write()?;
        let existing_identity =
            read_meta_record_from_write::<ChainIdentity>(&write, CHAIN_IDENTITY_KEY)?;
        let existing_activation =
            read_meta_record_from_write::<ChainAnchor>(&write, ACTIVATION_ANCHOR_KEY)?;
        let existing_tip = tip_from_write(&write)?;

        match (existing_identity, existing_activation, existing_tip) {
            (None, None, None) => {
                write_meta_record(&write, CHAIN_IDENTITY_KEY, &identity)?;
                write_meta_record(&write, ACTIVATION_ANCHOR_KEY, &activation_anchor)?;
                write_tip(&write, activation_anchor)?;
            }
            (Some(actual_identity), Some(actual_activation), Some(tip)) => {
                if actual_identity != identity {
                    return Err(StoreError::ChainIdentityMismatch {
                        expected: Box::new(actual_identity),
                        actual: Box::new(identity),
                    });
                }
                if actual_activation != activation_anchor {
                    return Err(StoreError::ActivationAnchorMismatch {
                        expected: actual_activation,
                        actual: activation_anchor,
                    });
                }
                if tip.height < activation_anchor.height {
                    return Err(StoreError::TipBeforeActivation {
                        tip,
                        activation: activation_anchor,
                    });
                }
                let canonical = canonical_anchor_from_write(&write, activation_anchor.height)?;
                if canonical != Some(activation_anchor) {
                    return Err(StoreError::ActivationAnchorNotCanonical {
                        expected: activation_anchor,
                        actual: canonical,
                    });
                }
            }
            _ => return Err(StoreError::IncompleteChainConfiguration),
        }
        write.commit()?;
        Ok(())
    }

    pub fn activation_anchor(&self) -> Result<Option<ChainAnchor>, StoreError> {
        self.read_meta_record(ACTIVATION_ANCHOR_KEY)
    }

    /// Low-level fixture initializer. Production code must atomically bind
    /// chain identity, activation, and tip through `initialize_chain`.
    #[cfg(test)]
    pub(crate) fn initialize_tip(&self, anchor: ChainAnchor) -> Result<(), StoreError> {
        let write = self.database.begin_write()?;
        {
            let mut tips = write.open_table(CHAIN_TIP)?;
            let existing = tips.get(TIP_KEY)?.map(|value| value.value().to_vec());
            match existing {
                Some(value) => {
                    let current: ChainAnchor = decode_record(&value)?;
                    if current != anchor {
                        return Err(StoreError::TipAlreadyInitialized {
                            current,
                            requested: anchor,
                        });
                    }
                }
                None => {
                    let encoded = encode_record(&anchor)?;
                    tips.insert(TIP_KEY, encoded.as_slice())?;
                }
            }
        }
        write.commit()?;
        Ok(())
    }

    pub fn tip(&self) -> Result<Option<ChainAnchor>, StoreError> {
        let read = self.database.begin_read()?;
        let table = read.open_table(CHAIN_TIP)?;
        table
            .get(TIP_KEY)?
            .map(|value| decode_record(value.value()))
            .transpose()
    }

    pub fn sync_status(&self) -> Result<SyncStatus, StoreError> {
        self.read_meta_record(SYNC_STATUS_KEY)?
            .ok_or(StoreError::MissingMetadata(SYNC_STATUS_KEY))
    }

    pub fn set_sync_status(&self, status: SyncStatus) -> Result<EventCursor, StoreError> {
        let write = self.database.begin_write()?;
        let current = read_meta_record_from_write::<SyncStatus>(&write, SYNC_STATUS_KEY)?
            .ok_or(StoreError::MissingMetadata(SYNC_STATUS_KEY))?;
        if status == SyncStatus::RescanRequired {
            mark_rebuild_required(&write)?;
            let cursor = high_watermark_from_write(&write)?;
            write.commit()?;
            return Ok(cursor);
        }
        if current == SyncStatus::RescanRequired {
            return Err(StoreError::RebuildRequired);
        }
        if current != status {
            write_meta_record(&write, SYNC_STATUS_KEY, &status)?;
            append_event(&write, StoredEvent::SyncStatusChanged { status })?;
        }
        let cursor = high_watermark_from_write(&write)?;
        write.commit()?;
        Ok(cursor)
    }

    pub fn event_high_watermark(&self) -> Result<EventCursor, StoreError> {
        let read = self.database.begin_read()?;
        let meta = read.open_table(META)?;
        event_cursor_from_meta(&meta)
    }

    pub fn status_snapshot(&self) -> Result<StoreStatusSnapshot, StoreError> {
        let read = self.database.begin_read()?;
        status_snapshot_from_read(&read)
    }

    /// Atomically capture the subscription boundary and validate a supplied
    /// cursor against that exact epoch/high-watermark snapshot.
    pub fn subscription_snapshot(
        &self,
        after: Option<EventCursor>,
    ) -> Result<StoreStatusSnapshot, StoreError> {
        let read = self.database.begin_read()?;
        let snapshot = status_snapshot_from_read(&read)?;
        validate_event_cursor(after, snapshot.event_high_watermark)?;
        Ok(snapshot)
    }

    pub fn events_after(
        &self,
        after: Option<EventCursor>,
        limit: usize,
    ) -> Result<Vec<StoredEventEnvelope>, StoreError> {
        let read = self.database.begin_read()?;
        let meta = read.open_table(META)?;
        let high = event_cursor_from_meta(&meta)?;
        let after_sequence = validate_event_cursor(after, high)?;
        let table = read.open_table(EVENTS)?;
        let mut events = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let key: [u8; 24] = key
                .value()
                .try_into()
                .map_err(|_| StoreError::CorruptIndexKey("events"))?;
            if key[..16] != high.epoch
                || u64::from_be_bytes(
                    key[16..]
                        .try_into()
                        .map_err(|_| StoreError::CorruptIndexKey("events"))?,
                ) <= after_sequence
            {
                continue;
            }
            events.push(decode_record(value.value())?);
            if events.len() == limit {
                break;
            }
        }
        Ok(events)
    }

    pub fn block(&self, height: u32) -> Result<Option<StoredBlock>, StoreError> {
        self.read_fixed(BLOCKS, &height.to_be_bytes())
    }

    pub fn transaction(
        &self,
        position: ChainPosition,
    ) -> Result<Option<StoredTransaction>, StoreError> {
        self.read_fixed(TRANSACTIONS, &position.to_fixed_key())
    }

    pub fn output(&self, outpoint: OutPoint) -> Result<Option<StoredOutput>, StoreError> {
        let Some(reference) =
            self.read_fixed::<StoredOutputRef, 36>(OUTPUTS, &outpoint_fixed_key(outpoint))?
        else {
            return Ok(None);
        };
        let transaction = self
            .transaction(reference.position)?
            .ok_or(StoreError::MissingOutputTransaction(reference.position))?;
        let decoded: Transaction = encode::deserialize(&transaction.raw_tx)
            .map_err(|error| StoreError::ConsensusDecode(error.to_string()))?;
        let output = decoded
            .output
            .get(usize::try_from(outpoint.vout).map_err(|_| {
                StoreError::ConsensusDecode("output index does not fit usize".to_owned())
            })?)
            .cloned()
            .ok_or(StoreError::MissingOutput(outpoint))?;
        Ok(Some(StoredOutput {
            position: reference.position,
            outpoint,
            output,
        }))
    }

    pub fn contract(&self, contract_id: ContractId) -> Result<Option<ContractRecord>, StoreError> {
        let read = self.database.begin_read()?;
        let snapshot = snapshot_from_read(&read)?;
        let table = read.open_table(CONTRACTS)?;
        table
            .get(contract_id.to_fixed_key().as_slice())?
            .map(|value| {
                let mut record: ContractRecord = decode_record(value.value())?;
                normalize_ready_anchor(&mut record, snapshot.as_of);
                Ok(record)
            })
            .transpose()
    }

    /// Return the normalized declaration retained as explicit watch intent for
    /// one contract. This registry is independent of canonical materialized
    /// state and therefore remains available while a rebuild is in progress.
    pub fn retained_declaration(
        &self,
        contract_id: ContractId,
    ) -> Result<Option<ContractDeclaration>, StoreError> {
        self.read_fixed(RETAINED_DECLARATIONS, &contract_id.to_fixed_key())
    }

    /// Return every explicitly retained contract anchored in `txid`, ordered
    /// by output index. The fixed-key layout makes this a bounded prefix scan
    /// rather than a walk over the complete watch registry.
    pub fn retained_declarations_for_txid(
        &self,
        txid: Txid,
    ) -> Result<Vec<ContractDeclaration>, StoreError> {
        let mut first = [0_u8; 36];
        first[..32].copy_from_slice(&txid.to_byte_array());
        let mut last = first;
        last[32..].copy_from_slice(&u32::MAX.to_be_bytes());

        let read = self.database.begin_read()?;
        let table = read.open_table(RETAINED_DECLARATIONS)?;
        let mut declarations = Vec::new();
        for entry in table.range(first.as_slice()..=last.as_slice())? {
            let (_, value) = entry?;
            declarations.push(decode_record(value.value())?);
        }
        Ok(declarations)
    }

    /// Prefetch retained declarations for one complete canonical block while
    /// holding a single redb read transaction/table handle. An empty registry
    /// returns before performing any per-txid tree seeks.
    pub fn retained_declarations_for_transactions(
        &self,
        txids: &[Txid],
    ) -> Result<HashMap<Txid, Vec<ContractDeclaration>>, StoreError> {
        let read = self.database.begin_read()?;
        let table = read.open_table(RETAINED_DECLARATIONS)?;
        if table.iter()?.next().transpose()?.is_none() {
            return Ok(HashMap::new());
        }

        let mut result = HashMap::new();
        for txid in txids {
            let mut first = [0_u8; 36];
            first[..32].copy_from_slice(&txid.to_byte_array());
            let mut last = first;
            last[32..].copy_from_slice(&u32::MAX.to_be_bytes());
            let mut declarations = Vec::new();
            for entry in table.range(first.as_slice()..=last.as_slice())? {
                let (_, value) = entry?;
                declarations.push(decode_record(value.value())?);
            }
            if !declarations.is_empty() {
                result.insert(*txid, declarations);
            }
        }
        Ok(result)
    }

    /// Return the canonical anchor retained for `height`, including the
    /// initialization baseline that does not have a full block row.
    pub fn canonical_anchor(&self, height: u32) -> Result<Option<ChainAnchor>, StoreError> {
        let read = self.database.begin_read()?;
        let tip_table = read.open_table(CHAIN_TIP)?;
        let Some(tip) = tip_table
            .get(TIP_KEY)?
            .map(|value| decode_record::<ChainAnchor>(value.value()))
            .transpose()?
        else {
            return Ok(None);
        };
        if height > tip.height {
            return Ok(None);
        }
        if height == tip.height {
            return Ok(Some(tip));
        }
        let blocks = read.open_table(BLOCKS)?;
        if let Some(block) = blocks.get(height.to_be_bytes().as_slice())? {
            return Ok(Some(decode_record::<StoredBlock>(block.value())?.anchor));
        }
        let Some(next_height) = height.checked_add(1) else {
            return Ok(None);
        };
        blocks
            .get(next_height.to_be_bytes().as_slice())?
            .map(|value| {
                let next = decode_record::<StoredBlock>(value.value())?;
                Ok(ChainAnchor {
                    height,
                    hash: next.prev_block_hash,
                })
            })
            .transpose()
    }

    pub fn backfill_progress(
        &self,
        contract_id: ContractId,
    ) -> Result<Option<BackfillProgress>, StoreError> {
        self.read_fixed(BACKFILL_PROGRESS, &contract_id.to_fixed_key())
    }

    /// Catching-up contracts in deterministic scan-position/contract order.
    pub fn pending_backfills(&self) -> Result<Vec<BackfillProgress>, StoreError> {
        let read = self.database.begin_read()?;
        let contracts = read.open_table(CONTRACTS)?;
        let progress = read.open_table(BACKFILL_PROGRESS)?;
        let mut pending: Vec<BackfillProgress> = Vec::new();
        for entry in contracts.iter()? {
            let (_, value) = entry?;
            let contract: ContractRecord = decode_record(value.value())?;
            if !matches!(contract.sync_state, ContractSyncState::CatchingUp { .. }) {
                continue;
            }
            let key = contract.contract_id.to_fixed_key();
            let value = progress
                .get(key.as_slice())?
                .ok_or(StoreError::MissingBackfillProgress(contract.contract_id))?;
            pending.push(decode_record(value.value())?);
        }
        pending.sort_by_key(|item| (item.next_position, item.contract_id.to_fixed_key()));
        Ok(pending)
    }

    /// Read the indexed tip and durable-event watermark from one redb snapshot.
    pub fn snapshot_metadata(&self) -> Result<StoreSnapshotMetadata, StoreError> {
        let read = self.database.begin_read()?;
        snapshot_from_read(&read)
    }

    /// Return a contract and its materialized parameters/state/live outpoints
    /// together with the exact snapshot at which it was read.
    pub fn contract_snapshot(
        &self,
        contract_id: ContractId,
    ) -> Result<(StoreSnapshotMetadata, Option<ContractRecord>), StoreError> {
        let read = self.database.begin_read()?;
        let snapshot = snapshot_from_read(&read)?;
        let table = read.open_table(CONTRACTS)?;
        let mut contract = table
            .get(contract_id.to_fixed_key().as_slice())?
            .map(|value| decode_record(value.value()))
            .transpose()?;
        if let Some(contract) = contract.as_mut() {
            normalize_ready_anchor(contract, snapshot.as_of);
        }
        Ok((snapshot, contract))
    }

    /// Page ready binary markets by stable `ContractId` key.
    pub fn ready_markets(
        &self,
        cursor: Option<&StoreSnapshotCursor>,
        limit: usize,
    ) -> Result<MaterializedPage<ContractRecord>, StoreError> {
        validate_query_limit(limit)?;
        let read = self.database.begin_read()?;
        let snapshot = snapshot_from_read(&read)?;
        let scope = SnapshotScope::Markets;
        validate_snapshot_cursor(cursor, snapshot, scope, 36)?;
        let after = cursor.map(|cursor| cursor.after_key.as_slice());
        let table = read.open_table(CONTRACTS)?;
        let mut rows = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let key = key.value();
            if after.is_some_and(|after| key <= after) {
                continue;
            }
            let record: ContractRecord = decode_record(value.value())?;
            if record.kind == ContractKind::BinaryMarketV1
                && matches!(record.sync_state, ContractSyncState::Ready { .. })
            {
                let mut record = record;
                normalize_ready_anchor(&mut record, snapshot.as_of);
                rows.push((key.to_vec(), record));
                if rows.len() > limit {
                    break;
                }
            }
        }
        materialized_page(snapshot, scope, rows, limit)
    }

    /// Page active ready maker orders in exact order-book key order.
    pub fn ready_orders(
        &self,
        market_id: ContractId,
        side: Option<OrderSide>,
        direction: Option<OrderDirection>,
        cursor: Option<&StoreSnapshotCursor>,
        limit: usize,
    ) -> Result<MaterializedPage<MaterializedOrder>, StoreError> {
        validate_query_limit(limit)?;
        let read = self.database.begin_read()?;
        let snapshot = snapshot_from_read(&read)?;
        let scope = SnapshotScope::Orders {
            market_id,
            side,
            direction,
        };
        validate_snapshot_cursor(cursor, snapshot, scope, 86)?;
        let after = cursor.map(|cursor| cursor.after_key.as_slice());
        let contracts = read.open_table(CONTRACTS)?;
        let mut market = contracts
            .get(market_id.to_fixed_key().as_slice())?
            .map(|value| decode_record::<ContractRecord>(value.value()))
            .transpose()?
            .ok_or(StoreError::MaterializedMarketNotFound(market_id))?;
        if market.kind != ContractKind::BinaryMarketV1 {
            return Err(StoreError::MaterializedContractIsNotMarket(market_id));
        }
        if !matches!(market.sync_state, ContractSyncState::Ready { .. }) {
            return Err(StoreError::MaterializedMarketNotReady(market_id));
        }
        normalize_ready_anchor(&mut market, snapshot.as_of);
        let table = read.open_table(ORDER_BOOK)?;
        let mut rows = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let key = key.value();
            if after.is_some_and(|after| key <= after) {
                continue;
            }
            let entry: OrderBookEntry = decode_record(value.value())?;
            if entry.market_id != market_id
                || side.is_some_and(|side| entry.side != side)
                || direction.is_some_and(|direction| entry.direction != direction)
            {
                continue;
            }
            let key_array: [u8; 86] = key
                .try_into()
                .map_err(|_| StoreError::CorruptIndexKey("order_book"))?;
            let contract_id = decode_contract_key(&key_array[50..])?;
            let Some(contract) = contracts.get(contract_id.to_fixed_key().as_slice())? else {
                return Err(StoreError::CorruptMaterializedIndex("order_book"));
            };
            let mut contract: ContractRecord = decode_record(contract.value())?;
            if !matches!(contract.sync_state, ContractSyncState::Ready { .. }) {
                continue;
            }
            normalize_ready_anchor(&mut contract, snapshot.as_of);
            rows.push((key.to_vec(), MaterializedOrder { contract, entry }));
            if rows.len() > limit {
                break;
            }
        }
        materialized_page(snapshot, scope, rows, limit)
    }

    /// Return the complete ready book in deterministic key order. Callers can
    /// split asks/bids without rebuilding contract state.
    pub fn order_book_entries(
        &self,
        market_id: ContractId,
    ) -> Result<
        (
            StoreSnapshotMetadata,
            Option<ContractRecord>,
            Vec<MaterializedOrder>,
        ),
        StoreError,
    > {
        let read = self.database.begin_read()?;
        let snapshot = snapshot_from_read(&read)?;
        let contracts = read.open_table(CONTRACTS)?;
        let mut market = contracts
            .get(market_id.to_fixed_key().as_slice())?
            .map(|value| decode_record(value.value()))
            .transpose()?;
        if let Some(market) = market.as_mut() {
            normalize_ready_anchor(market, snapshot.as_of);
        }
        let table = read.open_table(ORDER_BOOK)?;
        let mut orders = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let book: OrderBookEntry = decode_record(value.value())?;
            if book.market_id != market_id {
                continue;
            }
            let key: [u8; 86] = key
                .value()
                .try_into()
                .map_err(|_| StoreError::CorruptIndexKey("order_book"))?;
            let contract_id = decode_contract_key(&key[50..])?;
            let Some(contract) = contracts.get(contract_id.to_fixed_key().as_slice())? else {
                return Err(StoreError::CorruptMaterializedIndex("order_book"));
            };
            let mut contract: ContractRecord = decode_record(contract.value())?;
            if matches!(contract.sync_state, ContractSyncState::Ready { .. }) {
                normalize_ready_anchor(&mut contract, snapshot.as_of);
                orders.push(MaterializedOrder {
                    contract,
                    entry: book,
                });
            }
        }
        Ok((snapshot, market, orders))
    }

    /// Page public recovery hints by canonical chain/output location. A
    /// continuation is valid only while both the exact indexed tip and durable
    /// event watermark still match the snapshot that produced it.
    pub fn scan_recovery_hints(
        &self,
        family: Option<RecoveryFamily>,
        cursor: Option<&StoreSnapshotCursor>,
        limit: usize,
    ) -> Result<MaterializedPage<StoredRecoveryHint>, StoreError> {
        validate_query_limit(limit)?;
        let read = self.database.begin_read()?;
        let snapshot = snapshot_from_read(&read)?;
        let scope = SnapshotScope::RecoveryHints { family };
        validate_snapshot_cursor(cursor, snapshot, scope, 12)?;
        let after = cursor.map(|cursor| cursor.after_key.as_slice());
        let table = read.open_table(RECOVERY_HINTS)?;
        let mut rows = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let key: [u8; 12] = key
                .value()
                .try_into()
                .map_err(|_| StoreError::CorruptIndexKey("recovery_hints"))?;
            if after.is_some_and(|after| key.as_slice() <= after) {
                continue;
            }
            let hint: StoredRecoveryHint = decode_record(value.value())?;
            if family.is_none_or(|family| hint.family == family) {
                rows.push((key.to_vec(), hint));
                if rows.len() > limit {
                    break;
                }
            }
        }
        materialized_page(snapshot, scope, rows, limit)
    }

    pub fn asset_relations(
        &self,
        asset_id: AssetId,
    ) -> Result<(StoreSnapshotMetadata, Vec<AssetRelationRecord>), StoreError> {
        let read = self.database.begin_read()?;
        let snapshot = snapshot_from_read(&read)?;
        let table = read.open_table(ASSET_RELATIONS)?;
        let wanted = asset_id.into_inner().to_byte_array();
        let mut relations = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let key: [u8; 70] = key
                .value()
                .try_into()
                .map_err(|_| StoreError::CorruptIndexKey("asset_relations"))?;
            if key[..32] != wanted {
                continue;
            }
            relations.push(AssetRelationRecord {
                contract_id: decode_contract_key(&key[33..69])?,
                binding: decode_record(value.value())?,
            });
        }
        Ok((snapshot, relations))
    }

    /// Persist one fully chain-verified late registration. This compatibility
    /// wrapper delegates to the atomic batch path.
    pub fn register_contract(
        &self,
        record: &ContractRecord,
        evidence: &RegistrationEvidence,
    ) -> Result<bool, StoreError> {
        let mut results = self.register_contracts(&[(record.clone(), evidence.clone())])?;
        Ok(results
            .pop()
            .expect("a one-item registration batch returns one result")
            .inserted)
    }

    /// Atomically persist a nonempty batch of fully chain-verified late
    /// registrations. Every input is preflighted before any table is mutated;
    /// one conflict aborts the entire batch. Results retain input order.
    pub fn register_contracts(
        &self,
        registrations: &[(ContractRecord, RegistrationEvidence)],
    ) -> Result<Vec<ContractRegistrationResult>, StoreError> {
        if registrations.is_empty() {
            return Err(StoreError::InvalidRegistrationEvidence(
                "registration batch has no contracts".to_owned(),
            ));
        }

        let mut contract_ids = HashSet::with_capacity(registrations.len());
        for (record, _) in registrations {
            record.validate()?;
            if !contract_ids.insert(record.contract_id) {
                return Err(StoreError::InvalidRegistrationEvidence(
                    "registration batch contains a duplicate contract ID".to_owned(),
                ));
            }
            if !matches!(record.sync_state, ContractSyncState::CatchingUp { .. }) {
                return Err(StoreError::InvalidContract(
                    "late registration must begin in CatchingUp state".to_owned(),
                ));
            }
        }
        let retained_declarations = registrations
            .iter()
            .map(|(record, _)| declaration_from_record(record))
            .collect::<Result<Vec<_>, _>>()?;

        let write = self.database.begin_write()?;
        // A rebuild invalidates every chain-derived view. Registration must
        // obey the same write barrier as canonical and backfill application;
        // otherwise a late-registration row could be committed against state
        // that reset_for_rebuild is about to discard.
        if read_meta_record_from_write::<SyncStatus>(&write, SYNC_STATUS_KEY)?
            == Some(SyncStatus::RescanRequired)
        {
            return Err(StoreError::RebuildRequired);
        }
        let activation = read_meta_record_from_write::<ChainAnchor>(&write, ACTIVATION_ANCHOR_KEY)?;
        // Some low-level unit fixtures intentionally use the test-only tip
        // initializer. No non-test build can create such a store.
        if activation.is_none() && !cfg!(test) {
            return Err(StoreError::ActivationNotInitialized);
        }
        if let Some(activation) = activation
            && registrations
                .iter()
                .any(|(record, _)| record.creation_position.block_height <= activation.height)
        {
            return Err(StoreError::PreActivationContract { activation });
        }
        for declaration in &retained_declarations {
            if let Some(existing) = read_fixed_from_write::<ContractDeclaration, 36>(
                &write,
                RETAINED_DECLARATIONS,
                &declaration.contract_id.to_fixed_key(),
            )? && existing != *declaration
            {
                return Err(StoreError::InvalidRegistrationEvidence(format!(
                    "retained declaration conflicts for {}",
                    declaration.contract_id
                )));
            }
        }
        let tip = tip_from_write(&write)?.ok_or(StoreError::TipNotInitialized)?;
        let mut existing_records = HashMap::<ContractId, ContractRecord>::new();
        let mut new_progress = HashMap::<ContractId, BackfillProgress>::new();
        let mut proposed_owners = HashMap::<OutPoint, ContractId>::new();
        let mut claimed_hint_locations = HashSet::<RecoveryHintLocation>::new();
        let mut ambiguous_hint_locations = HashSet::<RecoveryHintLocation>::new();
        let mut transaction_groups = Vec::<RegistrationTransactionGroup>::new();
        let mut group_at_position = HashMap::<ChainPosition, usize>::new();
        let mut position_for_txid = HashMap::<Txid, ChainPosition>::new();

        // Preflight the complete batch. The evidence maps additionally prove
        // that contracts sharing a creation transaction agree on its exact
        // bytes and canonical position.
        for (record, evidence) in registrations {
            let ContractSyncState::CatchingUp { synced_through } = record.sync_state else {
                unreachable!("registration state was checked above")
            };
            if record.creation_position.block_height > tip.height {
                return Err(StoreError::InvalidContract(
                    "contract creation is above the indexed tip".to_owned(),
                ));
            }
            if evidence.anchor != synced_through
                || synced_through.height != record.creation_position.block_height
                || canonical_anchor_from_write(&write, synced_through.height)?
                    != Some(synced_through)
            {
                return Err(StoreError::InvalidContract(
                    "contract creation anchor is not canonical in the indexed chain".to_owned(),
                ));
            }
            let group_index = if let Some(group_index) =
                group_at_position.get(&record.creation_position).copied()
            {
                let group = &transaction_groups[group_index];
                if group.anchor != evidence.anchor
                    || (!Arc::ptr_eq(&group.transaction, &evidence.transaction)
                        && group.raw_tx != encode::serialize(evidence.transaction.as_ref()))
                {
                    return Err(StoreError::RegistrationTransactionConflict(
                        record.creation_position,
                    ));
                }
                group_index
            } else {
                let txid = evidence.transaction.txid();
                if let Some(previous_position) =
                    position_for_txid.insert(txid, record.creation_position)
                    && previous_position != record.creation_position
                {
                    return Err(StoreError::RegistrationTransactionConflict(
                        record.creation_position,
                    ));
                }
                let output_count =
                    u32::try_from(evidence.transaction.output.len()).map_err(|_| {
                        StoreError::InvalidRegistrationEvidence(
                            "creation output count exceeds u32".to_owned(),
                        )
                    })?;
                validate_registration_transaction_position(
                    &write,
                    record.creation_position,
                    evidence.anchor,
                    txid,
                )?;
                let group_index = transaction_groups.len();
                transaction_groups.push(RegistrationTransactionGroup {
                    position: record.creation_position,
                    anchor: evidence.anchor,
                    transaction: Arc::clone(&evidence.transaction),
                    txid,
                    raw_tx: encode::serialize(evidence.transaction.as_ref()),
                    output_count,
                    existing_contract_ids: Vec::new(),
                    new_contract_ids: Vec::new(),
                });
                group_at_position.insert(record.creation_position, group_index);
                group_index
            };
            let group = &transaction_groups[group_index];
            validate_registration_evidence(record, group.txid, group.output_count)?;
            if let Some(location) = evidence.associated_hint
                && !claimed_hint_locations.insert(location)
            {
                // Hints are unauthenticated discovery aids. Multiple claims
                // make this location useless for automatic association, but
                // cannot invalidate otherwise chain-valid contracts.
                ambiguous_hint_locations.insert(location);
            }

            if let Some(existing) = read_contract_from_write(&write, record.contract_id)? {
                if !registration_identity_matches(&existing, record) {
                    return Err(StoreError::ContractAlreadyExists(record.contract_id));
                }
                let mut existing = existing;
                normalize_ready_anchor(&mut existing, tip);
                existing_records.insert(record.contract_id, existing);
                transaction_groups[group_index]
                    .existing_contract_ids
                    .push(record.contract_id);
                continue;
            }

            for tracked in &record.outpoints {
                if let Some(owner) = proposed_owners.insert(tracked.outpoint, record.contract_id) {
                    return Err(StoreError::OutpointAlreadyOwned {
                        outpoint: tracked.outpoint,
                        owner,
                    });
                }
                if let Some(owner) = read_fixed_from_write::<OutpointOwner, 36>(
                    &write,
                    OUTPOINT_OWNERS,
                    &outpoint_fixed_key(tracked.outpoint),
                )? {
                    return Err(StoreError::OutpointAlreadyOwned {
                        outpoint: tracked.outpoint,
                        owner: owner.contract_id,
                    });
                }
            }

            new_progress.insert(
                record.contract_id,
                BackfillProgress {
                    contract_id: record.contract_id,
                    pinned_tip: tip,
                    next_position: ChainPosition {
                        block_height: record.creation_position.block_height,
                        tx_index: record
                            .creation_position
                            .tx_index
                            .checked_add(1)
                            .ok_or(StoreError::PositionOverflow)?,
                    },
                    last_applied: None,
                },
            );
            transaction_groups[group_index]
                .new_contract_ids
                .push(record.contract_id);
        }

        // Retain the normalized, verified semantics even when the contract was
        // already found through automatic discovery. These rows are watch
        // intent, not chain-derived state, and intentionally have no undo leg.
        for declaration in &retained_declarations {
            write_fixed(
                &write,
                RETAINED_DECLARATIONS,
                &declaration.contract_id.to_fixed_key(),
                declaration,
            )?;
        }

        let mut inserted_transaction_groups = Vec::new();
        for (group_index, group) in transaction_groups.iter().enumerate() {
            if merge_registration_transaction_group(&write, group)? {
                inserted_transaction_groups.push(group_index);
            }
        }

        for (record, _) in registrations {
            let Some(progress) = new_progress.get(&record.contract_id) else {
                continue;
            };
            insert_contract(&write, record)?;
            write_fixed(
                &write,
                BACKFILL_PROGRESS,
                &record.contract_id.to_fixed_key(),
                progress,
            )?;
            if let Some(mut undo) = read_fixed_from_write::<UndoBlock, 4>(
                &write,
                UNDO_BLOCKS,
                &record.creation_position.block_height.to_be_bytes(),
            )? {
                undo.contract_changes.push(ContractUndo {
                    contract_id: record.contract_id,
                    before: None,
                });
                undo.backfill_progress_changes.push(BackfillProgressUndo {
                    contract_id: record.contract_id,
                    before: None,
                });
                write_fixed(
                    &write,
                    UNDO_BLOCKS,
                    &record.creation_position.block_height.to_be_bytes(),
                    &undo,
                )?;
            }
            append_event(
                &write,
                StoredEvent::ContractRegistered {
                    contract_id: record.contract_id,
                },
            )?;
        }

        // A composed creation transaction has one retained transaction/output
        // leg in the block undo journal, independent of the number of newly
        // registered contracts it created.
        for group_index in inserted_transaction_groups {
            let group = &transaction_groups[group_index];
            if let Some(mut undo) = read_fixed_from_write::<UndoBlock, 4>(
                &write,
                UNDO_BLOCKS,
                &group.position.block_height.to_be_bytes(),
            )? {
                undo.transaction_positions.push(group.position);
                for vout in 0..group.output_count {
                    undo.output_outpoints.push(OutPoint::new(group.txid, vout));
                }
                write_fixed(
                    &write,
                    UNDO_BLOCKS,
                    &group.position.block_height.to_be_bytes(),
                    &undo,
                )?;
            }
        }

        // Association is derivative, best-effort discovery metadata. Only a
        // newly inserted contract may claim an unambiguous, matching and still
        // unowned hint. Idempotent retries never mutate state without a
        // corresponding registration event/high-watermark change.
        for (record, evidence) in registrations {
            if new_progress.contains_key(&record.contract_id)
                && evidence
                    .associated_hint
                    .is_none_or(|location| !ambiguous_hint_locations.contains(&location))
            {
                associate_registration_hint(&write, record, evidence)?;
            }
        }

        let results = registrations
            .iter()
            .map(|(record, _)| {
                existing_records
                    .get(&record.contract_id)
                    .cloned()
                    .map_or_else(
                        || ContractRegistrationResult {
                            record: record.clone(),
                            inserted: true,
                        },
                        |record| ContractRegistrationResult {
                            record,
                            inserted: false,
                        },
                    )
            })
            .collect();
        write.commit()?;
        Ok(results)
    }

    /// Atomically replay one complete canonical block for one or more
    /// late-registered contracts. All supplied contract legs and progress
    /// cursors commit together.
    pub fn apply_backfill_block(
        &self,
        contract_ids: &[ContractId],
        delta: &BlockDelta,
    ) -> Result<ApplyBackfillResult, StoreError> {
        validate_block_shape(delta)?;
        if contract_ids.is_empty() {
            return Err(StoreError::InvalidBackfill(
                "backfill batch has no contracts".to_owned(),
            ));
        }
        let mut targets = contract_ids.to_vec();
        sort_dedup_contracts(&mut targets);
        if targets.len() != contract_ids.len() {
            return Err(StoreError::InvalidBackfill(
                "backfill batch contains duplicate contracts".to_owned(),
            ));
        }
        let block_digest = digest(delta)?;
        let write = self.database.begin_write()?;
        if read_meta_record_from_write::<SyncStatus>(&write, SYNC_STATUS_KEY)?
            == Some(SyncStatus::RescanRequired)
        {
            return Err(StoreError::RebuildRequired);
        }
        verify_backfill_block(&write, delta)?;

        let mut progress = Vec::with_capacity(targets.len());
        let mut exact_retry = true;
        for contract_id in &targets {
            let item = read_fixed_from_write::<BackfillProgress, 36>(
                &write,
                BACKFILL_PROGRESS,
                &contract_id.to_fixed_key(),
            )?
            .ok_or(StoreError::MissingBackfillProgress(*contract_id))?;
            if item.last_applied != Some((delta.anchor, block_digest)) {
                exact_retry = false;
            }
            progress.push(item);
        }
        if exact_retry {
            let high = high_watermark_from_write(&write)?;
            let ready_contracts = ready_targets_from_write(&write, &targets)?;
            drop(write);
            return Ok(ApplyBackfillResult {
                applied: false,
                through: delta.anchor,
                ready_contracts,
                event_high_watermark: high,
            });
        }
        for item in &progress {
            if item.next_position.block_height != delta.anchor.height
                || item.pinned_tip.height < delta.anchor.height
            {
                return Err(StoreError::BackfillPositionMismatch {
                    contract_id: item.contract_id,
                    expected: item.next_position,
                    block_height: delta.anchor.height,
                });
            }
        }

        let target_set = targets.iter().copied().collect::<HashSet<_>>();
        validate_backfill_targets(delta, &progress, &target_set)?;
        let mut undo = read_fixed_from_write::<UndoBlock, 4>(
            &write,
            UNDO_BLOCKS,
            &delta.anchor.height.to_be_bytes(),
        )?;
        if let Some(undo) = undo.as_mut() {
            for item in &progress {
                undo.backfill_progress_changes.push(BackfillProgressUndo {
                    contract_id: item.contract_id,
                    before: Some(item.clone()),
                });
            }
        }

        let mut transitions = HashMap::<ContractId, u32>::new();
        let mut changed_contracts = HashSet::new();
        for transaction in &delta.relevant_transactions {
            apply_backfill_transaction(
                &write,
                transaction,
                &target_set,
                undo.as_mut(),
                &mut transitions,
                &mut changed_contracts,
            )?;
        }

        let indexed_tip = tip_from_write(&write)?.ok_or(StoreError::TipNotInitialized)?;
        let next_height = delta
            .anchor
            .height
            .checked_add(1)
            .ok_or(StoreError::HeightOverflow)?;
        let mut ready_contracts = Vec::new();
        for mut item in progress {
            let before = read_contract_from_write(&write, item.contract_id)?
                .ok_or(StoreError::ContractNotFound(item.contract_id))?;
            if !matches!(before.sync_state, ContractSyncState::CatchingUp { .. }) {
                return Err(StoreError::InvalidBackfill(
                    "backfill target is not catching up".to_owned(),
                ));
            }
            if let Some(undo) = undo.as_mut()
                && !changed_contracts.contains(&item.contract_id)
            {
                undo.contract_changes.push(ContractUndo {
                    contract_id: item.contract_id,
                    before: Some(before.clone()),
                });
            }
            remove_contract(&write, &before)?;
            let mut after = before;
            let ready = delta.anchor == indexed_tip;
            after.sync_state = if ready {
                ContractSyncState::Ready {
                    synced_through: delta.anchor,
                }
            } else {
                ContractSyncState::CatchingUp {
                    synced_through: delta.anchor,
                }
            };
            insert_contract(&write, &after)?;

            item.next_position = ChainPosition {
                block_height: next_height,
                tx_index: 0,
            };
            item.last_applied = Some((delta.anchor, block_digest));
            if item.pinned_tip == delta.anchor && indexed_tip != delta.anchor {
                item.pinned_tip = indexed_tip;
            }
            write_fixed(
                &write,
                BACKFILL_PROGRESS,
                &item.contract_id.to_fixed_key(),
                &item,
            )?;
            append_event(
                &write,
                StoredEvent::BackfillApplied {
                    contract_id: item.contract_id,
                    through: delta.anchor,
                    transition_count: transitions.get(&item.contract_id).copied().unwrap_or(0),
                },
            )?;
            if ready {
                ready_contracts.push(item.contract_id);
                append_event(
                    &write,
                    StoredEvent::ContractReady {
                        contract_id: item.contract_id,
                        through: delta.anchor,
                    },
                )?;
            }
        }
        if let Some(undo) = undo {
            write_fixed(
                &write,
                UNDO_BLOCKS,
                &delta.anchor.height.to_be_bytes(),
                &undo,
            )?;
        }
        let high = high_watermark_from_write(&write)?;
        write.commit()?;
        Ok(ApplyBackfillResult {
            applied: true,
            through: delta.anchor,
            ready_contracts,
            event_high_watermark: high,
        })
    }

    pub fn outpoint_owner(&self, outpoint: OutPoint) -> Result<Option<OutpointOwner>, StoreError> {
        self.read_fixed(OUTPOINT_OWNERS, &outpoint_fixed_key(outpoint))
    }

    pub fn recovery_hint(
        &self,
        location: RecoveryHintLocation,
    ) -> Result<Option<StoredRecoveryHint>, StoreError> {
        self.read_fixed(RECOVERY_HINTS, &recovery_key(location))
    }

    pub fn contract_history(
        &self,
        contract_id: ContractId,
    ) -> Result<Vec<StoredHistoryEntry>, StoreError> {
        let prefix = contract_id.to_fixed_key();
        let read = self.database.begin_read()?;
        let table = read.open_table(CONTRACT_HISTORY)?;
        let mut history = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let key: [u8; 44] = key
                .value()
                .try_into()
                .map_err(|_| StoreError::CorruptIndexKey("contract_history"))?;
            if key[..36] == prefix {
                history.push(decode_record(value.value())?);
            }
        }
        Ok(history)
    }

    /// Read contract existence/current state, its canonical history, and the
    /// pagination invalidation metadata from one redb read transaction.
    pub fn contract_history_snapshot(
        &self,
        contract_id: ContractId,
    ) -> Result<
        (
            StoreSnapshotMetadata,
            Option<ContractRecord>,
            Vec<StoredHistoryEntry>,
        ),
        StoreError,
    > {
        let read = self.database.begin_read()?;
        let snapshot = snapshot_from_read(&read)?;
        let contracts = read.open_table(CONTRACTS)?;
        let mut contract = contracts
            .get(contract_id.to_fixed_key().as_slice())?
            .map(|value| decode_record(value.value()))
            .transpose()?;
        if let Some(contract) = contract.as_mut() {
            normalize_ready_anchor(contract, snapshot.as_of);
        }
        let prefix = contract_id.to_fixed_key();
        let table = read.open_table(CONTRACT_HISTORY)?;
        let mut history = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let key: [u8; 44] = key
                .value()
                .try_into()
                .map_err(|_| StoreError::CorruptIndexKey("contract_history"))?;
            if key[..36] == prefix {
                history.push(decode_record(value.value())?);
            }
        }
        Ok((snapshot, contract, history))
    }

    pub fn apply_block(&self, delta: &BlockDelta) -> Result<ApplyBlockResult, StoreError> {
        validate_block_shape(delta)?;
        let delta_digest = digest(delta)?;
        let write = self.database.begin_write()?;
        if read_meta_record_from_write::<SyncStatus>(&write, SYNC_STATUS_KEY)?
            == Some(SyncStatus::RescanRequired)
        {
            return Err(StoreError::RebuildRequired);
        }

        if let Some(existing) = read_fixed_from_write::<StoredBlock, 4>(
            &write,
            BLOCKS,
            &delta.anchor.height.to_be_bytes(),
        )? {
            if existing.delta_digest == delta_digest
                && existing.anchor == delta.anchor
                && existing.prev_block_hash == delta.prev_block_hash
            {
                let high = high_watermark_from_write(&write)?;
                drop(write);
                return Ok(ApplyBlockResult {
                    applied: false,
                    new_tip: delta.anchor,
                    event_high_watermark: high,
                });
            }
            return Err(StoreError::ForkConflict {
                height: delta.anchor.height,
            });
        }

        let previous_tip = tip_from_write(&write)?.ok_or(StoreError::TipNotInitialized)?;
        if delta.anchor.height
            != previous_tip
                .height
                .checked_add(1)
                .ok_or(StoreError::HeightOverflow)?
            || delta.prev_block_hash != previous_tip.hash
        {
            return Err(StoreError::NonContiguousBlock {
                current: previous_tip,
                proposed: delta.anchor,
                proposed_previous_hash: delta.prev_block_hash,
            });
        }

        let mut undo = UndoBlock {
            previous_tip,
            contract_changes: Vec::new(),
            transaction_positions: Vec::new(),
            output_outpoints: Vec::new(),
            history_keys: Vec::new(),
            recovery_locations: Vec::new(),
            backfill_progress_changes: Vec::new(),
        };

        let mut transactions: Vec<_> = delta.relevant_transactions.iter().collect();
        transactions.sort_by_key(|transaction| transaction.position.tx_index);
        for transaction in transactions {
            apply_chain_transaction(&write, delta.anchor, transaction, &mut undo)?;
        }
        for hint in &delta.recovery_hints {
            insert_recovery_hint(&write, hint)?;
            undo.recovery_locations.push(hint.location);
        }
        advance_catching_through_canonical_block(&write, delta, delta_digest, &mut undo)?;

        let stored_block = StoredBlock {
            anchor: delta.anchor,
            prev_block_hash: delta.prev_block_hash,
            ordered_txids: delta.ordered_txids.clone(),
            delta_digest,
        };
        write_fixed(
            &write,
            BLOCKS,
            &delta.anchor.height.to_be_bytes(),
            &stored_block,
        )?;
        write_fixed(
            &write,
            UNDO_BLOCKS,
            &delta.anchor.height.to_be_bytes(),
            &undo,
        )?;
        write_tip(&write, delta.anchor)?;
        prune_undo(&write, delta.anchor.height)?;
        let high = high_watermark_from_write(&write)?;
        write.commit()?;
        Ok(ApplyBlockResult {
            applied: true,
            new_tip: delta.anchor,
            event_high_watermark: high,
        })
    }

    pub fn rollback_to(&self, ancestor: ChainAnchor) -> Result<RollbackResult, StoreError> {
        let write = self.database.begin_write()?;
        if read_meta_record_from_write::<SyncStatus>(&write, SYNC_STATUS_KEY)?
            == Some(SyncStatus::RescanRequired)
        {
            return Err(StoreError::RebuildRequired);
        }
        let old_tip = tip_from_write(&write)?.ok_or(StoreError::TipNotInitialized)?;
        if ancestor == old_tip {
            drop(write);
            return Ok(RollbackResult::Noop { tip: old_tip });
        }
        if ancestor.height >= old_tip.height {
            return Err(StoreError::InvalidRollbackTarget { old_tip, ancestor });
        }
        let depth = old_tip.height - ancestor.height;
        if depth > UNDO_RETENTION_BLOCKS
            || !undo_range_available(&write, old_tip.height, ancestor.height)?
        {
            let epoch = mark_rebuild_required(&write)?;
            write.commit()?;
            return Ok(RollbackResult::RebuildRequired {
                old_tip,
                requested_ancestor: ancestor,
                new_event_epoch: epoch,
            });
        }

        let mut current_tip = old_tip;
        let mut orphaned_positions = Vec::new();
        let mut affected_contract_ids = Vec::new();
        let mut affected_market_ids = Vec::new();
        for height in (ancestor.height + 1..=old_tip.height).rev() {
            let undo: UndoBlock =
                read_fixed_from_write(&write, UNDO_BLOCKS, &height.to_be_bytes())?
                    .ok_or(StoreError::MissingUndo { height })?;
            for change in undo.contract_changes.iter().rev() {
                if let Some(current) = read_contract_from_write(&write, change.contract_id)? {
                    affected_contract_ids.push(change.contract_id);
                    collect_market_id(&current, &mut affected_market_ids);
                    remove_contract(&write, &current)?;
                }
                if let Some(before) = &change.before {
                    insert_contract(&write, before)?;
                }
            }
            for position in &undo.transaction_positions {
                orphaned_positions.push(*position);
                remove_fixed(&write, TRANSACTIONS, &position.to_fixed_key())?;
            }
            for outpoint in &undo.output_outpoints {
                remove_fixed(&write, OUTPUTS, &outpoint_fixed_key(*outpoint))?;
            }
            for (contract_id, position) in &undo.history_keys {
                remove_fixed(
                    &write,
                    CONTRACT_HISTORY,
                    &history_key(*contract_id, *position),
                )?;
            }
            for location in &undo.recovery_locations {
                remove_fixed(&write, RECOVERY_HINTS, &recovery_key(*location))?;
            }
            for change in undo.backfill_progress_changes.iter().rev() {
                remove_fixed(
                    &write,
                    BACKFILL_PROGRESS,
                    &change.contract_id.to_fixed_key(),
                )?;
                if let Some(before) = &change.before {
                    write_fixed(
                        &write,
                        BACKFILL_PROGRESS,
                        &change.contract_id.to_fixed_key(),
                        before,
                    )?;
                }
            }
            remove_fixed(&write, BLOCKS, &height.to_be_bytes())?;
            remove_fixed(&write, UNDO_BLOCKS, &height.to_be_bytes())?;
            current_tip = undo.previous_tip;
        }
        if current_tip != ancestor {
            return Err(StoreError::AncestorMismatch {
                expected: ancestor,
                restored: current_tip,
            });
        }
        sort_dedup_contracts(&mut affected_contract_ids);
        sort_dedup_contracts(&mut affected_market_ids);
        orphaned_positions.sort();
        write_tip(&write, ancestor)?;
        write_meta_record(&write, SYNC_STATUS_KEY, &SyncStatus::Syncing)?;
        let event = StoredEvent::ChainRolledBack {
            old_tip,
            new_tip: ancestor,
            orphaned_positions: orphaned_positions.clone(),
            affected_contract_ids,
            affected_market_ids,
        };
        let high = append_event(&write, event)?;
        write.commit()?;
        Ok(RollbackResult::RolledBack {
            old_tip,
            new_tip: ancestor,
            orphaned_positions,
            event_high_watermark: high,
        })
    }

    pub fn invalidate_for_rebuild(&self) -> Result<[u8; 16], StoreError> {
        let write = self.database.begin_write()?;
        let epoch = mark_rebuild_required(&write)?;
        write.commit()?;
        Ok(epoch)
    }

    /// Explicitly discard chain-derived materialized state before replaying
    /// from the immutable v1 activation checkpoint. Registration rejects every
    /// pre-activation declaration, so retained watch intent is complete from
    /// this checkpoint without a genesis rescan.
    pub fn reset_for_rebuild(&self) -> Result<EventCursor, StoreError> {
        let write = self.database.begin_write()?;
        if read_meta_record_from_write::<SyncStatus>(&write, SYNC_STATUS_KEY)?
            != Some(SyncStatus::RescanRequired)
        {
            return Err(StoreError::RebuildNotRequired);
        }
        let baseline = read_meta_record_from_write::<ChainAnchor>(&write, ACTIVATION_ANCHOR_KEY)?
            .ok_or(StoreError::MissingMetadata(ACTIVATION_ANCHOR_KEY))?;
        clear_chain_tables(&write)?;
        write_tip(&write, baseline)?;
        write_meta_record(&write, SYNC_STATUS_KEY, &SyncStatus::Syncing)?;
        let cursor = append_event(
            &write,
            StoredEvent::SyncStatusChanged {
                status: SyncStatus::Syncing,
            },
        )?;
        write.commit()?;
        Ok(cursor)
    }

    fn initialize_schema(&self) -> Result<(), StoreError> {
        let write = self.database.begin_write()?;
        {
            let mut meta = write.open_table(META)?;
            let existing = meta
                .get(SCHEMA_VERSION_KEY)?
                .map(|value| value.value().to_vec());
            match existing {
                Some(value) => {
                    let actual =
                        decode_u32(&value).map_err(|_| StoreError::CorruptSchemaVersion)?;
                    if actual != SCHEMA_VERSION {
                        return Err(StoreError::SchemaMismatch {
                            expected: SCHEMA_VERSION,
                            actual,
                        });
                    }
                }
                None => {
                    let encoded = SCHEMA_VERSION.to_be_bytes();
                    meta.insert(SCHEMA_VERSION_KEY, encoded.as_slice())?;
                    let epoch = random_epoch();
                    meta.insert(EVENT_EPOCH_KEY, epoch.as_slice())?;
                    meta.insert(EVENT_SEQUENCE_KEY, 0_u64.to_be_bytes().as_slice())?;
                    let status = encode_record(&SyncStatus::Starting)?;
                    meta.insert(SYNC_STATUS_KEY, status.as_slice())?;
                }
            }
            ensure_metadata(&meta, EVENT_EPOCH_KEY, 16)?;
            ensure_metadata(&meta, EVENT_SEQUENCE_KEY, 8)?;
            if meta.get(SYNC_STATUS_KEY)?.is_none() {
                return Err(StoreError::MissingMetadata(SYNC_STATUS_KEY));
            }
        }
        create_tables(&write)?;
        write.commit()?;
        Ok(())
    }

    fn read_meta_record<T: DeserializeOwned>(
        &self,
        key: &'static str,
    ) -> Result<Option<T>, StoreError> {
        let read = self.database.begin_read()?;
        let table = read.open_table(META)?;
        table
            .get(key)?
            .map(|value| decode_record(value.value()))
            .transpose()
    }

    fn read_fixed<T: DeserializeOwned, const N: usize>(
        &self,
        definition: TableDefinition<&[u8], &[u8]>,
        key: &[u8; N],
    ) -> Result<Option<T>, StoreError> {
        let read = self.database.begin_read()?;
        let table = read.open_table(definition)?;
        table
            .get(key.as_slice())?
            .map(|value| decode_record(value.value()))
            .transpose()
    }
}

fn validate_block_shape(delta: &BlockDelta) -> Result<(), StoreError> {
    if delta.ordered_txids.is_empty() {
        return Err(StoreError::InvalidBlock(
            "complete txid list is empty".to_owned(),
        ));
    }
    let mut txids = HashSet::new();
    if delta.ordered_txids.iter().any(|txid| !txids.insert(*txid)) {
        return Err(StoreError::InvalidBlock(
            "complete txid list contains duplicates".to_owned(),
        ));
    }
    let mut positions = HashSet::new();
    if delta
        .relevant_transactions
        .windows(2)
        .any(|pair| pair[0].position >= pair[1].position)
    {
        return Err(StoreError::InvalidBlock(
            "relevant transactions are not in strict chain order".to_owned(),
        ));
    }
    for transaction in &delta.relevant_transactions {
        let index = usize::try_from(transaction.position.tx_index).map_err(|_| {
            StoreError::InvalidBlock("transaction index does not fit usize".to_owned())
        })?;
        let output_count = u32::try_from(transaction.raw_tx.output.len())
            .map_err(|_| StoreError::InvalidBlock("output count exceeds u32".to_owned()))?;
        if transaction.position.block_height != delta.anchor.height
            || transaction.block_hash != delta.anchor.hash
            || index >= delta.ordered_txids.len()
            || delta.ordered_txids[index] != transaction.txid
            || transaction.raw_tx.txid() != transaction.txid
            || !positions.insert(transaction.position)
        {
            return Err(StoreError::InvalidBlock(
                "relevant transaction position/hash/txid is inconsistent".to_owned(),
            ));
        }
        let mut contracts = HashSet::new();
        for contract in &transaction.created_contracts {
            if contract.creation_position != transaction.position
                || contract.contract_id.txid() != transaction.txid
                || !contracts.insert(contract.contract_id)
            {
                return Err(StoreError::InvalidBlock(
                    "created contract metadata is inconsistent or duplicated".to_owned(),
                ));
            }
            let creation_anchor = contract.contract_id.creation_anchor();
            if creation_anchor.vout >= output_count {
                return Err(StoreError::InvalidBlock(
                    "created contract anchor is absent from its creation transaction".to_owned(),
                ));
            }
            if !contract
                .outpoints
                .iter()
                .any(|tracked| tracked.outpoint == creation_anchor)
            {
                return Err(StoreError::InvalidBlock(
                    "created contract anchor is not one of its initial live outputs".to_owned(),
                ));
            }
            contract.validate()?;
        }
        for update in &transaction.state_updates {
            if !contracts.insert(update.contract_id) {
                return Err(StoreError::InvalidBlock(
                    "a transaction has duplicate legs for one contract".to_owned(),
                ));
            }
        }
    }
    if delta
        .recovery_hints
        .windows(2)
        .any(|pair| recovery_key(pair[0].location) >= recovery_key(pair[1].location))
    {
        return Err(StoreError::InvalidBlock(
            "recovery hints are not in strict chain/output order".to_owned(),
        ));
    }
    let mut hints = HashSet::new();
    for hint in &delta.recovery_hints {
        let index = usize::try_from(hint.location.position.tx_index)
            .map_err(|_| StoreError::InvalidBlock("hint index does not fit usize".to_owned()))?;
        if hint.location.position.block_height != delta.anchor.height
            || index >= delta.ordered_txids.len()
            || delta.ordered_txids[index] != hint.creation_txid
            || !hints.insert(hint.location)
        {
            return Err(StoreError::InvalidBlock(
                "recovery hint position/txid is inconsistent or duplicated".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_registration_evidence(
    record: &ContractRecord,
    txid: Txid,
    output_count: u32,
) -> Result<(), StoreError> {
    if txid != record.contract_id.txid() {
        return Err(StoreError::InvalidRegistrationEvidence(
            "creation transaction ID does not match the contract ID".to_owned(),
        ));
    }
    if record.contract_id.vout() >= output_count {
        return Err(StoreError::InvalidRegistrationEvidence(
            "contract creation anchor is absent from the creation transaction".to_owned(),
        ));
    }
    if !record
        .outpoints
        .iter()
        .any(|tracked| tracked.outpoint == record.contract_id.creation_anchor())
    {
        return Err(StoreError::InvalidRegistrationEvidence(
            "contract creation anchor is not one of the initial live outputs".to_owned(),
        ));
    }
    for tracked in &record.outpoints {
        if tracked.outpoint.txid != txid || tracked.outpoint.vout >= output_count {
            return Err(StoreError::InvalidRegistrationEvidence(
                "initial live outpoint is absent from the creation transaction".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_registration_transaction_position(
    write: &WriteTransaction,
    position: ChainPosition,
    anchor: ChainAnchor,
    txid: Txid,
) -> Result<(), StoreError> {
    if let Some(block) =
        read_fixed_from_write::<StoredBlock, 4>(write, BLOCKS, &anchor.height.to_be_bytes())?
    {
        let index = usize::try_from(position.tx_index).map_err(|_| {
            StoreError::InvalidRegistrationEvidence(
                "creation transaction index does not fit usize".to_owned(),
            )
        })?;
        if block.anchor != anchor || block.ordered_txids.get(index).copied() != Some(txid) {
            return Err(StoreError::InvalidRegistrationEvidence(
                "creation transaction is not at its claimed canonical position".to_owned(),
            ));
        }
    }
    Ok(())
}

fn associate_registration_hint(
    write: &WriteTransaction,
    record: &ContractRecord,
    evidence: &RegistrationEvidence,
) -> Result<(), StoreError> {
    let Some(location) = evidence.associated_hint else {
        return Ok(());
    };
    if location.position != record.creation_position
        || usize::try_from(location.output_index)
            .map_or(true, |vout| vout >= evidence.transaction.output.len())
    {
        return Ok(());
    }
    let key = recovery_key(location);
    let Some(mut hint) =
        read_fixed_from_write::<StoredRecoveryHint, 12>(write, RECOVERY_HINTS, &key)?
    else {
        return Ok(());
    };
    let expected_family = match record.kind {
        ContractKind::BinaryMarketV1 => RecoveryFamily::BinaryMarketV1,
        ContractKind::MakerOrderV1 => RecoveryFamily::MakerOrderV1,
        ContractKind::LmsrV1Reserved => return Ok(()),
    };
    if hint.location == location
        && hint.creation_txid == record.contract_id.txid()
        && hint.family == expected_family
        && hint.associated_contract.is_none()
    {
        hint.associated_contract = Some(record.contract_id);
        write_fixed(write, RECOVERY_HINTS, &key, &hint)?;
    }
    Ok(())
}

fn declaration_from_record(record: &ContractRecord) -> Result<ContractDeclaration, StoreError> {
    let descriptor = match (
        record.kind,
        &record.params,
        record.parent_market,
        record.outcome_side,
    ) {
        (ContractKind::BinaryMarketV1, ContractParameters::BinaryMarket(params), None, None) => {
            ContractDescriptor::BinaryMarketV1 { params: *params }
        }
        (
            ContractKind::MakerOrderV1,
            ContractParameters::MakerOrder(params),
            Some(parent_market),
            Some(side),
        ) => ContractDescriptor::MakerOrderV1 {
            parent_market,
            side,
            params: *params,
        },
        _ => {
            return Err(StoreError::InvalidContract(
                "contract cannot be normalized into a retained declaration".to_owned(),
            ));
        }
    };
    Ok(ContractDeclaration {
        contract_id: record.contract_id,
        descriptor,
    })
}

fn registration_identity_matches(existing: &ContractRecord, registration: &ContractRecord) -> bool {
    existing.contract_id == registration.contract_id
        && existing.kind == registration.kind
        && existing.params == registration.params
        && existing.creation_position == registration.creation_position
        && existing.parent_market == registration.parent_market
        && existing.outcome_side == registration.outcome_side
        && existing.scripts == registration.scripts
        && existing.assets == registration.assets
}

fn verify_registration_output_refs(
    write: &WriteTransaction,
    position: ChainPosition,
    txid: Txid,
    output_count: u32,
) -> Result<(), StoreError> {
    for vout in 0..output_count {
        let outpoint = OutPoint::new(txid, vout);
        let reference = read_fixed_from_write::<StoredOutputRef, 36>(
            write,
            OUTPUTS,
            &outpoint_fixed_key(outpoint),
        )?
        .ok_or(StoreError::MissingOutput(outpoint))?;
        if reference.position != position || reference.outpoint != outpoint {
            return Err(StoreError::RegistrationTransactionConflict(position));
        }
    }
    Ok(())
}

/// Merge one canonical creation transaction for every contract registered at
/// its position. Returns true only when this call created the transaction and
/// output-reference rows and must therefore add one leg to the retained undo
/// journal.
fn merge_registration_transaction_group(
    write: &WriteTransaction,
    group: &RegistrationTransactionGroup,
) -> Result<bool, StoreError> {
    if let Some(mut stored) = read_fixed_from_write::<StoredTransaction, 8>(
        write,
        TRANSACTIONS,
        &group.position.to_fixed_key(),
    )? {
        if stored.position != group.position
            || stored.block_hash != group.anchor.hash
            || stored.txid != group.txid
            || stored.raw_tx != group.raw_tx
        {
            return Err(StoreError::RegistrationTransactionConflict(group.position));
        }
        verify_registration_output_refs(write, group.position, group.txid, group.output_count)?;
        if group
            .existing_contract_ids
            .iter()
            .any(|contract_id| !stored.affected_contract_ids.contains(contract_id))
        {
            return Err(StoreError::RegistrationTransactionConflict(group.position));
        }
        if group.new_contract_ids.is_empty() {
            return Ok(false);
        }
        stored
            .affected_contract_ids
            .extend_from_slice(&group.new_contract_ids);
        sort_dedup_contracts(&mut stored.affected_contract_ids);
        write_fixed(write, TRANSACTIONS, &group.position.to_fixed_key(), &stored)?;
        return Ok(false);
    }

    if !group.existing_contract_ids.is_empty() {
        return Err(StoreError::MissingRegistrationTransaction(group.position));
    }
    let stored = StoredTransaction {
        position: group.position,
        block_hash: group.anchor.hash,
        txid: group.txid,
        raw_tx: group.raw_tx.clone(),
        affected_contract_ids: {
            let mut contract_ids = group.new_contract_ids.clone();
            sort_dedup_contracts(&mut contract_ids);
            contract_ids
        },
    };
    write_fixed(write, TRANSACTIONS, &group.position.to_fixed_key(), &stored)?;
    for vout in 0..group.output_count {
        let outpoint = OutPoint::new(stored.txid, vout);
        if read_fixed_from_write::<StoredOutputRef, 36>(
            write,
            OUTPUTS,
            &outpoint_fixed_key(outpoint),
        )?
        .is_some()
        {
            return Err(StoreError::RegistrationTransactionConflict(group.position));
        }
        write_fixed(
            write,
            OUTPUTS,
            &outpoint_fixed_key(outpoint),
            &StoredOutputRef {
                position: group.position,
                outpoint,
            },
        )?;
    }
    Ok(true)
}

fn verify_backfill_block(write: &WriteTransaction, delta: &BlockDelta) -> Result<(), StoreError> {
    if canonical_anchor_from_write(write, delta.anchor.height)? != Some(delta.anchor) {
        return Err(StoreError::BackfillBranchChanged {
            anchor: delta.anchor,
        });
    }
    if let Some(stored) =
        read_fixed_from_write::<StoredBlock, 4>(write, BLOCKS, &delta.anchor.height.to_be_bytes())?
        && (stored.anchor != delta.anchor
            || stored.prev_block_hash != delta.prev_block_hash
            || stored.ordered_txids != delta.ordered_txids)
    {
        return Err(StoreError::BackfillBranchChanged {
            anchor: delta.anchor,
        });
    }
    Ok(())
}

fn validate_backfill_targets(
    delta: &BlockDelta,
    progress: &[BackfillProgress],
    targets: &HashSet<ContractId>,
) -> Result<(), StoreError> {
    if !delta.recovery_hints.is_empty() {
        return Err(StoreError::InvalidBackfill(
            "canonical recovery hints cannot be inserted by historical contract backfill"
                .to_owned(),
        ));
    }
    let starts = progress
        .iter()
        .map(|item| (item.contract_id, item.next_position))
        .collect::<HashMap<_, _>>();
    for transaction in &delta.relevant_transactions {
        if !transaction.created_contracts.is_empty() {
            return Err(StoreError::InvalidBackfill(
                "late registration creation records are persisted before replay".to_owned(),
            ));
        }
        if transaction.state_updates.is_empty() {
            return Err(StoreError::InvalidBackfill(
                "backfill transaction has no target state update".to_owned(),
            ));
        }
        for update in &transaction.state_updates {
            let Some(start) = starts.get(&update.contract_id) else {
                return Err(StoreError::InvalidBackfill(
                    "backfill transaction updates a contract outside the atomic batch".to_owned(),
                ));
            };
            if !targets.contains(&update.contract_id) || transaction.position < *start {
                return Err(StoreError::InvalidBackfill(
                    "backfill transition precedes the contract scan cursor".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn apply_backfill_transaction(
    write: &WriteTransaction,
    delta: &ChainTxDelta,
    targets: &HashSet<ContractId>,
    mut undo: Option<&mut UndoBlock>,
    transitions: &mut HashMap<ContractId, u32>,
    changed_contracts: &mut HashSet<ContractId>,
) -> Result<(), StoreError> {
    validate_tracked_inputs(write, delta)?;
    let output_count = u32::try_from(delta.raw_tx.output.len())
        .map_err(|_| StoreError::InvalidBlock("output count exceeds u32".to_owned()))?;
    let mut affected = Vec::with_capacity(delta.state_updates.len());
    for update in &delta.state_updates {
        if !targets.contains(&update.contract_id) {
            return Err(StoreError::InvalidBackfill(
                "backfill transaction contains a non-target leg".to_owned(),
            ));
        }
        let before = read_contract_from_write(write, update.contract_id)?
            .ok_or(StoreError::ContractNotFound(update.contract_id))?;
        if !matches!(before.sync_state, ContractSyncState::CatchingUp { .. }) {
            return Err(StoreError::InvalidBackfill(
                "backfill transition targets a ready contract".to_owned(),
            ));
        }
        if before.state != update.old_state {
            return Err(StoreError::StateMismatch {
                contract_id: update.contract_id,
            });
        }
        ensure_all_outpoints_spent(&before, update)?;
        validate_new_outpoints(&update.new_outpoints, delta.txid, output_count)?;
        if let Some(undo) = undo.as_deref_mut() {
            undo.contract_changes.push(ContractUndo {
                contract_id: update.contract_id,
                before: Some(before.clone()),
            });
        }
        remove_contract(write, &before)?;
        let mut after = before;
        after.state = update.new_state;
        after.outpoints.clone_from(&update.new_outpoints);
        update_order_book(&mut after, update.order_remaining_base)?;
        after.validate()?;
        insert_contract(write, &after)?;

        let history = StoredHistoryEntry {
            position: delta.position,
            txid: delta.txid,
            old_state: update.old_state,
            new_state: update.new_state,
            transition: update.transition.clone(),
        };
        let key = history_key(update.contract_id, delta.position);
        if read_fixed_from_write::<StoredHistoryEntry, 44>(write, CONTRACT_HISTORY, &key)?.is_some()
        {
            return Err(StoreError::DuplicateHistory {
                contract_id: update.contract_id,
                position: delta.position,
            });
        }
        write_fixed(write, CONTRACT_HISTORY, &key, &history)?;
        if let Some(undo) = undo.as_deref_mut() {
            undo.history_keys.push((update.contract_id, delta.position));
        }
        let transition_count = transitions.entry(update.contract_id).or_default();
        *transition_count = transition_count
            .checked_add(1)
            .ok_or(StoreError::TransitionCountOverflow)?;
        changed_contracts.insert(update.contract_id);
        affected.push(update.contract_id);
    }
    sort_dedup_contracts(&mut affected);

    let raw_tx = encode::serialize(&delta.raw_tx);
    let existing = read_fixed_from_write::<StoredTransaction, 8>(
        write,
        TRANSACTIONS,
        &delta.position.to_fixed_key(),
    )?;
    match existing {
        Some(mut stored) => {
            if stored.position != delta.position
                || stored.block_hash != delta.block_hash
                || stored.txid != delta.txid
                || stored.raw_tx != raw_tx
            {
                return Err(StoreError::BackfillTransactionConflict(delta.position));
            }
            stored.affected_contract_ids.extend(affected);
            sort_dedup_contracts(&mut stored.affected_contract_ids);
            write_fixed(write, TRANSACTIONS, &delta.position.to_fixed_key(), &stored)?;
        }
        None => {
            let stored = StoredTransaction {
                position: delta.position,
                block_hash: delta.block_hash,
                txid: delta.txid,
                raw_tx,
                affected_contract_ids: affected,
            };
            write_fixed(write, TRANSACTIONS, &delta.position.to_fixed_key(), &stored)?;
            if let Some(undo) = undo.as_deref_mut() {
                undo.transaction_positions.push(delta.position);
            }
            for (vout, _) in delta.raw_tx.output.iter().enumerate() {
                let outpoint = OutPoint::new(
                    delta.txid,
                    u32::try_from(vout)
                        .map_err(|_| StoreError::InvalidBlock("vout exceeds u32".to_owned()))?,
                );
                if read_fixed_from_write::<StoredOutputRef, 36>(
                    write,
                    OUTPUTS,
                    &outpoint_fixed_key(outpoint),
                )?
                .is_some()
                {
                    return Err(StoreError::BackfillTransactionConflict(delta.position));
                }
                let reference = StoredOutputRef {
                    position: delta.position,
                    outpoint,
                };
                write_fixed(write, OUTPUTS, &outpoint_fixed_key(outpoint), &reference)?;
                if let Some(undo) = undo.as_deref_mut() {
                    undo.output_outpoints.push(outpoint);
                }
            }
        }
    }
    Ok(())
}

fn ready_targets_from_write(
    write: &WriteTransaction,
    targets: &[ContractId],
) -> Result<Vec<ContractId>, StoreError> {
    let mut ready = Vec::new();
    for contract_id in targets {
        let contract = read_contract_from_write(write, *contract_id)?
            .ok_or(StoreError::ContractNotFound(*contract_id))?;
        if matches!(contract.sync_state, ContractSyncState::Ready { .. }) {
            ready.push(*contract_id);
        }
    }
    Ok(ready)
}

fn apply_chain_transaction(
    write: &WriteTransaction,
    anchor: ChainAnchor,
    delta: &ChainTxDelta,
    undo: &mut UndoBlock,
) -> Result<(), StoreError> {
    validate_tracked_inputs(write, delta)?;
    let output_count = u32::try_from(delta.raw_tx.output.len())
        .map_err(|_| StoreError::InvalidBlock("output count exceeds u32".to_owned()))?;

    for contract in &delta.created_contracts {
        if read_contract_from_write(write, contract.contract_id)?.is_some() {
            return Err(StoreError::ContractAlreadyExists(contract.contract_id));
        }
        validate_new_outpoints(&contract.outpoints, delta.txid, output_count)?;
        insert_contract(write, contract)?;
        undo.contract_changes.push(ContractUndo {
            contract_id: contract.contract_id,
            before: None,
        });
    }

    let mut affected = delta
        .created_contracts
        .iter()
        .map(|contract| contract.contract_id)
        .collect::<Vec<_>>();
    let mut markets = Vec::new();
    for contract in &delta.created_contracts {
        collect_market_id(contract, &mut markets);
    }
    for update in &delta.state_updates {
        let before = read_contract_from_write(write, update.contract_id)?
            .ok_or(StoreError::ContractNotFound(update.contract_id))?;
        if before.state != update.old_state {
            return Err(StoreError::StateMismatch {
                contract_id: update.contract_id,
            });
        }
        ensure_all_outpoints_spent(&before, update)?;
        validate_new_outpoints(&update.new_outpoints, delta.txid, output_count)?;
        undo.contract_changes.push(ContractUndo {
            contract_id: update.contract_id,
            before: Some(before.clone()),
        });
        remove_contract(write, &before)?;
        let mut after = before.clone();
        after.state = update.new_state;
        after.outpoints.clone_from(&update.new_outpoints);
        update_order_book(&mut after, update.order_remaining_base)?;
        after.validate()?;
        insert_contract(write, &after)?;
        let history = StoredHistoryEntry {
            position: delta.position,
            txid: delta.txid,
            old_state: update.old_state,
            new_state: update.new_state,
            transition: update.transition.clone(),
        };
        let history_key = history_key(update.contract_id, delta.position);
        if read_fixed_from_write::<StoredHistoryEntry, 44>(write, CONTRACT_HISTORY, &history_key)?
            .is_some()
        {
            return Err(StoreError::DuplicateHistory {
                contract_id: update.contract_id,
                position: delta.position,
            });
        }
        write_fixed(write, CONTRACT_HISTORY, &history_key, &history)?;
        undo.history_keys.push((update.contract_id, delta.position));
        affected.push(update.contract_id);
        collect_market_id(&after, &mut markets);
    }

    sort_dedup_contracts(&mut affected);
    sort_dedup_contracts(&mut markets);
    let stored = StoredTransaction {
        position: delta.position,
        block_hash: delta.block_hash,
        txid: delta.txid,
        raw_tx: encode::serialize(&delta.raw_tx),
        affected_contract_ids: affected.clone(),
    };
    write_fixed(write, TRANSACTIONS, &delta.position.to_fixed_key(), &stored)?;
    undo.transaction_positions.push(delta.position);
    for (vout, _) in delta.raw_tx.output.iter().enumerate() {
        let outpoint = OutPoint::new(
            delta.txid,
            u32::try_from(vout)
                .map_err(|_| StoreError::InvalidBlock("vout exceeds u32".to_owned()))?,
        );
        let stored_output = StoredOutputRef {
            position: delta.position,
            outpoint,
        };
        write_fixed(
            write,
            OUTPUTS,
            &outpoint_fixed_key(outpoint),
            &stored_output,
        )?;
        undo.output_outpoints.push(outpoint);
    }
    append_event(
        write,
        StoredEvent::TransactionApplied {
            anchor,
            txid: delta.txid,
            position: delta.position,
            affected_contract_ids: affected,
            affected_market_ids: markets,
        },
    )?;
    Ok(())
}

/// If a reorg leaves a late registration waiting exactly at the next block,
/// the canonical pass itself is the replay. Advance its durable cursor in the
/// same block commit rather than interpreting that block a second time.
fn advance_catching_through_canonical_block(
    write: &WriteTransaction,
    delta: &BlockDelta,
    block_digest: [u8; 32],
    undo: &mut UndoBlock,
) -> Result<(), StoreError> {
    let mut progress_rows = Vec::new();
    {
        let table = write.open_table(BACKFILL_PROGRESS)?;
        for entry in table.iter()? {
            let (_, value) = entry?;
            let progress: BackfillProgress = decode_record(value.value())?;
            if progress.next_position.block_height == delta.anchor.height {
                progress_rows.push(progress);
            }
        }
    }
    if progress_rows.is_empty() {
        return Ok(());
    }
    let next_height = delta
        .anchor
        .height
        .checked_add(1)
        .ok_or(StoreError::HeightOverflow)?;
    for mut progress in progress_rows {
        let before = read_contract_from_write(write, progress.contract_id)?
            .ok_or(StoreError::ContractNotFound(progress.contract_id))?;
        if !matches!(before.sync_state, ContractSyncState::CatchingUp { .. }) {
            continue;
        }
        let transition_count = delta
            .relevant_transactions
            .iter()
            .flat_map(|transaction| &transaction.state_updates)
            .filter(|update| update.contract_id == progress.contract_id)
            .count();
        if transition_count == 0 {
            undo.contract_changes.push(ContractUndo {
                contract_id: progress.contract_id,
                before: Some(before.clone()),
            });
        }
        undo.backfill_progress_changes.push(BackfillProgressUndo {
            contract_id: progress.contract_id,
            before: Some(progress.clone()),
        });
        remove_contract(write, &before)?;
        let mut after = before;
        after.sync_state = ContractSyncState::Ready {
            synced_through: delta.anchor,
        };
        insert_contract(write, &after)?;

        progress.pinned_tip = delta.anchor;
        progress.next_position = ChainPosition {
            block_height: next_height,
            tx_index: 0,
        };
        progress.last_applied = Some((delta.anchor, block_digest));
        write_fixed(
            write,
            BACKFILL_PROGRESS,
            &progress.contract_id.to_fixed_key(),
            &progress,
        )?;
        append_event(
            write,
            StoredEvent::BackfillApplied {
                contract_id: progress.contract_id,
                through: delta.anchor,
                transition_count: u32::try_from(transition_count)
                    .map_err(|_| StoreError::TransitionCountOverflow)?,
            },
        )?;
        append_event(
            write,
            StoredEvent::ContractReady {
                contract_id: progress.contract_id,
                through: delta.anchor,
            },
        )?;
    }
    Ok(())
}

fn validate_tracked_inputs(
    write: &WriteTransaction,
    delta: &ChainTxDelta,
) -> Result<(), StoreError> {
    let mut declared = HashMap::new();
    for update in &delta.state_updates {
        for outpoint in &update.spent_outpoints {
            if declared.insert(*outpoint, update.contract_id).is_some() {
                return Err(StoreError::InvalidTransition(
                    "one tracked outpoint is declared by multiple legs".to_owned(),
                ));
            }
        }
    }
    let transaction_inputs = delta
        .raw_tx
        .input
        .iter()
        .map(|input| input.previous_output)
        .collect::<HashSet<_>>();
    for outpoint in declared.keys() {
        if !transaction_inputs.contains(outpoint) {
            return Err(StoreError::InvalidTransition(
                "declared spent outpoint is not a transaction input".to_owned(),
            ));
        }
    }
    for outpoint in transaction_inputs {
        let owner = read_fixed_from_write::<OutpointOwner, 36>(
            write,
            OUTPOINT_OWNERS,
            &outpoint_fixed_key(outpoint),
        )?;
        match (owner, declared.remove(&outpoint)) {
            (Some(owner), Some(contract_id)) if owner.contract_id == contract_id => {}
            (Some(owner), _) => {
                return Err(StoreError::UnaccountedTrackedInput {
                    outpoint,
                    owner: owner.contract_id,
                });
            }
            (None, Some(_)) => {
                return Err(StoreError::InvalidTransition(
                    "transition declares an untracked input".to_owned(),
                ));
            }
            (None, None) => {}
        }
    }
    if !declared.is_empty() {
        return Err(StoreError::InvalidTransition(
            "transition contains unmatched spent outpoints".to_owned(),
        ));
    }
    Ok(())
}

fn ensure_all_outpoints_spent(
    record: &ContractRecord,
    update: &StateUpdate,
) -> Result<(), StoreError> {
    let expected = record
        .outpoints
        .iter()
        .map(|tracked| tracked.outpoint)
        .collect::<HashSet<_>>();
    let actual = update
        .spent_outpoints
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    if expected != actual || actual.len() != update.spent_outpoints.len() {
        return Err(StoreError::InvalidTransition(
            "state update must consume every current contract outpoint exactly once".to_owned(),
        ));
    }
    Ok(())
}

fn validate_new_outpoints(
    outpoints: &[TrackedOutpoint],
    txid: Txid,
    output_count: u32,
) -> Result<(), StoreError> {
    let mut roles = HashSet::new();
    let mut values = HashSet::new();
    for tracked in outpoints {
        if tracked.outpoint.txid != txid
            || tracked.outpoint.vout >= output_count
            || !roles.insert(tracked.role)
            || !values.insert(tracked.outpoint)
        {
            return Err(StoreError::InvalidTransition(
                "new outpoint is out of range, duplicated, or belongs to another tx".to_owned(),
            ));
        }
    }
    Ok(())
}

fn update_order_book(
    record: &mut ContractRecord,
    remaining: Option<u64>,
) -> Result<(), StoreError> {
    match (record.state, remaining) {
        (ContractState::BinaryMarket(_), None) if record.order_book.is_none() => Ok(()),
        (
            ContractState::MakerOrder(MakerOrderState::Active { remaining_base, .. }),
            Some(supplied),
        ) if remaining_base == supplied => {
            let book = record.order_book.as_mut().ok_or_else(|| {
                StoreError::InvalidTransition("active order has no order-book metadata".to_owned())
            })?;
            book.remaining_base = supplied;
            Ok(())
        }
        (
            ContractState::MakerOrder(MakerOrderState::Consumed | MakerOrderState::Cancelled),
            None,
        ) => {
            record.order_book = None;
            Ok(())
        }
        _ => Err(StoreError::InvalidTransition(
            "order-book capacity disagrees with new contract state".to_owned(),
        )),
    }
}

fn insert_recovery_hint(
    write: &WriteTransaction,
    hint: &RecoveryHintDelta,
) -> Result<(), StoreError> {
    let key = recovery_key(hint.location);
    if read_fixed_from_write::<StoredRecoveryHint, 12>(write, RECOVERY_HINTS, &key)?.is_some() {
        return Err(StoreError::DuplicateRecoveryHint(hint.location));
    }
    let record = StoredRecoveryHint {
        location: hint.location,
        creation_txid: hint.creation_txid,
        family: hint.family,
        payload: hint.payload.clone(),
        associated_contract: hint.associated_contract,
    };
    write_fixed(write, RECOVERY_HINTS, &key, &record)
}

fn insert_contract(write: &WriteTransaction, record: &ContractRecord) -> Result<(), StoreError> {
    record.validate()?;
    let contract_key = record.contract_id.to_fixed_key();
    if read_contract_from_write(write, record.contract_id)?.is_some() {
        return Err(StoreError::ContractAlreadyExists(record.contract_id));
    }
    for tracked in &record.outpoints {
        let outpoint_key = outpoint_fixed_key(tracked.outpoint);
        if let Some(owner) =
            read_fixed_from_write::<OutpointOwner, 36>(write, OUTPOINT_OWNERS, &outpoint_key)?
        {
            return Err(StoreError::OutpointAlreadyOwned {
                outpoint: tracked.outpoint,
                owner: owner.contract_id,
            });
        }
        write_fixed(
            write,
            OUTPOINT_OWNERS,
            &outpoint_key,
            &OutpointOwner {
                contract_id: record.contract_id,
                role: tracked.role,
            },
        )?;
        write_fixed(
            write,
            CONTRACT_OUTPOINTS,
            &contract_outpoint_key(record.contract_id, tracked.role),
            &tracked.outpoint,
        )?;
    }
    if contract_is_live(record.state) {
        for script in &record.scripts {
            write_fixed(
                write,
                SCRIPT_INDEX,
                &script_key(record.contract_id, script),
                script,
            )?;
        }
    }
    for asset in &record.assets {
        write_fixed(
            write,
            ASSET_RELATIONS,
            &asset_key(record.contract_id, *asset),
            asset,
        )?;
    }
    if let Some(parent) = record.parent_market {
        write_fixed(
            write,
            MARKET_CHILDREN,
            &market_child_key(
                parent,
                record.contract_id,
                record.outcome_side.expect("validated maker order side"),
            ),
            &record.contract_id,
        )?;
    }
    if let Some(order) = record.order_book {
        write_fixed(
            write,
            ORDER_BOOK,
            &order_key(record.contract_id, order),
            &order,
        )?;
    }
    write_fixed(write, CONTRACTS, &contract_key, record)
}

fn remove_contract(write: &WriteTransaction, record: &ContractRecord) -> Result<(), StoreError> {
    for tracked in &record.outpoints {
        remove_fixed(
            write,
            OUTPOINT_OWNERS,
            &outpoint_fixed_key(tracked.outpoint),
        )?;
        remove_fixed(
            write,
            CONTRACT_OUTPOINTS,
            &contract_outpoint_key(record.contract_id, tracked.role),
        )?;
    }
    if contract_is_live(record.state) {
        for script in &record.scripts {
            remove_fixed(write, SCRIPT_INDEX, &script_key(record.contract_id, script))?;
        }
    }
    for asset in &record.assets {
        remove_fixed(
            write,
            ASSET_RELATIONS,
            &asset_key(record.contract_id, *asset),
        )?;
    }
    if let Some(parent) = record.parent_market {
        remove_fixed(
            write,
            MARKET_CHILDREN,
            &market_child_key(
                parent,
                record.contract_id,
                record.outcome_side.expect("validated maker order side"),
            ),
        )?;
    }
    if let Some(order) = record.order_book {
        remove_fixed(write, ORDER_BOOK, &order_key(record.contract_id, order))?;
    }
    remove_fixed(write, CONTRACTS, &record.contract_id.to_fixed_key())
}

fn collect_market_id(record: &ContractRecord, output: &mut Vec<ContractId>) {
    match record.kind {
        ContractKind::BinaryMarketV1 => output.push(record.contract_id),
        ContractKind::MakerOrderV1 => {
            if let Some(parent) = record.parent_market {
                output.push(parent);
            }
        }
        ContractKind::LmsrV1Reserved => {}
    }
}

fn contract_is_live(state: ContractState) -> bool {
    match state {
        ContractState::BinaryMarket(BinaryMarketState::Trading { .. }) => true,
        ContractState::BinaryMarket(
            BinaryMarketState::ResolvedYes {
                collateral_unredeemed,
            }
            | BinaryMarketState::ResolvedNo {
                collateral_unredeemed,
            }
            | BinaryMarketState::Expired {
                collateral_unredeemed,
            },
        ) => collateral_unredeemed != 0,
        ContractState::MakerOrder(MakerOrderState::Active { .. }) => true,
        ContractState::MakerOrder(MakerOrderState::Consumed | MakerOrderState::Cancelled) => false,
    }
}

/// Ready contracts advance under the single global chain coordinator, so
/// their effective synchronization anchor is always the snapshot tip. Keeping
/// this projection at read time avoids rewriting every contract on every
/// block while preserving the public `synced_through` invariant.
fn normalize_ready_anchor(record: &mut ContractRecord, as_of: ChainAnchor) {
    if matches!(record.sync_state, ContractSyncState::Ready { .. }) {
        record.sync_state = ContractSyncState::Ready {
            synced_through: as_of,
        };
    }
}

fn sort_dedup_contracts(contracts: &mut Vec<ContractId>) {
    contracts.sort_by_key(|contract| contract.to_fixed_key());
    contracts.dedup();
}

fn prune_undo(write: &WriteTransaction, new_height: u32) -> Result<(), StoreError> {
    let keep_from = new_height.saturating_sub(UNDO_RETENTION_BLOCKS - 1);
    let mut stale = Vec::new();
    {
        let table = write.open_table(UNDO_BLOCKS)?;
        for entry in table.iter()? {
            let (key, _) = entry?;
            let key: [u8; 4] = key
                .value()
                .try_into()
                .map_err(|_| StoreError::CorruptIndexKey("undo_blocks"))?;
            let height = u32::from_be_bytes(key);
            if height < keep_from {
                stale.push(key);
            }
        }
    }
    for key in stale {
        remove_fixed(write, UNDO_BLOCKS, &key)?;
    }
    Ok(())
}

fn undo_range_available(
    write: &WriteTransaction,
    tip_height: u32,
    ancestor_height: u32,
) -> Result<bool, StoreError> {
    for height in ancestor_height + 1..=tip_height {
        if read_fixed_from_write::<UndoBlock, 4>(write, UNDO_BLOCKS, &height.to_be_bytes())?
            .is_none()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn mark_rebuild_required(write: &WriteTransaction) -> Result<[u8; 16], StoreError> {
    if read_meta_record_from_write::<SyncStatus>(write, SYNC_STATUS_KEY)?
        == Some(SyncStatus::RescanRequired)
    {
        return Ok(high_watermark_from_write(write)?.epoch);
    }
    let epoch = random_epoch();
    {
        let mut meta = write.open_table(META)?;
        meta.insert(EVENT_EPOCH_KEY, epoch.as_slice())?;
        meta.insert(EVENT_SEQUENCE_KEY, 0_u64.to_be_bytes().as_slice())?;
    }
    write_meta_record(write, SYNC_STATUS_KEY, &SyncStatus::RescanRequired)?;
    append_event(
        write,
        StoredEvent::SyncStatusChanged {
            status: SyncStatus::RescanRequired,
        },
    )?;
    Ok(epoch)
}

fn append_event(write: &WriteTransaction, event: StoredEvent) -> Result<EventCursor, StoreError> {
    let current = high_watermark_from_write(write)?;
    let sequence = current
        .sequence
        .checked_add(1)
        .ok_or(StoreError::EventSequenceOverflow)?;
    let cursor = EventCursor {
        epoch: current.epoch,
        sequence,
    };
    let envelope = StoredEventEnvelope { cursor, event };
    write_fixed(write, EVENTS, &cursor.to_fixed_key(), &envelope)?;
    {
        let mut meta = write.open_table(META)?;
        meta.insert(EVENT_SEQUENCE_KEY, sequence.to_be_bytes().as_slice())?;
    }
    Ok(cursor)
}

fn high_watermark_from_write(write: &WriteTransaction) -> Result<EventCursor, StoreError> {
    let meta = write.open_table(META)?;
    event_cursor_from_meta(&meta)
}

fn event_cursor_from_meta(
    meta: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<EventCursor, StoreError> {
    let epoch = meta
        .get(EVENT_EPOCH_KEY)?
        .ok_or(StoreError::MissingMetadata(EVENT_EPOCH_KEY))?;
    let epoch: [u8; 16] = epoch
        .value()
        .try_into()
        .map_err(|_| StoreError::CorruptMetadata(EVENT_EPOCH_KEY))?;
    let sequence = meta
        .get(EVENT_SEQUENCE_KEY)?
        .ok_or(StoreError::MissingMetadata(EVENT_SEQUENCE_KEY))?;
    let sequence = decode_u64(sequence.value())
        .map_err(|_| StoreError::CorruptMetadata(EVENT_SEQUENCE_KEY))?;
    Ok(EventCursor { epoch, sequence })
}

fn create_tables(write: &WriteTransaction) -> Result<(), StoreError> {
    drop(write.open_table(CHAIN_TIP)?);
    drop(write.open_table(BLOCKS)?);
    drop(write.open_table(TRANSACTIONS)?);
    drop(write.open_table(OUTPUTS)?);
    drop(write.open_table(CONTRACTS)?);
    drop(write.open_table(RETAINED_DECLARATIONS)?);
    drop(write.open_table(OUTPOINT_OWNERS)?);
    drop(write.open_table(CONTRACT_OUTPOINTS)?);
    drop(write.open_table(SCRIPT_INDEX)?);
    drop(write.open_table(ASSET_RELATIONS)?);
    drop(write.open_table(MARKET_CHILDREN)?);
    drop(write.open_table(ORDER_BOOK)?);
    drop(write.open_table(RECOVERY_HINTS)?);
    drop(write.open_table(CONTRACT_HISTORY)?);
    drop(write.open_table(BACKFILL_PROGRESS)?);
    drop(write.open_table(UNDO_BLOCKS)?);
    drop(write.open_table(EVENTS)?);
    Ok(())
}

fn clear_chain_tables(write: &WriteTransaction) -> Result<(), StoreError> {
    write.open_table(BLOCKS)?.retain(|_, _| false)?;
    write.open_table(TRANSACTIONS)?.retain(|_, _| false)?;
    write.open_table(OUTPUTS)?.retain(|_, _| false)?;
    write.open_table(CONTRACTS)?.retain(|_, _| false)?;
    write.open_table(OUTPOINT_OWNERS)?.retain(|_, _| false)?;
    write.open_table(CONTRACT_OUTPOINTS)?.retain(|_, _| false)?;
    write.open_table(SCRIPT_INDEX)?.retain(|_, _| false)?;
    write.open_table(ASSET_RELATIONS)?.retain(|_, _| false)?;
    write.open_table(MARKET_CHILDREN)?.retain(|_, _| false)?;
    write.open_table(ORDER_BOOK)?.retain(|_, _| false)?;
    write.open_table(RECOVERY_HINTS)?.retain(|_, _| false)?;
    write.open_table(CONTRACT_HISTORY)?.retain(|_, _| false)?;
    write.open_table(BACKFILL_PROGRESS)?.retain(|_, _| false)?;
    write.open_table(UNDO_BLOCKS)?.retain(|_, _| false)?;
    write.open_table(CHAIN_TIP)?.retain(|_, _| false)?;
    Ok(())
}

fn tip_from_write(write: &WriteTransaction) -> Result<Option<ChainAnchor>, StoreError> {
    let table = write.open_table(CHAIN_TIP)?;
    table
        .get(TIP_KEY)?
        .map(|value| decode_record(value.value()))
        .transpose()
}

fn snapshot_from_read(read: &ReadTransaction) -> Result<StoreSnapshotMetadata, StoreError> {
    let tips = read.open_table(CHAIN_TIP)?;
    let as_of = tips
        .get(TIP_KEY)?
        .map(|value| decode_record(value.value()))
        .transpose()?
        .ok_or(StoreError::TipNotInitialized)?;
    let meta = read.open_table(META)?;
    Ok(StoreSnapshotMetadata {
        as_of,
        event_high_watermark: event_cursor_from_meta(&meta)?,
    })
}

fn status_snapshot_from_read(read: &ReadTransaction) -> Result<StoreStatusSnapshot, StoreError> {
    let tips = read.open_table(CHAIN_TIP)?;
    let indexed_tip = tips
        .get(TIP_KEY)?
        .map(|value| decode_record(value.value()))
        .transpose()?
        .ok_or(StoreError::TipNotInitialized)?;
    let meta = read.open_table(META)?;
    let activation_anchor = meta
        .get(ACTIVATION_ANCHOR_KEY)?
        .map(|value| decode_record(value.value()))
        .transpose()?
        .ok_or(StoreError::MissingMetadata(ACTIVATION_ANCHOR_KEY))?;
    let sync_status = meta
        .get(SYNC_STATUS_KEY)?
        .map(|value| decode_record(value.value()))
        .transpose()?
        .ok_or(StoreError::MissingMetadata(SYNC_STATUS_KEY))?;
    Ok(StoreStatusSnapshot {
        indexed_tip,
        activation_anchor,
        sync_status,
        event_high_watermark: event_cursor_from_meta(&meta)?,
    })
}

fn validate_event_cursor(after: Option<EventCursor>, high: EventCursor) -> Result<u64, StoreError> {
    match after {
        Some(cursor) if cursor.epoch != high.epoch => Err(StoreError::StaleCursor {
            expected_epoch: high.epoch,
            actual_epoch: cursor.epoch,
        }),
        Some(cursor) if cursor.sequence > high.sequence => Err(StoreError::CursorAhead {
            requested: cursor.sequence,
            high_watermark: high.sequence,
        }),
        Some(cursor) => Ok(cursor.sequence),
        None => Ok(0),
    }
}

fn validate_query_limit(limit: usize) -> Result<(), StoreError> {
    if limit == 0 {
        Err(StoreError::InvalidQueryLimit)
    } else {
        Ok(())
    }
}

fn validate_snapshot_cursor(
    cursor: Option<&StoreSnapshotCursor>,
    snapshot: StoreSnapshotMetadata,
    scope: SnapshotScope,
    key_len: usize,
) -> Result<(), StoreError> {
    let Some(cursor) = cursor else {
        return Ok(());
    };
    if cursor.as_of != snapshot.as_of
        || cursor.event_high_watermark != snapshot.event_high_watermark
    {
        return Err(StoreError::StaleSnapshotCursor {
            expected: Box::new(snapshot),
            actual: Box::new(StoreSnapshotMetadata {
                as_of: cursor.as_of,
                event_high_watermark: cursor.event_high_watermark,
            }),
        });
    }
    if cursor.after_key.len() != key_len {
        return Err(StoreError::InvalidSnapshotKey {
            expected: key_len,
            actual: cursor.after_key.len(),
        });
    }
    if cursor.scope != scope {
        return Err(StoreError::SnapshotScopeMismatch {
            expected: scope,
            actual: cursor.scope,
        });
    }
    Ok(())
}

fn materialized_page<T>(
    snapshot: StoreSnapshotMetadata,
    scope: SnapshotScope,
    mut rows: Vec<(Vec<u8>, T)>,
    limit: usize,
) -> Result<MaterializedPage<T>, StoreError> {
    let truncated = rows.len() > limit;
    if truncated {
        rows.pop();
    }
    let next = truncated.then(|| StoreSnapshotCursor {
        as_of: snapshot.as_of,
        event_high_watermark: snapshot.event_high_watermark,
        scope,
        after_key: rows
            .last()
            .expect("a nonzero page limit retains a row")
            .0
            .clone(),
    });
    Ok(MaterializedPage {
        snapshot,
        items: rows.into_iter().map(|(_, item)| item).collect(),
        next,
    })
}

fn decode_contract_key(bytes: &[u8]) -> Result<ContractId, StoreError> {
    let bytes: [u8; 36] = bytes
        .try_into()
        .map_err(|_| StoreError::CorruptIndexKey("contract_id"))?;
    let txid = Txid::from_byte_array(
        bytes[..32]
            .try_into()
            .map_err(|_| StoreError::CorruptIndexKey("contract_id"))?,
    );
    let vout = u32::from_be_bytes(
        bytes[32..]
            .try_into()
            .map_err(|_| StoreError::CorruptIndexKey("contract_id"))?,
    );
    Ok(ContractId::new(OutPoint::new(txid, vout)))
}

fn canonical_anchor_from_write(
    write: &WriteTransaction,
    height: u32,
) -> Result<Option<ChainAnchor>, StoreError> {
    let Some(tip) = tip_from_write(write)? else {
        return Ok(None);
    };
    if height > tip.height {
        return Ok(None);
    }
    if height == tip.height {
        return Ok(Some(tip));
    }
    if let Some(block) =
        read_fixed_from_write::<StoredBlock, 4>(write, BLOCKS, &height.to_be_bytes())?
    {
        return Ok(Some(block.anchor));
    }
    let Some(next_height) = height.checked_add(1) else {
        return Ok(None);
    };
    Ok(
        read_fixed_from_write::<StoredBlock, 4>(write, BLOCKS, &next_height.to_be_bytes())?.map(
            |next| ChainAnchor {
                height,
                hash: next.prev_block_hash,
            },
        ),
    )
}

fn write_tip(write: &WriteTransaction, anchor: ChainAnchor) -> Result<(), StoreError> {
    let encoded = encode_record(&anchor)?;
    write
        .open_table(CHAIN_TIP)?
        .insert(TIP_KEY, encoded.as_slice())?;
    Ok(())
}

fn read_contract_from_write(
    write: &WriteTransaction,
    contract_id: ContractId,
) -> Result<Option<ContractRecord>, StoreError> {
    read_fixed_from_write(write, CONTRACTS, &contract_id.to_fixed_key())
}

fn read_meta_record_from_write<T: DeserializeOwned>(
    write: &WriteTransaction,
    key: &'static str,
) -> Result<Option<T>, StoreError> {
    let table = write.open_table(META)?;
    table
        .get(key)?
        .map(|value| decode_record(value.value()))
        .transpose()
}

fn write_meta_record<T: Serialize>(
    write: &WriteTransaction,
    key: &'static str,
    value: &T,
) -> Result<(), StoreError> {
    let encoded = encode_record(value)?;
    write.open_table(META)?.insert(key, encoded.as_slice())?;
    Ok(())
}

fn read_fixed_from_write<T: DeserializeOwned, const N: usize>(
    write: &WriteTransaction,
    definition: TableDefinition<&[u8], &[u8]>,
    key: &[u8; N],
) -> Result<Option<T>, StoreError> {
    let table = write.open_table(definition)?;
    table
        .get(key.as_slice())?
        .map(|value| decode_record(value.value()))
        .transpose()
}

fn write_fixed<T: Serialize, const N: usize>(
    write: &WriteTransaction,
    definition: TableDefinition<&[u8], &[u8]>,
    key: &[u8; N],
    value: &T,
) -> Result<(), StoreError> {
    let encoded = encode_record(value)?;
    write
        .open_table(definition)?
        .insert(key.as_slice(), encoded.as_slice())?;
    Ok(())
}

fn remove_fixed<const N: usize>(
    write: &WriteTransaction,
    definition: TableDefinition<&[u8], &[u8]>,
    key: &[u8; N],
) -> Result<(), StoreError> {
    write.open_table(definition)?.remove(key.as_slice())?;
    Ok(())
}

fn encode_record<T: Serialize>(value: &T) -> Result<Vec<u8>, StoreError> {
    let mut encoded = Vec::with_capacity(64);
    encoded.push(RECORD_VERSION);
    encoded.extend(postcard::to_allocvec(value)?);
    Ok(encoded)
}

fn decode_record<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, StoreError> {
    let (&version, payload) = bytes.split_first().ok_or(StoreError::EmptyRecord)?;
    if version != RECORD_VERSION {
        return Err(StoreError::RecordVersionMismatch {
            expected: RECORD_VERSION,
            actual: version,
        });
    }
    Ok(postcard::from_bytes(payload)?)
}

fn digest<T: Serialize>(value: &T) -> Result<[u8; 32], StoreError> {
    let encoded = postcard::to_allocvec(value)?;
    Ok(Sha256::digest(encoded).into())
}

fn random_epoch() -> [u8; 16] {
    let mut epoch = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut epoch);
    epoch
}

fn ensure_metadata(
    meta: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &'static str,
    expected_len: usize,
) -> Result<(), StoreError> {
    let value = meta.get(key)?.ok_or(StoreError::MissingMetadata(key))?;
    if value.value().len() != expected_len {
        return Err(StoreError::CorruptMetadata(key));
    }
    Ok(())
}

fn decode_u32(bytes: &[u8]) -> Result<u32, ()> {
    Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| ())?))
}

fn decode_u64(bytes: &[u8]) -> Result<u64, ()> {
    Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| ())?))
}

fn outpoint_fixed_key(outpoint: OutPoint) -> [u8; 36] {
    let mut key = [0_u8; 36];
    key[..32].copy_from_slice(&outpoint.txid.to_byte_array());
    key[32..].copy_from_slice(&outpoint.vout.to_be_bytes());
    key
}

fn history_key(contract_id: ContractId, position: ChainPosition) -> [u8; 44] {
    let mut key = [0_u8; 44];
    key[..36].copy_from_slice(&contract_id.to_fixed_key());
    key[36..].copy_from_slice(&position.to_fixed_key());
    key
}

fn recovery_key(location: RecoveryHintLocation) -> [u8; 12] {
    let mut key = [0_u8; 12];
    key[..8].copy_from_slice(&location.position.to_fixed_key());
    key[8..].copy_from_slice(&location.output_index.to_be_bytes());
    key
}

fn contract_outpoint_key(contract_id: ContractId, role: u8) -> [u8; 37] {
    let mut key = [0_u8; 37];
    key[..36].copy_from_slice(&contract_id.to_fixed_key());
    key[36] = role;
    key
}

fn script_hash(script: &[u8]) -> [u8; 32] {
    Sha256::digest(script).into()
}

fn script_key(contract_id: ContractId, binding: &ScriptBinding) -> [u8; 69] {
    let mut key = [0_u8; 69];
    key[..32].copy_from_slice(&script_hash(&binding.script_pubkey));
    key[32..68].copy_from_slice(&contract_id.to_fixed_key());
    key[68] = binding.role;
    key
}

fn asset_key(contract_id: ContractId, binding: AssetBinding) -> [u8; 70] {
    let mut key = [0_u8; 70];
    key[..32].copy_from_slice(&binding.asset_id.into_inner().to_byte_array());
    key[32] = binding.relation.tag();
    key[33..69].copy_from_slice(&contract_id.to_fixed_key());
    key[69] = binding.role;
    key
}

fn market_child_key(parent: ContractId, child: ContractId, side: OrderSide) -> [u8; 74] {
    let mut key = [0_u8; 74];
    key[..36].copy_from_slice(&parent.to_fixed_key());
    key[36] = match side {
        OrderSide::Yes => 0,
        OrderSide::No => 1,
    };
    key[37] = 0; // v1 child kind: maker order
    key[38..].copy_from_slice(&child.to_fixed_key());
    key
}

fn order_key(contract_id: ContractId, order: OrderBookEntry) -> [u8; 86] {
    let mut key = [0_u8; 86];
    key[..36].copy_from_slice(&order.market_id.to_fixed_key());
    key[36] = match order.side {
        OrderSide::Yes => 0,
        OrderSide::No => 1,
    };
    key[37] = order.direction.protocol_byte();
    key[38..42].copy_from_slice(&order.price.to_be_bytes());
    key[42..50].copy_from_slice(&order.creation_position.to_fixed_key());
    key[50..].copy_from_slice(&contract_id.to_fixed_key());
    key
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("redb database error: {0}")]
    Database(#[from] redb::DatabaseError),
    #[error("redb transaction error: {0}")]
    Transaction(#[from] redb::TransactionError),
    #[error("redb table error: {0}")]
    Table(#[from] redb::TableError),
    #[error("redb storage error: {0}")]
    Storage(#[from] redb::StorageError),
    #[error("redb commit error: {0}")]
    Commit(#[from] redb::CommitError),
    #[error("record codec error: {0}")]
    Codec(#[from] postcard::Error),
    #[error("consensus transaction decode failed: {0}")]
    ConsensusDecode(String),
    #[error("output index is absent from its transaction: {0:?}")]
    MissingOutput(OutPoint),
    #[error("output references a missing canonical transaction at {0:?}")]
    MissingOutputTransaction(ChainPosition),
    #[error("redb schema version has an invalid encoding")]
    CorruptSchemaVersion,
    #[error("schema mismatch: expected {expected}, found {actual}")]
    SchemaMismatch { expected: u32, actual: u32 },
    #[error("required metadata is missing: {0}")]
    MissingMetadata(&'static str),
    #[error("metadata has an invalid encoding: {0}")]
    CorruptMetadata(&'static str),
    #[error("persisted index key has an invalid encoding: {0}")]
    CorruptIndexKey(&'static str),
    #[error("materialized index points to missing state: {0}")]
    CorruptMaterializedIndex(&'static str),
    #[error("materialized market was not found: {0:?}")]
    MaterializedMarketNotFound(ContractId),
    #[error("materialized contract is not a binary market: {0:?}")]
    MaterializedContractIsNotMarket(ContractId),
    #[error("materialized market is not ready: {0:?}")]
    MaterializedMarketNotReady(ContractId),
    #[error("persisted record is empty")]
    EmptyRecord,
    #[error("record version mismatch: expected {expected}, found {actual}")]
    RecordVersionMismatch { expected: u8, actual: u8 },
    #[error("chain identity mismatch: database has {expected:?}, requested {actual:?}")]
    ChainIdentityMismatch {
        expected: Box<ChainIdentity>,
        actual: Box<ChainIdentity>,
    },
    #[error("activation anchor mismatch: database has {expected:?}, requested {actual:?}")]
    ActivationAnchorMismatch {
        expected: ChainAnchor,
        actual: ChainAnchor,
    },
    #[error("v1 activation checkpoint is not initialized")]
    ActivationNotInitialized,
    #[error("database has only part of its chain identity, activation anchor, and tip")]
    IncompleteChainConfiguration,
    #[error("indexed tip {tip:?} is before activation checkpoint {activation:?}")]
    TipBeforeActivation {
        tip: ChainAnchor,
        activation: ChainAnchor,
    },
    #[error("activation checkpoint {expected:?} is not canonical in the database: {actual:?}")]
    ActivationAnchorNotCanonical {
        expected: ChainAnchor,
        actual: Option<ChainAnchor>,
    },
    #[error("chain tip is not initialized")]
    TipNotInitialized,
    #[error("chain tip already initialized to {current:?}, not {requested:?}")]
    TipAlreadyInitialized {
        current: ChainAnchor,
        requested: ChainAnchor,
    },
    #[error("block height overflow")]
    HeightOverflow,
    #[error("chain position overflow")]
    PositionOverflow,
    #[error(
        "block is not contiguous: current {current:?}, proposed {proposed:?}, prev {proposed_previous_hash}"
    )]
    NonContiguousBlock {
        current: ChainAnchor,
        proposed: ChainAnchor,
        proposed_previous_hash: BlockHash,
    },
    #[error("fork conflict at occupied height {height}")]
    ForkConflict { height: u32 },
    #[error("invalid block delta: {0}")]
    InvalidBlock(String),
    #[error("invalid contract: {0}")]
    InvalidContract(String),
    #[error("invalid transition: {0}")]
    InvalidTransition(String),
    #[error("contract already exists: {0:?}")]
    ContractAlreadyExists(ContractId),
    #[error("invalid canonical registration evidence: {0}")]
    InvalidRegistrationEvidence(String),
    #[error("canonical registration transaction is missing at {0:?}")]
    MissingRegistrationTransaction(ChainPosition),
    #[error("canonical registration transaction conflicts at {0:?}")]
    RegistrationTransactionConflict(ChainPosition),
    #[error("contract not found: {0:?}")]
    ContractNotFound(ContractId),
    #[error("old state does not match current state for {contract_id:?}")]
    StateMismatch { contract_id: ContractId },
    #[error("outpoint {outpoint:?} is already owned by {owner:?}")]
    OutpointAlreadyOwned {
        outpoint: OutPoint,
        owner: ContractId,
    },
    #[error("tracked input {outpoint:?} owned by {owner:?} has no matching transition leg")]
    UnaccountedTrackedInput {
        outpoint: OutPoint,
        owner: ContractId,
    },
    #[error("duplicate contract history at {contract_id:?} {position:?}")]
    DuplicateHistory {
        contract_id: ContractId,
        position: ChainPosition,
    },
    #[error("duplicate recovery hint at {0:?}")]
    DuplicateRecoveryHint(RecoveryHintLocation),
    #[error("missing durable backfill progress for {0:?}")]
    MissingBackfillProgress(ContractId),
    #[error("invalid backfill batch: {0}")]
    InvalidBackfill(String),
    #[error("backfill block is no longer canonical: {anchor:?}")]
    BackfillBranchChanged { anchor: ChainAnchor },
    #[error("backfill cursor for {contract_id:?} is {expected:?}, not block {block_height}")]
    BackfillPositionMismatch {
        contract_id: ContractId,
        expected: ChainPosition,
        block_height: u32,
    },
    #[error("canonical transaction conflicts with backfill at {0:?}")]
    BackfillTransactionConflict(ChainPosition),
    #[error("backfill transition count overflow")]
    TransitionCountOverflow,
    #[error("event cursor epoch is stale")]
    StaleCursor {
        expected_epoch: [u8; 16],
        actual_epoch: [u8; 16],
    },
    #[error("event cursor {requested} is ahead of high-watermark {high_watermark}")]
    CursorAhead { requested: u64, high_watermark: u64 },
    #[error("materialized query limit must be nonzero")]
    InvalidQueryLimit,
    #[error("snapshot cursor key has length {actual}, expected {expected}")]
    InvalidSnapshotKey { expected: usize, actual: usize },
    #[error("snapshot cursor is stale: expected {expected:?}, got {actual:?}")]
    StaleSnapshotCursor {
        expected: Box<StoreSnapshotMetadata>,
        actual: Box<StoreSnapshotMetadata>,
    },
    #[error("snapshot cursor scope mismatch: expected {expected:?}, got {actual:?}")]
    SnapshotScopeMismatch {
        expected: SnapshotScope,
        actual: SnapshotScope,
    },
    #[error("event sequence overflow")]
    EventSequenceOverflow,
    #[error("incremental block application is disabled until an explicit rebuild reset")]
    RebuildRequired,
    #[error("cannot reset canonical state when a rebuild is not required")]
    RebuildNotRequired,
    #[error("contract creation is not after v1 activation checkpoint {activation:?}")]
    PreActivationContract { activation: ChainAnchor },
    #[error("invalid rollback target {ancestor:?} from {old_tip:?}")]
    InvalidRollbackTarget {
        old_tip: ChainAnchor,
        ancestor: ChainAnchor,
    },
    #[error("missing undo journal for block {height}")]
    MissingUndo { height: u32 },
    #[error("rollback restored {restored:?}, expected ancestor {expected:?}")]
    AncestorMismatch {
        expected: ChainAnchor,
        restored: ChainAnchor,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::{LockTime, OutPoint, TxIn};

    fn block_hash(byte: u8) -> BlockHash {
        BlockHash::from_byte_array([byte; 32])
    }

    fn anchor(height: u32) -> ChainAnchor {
        ChainAnchor {
            height,
            hash: block_hash(u8::try_from(height).expect("small test height")),
        }
    }

    fn asset(byte: u8) -> AssetId {
        AssetId::from_slice(&[byte; 32]).expect("asset")
    }

    fn transaction(tag: u32, inputs: &[OutPoint], output_count: usize) -> Transaction {
        Transaction {
            version: 2,
            lock_time: LockTime::from_consensus(tag),
            input: inputs
                .iter()
                .map(|outpoint| TxIn {
                    previous_output: *outpoint,
                    ..TxIn::default()
                })
                .collect(),
            output: (0..output_count)
                .map(|index| {
                    TxOut::new_fee(
                        u64::try_from(index + 1).expect("small output count"),
                        asset(0x90),
                    )
                })
                .collect(),
        }
    }

    fn market_record(
        marker: u8,
        creation_position: ChainPosition,
        txid: Txid,
        vout: u32,
        outstanding_pairs: u64,
        synced_through: ChainAnchor,
    ) -> ContractRecord {
        let contract_id = ContractId::new(OutPoint::new(txid, vout));
        ContractRecord {
            contract_id,
            kind: ContractKind::BinaryMarketV1,
            params: ContractParameters::BinaryMarket(BinaryMarketParams {
                oracle_public_key: [marker.wrapping_add(1); 32],
                collateral_asset_id: asset(marker.wrapping_add(2)),
                yes_token_asset_id: asset(marker.wrapping_add(3)),
                no_token_asset_id: asset(marker.wrapping_add(4)),
                yes_reissuance_token_id: asset(marker.wrapping_add(5)),
                no_reissuance_token_id: asset(marker.wrapping_add(6)),
                base_payout: 100,
                expiry_height: 100,
            }),
            creation_position,
            state: ContractState::BinaryMarket(BinaryMarketState::Trading { outstanding_pairs }),
            sync_state: ContractSyncState::Ready { synced_through },
            parent_market: None,
            outcome_side: None,
            scripts: vec![ScriptBinding {
                role: 0,
                script_pubkey: vec![marker, 0x51],
            }],
            assets: vec![AssetBinding {
                asset_id: asset(marker.wrapping_add(2)),
                relation: AssetRelationKind::Collateral,
                role: 0,
            }],
            outpoints: vec![TrackedOutpoint {
                role: 0,
                outpoint: OutPoint::new(txid, vout),
            }],
            order_book: None,
        }
    }

    fn update_market(
        contract: &ContractRecord,
        spending_txid: Txid,
        vout: u32,
        new_pairs: u64,
    ) -> StateUpdate {
        StateUpdate {
            contract_id: contract.contract_id,
            old_state: contract.state,
            new_state: ContractState::BinaryMarket(BinaryMarketState::Trading {
                outstanding_pairs: new_pairs,
            }),
            spent_outpoints: contract
                .outpoints
                .iter()
                .map(|tracked| tracked.outpoint)
                .collect(),
            new_outpoints: vec![TrackedOutpoint {
                role: 0,
                outpoint: OutPoint::new(spending_txid, vout),
            }],
            order_remaining_base: None,
            transition: TransitionRecord {
                kind: 1,
                payload: new_pairs.to_be_bytes().to_vec(),
            },
        }
    }

    fn block(
        height: u32,
        transactions: Vec<ChainTxDelta>,
        recovery_hints: Vec<RecoveryHintDelta>,
    ) -> BlockDelta {
        let ordered_txids = transactions.iter().map(|tx| tx.txid).collect();
        BlockDelta {
            anchor: anchor(height),
            prev_block_hash: anchor(height - 1).hash,
            ordered_txids,
            relevant_transactions: transactions,
            recovery_hints,
        }
    }

    fn empty_block(height: u32) -> BlockDelta {
        let transaction = transaction(height + 10_000, &[], 1);
        BlockDelta {
            anchor: anchor(height),
            prev_block_hash: anchor(height - 1).hash,
            ordered_txids: vec![transaction.txid()],
            relevant_transactions: Vec::new(),
            recovery_hints: Vec::new(),
        }
    }

    fn initialized_store() -> (tempfile::TempDir, std::path::PathBuf, Store) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("deadcat.redb");
        let store = Store::open(&path).expect("open");
        store.initialize_tip(anchor(0)).expect("initial tip");
        (dir, path, store)
    }

    #[test]
    fn schema_chain_identity_epoch_and_state_survive_reopen() {
        let (dir, path, store) = initialized_store();
        let identity = ChainIdentity {
            network: LiquidNetwork::ElementsRegtest,
            genesis_hash: block_hash(0xaa),
            policy_asset: asset(0xbb),
        };
        store.bind_chain(identity).expect("bind chain");
        assert!(matches!(
            store.bind_chain(ChainIdentity {
                network: LiquidNetwork::LiquidTestnet,
                ..identity
            }),
            Err(StoreError::ChainIdentityMismatch { .. })
        ));
        let cursor = store
            .set_sync_status(SyncStatus::Syncing)
            .expect("sync event");
        assert_eq!(store.schema_version().expect("schema"), SCHEMA_VERSION);
        drop(store);

        let reopened = Store::open(&path).expect("reopen");
        assert_eq!(reopened.chain_identity().expect("identity"), Some(identity));
        assert_eq!(reopened.tip().expect("tip"), Some(anchor(0)));
        assert_eq!(reopened.sync_status().expect("status"), SyncStatus::Syncing);
        assert_eq!(reopened.event_high_watermark().expect("cursor"), cursor);
        assert_eq!(reopened.events_after(None, 10).expect("events").len(), 1);
        drop(reopened);
        drop(dir);
    }

    #[test]
    fn late_registration_is_persisted_once_in_catching_up_state() {
        let (_dir, _path, store) = initialized_store();
        let transaction = transaction(77, &[], 1);
        let mut market = market_record(
            0x6a,
            ChainPosition {
                block_height: 0,
                tx_index: 0,
            },
            transaction.txid(),
            0,
            0,
            anchor(0),
        );
        market.sync_state = ContractSyncState::CatchingUp {
            synced_through: anchor(0),
        };

        let evidence = RegistrationEvidence {
            anchor: anchor(0),
            transaction: Arc::new(transaction.clone()),
            associated_hint: None,
        };
        assert!(
            store
                .register_contract(&market, &evidence)
                .expect("register")
        );
        assert!(
            !store
                .register_contract(&market, &evidence)
                .expect("idempotent")
        );
        assert_eq!(
            store.contract(market.contract_id).expect("read"),
            Some(market.clone())
        );
        let expected_declaration = declaration_from_record(&market).expect("declaration");
        assert_eq!(
            store
                .retained_declaration(market.contract_id)
                .expect("retained declaration"),
            Some(expected_declaration)
        );
        assert_eq!(
            store
                .retained_declarations_for_txid(transaction.txid())
                .expect("declarations by txid"),
            vec![expected_declaration]
        );
        let unrelated_txid = Txid::from_byte_array([0xee; 32]);
        let prefetched = store
            .retained_declarations_for_transactions(&[unrelated_txid, transaction.txid()])
            .expect("block declaration prefetch");
        assert_eq!(prefetched.len(), 1);
        assert_eq!(
            prefetched
                .get(&transaction.txid())
                .expect("matching prefetched transaction")
                .as_slice(),
            &[expected_declaration]
        );
        assert!(!prefetched.contains_key(&unrelated_txid));
        let events = store.events_after(None, 10).expect("events");
        assert!(matches!(
            events.as_slice(),
            [StoredEventEnvelope {
                event: StoredEvent::ContractRegistered { contract_id },
                ..
            }] if *contract_id == market.contract_id
        ));
        assert_eq!(
            store
                .output(market.outpoints[0].outpoint)
                .expect("creation output")
                .expect("stored output")
                .output,
            transaction.output[0]
        );
    }

    #[test]
    fn registration_is_rejected_without_mutation_while_rebuild_is_required() {
        let (_dir, _path, store) = initialized_store();
        let creation = transaction(770, &[], 1);
        let position = ChainPosition {
            block_height: 0,
            tx_index: 0,
        };
        let mut market = market_record(0x6d, position, creation.txid(), 0, 0, anchor(0));
        market.sync_state = ContractSyncState::CatchingUp {
            synced_through: anchor(0),
        };
        let evidence = RegistrationEvidence {
            anchor: anchor(0),
            transaction: Arc::new(creation),
            associated_hint: None,
        };

        store.invalidate_for_rebuild().expect("invalidate");
        let high = store.event_high_watermark().expect("high watermark");
        assert!(matches!(
            store.register_contract(&market, &evidence),
            Err(StoreError::RebuildRequired)
        ));

        assert_eq!(store.event_high_watermark().expect("high watermark"), high);
        assert!(
            store
                .contract(market.contract_id)
                .expect("contract")
                .is_none()
        );
        assert!(store.transaction(position).expect("transaction").is_none());
        assert!(
            store
                .output(market.contract_id.creation_anchor())
                .expect("output")
                .is_none()
        );
        assert!(
            store
                .outpoint_owner(market.contract_id.creation_anchor())
                .expect("owner")
                .is_none()
        );
        assert!(
            store
                .backfill_progress(market.contract_id)
                .expect("progress")
                .is_none()
        );
    }

    #[test]
    fn script_index_allows_multiple_contract_instances_of_one_script() {
        let (_dir, _path, store) = initialized_store();
        let first_tx = transaction(78, &[], 1);
        let second_tx = transaction(79, &[], 1);
        let mut first = market_record(
            0x6b,
            ChainPosition {
                block_height: 0,
                tx_index: 0,
            },
            first_tx.txid(),
            0,
            0,
            anchor(0),
        );
        first.sync_state = ContractSyncState::CatchingUp {
            synced_through: anchor(0),
        };
        let mut second = first.clone();
        second.contract_id = ContractId::new(OutPoint::new(second_tx.txid(), 0));
        second.creation_position.tx_index = 1;
        second.outpoints[0].outpoint = OutPoint::new(second_tx.txid(), 0);

        assert!(
            store
                .register_contract(
                    &first,
                    &RegistrationEvidence {
                        anchor: anchor(0),
                        transaction: Arc::new(first_tx),
                        associated_hint: None,
                    },
                )
                .expect("first")
        );
        assert!(
            store
                .register_contract(
                    &second,
                    &RegistrationEvidence {
                        anchor: anchor(0),
                        transaction: Arc::new(second_tx),
                        associated_hint: None,
                    },
                )
                .expect("second")
        );
        assert!(
            store
                .contract(first.contract_id)
                .expect("first read")
                .is_some()
        );
        assert!(
            store
                .contract(second.contract_id)
                .expect("second read")
                .is_some()
        );
    }

    #[test]
    fn registration_evidence_merges_composed_contracts_and_preserves_outputs() {
        let (_dir, _path, store) = initialized_store();
        let creation = transaction(80, &[], 2);
        let position = ChainPosition {
            block_height: 0,
            tx_index: 0,
        };
        let mut first = market_record(0x6c, position, creation.txid(), 0, 0, anchor(0));
        first.sync_state = ContractSyncState::CatchingUp {
            synced_through: anchor(0),
        };
        let mut second = market_record(0x7c, position, creation.txid(), 1, 0, anchor(0));
        second.sync_state = ContractSyncState::CatchingUp {
            synced_through: anchor(0),
        };
        let evidence = RegistrationEvidence {
            anchor: anchor(0),
            transaction: Arc::new(creation.clone()),
            associated_hint: None,
        };

        let results = store
            .register_contracts(&[
                (first.clone(), evidence.clone()),
                (second.clone(), evidence),
            ])
            .expect("atomic composed registration");
        assert_eq!(
            results
                .iter()
                .map(|result| (result.record.contract_id, result.inserted))
                .collect::<Vec<_>>(),
            vec![(first.contract_id, true), (second.contract_id, true)]
        );

        let stored = store.transaction(position).expect("transaction").unwrap();
        let mut expected_ids = vec![first.contract_id, second.contract_id];
        sort_dedup_contracts(&mut expected_ids);
        assert_eq!(stored.affected_contract_ids, expected_ids);
        assert_eq!(
            store
                .output(first.outpoints[0].outpoint)
                .expect("first output")
                .unwrap()
                .output,
            creation.output[0]
        );
        assert_eq!(
            store
                .output(second.outpoints[0].outpoint)
                .expect("second output")
                .unwrap()
                .output,
            creation.output[1]
        );
    }

    #[test]
    fn composed_registration_has_one_transaction_undo_leg_and_rolls_back_together() {
        let (_dir, _path, store) = initialized_store();
        let creation = transaction(800, &[], 3);
        let position = ChainPosition {
            block_height: 1,
            tx_index: 0,
        };
        store
            .apply_block(&BlockDelta {
                anchor: anchor(1),
                prev_block_hash: anchor(0).hash,
                ordered_txids: vec![creation.txid()],
                relevant_transactions: Vec::new(),
                recovery_hints: Vec::new(),
            })
            .expect("index creation block before late registration");

        let mut first = market_record(0x6d, position, creation.txid(), 0, 0, anchor(1));
        first.sync_state = ContractSyncState::CatchingUp {
            synced_through: anchor(1),
        };
        let mut second = market_record(0x7d, position, creation.txid(), 1, 0, anchor(1));
        second.sync_state = ContractSyncState::CatchingUp {
            synced_through: anchor(1),
        };
        let evidence = RegistrationEvidence {
            anchor: anchor(1),
            transaction: Arc::new(creation.clone()),
            associated_hint: None,
        };
        store
            .register_contracts(&[
                (first.clone(), evidence.clone()),
                (second.clone(), evidence),
            ])
            .expect("register composed creation");

        let stored = store.transaction(position).expect("transaction").unwrap();
        let mut expected_ids = vec![first.contract_id, second.contract_id];
        sort_dedup_contracts(&mut expected_ids);
        assert_eq!(stored.affected_contract_ids, expected_ids);
        let undo = store
            .read_fixed::<UndoBlock, 4>(UNDO_BLOCKS, &1_u32.to_be_bytes())
            .expect("undo read")
            .expect("height-one undo");
        assert_eq!(undo.transaction_positions, vec![position]);
        assert_eq!(
            undo.output_outpoints,
            (0..3)
                .map(|vout| OutPoint::new(creation.txid(), vout))
                .collect::<Vec<_>>()
        );

        let result = store
            .rollback_to(anchor(0))
            .expect("rollback creation block");
        assert!(matches!(
            result,
            RollbackResult::RolledBack {
                orphaned_positions,
                ..
            } if orphaned_positions == vec![position]
        ));
        assert!(store.transaction(position).expect("transaction").is_none());
        assert!(store.contract(first.contract_id).expect("first").is_none());
        assert!(
            store
                .contract(second.contract_id)
                .expect("second")
                .is_none()
        );
        assert_eq!(
            store
                .retained_declaration(first.contract_id)
                .expect("first retained declaration"),
            Some(declaration_from_record(&first).expect("first declaration"))
        );
        assert_eq!(
            store
                .retained_declaration(second.contract_id)
                .expect("second retained declaration"),
            Some(declaration_from_record(&second).expect("second declaration"))
        );
        for vout in 0..3 {
            assert!(
                store
                    .output(OutPoint::new(creation.txid(), vout))
                    .expect("output")
                    .is_none()
            );
        }
    }

    #[test]
    fn registration_batch_conflict_leaves_no_partial_rows_or_events() {
        let (_dir, _path, store) = initialized_store();
        let creation = transaction(801, &[], 2);
        let position = ChainPosition {
            block_height: 0,
            tx_index: 0,
        };
        let mut first = market_record(0x61, position, creation.txid(), 0, 0, anchor(0));
        first.sync_state = ContractSyncState::CatchingUp {
            synced_through: anchor(0),
        };
        let mut second = market_record(0x62, position, creation.txid(), 1, 0, anchor(0));
        second.sync_state = ContractSyncState::CatchingUp {
            synced_through: anchor(0),
        };
        second.outpoints.push(TrackedOutpoint {
            role: 1,
            outpoint: first.outpoints[0].outpoint,
        });
        let evidence = RegistrationEvidence {
            anchor: anchor(0),
            transaction: Arc::new(creation),
            associated_hint: None,
        };

        assert!(matches!(
            store.register_contracts(&[
                (first.clone(), evidence.clone()),
                (second.clone(), evidence),
            ]),
            Err(StoreError::OutpointAlreadyOwned { outpoint, owner })
                if outpoint == first.outpoints[0].outpoint && owner == first.contract_id
        ));
        assert!(store.contract(first.contract_id).expect("first").is_none());
        assert!(
            store
                .contract(second.contract_id)
                .expect("second")
                .is_none()
        );
        assert!(store.transaction(position).expect("transaction").is_none());
        assert!(
            store
                .outpoint_owner(first.outpoints[0].outpoint)
                .expect("owner")
                .is_none()
        );
        assert!(
            store
                .backfill_progress(first.contract_id)
                .expect("first progress")
                .is_none()
        );
        assert!(store.events_after(None, 10).expect("events").is_empty());
        assert!(
            store
                .retained_declaration(first.contract_id)
                .expect("first retained declaration")
                .is_none()
        );
        assert!(
            store
                .retained_declaration(second.contract_id)
                .expect("second retained declaration")
                .is_none()
        );
    }

    #[test]
    fn destructive_rebuild_retains_watch_intent_from_activation() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("deadcat.redb");
        let store = Store::open(&path).expect("open store");
        let identity = ChainIdentity {
            network: LiquidNetwork::ElementsRegtest,
            genesis_hash: anchor(0).hash,
            policy_asset: asset(0xaa),
        };
        store
            .initialize_chain(identity, anchor(0))
            .expect("initialize chain");
        let pre_activation_creation = transaction(8_019, &[], 1);
        let mut pre_activation_market = market_record(
            0x66,
            ChainPosition {
                block_height: 0,
                tx_index: 0,
            },
            pre_activation_creation.txid(),
            0,
            0,
            anchor(0),
        );
        pre_activation_market.sync_state = ContractSyncState::CatchingUp {
            synced_through: anchor(0),
        };
        assert!(matches!(
            store.register_contract(
                &pre_activation_market,
                &RegistrationEvidence {
                    anchor: anchor(0),
                    transaction: Arc::new(pre_activation_creation),
                    associated_hint: None,
                },
            ),
            Err(StoreError::PreActivationContract { activation })
                if activation == anchor(0)
        ));
        assert!(
            store
                .retained_declaration(pre_activation_market.contract_id)
                .expect("pre-activation declaration")
                .is_none()
        );
        let creation = transaction(8_020, &[], 1);
        store
            .apply_block(&BlockDelta {
                anchor: anchor(1),
                prev_block_hash: anchor(0).hash,
                ordered_txids: vec![creation.txid()],
                relevant_transactions: Vec::new(),
                recovery_hints: Vec::new(),
            })
            .expect("index creation block");
        let mut market = market_record(
            0x67,
            ChainPosition {
                block_height: 1,
                tx_index: 0,
            },
            creation.txid(),
            0,
            0,
            anchor(1),
        );
        market.sync_state = ContractSyncState::CatchingUp {
            synced_through: anchor(1),
        };
        store
            .register_contract(
                &market,
                &RegistrationEvidence {
                    anchor: anchor(1),
                    transaction: Arc::new(creation),
                    associated_hint: None,
                },
            )
            .expect("register watched market");
        let declaration = declaration_from_record(&market).expect("declaration");

        store.invalidate_for_rebuild().expect("invalidate");
        assert_eq!(
            store.sync_status().expect("status before reset"),
            SyncStatus::RescanRequired
        );

        store.reset_for_rebuild().expect("activation rebuild reset");
        assert_eq!(store.tip().expect("activation tip"), Some(anchor(0)));
        assert!(
            store
                .contract(market.contract_id)
                .expect("contract")
                .is_none()
        );
        assert_eq!(
            store
                .retained_declaration(market.contract_id)
                .expect("retained declaration"),
            Some(declaration)
        );
        drop(store);

        let reopened = Store::open(path).expect("reopen");
        assert_eq!(
            reopened
                .retained_declaration(market.contract_id)
                .expect("reopened retained declaration"),
            Some(declaration)
        );
        drop(reopened);
        drop(directory);
    }

    #[test]
    fn nonzero_activation_rejects_lower_equal_and_mixed_registrations_atomically() {
        let directory = tempfile::tempdir().expect("tempdir");
        let store = Store::open(directory.path().join("deadcat.redb")).expect("open store");
        store
            .initialize_chain(
                ChainIdentity {
                    network: LiquidNetwork::ElementsRegtest,
                    genesis_hash: anchor(0).hash,
                    policy_asset: asset(0xaa),
                },
                anchor(2),
            )
            .expect("initialize nonzero activation");

        let lower_tx = transaction(8_101, &[], 1);
        let mut lower = market_record(
            0x71,
            ChainPosition {
                block_height: 1,
                tx_index: 0,
            },
            lower_tx.txid(),
            0,
            0,
            anchor(1),
        );
        lower.sync_state = ContractSyncState::CatchingUp {
            synced_through: anchor(1),
        };
        assert!(matches!(
            store.register_contract(
                &lower,
                &RegistrationEvidence {
                    anchor: anchor(1),
                    transaction: Arc::new(lower_tx),
                    associated_hint: None,
                },
            ),
            Err(StoreError::PreActivationContract { activation }) if activation == anchor(2)
        ));

        let equal_tx = transaction(8_102, &[], 1);
        let mut equal = market_record(
            0x72,
            ChainPosition {
                block_height: 2,
                tx_index: 0,
            },
            equal_tx.txid(),
            0,
            0,
            anchor(2),
        );
        equal.sync_state = ContractSyncState::CatchingUp {
            synced_through: anchor(2),
        };
        let valid_tx = transaction(8_103, &[], 1);
        store
            .apply_block(&BlockDelta {
                anchor: anchor(3),
                prev_block_hash: anchor(2).hash,
                ordered_txids: vec![valid_tx.txid()],
                relevant_transactions: Vec::new(),
                recovery_hints: Vec::new(),
            })
            .expect("index first post-activation block");
        let mut valid = market_record(
            0x73,
            ChainPosition {
                block_height: 3,
                tx_index: 0,
            },
            valid_tx.txid(),
            0,
            0,
            anchor(3),
        );
        valid.sync_state = ContractSyncState::CatchingUp {
            synced_through: anchor(3),
        };
        let equal_evidence = RegistrationEvidence {
            anchor: anchor(2),
            transaction: Arc::new(equal_tx),
            associated_hint: None,
        };
        let valid_evidence = RegistrationEvidence {
            anchor: anchor(3),
            transaction: Arc::new(valid_tx),
            associated_hint: None,
        };
        assert!(matches!(
            store.register_contracts(&[
                (valid.clone(), valid_evidence.clone()),
                (equal.clone(), equal_evidence),
            ]),
            Err(StoreError::PreActivationContract { activation }) if activation == anchor(2)
        ));
        for contract_id in [equal.contract_id, valid.contract_id] {
            assert!(
                store
                    .contract(contract_id)
                    .expect("contract lookup")
                    .is_none()
            );
            assert!(
                store
                    .retained_declaration(contract_id)
                    .expect("declaration lookup")
                    .is_none()
            );
        }
        assert!(
            store
                .register_contract(&valid, &valid_evidence)
                .expect("post-activation registration")
        );
    }

    #[test]
    fn registration_batch_mixes_ready_idempotent_and_new_shared_evidence() {
        let (_dir, _path, store) = initialized_store();
        let creation = transaction(802, &[], 2);
        let position = ChainPosition {
            block_height: 0,
            tx_index: 0,
        };
        let mut existing = market_record(0x63, position, creation.txid(), 0, 0, anchor(0));
        existing.sync_state = ContractSyncState::CatchingUp {
            synced_through: anchor(0),
        };
        let mut new = market_record(0x64, position, creation.txid(), 1, 0, anchor(0));
        new.sync_state = ContractSyncState::CatchingUp {
            synced_through: anchor(0),
        };
        let evidence = RegistrationEvidence {
            anchor: anchor(0),
            transaction: Arc::new(creation.clone()),
            associated_hint: None,
        };
        store
            .register_contract(&existing, &evidence)
            .expect("initial registration");
        store
            .apply_backfill_block(
                &[existing.contract_id],
                &BlockDelta {
                    anchor: anchor(0),
                    prev_block_hash: block_hash(0xff),
                    ordered_txids: vec![creation.txid()],
                    relevant_transactions: Vec::new(),
                    recovery_hints: Vec::new(),
                },
            )
            .expect("complete initial backfill");

        let results = store
            .register_contracts(&[
                (existing.clone(), evidence.clone()),
                (new.clone(), evidence.clone()),
            ])
            .expect("mixed batch");
        assert!(!results[0].inserted);
        assert!(matches!(
            results[0].record.sync_state,
            ContractSyncState::Ready { synced_through } if synced_through == anchor(0)
        ));
        assert!(results[1].inserted);
        assert_eq!(results[1].record, new);

        let stored = store.transaction(position).expect("transaction").unwrap();
        let mut expected_ids = vec![existing.contract_id, new.contract_id];
        sort_dedup_contracts(&mut expected_ids);
        assert_eq!(stored.affected_contract_ids, expected_ids);
        assert!(store.contract(new.contract_id).expect("new").is_some());

        let retry = store
            .register_contracts(&[(existing, evidence.clone()), (new, evidence)])
            .expect("idempotent retry");
        assert!(retry.iter().all(|result| !result.inserted));
        assert!(matches!(
            retry[0].record.sync_state,
            ContractSyncState::Ready { .. }
        ));
        assert!(matches!(
            retry[1].record.sync_state,
            ContractSyncState::CatchingUp { .. }
        ));
    }

    #[test]
    fn ambiguous_and_idempotent_hint_claims_do_not_mutate_association() {
        let (_dir, _path, store) = initialized_store();
        let creation = transaction(803, &[], 2);
        let position = ChainPosition {
            block_height: 1,
            tx_index: 0,
        };
        let location = RecoveryHintLocation {
            position,
            output_index: 1,
        };
        store
            .apply_block(&BlockDelta {
                anchor: anchor(1),
                prev_block_hash: anchor(0).hash,
                ordered_txids: vec![creation.txid()],
                relevant_transactions: Vec::new(),
                recovery_hints: vec![RecoveryHintDelta {
                    location,
                    creation_txid: creation.txid(),
                    family: RecoveryFamily::BinaryMarketV1,
                    payload: vec![0x10, 0x01],
                    associated_contract: None,
                }],
            })
            .expect("index unassociated hint");

        let mut market = market_record(0x65, position, creation.txid(), 0, 0, anchor(1));
        market.sync_state = ContractSyncState::CatchingUp {
            synced_through: anchor(1),
        };
        let unassociated = RegistrationEvidence {
            anchor: anchor(1),
            transaction: Arc::new(creation.clone()),
            associated_hint: None,
        };
        let associated = RegistrationEvidence {
            associated_hint: Some(location),
            ..unassociated.clone()
        };
        let mut other = market_record(0x66, position, creation.txid(), 1, 0, anchor(1));
        other.sync_state = ContractSyncState::CatchingUp {
            synced_through: anchor(1),
        };
        let results = store
            .register_contracts(&[
                (market.clone(), associated.clone()),
                (other.clone(), associated.clone()),
            ])
            .expect("ambiguous hint claims do not invalidate contracts");
        assert!(results.iter().all(|result| result.inserted));
        assert!(
            store
                .contract(market.contract_id)
                .expect("market")
                .is_some()
        );
        assert!(store.contract(other.contract_id).expect("other").is_some());
        assert_eq!(
            store
                .recovery_hint(location)
                .expect("hint")
                .expect("stored hint")
                .associated_contract,
            None
        );

        let high = store.event_high_watermark().expect("high watermark");
        let results = store
            .register_contracts(&[(market.clone(), associated)])
            .expect("idempotent hint claim");
        assert!(!results[0].inserted);
        assert_eq!(results[0].record, market);
        assert_eq!(
            store
                .recovery_hint(location)
                .expect("hint")
                .expect("stored hint")
                .associated_contract,
            None
        );
        assert_eq!(store.event_high_watermark().expect("high watermark"), high);

        // The unassociated evidence remains an equivalent idempotent retry.
        assert!(
            !store
                .register_contract(&market, &unassociated)
                .expect("unassociated retry")
        );
    }

    #[test]
    fn new_registration_and_recovery_hint_association_commit_together() {
        let (_dir, _path, store) = initialized_store();
        let creation = transaction(804, &[], 2);
        let position = ChainPosition {
            block_height: 1,
            tx_index: 0,
        };
        let location = RecoveryHintLocation {
            position,
            output_index: 1,
        };
        store
            .apply_block(&BlockDelta {
                anchor: anchor(1),
                prev_block_hash: anchor(0).hash,
                ordered_txids: vec![creation.txid()],
                relevant_transactions: Vec::new(),
                recovery_hints: vec![
                    RecoveryHintDelta {
                        location: RecoveryHintLocation {
                            position,
                            output_index: 0,
                        },
                        creation_txid: creation.txid(),
                        family: RecoveryFamily::BinaryMarketV1,
                        payload: vec![0x10, 0x01],
                        associated_contract: None,
                    },
                    RecoveryHintDelta {
                        location,
                        creation_txid: creation.txid(),
                        family: RecoveryFamily::BinaryMarketV1,
                        payload: vec![0x10, 0x02],
                        associated_contract: None,
                    },
                ],
            })
            .expect("index hint");
        let first_page = store
            .scan_recovery_hints(None, None, 1)
            .expect("first recovery-hint page");
        assert_eq!(first_page.items.len(), 1);
        let cursor = first_page.next.expect("continuation cursor");
        assert!(matches!(
            store.scan_recovery_hints(Some(RecoveryFamily::BinaryMarketV1), Some(&cursor), 1),
            Err(StoreError::SnapshotScopeMismatch { .. })
        ));
        let second_page = store
            .scan_recovery_hints(None, Some(&cursor), 1)
            .expect("stable continuation");
        assert_eq!(second_page.snapshot, first_page.snapshot);
        assert_eq!(second_page.items.len(), 1);
        assert!(second_page.next.is_none());

        let mut market = market_record(0x67, position, creation.txid(), 0, 0, anchor(1));
        market.sync_state = ContractSyncState::CatchingUp {
            synced_through: anchor(1),
        };
        let evidence = RegistrationEvidence {
            anchor: anchor(1),
            transaction: Arc::new(creation.clone()),
            associated_hint: Some(location),
        };

        let results = store
            .register_contracts(&[(market.clone(), evidence)])
            .expect("register and associate");
        assert!(results[0].inserted);
        assert_eq!(results[0].record, market);
        assert_eq!(
            store
                .recovery_hint(location)
                .expect("hint")
                .expect("stored hint")
                .associated_contract,
            Some(market.contract_id)
        );
        let current_snapshot = store.snapshot_metadata().expect("current snapshot");
        assert_eq!(current_snapshot.as_of, first_page.snapshot.as_of);
        assert_ne!(
            current_snapshot.event_high_watermark,
            first_page.snapshot.event_high_watermark
        );
        assert!(matches!(
            store.scan_recovery_hints(None, Some(&cursor), 1),
            Err(StoreError::StaleSnapshotCursor { .. })
        ));

        let mut other = market_record(0x68, position, creation.txid(), 1, 0, anchor(1));
        other.sync_state = ContractSyncState::CatchingUp {
            synced_through: anchor(1),
        };
        let competing = RegistrationEvidence {
            anchor: anchor(1),
            transaction: Arc::new(creation),
            associated_hint: Some(location),
        };
        assert!(
            store
                .register_contract(&other, &competing)
                .expect("already-owned hint is advisory")
        );
        assert_eq!(
            store
                .recovery_hint(location)
                .expect("hint")
                .expect("stored hint")
                .associated_contract,
            Some(market.contract_id)
        );
    }

    #[test]
    fn missing_and_mismatched_hints_do_not_block_registration() {
        let (_dir, _path, store) = initialized_store();
        let missing_tx = transaction(805, &[], 2);
        let mismatched_tx = transaction(806, &[], 2);
        let missing_position = ChainPosition {
            block_height: 1,
            tx_index: 0,
        };
        let mismatched_position = ChainPosition {
            block_height: 1,
            tx_index: 1,
        };
        let missing_location = RecoveryHintLocation {
            position: missing_position,
            output_index: 1,
        };
        let mismatched_location = RecoveryHintLocation {
            position: mismatched_position,
            output_index: 1,
        };
        store
            .apply_block(&BlockDelta {
                anchor: anchor(1),
                prev_block_hash: anchor(0).hash,
                ordered_txids: vec![missing_tx.txid(), mismatched_tx.txid()],
                relevant_transactions: Vec::new(),
                recovery_hints: vec![RecoveryHintDelta {
                    location: mismatched_location,
                    creation_txid: mismatched_tx.txid(),
                    family: RecoveryFamily::MakerOrderV1,
                    payload: vec![0x20, 0x01],
                    associated_contract: None,
                }],
            })
            .expect("index mismatched-family hint");

        let mut missing = market_record(0x69, missing_position, missing_tx.txid(), 0, 0, anchor(1));
        missing.sync_state = ContractSyncState::CatchingUp {
            synced_through: anchor(1),
        };
        let mut mismatched = market_record(
            0x6a,
            mismatched_position,
            mismatched_tx.txid(),
            0,
            0,
            anchor(1),
        );
        mismatched.sync_state = ContractSyncState::CatchingUp {
            synced_through: anchor(1),
        };

        let results = store
            .register_contracts(&[
                (
                    missing.clone(),
                    RegistrationEvidence {
                        anchor: anchor(1),
                        transaction: Arc::new(missing_tx),
                        associated_hint: Some(missing_location),
                    },
                ),
                (
                    mismatched.clone(),
                    RegistrationEvidence {
                        anchor: anchor(1),
                        transaction: Arc::new(mismatched_tx),
                        associated_hint: Some(mismatched_location),
                    },
                ),
            ])
            .expect("advisory hint failures do not invalidate registration");
        assert!(results.iter().all(|result| result.inserted));
        assert!(
            store
                .contract(missing.contract_id)
                .expect("missing")
                .is_some()
        );
        assert!(
            store
                .contract(mismatched.contract_id)
                .expect("mismatched")
                .is_some()
        );
        assert_eq!(
            store
                .recovery_hint(mismatched_location)
                .expect("hint")
                .expect("stored hint")
                .associated_contract,
            None
        );
    }

    #[test]
    fn materialized_pages_are_ready_only_deterministic_and_snapshot_bound() {
        let (_dir, _path, store) = initialized_store();
        let create_a = transaction(81, &[], 1);
        let create_b = transaction(82, &[], 1);
        let position_a = ChainPosition {
            block_height: 1,
            tx_index: 0,
        };
        let position_b = ChainPosition {
            block_height: 1,
            tx_index: 1,
        };
        let market_a = market_record(0x31, position_a, create_a.txid(), 0, 0, anchor(1));
        let market_b = market_record(0x32, position_b, create_b.txid(), 0, 0, anchor(1));
        store
            .apply_block(&BlockDelta {
                anchor: anchor(1),
                prev_block_hash: anchor(0).hash,
                ordered_txids: vec![create_a.txid(), create_b.txid()],
                relevant_transactions: vec![
                    ChainTxDelta {
                        position: position_a,
                        block_hash: anchor(1).hash,
                        txid: create_a.txid(),
                        raw_tx: create_a,
                        created_contracts: vec![market_a.clone()],
                        state_updates: Vec::new(),
                    },
                    ChainTxDelta {
                        position: position_b,
                        block_hash: anchor(1).hash,
                        txid: create_b.txid(),
                        raw_tx: create_b,
                        created_contracts: vec![market_b.clone()],
                        state_updates: Vec::new(),
                    },
                ],
                recovery_hints: Vec::new(),
            })
            .expect("block");
        store.apply_block(&empty_block(2)).expect("empty block");

        let first = store.ready_markets(None, 1).expect("first page");
        assert_eq!(first.items.len(), 1);
        assert!(matches!(
            first.items[0].sync_state,
            ContractSyncState::Ready { synced_through } if synced_through == anchor(2)
        ));
        let cursor = first.next.clone().expect("next cursor");
        let second = store.ready_markets(Some(&cursor), 1).expect("second page");
        assert_eq!(second.items.len(), 1);
        assert!(second.next.is_none());
        let listed = [first.items[0].contract_id, second.items[0].contract_id]
            .into_iter()
            .collect::<HashSet<_>>();
        assert_eq!(
            listed,
            [market_a.contract_id, market_b.contract_id]
                .into_iter()
                .collect()
        );
        let (snapshot, contract) = store
            .contract_snapshot(market_a.contract_id)
            .expect("snapshot");
        assert_eq!(snapshot, first.snapshot);
        let mut expected_market = market_a.clone();
        expected_market.sync_state = ContractSyncState::Ready {
            synced_through: anchor(2),
        };
        assert_eq!(contract, Some(expected_market));
        let collateral = match market_a.params {
            ContractParameters::BinaryMarket(params) => params.collateral_asset_id,
            ContractParameters::MakerOrder(_) => unreachable!(),
        };
        assert!(
            store
                .asset_relations(collateral)
                .expect("asset lookup")
                .1
                .iter()
                .any(|relation| relation.contract_id == market_a.contract_id)
        );

        store
            .set_sync_status(SyncStatus::Ready)
            .expect("change watermark");
        assert!(matches!(
            store.ready_markets(Some(&cursor), 1),
            Err(StoreError::StaleSnapshotCursor { .. })
        ));
    }

    #[test]
    fn block_apply_persists_composed_transitions_outputs_hints_and_indexes() {
        let (_dir, path, store) = initialized_store();
        let create_a = transaction(101, &[], 1);
        let create_b = transaction(102, &[], 1);
        let position_a = ChainPosition {
            block_height: 1,
            tx_index: 0,
        };
        let position_b = ChainPosition {
            block_height: 1,
            tx_index: 1,
        };
        let market_a = market_record(0x11, position_a, create_a.txid(), 0, 1, anchor(1));
        let market_b = market_record(0x22, position_b, create_b.txid(), 0, 2, anchor(1));
        let creation = block(
            1,
            vec![
                ChainTxDelta {
                    position: position_a,
                    block_hash: anchor(1).hash,
                    txid: create_a.txid(),
                    raw_tx: create_a.clone(),
                    created_contracts: vec![market_a.clone()],
                    state_updates: vec![],
                },
                ChainTxDelta {
                    position: position_b,
                    block_hash: anchor(1).hash,
                    txid: create_b.txid(),
                    raw_tx: create_b,
                    created_contracts: vec![market_b.clone()],
                    state_updates: vec![],
                },
            ],
            vec![RecoveryHintDelta {
                location: RecoveryHintLocation {
                    position: position_a,
                    output_index: 0,
                },
                creation_txid: create_a.txid(),
                family: RecoveryFamily::BinaryMarketV1,
                payload: vec![0x10, 1, 2, 3],
                associated_contract: Some(market_a.contract_id),
            }],
        );
        store.apply_block(&creation).expect("creation block");

        let composed = transaction(
            201,
            &[
                market_a.outpoints[0].outpoint,
                market_b.outpoints[0].outpoint,
            ],
            2,
        );
        let position = ChainPosition {
            block_height: 2,
            tx_index: 0,
        };
        let delta = block(
            2,
            vec![ChainTxDelta {
                position,
                block_hash: anchor(2).hash,
                txid: composed.txid(),
                raw_tx: composed.clone(),
                created_contracts: vec![],
                state_updates: vec![
                    update_market(&market_a, composed.txid(), 0, 3),
                    update_market(&market_b, composed.txid(), 1, 4),
                ],
            }],
            vec![],
        );
        let applied = store.apply_block(&delta).expect("composed block");
        assert!(applied.applied);
        assert_eq!(store.tip().expect("tip"), Some(anchor(2)));
        assert_eq!(
            store
                .contract(market_a.contract_id)
                .expect("contract")
                .expect("market")
                .state,
            ContractState::BinaryMarket(BinaryMarketState::Trading {
                outstanding_pairs: 3
            })
        );
        assert_eq!(
            store
                .outpoint_owner(OutPoint::new(composed.txid(), 1))
                .expect("owner")
                .expect("tracked")
                .contract_id,
            market_b.contract_id
        );
        assert_eq!(
            store
                .transaction(position)
                .expect("transaction")
                .expect("stored")
                .affected_contract_ids
                .len(),
            2
        );
        assert!(
            store
                .output(OutPoint::new(composed.txid(), 0))
                .expect("output")
                .is_some()
        );
        assert_eq!(
            store
                .contract_history(market_a.contract_id)
                .expect("history")
                .len(),
            1
        );
        assert!(
            store
                .recovery_hint(RecoveryHintLocation {
                    position: position_a,
                    output_index: 0,
                })
                .expect("hint")
                .is_some()
        );

        let cursor = store.event_high_watermark().expect("cursor");
        assert_eq!(cursor.sequence, 3);
        assert!(!store.apply_block(&delta).expect("idempotent retry").applied);
        assert_eq!(store.event_high_watermark().expect("cursor"), cursor);
        drop(store);
        let reopened = Store::open(&path).expect("reopen");
        assert_eq!(reopened.tip().expect("tip"), Some(anchor(2)));
        assert_eq!(reopened.event_high_watermark().expect("cursor"), cursor);
    }

    #[test]
    fn block_rejects_creation_anchor_not_tracked_as_an_initial_output() {
        let (_dir, _path, store) = initialized_store();
        let creation = transaction(299, &[], 2);
        let position = ChainPosition {
            block_height: 1,
            tx_index: 0,
        };
        let mut market = market_record(0x2a, position, creation.txid(), 0, 0, anchor(1));
        market.outpoints[0].outpoint = OutPoint::new(creation.txid(), 1);
        let contract_id = market.contract_id;

        assert!(matches!(
            store.apply_block(&block(
                1,
                vec![ChainTxDelta {
                    position,
                    block_hash: anchor(1).hash,
                    txid: creation.txid(),
                    raw_tx: creation,
                    created_contracts: vec![market],
                    state_updates: Vec::new(),
                }],
                Vec::new(),
            )),
            Err(StoreError::InvalidBlock(message))
                if message.contains("anchor is not one of its initial live outputs")
        ));
        assert_eq!(store.tip().expect("tip"), Some(anchor(0)));
        assert!(store.contract(contract_id).expect("contract").is_none());
        assert!(store.transaction(position).expect("transaction").is_none());
        assert!(store.events_after(None, 10).expect("events").is_empty());
    }

    #[test]
    fn block_rejects_creation_anchor_outside_the_creation_transaction() {
        let (_dir, _path, store) = initialized_store();
        let creation = transaction(300, &[], 1);
        let position = ChainPosition {
            block_height: 1,
            tx_index: 0,
        };
        let absent_anchor = OutPoint::new(creation.txid(), 1);
        let mut market = market_record(0x2b, position, creation.txid(), 0, 0, anchor(1));
        market.contract_id = ContractId::new(absent_anchor);
        market.outpoints[0].outpoint = absent_anchor;

        assert!(matches!(
            store.apply_block(&block(
                1,
                vec![ChainTxDelta {
                    position,
                    block_hash: anchor(1).hash,
                    txid: creation.txid(),
                    raw_tx: creation,
                    created_contracts: vec![market],
                    state_updates: Vec::new(),
                }],
                Vec::new(),
            )),
            Err(StoreError::InvalidBlock(message))
                if message.contains("anchor is absent from its creation transaction")
        ));
        assert_eq!(store.tip().expect("tip"), Some(anchor(0)));
        assert!(
            store
                .contract(ContractId::new(absent_anchor))
                .expect("contract")
                .is_none()
        );
        assert!(store.transaction(position).expect("transaction").is_none());
        assert!(store.events_after(None, 10).expect("events").is_empty());
    }

    #[test]
    fn invalid_later_transaction_aborts_the_entire_block() {
        let (_dir, _path, store) = initialized_store();
        let creation_tx = transaction(301, &[], 1);
        let creation_position = ChainPosition {
            block_height: 1,
            tx_index: 0,
        };
        let market = market_record(0x31, creation_position, creation_tx.txid(), 0, 1, anchor(1));
        let spend = transaction(302, &[market.outpoints[0].outpoint], 1);
        let invalid = block(
            1,
            vec![
                ChainTxDelta {
                    position: creation_position,
                    block_hash: anchor(1).hash,
                    txid: creation_tx.txid(),
                    raw_tx: creation_tx,
                    created_contracts: vec![market.clone()],
                    state_updates: vec![],
                },
                ChainTxDelta {
                    position: ChainPosition {
                        block_height: 1,
                        tx_index: 1,
                    },
                    block_hash: anchor(1).hash,
                    txid: spend.txid(),
                    raw_tx: spend,
                    created_contracts: vec![],
                    state_updates: vec![],
                },
            ],
            vec![],
        );
        assert!(matches!(
            store.apply_block(&invalid),
            Err(StoreError::UnaccountedTrackedInput { .. })
        ));
        assert_eq!(store.tip().expect("tip"), Some(anchor(0)));
        assert!(store.block(1).expect("block").is_none());
        assert!(
            store
                .contract(market.contract_id)
                .expect("contract")
                .is_none()
        );
        assert_eq!(store.event_high_watermark().expect("cursor").sequence, 0);
    }

    #[test]
    fn rollback_two_blocks_restores_state_indexes_and_canonical_history() {
        let (_dir, _path, store) = initialized_store();
        let create_tx = transaction(401, &[], 1);
        let creation_position = ChainPosition {
            block_height: 1,
            tx_index: 0,
        };
        let initial = market_record(0x41, creation_position, create_tx.txid(), 0, 1, anchor(1));
        store
            .apply_block(&block(
                1,
                vec![ChainTxDelta {
                    position: creation_position,
                    block_hash: anchor(1).hash,
                    txid: create_tx.txid(),
                    raw_tx: create_tx,
                    created_contracts: vec![initial.clone()],
                    state_updates: vec![],
                }],
                vec![],
            ))
            .expect("block 1");

        let tx2 = transaction(402, &[initial.outpoints[0].outpoint], 1);
        let update2 = update_market(&initial, tx2.txid(), 0, 2);
        store
            .apply_block(&block(
                2,
                vec![ChainTxDelta {
                    position: ChainPosition {
                        block_height: 2,
                        tx_index: 0,
                    },
                    block_hash: anchor(2).hash,
                    txid: tx2.txid(),
                    raw_tx: tx2,
                    created_contracts: vec![],
                    state_updates: vec![update2],
                }],
                vec![],
            ))
            .expect("block 2");
        let after2 = store
            .contract(initial.contract_id)
            .expect("contract")
            .expect("market");
        let tx3 = transaction(403, &[after2.outpoints[0].outpoint], 1);
        store
            .apply_block(&block(
                3,
                vec![ChainTxDelta {
                    position: ChainPosition {
                        block_height: 3,
                        tx_index: 0,
                    },
                    block_hash: anchor(3).hash,
                    txid: tx3.txid(),
                    raw_tx: tx3.clone(),
                    created_contracts: vec![],
                    state_updates: vec![update_market(&after2, tx3.txid(), 0, 3)],
                }],
                vec![],
            ))
            .expect("block 3");

        let result = store.rollback_to(anchor(1)).expect("rollback");
        assert!(matches!(result, RollbackResult::RolledBack { .. }));
        assert_eq!(store.tip().expect("tip"), Some(anchor(1)));
        assert_eq!(
            store
                .contract(initial.contract_id)
                .expect("contract")
                .expect("market")
                .state,
            initial.state
        );
        assert_eq!(
            store
                .outpoint_owner(initial.outpoints[0].outpoint)
                .expect("owner")
                .expect("restored")
                .contract_id,
            initial.contract_id
        );
        assert!(
            store
                .outpoint_owner(OutPoint::new(tx3.txid(), 0))
                .expect("owner")
                .is_none()
        );
        assert!(
            store
                .transaction(ChainPosition {
                    block_height: 2,
                    tx_index: 0
                })
                .expect("tx")
                .is_none()
        );
        assert!(
            store
                .output(OutPoint::new(tx3.txid(), 0))
                .expect("output")
                .is_none()
        );
        assert!(
            store
                .contract_history(initial.contract_id)
                .expect("history")
                .is_empty()
        );
        assert_eq!(store.sync_status().expect("status"), SyncStatus::Syncing);
        assert_eq!(store.events_after(None, 10).expect("events").len(), 4);
    }

    #[test]
    fn deeper_rollback_requires_rebuild_and_invalidates_old_cursors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(dir.path().join("deadcat.redb")).expect("open store");
        store
            .initialize_chain(
                ChainIdentity {
                    network: LiquidNetwork::ElementsRegtest,
                    genesis_hash: anchor(0).hash,
                    policy_asset: asset(0xaa),
                },
                anchor(0),
            )
            .expect("initialize chain");
        for height in 1..=3 {
            store
                .apply_block(&empty_block(height))
                .expect("empty block");
        }
        let old_cursor = store.event_high_watermark().expect("old cursor");
        let result = store.rollback_to(anchor(0)).expect("deep rollback outcome");
        let RollbackResult::RebuildRequired {
            new_event_epoch, ..
        } = result
        else {
            panic!("expected explicit rebuild requirement");
        };
        assert_ne!(old_cursor.epoch, new_event_epoch);
        assert_eq!(store.tip().expect("tip"), Some(anchor(3)));
        assert_eq!(
            store.sync_status().expect("status"),
            SyncStatus::RescanRequired
        );
        let invalidated_cursor = store.event_high_watermark().expect("invalidated cursor");
        assert!(matches!(
            store.rollback_to(anchor(2)),
            Err(StoreError::RebuildRequired)
        ));
        assert_eq!(store.tip().expect("sticky rollback tip"), Some(anchor(3)));
        assert_eq!(
            store
                .event_high_watermark()
                .expect("sticky rollback cursor"),
            invalidated_cursor
        );
        for attempted in [
            SyncStatus::BackendUnavailable,
            SyncStatus::Syncing,
            SyncStatus::Ready,
        ] {
            assert!(matches!(
                store.set_sync_status(attempted),
                Err(StoreError::RebuildRequired)
            ));
            assert_eq!(
                store.sync_status().expect("sticky status"),
                SyncStatus::RescanRequired
            );
        }
        assert_eq!(
            store.invalidate_for_rebuild().expect("repeat invalidation"),
            new_event_epoch
        );
        assert_eq!(
            store.event_high_watermark().expect("stable cursor"),
            invalidated_cursor
        );
        assert!(matches!(
            store.events_after(Some(old_cursor), 10),
            Err(StoreError::StaleCursor { .. })
        ));
        let high = store.event_high_watermark().expect("new cursor");
        assert_eq!(high.epoch, new_event_epoch);
        assert_eq!(high.sequence, 1);
        assert!(matches!(
            store.events_after(
                Some(EventCursor {
                    epoch: high.epoch,
                    sequence: high.sequence + 1,
                }),
                10,
            ),
            Err(StoreError::CursorAhead { .. })
        ));

        let reset_cursor = store.reset_for_rebuild().expect("explicit reset");
        assert_eq!(reset_cursor.epoch, new_event_epoch);
        assert_eq!(reset_cursor.sequence, 2);
        assert_eq!(store.tip().expect("baseline tip"), Some(anchor(0)));
        assert_eq!(store.sync_status().expect("status"), SyncStatus::Syncing);
        assert!(store.block(1).expect("cleared block").is_none());
        store
            .apply_block(&empty_block(1))
            .expect("replay after explicit reset");
    }

    #[test]
    fn generic_rescan_status_transition_rotates_the_epoch_exactly_once() {
        let (_dir, _path, store) = initialized_store();
        let before = store.event_high_watermark().expect("initial cursor");
        let invalidated = store
            .set_sync_status(SyncStatus::RescanRequired)
            .expect("enter rescan through generic status API");
        assert_ne!(invalidated.epoch, before.epoch);
        assert_eq!(invalidated.sequence, 1);
        assert_eq!(
            store.sync_status().expect("rescan status"),
            SyncStatus::RescanRequired
        );
        assert_eq!(
            store
                .set_sync_status(SyncStatus::RescanRequired)
                .expect("repeat rescan"),
            invalidated
        );
    }

    #[test]
    fn schema_mismatch_is_rejected_on_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("deadcat.redb");
        let store = Store::open(&path).expect("open");
        let write = store.database.begin_write().expect("write");
        {
            let mut meta = write.open_table(META).expect("meta");
            meta.insert(
                SCHEMA_VERSION_KEY,
                (SCHEMA_VERSION + 1).to_be_bytes().as_slice(),
            )
            .expect("corrupt version");
        }
        write.commit().expect("commit");
        drop(store);
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::SchemaMismatch {
                expected: SCHEMA_VERSION,
                actual,
            }) if actual == SCHEMA_VERSION + 1
        ));
    }

    #[test]
    fn chain_activation_and_tip_are_bound_atomically_and_exactly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("deadcat.redb");
        let store = Store::open(&path).expect("open");
        let identity = ChainIdentity {
            network: LiquidNetwork::ElementsRegtest,
            genesis_hash: anchor(0).hash,
            policy_asset: asset(0xaa),
        };
        store
            .initialize_chain(identity, anchor(0))
            .expect("initialize exact binding");
        assert_eq!(store.chain_identity().expect("identity"), Some(identity));
        assert_eq!(
            store.activation_anchor().expect("activation"),
            Some(anchor(0))
        );
        assert_eq!(store.tip().expect("tip"), Some(anchor(0)));
        store
            .initialize_chain(identity, anchor(0))
            .expect("idempotent binding");
        assert!(matches!(
            store.initialize_chain(identity, anchor(1)),
            Err(StoreError::ActivationAnchorMismatch { expected, actual })
                if expected == anchor(0) && actual == anchor(1)
        ));
        drop(store);

        let reopened = Store::open(&path).expect("reopen");
        reopened
            .initialize_chain(identity, anchor(0))
            .expect("verify reopened binding");

        let partial_dir = tempfile::tempdir().expect("partial tempdir");
        let partial = Store::open(partial_dir.path().join("deadcat.redb")).expect("partial store");
        partial
            .bind_chain(identity)
            .expect("write partial identity");
        assert!(matches!(
            partial.initialize_chain(identity, anchor(0)),
            Err(StoreError::IncompleteChainConfiguration)
        ));
    }
}

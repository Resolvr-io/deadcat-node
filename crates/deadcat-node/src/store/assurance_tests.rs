//! Deterministic differential and mutation-boundary assurance for the store.
//!
//! The reference model below deliberately does not call store mutation helpers
//! or serialize through redb. It interprets valid block deltas into ordinary
//! in-memory collections, then checks the public store surface after every
//! generated operation and after process-style reopen boundaries.
//!
//! The seeded generator is intentionally bounded to ready, live binary-market
//! trading state in the canonical block path. Maker-order, terminal-state,
//! retained-registration, and backfill semantics have targeted tests elsewhere;
//! the failpoint fixtures below touch recovery, retained, and backfill rows only
//! where needed to exercise a real mutation boundary.
//!
//! Failpoints model a graceful error returned before `redb` commit: dropping the
//! write transaction must publish none of its table mutations, and reopening
//! must preserve that exact logical database. They do not simulate process kill,
//! commit I/O failure, torn writes, or `redb`'s internal crash-recovery protocol.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use elements::hashes::Hash as _;
use elements::{LockTime, TxIn};
use redb::{ReadTransaction, ReadableDatabase as _, ReadableTable as _, TableDefinition};
use sha2::{Digest as _, Sha256};

use super::*;

const RANDOM_STEPS: usize = 72;
const RANDOM_SEEDS: [u64; 4] = [
    0xdead_cafe_0000_0001,
    0x51ab_1e00_0000_0002,
    0xa11c_e5ee_0000_0003,
    0xc0de_cafe_0000_0004,
];

#[derive(Clone, Copy)]
struct DeterministicRng(u64);

impl DeterministicRng {
    fn next_u64(&mut self) -> u64 {
        // xorshift64*: tiny, fixed, and independent of rand crate upgrades.
        let mut value = self.0;
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        self.0 = value;
        value.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn index(&mut self, upper: usize) -> usize {
        assert_ne!(upper, 0);
        usize::try_from(self.next_u64() % u64::try_from(upper).expect("small upper bound"))
            .expect("bounded random index")
    }

    fn one_in(&mut self, denominator: u64) -> bool {
        self.next_u64().is_multiple_of(denominator)
    }
}

fn test_hash(domain: u64) -> BlockHash {
    let mut bytes = [0_u8; 32];
    let mut value = domain;
    for chunk in bytes.chunks_exact_mut(8) {
        value = value
            .wrapping_add(0x9e37_79b9_7f4a_7c15)
            .wrapping_mul(0xbf58_476d_1ce4_e5b9);
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    BlockHash::from_byte_array(bytes)
}

fn asset(marker: u8) -> AssetId {
    AssetId::from_slice(&[marker; 32]).expect("asset id")
}

fn test_identity() -> ChainIdentity {
    ChainIdentity {
        network: LiquidNetwork::ElementsRegtest,
        genesis_hash: test_hash(0x100),
        policy_asset: asset(0x42),
    }
}

fn activation() -> ChainAnchor {
    ChainAnchor {
        height: 0,
        hash: test_hash(0),
    }
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
    position: ChainPosition,
    txid: Txid,
    vout: u32,
    synced_through: ChainAnchor,
) -> ContractRecord {
    ContractRecord {
        contract_id: ContractId::new(OutPoint::new(txid, vout)),
        kind: ContractKind::BinaryMarketV1,
        params: ContractParameters::BinaryMarket(BinaryMarketParams {
            oracle_public_key: [marker.wrapping_add(1); 32],
            collateral_asset_id: asset(marker.wrapping_add(2)),
            yes_token_asset_id: asset(marker.wrapping_add(3)),
            no_token_asset_id: asset(marker.wrapping_add(4)),
            yes_reissuance_token_id: asset(marker.wrapping_add(5)),
            no_reissuance_token_id: asset(marker.wrapping_add(6)),
            base_payout: 100,
            expiry_height: 1_000_000,
        }),
        creation_position: position,
        state: ContractState::BinaryMarket(BinaryMarketState::Trading {
            outstanding_pairs: 0,
        }),
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

fn market_pairs(state: ContractState) -> u64 {
    let ContractState::BinaryMarket(BinaryMarketState::Trading { outstanding_pairs }) = state
    else {
        panic!("assurance generator only creates trading binary markets");
    };
    outstanding_pairs
}

#[derive(Clone, Debug)]
struct ModelContract {
    record: ContractRecord,
    history: Vec<StoredHistoryEntry>,
}

#[derive(Clone, Debug, Default)]
struct MaterializedModel {
    contracts: BTreeMap<ContractId, ModelContract>,
    transactions: BTreeMap<ChainPosition, StoredTransaction>,
    outputs: BTreeMap<OutPoint, StoredOutput>,
}

type RawRow = (Vec<u8>, Vec<u8>);

/// Exact logical contents of every application-owned redb table. Comparing
/// rows rather than database-file bytes avoids false failures from redb page
/// allocation while still detecting leaked undo, index, metadata, or stale-
/// epoch event mutations that are not currently reachable through public RPCs.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DatabaseInventory {
    meta: Vec<RawRow>,
    chain_tip: Vec<RawRow>,
    blocks: Vec<RawRow>,
    transactions: Vec<RawRow>,
    outputs: Vec<RawRow>,
    contracts: Vec<RawRow>,
    retained_declarations: Vec<RawRow>,
    outpoint_owners: Vec<RawRow>,
    contract_outpoints: Vec<RawRow>,
    script_index: Vec<RawRow>,
    asset_relations: Vec<RawRow>,
    market_children: Vec<RawRow>,
    order_book: Vec<RawRow>,
    recovery_hints: Vec<RawRow>,
    contract_history: Vec<RawRow>,
    backfill_progress: Vec<RawRow>,
    undo_blocks: Vec<RawRow>,
    events: Vec<RawRow>,
}

fn string_rows(read: &ReadTransaction, definition: TableDefinition<&str, &[u8]>) -> Vec<RawRow> {
    read.open_table(definition)
        .expect("open string-keyed table")
        .iter()
        .expect("iterate string-keyed table")
        .map(|entry| {
            let (key, value) = entry.expect("read string-keyed row");
            (key.value().as_bytes().to_vec(), value.value().to_vec())
        })
        .collect()
}

fn byte_rows(read: &ReadTransaction, definition: TableDefinition<&[u8], &[u8]>) -> Vec<RawRow> {
    read.open_table(definition)
        .expect("open byte-keyed table")
        .iter()
        .expect("iterate byte-keyed table")
        .map(|entry| {
            let (key, value) = entry.expect("read byte-keyed row");
            (key.value().to_vec(), value.value().to_vec())
        })
        .collect()
}

fn database_inventory(store: &Store) -> DatabaseInventory {
    let read = store.database.begin_read().expect("inventory read");
    DatabaseInventory {
        meta: string_rows(&read, META),
        chain_tip: string_rows(&read, CHAIN_TIP),
        blocks: byte_rows(&read, BLOCKS),
        transactions: byte_rows(&read, TRANSACTIONS),
        outputs: byte_rows(&read, OUTPUTS),
        contracts: byte_rows(&read, CONTRACTS),
        retained_declarations: byte_rows(&read, RETAINED_DECLARATIONS),
        outpoint_owners: byte_rows(&read, OUTPOINT_OWNERS),
        contract_outpoints: byte_rows(&read, CONTRACT_OUTPOINTS),
        script_index: byte_rows(&read, SCRIPT_INDEX),
        asset_relations: byte_rows(&read, ASSET_RELATIONS),
        market_children: byte_rows(&read, MARKET_CHILDREN),
        order_book: byte_rows(&read, ORDER_BOOK),
        recovery_hints: byte_rows(&read, RECOVERY_HINTS),
        contract_history: byte_rows(&read, CONTRACT_HISTORY),
        backfill_progress: byte_rows(&read, BACKFILL_PROGRESS),
        undo_blocks: byte_rows(&read, UNDO_BLOCKS),
        events: byte_rows(&read, EVENTS),
    }
}

#[derive(Clone, Debug)]
struct ModelBlock {
    delta: BlockDelta,
    before: MaterializedModel,
    undo: UndoBlock,
}

#[derive(Debug)]
struct ReferenceModel {
    activation: ChainAnchor,
    tip: ChainAnchor,
    status: SyncStatus,
    cursor: EventCursor,
    events: Vec<StoredEventEnvelope>,
    all_events: BTreeMap<EventCursor, StoredEventEnvelope>,
    blocks: Vec<ModelBlock>,
    undo_heights: BTreeSet<u32>,
    materialized: MaterializedModel,
    known_contracts: BTreeSet<ContractId>,
    known_positions: BTreeSet<ChainPosition>,
    known_outpoints: BTreeSet<OutPoint>,
    known_heights: BTreeSet<u32>,
}

impl ReferenceModel {
    fn new(activation: ChainAnchor, cursor: EventCursor) -> Self {
        assert_eq!(cursor.sequence, 1, "initial syncing event sequence");
        let initial_event = StoredEventEnvelope {
            cursor,
            event: StoredEvent::SyncStatusChanged {
                status: SyncStatus::Syncing,
            },
        };
        Self {
            activation,
            tip: activation,
            status: SyncStatus::Syncing,
            cursor,
            events: vec![initial_event.clone()],
            all_events: BTreeMap::from([(cursor, initial_event)]),
            blocks: Vec::new(),
            undo_heights: BTreeSet::new(),
            materialized: MaterializedModel::default(),
            known_contracts: BTreeSet::new(),
            known_positions: BTreeSet::new(),
            known_outpoints: BTreeSet::new(),
            known_heights: BTreeSet::new(),
        }
    }

    fn apply(&mut self, delta: &BlockDelta) {
        assert_eq!(delta.anchor.height, self.tip.height + 1);
        assert_eq!(delta.prev_block_hash, self.tip.hash);
        let before = self.materialized.clone();
        let mut undo = UndoBlock {
            previous_tip: self.tip,
            contract_changes: Vec::new(),
            transaction_positions: Vec::new(),
            output_outpoints: Vec::new(),
            history_keys: Vec::new(),
            recovery_locations: Vec::new(),
            backfill_progress_changes: Vec::new(),
        };

        for transaction in &delta.relevant_transactions {
            let mut affected = Vec::new();
            for record in &transaction.created_contracts {
                assert!(
                    self.materialized
                        .contracts
                        .insert(
                            record.contract_id,
                            ModelContract {
                                record: record.clone(),
                                history: Vec::new(),
                            },
                        )
                        .is_none()
                );
                undo.contract_changes.push(ContractUndo {
                    contract_id: record.contract_id,
                    before: None,
                });
                self.known_contracts.insert(record.contract_id);
                affected.push(record.contract_id);
            }
            for update in &transaction.state_updates {
                let contract = self
                    .materialized
                    .contracts
                    .get_mut(&update.contract_id)
                    .expect("generated transition contract");
                assert_eq!(contract.record.state, update.old_state);
                undo.contract_changes.push(ContractUndo {
                    contract_id: update.contract_id,
                    before: Some(contract.record.clone()),
                });
                contract.record.state = update.new_state;
                contract.record.outpoints.clone_from(&update.new_outpoints);
                contract.history.push(StoredHistoryEntry {
                    position: transaction.position,
                    txid: transaction.txid,
                    old_state: update.old_state,
                    new_state: update.new_state,
                    transition: update.transition.clone(),
                });
                undo.history_keys
                    .push((update.contract_id, transaction.position));
                affected.push(update.contract_id);
            }
            affected.sort_by_key(|contract| contract.to_fixed_key());
            affected.dedup();

            self.known_positions.insert(transaction.position);
            undo.transaction_positions.push(transaction.position);
            self.materialized.transactions.insert(
                transaction.position,
                StoredTransaction {
                    position: transaction.position,
                    block_hash: transaction.block_hash,
                    txid: transaction.txid,
                    raw_tx: encode::serialize(&transaction.raw_tx),
                    affected_contract_ids: affected.clone(),
                },
            );
            for (vout, output) in transaction.raw_tx.output.iter().enumerate() {
                let outpoint = OutPoint::new(
                    transaction.txid,
                    u32::try_from(vout).expect("small generated vout"),
                );
                self.known_outpoints.insert(outpoint);
                self.materialized.outputs.insert(
                    outpoint,
                    StoredOutput {
                        position: transaction.position,
                        outpoint,
                        output: output.clone(),
                    },
                );
                undo.output_outpoints.push(outpoint);
            }
            self.append_event(StoredEvent::TransactionApplied {
                anchor: delta.anchor,
                txid: transaction.txid,
                position: transaction.position,
                affected_contract_ids: affected.clone(),
                affected_market_ids: affected,
            });
        }
        assert!(
            delta.recovery_hints.is_empty(),
            "the bounded seeded model does not generate recovery hints"
        );

        self.known_heights.insert(delta.anchor.height);
        self.blocks.push(ModelBlock {
            delta: delta.clone(),
            before,
            undo,
        });
        self.undo_heights.insert(delta.anchor.height);
        let keep_from = delta
            .anchor
            .height
            .saturating_sub(UNDO_RETENTION_BLOCKS - 1);
        self.undo_heights.retain(|height| *height >= keep_from);
        self.tip = delta.anchor;
    }

    fn rollback(&mut self, depth: usize) -> ChainAnchor {
        assert!((1..=2).contains(&depth));
        assert!(depth <= self.blocks.len());
        let new_len = self.blocks.len() - depth;
        let old_tip = self.tip;
        let mut orphaned_positions = Vec::new();
        let mut affected_contract_ids = Vec::new();
        for block in &self.blocks[new_len..] {
            for transaction in &block.delta.relevant_transactions {
                orphaned_positions.push(transaction.position);
                affected_contract_ids.extend(
                    transaction
                        .created_contracts
                        .iter()
                        .map(|record| record.contract_id),
                );
                affected_contract_ids.extend(
                    transaction
                        .state_updates
                        .iter()
                        .map(|update| update.contract_id),
                );
            }
        }
        orphaned_positions.sort();
        affected_contract_ids.sort_by_key(|contract| contract.to_fixed_key());
        affected_contract_ids.dedup();
        self.materialized = self.blocks[new_len].before.clone();
        self.blocks.truncate(new_len);
        self.tip = self
            .blocks
            .last()
            .map_or(self.activation, |block| block.delta.anchor);
        self.undo_heights
            .retain(|height| *height <= self.tip.height);
        self.status = SyncStatus::Syncing;
        self.append_event(StoredEvent::ChainRolledBack {
            old_tip,
            new_tip: self.tip,
            orphaned_positions,
            affected_contract_ids: affected_contract_ids.clone(),
            affected_market_ids: affected_contract_ids,
        });
        self.tip
    }

    fn can_rollback_to(&self, ancestor: ChainAnchor) -> bool {
        let depth = self.tip.height - ancestor.height;
        depth <= UNDO_RETENTION_BLOCKS
            && (ancestor.height + 1..=self.tip.height)
                .all(|height| self.undo_heights.contains(&height))
    }

    fn require_rebuild(&mut self, new_epoch: [u8; 16]) {
        assert_ne!(self.cursor.epoch, new_epoch);
        self.status = SyncStatus::RescanRequired;
        self.cursor = EventCursor {
            epoch: new_epoch,
            sequence: 0,
        };
        self.events.clear();
        self.append_event(StoredEvent::SyncStatusChanged {
            status: SyncStatus::RescanRequired,
        });
    }

    fn reset_for_rebuild(&mut self) {
        assert_eq!(self.status, SyncStatus::RescanRequired);
        self.tip = self.activation;
        self.status = SyncStatus::Syncing;
        self.blocks.clear();
        self.undo_heights.clear();
        self.materialized = MaterializedModel::default();
        self.append_event(StoredEvent::SyncStatusChanged {
            status: SyncStatus::Syncing,
        });
    }

    fn append_event(&mut self, event: StoredEvent) {
        self.cursor.sequence = self
            .cursor
            .sequence
            .checked_add(1)
            .expect("model event sequence overflow");
        let envelope = StoredEventEnvelope {
            cursor: self.cursor,
            event,
        };
        assert!(
            self.all_events
                .insert(self.cursor, envelope.clone())
                .is_none(),
            "model event cursor collision"
        );
        self.events.push(envelope);
    }
}

fn normalized_record(record: &ContractRecord, tip: ChainAnchor) -> ContractRecord {
    let mut record = record.clone();
    if matches!(record.sync_state, ContractSyncState::Ready { .. }) {
        record.sync_state = ContractSyncState::Ready {
            synced_through: tip,
        };
    }
    record
}

fn model_encode<T: Serialize>(value: &T) -> Vec<u8> {
    let mut encoded = vec![RECORD_VERSION];
    encoded.extend(postcard::to_allocvec(value).expect("model record encoding"));
    encoded
}

fn model_digest<T: Serialize>(value: &T) -> [u8; 32] {
    Sha256::digest(postcard::to_allocvec(value).expect("model digest encoding")).into()
}

fn model_outpoint_key(outpoint: OutPoint) -> Vec<u8> {
    let mut key = Vec::with_capacity(36);
    key.extend_from_slice(&outpoint.txid.to_byte_array());
    key.extend_from_slice(&outpoint.vout.to_be_bytes());
    key
}

fn model_contract_outpoint_key(contract_id: ContractId, role: u8) -> Vec<u8> {
    let mut key = contract_id.to_fixed_key().to_vec();
    key.push(role);
    key
}

fn model_script_key(contract_id: ContractId, binding: &ScriptBinding) -> Vec<u8> {
    let mut key = Vec::with_capacity(69);
    key.extend_from_slice(&<[u8; 32]>::from(Sha256::digest(&binding.script_pubkey)));
    key.extend_from_slice(&contract_id.to_fixed_key());
    key.push(binding.role);
    key
}

fn model_asset_relation_tag(relation: AssetRelationKind) -> u8 {
    match relation {
        AssetRelationKind::Collateral => 0,
        AssetRelationKind::YesToken => 1,
        AssetRelationKind::NoToken => 2,
        AssetRelationKind::YesReissuanceToken => 3,
        AssetRelationKind::NoReissuanceToken => 4,
        AssetRelationKind::OrderBase => 5,
        AssetRelationKind::OrderQuote => 6,
    }
}

fn model_asset_key(contract_id: ContractId, binding: AssetBinding) -> Vec<u8> {
    let mut key = Vec::with_capacity(70);
    key.extend_from_slice(&binding.asset_id.into_inner().to_byte_array());
    key.push(model_asset_relation_tag(binding.relation));
    key.extend_from_slice(&contract_id.to_fixed_key());
    key.push(binding.role);
    key
}

fn model_history_key(contract_id: ContractId, position: ChainPosition) -> Vec<u8> {
    let mut key = contract_id.to_fixed_key().to_vec();
    key.extend_from_slice(&position.to_fixed_key());
    key
}

fn sorted(mut rows: Vec<RawRow>) -> Vec<RawRow> {
    rows.sort();
    rows
}

fn model_inventory(model: &ReferenceModel) -> DatabaseInventory {
    let meta = sorted(vec![
        (
            SCHEMA_VERSION_KEY.as_bytes().to_vec(),
            SCHEMA_VERSION.to_be_bytes().to_vec(),
        ),
        (
            EVENT_EPOCH_KEY.as_bytes().to_vec(),
            model.cursor.epoch.to_vec(),
        ),
        (
            EVENT_SEQUENCE_KEY.as_bytes().to_vec(),
            model.cursor.sequence.to_be_bytes().to_vec(),
        ),
        (
            SYNC_STATUS_KEY.as_bytes().to_vec(),
            model_encode(&model.status),
        ),
        (
            CHAIN_IDENTITY_KEY.as_bytes().to_vec(),
            model_encode(&test_identity()),
        ),
        (
            ACTIVATION_ANCHOR_KEY.as_bytes().to_vec(),
            model_encode(&model.activation),
        ),
    ]);
    let chain_tip = vec![(TIP_KEY.as_bytes().to_vec(), model_encode(&model.tip))];

    let blocks = model
        .blocks
        .iter()
        .map(|block| {
            (
                block.delta.anchor.height.to_be_bytes().to_vec(),
                model_encode(&StoredBlock {
                    anchor: block.delta.anchor,
                    prev_block_hash: block.delta.prev_block_hash,
                    ordered_txids: block.delta.ordered_txids.clone(),
                    delta_digest: model_digest(&block.delta),
                }),
            )
        })
        .collect();
    let transactions = model
        .materialized
        .transactions
        .iter()
        .map(|(position, transaction)| {
            (position.to_fixed_key().to_vec(), model_encode(transaction))
        })
        .collect();
    let outputs = sorted(
        model
            .materialized
            .outputs
            .iter()
            .map(|(outpoint, output)| {
                (
                    model_outpoint_key(*outpoint),
                    model_encode(&StoredOutputRef {
                        position: output.position,
                        outpoint: *outpoint,
                    }),
                )
            })
            .collect(),
    );
    let contracts = model
        .materialized
        .contracts
        .iter()
        .map(|(contract_id, contract)| {
            (
                contract_id.to_fixed_key().to_vec(),
                model_encode(&contract.record),
            )
        })
        .collect();

    let mut outpoint_owners = Vec::new();
    let mut contract_outpoints = Vec::new();
    let mut script_index = Vec::new();
    let mut asset_relations = Vec::new();
    let mut contract_history = Vec::new();
    for contract in model.materialized.contracts.values() {
        for tracked in &contract.record.outpoints {
            outpoint_owners.push((
                model_outpoint_key(tracked.outpoint),
                model_encode(&OutpointOwner {
                    contract_id: contract.record.contract_id,
                    role: tracked.role,
                }),
            ));
            contract_outpoints.push((
                model_contract_outpoint_key(contract.record.contract_id, tracked.role),
                model_encode(&tracked.outpoint),
            ));
        }
        for binding in &contract.record.scripts {
            script_index.push((
                model_script_key(contract.record.contract_id, binding),
                model_encode(binding),
            ));
        }
        for binding in &contract.record.assets {
            asset_relations.push((
                model_asset_key(contract.record.contract_id, *binding),
                model_encode(binding),
            ));
        }
        for history in &contract.history {
            contract_history.push((
                model_history_key(contract.record.contract_id, history.position),
                model_encode(history),
            ));
        }
    }

    let undo_blocks = model
        .blocks
        .iter()
        .filter(|block| model.undo_heights.contains(&block.delta.anchor.height))
        .map(|block| {
            (
                block.delta.anchor.height.to_be_bytes().to_vec(),
                model_encode(&block.undo),
            )
        })
        .collect();
    let events = model
        .all_events
        .iter()
        .map(|(cursor, event)| (cursor.to_fixed_key().to_vec(), model_encode(event)))
        .collect();

    DatabaseInventory {
        meta,
        chain_tip,
        blocks,
        transactions,
        outputs,
        contracts,
        retained_declarations: Vec::new(),
        outpoint_owners: sorted(outpoint_owners),
        contract_outpoints: sorted(contract_outpoints),
        script_index: sorted(script_index),
        asset_relations: sorted(asset_relations),
        market_children: Vec::new(),
        order_book: Vec::new(),
        recovery_hints: Vec::new(),
        contract_history: sorted(contract_history),
        backfill_progress: Vec::new(),
        undo_blocks,
        events,
    }
}

fn assert_matches_model(store: &Store, model: &ReferenceModel, seed: u64, step: usize) {
    let context = || format!("seed {seed:#x}, step {step}");
    assert_eq!(store.tip().expect("tip"), Some(model.tip), "{}", context());
    assert_eq!(
        store.sync_status().expect("sync status"),
        model.status,
        "{}",
        context()
    );
    assert_eq!(
        store.activation_anchor().expect("activation"),
        Some(model.activation),
        "{}",
        context()
    );
    assert_eq!(
        store.event_high_watermark().expect("event cursor"),
        model.cursor,
        "{}",
        context()
    );
    assert_eq!(
        store.events_after(None, usize::MAX).expect("events"),
        model.events,
        "{}",
        context()
    );
    assert_eq!(
        database_inventory(store),
        model_inventory(model),
        "{}",
        context()
    );

    for height in &model.known_heights {
        let expected = model
            .blocks
            .iter()
            .find(|block| block.delta.anchor.height == *height);
        let actual = store.block(*height).expect("block lookup");
        match (expected, actual) {
            (None, None) => {}
            (Some(expected), Some(actual)) => {
                assert_eq!(actual.anchor, expected.delta.anchor, "{}", context());
                assert_eq!(
                    actual.prev_block_hash,
                    expected.delta.prev_block_hash,
                    "{}",
                    context()
                );
                assert_eq!(
                    actual.ordered_txids,
                    expected.delta.ordered_txids,
                    "{}",
                    context()
                );
            }
            pair => panic!(
                "block mismatch ({}) at height {height}: {pair:?}",
                context()
            ),
        }
    }

    for contract_id in &model.known_contracts {
        let expected = model.materialized.contracts.get(contract_id);
        let expected_record =
            expected.map(|contract| normalized_record(&contract.record, model.tip));
        assert_eq!(
            store.contract(*contract_id).expect("contract lookup"),
            expected_record,
            "{}",
            context()
        );
        assert_eq!(
            store
                .contract_history(*contract_id)
                .expect("contract history"),
            expected.map_or_else(Vec::new, |contract| contract.history.clone()),
            "{}",
            context()
        );
    }

    for position in &model.known_positions {
        assert_eq!(
            store.transaction(*position).expect("transaction lookup"),
            model.materialized.transactions.get(position).cloned(),
            "{}",
            context()
        );
    }

    for outpoint in &model.known_outpoints {
        assert_eq!(
            store.output(*outpoint).expect("output lookup"),
            model.materialized.outputs.get(outpoint).cloned(),
            "{}",
            context()
        );
        let expected_owner = model.materialized.contracts.values().find_map(|contract| {
            contract
                .record
                .outpoints
                .iter()
                .find(|tracked| tracked.outpoint == *outpoint)
                .map(|tracked| OutpointOwner {
                    contract_id: contract.record.contract_id,
                    role: tracked.role,
                })
        });
        assert_eq!(
            store.outpoint_owner(*outpoint).expect("outpoint owner"),
            expected_owner,
            "{}",
            context()
        );
    }
}

fn next_nonce(nonce: &mut u32) -> u32 {
    let value = *nonce;
    *nonce = nonce.checked_add(1).expect("test nonce overflow");
    value
}

fn generated_block(
    model: &ReferenceModel,
    rng: &mut DeterministicRng,
    nonce: &mut u32,
) -> BlockDelta {
    let height = model.tip.height + 1;
    let anchor = ChainAnchor {
        height,
        hash: test_hash(u64::from(next_nonce(nonce)) | (u64::from(height) << 32)),
    };

    if !model.materialized.contracts.is_empty() && rng.one_in(5) {
        let irrelevant = transaction(next_nonce(nonce), &[], 1);
        return BlockDelta {
            anchor,
            prev_block_hash: model.tip.hash,
            ordered_txids: vec![irrelevant.txid()],
            relevant_transactions: Vec::new(),
            recovery_hints: Vec::new(),
        };
    }

    let position = ChainPosition {
        block_height: height,
        tx_index: 0,
    };
    let create = model.materialized.contracts.is_empty() || rng.one_in(3);
    let transaction_count = if rng.one_in(3) { 2 } else { 1 };
    let tag = next_nonce(nonce);

    let (raw_tx, created_contracts, state_updates) = if create {
        let raw_tx = transaction(tag, &[], transaction_count);
        let txid = raw_tx.txid();
        let created = (0..transaction_count)
            .map(|vout| {
                market_record(
                    tag.wrapping_add(u32::try_from(vout).expect("small vout")) as u8,
                    position,
                    txid,
                    u32::try_from(vout).expect("small vout"),
                    anchor,
                )
            })
            .collect();
        (raw_tx, created, Vec::new())
    } else {
        let contracts: Vec<_> = model.materialized.contracts.values().collect();
        let first = rng.index(contracts.len());
        let mut selected = vec![contracts[first]];
        if contracts.len() > 1 && transaction_count == 2 {
            let offset = 1 + rng.index(contracts.len() - 1);
            selected.push(contracts[(first + offset) % contracts.len()]);
        }
        let inputs: Vec<_> = selected
            .iter()
            .map(|contract| contract.record.outpoints[0].outpoint)
            .collect();
        let raw_tx = transaction(tag, &inputs, selected.len());
        let txid = raw_tx.txid();
        let updates = selected
            .iter()
            .enumerate()
            .map(|(vout, contract)| {
                let old_pairs = market_pairs(contract.record.state);
                let new_pairs = old_pairs + 1 + (rng.next_u64() % 50);
                StateUpdate {
                    contract_id: contract.record.contract_id,
                    old_state: contract.record.state,
                    new_state: ContractState::BinaryMarket(BinaryMarketState::Trading {
                        outstanding_pairs: new_pairs,
                    }),
                    spent_outpoints: vec![contract.record.outpoints[0].outpoint],
                    new_outpoints: vec![TrackedOutpoint {
                        role: 0,
                        outpoint: OutPoint::new(
                            txid,
                            u32::try_from(vout).expect("small generated vout"),
                        ),
                    }],
                    order_remaining_base: None,
                    transition: TransitionRecord {
                        kind: 1,
                        payload: new_pairs.to_be_bytes().to_vec(),
                    },
                }
            })
            .collect();
        (raw_tx, Vec::new(), updates)
    };
    let txid = raw_tx.txid();
    BlockDelta {
        anchor,
        prev_block_hash: model.tip.hash,
        ordered_txids: vec![txid],
        relevant_transactions: vec![ChainTxDelta {
            position,
            block_hash: anchor.hash,
            txid,
            raw_tx,
            created_contracts,
            state_updates,
        }],
        recovery_hints: Vec::new(),
    }
}

fn initialized_store() -> (tempfile::TempDir, PathBuf, Store, EventCursor) {
    let directory = tempfile::tempdir().expect("temporary store directory");
    let path = directory.path().join("deadcat.redb");
    let store = Store::open(&path).expect("open store");
    store
        .initialize_chain(test_identity(), activation())
        .expect("initialize chain");
    let cursor = store
        .set_sync_status(SyncStatus::Syncing)
        .expect("set syncing");
    (directory, path, store, cursor)
}

#[test]
fn seeded_reference_model_matches_redb_across_apply_rollback_rebuild_and_reopen() {
    for seed in RANDOM_SEEDS {
        let (_directory, path, mut store, cursor) = initialized_store();
        let mut model = ReferenceModel::new(activation(), cursor);
        let mut rng = DeterministicRng(seed);
        let mut nonce = (seed as u32) | 1;
        assert_matches_model(&store, &model, seed, 0);

        for step in 1..=RANDOM_STEPS {
            let action = rng.index(100);
            if action < 58 || model.blocks.is_empty() {
                let delta = generated_block(&model, &mut rng, &mut nonce);
                let result = store.apply_block(&delta).expect("apply generated block");
                assert!(result.applied);
                model.apply(&delta);
            } else if action < 76 {
                let depth = 1 + rng.index(model.blocks.len().min(2));
                let target = if model.blocks.len() == depth {
                    model.activation
                } else {
                    model.blocks[model.blocks.len() - depth - 1].delta.anchor
                };
                let can_rollback = model.can_rollback_to(target);
                let result = store.rollback_to(target).expect("shallow rollback");
                if can_rollback {
                    assert!(
                        matches!(result, RollbackResult::RolledBack { .. }),
                        "seed {seed:#x}, step {step}, depth {depth}, target {target:?}: {result:?}"
                    );
                    assert_eq!(model.rollback(depth), target);
                } else {
                    let RollbackResult::RebuildRequired {
                        new_event_epoch, ..
                    } = result
                    else {
                        panic!("missing undo must require rebuild: {result:?}");
                    };
                    model.require_rebuild(new_event_epoch);
                    assert_matches_model(&store, &model, seed, step);

                    drop(store);
                    store = Store::open(&path).expect("reopen cumulatively deep rollback");
                    assert_matches_model(&store, &model, seed, step);

                    store.reset_for_rebuild().expect("reset for replay");
                    model.reset_for_rebuild();
                }
            } else if action < 84 {
                let delta = &model.blocks.last().expect("nonempty chain").delta;
                let result = store.apply_block(delta).expect("idempotent retry");
                assert!(!result.applied);
            } else if action < 94 && model.blocks.len() >= 3 {
                let result = store
                    .rollback_to(model.activation)
                    .expect("deep rollback invalidation");
                let RollbackResult::RebuildRequired {
                    new_event_epoch, ..
                } = result
                else {
                    panic!("deep rollback must require rebuild");
                };
                model.require_rebuild(new_event_epoch);
                assert_matches_model(&store, &model, seed, step);

                drop(store);
                store = Store::open(&path).expect("reopen invalidated store");
                assert_matches_model(&store, &model, seed, step);

                store.reset_for_rebuild().expect("reset for replay");
                model.reset_for_rebuild();
            } else {
                drop(store);
                store = Store::open(&path).expect("random reopen");
            }

            assert_matches_model(&store, &model, seed, step);
            if rng.one_in(7) {
                drop(store);
                store = Store::open(&path).expect("post-operation reopen");
                assert_matches_model(&store, &model, seed, step);
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Probe {
    heights: BTreeSet<u32>,
    contracts: BTreeSet<ContractId>,
    positions: BTreeSet<ChainPosition>,
    outpoints: BTreeSet<OutPoint>,
    hints: Vec<RecoveryHintLocation>,
}

impl Probe {
    fn for_blocks(blocks: &[&BlockDelta]) -> Self {
        let mut probe = Self::default();
        for block in blocks {
            probe.heights.insert(block.anchor.height);
            for transaction in &block.relevant_transactions {
                probe.positions.insert(transaction.position);
                probe.contracts.extend(
                    transaction
                        .created_contracts
                        .iter()
                        .map(|record| record.contract_id),
                );
                probe.contracts.extend(
                    transaction
                        .state_updates
                        .iter()
                        .map(|update| update.contract_id),
                );
                for vout in 0..transaction.raw_tx.output.len() {
                    probe.outpoints.insert(OutPoint::new(
                        transaction.txid,
                        u32::try_from(vout).expect("small fixture vout"),
                    ));
                }
                probe.outpoints.extend(
                    transaction
                        .raw_tx
                        .input
                        .iter()
                        .map(|input| input.previous_output),
                );
            }
            for hint in &block.recovery_hints {
                if !probe.hints.contains(&hint.location) {
                    probe.hints.push(hint.location);
                }
            }
        }
        probe
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SemanticSnapshot {
    inventory: DatabaseInventory,
    schema_version: u32,
    identity: Option<ChainIdentity>,
    activation: Option<ChainAnchor>,
    status: StoreStatusSnapshot,
    blocks: Vec<(u32, Option<StoredBlock>)>,
    contracts: Vec<(ContractId, Option<ContractRecord>, Vec<StoredHistoryEntry>)>,
    transactions: Vec<(ChainPosition, Option<StoredTransaction>)>,
    outputs: Vec<(OutPoint, Option<StoredOutput>, Option<OutpointOwner>)>,
    hints: Vec<(RecoveryHintLocation, Option<StoredRecoveryHint>)>,
    events: Vec<StoredEventEnvelope>,
}

fn semantic_snapshot(store: &Store, probe: &Probe) -> SemanticSnapshot {
    SemanticSnapshot {
        inventory: database_inventory(store),
        schema_version: store.schema_version().expect("schema version"),
        identity: store.chain_identity().expect("chain identity"),
        activation: store.activation_anchor().expect("activation anchor"),
        status: store.status_snapshot().expect("status snapshot"),
        blocks: probe
            .heights
            .iter()
            .map(|height| (*height, store.block(*height).expect("block")))
            .collect(),
        contracts: probe
            .contracts
            .iter()
            .map(|contract_id| {
                (
                    *contract_id,
                    store.contract(*contract_id).expect("contract"),
                    store
                        .contract_history(*contract_id)
                        .expect("contract history"),
                )
            })
            .collect(),
        transactions: probe
            .positions
            .iter()
            .map(|position| {
                (
                    *position,
                    store.transaction(*position).expect("transaction"),
                )
            })
            .collect(),
        outputs: probe
            .outpoints
            .iter()
            .map(|outpoint| {
                (
                    *outpoint,
                    store.output(*outpoint).expect("output"),
                    store.outpoint_owner(*outpoint).expect("owner"),
                )
            })
            .collect(),
        hints: probe
            .hints
            .iter()
            .map(|location| {
                (
                    *location,
                    store.recovery_hint(*location).expect("recovery hint"),
                )
            })
            .collect(),
        events: store.events_after(None, usize::MAX).expect("events"),
    }
}

fn assert_injected<T>(result: &Result<T, StoreError>, expected: &'static str) {
    assert!(
        matches!(
            result,
            Err(StoreError::InjectedMutationFailure(actual)) if *actual == expected
        ),
        "expected failpoint {expected}"
    );
}

fn two_transaction_creation_block() -> BlockDelta {
    let anchor = ChainAnchor {
        height: 1,
        hash: test_hash(1),
    };
    let first = transaction(10_001, &[], 1);
    let second = transaction(10_002, &[], 1);
    let first_position = ChainPosition {
        block_height: 1,
        tx_index: 0,
    };
    let second_position = ChainPosition {
        block_height: 1,
        tx_index: 1,
    };
    let first_market = market_record(0x31, first_position, first.txid(), 0, anchor);
    let second_market = market_record(0x41, second_position, second.txid(), 0, anchor);
    let first_id = first_market.contract_id;
    BlockDelta {
        anchor,
        prev_block_hash: activation().hash,
        ordered_txids: vec![first.txid(), second.txid()],
        relevant_transactions: vec![
            ChainTxDelta {
                position: first_position,
                block_hash: anchor.hash,
                txid: first.txid(),
                raw_tx: first,
                created_contracts: vec![first_market],
                state_updates: Vec::new(),
            },
            ChainTxDelta {
                position: second_position,
                block_hash: anchor.hash,
                txid: second.txid(),
                raw_tx: second,
                created_contracts: vec![second_market],
                state_updates: Vec::new(),
            },
        ],
        recovery_hints: vec![RecoveryHintDelta {
            location: RecoveryHintLocation {
                position: first_position,
                output_index: 0,
            },
            creation_txid: first_id.txid(),
            family: RecoveryFamily::BinaryMarketV1,
            payload: vec![0x10, 0x01],
            associated_contract: Some(first_id),
        }],
    }
}

fn composed_transition_block(previous: &BlockDelta) -> BlockDelta {
    let anchor = ChainAnchor {
        height: 2,
        hash: test_hash(2),
    };
    let records: Vec<_> = previous
        .relevant_transactions
        .iter()
        .flat_map(|transaction| transaction.created_contracts.iter())
        .collect();
    let inputs: Vec<_> = records
        .iter()
        .map(|record| record.outpoints[0].outpoint)
        .collect();
    let raw_tx = transaction(10_003, &inputs, records.len());
    let txid = raw_tx.txid();
    let position = ChainPosition {
        block_height: 2,
        tx_index: 0,
    };
    let state_updates = records
        .iter()
        .enumerate()
        .map(|(vout, record)| StateUpdate {
            contract_id: record.contract_id,
            old_state: record.state,
            new_state: ContractState::BinaryMarket(BinaryMarketState::Trading {
                outstanding_pairs: u64::try_from(vout + 1).expect("small pair count") * 10,
            }),
            spent_outpoints: vec![record.outpoints[0].outpoint],
            new_outpoints: vec![TrackedOutpoint {
                role: 0,
                outpoint: OutPoint::new(txid, u32::try_from(vout).expect("small vout")),
            }],
            order_remaining_base: None,
            transition: TransitionRecord {
                kind: 1,
                payload: vec![u8::try_from(vout).expect("small transition")],
            },
        })
        .collect();
    BlockDelta {
        anchor,
        prev_block_hash: previous.anchor.hash,
        ordered_txids: vec![txid],
        relevant_transactions: vec![ChainTxDelta {
            position,
            block_hash: anchor.hash,
            txid,
            raw_tx,
            created_contracts: Vec::new(),
            state_updates,
        }],
        recovery_hints: Vec::new(),
    }
}

fn empty_third_block(previous: &BlockDelta) -> BlockDelta {
    let raw_tx = transaction(10_004, &[], 1);
    BlockDelta {
        anchor: ChainAnchor {
            height: 3,
            hash: test_hash(3),
        },
        prev_block_hash: previous.anchor.hash,
        ordered_txids: vec![raw_tx.txid()],
        relevant_transactions: Vec::new(),
        recovery_hints: Vec::new(),
    }
}

fn empty_block_at(
    height: u32,
    hash_domain: u64,
    previous_hash: BlockHash,
    transaction_tag: u32,
) -> BlockDelta {
    let raw_tx = transaction(transaction_tag, &[], 1);
    BlockDelta {
        anchor: ChainAnchor {
            height,
            hash: test_hash(hash_domain),
        },
        prev_block_hash: previous_hash,
        ordered_txids: vec![raw_tx.txid()],
        relevant_transactions: Vec::new(),
        recovery_hints: Vec::new(),
    }
}

fn catching_up_apply_fixture(store: &Store) -> (BlockDelta, BlockDelta, ContractId, Probe) {
    let creation = transaction(20_001, &[], 1);
    let creation_position = ChainPosition {
        block_height: 1,
        tx_index: 0,
    };
    let indexed_creation = BlockDelta {
        anchor: ChainAnchor {
            height: 1,
            hash: test_hash(0x201),
        },
        prev_block_hash: activation().hash,
        ordered_txids: vec![creation.txid()],
        relevant_transactions: Vec::new(),
        recovery_hints: Vec::new(),
    };
    store
        .apply_block(&indexed_creation)
        .expect("index creation block");

    let mut market = market_record(
        0x71,
        creation_position,
        creation.txid(),
        0,
        indexed_creation.anchor,
    );
    market.sync_state = ContractSyncState::CatchingUp {
        synced_through: indexed_creation.anchor,
    };
    store
        .register_contract(
            &market,
            &RegistrationEvidence {
                anchor: indexed_creation.anchor,
                transaction: Arc::new(creation),
                associated_hint: None,
            },
        )
        .expect("register catching-up market");

    // Model the coordinator race for which `advance_catching...` exists: the
    // durable replay cursor is waiting exactly at the next canonical block.
    let mut progress = store
        .backfill_progress(market.contract_id)
        .expect("backfill progress")
        .expect("registered progress");
    progress.next_position = ChainPosition {
        block_height: 2,
        tx_index: 0,
    };
    let write = store.database.begin_write().expect("progress write");
    write_fixed(
        &write,
        BACKFILL_PROGRESS,
        &market.contract_id.to_fixed_key(),
        &progress,
    )
    .expect("align progress with next block");
    write.commit().expect("commit aligned progress");

    let candidate = empty_block_at(2, 0x202, indexed_creation.anchor.hash, 20_002);
    let mut probe = Probe::for_blocks(&[&indexed_creation, &candidate]);
    probe.contracts.insert(market.contract_id);
    probe.positions.insert(creation_position);
    probe.outpoints.insert(market.contract_id.creation_anchor());
    (indexed_creation, candidate, market.contract_id, probe)
}

fn undo_inventory_heights(inventory: &DatabaseInventory) -> Vec<u32> {
    inventory
        .undo_blocks
        .iter()
        .map(|(key, _)| u32::from_be_bytes(key.as_slice().try_into().expect("four-byte undo key")))
        .collect()
}

#[test]
fn apply_failpoints_abort_every_mutation_boundary_and_retry_after_reopen() {
    let cases = [
        (mutation_failpoints::APPLY_AFTER_TRANSACTION, 0),
        (mutation_failpoints::APPLY_AFTER_TRANSACTION, 1),
        (mutation_failpoints::APPLY_AFTER_RECOVERY_HINT, 0),
        (mutation_failpoints::APPLY_AFTER_BLOCK, 0),
        (mutation_failpoints::APPLY_AFTER_UNDO, 0),
        (mutation_failpoints::APPLY_AFTER_TIP, 0),
        (mutation_failpoints::APPLY_BEFORE_COMMIT, 0),
    ];
    for (name, occurrence) in cases {
        let (_directory, path, store, _cursor) = initialized_store();
        let block = two_transaction_creation_block();
        let probe = Probe::for_blocks(&[&block]);
        let before = semantic_snapshot(&store, &probe);

        let guard = mutation_failpoints::arm(name, occurrence);
        assert_injected(&store.apply_block(&block), name);
        drop(guard);
        drop(store);

        let reopened = Store::open(&path).expect("reopen after aborted apply");
        assert_eq!(semantic_snapshot(&reopened, &probe), before, "{name}");
        reopened.apply_block(&block).expect("retry apply");
        let after_retry = semantic_snapshot(&reopened, &probe);
        drop(reopened);

        let reopened = Store::open(&path).expect("reopen after apply retry");
        assert_eq!(semantic_snapshot(&reopened, &probe), after_retry, "{name}");
        assert!(
            after_retry
                .contracts
                .iter()
                .all(|(_, record, _)| record.is_some())
        );
    }
}

#[test]
fn catch_up_failpoint_aborts_real_contract_progress_and_event_mutations() {
    let (_directory, path, store, _cursor) = initialized_store();
    let (_indexed_creation, candidate, contract_id, probe) = catching_up_apply_fixture(&store);
    let before = semantic_snapshot(&store, &probe);
    assert!(matches!(
        store
            .contract(contract_id)
            .expect("catching-up contract")
            .expect("registered contract")
            .sync_state,
        ContractSyncState::CatchingUp { .. }
    ));

    let name = mutation_failpoints::APPLY_AFTER_CATCH_UP;
    let guard = mutation_failpoints::arm(name, 0);
    assert_injected(&store.apply_block(&candidate), name);
    drop(guard);
    drop(store);

    let reopened = Store::open(&path).expect("reopen after aborted catch-up advancement");
    assert_eq!(semantic_snapshot(&reopened, &probe), before);
    reopened
        .apply_block(&candidate)
        .expect("retry catch-up block");
    let after_retry = semantic_snapshot(&reopened, &probe);
    assert_ne!(after_retry.inventory, before.inventory);
    assert!(matches!(
        reopened
            .contract(contract_id)
            .expect("ready contract")
            .expect("materialized contract")
            .sync_state,
        ContractSyncState::Ready { .. }
    ));
    let progress = reopened
        .backfill_progress(contract_id)
        .expect("advanced progress")
        .expect("durable progress");
    assert_eq!(progress.next_position.block_height, 3);
    assert!(progress.last_applied.is_some());
    drop(reopened);

    let reopened = Store::open(&path).expect("reopen after catch-up retry");
    assert_eq!(semantic_snapshot(&reopened, &probe), after_retry);
}

#[test]
fn prune_failpoint_restores_the_undo_row_that_pruning_actually_removed() {
    let (_directory, path, store, _cursor) = initialized_store();
    let first = empty_block_at(1, 0x301, activation().hash, 30_001);
    let second = empty_block_at(2, 0x302, first.anchor.hash, 30_002);
    let candidate = empty_block_at(3, 0x303, second.anchor.hash, 30_003);
    store.apply_block(&first).expect("first empty block");
    store.apply_block(&second).expect("second empty block");
    let probe = Probe::for_blocks(&[&first, &second, &candidate]);
    let before = semantic_snapshot(&store, &probe);
    assert_eq!(undo_inventory_heights(&before.inventory), vec![1, 2]);

    let name = mutation_failpoints::APPLY_AFTER_PRUNE;
    let guard = mutation_failpoints::arm(name, 0);
    assert_injected(&store.apply_block(&candidate), name);
    drop(guard);
    drop(store);

    let reopened = Store::open(&path).expect("reopen after aborted prune");
    assert_eq!(semantic_snapshot(&reopened, &probe), before);
    assert_eq!(
        undo_inventory_heights(&database_inventory(&reopened)),
        vec![1, 2]
    );
    reopened
        .apply_block(&candidate)
        .expect("retry pruned block");
    let after_retry = semantic_snapshot(&reopened, &probe);
    assert_eq!(undo_inventory_heights(&after_retry.inventory), vec![2, 3]);
    drop(reopened);

    let reopened = Store::open(&path).expect("reopen after prune retry");
    assert_eq!(semantic_snapshot(&reopened, &probe), after_retry);
}

#[test]
fn rollback_failpoints_restore_the_pre_rollback_snapshot_and_retry_cleanly() {
    let cases = [
        (mutation_failpoints::ROLLBACK_AFTER_BLOCK, 0),
        (mutation_failpoints::ROLLBACK_AFTER_BLOCK, 1),
        (mutation_failpoints::ROLLBACK_AFTER_TIP, 0),
        (mutation_failpoints::ROLLBACK_AFTER_STATUS, 0),
        (mutation_failpoints::ROLLBACK_AFTER_EVENT, 0),
        (mutation_failpoints::ROLLBACK_BEFORE_COMMIT, 0),
    ];
    for (name, occurrence) in cases {
        let (_directory, path, store, _cursor) = initialized_store();
        let first = two_transaction_creation_block();
        let second = composed_transition_block(&first);
        store.apply_block(&first).expect("first block");
        store.apply_block(&second).expect("second block");
        store
            .set_sync_status(SyncStatus::Ready)
            .expect("ready before rollback");
        let probe = Probe::for_blocks(&[&first, &second]);
        let before = semantic_snapshot(&store, &probe);
        assert_eq!(before.status.sync_status, SyncStatus::Ready);

        let guard = mutation_failpoints::arm(name, occurrence);
        assert_injected(&store.rollback_to(activation()), name);
        drop(guard);
        drop(store);

        let reopened = Store::open(&path).expect("reopen after aborted rollback");
        assert_eq!(semantic_snapshot(&reopened, &probe), before, "{name}");
        assert!(matches!(
            reopened.rollback_to(activation()).expect("retry rollback"),
            RollbackResult::RolledBack { .. }
        ));
        let after_retry = semantic_snapshot(&reopened, &probe);
        drop(reopened);

        let reopened = Store::open(&path).expect("reopen after rollback retry");
        assert_eq!(semantic_snapshot(&reopened, &probe), after_retry, "{name}");
        assert_eq!(after_retry.status.indexed_tip, activation());
        assert!(
            after_retry
                .contracts
                .iter()
                .all(|(_, record, history)| { record.is_none() && history.is_empty() })
        );
    }
}

#[test]
fn rebuild_invalidation_failpoints_do_not_publish_a_partial_epoch_rotation() {
    let cases = [
        mutation_failpoints::INVALIDATE_AFTER_REBUILD_MARK,
        mutation_failpoints::INVALIDATE_BEFORE_COMMIT,
    ];
    for name in cases {
        let (_directory, path, store, _cursor) = initialized_store();
        let first = two_transaction_creation_block();
        store.apply_block(&first).expect("first block");
        let probe = Probe::for_blocks(&[&first]);
        let before = semantic_snapshot(&store, &probe);

        let guard = mutation_failpoints::arm(name, 0);
        assert_injected(&store.invalidate_for_rebuild(), name);
        drop(guard);
        drop(store);

        let reopened = Store::open(&path).expect("reopen after aborted invalidation");
        assert_eq!(semantic_snapshot(&reopened, &probe), before, "{name}");
        reopened
            .invalidate_for_rebuild()
            .expect("retry invalidation");
        let after_retry = semantic_snapshot(&reopened, &probe);
        drop(reopened);

        let reopened = Store::open(&path).expect("reopen after invalidation retry");
        assert_eq!(semantic_snapshot(&reopened, &probe), after_retry, "{name}");
        assert_eq!(after_retry.status.sync_status, SyncStatus::RescanRequired);
        assert_ne!(
            after_retry.status.event_high_watermark.epoch,
            before.status.event_high_watermark.epoch
        );
    }
}

#[test]
fn deep_rollback_invalidation_boundary_aborts_without_disabling_the_store() {
    let (_directory, path, store, _cursor) = initialized_store();
    let first = two_transaction_creation_block();
    let second = composed_transition_block(&first);
    let third = empty_third_block(&second);
    store.apply_block(&first).expect("first block");
    store.apply_block(&second).expect("second block");
    store.apply_block(&third).expect("third block");
    let probe = Probe::for_blocks(&[&first, &second, &third]);
    let before = semantic_snapshot(&store, &probe);

    let name = mutation_failpoints::ROLLBACK_AFTER_REBUILD_MARK;
    let guard = mutation_failpoints::arm(name, 0);
    assert_injected(&store.rollback_to(activation()), name);
    drop(guard);
    drop(store);

    let reopened = Store::open(&path).expect("reopen after aborted deep rollback");
    assert_eq!(semantic_snapshot(&reopened, &probe), before);
    assert!(matches!(
        reopened
            .rollback_to(activation())
            .expect("retry deep rollback"),
        RollbackResult::RebuildRequired { .. }
    ));
    assert_eq!(
        reopened.sync_status().expect("status"),
        SyncStatus::RescanRequired
    );
}

#[test]
fn rebuild_reset_failpoints_preserve_invalidated_state_until_atomic_reset() {
    let cases = [
        mutation_failpoints::RESET_AFTER_CLEAR,
        mutation_failpoints::RESET_AFTER_TIP,
        mutation_failpoints::RESET_AFTER_STATUS,
        mutation_failpoints::RESET_AFTER_EVENT,
        mutation_failpoints::RESET_BEFORE_COMMIT,
    ];
    for name in cases {
        let (_directory, path, store, _cursor) = initialized_store();
        let first = two_transaction_creation_block();
        store.apply_block(&first).expect("first block");
        store.invalidate_for_rebuild().expect("invalidate");
        let probe = Probe::for_blocks(&[&first]);
        let before = semantic_snapshot(&store, &probe);

        let guard = mutation_failpoints::arm(name, 0);
        assert_injected(&store.reset_for_rebuild(), name);
        drop(guard);
        drop(store);

        let reopened = Store::open(&path).expect("reopen after aborted reset");
        assert_eq!(semantic_snapshot(&reopened, &probe), before, "{name}");
        reopened.reset_for_rebuild().expect("retry reset");
        let after_retry = semantic_snapshot(&reopened, &probe);
        drop(reopened);

        let reopened = Store::open(&path).expect("reopen after reset retry");
        assert_eq!(semantic_snapshot(&reopened, &probe), after_retry, "{name}");
        assert_eq!(after_retry.status.indexed_tip, activation());
        assert_eq!(after_retry.status.sync_status, SyncStatus::Syncing);
        assert!(after_retry.blocks.iter().all(|(_, block)| block.is_none()));
        assert!(
            after_retry
                .contracts
                .iter()
                .all(|(_, record, history)| { record.is_none() && history.is_empty() })
        );
    }
}

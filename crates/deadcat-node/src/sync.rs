//! Chain-ordered synchronization and late-registration catch-up.
//!
//! The coordinator owns ordering, canonicality checks, reorg recovery, and the
//! atomic store boundary. Contract decoding remains behind [`ChainInterpreter`]
//! so the concrete Simplicity transaction interpreter can land independently.

use std::collections::HashSet;
use std::error::Error as StdError;

use deadcat_rpc::{RecoveryFamily, SyncStatus};
use deadcat_types::{
    ChainAnchor, ChainPosition, ContractDeclaration, ContractId, RecoveryHintLocation,
};
use elements::hashes::{Hash as _, HashEngine as _, sha256d};
use elements::{Block, BlockHash, Transaction, TxMerkleNode};
use thiserror::Error;

use crate::chain::{ChainSource, ChainSourceError};
use crate::store::{
    BlockDelta, ChainTxDelta, ContractRecord, RecoveryHintDelta, RollbackResult, StateUpdate,
    Store, StoreError, UNDO_RETENTION_BLOCKS,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncConfig {
    /// Bound repeated restarts caused by an unstable backend branch.
    pub max_branch_restarts: u32,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_branch_restarts: 8,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterpretationMode<'a> {
    Canonical,
    /// Only these late-registered contracts should be replayed. The slice can
    /// shrink within a block when contracts have different creation indexes.
    Backfill {
        contract_ids: &'a [ContractId],
    },
}

pub struct InterpretationContext<'a> {
    pub store: &'a Store,
    pub anchor: ChainAnchor,
    pub position: ChainPosition,
    /// Relevant deltas already interpreted earlier in this same block. This
    /// is the authoritative view for same-block creations and spends that are
    /// not visible in redb until the complete block commits.
    pub prior_transactions: &'a [ChainTxDelta],
    /// Explicit watch declarations whose creation IDs share the transaction
    /// currently being interpreted. Canonical block coordination prefetches
    /// these once per block; backfill and advisory interpretation pass none.
    pub retained_declarations: &'a [ContractDeclaration],
    pub mode: InterpretationMode<'a>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterpretedRecoveryHint {
    pub output_index: u32,
    pub family: RecoveryFamily,
    pub payload: Vec<u8>,
    pub associated_contract: Option<ContractId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransactionInterpretation {
    pub created_contracts: Vec<ContractRecord>,
    pub state_updates: Vec<StateUpdate>,
    pub recovery_hints: Vec<InterpretedRecoveryHint>,
}

/// Contract-specific decoder boundary. Calls are synchronous because
/// interpretation is CPU/local-state work; all chain I/O stays in the
/// coordinator.
pub trait ChainInterpreter: Send + Sync {
    type Error: StdError + Send + Sync + 'static;

    fn interpret_transaction(
        &self,
        context: &InterpretationContext<'_>,
        transaction: &Transaction,
    ) -> Result<TransactionInterpretation, Self::Error>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncReport {
    pub starting_tip: ChainAnchor,
    pub indexed_tip: ChainAnchor,
    pub blocks_applied: u32,
    pub blocks_rolled_back: u32,
    pub backfill_blocks_applied: u32,
    pub branch_restarts: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncOutcome {
    Ready(SyncReport),
    RescanRequired {
        indexed_tip: ChainAnchor,
        source_tip: ChainAnchor,
    },
}

pub struct SyncCoordinator<'a, S, I> {
    source: &'a S,
    store: &'a Store,
    interpreter: &'a I,
    config: SyncConfig,
}

impl<'a, S, I> SyncCoordinator<'a, S, I>
where
    S: ChainSource,
    I: ChainInterpreter,
{
    #[must_use]
    pub const fn new(source: &'a S, store: &'a Store, interpreter: &'a I) -> Self {
        Self {
            source,
            store,
            interpreter,
            config: SyncConfig {
                max_branch_restarts: 8,
            },
        }
    }

    #[must_use]
    pub const fn with_config(mut self, config: SyncConfig) -> Self {
        self.config = config;
        self
    }

    /// Explicitly reset an invalidated database to its immutable activation
    /// checkpoint and replay to a pinned source tip. A previous invocation
    /// interrupted after the atomic reset resumes from its persisted prefix
    /// without clearing it again.
    pub async fn rebuild_to_tip(&self) -> Result<SyncOutcome, SyncError> {
        let activation = self
            .store
            .activation_anchor()?
            .ok_or(SyncError::ActivationNotInitialized)?;
        let source_tip = self.source.tip().await?;
        if source_tip.height < activation.height {
            return Err(SyncError::ActivationAboveSourceTip {
                activation,
                source_tip,
            });
        }
        let source_hash = self.source.block_hash(activation.height).await?;
        if source_hash != activation.hash {
            return Err(SyncError::ActivationHashMismatch {
                activation,
                actual: source_hash,
            });
        }

        match self.store.sync_status()? {
            SyncStatus::RescanRequired => {
                self.store.reset_for_rebuild()?;
            }
            SyncStatus::Syncing | SyncStatus::BackendUnavailable => {
                let indexed_activation = self.store.canonical_anchor(activation.height)?;
                if indexed_activation != Some(activation) {
                    return Err(SyncError::IndexedActivationMismatch {
                        expected: activation,
                        actual: indexed_activation,
                    });
                }
            }
            status => return Err(SyncError::RebuildNotRequired { status }),
        }
        self.sync_to_tip().await
    }

    /// Reconcile the indexed chain, replay all pending late registrations, and
    /// advance to a pinned source tip. The method returns only after a final
    /// canonicality check or after explicitly entering `RescanRequired`.
    pub async fn sync_to_tip(&self) -> Result<SyncOutcome, SyncError> {
        let starting_tip = self.store.tip()?.ok_or(SyncError::TipNotInitialized)?;
        let initial_status = self.store.sync_status()?;
        if initial_status == SyncStatus::RescanRequired {
            return Ok(SyncOutcome::RescanRequired {
                indexed_tip: starting_tip,
                source_tip: self.source.tip().await?,
            });
        }
        if matches!(
            initial_status,
            SyncStatus::Starting | SyncStatus::BackendUnavailable
        ) {
            self.store.set_sync_status(SyncStatus::Syncing)?;
        }
        let mut report = SyncReport {
            starting_tip,
            indexed_tip: starting_tip,
            blocks_applied: 0,
            blocks_rolled_back: 0,
            backfill_blocks_applied: 0,
            branch_restarts: 0,
        };

        'restart: loop {
            let pinned_tip = self.source.tip().await?;
            match self.reconcile(pinned_tip).await? {
                Reconcile::Stable => {}
                Reconcile::RolledBack(depth) => {
                    report.blocks_rolled_back = report
                        .blocks_rolled_back
                        .checked_add(depth)
                        .ok_or(SyncError::CounterOverflow)?;
                    continue;
                }
                Reconcile::Restart => {
                    self.note_restart(&mut report)?;
                    continue;
                }
                Reconcile::RescanRequired => {
                    report.indexed_tip = self.store.tip()?.ok_or(SyncError::TipNotInitialized)?;
                    return Ok(SyncOutcome::RescanRequired {
                        indexed_tip: report.indexed_tip,
                        source_tip: pinned_tip,
                    });
                }
            }

            match self.backfill_pending(&mut report).await? {
                FetchDisposition::Canonical => {}
                FetchDisposition::BranchChanged => {
                    self.note_restart(&mut report)?;
                    continue;
                }
            }

            let indexed_tip = self.store.tip()?.ok_or(SyncError::TipNotInitialized)?;
            if indexed_tip.height > pinned_tip.height {
                continue;
            }
            if indexed_tip.height < pinned_tip.height {
                self.store.set_sync_status(SyncStatus::Syncing)?;
            }
            for height in indexed_tip.height + 1..=pinned_tip.height {
                let current_tip = self.store.tip()?.ok_or(SyncError::TipNotInitialized)?;
                let fetched = match self
                    .fetch_block(height, pinned_tip, current_tip.hash)
                    .await?
                {
                    FetchResult::Block(block) => block,
                    FetchResult::BranchChanged => {
                        self.note_restart(&mut report)?;
                        continue 'restart;
                    }
                };
                let delta = self.interpret_canonical_block(&fetched)?;
                if !self.block_still_pinned(delta.anchor, pinned_tip).await? {
                    self.note_restart(&mut report)?;
                    continue 'restart;
                }
                self.store.apply_block(&delta)?;
                report.blocks_applied = report
                    .blocks_applied
                    .checked_add(1)
                    .ok_or(SyncError::CounterOverflow)?;
            }

            let final_tip = self.store.tip()?.ok_or(SyncError::TipNotInitialized)?;
            if final_tip != pinned_tip || !self.pin_still_canonical(pinned_tip).await? {
                self.note_restart(&mut report)?;
                continue;
            }
            if !self.store.pending_backfills()?.is_empty() {
                continue;
            }
            self.store.set_sync_status(SyncStatus::Ready)?;
            report.indexed_tip = final_tip;
            return Ok(SyncOutcome::Ready(report));
        }
    }

    fn note_restart(&self, report: &mut SyncReport) -> Result<(), SyncError> {
        report.branch_restarts = report
            .branch_restarts
            .checked_add(1)
            .ok_or(SyncError::CounterOverflow)?;
        if report.branch_restarts > self.config.max_branch_restarts {
            return Err(SyncError::TooManyBranchChanges {
                limit: self.config.max_branch_restarts,
            });
        }
        Ok(())
    }

    async fn reconcile(&self, pinned_tip: ChainAnchor) -> Result<Reconcile, SyncError> {
        let indexed_tip = self.store.tip()?.ok_or(SyncError::TipNotInitialized)?;
        if pinned_tip.height >= indexed_tip.height
            && self.source.block_hash(indexed_tip.height).await? == indexed_tip.hash
        {
            return Ok(Reconcile::Stable);
        }

        let mut common = None;
        for depth in 1..=UNDO_RETENTION_BLOCKS {
            let Some(height) = indexed_tip.height.checked_sub(depth) else {
                break;
            };
            if height > pinned_tip.height {
                continue;
            }
            let local = self
                .store
                .canonical_anchor(height)?
                .ok_or(SyncError::MissingCheckpoint(height))?;
            if self.source.block_hash(height).await? == local.hash {
                common = Some((local, depth));
                break;
            }
        }
        if !self.pin_still_canonical(pinned_tip).await? {
            return Ok(Reconcile::Restart);
        }
        let Some((ancestor, depth)) = common else {
            self.store.invalidate_for_rebuild()?;
            return Ok(Reconcile::RescanRequired);
        };
        match self.store.rollback_to(ancestor)? {
            RollbackResult::RolledBack { .. } | RollbackResult::Noop { .. } => {
                Ok(Reconcile::RolledBack(depth))
            }
            RollbackResult::RebuildRequired { .. } => Ok(Reconcile::RescanRequired),
        }
    }

    async fn backfill_pending(
        &self,
        report: &mut SyncReport,
    ) -> Result<FetchDisposition, SyncError> {
        loop {
            let pending = self.store.pending_backfills()?;
            let Some(first) = pending.first() else {
                return Ok(FetchDisposition::Canonical);
            };
            self.store.set_sync_status(SyncStatus::Syncing)?;
            let indexed_tip = self.store.tip()?.ok_or(SyncError::TipNotInitialized)?;
            if first.next_position.block_height > indexed_tip.height {
                // This occurs after rolling back the block that previously
                // completed a backfill. The next canonical block pass will
                // replay and advance the catching-up contract atomically.
                return Ok(FetchDisposition::Canonical);
            }
            let height = first.next_position.block_height;
            let batch = pending
                .iter()
                .filter(|item| item.next_position.block_height == height)
                .cloned()
                .collect::<Vec<_>>();
            let anchor = self
                .store
                .canonical_anchor(height)?
                .ok_or(SyncError::MissingCheckpoint(height))?;
            let expected_prev = if height == 0 {
                None
            } else {
                Some(
                    self.store
                        .canonical_anchor(height - 1)?
                        .ok_or(SyncError::MissingCheckpoint(height - 1))?
                        .hash,
                )
            };
            let fetched = match self
                .fetch_canonical_backfill_block(anchor, indexed_tip, expected_prev)
                .await?
            {
                FetchResult::Block(block) => block,
                FetchResult::BranchChanged => return Ok(FetchDisposition::BranchChanged),
            };
            let contract_ids = batch
                .iter()
                .map(|item| item.contract_id)
                .collect::<Vec<_>>();
            let delta = self.interpret_backfill_block(&fetched, &batch)?;
            if !self.block_still_pinned(anchor, indexed_tip).await? {
                return Ok(FetchDisposition::BranchChanged);
            }
            let result = self.store.apply_backfill_block(&contract_ids, &delta)?;
            if result.applied {
                report.backfill_blocks_applied = report
                    .backfill_blocks_applied
                    .checked_add(1)
                    .ok_or(SyncError::CounterOverflow)?;
            }
        }
    }

    async fn fetch_block(
        &self,
        height: u32,
        pinned_tip: ChainAnchor,
        expected_prev: BlockHash,
    ) -> Result<FetchResult, SyncError> {
        let hash = self.source.block_hash(height).await?;
        let block = self.source.block(hash).await?;
        if let Err(reason) = validate_complete_block(&block, height, hash, Some(expected_prev)) {
            return Err(SyncError::InvalidBlock { height, reason });
        }
        if !self
            .block_still_pinned(ChainAnchor { height, hash }, pinned_tip)
            .await?
        {
            return Ok(FetchResult::BranchChanged);
        }
        Ok(FetchResult::Block(Box::new(FetchedBlock {
            anchor: ChainAnchor { height, hash },
            block,
        })))
    }

    async fn fetch_canonical_backfill_block(
        &self,
        anchor: ChainAnchor,
        indexed_tip: ChainAnchor,
        expected_prev: Option<BlockHash>,
    ) -> Result<FetchResult, SyncError> {
        if self.source.block_hash(anchor.height).await? != anchor.hash {
            return Ok(FetchResult::BranchChanged);
        }
        let block = self.source.block(anchor.hash).await?;
        validate_complete_block(&block, anchor.height, anchor.hash, expected_prev).map_err(
            |reason| SyncError::InvalidBlock {
                height: anchor.height,
                reason,
            },
        )?;
        if !self.block_still_pinned(anchor, indexed_tip).await? {
            return Ok(FetchResult::BranchChanged);
        }
        Ok(FetchResult::Block(Box::new(FetchedBlock { anchor, block })))
    }

    fn interpret_canonical_block(&self, fetched: &FetchedBlock) -> Result<BlockDelta, SyncError> {
        let mut relevant_transactions = Vec::new();
        let mut recovery_hints = Vec::new();
        let ordered_txids = fetched
            .block
            .txdata
            .iter()
            .map(Transaction::txid)
            .collect::<Vec<_>>();
        let retained = self
            .store
            .retained_declarations_for_transactions(&ordered_txids)?;
        for (tx_index, transaction) in fetched.block.txdata.iter().enumerate() {
            let position = ChainPosition {
                block_height: fetched.anchor.height,
                tx_index: u32::try_from(tx_index).map_err(|_| SyncError::TransactionOverflow)?,
            };
            let context = InterpretationContext {
                store: self.store,
                anchor: fetched.anchor,
                position,
                prior_transactions: &relevant_transactions,
                retained_declarations: retained
                    .get(&ordered_txids[tx_index])
                    .map_or(&[], Vec::as_slice),
                mode: InterpretationMode::Canonical,
            };
            let interpreted = self
                .interpreter
                .interpret_transaction(&context, transaction)
                .map_err(|error| SyncError::Interpretation(error.to_string()))?;
            append_interpretation(
                &mut relevant_transactions,
                &mut recovery_hints,
                fetched.anchor,
                position,
                transaction,
                interpreted,
                true,
            )?;
        }
        recovery_hints.sort_by_key(|hint| (hint.location.position, hint.location.output_index));
        Ok(BlockDelta {
            anchor: fetched.anchor,
            prev_block_hash: fetched.block.header.prev_blockhash,
            ordered_txids,
            relevant_transactions,
            recovery_hints,
        })
    }

    fn interpret_backfill_block(
        &self,
        fetched: &FetchedBlock,
        progress: &[crate::store::BackfillProgress],
    ) -> Result<BlockDelta, SyncError> {
        let mut relevant_transactions = Vec::new();
        let mut ignored_hints = Vec::new();
        for (tx_index, transaction) in fetched.block.txdata.iter().enumerate() {
            let position = ChainPosition {
                block_height: fetched.anchor.height,
                tx_index: u32::try_from(tx_index).map_err(|_| SyncError::TransactionOverflow)?,
            };
            let active = progress
                .iter()
                .filter(|item| item.next_position <= position)
                .map(|item| item.contract_id)
                .collect::<Vec<_>>();
            if active.is_empty() {
                continue;
            }
            let context = InterpretationContext {
                store: self.store,
                anchor: fetched.anchor,
                position,
                prior_transactions: &relevant_transactions,
                retained_declarations: &[],
                mode: InterpretationMode::Backfill {
                    contract_ids: &active,
                },
            };
            let interpreted = self
                .interpreter
                .interpret_transaction(&context, transaction)
                .map_err(|error| SyncError::Interpretation(error.to_string()))?;
            append_interpretation(
                &mut relevant_transactions,
                &mut ignored_hints,
                fetched.anchor,
                position,
                transaction,
                interpreted,
                false,
            )?;
        }
        Ok(BlockDelta {
            anchor: fetched.anchor,
            prev_block_hash: fetched.block.header.prev_blockhash,
            ordered_txids: fetched.block.txdata.iter().map(Transaction::txid).collect(),
            relevant_transactions,
            recovery_hints: Vec::new(),
        })
    }

    async fn block_still_pinned(
        &self,
        block: ChainAnchor,
        pinned_tip: ChainAnchor,
    ) -> Result<bool, SyncError> {
        Ok(self.source.block_hash(block.height).await? == block.hash
            && self.pin_still_canonical(pinned_tip).await?)
    }

    async fn pin_still_canonical(&self, pinned_tip: ChainAnchor) -> Result<bool, SyncError> {
        let current_tip = self.source.tip().await?;
        if current_tip.height < pinned_tip.height {
            return Ok(false);
        }
        Ok(self.source.block_hash(pinned_tip.height).await? == pinned_tip.hash)
    }
}

fn append_interpretation(
    relevant_transactions: &mut Vec<ChainTxDelta>,
    recovery_hints: &mut Vec<RecoveryHintDelta>,
    anchor: ChainAnchor,
    position: ChainPosition,
    transaction: &Transaction,
    interpreted: TransactionInterpretation,
    include_hints: bool,
) -> Result<(), SyncError> {
    if include_hints {
        let mut outputs = HashSet::new();
        for hint in interpreted.recovery_hints {
            let output_index = usize::try_from(hint.output_index)
                .map_err(|_| SyncError::RecoveryHintOutputOverflow)?;
            if output_index >= transaction.output.len() || !outputs.insert(hint.output_index) {
                return Err(SyncError::InvalidRecoveryHint {
                    position,
                    output_index: hint.output_index,
                });
            }
            recovery_hints.push(RecoveryHintDelta {
                location: RecoveryHintLocation {
                    position,
                    output_index: hint.output_index,
                },
                creation_txid: transaction.txid(),
                family: hint.family,
                payload: hint.payload,
                associated_contract: hint.associated_contract,
            });
        }
    }
    if interpreted.created_contracts.is_empty() && interpreted.state_updates.is_empty() {
        return Ok(());
    }
    relevant_transactions.push(ChainTxDelta {
        position,
        block_hash: anchor.hash,
        txid: transaction.txid(),
        raw_tx: transaction.clone(),
        created_contracts: interpreted.created_contracts,
        state_updates: interpreted.state_updates,
    });
    Ok(())
}

fn validate_complete_block(
    block: &Block,
    expected_height: u32,
    expected_hash: BlockHash,
    expected_prev: Option<BlockHash>,
) -> Result<(), String> {
    if block.block_hash() != expected_hash {
        return Err("returned block hash differs from the requested canonical hash".to_owned());
    }
    if block.header.height != expected_height {
        return Err("returned block header height is inconsistent".to_owned());
    }
    if let Some(expected_prev) = expected_prev
        && block.header.prev_blockhash != expected_prev
    {
        return Err("returned block does not extend the expected predecessor".to_owned());
    }
    if block.txdata.is_empty() {
        return Err("canonical block has no transactions".to_owned());
    }
    let mut txids = HashSet::with_capacity(block.txdata.len());
    if block
        .txdata
        .iter()
        .map(Transaction::txid)
        .any(|txid| !txids.insert(txid))
    {
        return Err("canonical block contains duplicate transaction IDs".to_owned());
    }
    if transaction_merkle_root(&block.txdata) != Some(block.header.merkle_root) {
        return Err("canonical block transaction list does not match its merkle root".to_owned());
    }
    Ok(())
}

fn transaction_merkle_root(transactions: &[Transaction]) -> Option<TxMerkleNode> {
    let mut layer = transactions
        .iter()
        .map(|transaction| transaction.txid().to_raw_hash())
        .collect::<Vec<sha256d::Hash>>();
    if layer.is_empty() {
        return None;
    }
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            let mut engine = sha256d::Hash::engine();
            engine.input(left.as_byte_array());
            engine.input(right.as_byte_array());
            next.push(sha256d::Hash::from_engine(engine));
        }
        layer = next;
    }
    Some(TxMerkleNode::from_raw_hash(layer[0]))
}

struct FetchedBlock {
    anchor: ChainAnchor,
    block: Block,
}

enum FetchResult {
    Block(Box<FetchedBlock>),
    BranchChanged,
}

enum FetchDisposition {
    Canonical,
    BranchChanged,
}

enum Reconcile {
    Stable,
    RolledBack(u32),
    Restart,
    RescanRequired,
}

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("chain source error: {0}")]
    ChainSource(#[from] ChainSourceError),
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("indexed tip is not initialized")]
    TipNotInitialized,
    #[error("v1 activation checkpoint is not initialized")]
    ActivationNotInitialized,
    #[error("activation checkpoint {activation:?} is above source tip {source_tip:?}")]
    ActivationAboveSourceTip {
        activation: ChainAnchor,
        source_tip: ChainAnchor,
    },
    #[error("activation checkpoint {activation:?} has source hash {actual}")]
    ActivationHashMismatch {
        activation: ChainAnchor,
        actual: BlockHash,
    },
    #[error("indexed activation checkpoint mismatch: expected {expected:?}, got {actual:?}")]
    IndexedActivationMismatch {
        expected: ChainAnchor,
        actual: Option<ChainAnchor>,
    },
    #[error("explicit rebuild is not required while sync status is {status:?}")]
    RebuildNotRequired { status: SyncStatus },
    #[error("canonical checkpoint is missing at height {0}")]
    MissingCheckpoint(u32),
    #[error("invalid complete block at height {height}: {reason}")]
    InvalidBlock { height: u32, reason: String },
    #[error("contract interpretation failed: {0}")]
    Interpretation(String),
    #[error("too many source branch changes (limit {limit})")]
    TooManyBranchChanges { limit: u32 },
    #[error("chain transaction count exceeds u32")]
    TransactionOverflow,
    #[error("recovery hint output index does not fit usize")]
    RecoveryHintOutputOverflow,
    #[error("recovery hint points outside its transaction at {position:?}:{output_index}")]
    InvalidRecoveryHint {
        position: ChainPosition,
        output_index: u32,
    },
    #[error("synchronization counter overflow")]
    CounterOverflow,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use deadcat_types::{BinaryMarketParams, BinaryMarketState, ContractKind, ContractSyncState};
    use elements::hashes::Hash as _;
    use elements::{
        AssetId, BlockExtData, BlockHeader, LockTime, OutPoint, Script, TxIn, TxOut, Txid,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::chain::{Outspend, TransactionStatus};
    use crate::store::{
        AssetBinding, AssetRelationKind, ChainIdentity, ContractParameters, ContractState,
        RegistrationEvidence, ScriptBinding, TrackedOutpoint, TransitionRecord,
    };

    #[derive(Clone)]
    struct FakeChain {
        state: Arc<Mutex<FakeChainState>>,
    }

    struct FakeChainState {
        blocks: BTreeMap<u32, Block>,
        switch_after_fetch: Option<BTreeMap<u32, Block>>,
    }

    impl FakeChain {
        fn new(blocks: Vec<Block>) -> Self {
            Self {
                state: Arc::new(Mutex::new(FakeChainState {
                    blocks: block_map(blocks),
                    switch_after_fetch: None,
                })),
            }
        }

        fn replace(&self, blocks: Vec<Block>) {
            self.state.lock().expect("chain lock").blocks = block_map(blocks);
        }

        fn switch_after_next_fetch(&self, blocks: Vec<Block>) {
            self.state.lock().expect("chain lock").switch_after_fetch = Some(block_map(blocks));
        }
    }

    #[async_trait]
    impl ChainSource for FakeChain {
        async fn tip(&self) -> Result<ChainAnchor, ChainSourceError> {
            let state = self.state.lock().expect("chain lock");
            let (&height, block) = state
                .blocks
                .last_key_value()
                .ok_or_else(|| ChainSourceError::NotFound("tip".to_owned()))?;
            Ok(ChainAnchor {
                height,
                hash: block.block_hash(),
            })
        }

        async fn block_hash(&self, height: u32) -> Result<BlockHash, ChainSourceError> {
            self.state
                .lock()
                .expect("chain lock")
                .blocks
                .get(&height)
                .map(Block::block_hash)
                .ok_or_else(|| ChainSourceError::NotFound(format!("block {height}")))
        }

        async fn block(&self, hash: BlockHash) -> Result<Block, ChainSourceError> {
            let mut state = self.state.lock().expect("chain lock");
            let block = state
                .blocks
                .values()
                .find(|block| block.block_hash() == hash)
                .cloned()
                .ok_or_else(|| ChainSourceError::NotFound(hash.to_string()))?;
            if let Some(replacement) = state.switch_after_fetch.take() {
                state.blocks = replacement;
            }
            Ok(block)
        }

        async fn transaction(&self, txid: Txid) -> Result<Transaction, ChainSourceError> {
            self.state
                .lock()
                .expect("chain lock")
                .blocks
                .values()
                .flat_map(|block| &block.txdata)
                .find(|transaction| transaction.txid() == txid)
                .cloned()
                .ok_or_else(|| ChainSourceError::NotFound(txid.to_string()))
        }

        async fn transaction_status(
            &self,
            txid: Txid,
        ) -> Result<TransactionStatus, ChainSourceError> {
            let state = self.state.lock().expect("chain lock");
            for (height, block) in &state.blocks {
                if let Some(index) = block
                    .txdata
                    .iter()
                    .position(|transaction| transaction.txid() == txid)
                {
                    return Ok(TransactionStatus::Confirmed {
                        anchor: ChainAnchor {
                            height: *height,
                            hash: block.block_hash(),
                        },
                        tx_index: u32::try_from(index)
                            .map_err(|_| ChainSourceError::InvalidData("tx index".to_owned()))?,
                    });
                }
            }
            Err(ChainSourceError::NotFound(txid.to_string()))
        }

        async fn outspend(&self, outpoint: OutPoint) -> Result<Option<Outspend>, ChainSourceError> {
            let state = self.state.lock().expect("chain lock");
            for (height, block) in &state.blocks {
                for (tx_index, transaction) in block.txdata.iter().enumerate() {
                    for (input_index, input) in transaction.input.iter().enumerate() {
                        if input.previous_output == outpoint {
                            return Ok(Some(Outspend {
                                spending_txid: transaction.txid(),
                                input_index: u32::try_from(input_index).map_err(|_| {
                                    ChainSourceError::InvalidData("input index".to_owned())
                                })?,
                                status: TransactionStatus::Confirmed {
                                    anchor: ChainAnchor {
                                        height: *height,
                                        hash: block.block_hash(),
                                    },
                                    tx_index: u32::try_from(tx_index).map_err(|_| {
                                        ChainSourceError::InvalidData("tx index".to_owned())
                                    })?,
                                },
                            }));
                        }
                    }
                }
            }
            Ok(None)
        }

        async fn script_history(&self, _script: &Script) -> Result<Vec<Txid>, ChainSourceError> {
            Ok(Vec::new())
        }

        async fn issuance_transaction(
            &self,
            _asset_id: AssetId,
        ) -> Result<Option<Txid>, ChainSourceError> {
            Ok(None)
        }

        async fn estimate_fee_rate(&self, _target_blocks: u16) -> Result<f64, ChainSourceError> {
            Ok(0.1)
        }

        async fn broadcast(&self, transaction: &Transaction) -> Result<Txid, ChainSourceError> {
            Ok(transaction.txid())
        }
    }

    #[derive(Default)]
    struct NoopInterpreter;

    impl ChainInterpreter for NoopInterpreter {
        type Error = Infallible;

        fn interpret_transaction(
            &self,
            _context: &InterpretationContext<'_>,
            _transaction: &Transaction,
        ) -> Result<TransactionInterpretation, Self::Error> {
            Ok(TransactionInterpretation::default())
        }
    }

    #[derive(Default)]
    struct ReferenceInterpreter {
        calls: Mutex<Vec<(ChainPosition, bool)>>,
    }

    impl ChainInterpreter for ReferenceInterpreter {
        type Error = Infallible;

        fn interpret_transaction(
            &self,
            context: &InterpretationContext<'_>,
            transaction: &Transaction,
        ) -> Result<TransactionInterpretation, Self::Error> {
            let is_backfill = matches!(context.mode, InterpretationMode::Backfill { .. });
            self.calls
                .lock()
                .expect("calls lock")
                .push((context.position, is_backfill));
            let tag = transaction.lock_time.to_consensus_u32();
            if tag == 55 {
                return Ok(TransactionInterpretation {
                    recovery_hints: vec![InterpretedRecoveryHint {
                        output_index: 0,
                        family: RecoveryFamily::BinaryMarketV1,
                        payload: vec![0xdc, 1],
                        associated_contract: None,
                    }],
                    ..TransactionInterpretation::default()
                });
            }
            if tag == 100 && !is_backfill {
                return Ok(TransactionInterpretation {
                    created_contracts: vec![market_record(
                        context.position,
                        transaction.txid(),
                        context.anchor,
                        ContractSyncState::Ready {
                            synced_through: context.anchor,
                        },
                    )],
                    ..TransactionInterpretation::default()
                });
            }
            if tag != 101 {
                return Ok(TransactionInterpretation::default());
            }

            let contract = match context.mode {
                InterpretationMode::Canonical => context
                    .prior_transactions
                    .iter()
                    .rev()
                    .flat_map(|delta| &delta.created_contracts)
                    .next()
                    .cloned()
                    .or_else(|| {
                        transaction.input.first().and_then(|input| {
                            context
                                .store
                                .outpoint_owner(input.previous_output)
                                .ok()
                                .flatten()
                                .and_then(|owner| context.store.contract(owner.contract_id).ok())
                                .flatten()
                        })
                    }),
                InterpretationMode::Backfill { contract_ids } => contract_ids
                    .first()
                    .and_then(|contract_id| context.store.contract(*contract_id).ok())
                    .flatten(),
            }
            .expect("scripted spend has a contract");
            let old_pairs = match contract.state {
                ContractState::BinaryMarket(BinaryMarketState::Trading { outstanding_pairs }) => {
                    outstanding_pairs
                }
                _ => panic!("unexpected market state"),
            };
            Ok(TransactionInterpretation {
                state_updates: vec![market_update(&contract, transaction.txid(), old_pairs + 1)],
                ..TransactionInterpretation::default()
            })
        }
    }

    #[tokio::test]
    async fn catches_up_in_chain_order_scans_hints_and_restart_is_idempotent() {
        let block0 = test_block(0, BlockHash::all_zeros(), 1, vec![transaction(1, &[])]);
        let create = transaction(100, &[]);
        let spend = transaction(101, &[OutPoint::new(create.txid(), 0)]);
        let block1 = test_block(
            1,
            block0.block_hash(),
            2,
            vec![
                transaction(10, &[]),
                transaction(55, &[]),
                create.clone(),
                spend,
            ],
        );
        let source = FakeChain::new(vec![block0.clone(), block1.clone()]);
        let (dir, path, store) = initialized_store(block_anchor(&block0));
        let interpreter = ReferenceInterpreter::default();

        let outcome = SyncCoordinator::new(&source, &store, &interpreter)
            .sync_to_tip()
            .await
            .expect("sync");
        let SyncOutcome::Ready(report) = outcome else {
            panic!("expected ready");
        };
        assert_eq!(report.blocks_applied, 1);
        assert_eq!(report.indexed_tip, block_anchor(&block1));
        assert_eq!(
            interpreter.calls.lock().expect("calls").as_slice(),
            &[
                (
                    ChainPosition {
                        block_height: 1,
                        tx_index: 0
                    },
                    false
                ),
                (
                    ChainPosition {
                        block_height: 1,
                        tx_index: 1
                    },
                    false
                ),
                (
                    ChainPosition {
                        block_height: 1,
                        tx_index: 2
                    },
                    false
                ),
                (
                    ChainPosition {
                        block_height: 1,
                        tx_index: 3
                    },
                    false
                ),
            ]
        );
        let contract_id = market_record(
            ChainPosition {
                block_height: 1,
                tx_index: 2,
            },
            create.txid(),
            block_anchor(&block1),
            ContractSyncState::Ready {
                synced_through: block_anchor(&block1),
            },
        )
        .contract_id;
        assert_eq!(
            market_pairs(&store.contract(contract_id).expect("contract").unwrap()),
            1
        );
        assert!(
            store
                .recovery_hint(RecoveryHintLocation {
                    position: ChainPosition {
                        block_height: 1,
                        tx_index: 1,
                    },
                    output_index: 0,
                })
                .expect("hint")
                .is_some()
        );
        let cursor = store.event_high_watermark().expect("cursor");
        drop(store);

        let reopened = Store::open(&path).expect("reopen");
        let second = SyncCoordinator::new(&source, &reopened, &NoopInterpreter)
            .sync_to_tip()
            .await
            .expect("idempotent sync");
        let SyncOutcome::Ready(second) = second else {
            panic!("expected ready");
        };
        assert_eq!(second.blocks_applied, 0);
        assert_eq!(reopened.event_high_watermark().expect("cursor"), cursor);
        drop(reopened);
        drop(dir);
    }

    #[tokio::test]
    async fn restarts_a_pinned_range_when_the_source_switches_branches() {
        let block0 = test_block(0, BlockHash::all_zeros(), 10, vec![transaction(1, &[])]);
        let old1 = test_block(1, block0.block_hash(), 11, vec![transaction(2, &[])]);
        let old2 = test_block(2, old1.block_hash(), 12, vec![transaction(3, &[])]);
        let new1 = test_block(1, block0.block_hash(), 21, vec![transaction(4, &[])]);
        let new2 = test_block(2, new1.block_hash(), 22, vec![transaction(5, &[])]);
        let source = FakeChain::new(vec![block0.clone(), old1, old2]);
        source.switch_after_next_fetch(vec![block0.clone(), new1, new2.clone()]);
        let (_dir, _path, store) = initialized_store(block_anchor(&block0));

        let outcome = SyncCoordinator::new(&source, &store, &NoopInterpreter)
            .sync_to_tip()
            .await
            .expect("sync");
        let SyncOutcome::Ready(report) = outcome else {
            panic!("expected ready");
        };
        assert_eq!(report.branch_restarts, 1);
        assert_eq!(report.blocks_applied, 2);
        assert_eq!(store.tip().expect("tip"), Some(block_anchor(&new2)));
    }

    #[tokio::test]
    async fn recovers_shallow_reorgs_then_explicitly_rebuilds_a_three_block_fork() {
        let block0 = test_block(0, BlockHash::all_zeros(), 30, vec![transaction(1, &[])]);
        let a1 = test_block(1, block0.block_hash(), 31, vec![transaction(2, &[])]);
        let a2 = test_block(2, a1.block_hash(), 32, vec![transaction(3, &[])]);
        let a3 = test_block(3, a2.block_hash(), 33, vec![transaction(4, &[])]);
        let source = FakeChain::new(vec![block0.clone(), a1.clone(), a2.clone(), a3]);
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(dir.path().join("store.redb")).expect("open store");
        store
            .initialize_chain(
                ChainIdentity {
                    network: deadcat_types::LiquidNetwork::ElementsRegtest,
                    genesis_hash: block0.block_hash(),
                    policy_asset: asset(0x90),
                },
                block_anchor(&block0),
            )
            .expect("initialize chain");
        let coordinator = SyncCoordinator::new(&source, &store, &NoopInterpreter);
        assert!(matches!(
            coordinator.sync_to_tip().await.expect("initial"),
            SyncOutcome::Ready(_)
        ));

        let b3 = test_block(3, a2.block_hash(), 43, vec![transaction(5, &[])]);
        source.replace(vec![block0.clone(), a1.clone(), a2.clone(), b3]);
        let SyncOutcome::Ready(one) = coordinator.sync_to_tip().await.expect("one block") else {
            panic!("expected ready");
        };
        assert_eq!(one.blocks_rolled_back, 1);
        assert_eq!(one.blocks_applied, 1);

        let c2 = test_block(2, a1.block_hash(), 52, vec![transaction(6, &[])]);
        let c3 = test_block(3, c2.block_hash(), 53, vec![transaction(7, &[])]);
        source.replace(vec![block0.clone(), a1, c2, c3]);
        let SyncOutcome::Ready(two) = coordinator.sync_to_tip().await.expect("two block") else {
            panic!("expected ready");
        };
        assert_eq!(two.blocks_rolled_back, 2);
        assert_eq!(two.blocks_applied, 2);

        let d1 = test_block(1, block0.block_hash(), 61, vec![transaction(8, &[])]);
        let d2 = test_block(2, d1.block_hash(), 62, vec![transaction(9, &[])]);
        let d3 = test_block(3, d2.block_hash(), 63, vec![transaction(10, &[])]);
        source.replace(vec![block0, d1, d2, d3]);
        assert!(matches!(
            coordinator.sync_to_tip().await.expect("deep reorg"),
            SyncOutcome::RescanRequired { .. }
        ));
        assert_eq!(
            store.sync_status().expect("status"),
            SyncStatus::RescanRequired
        );
        let rebuild_epoch = store.event_high_watermark().expect("rebuild epoch").epoch;
        let invalidated_tip = store.tip().expect("invalidated tip");
        let wrong_activation =
            test_block(0, BlockHash::all_zeros(), 99, vec![transaction(99, &[])]);
        let wrong_source = FakeChain::new(vec![wrong_activation]);
        assert!(matches!(
            SyncCoordinator::new(&wrong_source, &store, &NoopInterpreter)
                .rebuild_to_tip()
                .await,
            Err(SyncError::ActivationHashMismatch { .. })
        ));
        assert_eq!(
            store.tip().expect("preflight preserves tip"),
            invalidated_tip
        );
        assert_eq!(
            store.sync_status().expect("preflight preserves status"),
            SyncStatus::RescanRequired
        );
        assert_eq!(
            store
                .event_high_watermark()
                .expect("preflight preserves epoch")
                .epoch,
            rebuild_epoch
        );
        let SyncOutcome::Ready(rebuilt) = coordinator
            .rebuild_to_tip()
            .await
            .expect("explicit activation rebuild")
        else {
            panic!("replacement branch unexpectedly required another rebuild")
        };
        assert_eq!(rebuilt.starting_tip.height, 0);
        assert_eq!(rebuilt.blocks_applied, 3);
        assert_eq!(
            store.tip().expect("replacement tip"),
            Some(source.tip().await.unwrap())
        );
        assert_eq!(
            store.sync_status().expect("ready status"),
            SyncStatus::Ready
        );
        assert_eq!(
            store
                .event_high_watermark()
                .expect("stable rebuild epoch")
                .epoch,
            rebuild_epoch
        );
    }

    #[tokio::test]
    async fn late_registration_replays_same_block_spend_and_resumes_after_reopen() {
        let block0 = test_block(0, BlockHash::all_zeros(), 70, vec![transaction(1, &[])]);
        let create = transaction(100, &[]);
        let spend = transaction(101, &[OutPoint::new(create.txid(), 0)]);
        let block1 = test_block(
            1,
            block0.block_hash(),
            71,
            vec![create.clone(), spend.clone()],
        );
        let block2 = test_block(2, block1.block_hash(), 72, vec![transaction(20, &[])]);
        let source = FakeChain::new(vec![block0.clone(), block1.clone(), block2.clone()]);
        let (dir, path, store) = initialized_store(block_anchor(&block0));
        assert!(matches!(
            SyncCoordinator::new(&source, &store, &NoopInterpreter)
                .sync_to_tip()
                .await
                .expect("global sync"),
            SyncOutcome::Ready(_)
        ));

        let creation_position = ChainPosition {
            block_height: 1,
            tx_index: 0,
        };
        let mut registered = market_record(
            creation_position,
            create.txid(),
            block_anchor(&block1),
            ContractSyncState::CatchingUp {
                synced_through: block_anchor(&block1),
            },
        );
        registered.sync_state = ContractSyncState::CatchingUp {
            synced_through: block_anchor(&block1),
        };
        let contract_id = registered.contract_id;
        store
            .register_contract(
                &registered,
                &RegistrationEvidence {
                    anchor: block_anchor(&block1),
                    transaction: Arc::new(create),
                    associated_hint: None,
                },
            )
            .expect("register");
        assert_eq!(
            store
                .backfill_progress(contract_id)
                .expect("progress")
                .unwrap()
                .next_position,
            ChainPosition {
                block_height: 1,
                tx_index: 1
            }
        );

        let update = market_update(&registered, spend.txid(), 1);
        let first_delta = BlockDelta {
            anchor: block_anchor(&block1),
            prev_block_hash: block1.header.prev_blockhash,
            ordered_txids: block1.txdata.iter().map(Transaction::txid).collect(),
            relevant_transactions: vec![ChainTxDelta {
                position: ChainPosition {
                    block_height: 1,
                    tx_index: 1,
                },
                block_hash: block1.block_hash(),
                txid: spend.txid(),
                raw_tx: spend.clone(),
                created_contracts: Vec::new(),
                state_updates: vec![update],
            }],
            recovery_hints: Vec::new(),
        };
        assert!(
            store
                .apply_backfill_block(&[contract_id], &first_delta)
                .expect("first backfill")
                .applied
        );
        assert!(
            !store
                .apply_backfill_block(&[contract_id], &first_delta)
                .expect("idempotent retry")
                .applied
        );
        assert!(matches!(
            store.contract(contract_id).expect("contract").unwrap().sync_state,
            ContractSyncState::CatchingUp { synced_through } if synced_through == block_anchor(&block1)
        ));
        drop(store);

        let reopened = Store::open(&path).expect("reopen");
        let interpreter = ReferenceInterpreter::default();
        let SyncOutcome::Ready(report) = SyncCoordinator::new(&source, &reopened, &interpreter)
            .sync_to_tip()
            .await
            .expect("resume")
        else {
            panic!("expected ready");
        };
        assert_eq!(report.backfill_blocks_applied, 1);
        let final_record = reopened.contract(contract_id).expect("contract").unwrap();
        assert_eq!(market_pairs(&final_record), 1);
        assert!(matches!(
            final_record.sync_state,
            ContractSyncState::Ready { synced_through } if synced_through == block_anchor(&block2)
        ));
        assert!(reopened.pending_backfills().expect("pending").is_empty());
        assert_eq!(
            interpreter.calls.lock().expect("calls").as_slice(),
            &[(
                ChainPosition {
                    block_height: 2,
                    tx_index: 0
                },
                true
            )]
        );

        let spend_again = transaction(101, &[OutPoint::new(spend.txid(), 0)]);
        let replacement2 = test_block(2, block1.block_hash(), 82, vec![spend_again]);
        source.replace(vec![block0, block1, replacement2.clone()]);
        let replacement_interpreter = ReferenceInterpreter::default();
        let SyncOutcome::Ready(reorg) =
            SyncCoordinator::new(&source, &reopened, &replacement_interpreter)
                .sync_to_tip()
                .await
                .expect("reorg while ready")
        else {
            panic!("expected ready after reorg");
        };
        assert_eq!(reorg.blocks_rolled_back, 1);
        assert_eq!(reorg.blocks_applied, 1);
        let reorged = reopened.contract(contract_id).expect("contract").unwrap();
        assert_eq!(market_pairs(&reorged), 2);
        assert!(matches!(
            reorged.sync_state,
            ContractSyncState::Ready { synced_through } if synced_through == block_anchor(&replacement2)
        ));
        drop(reopened);
        drop(dir);
    }

    fn initialized_store(anchor: ChainAnchor) -> (TempDir, std::path::PathBuf, Store) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("store.redb");
        let store = Store::open(&path).expect("open");
        store.initialize_tip(anchor).expect("tip");
        (dir, path, store)
    }

    fn block_map(blocks: Vec<Block>) -> BTreeMap<u32, Block> {
        blocks
            .into_iter()
            .map(|block| (block.header.height, block))
            .collect()
    }

    fn block_anchor(block: &Block) -> ChainAnchor {
        ChainAnchor {
            height: block.header.height,
            hash: block.block_hash(),
        }
    }

    fn test_block(
        height: u32,
        prev_blockhash: BlockHash,
        marker: u8,
        txdata: Vec<Transaction>,
    ) -> Block {
        let merkle_root = transaction_merkle_root(&txdata).expect("nonempty test block");
        Block {
            header: BlockHeader {
                version: 0x2000_0000,
                prev_blockhash,
                merkle_root,
                time: u32::from(marker),
                height,
                ext: BlockExtData::Proof {
                    challenge: Script::new(),
                    solution: Script::new(),
                },
            },
            txdata,
        }
    }

    fn asset(byte: u8) -> AssetId {
        AssetId::from_slice(&[byte; 32]).expect("asset")
    }

    fn transaction(tag: u32, inputs: &[OutPoint]) -> Transaction {
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
            output: vec![TxOut::new_fee(u64::from(tag) + 1, asset(0x90))],
        }
    }

    fn market_record(
        creation_position: ChainPosition,
        txid: Txid,
        _creation_anchor: ChainAnchor,
        sync_state: ContractSyncState,
    ) -> ContractRecord {
        let marker = 0x44;
        ContractRecord {
            contract_id: ContractId::new(OutPoint::new(txid, 0)),
            kind: ContractKind::BinaryMarketV1,
            params: ContractParameters::BinaryMarket(BinaryMarketParams {
                oracle_public_key: [0x45; 32],
                collateral_asset_id: asset(0x46),
                yes_token_asset_id: asset(0x47),
                no_token_asset_id: asset(0x48),
                yes_reissuance_token_id: asset(0x49),
                no_reissuance_token_id: asset(0x4a),
                base_payout: 100,
                expiry_height: 1_000,
            }),
            creation_position,
            state: ContractState::BinaryMarket(BinaryMarketState::Trading {
                outstanding_pairs: 0,
            }),
            sync_state,
            parent_market: None,
            outcome_side: None,
            scripts: vec![ScriptBinding {
                role: 0,
                script_pubkey: vec![marker, 0x51],
            }],
            assets: vec![AssetBinding {
                asset_id: asset(0x46),
                relation: AssetRelationKind::Collateral,
                role: 0,
            }],
            outpoints: vec![TrackedOutpoint {
                role: 0,
                outpoint: OutPoint::new(txid, 0),
            }],
            order_book: None,
        }
    }

    fn market_update(
        contract: &ContractRecord,
        spending_txid: Txid,
        outstanding_pairs: u64,
    ) -> StateUpdate {
        StateUpdate {
            contract_id: contract.contract_id,
            old_state: contract.state,
            new_state: ContractState::BinaryMarket(BinaryMarketState::Trading {
                outstanding_pairs,
            }),
            spent_outpoints: contract
                .outpoints
                .iter()
                .map(|tracked| tracked.outpoint)
                .collect(),
            new_outpoints: vec![TrackedOutpoint {
                role: 0,
                outpoint: OutPoint::new(spending_txid, 0),
            }],
            order_remaining_base: None,
            transition: TransitionRecord {
                kind: 1,
                payload: outstanding_pairs.to_be_bytes().to_vec(),
            },
        }
    }

    fn market_pairs(record: &ContractRecord) -> u64 {
        match record.state {
            ContractState::BinaryMarket(BinaryMarketState::Trading { outstanding_pairs }) => {
                outstanding_pairs
            }
            _ => panic!("unexpected market state"),
        }
    }
}

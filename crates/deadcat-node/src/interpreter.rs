//! Concrete confirmed-chain interpretation for the v1 Deadcat contracts.
//!
//! This module is deliberately evidence-driven: ownership comes from the
//! canonical store plus earlier relevant transactions in the same block, and
//! previous outputs are loaded from those exact transactions. A transaction
//! touching several contracts produces one atomic batch or no batch at all.

use std::collections::HashSet;
use std::sync::Arc;

use deadcat_contracts::binary_market::{BinaryMarketSlot, BinaryMarketTransition, BinaryOutcome};
use deadcat_contracts::interpret::{
    BinaryMarketLiveOutputs, BinaryMarketPath, InterpretError, MakerOrderSpendKind,
    TrackedContractOutput, interpret_binary_market_spend, interpret_maker_order_spend,
};
use deadcat_rpc::RecoveryFamily;
use deadcat_types::{
    ContractDescriptor, ContractId, ContractKind, ContractSyncState, LiquidNetwork, MakerOrderState,
};
use elements::{AssetId, OutPoint, Transaction};
use thiserror::Error;

use crate::discovery::scan_transaction_hints;
use crate::registration::{
    verify_binary_market_creation_shared, verify_maker_order_creation_shared,
};
use crate::store::{
    ContractParameters, ContractRecord, ContractState, OutpointOwner, StateUpdate, StoreError,
    TrackedOutpoint, TransitionRecord,
};
use crate::sync::{
    ChainInterpreter, InterpretationContext, InterpretationMode, InterpretedRecoveryHint,
    TransactionInterpretation,
};

/// Transition tags reserve the high nibble for the payload version, the next
/// nibble for the contract family (`0` market, `1` maker), and the low byte for
/// the operation. Payload integers are fixed-width big-endian values.
///
/// Market payloads begin with the one-byte [`BinaryMarketPath`], followed by:
/// issued `(pairs:u64, collateral:u64)`, cancelled
/// `(pairs:u64, collateral:u64, full:u8)`, resolved
/// `(outcome:u8, collateral:u64)`, expired `(collateral:u64)`, or redeemed
/// `(outcome:u8, tokens:u64, collateral:u64, complete:u8)`. Outcomes encode
/// YES as zero and NO as one. Maker fills encode
/// `(filled_base:u64, payment:u64, has_remaining:u8, remaining_locked:u64)`;
/// cancellation has an empty payload.
pub const TRANSITION_V1_MARKET_ISSUED: u16 = 0x1001;
pub const TRANSITION_V1_MARKET_CANCELLED: u16 = 0x1002;
pub const TRANSITION_V1_MARKET_RESOLVED: u16 = 0x1003;
pub const TRANSITION_V1_MARKET_EXPIRED: u16 = 0x1004;
pub const TRANSITION_V1_MARKET_REDEEMED: u16 = 0x1005;
pub const TRANSITION_V1_MAKER_FILLED: u16 = 0x1101;
pub const TRANSITION_V1_MAKER_CANCELLED: u16 = 0x1102;

#[derive(Clone, Copy, Debug)]
pub struct DeadcatInterpreter {
    network: LiquidNetwork,
    policy_asset: AssetId,
}

impl DeadcatInterpreter {
    #[must_use]
    pub const fn new(network: LiquidNetwork, policy_asset: AssetId) -> Self {
        Self {
            network,
            policy_asset,
        }
    }
}

impl ChainInterpreter for DeadcatInterpreter {
    type Error = NodeInterpretError;

    fn interpret_transaction(
        &self,
        context: &InterpretationContext<'_>,
        transaction: &Transaction,
    ) -> Result<TransactionInterpretation, Self::Error> {
        let canonical = matches!(context.mode, InterpretationMode::Canonical);
        let mut result = TransactionInterpretation::default();

        if canonical {
            let scan = scan_transaction_hints(
                transaction,
                context.position,
                self.network,
                self.policy_asset,
            );
            result.recovery_hints = scan
                .candidates
                .into_iter()
                .map(|hint| InterpretedRecoveryHint {
                    output_index: hint.location.output_index,
                    family: hint.family,
                    payload: hint.payload,
                    associated_contract: None,
                })
                .collect();

            let retained = context.retained_declarations;
            let has_market_hint = result
                .recovery_hints
                .iter()
                .any(|hint| hint.family == RecoveryFamily::BinaryMarketV1);
            let shared_transaction =
                (!retained.is_empty() || has_market_hint).then(|| Arc::new(transaction.clone()));

            // Explicit declarations are durable watch intent, not authority.
            // Recompile every retained market against this exact canonical
            // transaction before considering any retained child orders.
            for declaration in retained.iter().filter(|declaration| {
                matches!(
                    declaration.descriptor,
                    ContractDescriptor::BinaryMarketV1 { .. }
                )
            }) {
                let ContractDescriptor::BinaryMarketV1 { params } = declaration.descriptor else {
                    unreachable!("filtered to market declarations")
                };
                if let Ok(mut verified) = verify_binary_market_creation_shared(
                    Arc::clone(
                        shared_transaction
                            .as_ref()
                            .expect("retained declarations allocate shared transaction evidence"),
                    ),
                    context.position,
                    context.anchor,
                    self.network,
                    self.policy_asset,
                    Some(params),
                    Some(declaration.contract_id),
                ) {
                    verified.record.sync_state = ContractSyncState::Ready {
                        synced_through: context.anchor,
                    };
                    retain_canonical_creation(
                        context,
                        &mut result.created_contracts,
                        verified.record,
                    )?;
                }
            }

            // A valid hint is merely a candidate. Only the fixed standalone
            // creation shape is globally discoverable; composed creations
            // continue to require explicit registration parameters.
            if has_market_hint
                && let Ok(mut verified) = verify_binary_market_creation_shared(
                    Arc::clone(
                        shared_transaction
                            .as_ref()
                            .expect("market hints allocate shared transaction evidence"),
                    ),
                    context.position,
                    context.anchor,
                    self.network,
                    self.policy_asset,
                    None,
                    None,
                )
            {
                verified.record.sync_state = ContractSyncState::Ready {
                    synced_through: context.anchor,
                };
                let contract_id = verified.record.contract_id;
                retain_canonical_creation(context, &mut result.created_contracts, verified.record)?;
                if let Some(location) = verified.associated_hint {
                    let hint = result
                        .recovery_hints
                        .iter_mut()
                        .find(|hint| hint.output_index == location.output_index)
                        .ok_or(NodeInterpretError::MissingAssociatedHint)?;
                    hint.associated_contract = Some(contract_id);
                }
            }

            // A maker hint is deliberately insufficient for public discovery.
            // Retained declarations provide the missing semantics, but remain
            // dormant if their parent or exact canonical output no longer
            // validates on this branch.
            for declaration in retained.iter().filter(|declaration| {
                matches!(
                    declaration.descriptor,
                    ContractDescriptor::MakerOrderV1 { .. }
                )
            }) {
                let ContractDescriptor::MakerOrderV1 {
                    parent_market,
                    side,
                    params,
                } = declaration.descriptor
                else {
                    unreachable!("filtered to maker declarations")
                };
                let same_transaction_parent = result
                    .created_contracts
                    .iter()
                    .find(|record| record.contract_id == parent_market);
                let stored_parent;
                let parent = if let Some(parent) = same_transaction_parent {
                    parent
                } else {
                    let Some(parent) = contract_in_context(context, parent_market)? else {
                        continue;
                    };
                    stored_parent = parent;
                    &stored_parent
                };
                if let Ok(mut verified) = verify_maker_order_creation_shared(
                    Arc::clone(
                        shared_transaction
                            .as_ref()
                            .expect("retained declarations allocate shared transaction evidence"),
                    ),
                    context.position,
                    context.anchor,
                    declaration.contract_id,
                    parent,
                    side,
                    params,
                ) {
                    verified.record.sync_state = ContractSyncState::Ready {
                        synced_through: context.anchor,
                    };
                    retain_canonical_creation(
                        context,
                        &mut result.created_contracts,
                        verified.record,
                    )?;
                }
            }
        }

        let targets = match context.mode {
            InterpretationMode::Canonical => None,
            InterpretationMode::Backfill { contract_ids } => {
                Some(contract_ids.iter().copied().collect::<HashSet<_>>())
            }
        };
        let mut touched = Vec::new();
        for input in &transaction.input {
            match owner_in_context(context, input.previous_output)? {
                OwnerResolution::Untracked => {}
                OwnerResolution::SpentEarlier(contract_id) => {
                    return Err(NodeInterpretError::SameBlockDoubleSpend {
                        outpoint: input.previous_output,
                        contract_id,
                    });
                }
                OwnerResolution::Live(owner) => {
                    if targets
                        .as_ref()
                        .is_some_and(|targets| !targets.contains(&owner.contract_id))
                    {
                        continue;
                    }
                    if !touched.contains(&owner.contract_id) {
                        touched.push(owner.contract_id);
                    }
                }
            }
        }

        for contract_id in touched {
            let record = contract_in_context(context, contract_id)?
                .ok_or(NodeInterpretError::MissingContract(contract_id))?;
            let update = interpret_contract(context, &record, transaction)?;
            result.state_updates.push(update);
        }
        validate_atomic_claims(&result)?;
        Ok(result)
    }
}

fn retain_canonical_creation(
    context: &InterpretationContext<'_>,
    created: &mut Vec<ContractRecord>,
    candidate: ContractRecord,
) -> Result<(), NodeInterpretError> {
    let current_transaction = created
        .iter()
        .find(|record| record.contract_id == candidate.contract_id);
    if let Some(existing) = current_transaction {
        return ensure_creation_identity(existing, &candidate);
    }
    if let Some(existing) = contract_in_context(context, candidate.contract_id)? {
        return ensure_creation_identity(&existing, &candidate);
    }
    created.push(candidate);
    Ok(())
}

fn ensure_creation_identity(
    existing: &ContractRecord,
    candidate: &ContractRecord,
) -> Result<(), NodeInterpretError> {
    if existing.kind != candidate.kind
        || existing.params != candidate.params
        || existing.creation_position != candidate.creation_position
        || existing.parent_market != candidate.parent_market
        || existing.outcome_side != candidate.outcome_side
        || existing.scripts != candidate.scripts
        || existing.assets != candidate.assets
    {
        return Err(NodeInterpretError::DiscoveryConflict(candidate.contract_id));
    }
    Ok(())
}

fn validate_atomic_claims(
    interpretation: &TransactionInterpretation,
) -> Result<(), NodeInterpretError> {
    let mut contracts = HashSet::new();
    let mut spent = HashSet::new();
    let mut created_outputs = HashSet::new();
    for contract in &interpretation.created_contracts {
        if !contracts.insert(contract.contract_id)
            || contract
                .outpoints
                .iter()
                .any(|tracked| !created_outputs.insert(tracked.outpoint))
        {
            return Err(NodeInterpretError::ConflictingAtomicBatch);
        }
    }
    for update in &interpretation.state_updates {
        if !contracts.insert(update.contract_id)
            || update
                .spent_outpoints
                .iter()
                .any(|outpoint| !spent.insert(*outpoint))
            || update
                .new_outpoints
                .iter()
                .any(|tracked| !created_outputs.insert(tracked.outpoint))
        {
            return Err(NodeInterpretError::ConflictingAtomicBatch);
        }
    }
    Ok(())
}

fn interpret_contract(
    context: &InterpretationContext<'_>,
    record: &ContractRecord,
    transaction: &Transaction,
) -> Result<StateUpdate, NodeInterpretError> {
    match (record.kind, &record.params, record.state) {
        (
            ContractKind::BinaryMarketV1,
            ContractParameters::BinaryMarket(params),
            ContractState::BinaryMarket(before),
        ) => {
            let live = materialize_market_outputs(context, record)?;
            let interpreted = interpret_binary_market_spend(*params, before, &live, transaction)?;
            let spent_outpoints = interpreted.spent_outpoints.to_vec();
            ensure_complete_spend(record, &spent_outpoints)?;
            let new_outpoints = interpreted
                .continuations
                .iter()
                .map(|continuation| TrackedOutpoint {
                    role: continuation.slot as u8,
                    outpoint: continuation.output.outpoint,
                })
                .collect();
            Ok(StateUpdate {
                contract_id: record.contract_id,
                old_state: record.state,
                new_state: ContractState::BinaryMarket(interpreted.after),
                spent_outpoints,
                new_outpoints,
                order_remaining_base: None,
                transition: market_transition_record(interpreted.path, interpreted.transition),
            })
        }
        (
            ContractKind::MakerOrderV1,
            ContractParameters::MakerOrder(params),
            ContractState::MakerOrder(before),
        ) => {
            let live = materialize_maker_output(context, record)?;
            let interpreted = interpret_maker_order_spend(*params, before, &live, transaction)?;
            let spent_outpoints = vec![interpreted.spent_outpoint];
            ensure_complete_spend(record, &spent_outpoints)?;
            let new_outpoints = interpreted
                .continuation
                .as_ref()
                .map(|continuation| {
                    vec![TrackedOutpoint {
                        role: 0,
                        outpoint: continuation.outpoint,
                    }]
                })
                .unwrap_or_default();
            let order_remaining_base = match interpreted.after {
                MakerOrderState::Active { remaining_base, .. } => Some(remaining_base),
                MakerOrderState::Consumed | MakerOrderState::Cancelled => None,
            };
            Ok(StateUpdate {
                contract_id: record.contract_id,
                old_state: record.state,
                new_state: ContractState::MakerOrder(interpreted.after),
                spent_outpoints,
                new_outpoints,
                order_remaining_base,
                transition: maker_transition_record(interpreted.kind),
            })
        }
        _ => Err(NodeInterpretError::ContractShape(record.contract_id)),
    }
}

fn materialize_maker_output(
    context: &InterpretationContext<'_>,
    record: &ContractRecord,
) -> Result<TrackedContractOutput, NodeInterpretError> {
    let [tracked] = record.outpoints.as_slice() else {
        return Err(NodeInterpretError::InvalidLiveSet(record.contract_id));
    };
    if tracked.role != 0 {
        return Err(NodeInterpretError::InvalidLiveSet(record.contract_id));
    }
    materialize_output(context, *tracked)
}

fn materialize_market_outputs(
    context: &InterpretationContext<'_>,
    record: &ContractRecord,
) -> Result<BinaryMarketLiveOutputs, NodeInterpretError> {
    let mut live = BinaryMarketLiveOutputs::default();
    for tracked in &record.outpoints {
        let output = materialize_output(context, *tracked)?;
        match tracked.role {
            role if role == BinaryMarketSlot::DormantYesRt as u8
                || role == BinaryMarketSlot::UnresolvedYesRt as u8 =>
            {
                set_once(&mut live.yes_rt, output, record.contract_id)?;
            }
            role if role == BinaryMarketSlot::DormantNoRt as u8
                || role == BinaryMarketSlot::UnresolvedNoRt as u8 =>
            {
                set_once(&mut live.no_rt, output, record.contract_id)?;
            }
            role if role == BinaryMarketSlot::UnresolvedCollateral as u8
                || role == BinaryMarketSlot::ResolvedYesCollateral as u8
                || role == BinaryMarketSlot::ResolvedNoCollateral as u8
                || role == BinaryMarketSlot::ExpiredCollateral as u8 =>
            {
                set_once(&mut live.collateral, output, record.contract_id)?;
            }
            _ => return Err(NodeInterpretError::InvalidLiveSet(record.contract_id)),
        }
    }
    Ok(live)
}

fn set_once(
    slot: &mut Option<TrackedContractOutput>,
    output: TrackedContractOutput,
    contract_id: ContractId,
) -> Result<(), NodeInterpretError> {
    if slot.replace(output).is_some() {
        return Err(NodeInterpretError::InvalidLiveSet(contract_id));
    }
    Ok(())
}

fn materialize_output(
    context: &InterpretationContext<'_>,
    tracked: TrackedOutpoint,
) -> Result<TrackedContractOutput, NodeInterpretError> {
    for delta in context.prior_transactions.iter().rev() {
        if delta.txid != tracked.outpoint.txid {
            continue;
        }
        let txout = delta
            .raw_tx
            .output
            .get(tracked.outpoint.vout as usize)
            .cloned()
            .ok_or(NodeInterpretError::MissingOutput(tracked.outpoint))?;
        return Ok(TrackedContractOutput {
            outpoint: tracked.outpoint,
            txout,
        });
    }
    let stored = context
        .store
        .output(tracked.outpoint)?
        .ok_or(NodeInterpretError::MissingOutput(tracked.outpoint))?;
    Ok(TrackedContractOutput {
        outpoint: stored.outpoint,
        txout: stored.output,
    })
}

fn owner_in_context(
    context: &InterpretationContext<'_>,
    outpoint: OutPoint,
) -> Result<OwnerResolution, NodeInterpretError> {
    for delta in context.prior_transactions.iter().rev() {
        for update in delta.state_updates.iter().rev() {
            if update.spent_outpoints.contains(&outpoint) {
                return Ok(OwnerResolution::SpentEarlier(update.contract_id));
            }
            if let Some(tracked) = update
                .new_outpoints
                .iter()
                .find(|tracked| tracked.outpoint == outpoint)
            {
                return Ok(OwnerResolution::Live(OutpointOwner {
                    contract_id: update.contract_id,
                    role: tracked.role,
                }));
            }
        }
        for contract in delta.created_contracts.iter().rev() {
            if let Some(tracked) = contract
                .outpoints
                .iter()
                .find(|tracked| tracked.outpoint == outpoint)
            {
                return Ok(OwnerResolution::Live(OutpointOwner {
                    contract_id: contract.contract_id,
                    role: tracked.role,
                }));
            }
        }
    }
    Ok(context
        .store
        .outpoint_owner(outpoint)?
        .map_or(OwnerResolution::Untracked, OwnerResolution::Live))
}

fn contract_in_context(
    context: &InterpretationContext<'_>,
    contract_id: ContractId,
) -> Result<Option<ContractRecord>, NodeInterpretError> {
    let mut current = context.store.contract(contract_id)?;
    for delta in context.prior_transactions {
        if let Some(created) = delta
            .created_contracts
            .iter()
            .find(|record| record.contract_id == contract_id)
        {
            if current.is_some() {
                return Err(NodeInterpretError::DuplicateOverlayContract(contract_id));
            }
            current = Some(created.clone());
        }
        for update in delta
            .state_updates
            .iter()
            .filter(|update| update.contract_id == contract_id)
        {
            let record = current
                .as_mut()
                .ok_or(NodeInterpretError::MissingContract(contract_id))?;
            if record.state != update.old_state {
                return Err(NodeInterpretError::OverlayStateMismatch(contract_id));
            }
            ensure_complete_spend(record, &update.spent_outpoints)?;
            record.state = update.new_state;
            record.outpoints.clone_from(&update.new_outpoints);
            match (record.state, update.order_remaining_base) {
                (ContractState::BinaryMarket(_), None) => {}
                (
                    ContractState::MakerOrder(MakerOrderState::Active { remaining_base, .. }),
                    Some(supplied),
                ) if remaining_base == supplied => {
                    let order_book = record
                        .order_book
                        .as_mut()
                        .ok_or(NodeInterpretError::OverlayStateMismatch(contract_id))?;
                    order_book.remaining_base = supplied;
                }
                (
                    ContractState::MakerOrder(
                        MakerOrderState::Consumed | MakerOrderState::Cancelled,
                    ),
                    None,
                ) => record.order_book = None,
                _ => return Err(NodeInterpretError::OverlayStateMismatch(contract_id)),
            }
        }
    }
    Ok(current)
}

fn ensure_complete_spend(
    record: &ContractRecord,
    spent: &[OutPoint],
) -> Result<(), NodeInterpretError> {
    let expected = record
        .outpoints
        .iter()
        .map(|tracked| tracked.outpoint)
        .collect::<HashSet<_>>();
    let actual = spent.iter().copied().collect::<HashSet<_>>();
    if expected != actual || actual.len() != spent.len() {
        return Err(NodeInterpretError::IncompleteSpend(record.contract_id));
    }
    Ok(())
}

fn market_transition_record(
    path: BinaryMarketPath,
    transition: BinaryMarketTransition,
) -> TransitionRecord {
    let mut payload = vec![path as u8];
    let kind = match transition {
        BinaryMarketTransition::Issued {
            pairs,
            collateral_locked,
        } => {
            payload.extend_from_slice(&pairs.to_be_bytes());
            payload.extend_from_slice(&collateral_locked.to_be_bytes());
            TRANSITION_V1_MARKET_ISSUED
        }
        BinaryMarketTransition::Cancelled {
            pairs,
            collateral_released,
            full,
        } => {
            payload.extend_from_slice(&pairs.to_be_bytes());
            payload.extend_from_slice(&collateral_released.to_be_bytes());
            payload.push(u8::from(full));
            TRANSITION_V1_MARKET_CANCELLED
        }
        BinaryMarketTransition::Resolved {
            outcome,
            collateral_retained,
        } => {
            payload.push(outcome_byte(outcome));
            payload.extend_from_slice(&collateral_retained.to_be_bytes());
            TRANSITION_V1_MARKET_RESOLVED
        }
        BinaryMarketTransition::Expired {
            collateral_retained,
        } => {
            payload.extend_from_slice(&collateral_retained.to_be_bytes());
            TRANSITION_V1_MARKET_EXPIRED
        }
        BinaryMarketTransition::Redeemed {
            outcome,
            tokens,
            collateral_released,
            complete,
        } => {
            payload.push(outcome_byte(outcome));
            payload.extend_from_slice(&tokens.to_be_bytes());
            payload.extend_from_slice(&collateral_released.to_be_bytes());
            payload.push(u8::from(complete));
            TRANSITION_V1_MARKET_REDEEMED
        }
    };
    TransitionRecord { kind, payload }
}

fn maker_transition_record(kind: MakerOrderSpendKind) -> TransitionRecord {
    match kind {
        MakerOrderSpendKind::Fill(fill) => {
            let mut payload = Vec::with_capacity(25);
            payload.extend_from_slice(&fill.filled_base.to_be_bytes());
            payload.extend_from_slice(&fill.maker_payment.to_be_bytes());
            match fill.remaining_locked {
                Some(remaining) => {
                    payload.push(1);
                    payload.extend_from_slice(&remaining.to_be_bytes());
                }
                None => {
                    payload.push(0);
                    payload.extend_from_slice(&0_u64.to_be_bytes());
                }
            }
            TransitionRecord {
                kind: TRANSITION_V1_MAKER_FILLED,
                payload,
            }
        }
        MakerOrderSpendKind::Cancel => TransitionRecord {
            kind: TRANSITION_V1_MAKER_CANCELLED,
            payload: Vec::new(),
        },
    }
}

const fn outcome_byte(outcome: BinaryOutcome) -> u8 {
    match outcome {
        BinaryOutcome::Yes => 0,
        BinaryOutcome::No => 1,
    }
}

enum OwnerResolution {
    Untracked,
    Live(OutpointOwner),
    SpentEarlier(ContractId),
}

#[derive(Debug, Error)]
pub enum NodeInterpretError {
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("contract spend interpretation failed: {0}")]
    Contract(#[from] InterpretError),
    #[error("tracked contract {0:?} is missing")]
    MissingContract(ContractId),
    #[error("tracked output {0:?} cannot be materialized from canonical evidence")]
    MissingOutput(OutPoint),
    #[error("tracked contract {0:?} has an invalid live-output set")]
    InvalidLiveSet(ContractId),
    #[error("tracked contract {0:?} has inconsistent kind, parameters, and state")]
    ContractShape(ContractId),
    #[error("contract {0:?} was created twice in one interpretation overlay")]
    DuplicateOverlayContract(ContractId),
    #[error("contract {0:?} has inconsistent same-block transition state")]
    OverlayStateMismatch(ContractId),
    #[error("contract {0:?} did not account for every current tracked output")]
    IncompleteSpend(ContractId),
    #[error(
        "tracked output {outpoint:?} for {contract_id:?} was already spent earlier in the block"
    )]
    SameBlockDoubleSpend {
        outpoint: OutPoint,
        contract_id: ContractId,
    },
    #[error("automatic discovery conflicts with stored contract {0:?}")]
    DiscoveryConflict(ContractId),
    #[error("verified automatic discovery did not retain its associated hint")]
    MissingAssociatedHint,
    #[error("one atomic interpretation batch contains conflicting contracts or outpoints")]
    ConflictingAtomicBatch,
}

#[cfg(test)]
mod tests;

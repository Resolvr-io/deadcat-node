//! Fail-closed validation of node-provided views, evidence, and signing intents.
//!
//! These helpers deliberately require a caller-provided canonical-chain check
//! or trusted snapshot anchor where chain authenticity matters. Internal DTO
//! consistency is not proof that a node reported the canonical Liquid chain.

use std::collections::{HashMap, HashSet};

use deadcat_contracts::SimplicityNetwork;
use deadcat_contracts::binary_market::{
    BinaryMarketEconomics, BinaryMarketPath, BinaryMarketSlot, BinaryMarketTransition,
    BinaryOutcome, CompiledBinaryMarket, CompiledBinaryMarketError,
};
use deadcat_contracts::interpret::{
    BinaryMarketLiveOutputs, TrackedContractOutput, interpret_binary_market_spend,
};
use deadcat_contracts::rt::{RtLeg, RtSide, commitments, factors};
use deadcat_rpc::{
    ContractHistoryPage, ContractParametersView, ContractStateView, ContractView, HistoryEntry,
    LiveOutpoint, MarketSnapshot, SnapshotMetadata, TransactionEvidence,
};
use deadcat_types::{
    BinaryMarketParams, BinaryMarketState, ChainAnchor, ChainPosition, ContractId, ContractKind,
    ContractSyncState,
};
use elements::confidential::{Asset, Value};
use elements::pset::PartiallySignedTransaction;
use elements::secp256k1_zkp::ZERO_TWEAK;
use elements::{BlockHash, OutPoint, Transaction};
use thiserror::Error;

use crate::market_builder::{BinaryMarketTransitionPlan, MarketBuilderError};

const TRANSITION_V1_MARKET_ISSUED: u16 = 0x1001;
const TRANSITION_V1_MARKET_CANCELLED: u16 = 0x1002;
const TRANSITION_V1_MARKET_RESOLVED: u16 = 0x1003;
const TRANSITION_V1_MARKET_EXPIRED: u16 = 0x1004;
const TRANSITION_V1_MARKET_REDEEMED: u16 = 0x1005;

/// A structurally validated contract view.
///
/// This proves that the parameters compile and that the state/live-output
/// shape is coherent. Use [`replay_contract_history`] to prove that the
/// creation-anchor identity, state, and live outpoints follow from canonical
/// transaction evidence.
#[derive(Clone, Debug)]
pub struct ValidatedContractView {
    view: ContractView,
}

impl ValidatedContractView {
    #[must_use]
    pub const fn view(&self) -> &ContractView {
        &self.view
    }

    #[must_use]
    pub const fn contract_id(&self) -> ContractId {
        self.view.contract_id
    }
}

/// Result of replaying a complete contract history from its creation.
#[derive(Clone, Debug)]
pub struct ValidatedContractReplay {
    contract: ValidatedContractView,
    transition_count: usize,
}

impl ValidatedContractReplay {
    #[must_use]
    pub const fn contract(&self) -> &ValidatedContractView {
        &self.contract
    }

    #[must_use]
    pub const fn transition_count(&self) -> usize {
        self.transition_count
    }
}

/// Recompile and validate every locally checkable field in a contract view.
pub fn validate_contract_view(
    view: &ContractView,
) -> Result<ValidatedContractView, ValidationError> {
    if sync_anchor(view.sync_state).height < view.creation_position.block_height {
        return Err(ValidationError::ContractShape(
            "sync anchor predates contract creation",
        ));
    }
    validate_unique_live_outpoints(&view.live_outpoints)?;

    let ContractParametersView::BinaryMarket { params } = &view.parameters;
    let ContractStateView::BinaryMarket { state } = view.state;
    CompiledBinaryMarket::new(*params)?;
    BinaryMarketEconomics::new(params.base_payout)
        .and_then(|economics| economics.validate_state(state))
        .map_err(|error| ValidationError::Economics(error.to_string()))?;
    validate_market_live_shape(state, &view.live_outpoints)?;
    Ok(ValidatedContractView { view: view.clone() })
}

/// Validate a market snapshot against a chain anchor obtained independently
/// from the user's own backend or block-header verifier.
pub fn validate_market_snapshot(
    snapshot: &MarketSnapshot,
    trusted_anchor: ChainAnchor,
) -> Result<ValidatedContractView, ValidationError> {
    validate_snapshot_metadata(&snapshot.snapshot, trusted_anchor)?;
    let validated = validate_contract_view(&snapshot.contract)?;
    if snapshot.contract.kind != ContractKind::BinaryMarketV1
        || snapshot.contract.parameters
            != (ContractParametersView::BinaryMarket {
                params: snapshot.params,
            })
        || snapshot.contract.state
            != (ContractStateView::BinaryMarket {
                state: snapshot.state,
            })
        || snapshot.contract.live_outpoints != snapshot.live_outpoints
    {
        return Err(ValidationError::SnapshotMismatch(
            "duplicated market fields disagree with the contract view",
        ));
    }
    validate_ready_at(&snapshot.contract, trusted_anchor)?;
    Ok(validated)
}

/// Replay a complete ordered history through the canonical contract
/// interpreters and compare the resulting state and live outpoints with the
/// reported view. `trusted_snapshot_anchor` and `is_canonical` must come from
/// a chain source independent of the node response. The callback must verify
/// that the exact consensus transaction, including all input and output
/// witnesses, occupies the reported position in the canonical block. Comparing
/// only the block hash or transaction ID is insufficient because an Elements
/// transaction ID does not commit to witness data, while contract
/// interpretation does. Proving that a remote node did not omit another
/// relevant transaction still requires a local scan of the contract
/// scripts/outpoints.
pub fn replay_contract_history<F>(
    expected: &ContractView,
    history: &ContractHistoryPage,
    creation: &TransactionEvidence,
    transitions: &[TransactionEvidence],
    trusted_snapshot_anchor: ChainAnchor,
    mut is_canonical: F,
) -> Result<ValidatedContractReplay, ValidationError>
where
    F: FnMut(ChainPosition, BlockHash, &Transaction) -> bool,
{
    validate_contract_view(expected)?;
    if history.contract_id != expected.contract_id {
        return Err(ValidationError::HistoryMismatch(
            "history belongs to another contract",
        ));
    }
    if history.next.is_some() {
        return Err(ValidationError::IncompleteHistory);
    }
    validate_snapshot_metadata(&history.snapshot, trusted_snapshot_anchor)?;
    validate_ready_at(expected, trusted_snapshot_anchor)?;
    validate_evidence(creation, expected.contract_id, &mut is_canonical)?;
    validate_evidence_snapshot_bound(creation, trusted_snapshot_anchor)?;
    if creation.position != expected.creation_position
        || creation.txid != expected.contract_id.txid()
        || creation.transaction.txid() != expected.contract_id.txid()
    {
        return Err(ValidationError::CreationMismatch(
            "creation evidence position or txid is wrong",
        ));
    }
    if history.entries.len() != transitions.len() {
        return Err(ValidationError::HistoryMismatch(
            "history entries and transaction evidence counts differ",
        ));
    }

    let mut previous = creation.position;
    for (entry, evidence) in history.entries.iter().zip(transitions) {
        if entry.position <= previous {
            return Err(ValidationError::HistoryOrder);
        }
        if entry.position != evidence.position || entry.txid != evidence.txid {
            return Err(ValidationError::HistoryMismatch(
                "history entry does not match transaction evidence",
            ));
        }
        validate_evidence(evidence, expected.contract_id, &mut is_canonical)?;
        validate_evidence_snapshot_bound(evidence, trusted_snapshot_anchor)?;
        previous = entry.position;
    }

    let ContractParametersView::BinaryMarket { params } = expected.parameters;
    replay_market(expected, params, history, creation, transitions)?;
    Ok(ValidatedContractReplay {
        contract: ValidatedContractView {
            view: expected.clone(),
        },
        transition_count: transitions.len(),
    })
}

/// Validate a composed market transition PSET without mutating the caller's
/// PSET. This executes every affected Simplicity covenant on a clone.
pub fn validate_market_pset_intent(
    plan: &BinaryMarketTransitionPlan,
    pset: &PartiallySignedTransaction,
    input_base: usize,
    output_base: usize,
    network: &SimplicityNetwork,
) -> Result<(), ValidationError> {
    let mut staged = pset.clone();
    plan.finalize(&mut staged, input_base, output_base, network)?;
    Ok(())
}

fn replay_market(
    expected: &ContractView,
    params: BinaryMarketParams,
    history: &ContractHistoryPage,
    creation: &TransactionEvidence,
    transitions: &[TransactionEvidence],
) -> Result<(), ValidationError> {
    let compiled = CompiledBinaryMarket::new(params)?;
    let yes_input = unique_defining_input(
        &creation.transaction,
        params.yes_token_asset_id,
        params.yes_reissuance_token_id,
    )?;
    let no_input = unique_defining_input(
        &creation.transaction,
        params.no_token_asset_id,
        params.no_reissuance_token_id,
    )?;
    if yes_input == no_input {
        return Err(ValidationError::CreationMismatch(
            "YES and NO use the same defining issuance",
        ));
    }
    // Re-derive canonical side-A creation independently of the node's view.
    let yes_commitments = commitments(
        params.yes_reissuance_token_id,
        factors(RtLeg::Yes, RtSide::A),
    )
    .map_err(|error| ValidationError::CreationMismatchOwned(error.to_string()))?;
    let no_commitments = commitments(params.no_reissuance_token_id, factors(RtLeg::No, RtSide::A))
        .map_err(|error| ValidationError::CreationMismatchOwned(error.to_string()))?;
    let yes = unique_market_output(
        &creation.transaction,
        compiled
            .slot(BinaryMarketSlot::DormantYesRt)
            .script_pubkey(),
        yes_commitments,
    )?;
    let no = unique_market_output(
        &creation.transaction,
        compiled.slot(BinaryMarketSlot::DormantNoRt).script_pubkey(),
        no_commitments,
    )?;
    if expected.contract_id.creation_anchor() != OutPoint::new(creation.txid, yes) {
        return Err(ValidationError::CreationMismatch(
            "market ContractId does not nominate its initial dormant YES RT output",
        ));
    }
    let mut state = BinaryMarketState::Trading {
        outstanding_pairs: 0,
    };
    let mut live = BinaryMarketLiveOutputs {
        yes_rt: Some(tracked_output(&creation.transaction, yes)?),
        no_rt: Some(tracked_output(&creation.transaction, no)?),
        collateral: None,
    };
    for (entry, evidence) in history.entries.iter().zip(transitions) {
        let interpreted =
            interpret_binary_market_spend(params, state, &live, &evidence.transaction)
                .map_err(|error| ValidationError::Interpretation(error.to_string()))?;
        let (kind, payload) = encode_market_transition(interpreted.path, interpreted.transition);
        validate_transition_record(entry, kind, &payload)?;
        state = interpreted.after;
        live = live_from_market_continuations(&interpreted.continuations);
    }
    if expected.state != (ContractStateView::BinaryMarket { state }) {
        return Err(ValidationError::FinalStateMismatch);
    }
    let final_live = market_live_outpoints(&compiled, &live)?;
    if !same_live_set(&final_live, &expected.live_outpoints) {
        return Err(ValidationError::FinalLiveOutpointsMismatch);
    }
    Ok(())
}

fn validate_evidence<F>(
    evidence: &TransactionEvidence,
    contract_id: ContractId,
    is_canonical: &mut F,
) -> Result<(), ValidationError>
where
    F: FnMut(ChainPosition, BlockHash, &Transaction) -> bool,
{
    if evidence.transaction.txid() != evidence.txid {
        return Err(ValidationError::EvidenceTxidMismatch);
    }
    if !evidence.affected_contract_ids.contains(&contract_id) {
        return Err(ValidationError::EvidenceContractMissing(contract_id));
    }
    if !(is_canonical)(
        evidence.position,
        evidence.block_hash,
        &evidence.transaction,
    ) {
        return Err(ValidationError::NonCanonicalEvidence {
            position: evidence.position,
            block_hash: evidence.block_hash,
        });
    }
    Ok(())
}

fn validate_evidence_snapshot_bound(
    evidence: &TransactionEvidence,
    snapshot: ChainAnchor,
) -> Result<(), ValidationError> {
    if evidence.position.block_height > snapshot.height
        || (evidence.position.block_height == snapshot.height
            && evidence.block_hash != snapshot.hash)
    {
        return Err(ValidationError::EvidenceOutsideSnapshot {
            position: evidence.position,
        });
    }
    Ok(())
}

fn validate_snapshot_metadata(
    metadata: &SnapshotMetadata,
    trusted_anchor: ChainAnchor,
) -> Result<(), ValidationError> {
    if metadata.as_of != trusted_anchor {
        return Err(ValidationError::UntrustedSnapshotAnchor);
    }
    Ok(())
}

fn validate_ready_at(
    view: &ContractView,
    trusted_anchor: ChainAnchor,
) -> Result<(), ValidationError> {
    if view.sync_state
        != (ContractSyncState::Ready {
            synced_through: trusted_anchor,
        })
    {
        return Err(ValidationError::ContractNotReadyAtSnapshot);
    }
    Ok(())
}

const fn sync_anchor(state: ContractSyncState) -> ChainAnchor {
    match state {
        ContractSyncState::CatchingUp { synced_through }
        | ContractSyncState::Ready { synced_through } => synced_through,
    }
}

fn validate_unique_live_outpoints(live: &[LiveOutpoint]) -> Result<(), ValidationError> {
    let mut roles = HashSet::new();
    let mut outpoints = HashSet::new();
    for item in live {
        if !roles.insert(item.role) || !outpoints.insert(item.outpoint) {
            return Err(ValidationError::LiveOutpointShape(
                "duplicate live role or outpoint",
            ));
        }
    }
    Ok(())
}

fn validate_market_live_shape(
    state: BinaryMarketState,
    live: &[LiveOutpoint],
) -> Result<(), ValidationError> {
    let mut roles = live.iter().map(|item| item.role).collect::<Vec<_>>();
    roles.sort_unstable();
    let expected: &[u8] = match state {
        BinaryMarketState::Trading {
            outstanding_pairs: 0,
        } => &[
            BinaryMarketSlot::DormantYesRt as u8,
            BinaryMarketSlot::DormantNoRt as u8,
        ],
        BinaryMarketState::Trading { .. } => &[
            BinaryMarketSlot::UnresolvedYesRt as u8,
            BinaryMarketSlot::UnresolvedNoRt as u8,
            BinaryMarketSlot::UnresolvedCollateral as u8,
        ],
        BinaryMarketState::ResolvedYes {
            collateral_unredeemed: 0,
        }
        | BinaryMarketState::ResolvedNo {
            collateral_unredeemed: 0,
        }
        | BinaryMarketState::Expired {
            collateral_unredeemed: 0,
        } => &[],
        BinaryMarketState::ResolvedYes { .. } => &[BinaryMarketSlot::ResolvedYesCollateral as u8],
        BinaryMarketState::ResolvedNo { .. } => &[BinaryMarketSlot::ResolvedNoCollateral as u8],
        BinaryMarketState::Expired { .. } => &[BinaryMarketSlot::ExpiredCollateral as u8],
    };
    if roles != expected {
        return Err(ValidationError::LiveOutpointShape(
            "binary-market roles disagree with materialized state",
        ));
    }
    match state {
        BinaryMarketState::Trading {
            outstanding_pairs: 0,
        } => {
            if live[0].outpoint.txid != live[1].outpoint.txid {
                return Err(ValidationError::LiveOutpointShape(
                    "dormant RT outputs are not transaction siblings",
                ));
            }
        }
        BinaryMarketState::Trading { .. } => {
            let by_role = live
                .iter()
                .map(|item| (item.role, item.outpoint))
                .collect::<HashMap<_, _>>();
            let yes = by_role[&(BinaryMarketSlot::UnresolvedYesRt as u8)];
            let no = by_role[&(BinaryMarketSlot::UnresolvedNoRt as u8)];
            let collateral = by_role[&(BinaryMarketSlot::UnresolvedCollateral as u8)];
            if yes.txid != no.txid
                || yes.txid != collateral.txid
                || yes.vout.checked_add(1) != Some(no.vout)
                || yes.vout.checked_add(2) != Some(collateral.vout)
            {
                return Err(ValidationError::LiveOutpointShape(
                    "active market outputs are not the canonical sibling group",
                ));
            }
        }
        BinaryMarketState::ResolvedYes { .. }
        | BinaryMarketState::ResolvedNo { .. }
        | BinaryMarketState::Expired { .. } => {}
    }
    Ok(())
}

fn unique_defining_input(
    transaction: &Transaction,
    expected_asset: elements::AssetId,
    expected_rt: elements::AssetId,
) -> Result<usize, ValidationError> {
    let matches = transaction
        .input
        .iter()
        .enumerate()
        .filter(|(_, input)| {
            input.has_issuance()
                && input.asset_issuance.asset_blinding_nonce == ZERO_TWEAK
                && input.asset_issuance.asset_entropy == [0; 32]
                && input.asset_issuance.amount == Value::Null
                && input.asset_issuance.inflation_keys == Value::Explicit(1)
                && input.issuance_ids() == (expected_asset, expected_rt)
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [index] => Ok(*index),
        _ => Err(ValidationError::CreationMismatchOwned(format!(
            "expected one canonical defining issuance, found {}",
            matches.len()
        ))),
    }
}

fn unique_market_output(
    transaction: &Transaction,
    script: &elements::Script,
    commitment: (Asset, Value),
) -> Result<u32, ValidationError> {
    let matches = transaction
        .output
        .iter()
        .enumerate()
        .filter(|(_, output)| {
            output.script_pubkey == *script
                && output.asset == commitment.0
                && output.value == commitment.1
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [index] => u32::try_from(*index).map_err(|_| ValidationError::IndexOverflow),
        _ => Err(ValidationError::CreationMismatchOwned(format!(
            "expected one deterministic dormant RT output, found {}",
            matches.len()
        ))),
    }
}

fn tracked_output(
    transaction: &Transaction,
    index: u32,
) -> Result<TrackedContractOutput, ValidationError> {
    let txout = transaction
        .output
        .get(index as usize)
        .cloned()
        .ok_or(ValidationError::IndexOverflow)?;
    Ok(TrackedContractOutput {
        outpoint: OutPoint::new(transaction.txid(), index),
        txout,
    })
}

fn live_from_market_continuations(
    continuations: &[deadcat_contracts::interpret::BinaryMarketContinuation],
) -> BinaryMarketLiveOutputs {
    let mut live = BinaryMarketLiveOutputs::default();
    for continuation in continuations {
        match continuation.slot {
            BinaryMarketSlot::DormantYesRt | BinaryMarketSlot::UnresolvedYesRt => {
                live.yes_rt = Some(continuation.output.clone());
            }
            BinaryMarketSlot::DormantNoRt | BinaryMarketSlot::UnresolvedNoRt => {
                live.no_rt = Some(continuation.output.clone());
            }
            BinaryMarketSlot::UnresolvedCollateral
            | BinaryMarketSlot::ResolvedYesCollateral
            | BinaryMarketSlot::ResolvedNoCollateral
            | BinaryMarketSlot::ExpiredCollateral => {
                live.collateral = Some(continuation.output.clone());
            }
        }
    }
    live
}

fn market_live_outpoints(
    compiled: &CompiledBinaryMarket,
    live: &BinaryMarketLiveOutputs,
) -> Result<Vec<LiveOutpoint>, ValidationError> {
    let mut output = Vec::new();
    if let Some(item) = &live.yes_rt {
        output.push(LiveOutpoint {
            role: market_slot_from_script(compiled, item)?,
            outpoint: item.outpoint,
        });
    }
    if let Some(item) = &live.no_rt {
        output.push(LiveOutpoint {
            role: market_slot_from_script(compiled, item)?,
            outpoint: item.outpoint,
        });
    }
    if let Some(item) = &live.collateral {
        output.push(LiveOutpoint {
            role: market_slot_from_script(compiled, item)?,
            outpoint: item.outpoint,
        });
    }
    Ok(output)
}

fn market_slot_from_script(
    compiled: &CompiledBinaryMarket,
    output: &TrackedContractOutput,
) -> Result<u8, ValidationError> {
    let matching = compiled
        .slots()
        .iter()
        .filter(|slot| output.txout.script_pubkey == *slot.script_pubkey())
        .map(|slot| slot.slot() as u8)
        .collect::<Vec<_>>();
    match matching.as_slice() {
        [role] => Ok(*role),
        _ => Err(ValidationError::Interpretation(
            "continuation script does not uniquely identify a market slot".to_owned(),
        )),
    }
}

fn same_live_set(left: &[LiveOutpoint], right: &[LiveOutpoint]) -> bool {
    let left = left
        .iter()
        .map(|item| (item.role, item.outpoint))
        .collect::<HashSet<_>>();
    let right = right
        .iter()
        .map(|item| (item.role, item.outpoint))
        .collect::<HashSet<_>>();
    left == right
}

fn validate_transition_record(
    entry: &HistoryEntry,
    kind: u16,
    payload: &[u8],
) -> Result<(), ValidationError> {
    if entry.transition_kind != kind || entry.transition_payload != payload {
        return Err(ValidationError::TransitionRecordMismatch {
            position: entry.position,
        });
    }
    Ok(())
}

fn encode_market_transition(
    path: BinaryMarketPath,
    transition: BinaryMarketTransition,
) -> (u16, Vec<u8>) {
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
    (kind, payload)
}

const fn outcome_byte(outcome: BinaryOutcome) -> u8 {
    match outcome {
        BinaryOutcome::Yes => 0,
        BinaryOutcome::No => 1,
    }
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("invalid contract shape: {0}")]
    ContractShape(&'static str),
    #[error("contract compilation failed: {0}")]
    Compilation(#[from] CompiledBinaryMarketError),
    #[error("invalid contract economics: {0}")]
    Economics(String),
    #[error("duplicate live role or invalid live-output shape: {0}")]
    LiveOutpointShape(&'static str),
    #[error("snapshot mismatch: {0}")]
    SnapshotMismatch(&'static str),
    #[error("snapshot anchor was not confirmed by the independent chain source")]
    UntrustedSnapshotAnchor,
    #[error("contract is not ready at the requested snapshot")]
    ContractNotReadyAtSnapshot,
    #[error("history response is paginated; complete replay is impossible")]
    IncompleteHistory,
    #[error("invalid history: {0}")]
    HistoryMismatch(&'static str),
    #[error("history positions are not strictly increasing after creation")]
    HistoryOrder,
    #[error("creation evidence mismatch: {0}")]
    CreationMismatch(&'static str),
    #[error("creation evidence mismatch: {0}")]
    CreationMismatchOwned(String),
    #[error("transaction evidence txid does not match its transaction")]
    EvidenceTxidMismatch,
    #[error("transaction evidence omits affected contract {0:?}")]
    EvidenceContractMissing(ContractId),
    #[error("transaction evidence at {position:?} is not canonical in block {block_hash}")]
    NonCanonicalEvidence {
        position: ChainPosition,
        block_hash: BlockHash,
    },
    #[error("transaction evidence at {position:?} is after or conflicts with the snapshot tip")]
    EvidenceOutsideSnapshot { position: ChainPosition },
    #[error("canonical contract interpretation failed: {0}")]
    Interpretation(String),
    #[error("history transition record mismatch at {position:?}")]
    TransitionRecordMismatch { position: ChainPosition },
    #[error("replayed final state differs from the contract view")]
    FinalStateMismatch,
    #[error("replayed live outpoints differ from the contract view")]
    FinalLiveOutpointsMismatch,
    #[error("transaction index does not fit u32")]
    IndexOverflow,
    #[error("market PSET intent is invalid: {0}")]
    MarketIntent(#[from] MarketBuilderError),
}

#[cfg(test)]
mod tests {
    use deadcat_contracts::binary_market::{BinaryMarketAction, CompiledBinaryMarket};
    use deadcat_contracts::market_crypto::derive_issuance_assets;
    use deadcat_contracts::recovery::{MarketCollateral, MarketRecoveryHint};
    use deadcat_contracts::rt::{RtLeg, RtSide, commitments, factors};
    use deadcat_rpc::{ContractParametersView, ContractStateView};
    use elements::confidential::{Asset, Nonce, Value};
    use elements::hashes::Hash as _;
    use elements::pset::{Input as PsetInput, Output as PsetOutput};
    use elements::secp256k1_zkp::{Keypair, Secp256k1, Tweak};
    use elements::{
        AssetId, AssetIssuance, LockTime, OutPoint, Script, Transaction, TxIn, TxOut, TxOutWitness,
        Txid,
    };

    use super::*;
    use crate::market_builder::{
        BinaryMarketCreationPlan, BinaryMarketLiveInputs, MarketCreationContext, MarketRtInput,
    };

    fn asset(byte: u8) -> AssetId {
        AssetId::from_slice(&[byte; 32]).expect("asset")
    }

    fn txid(byte: u8) -> Txid {
        Txid::from_byte_array([byte; 32])
    }

    fn block(byte: u8) -> BlockHash {
        BlockHash::from_byte_array([byte; 32])
    }

    fn anchor(height: u32, byte: u8) -> ChainAnchor {
        ChainAnchor {
            height,
            hash: block(byte),
        }
    }

    fn position(height: u32, index: u32) -> ChainPosition {
        ChainPosition {
            block_height: height,
            tx_index: index,
        }
    }

    fn key(seed: u8) -> [u8; 32] {
        Keypair::from_seckey_slice(&Secp256k1::new(), &[seed; 32])
            .expect("key")
            .x_only_public_key()
            .0
            .serialize()
    }

    fn explicit_output(asset_id: AssetId, value: u64, script: Script) -> TxOut {
        TxOut {
            asset: Asset::Explicit(asset_id),
            value: Value::Explicit(value),
            nonce: Nonce::Null,
            script_pubkey: script,
            witness: TxOutWitness::default(),
        }
    }

    fn base_market_params() -> BinaryMarketParams {
        BinaryMarketParams {
            oracle_public_key: key(0x31),
            collateral_asset_id: asset(0x10),
            yes_token_asset_id: asset(0x11),
            no_token_asset_id: asset(0x12),
            yes_reissuance_token_id: asset(0x13),
            no_reissuance_token_id: asset(0x14),
            base_payout: 100,
            expiry_height: 500,
        }
    }

    fn market_view(at: ChainAnchor) -> ContractView {
        let params = base_market_params();
        let creation_txid = txid(0x21);
        CompiledBinaryMarket::new(params).expect("compile");
        let contract_id = ContractId::new(OutPoint::new(creation_txid, 0));
        ContractView {
            contract_id,
            kind: ContractKind::BinaryMarketV1,
            sync_state: ContractSyncState::Ready { synced_through: at },
            creation_position: position(1, 0),
            parameters: ContractParametersView::BinaryMarket { params },
            state: ContractStateView::BinaryMarket {
                state: BinaryMarketState::Trading {
                    outstanding_pairs: 0,
                },
            },
            live_outpoints: vec![
                LiveOutpoint {
                    role: BinaryMarketSlot::DormantYesRt as u8,
                    outpoint: OutPoint::new(creation_txid, 0),
                },
                LiveOutpoint {
                    role: BinaryMarketSlot::DormantNoRt as u8,
                    outpoint: OutPoint::new(creation_txid, 1),
                },
            ],
        }
    }

    fn market_snapshot(view: ContractView, at: ChainAnchor) -> MarketSnapshot {
        let ContractParametersView::BinaryMarket { params } = view.parameters;
        let ContractStateView::BinaryMarket { state } = view.state;
        MarketSnapshot {
            snapshot: SnapshotMetadata {
                as_of: at,
                event_high_watermark: deadcat_types::EventCursor {
                    epoch: [7; 16],
                    sequence: 9,
                },
            },
            params,
            state,
            live_outpoints: view.live_outpoints.clone(),
            contract: view,
        }
    }

    #[test]
    fn contract_shape_and_snapshot_anchor_fail_closed() {
        let tip = anchor(8, 0x80);
        let market = market_view(tip);
        validate_contract_view(&market).expect("valid market");
        validate_market_snapshot(&market_snapshot(market.clone(), tip), tip)
            .expect("trusted snapshot");

        let mut bad_live = market.clone();
        bad_live.live_outpoints[0].role = BinaryMarketSlot::UnresolvedYesRt as u8;
        assert!(matches!(
            validate_contract_view(&bad_live),
            Err(ValidationError::LiveOutpointShape(_))
        ));

        assert!(matches!(
            validate_market_snapshot(&market_snapshot(market, tip), anchor(8, 0x81)),
            Err(ValidationError::UntrustedSnapshotAnchor)
        ));
    }

    fn new_issuance_input(outpoint: OutPoint) -> TxIn {
        TxIn {
            previous_output: outpoint,
            asset_issuance: AssetIssuance {
                asset_blinding_nonce: ZERO_TWEAK,
                asset_entropy: [0; 32],
                amount: Value::Null,
                inflation_keys: Value::Explicit(1),
            },
            ..TxIn::default()
        }
    }

    #[test]
    fn market_creation_replay_rederives_issuances_commitments_and_live_outputs() {
        let yes_defining = OutPoint::new(txid(0x51), 3);
        let no_defining = OutPoint::new(txid(0x52), 4);
        let assets = derive_issuance_assets(yes_defining, no_defining);
        let params = BinaryMarketParams {
            oracle_public_key: key(0x31),
            collateral_asset_id: asset(0x70),
            yes_token_asset_id: assets.yes_token,
            no_token_asset_id: assets.no_token,
            yes_reissuance_token_id: assets.yes_reissuance_token,
            no_reissuance_token_id: assets.no_reissuance_token,
            base_payout: 100,
            expiry_height: 500,
        };
        let compiled = CompiledBinaryMarket::new(params).expect("compile");
        let rt_output = |asset_id, factors, slot| {
            let (asset, value) = commitments(asset_id, factors).expect("commitments");
            TxOut {
                asset,
                value,
                nonce: Nonce::Null,
                script_pubkey: compiled.slot(slot).script_pubkey().clone(),
                witness: TxOutWitness::default(),
            }
        };
        let creation_tx = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![
                new_issuance_input(yes_defining),
                new_issuance_input(no_defining),
            ],
            output: vec![
                rt_output(
                    params.yes_reissuance_token_id,
                    factors(RtLeg::Yes, RtSide::A),
                    BinaryMarketSlot::DormantYesRt,
                ),
                rt_output(
                    params.no_reissuance_token_id,
                    factors(RtLeg::No, RtSide::A),
                    BinaryMarketSlot::DormantNoRt,
                ),
            ],
        };
        let tip = anchor(4, 0x84);
        let id = ContractId::new(OutPoint::new(creation_tx.txid(), 0));
        let expected = ContractView {
            contract_id: id,
            kind: ContractKind::BinaryMarketV1,
            sync_state: ContractSyncState::Ready {
                synced_through: tip,
            },
            creation_position: position(4, 0),
            parameters: ContractParametersView::BinaryMarket { params },
            state: ContractStateView::BinaryMarket {
                state: BinaryMarketState::Trading {
                    outstanding_pairs: 0,
                },
            },
            live_outpoints: vec![
                LiveOutpoint {
                    role: BinaryMarketSlot::DormantYesRt as u8,
                    outpoint: OutPoint::new(creation_tx.txid(), 0),
                },
                LiveOutpoint {
                    role: BinaryMarketSlot::DormantNoRt as u8,
                    outpoint: OutPoint::new(creation_tx.txid(), 1),
                },
            ],
        };
        let evidence = TransactionEvidence {
            position: position(4, 0),
            block_hash: tip.hash,
            txid: creation_tx.txid(),
            transaction: creation_tx,
            affected_contract_ids: vec![id],
        };
        let history = ContractHistoryPage {
            snapshot: SnapshotMetadata {
                as_of: tip,
                event_high_watermark: deadcat_types::EventCursor {
                    epoch: [9; 16],
                    sequence: 1,
                },
            },
            contract_id: id,
            entries: Vec::new(),
            next: None,
        };
        let evidence_wtxid = evidence.transaction.wtxid();
        replay_contract_history(
            &expected,
            &history,
            &evidence,
            &[],
            tip,
            |pos, hash, transaction| {
                pos == position(4, 0) && hash == tip.hash && transaction.wtxid() == evidence_wtxid
            },
        )
        .expect("market creation replay");

        let wrong_anchor_id = ContractId::new(OutPoint::new(evidence.txid, 1));
        let mut wrong_anchor_view = expected.clone();
        wrong_anchor_view.contract_id = wrong_anchor_id;
        let mut wrong_anchor_evidence = evidence.clone();
        wrong_anchor_evidence.affected_contract_ids = vec![wrong_anchor_id];
        let mut wrong_anchor_history = history.clone();
        wrong_anchor_history.contract_id = wrong_anchor_id;
        assert!(matches!(
            replay_contract_history(
                &wrong_anchor_view,
                &wrong_anchor_history,
                &wrong_anchor_evidence,
                &[],
                tip,
                |pos, hash, transaction| {
                    pos == position(4, 0)
                        && hash == tip.hash
                        && transaction.wtxid() == evidence_wtxid
                },
            ),
            Err(ValidationError::CreationMismatch(message))
                if message.contains("initial dormant YES RT output")
        ));

        let mut bad_evidence = evidence;
        let (asset, value) = commitments(
            params.yes_reissuance_token_id,
            factors(RtLeg::Yes, RtSide::B),
        )
        .expect("side-B YES commitments");
        bad_evidence.transaction.output[0].asset = asset;
        bad_evidence.transaction.output[0].value = value;
        let bad_txid = bad_evidence.transaction.txid();
        let bad_id = ContractId::new(OutPoint::new(bad_txid, 0));
        bad_evidence.txid = bad_txid;
        bad_evidence.affected_contract_ids = vec![bad_id];

        let mut bad_expected = expected;
        bad_expected.contract_id = bad_id;
        bad_expected.live_outpoints[0].outpoint = OutPoint::new(bad_txid, 0);
        bad_expected.live_outpoints[1].outpoint = OutPoint::new(bad_txid, 1);
        let mut bad_history = history;
        bad_history.contract_id = bad_id;

        assert!(matches!(
            replay_contract_history(
                &bad_expected,
                &bad_history,
                &bad_evidence,
                &[],
                tip,
                |pos, hash, transaction| {
                    pos == position(4, 0)
                        && hash == tip.hash
                        && transaction.wtxid() == bad_evidence.transaction.wtxid()
                },
            ),
            Err(ValidationError::CreationMismatchOwned(message)) if message.contains("found 0")
        ));
    }

    #[test]
    fn market_transition_replay_rejects_side_nonce_and_history_tampering() {
        let policy_asset = asset(0x70);
        let yes_defining = OutPoint::new(txid(0x61), 3);
        let no_defining = OutPoint::new(txid(0x62), 4);
        let assets = derive_issuance_assets(yes_defining, no_defining);
        let params = BinaryMarketParams {
            oracle_public_key: key(0x31),
            collateral_asset_id: policy_asset,
            yes_token_asset_id: assets.yes_token,
            no_token_asset_id: assets.no_token,
            yes_reissuance_token_id: assets.yes_reissuance_token,
            no_reissuance_token_id: assets.no_reissuance_token,
            base_payout: 100,
            expiry_height: 500,
        };
        let creation_plan = BinaryMarketCreationPlan::new(
            MarketCreationContext {
                policy_asset,
                liquid_mainnet_usdt: None,
            },
            params,
            MarketRecoveryHint {
                oracle_public_key: params.oracle_public_key,
                collateral: MarketCollateral::PolicyAsset,
                base_payout: params.base_payout,
                expiry_height: params.expiry_height,
            },
            yes_defining,
            no_defining,
        )
        .expect("creation plan");
        let funding = explicit_output(policy_asset, 10_000, Script::from(vec![0x51]));
        let mut yes_funding = PsetInput::from_prevout(yes_defining);
        yes_funding.witness_utxo = Some(funding.clone());
        let mut no_funding = PsetInput::from_prevout(no_defining);
        no_funding.witness_utxo = Some(funding);
        let mut creation_pset = creation_plan
            .build_pset(yes_funding, no_funding)
            .expect("creation PSET");
        creation_plan
            .finalize_rt_proofs(&mut creation_pset)
            .expect("creation RT proofs");
        let creation_tx = creation_pset.extract_tx().expect("creation transaction");

        let pairs = 2;
        let live = BinaryMarketLiveInputs {
            yes_rt: Some(MarketRtInput {
                outpoint: OutPoint::new(creation_tx.txid(), 0),
                txout: creation_tx.output[0].clone(),
            }),
            no_rt: Some(MarketRtInput {
                outpoint: OutPoint::new(creation_tx.txid(), 1),
                txout: creation_tx.output[1].clone(),
            }),
            collateral: None,
        };
        let issuance_plan = BinaryMarketTransitionPlan::new(
            params,
            BinaryMarketState::Trading {
                outstanding_pairs: 0,
            },
            BinaryMarketAction::Issue { pairs },
            live,
            None,
        )
        .expect("initial issuance plan");
        let mut issuance_pset = PartiallySignedTransaction::new_v2();
        for vout in 0..2_u32 {
            let mut input = PsetInput::from_prevout(OutPoint::new(creation_tx.txid(), vout));
            input.witness_utxo =
                Some(creation_tx.output[usize::try_from(vout).expect("vout")].clone());
            issuance_pset.add_input(input);
        }
        for (_, output) in issuance_plan
            .mandatory_outputs(0)
            .expect("mandatory outputs")
        {
            issuance_pset.add_output(PsetOutput::from_txout(output));
        }
        issuance_plan
            .configure_reissuance_inputs(&mut issuance_pset, 0, creation_plan.entropies())
            .expect("reissuance inputs");
        issuance_plan
            .finalize(
                &mut issuance_pset,
                0,
                0,
                &SimplicityNetwork::ElementsRegtest { policy_asset },
            )
            .expect("official A-to-B issuance");
        let issuance_tx = issuance_pset.extract_tx().expect("issuance transaction");

        let contract_id = ContractId::new(OutPoint::new(creation_tx.txid(), 0));
        let creation_position = position(1, 0);
        let issuance_position = position(2, 0);
        let creation_block = block(0x81);
        let tip = anchor(2, 0x82);
        let expected = ContractView {
            contract_id,
            kind: ContractKind::BinaryMarketV1,
            sync_state: ContractSyncState::Ready {
                synced_through: tip,
            },
            creation_position,
            parameters: ContractParametersView::BinaryMarket { params },
            state: ContractStateView::BinaryMarket {
                state: BinaryMarketState::Trading {
                    outstanding_pairs: pairs,
                },
            },
            live_outpoints: vec![
                LiveOutpoint {
                    role: BinaryMarketSlot::UnresolvedYesRt as u8,
                    outpoint: OutPoint::new(issuance_tx.txid(), 0),
                },
                LiveOutpoint {
                    role: BinaryMarketSlot::UnresolvedNoRt as u8,
                    outpoint: OutPoint::new(issuance_tx.txid(), 1),
                },
                LiveOutpoint {
                    role: BinaryMarketSlot::UnresolvedCollateral as u8,
                    outpoint: OutPoint::new(issuance_tx.txid(), 2),
                },
            ],
        };
        let creation = TransactionEvidence {
            position: creation_position,
            block_hash: creation_block,
            txid: creation_tx.txid(),
            transaction: creation_tx,
            affected_contract_ids: vec![contract_id],
        };
        let issuance = TransactionEvidence {
            position: issuance_position,
            block_hash: tip.hash,
            txid: issuance_tx.txid(),
            transaction: issuance_tx,
            affected_contract_ids: vec![contract_id],
        };
        let collateral_locked = BinaryMarketEconomics::new(params.base_payout)
            .expect("economics")
            .collateral_for_pairs(pairs)
            .expect("collateral amount");
        let (transition_kind, transition_payload) = encode_market_transition(
            BinaryMarketPath::InitialIssuance,
            BinaryMarketTransition::Issued {
                pairs,
                collateral_locked,
            },
        );
        let history = ContractHistoryPage {
            snapshot: SnapshotMetadata {
                as_of: tip,
                event_high_watermark: deadcat_types::EventCursor {
                    epoch: [0x91; 16],
                    sequence: 2,
                },
            },
            contract_id,
            entries: vec![HistoryEntry {
                position: issuance_position,
                txid: issuance.txid,
                transition_kind,
                transition_payload,
            }],
            next: None,
        };
        let creation_wtxid = creation.transaction.wtxid();
        let issuance_wtxid = issuance.transaction.wtxid();
        let canonical = |position, hash, transaction: &Transaction| {
            (position == creation_position
                && hash == creation_block
                && transaction.wtxid() == creation_wtxid)
                || (position == issuance_position
                    && hash == tip.hash
                    && transaction.wtxid() == issuance_wtxid)
        };

        let replay = replay_contract_history(
            &expected,
            &history,
            &creation,
            std::slice::from_ref(&issuance),
            tip,
            canonical,
        )
        .expect("creation plus A-to-B replay");
        assert_eq!(replay.transition_count(), 1);

        let mut wrong_side = issuance.clone();
        let (asset, value) = commitments(
            params.yes_reissuance_token_id,
            factors(RtLeg::Yes, RtSide::A),
        )
        .expect("same-side commitments");
        wrong_side.transaction.output[0].asset = asset;
        wrong_side.transaction.output[0].value = value;
        wrong_side.txid = wrong_side.transaction.txid();
        let wrong_side_wtxid = wrong_side.transaction.wtxid();
        let mut wrong_side_history = history.clone();
        wrong_side_history.entries[0].txid = wrong_side.txid;
        assert!(matches!(
            replay_contract_history(
                &expected,
                &wrong_side_history,
                &creation,
                &[wrong_side],
                tip,
                |position, hash, transaction| {
                    (position == creation_position
                        && hash == creation_block
                        && transaction.wtxid() == creation_wtxid)
                        || (position == issuance_position
                            && hash == tip.hash
                            && transaction.wtxid() == wrong_side_wtxid)
                },
            ),
            Err(ValidationError::Interpretation(_))
        ));

        let mut wrong_nonce = issuance.clone();
        wrong_nonce.transaction.input[0]
            .asset_issuance
            .asset_blinding_nonce =
            Tweak::from_inner(RtSide::B.abf()).expect("opposite public ABF");
        wrong_nonce.txid = wrong_nonce.transaction.txid();
        let wrong_nonce_wtxid = wrong_nonce.transaction.wtxid();
        let mut wrong_nonce_history = history.clone();
        wrong_nonce_history.entries[0].txid = wrong_nonce.txid;
        assert!(matches!(
            replay_contract_history(
                &expected,
                &wrong_nonce_history,
                &creation,
                &[wrong_nonce],
                tip,
                |position, hash, transaction| {
                    (position == creation_position
                        && hash == creation_block
                        && transaction.wtxid() == creation_wtxid)
                        || (position == issuance_position
                            && hash == tip.hash
                            && transaction.wtxid() == wrong_nonce_wtxid)
                },
            ),
            Err(ValidationError::Interpretation(_))
        ));

        let mut wrong_history = history;
        wrong_history.entries[0].transition_payload[0] = BinaryMarketPath::SubsequentIssuance as u8;
        assert!(matches!(
            replay_contract_history(
                &expected,
                &wrong_history,
                &creation,
                &[issuance],
                tip,
                canonical,
            ),
            Err(ValidationError::TransitionRecordMismatch { .. })
        ));
    }

    #[test]
    fn market_signing_intent_validation_is_non_mutating_and_rejects_tampering() {
        let params = base_market_params();
        let compiled = CompiledBinaryMarket::new(params).expect("compile market");
        let rt_input = |outpoint, asset_id, leg, slot| {
            let (asset, value) =
                commitments(asset_id, factors(leg, RtSide::A)).expect("commitments");
            MarketRtInput {
                outpoint,
                txout: TxOut {
                    asset,
                    value,
                    nonce: Nonce::Null,
                    script_pubkey: compiled.slot(slot).script_pubkey().clone(),
                    witness: TxOutWitness::default(),
                },
            }
        };
        let yes = rt_input(
            OutPoint::new(txid(0x90), 0),
            params.yes_reissuance_token_id,
            RtLeg::Yes,
            BinaryMarketSlot::DormantYesRt,
        );
        let no = rt_input(
            OutPoint::new(txid(0x90), 1),
            params.no_reissuance_token_id,
            RtLeg::No,
            BinaryMarketSlot::DormantNoRt,
        );
        let market_plan = BinaryMarketTransitionPlan::new(
            params,
            BinaryMarketState::Trading {
                outstanding_pairs: 0,
            },
            BinaryMarketAction::Expire,
            BinaryMarketLiveInputs {
                yes_rt: Some(yes.clone()),
                no_rt: Some(no.clone()),
                collateral: None,
            },
            None,
        )
        .expect("market plan");
        let mut market_pset = PartiallySignedTransaction::new_v2();
        for input in [&yes, &no] {
            let mut pset_input = PsetInput::from_prevout(input.outpoint);
            pset_input.witness_utxo = Some(input.txout.clone());
            market_pset.add_input(pset_input);
        }
        for (_, output) in market_plan.mandatory_outputs(0).expect("outputs") {
            market_pset.add_output(PsetOutput::from_txout(output));
        }
        market_plan
            .prepare_expiry(&mut market_pset, 0)
            .expect("expiry");
        let market_original = market_pset.clone();
        let market_network = SimplicityNetwork::ElementsRegtest {
            policy_asset: params.collateral_asset_id,
        };
        validate_market_pset_intent(&market_plan, &market_pset, 0, 0, &market_network)
            .expect("market intent");
        assert_eq!(market_pset, market_original);
        market_pset.global.tx_data.fallback_locktime = Some(LockTime::ZERO);
        assert!(matches!(
            validate_market_pset_intent(&market_plan, &market_pset, 0, 0, &market_network),
            Err(ValidationError::MarketIntent(
                MarketBuilderError::MissingExpiryLocktime
            ))
        ));
    }
}

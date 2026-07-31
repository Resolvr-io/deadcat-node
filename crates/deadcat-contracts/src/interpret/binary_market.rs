use deadcat_types::{BinaryMarketParams, BinaryMarketState};
use elements::confidential::{Asset, Value};
use elements::secp256k1_zkp::{Message, Secp256k1, Tweak, XOnlyPublicKey, schnorr::Signature};
use elements::{AssetId, OutPoint, Transaction, TxOut};
use simplex::simplicityhl::simplicity::types::Final;
use simplex::simplicityhl::simplicity::{Value as SimplicityValue, ValueRef};

use super::{
    DecodedSimplicityWitness, InterpretError, TrackedContractOutput, decode_simplicity_witness,
    locate_input, output_at,
};
use crate::binary_market::{
    AppliedBinaryMarketTransition, BinaryMarketAction, BinaryMarketCoordinatorAction,
    BinaryMarketCoordinatorRole, BinaryMarketEconomics, BinaryMarketLayout, BinaryMarketPath,
    BinaryMarketResolution, BinaryMarketSlot, CompiledBinaryMarket,
};
use crate::binary_market::{BinaryMarketTransition, BinaryOutcome};
use crate::market_crypto::{BinaryOutcome as OracleOutcome, oracle_message};
use crate::rt::{RtFactors, RtLeg, RtSide, commitments, factors, infer_side};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BinaryMarketLiveOutputs {
    pub yes_rt: Option<TrackedContractOutput>,
    pub no_rt: Option<TrackedContractOutput>,
    pub collateral: Option<TrackedContractOutput>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryMarketContinuation {
    pub slot: BinaryMarketSlot,
    pub output: TrackedContractOutput,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryMarketInterpretation {
    pub path: BinaryMarketPath,
    pub action: BinaryMarketAction,
    pub before: BinaryMarketState,
    pub after: BinaryMarketState,
    pub transition: BinaryMarketTransition,
    pub input_base: u32,
    pub output_base: u32,
    pub spent_outpoints: Vec<OutPoint>,
    pub continuations: Vec<BinaryMarketContinuation>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct BinaryMarketRtSides {
    yes: Option<RtSide>,
    no: Option<RtSide>,
}

pub fn interpret_binary_market_spend(
    params: BinaryMarketParams,
    before: BinaryMarketState,
    live: &BinaryMarketLiveOutputs,
    transaction: &Transaction,
) -> Result<BinaryMarketInterpretation, InterpretError> {
    let compiled = CompiledBinaryMarket::new(params)?;
    interpret_binary_market_spend_with_compiled(&compiled, before, live, transaction)
}

/// Interpret a spend using an already compiled canonical binary market.
///
/// This avoids recompiling the same parameterized covenant when a caller
/// interprets multiple transactions for one market.
pub fn interpret_binary_market_spend_with_compiled(
    compiled: &CompiledBinaryMarket,
    before: BinaryMarketState,
    live: &BinaryMarketLiveOutputs,
    transaction: &Transaction,
) -> Result<BinaryMarketInterpretation, InterpretError> {
    let params = compiled.params();
    validate_live_outputs(compiled, params, before, live)?;
    let head = match before {
        BinaryMarketState::Trading { .. } => live.yes_rt.as_ref(),
        BinaryMarketState::ResolvedYes { .. }
        | BinaryMarketState::ResolvedNo { .. }
        | BinaryMarketState::Expired { .. } => live.collateral.as_ref(),
    }
    .ok_or(InterpretError::InvalidTrackedOutput(
        "missing primary live output",
    ))?;
    let head_index = locate_input(transaction, head.outpoint)?;
    let input_base = u32::try_from(head_index).map_err(|_| InterpretError::IndexOverflow)?;
    let stack = &transaction.input[head_index].witness.script_witness;
    let key_path_items = if stack.len() == 2
        && stack
            .last()
            .and_then(|item| item.first())
            .is_some_and(|byte| *byte == 0x50)
    {
        1
    } else {
        stack.len()
    };
    if key_path_items == 1 {
        return Err(InterpretError::UnexpectedKeySpend);
    }
    let decoded = decode_simplicity_witness(stack)?;
    if decoded.cmr() != compiled.cmr() {
        return Err(InterpretError::CmrMismatch);
    }
    let coordinator = BinaryMarketCoordinatorRole::for_state(before);
    let expected_slot = coordinator.slot();
    if decoded.control_block() != compiled.slot(expected_slot).control_block() {
        return Err(InterpretError::Inconsistent(
            "market control block mismatch",
        ));
    }
    let operation = decode_market_witness(&decoded, expected_slot)?;
    let output_base = operation.output_base();
    let live_rt_sides = infer_live_rt_sides(params, before, live)?;
    let full_cancellation = match operation {
        BinaryMarketCoordinatorAction::Cancel { .. } => {
            Some(cancellation_is_full(params, transaction, output_base)?)
        }
        _ => None,
    };
    let layout = BinaryMarketLayout::for_operation(
        BinaryMarketCoordinatorRole::try_from(expected_slot)?,
        operation.operation(),
        full_cancellation,
    )?;
    let (outcome_yes, tokens) = match operation {
        BinaryMarketCoordinatorAction::Resolve { resolution, .. } => {
            let outcome_yes = resolution.outcome() == BinaryOutcome::Yes;
            if !verify_oracle_signature(params, outcome_yes, &resolution.signature()) {
                return Err(InterpretError::Inconsistent("invalid oracle signature"));
            }
            (outcome_yes, 0)
        }
        BinaryMarketCoordinatorAction::Redeem { .. } => {
            redemption_details(params, before, transaction, output_base)?
        }
        _ => (false, 0),
    };
    let economics = BinaryMarketEconomics::new(params.base_payout)?;
    interpret_decoded_action(
        params,
        economics,
        compiled,
        before,
        live,
        live_rt_sides,
        transaction,
        layout,
        input_base,
        output_base,
        outcome_yes,
        tokens,
    )
}

#[allow(clippy::too_many_arguments)]
fn interpret_decoded_action(
    params: BinaryMarketParams,
    economics: BinaryMarketEconomics,
    compiled: &CompiledBinaryMarket,
    before: BinaryMarketState,
    live: &BinaryMarketLiveOutputs,
    live_rt_sides: BinaryMarketRtSides,
    transaction: &Transaction,
    layout: BinaryMarketLayout,
    input_base: u32,
    output_base: u32,
    outcome_yes: bool,
    tokens: u64,
) -> Result<BinaryMarketInterpretation, InterpretError> {
    let path = layout.path();
    let spent = verify_input_group(layout, before, live, transaction, input_base)?;
    let action = match path {
        BinaryMarketPath::InitialIssuance | BinaryMarketPath::SubsequentIssuance => {
            let yes_side = live_rt_sides
                .yes
                .ok_or(InterpretError::InvalidTrackedOutput(
                    "missing inferred YES RT side",
                ))?;
            let no_side = live_rt_sides
                .no
                .ok_or(InterpretError::InvalidTrackedOutput(
                    "missing inferred NO RT side",
                ))?;
            let yes = issuance_amount(
                transaction,
                input_base,
                params.yes_token_asset_id,
                params.yes_reissuance_token_id,
                factors(RtLeg::Yes, yes_side).abf,
            )?;
            let no = issuance_amount(
                transaction,
                add_index(input_base, 1)?,
                params.no_token_asset_id,
                params.no_reissuance_token_id,
                factors(RtLeg::No, no_side).abf,
            )?;
            if yes == 0 || yes != no {
                return Err(InterpretError::Inconsistent("unequal or zero issuance"));
            }
            BinaryMarketAction::Issue { pairs: yes }
        }
        BinaryMarketPath::PartialCancellation => {
            let pairs = token_burn_amount(
                transaction,
                add_index(output_base, 3)?,
                params.yes_token_asset_id,
            )?;
            check_token_burn(
                transaction,
                add_index(output_base, 4)?,
                params.no_token_asset_id,
                pairs,
            )?;
            BinaryMarketAction::Cancel { pairs }
        }
        BinaryMarketPath::FullCancellation => {
            let pairs = token_burn_amount(
                transaction,
                add_index(output_base, 2)?,
                params.yes_token_asset_id,
            )?;
            check_token_burn(
                transaction,
                add_index(output_base, 3)?,
                params.no_token_asset_id,
                pairs,
            )?;
            BinaryMarketAction::Cancel { pairs }
        }
        BinaryMarketPath::ActiveResolution | BinaryMarketPath::DormantResolution => {
            BinaryMarketAction::Resolve {
                outcome: if outcome_yes {
                    BinaryOutcome::Yes
                } else {
                    BinaryOutcome::No
                },
            }
        }
        BinaryMarketPath::ActiveExpiry | BinaryMarketPath::DormantExpiry => {
            check_expiry_lock(transaction, params.expiry_height)?;
            BinaryMarketAction::Expire
        }
        BinaryMarketPath::ResolvedRedemption => BinaryMarketAction::Redeem {
            outcome: match before {
                BinaryMarketState::ResolvedYes { .. } => BinaryOutcome::Yes,
                BinaryMarketState::ResolvedNo { .. } => BinaryOutcome::No,
                _ => return Err(InterpretError::Inconsistent("resolved redemption phase")),
            },
            tokens,
        },
        BinaryMarketPath::ExpiryRedemption => BinaryMarketAction::Redeem {
            outcome: if outcome_yes {
                BinaryOutcome::Yes
            } else {
                BinaryOutcome::No
            },
            tokens,
        },
    };
    let applied = economics.apply(before, action)?;
    let continuations = verify_outputs(
        params,
        compiled,
        transaction,
        layout,
        before,
        live,
        live_rt_sides,
        applied,
        output_base,
        tokens,
    )?;
    Ok(BinaryMarketInterpretation {
        path,
        action,
        before,
        after: applied.new_state,
        transition: applied.transition,
        input_base,
        output_base,
        spent_outpoints: spent,
        continuations,
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn verify_outputs(
    params: BinaryMarketParams,
    compiled: &CompiledBinaryMarket,
    transaction: &Transaction,
    layout: BinaryMarketLayout,
    before: BinaryMarketState,
    live: &BinaryMarketLiveOutputs,
    live_rt_sides: BinaryMarketRtSides,
    applied: AppliedBinaryMarketTransition,
    output_base: u32,
    tokens: u64,
) -> Result<Vec<BinaryMarketContinuation>, InterpretError> {
    let path = layout.path();
    let mut output = Vec::new();
    let yes_continuation =
        opposite_side_factors(RtLeg::Yes, live.yes_rt.as_ref(), live_rt_sides.yes)?;
    let no_continuation = opposite_side_factors(RtLeg::No, live.no_rt.as_ref(), live_rt_sides.no)?;
    match path {
        BinaryMarketPath::InitialIssuance | BinaryMarketPath::SubsequentIssuance => {
            push_rt_continuation(
                &mut output,
                compiled,
                transaction,
                output_base,
                BinaryMarketSlot::UnresolvedYesRt,
                params.yes_reissuance_token_id,
                yes_continuation.ok_or(InterpretError::InvalidTrackedOutput(
                    "missing inferred YES RT side",
                ))?,
            )?;
            push_rt_continuation(
                &mut output,
                compiled,
                transaction,
                add_index(output_base, 1)?,
                BinaryMarketSlot::UnresolvedNoRt,
                params.no_reissuance_token_id,
                no_continuation.ok_or(InterpretError::InvalidTrackedOutput(
                    "missing inferred NO RT side",
                ))?,
            )?;
            let amount = trading_collateral(applied.new_state, params)?;
            push_collateral_continuation(
                &mut output,
                compiled,
                transaction,
                add_index(output_base, 2)?,
                BinaryMarketSlot::UnresolvedCollateral,
                params.collateral_asset_id,
                amount,
            )?;
        }
        BinaryMarketPath::PartialCancellation => {
            push_rt_continuation(
                &mut output,
                compiled,
                transaction,
                output_base,
                BinaryMarketSlot::UnresolvedYesRt,
                params.yes_reissuance_token_id,
                yes_continuation.ok_or(InterpretError::InvalidTrackedOutput(
                    "missing inferred YES RT side",
                ))?,
            )?;
            push_rt_continuation(
                &mut output,
                compiled,
                transaction,
                add_index(output_base, 1)?,
                BinaryMarketSlot::UnresolvedNoRt,
                params.no_reissuance_token_id,
                no_continuation.ok_or(InterpretError::InvalidTrackedOutput(
                    "missing inferred NO RT side",
                ))?,
            )?;
            let amount = trading_collateral(applied.new_state, params)?;
            if amount == 0 {
                return Err(InterpretError::Inconsistent(
                    "partial cancellation drained market",
                ));
            }
            push_collateral_continuation(
                &mut output,
                compiled,
                transaction,
                add_index(output_base, 2)?,
                BinaryMarketSlot::UnresolvedCollateral,
                params.collateral_asset_id,
                amount,
            )?;
        }
        BinaryMarketPath::FullCancellation => {
            if applied.new_state
                != (BinaryMarketState::Trading {
                    outstanding_pairs: 0,
                })
            {
                return Err(InterpretError::Inconsistent("full cancellation left pairs"));
            }
            push_rt_continuation(
                &mut output,
                compiled,
                transaction,
                output_base,
                BinaryMarketSlot::DormantYesRt,
                params.yes_reissuance_token_id,
                yes_continuation.ok_or(InterpretError::InvalidTrackedOutput(
                    "missing inferred YES RT side",
                ))?,
            )?;
            push_rt_continuation(
                &mut output,
                compiled,
                transaction,
                add_index(output_base, 1)?,
                BinaryMarketSlot::DormantNoRt,
                params.no_reissuance_token_id,
                no_continuation.ok_or(InterpretError::InvalidTrackedOutput(
                    "missing inferred NO RT side",
                ))?,
            )?;
        }
        BinaryMarketPath::ActiveResolution => {
            check_rt_burn(
                transaction,
                output_base,
                params.yes_reissuance_token_id,
                yes_continuation.ok_or(InterpretError::InvalidTrackedOutput(
                    "missing inferred YES RT side",
                ))?,
            )?;
            check_rt_burn(
                transaction,
                add_index(output_base, 1)?,
                params.no_reissuance_token_id,
                no_continuation.ok_or(InterpretError::InvalidTrackedOutput(
                    "missing inferred NO RT side",
                ))?,
            )?;
            let (slot, amount) = terminal_slot_amount(applied.new_state)?;
            push_collateral_continuation(
                &mut output,
                compiled,
                transaction,
                add_index(output_base, 2)?,
                slot,
                params.collateral_asset_id,
                amount,
            )?;
        }
        BinaryMarketPath::DormantResolution => {
            check_rt_burn(
                transaction,
                output_base,
                params.yes_reissuance_token_id,
                yes_continuation.ok_or(InterpretError::InvalidTrackedOutput(
                    "missing inferred YES RT side",
                ))?,
            )?;
            check_rt_burn(
                transaction,
                add_index(output_base, 1)?,
                params.no_reissuance_token_id,
                no_continuation.ok_or(InterpretError::InvalidTrackedOutput(
                    "missing inferred NO RT side",
                ))?,
            )?;
            if !matches!(
                before,
                BinaryMarketState::Trading {
                    outstanding_pairs: 0
                }
            ) {
                return Err(InterpretError::Inconsistent("dormant resolution state"));
            }
        }
        BinaryMarketPath::ActiveExpiry => {
            check_rt_burn(
                transaction,
                output_base,
                params.yes_reissuance_token_id,
                yes_continuation.ok_or(InterpretError::InvalidTrackedOutput(
                    "missing inferred YES RT side",
                ))?,
            )?;
            check_rt_burn(
                transaction,
                add_index(output_base, 1)?,
                params.no_reissuance_token_id,
                no_continuation.ok_or(InterpretError::InvalidTrackedOutput(
                    "missing inferred NO RT side",
                ))?,
            )?;
            let (_, amount) = terminal_slot_amount(applied.new_state)?;
            push_collateral_continuation(
                &mut output,
                compiled,
                transaction,
                add_index(output_base, 2)?,
                BinaryMarketSlot::ExpiredCollateral,
                params.collateral_asset_id,
                amount,
            )?;
        }
        BinaryMarketPath::DormantExpiry => {
            check_rt_burn(
                transaction,
                output_base,
                params.yes_reissuance_token_id,
                yes_continuation.ok_or(InterpretError::InvalidTrackedOutput(
                    "missing inferred YES RT side",
                ))?,
            )?;
            check_rt_burn(
                transaction,
                add_index(output_base, 1)?,
                params.no_reissuance_token_id,
                no_continuation.ok_or(InterpretError::InvalidTrackedOutput(
                    "missing inferred NO RT side",
                ))?,
            )?;
        }
        BinaryMarketPath::ResolvedRedemption | BinaryMarketPath::ExpiryRedemption => {
            if tokens == 0 {
                return Err(InterpretError::Inconsistent("zero redemption"));
            }
            let burn_asset = match action_outcome(applied.transition)? {
                BinaryOutcome::Yes => params.yes_token_asset_id,
                BinaryOutcome::No => params.no_token_asset_id,
            };
            match terminal_collateral(applied.new_state) {
                Some((slot, remaining)) if remaining > 0 => {
                    push_collateral_continuation(
                        &mut output,
                        compiled,
                        transaction,
                        output_base,
                        slot,
                        params.collateral_asset_id,
                        remaining,
                    )?;
                    check_token_burn(transaction, add_index(output_base, 1)?, burn_asset, tokens)?;
                }
                _ => check_token_burn(transaction, output_base, burn_asset, tokens)?,
            }
        }
    }
    Ok(output)
}

fn verify_input_group(
    layout: BinaryMarketLayout,
    before: BinaryMarketState,
    live: &BinaryMarketLiveOutputs,
    transaction: &Transaction,
    input_base: u32,
) -> Result<Vec<OutPoint>, InterpretError> {
    let path = layout.path();
    let mut spent = Vec::with_capacity(layout.input_roles().len());
    for (offset, role) in layout.input_roles().iter().copied().enumerate() {
        let tracked = match role.slot() {
            BinaryMarketSlot::DormantYesRt | BinaryMarketSlot::UnresolvedYesRt => {
                live.yes_rt.as_ref()
            }
            BinaryMarketSlot::DormantNoRt | BinaryMarketSlot::UnresolvedNoRt => live.no_rt.as_ref(),
            BinaryMarketSlot::UnresolvedCollateral
            | BinaryMarketSlot::ResolvedYesCollateral
            | BinaryMarketSlot::ResolvedNoCollateral
            | BinaryMarketSlot::ExpiredCollateral => live.collateral.as_ref(),
        }
        .ok_or(InterpretError::InvalidTrackedOutput(
            "missing input role output",
        ))?;
        let offset = u32::try_from(offset).map_err(|_| InterpretError::IndexOverflow)?;
        check_input(
            transaction,
            add_index(input_base, offset)?,
            tracked.outpoint,
        )?;
        spent.push(tracked.outpoint);
    }

    match layout.coordinator_role() {
        BinaryMarketCoordinatorRole::DormantYesRt => {
            if before
                != (BinaryMarketState::Trading {
                    outstanding_pairs: 0,
                })
            {
                return Err(InterpretError::Inconsistent("dormant input state"));
            }
            let yes = live
                .yes_rt
                .as_ref()
                .ok_or(InterpretError::InvalidTrackedOutput("missing YES RT"))?;
            let no = live
                .no_rt
                .as_ref()
                .ok_or(InterpretError::InvalidTrackedOutput("missing NO RT"))?;
            if yes.outpoint.txid != no.outpoint.txid {
                return Err(InterpretError::Inconsistent(
                    "dormant siblings have different txids",
                ));
            }
            if path != BinaryMarketPath::InitialIssuance
                && (transaction.input[input_base as usize].has_issuance()
                    || transaction.input[add_index(input_base, 1)? as usize].has_issuance())
            {
                return Err(InterpretError::Inconsistent(
                    "issuance on dormant terminal path",
                ));
            }
            Ok(spent)
        }
        BinaryMarketCoordinatorRole::UnresolvedYesRt => {
            if !matches!(before, BinaryMarketState::Trading { outstanding_pairs } if outstanding_pairs > 0)
            {
                return Err(InterpretError::Inconsistent("active input state"));
            }
            let yes = live
                .yes_rt
                .as_ref()
                .ok_or(InterpretError::InvalidTrackedOutput("missing YES RT"))?;
            let no = live
                .no_rt
                .as_ref()
                .ok_or(InterpretError::InvalidTrackedOutput("missing NO RT"))?;
            let collateral = live
                .collateral
                .as_ref()
                .ok_or(InterpretError::InvalidTrackedOutput("missing collateral"))?;
            if no.outpoint.txid != yes.outpoint.txid
                || collateral.outpoint.txid != yes.outpoint.txid
                || no.outpoint.vout
                    != yes
                        .outpoint
                        .vout
                        .checked_add(1)
                        .ok_or(InterpretError::Inconsistent("sibling vout overflow"))?
                || collateral.outpoint.vout
                    != yes
                        .outpoint
                        .vout
                        .checked_add(2)
                        .ok_or(InterpretError::Inconsistent("sibling vout overflow"))?
            {
                return Err(InterpretError::Inconsistent(
                    "unresolved siblings are not consecutive",
                ));
            }
            for index in [
                input_base,
                add_index(input_base, 1)?,
                add_index(input_base, 2)?,
            ] {
                if !matches!(path, BinaryMarketPath::SubsequentIssuance)
                    && transaction.input[index as usize].has_issuance()
                {
                    return Err(InterpretError::Inconsistent(
                        "issuance on non-issuance path",
                    ));
                }
            }
            if path == BinaryMarketPath::SubsequentIssuance
                && transaction.input[add_index(input_base, 2)? as usize].has_issuance()
            {
                return Err(InterpretError::Inconsistent(
                    "collateral input carries issuance",
                ));
            }
            Ok(spent)
        }
        BinaryMarketCoordinatorRole::ResolvedYesCollateral
        | BinaryMarketCoordinatorRole::ResolvedNoCollateral
        | BinaryMarketCoordinatorRole::ExpiredCollateral => {
            if transaction.input[input_base as usize].has_issuance() {
                return Err(InterpretError::Inconsistent("issuance on redemption"));
            }
            Ok(spent)
        }
    }
}

fn validate_live_outputs(
    compiled: &CompiledBinaryMarket,
    params: BinaryMarketParams,
    state: BinaryMarketState,
    live: &BinaryMarketLiveOutputs,
) -> Result<(), InterpretError> {
    let economics = BinaryMarketEconomics::new(params.base_payout)?;
    economics.validate_state(state)?;
    match state {
        BinaryMarketState::Trading {
            outstanding_pairs: 0,
        } => {
            check_live_slot(
                compiled,
                live.yes_rt.as_ref(),
                BinaryMarketSlot::DormantYesRt,
            )?;
            check_live_slot(compiled, live.no_rt.as_ref(), BinaryMarketSlot::DormantNoRt)?;
            check_confidential_rt(live.yes_rt.as_ref())?;
            check_confidential_rt(live.no_rt.as_ref())?;
            if live.collateral.is_some() {
                return Err(InterpretError::InvalidTrackedOutput(
                    "dormant market has collateral",
                ));
            }
        }
        BinaryMarketState::Trading { outstanding_pairs } => {
            check_live_slot(
                compiled,
                live.yes_rt.as_ref(),
                BinaryMarketSlot::UnresolvedYesRt,
            )?;
            check_live_slot(
                compiled,
                live.no_rt.as_ref(),
                BinaryMarketSlot::UnresolvedNoRt,
            )?;
            check_confidential_rt(live.yes_rt.as_ref())?;
            check_confidential_rt(live.no_rt.as_ref())?;
            check_live_slot(
                compiled,
                live.collateral.as_ref(),
                BinaryMarketSlot::UnresolvedCollateral,
            )?;
            let expected = economics.collateral_for_pairs(outstanding_pairs)?;
            check_explicit_live(
                live.collateral.as_ref(),
                params.collateral_asset_id,
                expected,
            )?;
        }
        BinaryMarketState::ResolvedYes {
            collateral_unredeemed,
        } => {
            if live.yes_rt.is_some() || live.no_rt.is_some() {
                return Err(InterpretError::InvalidTrackedOutput(
                    "resolved market still tracks RTs",
                ));
            }
            check_live_slot(
                compiled,
                live.collateral.as_ref(),
                BinaryMarketSlot::ResolvedYesCollateral,
            )?;
            check_explicit_live(
                live.collateral.as_ref(),
                params.collateral_asset_id,
                collateral_unredeemed,
            )?;
        }
        BinaryMarketState::ResolvedNo {
            collateral_unredeemed,
        } => {
            if live.yes_rt.is_some() || live.no_rt.is_some() {
                return Err(InterpretError::InvalidTrackedOutput(
                    "resolved market still tracks RTs",
                ));
            }
            check_live_slot(
                compiled,
                live.collateral.as_ref(),
                BinaryMarketSlot::ResolvedNoCollateral,
            )?;
            check_explicit_live(
                live.collateral.as_ref(),
                params.collateral_asset_id,
                collateral_unredeemed,
            )?;
        }
        BinaryMarketState::Expired {
            collateral_unredeemed,
        } => {
            if live.yes_rt.is_some() || live.no_rt.is_some() {
                return Err(InterpretError::InvalidTrackedOutput(
                    "expired market still tracks RTs",
                ));
            }
            check_live_slot(
                compiled,
                live.collateral.as_ref(),
                BinaryMarketSlot::ExpiredCollateral,
            )?;
            check_explicit_live(
                live.collateral.as_ref(),
                params.collateral_asset_id,
                collateral_unredeemed,
            )?;
        }
    }
    Ok(())
}

fn infer_live_rt_sides(
    params: BinaryMarketParams,
    state: BinaryMarketState,
    live: &BinaryMarketLiveOutputs,
) -> Result<BinaryMarketRtSides, InterpretError> {
    if !matches!(state, BinaryMarketState::Trading { .. }) {
        return Ok(BinaryMarketRtSides::default());
    }
    let yes = live
        .yes_rt
        .as_ref()
        .ok_or(InterpretError::InvalidTrackedOutput("missing YES RT"))?;
    let no = live
        .no_rt
        .as_ref()
        .ok_or(InterpretError::InvalidTrackedOutput("missing NO RT"))?;
    // The raw commitments are authoritative protocol state. In particular,
    // do not trust or recover a side from the spending witness.
    let yes_side = infer_side(
        RtLeg::Yes,
        params.yes_reissuance_token_id,
        yes.txout.asset,
        yes.txout.value,
    )
    .map_err(|_| {
        InterpretError::InvalidTrackedOutput("YES RT commitment is not a recognized A/B side")
    })?;
    let no_side = infer_side(
        RtLeg::No,
        params.no_reissuance_token_id,
        no.txout.asset,
        no.txout.value,
    )
    .map_err(|_| {
        InterpretError::InvalidTrackedOutput("NO RT commitment is not a recognized A/B side")
    })?;
    if yes_side != no_side {
        return Err(InterpretError::InvalidTrackedOutput(
            "YES and NO RT sides disagree",
        ));
    }
    Ok(BinaryMarketRtSides {
        yes: Some(yes_side),
        no: Some(no_side),
    })
}

fn opposite_side_factors(
    leg: RtLeg,
    live: Option<&TrackedContractOutput>,
    side: Option<RtSide>,
) -> Result<Option<RtFactors>, InterpretError> {
    match (live, side) {
        (Some(_), Some(side)) => Ok(Some(factors(leg, side.flip()))),
        (None, None) => Ok(None),
        _ => Err(InterpretError::InvalidTrackedOutput(
            "RT output and inferred side disagree",
        )),
    }
}

fn decode_market_witness(
    decoded: &DecodedSimplicityWitness,
    expected_slot: BinaryMarketSlot,
) -> Result<BinaryMarketCoordinatorAction, InterpretError> {
    decode_market_witness_values(decoded.values(), expected_slot)
}

fn decode_market_witness_values(
    values: &[SimplicityValue],
    expected_slot: BinaryMarketSlot,
) -> Result<BinaryMarketCoordinatorAction, InterpretError> {
    let slot_type = Final::u8();
    let action_types = market_action_types();
    let mut slot = None;
    let mut action = None;

    for value in values {
        if value.ty() == slot_type.as_ref() {
            if slot.replace(decode_u8(value.as_ref())?).is_some() {
                return Err(InterpretError::Inconsistent("duplicate SLOT witness"));
            }
        } else if action_types
            .iter()
            .any(|action_type| value.ty() == action_type.as_ref())
        {
            if action.replace(decode_market_action(value)?).is_some() {
                return Err(InterpretError::Inconsistent("duplicate ACTION witness"));
            }
        } else {
            return Err(InterpretError::Inconsistent(
                "unexpected binary-market witness value type",
            ));
        }
    }

    let slot = slot.ok_or(InterpretError::MissingWitness("SLOT"))?;
    if slot != expected_slot as u8 {
        return Err(InterpretError::Inconsistent(
            "SLOT does not match authenticated market slot",
        ));
    }
    action.ok_or(InterpretError::MissingWitness("ACTION"))
}

fn resolve_action_payload_type() -> std::sync::Arc<Final> {
    Final::product(Final::u32(), Final::product(Final::u1(), Final::u512()))
}

fn market_action_types() -> [std::sync::Arc<Final>; 5] {
    [
        Final::sum(Final::sum(Final::u32(), Final::unit()), Final::unit()),
        Final::sum(Final::sum(Final::unit(), Final::u32()), Final::unit()),
        Final::sum(
            Final::unit(),
            Final::sum(resolve_action_payload_type(), Final::unit()),
        ),
        Final::sum(
            Final::unit(),
            Final::sum(Final::unit(), Final::sum(Final::u32(), Final::unit())),
        ),
        Final::sum(
            Final::unit(),
            Final::sum(Final::unit(), Final::sum(Final::unit(), Final::u32())),
        ),
    ]
}

fn decode_market_action(
    value: &SimplicityValue,
) -> Result<BinaryMarketCoordinatorAction, InterpretError> {
    if !market_action_types()
        .iter()
        .any(|action_type| value.ty() == action_type.as_ref())
    {
        return Err(InterpretError::Inconsistent(
            "ACTION has the wrong structural type",
        ));
    }

    let root = value.as_ref();
    if let Some(issue_or_cancel) = root.as_left() {
        if let Some(issue) = issue_or_cancel.as_left() {
            return Ok(BinaryMarketCoordinatorAction::Issue {
                output_base: decode_u32(issue)?,
            });
        }
        let cancel = issue_or_cancel
            .as_right()
            .ok_or(InterpretError::Inconsistent("malformed ACTION sum branch"))?;
        return Ok(BinaryMarketCoordinatorAction::Cancel {
            output_base: decode_u32(cancel)?,
        });
    }

    let resolve_or_terminal = root
        .as_right()
        .ok_or(InterpretError::Inconsistent("malformed ACTION sum branch"))?;
    if let Some(resolve) = resolve_or_terminal.as_left() {
        let (output_base, outcome_and_signature) = resolve.as_product().ok_or(
            InterpretError::Inconsistent("malformed Resolve ACTION payload"),
        )?;
        let (outcome_yes, signature) =
            outcome_and_signature
                .as_product()
                .ok_or(InterpretError::Inconsistent(
                    "malformed Resolve ACTION payload",
                ))?;
        let outcome = if decode_bool(outcome_yes)? {
            BinaryOutcome::Yes
        } else {
            BinaryOutcome::No
        };
        return Ok(BinaryMarketCoordinatorAction::Resolve {
            output_base: decode_u32(output_base)?,
            resolution: BinaryMarketResolution::new(outcome, decode_signature(signature)?),
        });
    }

    let expire_or_redeem = resolve_or_terminal
        .as_right()
        .ok_or(InterpretError::Inconsistent("malformed ACTION sum branch"))?;
    if let Some(expire) = expire_or_redeem.as_left() {
        return Ok(BinaryMarketCoordinatorAction::Expire {
            output_base: decode_u32(expire)?,
        });
    }
    let redeem = expire_or_redeem
        .as_right()
        .ok_or(InterpretError::Inconsistent("malformed ACTION sum branch"))?;
    Ok(BinaryMarketCoordinatorAction::Redeem {
        output_base: decode_u32(redeem)?,
    })
}

fn decode_u8(value: ValueRef<'_>) -> Result<u8, InterpretError> {
    word_bytes(value)
        .map(u8::from_be_bytes)
        .ok_or(InterpretError::Inconsistent("malformed u8 witness value"))
}

fn decode_u32(value: ValueRef<'_>) -> Result<u32, InterpretError> {
    word_bytes(value)
        .map(u32::from_be_bytes)
        .ok_or(InterpretError::Inconsistent("malformed u32 witness value"))
}

fn decode_bool(value: ValueRef<'_>) -> Result<bool, InterpretError> {
    let word = value
        .to_word()
        .filter(|word| word.n() == 0)
        .ok_or(InterpretError::Inconsistent("malformed bool witness value"))?;
    word.iter()
        .next()
        .ok_or(InterpretError::Inconsistent("malformed bool witness value"))
}

fn decode_signature(value: ValueRef<'_>) -> Result<[u8; 64], InterpretError> {
    word_bytes(value).ok_or(InterpretError::Inconsistent(
        "malformed Signature witness value",
    ))
}

fn word_bytes<const N: usize>(value: ValueRef<'_>) -> Option<[u8; N]> {
    let word = value.to_word()?;
    if word.len() != N.checked_mul(8)? {
        return None;
    }
    let mut output = [0_u8; N];
    for (index, bit) in word.iter().enumerate() {
        if bit {
            output[index / 8] |= 1 << (7 - index % 8);
        }
    }
    Some(output)
}

fn cancellation_is_full(
    params: BinaryMarketParams,
    transaction: &Transaction,
    output_base: u32,
) -> Result<bool, InterpretError> {
    let discriminator_index = add_index(output_base, 2)?;
    let discriminator = output_at(transaction, discriminator_index)?;
    let Some((asset, _)) = explicit_asset_value(discriminator) else {
        return Err(InterpretError::Inconsistent(
            "cancellation discriminator output not explicit",
        ));
    };
    if asset == params.collateral_asset_id {
        Ok(false)
    } else {
        token_burn_amount(transaction, discriminator_index, params.yes_token_asset_id)?;
        Ok(true)
    }
}

fn redemption_details(
    params: BinaryMarketParams,
    before: BinaryMarketState,
    transaction: &Transaction,
    output_base: u32,
) -> Result<(bool, u64), InterpretError> {
    let first_output = output_at(transaction, output_base)?;
    let Some((first_asset, _)) = explicit_asset_value(first_output) else {
        return Err(InterpretError::Inconsistent(
            "redemption discriminator output not explicit",
        ));
    };
    let burn_index = if first_asset == params.collateral_asset_id {
        add_index(output_base, 1)?
    } else {
        output_base
    };

    let outcome_yes = match before {
        BinaryMarketState::ResolvedYes { .. } => true,
        BinaryMarketState::ResolvedNo { .. } => false,
        BinaryMarketState::Expired { .. } => {
            let burn = output_at(transaction, burn_index)?;
            let Some((asset, _)) = explicit_asset_value(burn) else {
                return Err(InterpretError::Inconsistent("redemption burn not explicit"));
            };
            if asset == params.yes_token_asset_id {
                true
            } else if asset == params.no_token_asset_id {
                false
            } else {
                return Err(InterpretError::Inconsistent(
                    "redemption burn has unknown token asset",
                ));
            }
        }
        BinaryMarketState::Trading { .. } => {
            return Err(InterpretError::Inconsistent("redemption phase"));
        }
    };
    let burn_asset = if outcome_yes {
        params.yes_token_asset_id
    } else {
        params.no_token_asset_id
    };
    let tokens = token_burn_amount(transaction, burn_index, burn_asset)?;
    Ok((outcome_yes, tokens))
}

fn verify_oracle_signature(params: BinaryMarketParams, outcome_yes: bool, bytes: &[u8]) -> bool {
    let Ok(key) = XOnlyPublicKey::from_slice(&params.oracle_public_key) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(bytes) else {
        return false;
    };
    let outcome = if outcome_yes {
        OracleOutcome::Yes
    } else {
        OracleOutcome::No
    };
    let message = Message::from_digest(oracle_message(
        params.yes_token_asset_id,
        params.no_token_asset_id,
        outcome,
    ));
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &message, &key)
        .is_ok()
}

fn issuance_amount(
    transaction: &Transaction,
    index: u32,
    expected_asset: AssetId,
    expected_rt: AssetId,
    expected_nonce_abf: [u8; 32],
) -> Result<u64, InterpretError> {
    let input = transaction
        .input
        .get(index as usize)
        .ok_or(InterpretError::Inconsistent("issuance input index"))?;
    let expected_nonce = Tweak::from_inner(expected_nonce_abf)
        .map_err(|_| InterpretError::Inconsistent("invalid public RT nonce factor"))?;
    if !input.has_issuance()
        || input.issuance_ids() != (expected_asset, expected_rt)
        || !input.asset_issuance.inflation_keys.is_null()
        || input.asset_issuance.asset_blinding_nonce != expected_nonce
    {
        return Err(InterpretError::Inconsistent("issuance identity"));
    }
    let Value::Explicit(amount) = input.asset_issuance.amount else {
        return Err(InterpretError::Inconsistent(
            "issuance amount is not explicit",
        ));
    };
    Ok(amount)
}

fn check_expiry_lock(transaction: &Transaction, expiry: u32) -> Result<(), InterpretError> {
    let locktime = transaction.lock_time;
    // Elements' `check_lock_height` jet activates the transaction-wide
    // nLockTime when any input is non-final. Do not narrow this to the market
    // coordinator: a follower or unrelated wallet input may legally activate
    // the shared lock.
    let has_nonfinal_input = transaction
        .input
        .iter()
        .any(|input| !input.sequence.is_final());
    if !locktime.is_block_height() || locktime.to_consensus_u32() < expiry || !has_nonfinal_input {
        return Err(InterpretError::Inconsistent("expiry locktime"));
    }
    Ok(())
}

fn check_input(
    transaction: &Transaction,
    index: u32,
    expected: OutPoint,
) -> Result<(), InterpretError> {
    if transaction
        .input
        .get(index as usize)
        .map(|input| input.previous_output)
        != Some(expected)
    {
        return Err(InterpretError::Inconsistent("input window"));
    }
    Ok(())
}

fn check_live_slot(
    compiled: &CompiledBinaryMarket,
    output: Option<&TrackedContractOutput>,
    slot: BinaryMarketSlot,
) -> Result<(), InterpretError> {
    let output = output.ok_or(InterpretError::InvalidTrackedOutput("missing slot output"))?;
    if output.txout.script_pubkey != *compiled.slot(slot).script_pubkey() {
        return Err(InterpretError::InvalidTrackedOutput("slot script mismatch"));
    }
    Ok(())
}

fn check_explicit_live(
    output: Option<&TrackedContractOutput>,
    asset: AssetId,
    amount: u64,
) -> Result<(), InterpretError> {
    let output = output.ok_or(InterpretError::InvalidTrackedOutput(
        "missing explicit output",
    ))?;
    if explicit_asset_value(&output.txout) != Some((asset, amount)) {
        return Err(InterpretError::InvalidTrackedOutput(
            "explicit asset/value mismatch",
        ));
    }
    Ok(())
}

fn check_confidential_rt(output: Option<&TrackedContractOutput>) -> Result<(), InterpretError> {
    let output = output.ok_or(InterpretError::InvalidTrackedOutput("missing RT output"))?;
    if !matches!(output.txout.asset, Asset::Confidential(_))
        || !matches!(output.txout.value, Value::Confidential(_))
    {
        return Err(InterpretError::InvalidTrackedOutput(
            "RT output is not confidential",
        ));
    }
    Ok(())
}

fn push_rt_continuation(
    output: &mut Vec<BinaryMarketContinuation>,
    compiled: &CompiledBinaryMarket,
    transaction: &Transaction,
    index: u32,
    slot: BinaryMarketSlot,
    asset_id: AssetId,
    factors: RtFactors,
) -> Result<(), InterpretError> {
    let txout = output_at(transaction, index)?;
    let expected = commitments(asset_id, factors)
        .map_err(|_| InterpretError::Inconsistent("invalid RT continuation factors"))?;
    if txout.script_pubkey != *compiled.slot(slot).script_pubkey()
        || (txout.asset, txout.value) != expected
    {
        return Err(InterpretError::Inconsistent("RT continuation"));
    }
    output.push(continuation(transaction, index, slot, txout));
    Ok(())
}

fn push_collateral_continuation(
    output: &mut Vec<BinaryMarketContinuation>,
    compiled: &CompiledBinaryMarket,
    transaction: &Transaction,
    index: u32,
    slot: BinaryMarketSlot,
    asset: AssetId,
    amount: u64,
) -> Result<(), InterpretError> {
    let txout = output_at(transaction, index)?;
    if txout.script_pubkey != *compiled.slot(slot).script_pubkey()
        || explicit_asset_value(txout) != Some((asset, amount))
    {
        return Err(InterpretError::Inconsistent("collateral continuation"));
    }
    output.push(continuation(transaction, index, slot, txout));
    Ok(())
}

fn continuation(
    transaction: &Transaction,
    index: u32,
    slot: BinaryMarketSlot,
    txout: &TxOut,
) -> BinaryMarketContinuation {
    BinaryMarketContinuation {
        slot,
        output: TrackedContractOutput {
            outpoint: OutPoint::new(transaction.txid(), index),
            txout: txout.clone(),
        },
    }
}

fn check_rt_burn(
    transaction: &Transaction,
    index: u32,
    asset_id: AssetId,
    expected_factors: RtFactors,
) -> Result<(), InterpretError> {
    let output = output_at(transaction, index)?;
    let expected = commitments(asset_id, expected_factors)
        .map_err(|_| InterpretError::Inconsistent("invalid RT burn factors"))?;
    if output.script_pubkey.as_bytes() != [0x6a] || (output.asset, output.value) != expected {
        return Err(InterpretError::Inconsistent("RT burn"));
    }
    Ok(())
}

fn token_burn_amount(
    transaction: &Transaction,
    index: u32,
    asset: AssetId,
) -> Result<u64, InterpretError> {
    let output = output_at(transaction, index)?;
    let Some((actual, amount)) = explicit_asset_value(output) else {
        return Err(InterpretError::Inconsistent("token burn not explicit"));
    };
    if actual != asset || amount == 0 || output.script_pubkey.as_bytes() != [0x6a] {
        return Err(InterpretError::Inconsistent("token burn"));
    }
    Ok(amount)
}

fn check_token_burn(
    transaction: &Transaction,
    index: u32,
    asset: AssetId,
    amount: u64,
) -> Result<(), InterpretError> {
    if token_burn_amount(transaction, index, asset)? != amount {
        return Err(InterpretError::Inconsistent("token burn amount"));
    }
    Ok(())
}

fn explicit_asset_value(output: &TxOut) -> Option<(AssetId, u64)> {
    let Asset::Explicit(asset) = output.asset else {
        return None;
    };
    let Value::Explicit(value) = output.value else {
        return None;
    };
    Some((asset, value))
}

fn trading_collateral(
    state: BinaryMarketState,
    params: BinaryMarketParams,
) -> Result<u64, InterpretError> {
    let BinaryMarketState::Trading { outstanding_pairs } = state else {
        return Err(InterpretError::Inconsistent("expected trading state"));
    };
    Ok(BinaryMarketEconomics::new(params.base_payout)?.collateral_for_pairs(outstanding_pairs)?)
}

fn terminal_slot_amount(
    state: BinaryMarketState,
) -> Result<(BinaryMarketSlot, u64), InterpretError> {
    terminal_collateral(state).ok_or(InterpretError::Inconsistent("expected terminal collateral"))
}

fn terminal_collateral(state: BinaryMarketState) -> Option<(BinaryMarketSlot, u64)> {
    match state {
        BinaryMarketState::ResolvedYes {
            collateral_unredeemed,
        } => Some((
            BinaryMarketSlot::ResolvedYesCollateral,
            collateral_unredeemed,
        )),
        BinaryMarketState::ResolvedNo {
            collateral_unredeemed,
        } => Some((
            BinaryMarketSlot::ResolvedNoCollateral,
            collateral_unredeemed,
        )),
        BinaryMarketState::Expired {
            collateral_unredeemed,
        } => Some((BinaryMarketSlot::ExpiredCollateral, collateral_unredeemed)),
        BinaryMarketState::Trading { .. } => None,
    }
}

fn action_outcome(transition: BinaryMarketTransition) -> Result<BinaryOutcome, InterpretError> {
    match transition {
        BinaryMarketTransition::Redeemed { outcome, .. } => Ok(outcome),
        _ => Err(InterpretError::Inconsistent(
            "expected redemption transition",
        )),
    }
}

fn add_index(index: u32, offset: u32) -> Result<u32, InterpretError> {
    index
        .checked_add(offset)
        .ok_or(InterpretError::IndexOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_action(action: BinaryMarketCoordinatorAction) -> SimplicityValue {
        match action {
            BinaryMarketCoordinatorAction::Issue { output_base } => SimplicityValue::left(
                SimplicityValue::left(SimplicityValue::u32(output_base), Final::unit()),
                Final::unit(),
            ),
            BinaryMarketCoordinatorAction::Cancel { output_base } => SimplicityValue::left(
                SimplicityValue::right(Final::unit(), SimplicityValue::u32(output_base)),
                Final::unit(),
            ),
            BinaryMarketCoordinatorAction::Resolve {
                output_base,
                resolution,
            } => {
                let outcome = u8::from(resolution.outcome() == BinaryOutcome::Yes);
                let payload = SimplicityValue::product(
                    SimplicityValue::u32(output_base),
                    SimplicityValue::product(
                        SimplicityValue::u1(outcome),
                        SimplicityValue::u512(resolution.signature()),
                    ),
                );
                SimplicityValue::right(Final::unit(), SimplicityValue::left(payload, Final::unit()))
            }
            BinaryMarketCoordinatorAction::Expire { output_base } => SimplicityValue::right(
                Final::unit(),
                SimplicityValue::right(
                    Final::unit(),
                    SimplicityValue::left(SimplicityValue::u32(output_base), Final::unit()),
                ),
            ),
            BinaryMarketCoordinatorAction::Redeem { output_base } => SimplicityValue::right(
                Final::unit(),
                SimplicityValue::right(
                    Final::unit(),
                    SimplicityValue::right(Final::unit(), SimplicityValue::u32(output_base)),
                ),
            ),
        }
    }

    #[test]
    fn exact_action_decoder_accepts_all_five_finalized_sum_branches() {
        let signature = [0xa5; 64];
        let actions = [
            BinaryMarketCoordinatorAction::Issue { output_base: 11 },
            BinaryMarketCoordinatorAction::Cancel { output_base: 12 },
            BinaryMarketCoordinatorAction::Resolve {
                output_base: 13,
                resolution: BinaryMarketResolution::new(BinaryOutcome::Yes, signature),
            },
            BinaryMarketCoordinatorAction::Expire { output_base: 14 },
            BinaryMarketCoordinatorAction::Redeem { output_base: 15 },
        ];

        for action in actions {
            assert_eq!(
                decode_market_action(&encode_action(action)).unwrap(),
                action
            );
        }
    }

    #[test]
    fn exact_witness_decoder_requires_one_slot_and_one_action() {
        let action = BinaryMarketCoordinatorAction::Expire { output_base: 7 };
        let valid = [
            SimplicityValue::u8(BinaryMarketSlot::DormantYesRt.tag()),
            encode_action(action),
        ];
        assert_eq!(
            decode_market_witness_values(&valid, BinaryMarketSlot::DormantYesRt).unwrap(),
            action
        );

        assert!(matches!(
            decode_market_witness_values(&valid[..1], BinaryMarketSlot::DormantYesRt),
            Err(InterpretError::MissingWitness("ACTION"))
        ));
        assert!(matches!(
            decode_market_witness_values(&valid[1..], BinaryMarketSlot::DormantYesRt),
            Err(InterpretError::MissingWitness("SLOT"))
        ));
        assert!(matches!(
            decode_market_witness_values(&valid, BinaryMarketSlot::UnresolvedYesRt),
            Err(InterpretError::Inconsistent(_))
        ));

        let duplicate_slot = [
            SimplicityValue::u8(BinaryMarketSlot::DormantYesRt.tag()),
            SimplicityValue::u8(BinaryMarketSlot::DormantYesRt.tag()),
            encode_action(action),
        ];
        assert!(matches!(
            decode_market_witness_values(&duplicate_slot, BinaryMarketSlot::DormantYesRt),
            Err(InterpretError::Inconsistent("duplicate SLOT witness"))
        ));

        let duplicate_action = [
            SimplicityValue::u8(BinaryMarketSlot::DormantYesRt.tag()),
            encode_action(action),
            encode_action(action),
        ];
        assert!(matches!(
            decode_market_witness_values(&duplicate_action, BinaryMarketSlot::DormantYesRt),
            Err(InterpretError::Inconsistent("duplicate ACTION witness"))
        ));
    }

    #[test]
    fn exact_action_decoder_rejects_near_miss_structural_types() {
        let left_associated_resolve = SimplicityValue::product(
            SimplicityValue::product(SimplicityValue::u32(3), SimplicityValue::u1(1)),
            SimplicityValue::u512([0x42; 64]),
        );
        let malformed = SimplicityValue::right(
            Final::unit(),
            SimplicityValue::left(left_associated_resolve, Final::unit()),
        );
        assert!(matches!(
            decode_market_action(&malformed),
            Err(InterpretError::Inconsistent(
                "ACTION has the wrong structural type"
            ))
        ));

        let unpruned_source_action = SimplicityValue::left(
            SimplicityValue::left(SimplicityValue::u32(3), Final::u32()),
            Final::sum(
                resolve_action_payload_type(),
                Final::sum(Final::u32(), Final::u32()),
            ),
        );
        assert!(matches!(
            decode_market_action(&unpruned_source_action),
            Err(InterpretError::Inconsistent(
                "ACTION has the wrong structural type"
            ))
        ));

        let unexpected_leaf = [
            SimplicityValue::u8(BinaryMarketSlot::DormantYesRt.tag()),
            SimplicityValue::u32(3),
        ];
        assert!(matches!(
            decode_market_witness_values(&unexpected_leaf, BinaryMarketSlot::DormantYesRt),
            Err(InterpretError::Inconsistent(
                "unexpected binary-market witness value type"
            ))
        ));
    }
}

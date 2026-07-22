use deadcat_types::{BinaryMarketParams, BinaryMarketState};
use elements::confidential::{Asset, Value};
use elements::secp256k1_zkp::{Message, Secp256k1, Tweak, XOnlyPublicKey, schnorr::Signature};
use elements::{AssetId, OutPoint, Transaction, TxOut};

use super::{
    DecodedSimplicityWitness, InterpretError, TrackedContractOutput, decode_simplicity_witness,
    locate_input, output_at, strip_taproot_annex,
};
use crate::binary_market::{
    AppliedBinaryMarketTransition, BinaryMarketAction, BinaryMarketEconomics, BinaryMarketSlot,
    CompiledBinaryMarket,
};
use crate::binary_market::{BinaryMarketTransition, BinaryOutcome};
use crate::market_crypto::{BinaryOutcome as OracleOutcome, oracle_message};
use crate::rt::{RtFactors, RtLeg, RtSide, commitments, factors, infer_side};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BinaryMarketPath {
    InitialIssuance = 0,
    SubsequentIssuance = 1,
    PartialCancellation = 2,
    FullCancellation = 3,
    ActiveResolution = 4,
    DormantResolution = 5,
    ActiveExpiry = 6,
    DormantExpiry = 7,
    ResolvedRedemption = 8,
    ExpiryRedemption = 9,
}

impl BinaryMarketPath {
    fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            0 => Self::InitialIssuance,
            1 => Self::SubsequentIssuance,
            2 => Self::PartialCancellation,
            3 => Self::FullCancellation,
            4 => Self::ActiveResolution,
            5 => Self::DormantResolution,
            6 => Self::ActiveExpiry,
            7 => Self::DormantExpiry,
            8 => Self::ResolvedRedemption,
            9 => Self::ExpiryRedemption,
            _ => return None,
        })
    }
}

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
    validate_live_outputs(&compiled, params, before, live)?;
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
    let (core_stack, _) = strip_taproot_annex(stack);
    if core_stack.len() == 1 {
        return Err(InterpretError::UnexpectedKeySpend);
    }
    let decoded = decode_simplicity_witness(stack)?;
    if decoded.cmr() != compiled.cmr() {
        return Err(InterpretError::CmrMismatch);
    }
    let expected_slot = primary_slot(before);
    if decoded.control_block() != compiled.slot(expected_slot).control_block().serialize() {
        return Err(InterpretError::Inconsistent(
            "market control block mismatch",
        ));
    }
    if !decoded.u8_values().contains(&(expected_slot as u8)) {
        return Err(InterpretError::MissingWitness("SLOT"));
    }
    let live_rt_sides = infer_live_rt_sides(params, before, live)?;

    let u8_values = decoded.u8_values();
    let paths: Vec<BinaryMarketPath> = u8_values
        .iter()
        .copied()
        .filter_map(BinaryMarketPath::from_tag)
        .filter(|path| path_allowed(*path, before))
        .filter(|path| {
            u8_values
                .iter()
                .all(|value| *value == expected_slot as u8 || *value == *path as u8)
        })
        .collect();
    if paths.is_empty() {
        return Err(InterpretError::MissingWitness("PATH"));
    }
    let u32_values = decoded.u32_values();
    let output_bases: Vec<u32> = u32_values
        .iter()
        .copied()
        .filter(|candidate| {
            u32_values
                .iter()
                .all(|value| *value == input_base || *value == *candidate)
        })
        .collect();
    if output_bases.is_empty() {
        return Err(InterpretError::MissingWitness("OUTPUT_BASE"));
    }

    let economics = BinaryMarketEconomics::new(params.base_payout)?;
    let mut interpretations = Vec::new();
    for path in paths {
        let outcomes = candidate_outcomes(path, params, &decoded, transaction)?;
        let token_amounts = if matches!(
            path,
            BinaryMarketPath::ResolvedRedemption | BinaryMarketPath::ExpiryRedemption
        ) {
            decoded.u64_values()
        } else {
            vec![0]
        };
        for output_base in output_bases.iter().copied() {
            for outcome_yes in outcomes.iter().copied() {
                for tokens in token_amounts.iter().copied() {
                    if let Ok(interpretation) = interpret_candidate(
                        params,
                        economics,
                        &compiled,
                        before,
                        live,
                        live_rt_sides,
                        transaction,
                        path,
                        input_base,
                        output_base,
                        outcome_yes,
                        tokens,
                    ) && !interpretations.contains(&interpretation)
                    {
                        interpretations.push(interpretation);
                    }
                }
            }
        }
    }
    match interpretations.len() {
        0 => Err(InterpretError::Inconsistent(
            "no decoded market path matches the transaction",
        )),
        1 => Ok(interpretations.pop().expect("one interpretation")),
        _ => Err(InterpretError::AmbiguousInterpretation),
    }
}

#[allow(clippy::too_many_arguments)]
fn interpret_candidate(
    params: BinaryMarketParams,
    economics: BinaryMarketEconomics,
    compiled: &CompiledBinaryMarket,
    before: BinaryMarketState,
    live: &BinaryMarketLiveOutputs,
    live_rt_sides: BinaryMarketRtSides,
    transaction: &Transaction,
    path: BinaryMarketPath,
    input_base: u32,
    output_base: u32,
    outcome_yes: bool,
    tokens: u64,
) -> Result<BinaryMarketInterpretation, InterpretError> {
    let spent = verify_input_group(path, before, live, transaction, input_base)?;
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
            check_expiry_lock(transaction, input_base, params.expiry_height)?;
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
        path,
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
    path: BinaryMarketPath,
    before: BinaryMarketState,
    live: &BinaryMarketLiveOutputs,
    live_rt_sides: BinaryMarketRtSides,
    applied: AppliedBinaryMarketTransition,
    output_base: u32,
    tokens: u64,
) -> Result<Vec<BinaryMarketContinuation>, InterpretError> {
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
    path: BinaryMarketPath,
    before: BinaryMarketState,
    live: &BinaryMarketLiveOutputs,
    transaction: &Transaction,
    input_base: u32,
) -> Result<Vec<OutPoint>, InterpretError> {
    match path {
        BinaryMarketPath::InitialIssuance
        | BinaryMarketPath::DormantResolution
        | BinaryMarketPath::DormantExpiry => {
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
            check_input(transaction, input_base, yes.outpoint)?;
            check_input(transaction, add_index(input_base, 1)?, no.outpoint)?;
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
            Ok(vec![yes.outpoint, no.outpoint])
        }
        BinaryMarketPath::SubsequentIssuance
        | BinaryMarketPath::PartialCancellation
        | BinaryMarketPath::FullCancellation
        | BinaryMarketPath::ActiveResolution
        | BinaryMarketPath::ActiveExpiry => {
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
            check_input(transaction, input_base, yes.outpoint)?;
            check_input(transaction, add_index(input_base, 1)?, no.outpoint)?;
            check_input(transaction, add_index(input_base, 2)?, collateral.outpoint)?;
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
            Ok(vec![yes.outpoint, no.outpoint, collateral.outpoint])
        }
        BinaryMarketPath::ResolvedRedemption | BinaryMarketPath::ExpiryRedemption => {
            let collateral = live
                .collateral
                .as_ref()
                .ok_or(InterpretError::InvalidTrackedOutput("missing collateral"))?;
            check_input(transaction, input_base, collateral.outpoint)?;
            if transaction.input[input_base as usize].has_issuance() {
                return Err(InterpretError::Inconsistent("issuance on redemption"));
            }
            Ok(vec![collateral.outpoint])
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

fn candidate_outcomes(
    path: BinaryMarketPath,
    params: BinaryMarketParams,
    decoded: &DecodedSimplicityWitness,
    transaction: &Transaction,
) -> Result<Vec<bool>, InterpretError> {
    match path {
        BinaryMarketPath::ActiveResolution | BinaryMarketPath::DormantResolution => {
            let mut output = Vec::new();
            for outcome in decoded.bool_values() {
                if decoded
                    .bytes_values(64)
                    .iter()
                    .any(|signature| verify_oracle_signature(params, outcome, signature))
                {
                    output.push(outcome);
                }
            }
            Ok(output)
        }
        BinaryMarketPath::ExpiryRedemption => Ok(decoded.bool_values()),
        BinaryMarketPath::ActiveExpiry | BinaryMarketPath::DormantExpiry => {
            if transaction.lock_time.to_consensus_u32() < params.expiry_height {
                Ok(Vec::new())
            } else {
                Ok(vec![false])
            }
        }
        _ => Ok(vec![false]),
    }
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

fn path_allowed(path: BinaryMarketPath, state: BinaryMarketState) -> bool {
    match state {
        BinaryMarketState::Trading {
            outstanding_pairs: 0,
        } => matches!(
            path,
            BinaryMarketPath::InitialIssuance
                | BinaryMarketPath::DormantResolution
                | BinaryMarketPath::DormantExpiry
        ),
        BinaryMarketState::Trading { .. } => matches!(
            path,
            BinaryMarketPath::SubsequentIssuance
                | BinaryMarketPath::PartialCancellation
                | BinaryMarketPath::FullCancellation
                | BinaryMarketPath::ActiveResolution
                | BinaryMarketPath::ActiveExpiry
        ),
        BinaryMarketState::ResolvedYes { .. } | BinaryMarketState::ResolvedNo { .. } => {
            path == BinaryMarketPath::ResolvedRedemption
        }
        BinaryMarketState::Expired { .. } => path == BinaryMarketPath::ExpiryRedemption,
    }
}

fn primary_slot(state: BinaryMarketState) -> BinaryMarketSlot {
    match state {
        BinaryMarketState::Trading {
            outstanding_pairs: 0,
        } => BinaryMarketSlot::DormantYesRt,
        BinaryMarketState::Trading { .. } => BinaryMarketSlot::UnresolvedYesRt,
        BinaryMarketState::ResolvedYes { .. } => BinaryMarketSlot::ResolvedYesCollateral,
        BinaryMarketState::ResolvedNo { .. } => BinaryMarketSlot::ResolvedNoCollateral,
        BinaryMarketState::Expired { .. } => BinaryMarketSlot::ExpiredCollateral,
    }
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

fn check_expiry_lock(
    transaction: &Transaction,
    input_index: u32,
    expiry: u32,
) -> Result<(), InterpretError> {
    let input = transaction
        .input
        .get(input_index as usize)
        .ok_or(InterpretError::Inconsistent("expiry input index"))?;
    if transaction.lock_time.to_consensus_u32() < expiry || input.sequence.is_final() {
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

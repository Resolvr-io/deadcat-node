use deadcat_types::{MakerOrderParams, MakerOrderState, OrderDirection};
use elements::confidential::{Asset, Value};
use elements::{OutPoint, Transaction};

use super::{
    InterpretError, TrackedContractOutput, decode_simplicity_witness, locate_input, output_at,
    strip_taproot_annex,
};
use crate::maker_order::{CompiledMakerOrder, MakerOrderFill, cancel, fill};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MakerOrderSpendKind {
    Fill(MakerOrderFill),
    Cancel,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MakerOrderInterpretation {
    pub kind: MakerOrderSpendKind,
    pub before: MakerOrderState,
    pub after: MakerOrderState,
    pub spent_outpoint: OutPoint,
    pub input_index: u32,
    pub payment_index: Option<u32>,
    pub remainder_index: Option<u32>,
    pub continuation: Option<TrackedContractOutput>,
    pub annex_present: bool,
}

pub fn interpret_maker_order_spend(
    params: MakerOrderParams,
    before: MakerOrderState,
    live_output: &TrackedContractOutput,
    transaction: &Transaction,
) -> Result<MakerOrderInterpretation, InterpretError> {
    let compiled = CompiledMakerOrder::new(params)?;
    if live_output.txout.script_pubkey != *compiled.script_pubkey() {
        return Err(InterpretError::InvalidTrackedOutput(
            "maker script does not match compiled parameters",
        ));
    }
    let input_index = locate_input(transaction, live_output.outpoint)?;
    let input_index_u32 = u32::try_from(input_index).map_err(|_| InterpretError::IndexOverflow)?;
    let (input_asset, input_locked) = explicit_asset_value(&live_output.txout).ok_or(
        InterpretError::InvalidTrackedOutput("maker input is not explicit"),
    )?;
    let expected_input_asset = match params.direction {
        OrderDirection::SellBase => params.base_asset_id,
        OrderDirection::SellQuote => params.quote_asset_id,
    };
    if input_asset != expected_input_asset {
        return Err(InterpretError::InvalidTrackedOutput(
            "maker input asset is wrong",
        ));
    }
    let MakerOrderState::Active { remaining_base, .. } = before else {
        return Err(InterpretError::InvalidTrackedOutput(
            "terminal maker order still has a live output",
        ));
    };
    let expected_locked = match params.direction {
        OrderDirection::SellBase => remaining_base,
        OrderDirection::SellQuote => remaining_base
            .checked_mul(u64::from(params.price))
            .ok_or(crate::maker_order::MakerOrderError::ArithmeticOverflow)?,
    };
    if input_locked != expected_locked {
        return Err(InterpretError::InvalidTrackedOutput(
            "maker input amount disagrees with state",
        ));
    }

    let stack = &transaction.input[input_index].witness.script_witness;
    let (core_stack, annex) = strip_taproot_annex(stack);
    if core_stack.len() == 1 {
        if !matches!(core_stack[0].len(), 64 | 65) {
            return Err(InterpretError::BadWitnessStack {
                len: core_stack.len(),
            });
        }
        let after = cancel(before)?;
        return Ok(MakerOrderInterpretation {
            kind: MakerOrderSpendKind::Cancel,
            before,
            after,
            spent_outpoint: live_output.outpoint,
            input_index: input_index_u32,
            payment_index: None,
            remainder_index: None,
            continuation: None,
            annex_present: annex.is_some(),
        });
    }

    let decoded = decode_simplicity_witness(stack)?;
    if decoded.cmr() != compiled.cmr() {
        return Err(InterpretError::CmrMismatch);
    }
    if decoded.control_block() != compiled.control_block().serialize() {
        return Err(InterpretError::Inconsistent("maker control block mismatch"));
    }
    if transaction.input[input_index].has_issuance() {
        return Err(InterpretError::Inconsistent(
            "maker script spend carries issuance",
        ));
    }
    let partial_flags = decoded.bool_values();
    if partial_flags.len() != 1 {
        return Err(if partial_flags.is_empty() {
            InterpretError::MissingWitness("IS_PARTIAL")
        } else {
            InterpretError::AmbiguousInterpretation
        });
    }
    let is_partial = partial_flags[0];
    let indices = decoded.u32_values();
    if indices.len() != 2 {
        return Err(if indices.is_empty() {
            InterpretError::MissingWitness("PAYMENT_INDEX and REMAINDER_INDEX")
        } else {
            InterpretError::AmbiguousInterpretation
        });
    }
    let payment_index = indices[0];
    let remainder_index_witness = indices[1];
    if payment_index == remainder_index_witness {
        return Err(InterpretError::Inconsistent(
            "maker output witness indices alias",
        ));
    }
    let payment_output = output_at(transaction, payment_index)?;
    let (payment_asset, maker_payment) = explicit_asset_value(payment_output).ok_or(
        InterpretError::Inconsistent("maker payment is not explicit"),
    )?;
    let expected_payment_asset = match params.direction {
        OrderDirection::SellBase => params.quote_asset_id,
        OrderDirection::SellQuote => params.base_asset_id,
    };
    if payment_asset != expected_payment_asset
        || payment_output.script_pubkey != *compiled.maker_receive_spk()
    {
        return Err(InterpretError::Inconsistent(
            "maker payment asset or destination is wrong",
        ));
    }

    let remainder_locked = if !is_partial {
        None
    } else {
        let remainder_output = output_at(transaction, remainder_index_witness)?;
        if remainder_output.script_pubkey != *compiled.script_pubkey() {
            return Err(InterpretError::Inconsistent(
                "witness-designated remainder script is wrong",
            ));
        }
        let (asset, amount) = explicit_asset_value(remainder_output).ok_or(
            InterpretError::Inconsistent("witness-designated remainder is not explicit"),
        )?;
        if asset != expected_input_asset {
            return Err(InterpretError::Inconsistent(
                "witness-designated remainder asset is wrong",
            ));
        }
        Some(amount)
    };
    let remainder_index = if remainder_locked.is_some() {
        Some(remainder_index_witness)
    } else {
        None
    };

    let interpreted = fill(
        params,
        before,
        input_locked,
        maker_payment,
        remainder_locked,
    )?;
    let continuation = remainder_index.map(|index| TrackedContractOutput {
        outpoint: OutPoint::new(transaction.txid(), index),
        txout: transaction.output[index as usize].clone(),
    });
    Ok(MakerOrderInterpretation {
        kind: MakerOrderSpendKind::Fill(interpreted),
        before,
        after: interpreted.next_state,
        spent_outpoint: live_output.outpoint,
        input_index: input_index_u32,
        payment_index: Some(payment_index),
        remainder_index,
        continuation,
        annex_present: annex.is_some(),
    })
}

fn explicit_asset_value(output: &elements::TxOut) -> Option<(elements::AssetId, u64)> {
    let Asset::Explicit(asset) = output.asset else {
        return None;
    };
    let Value::Explicit(value) = output.value else {
        return None;
    };
    Some((asset, value))
}

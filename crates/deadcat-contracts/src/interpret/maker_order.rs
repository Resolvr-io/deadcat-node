use deadcat_types::{MakerOrderParams, MakerOrderState, OrderDirection};
use elements::confidential::{Asset, Value};
use elements::{OutPoint, Transaction};
use sha2::{Digest as _, Sha256};

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
    let payment_output = output_at(transaction, input_index_u32)?;
    let (payment_asset, maker_payment) = explicit_asset_value(payment_output).ok_or(
        InterpretError::Inconsistent("maker payment is not explicit"),
    )?;
    let expected_payment_asset = match params.direction {
        OrderDirection::SellBase => params.quote_asset_id,
        OrderDirection::SellQuote => params.base_asset_id,
    };
    if payment_asset != expected_payment_asset
        || script_hash(&payment_output.script_pubkey) != params.maker_receive_spk_hash
    {
        return Err(InterpretError::Inconsistent(
            "maker payment asset or destination is wrong",
        ));
    }

    let price = u64::from(params.price);
    let full = match params.direction {
        OrderDirection::SellBase => {
            input_locked
                .checked_mul(price)
                .ok_or(crate::maker_order::MakerOrderError::ArithmeticOverflow)?
                == maker_payment
        }
        OrderDirection::SellQuote => {
            maker_payment
                .checked_mul(price)
                .ok_or(crate::maker_order::MakerOrderError::ArithmeticOverflow)?
                == input_locked
        }
    };
    let remainder_locked = if full {
        None
    } else {
        let remainder_indices = decoded.u32_values();
        if remainder_indices.len() != 1 {
            return Err(if remainder_indices.is_empty() {
                InterpretError::MissingWitness("REMAINDER_INDEX")
            } else {
                InterpretError::AmbiguousInterpretation
            });
        }
        let remainder_index = remainder_indices[0];
        if remainder_index == input_index_u32 {
            return Err(InterpretError::Inconsistent(
                "remainder aliases mandatory payment",
            ));
        }
        let remainder_output = output_at(transaction, remainder_index)?;
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
        Some(decoded.u32_values()[0])
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

fn script_hash(script: &elements::Script) -> [u8; 32] {
    Sha256::digest(script.as_bytes()).into()
}

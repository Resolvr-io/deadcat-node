//! Confirmed-transaction decoding and typed covenant interpretation.

use elements::{OutPoint, TxOut};
use simplex::simplicityhl::simplicity::dag::{DagLike as _, InternalSharing};
use simplex::simplicityhl::simplicity::jet::Elements;
use simplex::simplicityhl::simplicity::node::Inner;
use simplex::simplicityhl::simplicity::{BitIter, HasCmr as _, RedeemNode, Value};
use thiserror::Error;

mod binary_market;
mod maker_order;

pub use binary_market::{
    BinaryMarketContinuation, BinaryMarketInterpretation, BinaryMarketLiveOutputs,
    BinaryMarketPath, interpret_binary_market_spend,
};
pub use maker_order::{MakerOrderInterpretation, MakerOrderSpendKind, interpret_maker_order_spend};

/// A tracked covenant output with the previous output data needed to interpret
/// explicit amounts and confidential value classes from a confirmed spend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackedContractOutput {
    pub outpoint: OutPoint,
    pub txout: TxOut,
}

/// Generic errors shared by the v1 confirmed-transaction interpreters.
#[derive(Debug, Error)]
pub enum InterpretError {
    #[error("transaction does not spend the tracked covenant output")]
    NotCovenantSpend,
    #[error("tracked contract output is inconsistent with its parameters/state: {0}")]
    InvalidTrackedOutput(&'static str),
    #[error("taproot witness stack has unsupported shape after annex stripping (len {len})")]
    BadWitnessStack { len: usize },
    #[error("unexpected key-path spend")]
    UnexpectedKeySpend,
    #[error("simplicity witness decode failed: {0}")]
    Decode(String),
    #[error("decoded Simplicity CMR does not match the compiled contract")]
    CmrMismatch,
    #[error("required decoded witness value is missing: {0}")]
    MissingWitness(&'static str),
    #[error("decoded witness admits more than one transaction interpretation")]
    AmbiguousInterpretation,
    #[error("transaction contradicts its decoded covenant witness: {0}")]
    Inconsistent(&'static str),
    #[error("maker-order economics rejected the spend: {0}")]
    MakerEconomics(#[from] crate::maker_order::MakerOrderError),
    #[error("binary-market economics rejected the spend: {0}")]
    BinaryEconomics(#[from] crate::binary_market::BinaryMarketError),
    #[error("maker-order compilation failed: {0}")]
    MakerCompilation(#[from] crate::maker_order::CompiledMakerOrderError),
    #[error("binary-market compilation failed: {0}")]
    BinaryCompilation(#[from] crate::binary_market::CompiledBinaryMarketError),
    #[error("transaction index does not fit the v1 u32 witness domain")]
    IndexOverflow,
}

/// A decoded finalized Simplicity script-path witness.
///
/// `values` contains witness values in deterministic post-order; source-level
/// names are not present in the serialized Simplicity program. Optimizer
/// sharing may merge equal same-typed values, so contract-specific
/// interpreters use typed membership plus transaction validation rather than
/// assuming a fixed positional ABI.
#[derive(Clone)]
pub struct DecodedSimplicityWitness {
    cmr: [u8; 32],
    control_block: Vec<u8>,
    values: Vec<Value>,
}

impl DecodedSimplicityWitness {
    #[must_use]
    pub const fn cmr(&self) -> [u8; 32] {
        self.cmr
    }

    #[must_use]
    pub fn control_block(&self) -> &[u8] {
        &self.control_block
    }

    #[must_use]
    pub fn values(&self) -> &[Value] {
        &self.values
    }

    #[must_use]
    pub fn u8_values(&self) -> Vec<u8> {
        unique_words(&self.values, 1)
            .into_iter()
            .map(|bytes| bytes[0])
            .collect()
    }

    #[must_use]
    pub fn u32_values(&self) -> Vec<u32> {
        unique_words(&self.values, 4)
            .into_iter()
            .map(|bytes| u32::from_be_bytes(bytes.try_into().expect("four bytes")))
            .collect()
    }

    #[must_use]
    pub fn u64_values(&self) -> Vec<u64> {
        unique_words(&self.values, 8)
            .into_iter()
            .map(|bytes| u64::from_be_bytes(bytes.try_into().expect("eight bytes")))
            .collect()
    }

    #[must_use]
    pub fn bool_values(&self) -> Vec<bool> {
        let mut output = Vec::new();
        for value in &self.values {
            let bits: Vec<bool> = value.iter_compact().collect();
            if bits.len() == 1 && !output.contains(&bits[0]) {
                output.push(bits[0]);
            }
        }
        output
    }

    #[must_use]
    pub fn bytes_values(&self, length: usize) -> Vec<Vec<u8>> {
        unique_words(&self.values, length)
    }
}

/// Remove a BIP341 annex from a finalized Taproot witness.
///
/// Annex recognition requires at least two elements, preventing a key-spend
/// signature beginning with `0x50` from being mistaken for an annex.
#[must_use]
pub fn strip_taproot_annex(stack: &[Vec<u8>]) -> (&[Vec<u8>], Option<&[u8]>) {
    if stack.len() >= 2
        && stack
            .last()
            .and_then(|element| element.first())
            .is_some_and(|byte| *byte == 0x50)
    {
        let (without, annex) = stack.split_at(stack.len() - 1);
        (without, Some(annex[0].as_slice()))
    } else {
        (stack, None)
    }
}

/// Decode the four-element smplx script-path stack
/// `[witness_bits, program_bits, cmr, control_block]`.
pub fn decode_simplicity_witness(
    stack: &[Vec<u8>],
) -> Result<DecodedSimplicityWitness, InterpretError> {
    let (stack, _) = strip_taproot_annex(stack);
    if stack.len() != 4 {
        return Err(InterpretError::BadWitnessStack { len: stack.len() });
    }
    let redeem = RedeemNode::<Elements>::decode(
        BitIter::from(stack[1].iter().copied()),
        BitIter::from(stack[0].iter().copied()),
    )
    .map_err(|error| InterpretError::Decode(format!("{error:?}")))?;
    if redeem.cmr().as_ref() != stack[2].as_slice() {
        return Err(InterpretError::CmrMismatch);
    }
    let mut cmr = [0_u8; 32];
    cmr.copy_from_slice(&stack[2]);

    let mut values = Vec::new();
    for item in redeem.as_ref().post_order_iter::<InternalSharing>() {
        if let Inner::Witness(value) = item.node.inner() {
            values.push(value.shallow_clone());
        }
    }
    Ok(DecodedSimplicityWitness {
        cmr,
        control_block: stack[3].clone(),
        values,
    })
}

fn value_bytes(value: &Value, length: usize) -> Option<Vec<u8>> {
    let bits: Vec<bool> = value.iter_compact().collect();
    if bits.len() != length.checked_mul(8)? {
        return None;
    }
    let mut output = vec![0_u8; length];
    for (index, bit) in bits.into_iter().enumerate() {
        if bit {
            output[index / 8] |= 1 << (7 - index % 8);
        }
    }
    Some(output)
}

fn unique_words(values: &[Value], length: usize) -> Vec<Vec<u8>> {
    let mut output = Vec::new();
    for bytes in values.iter().filter_map(|value| value_bytes(value, length)) {
        if !output.contains(&bytes) {
            output.push(bytes);
        }
    }
    output
}

fn locate_input(
    transaction: &elements::Transaction,
    outpoint: OutPoint,
) -> Result<usize, InterpretError> {
    let mut matching = transaction
        .input
        .iter()
        .enumerate()
        .filter(|(_, input)| input.previous_output == outpoint)
        .map(|(index, _)| index);
    let index = matching.next().ok_or(InterpretError::NotCovenantSpend)?;
    if matching.next().is_some() {
        return Err(InterpretError::Inconsistent(
            "tracked outpoint appears more than once",
        ));
    }
    Ok(index)
}

fn output_at(transaction: &elements::Transaction, index: u32) -> Result<&TxOut, InterpretError> {
    transaction
        .output
        .get(index as usize)
        .ok_or(InterpretError::Inconsistent("output index out of bounds"))
}

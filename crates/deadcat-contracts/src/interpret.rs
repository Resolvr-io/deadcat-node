//! Confirmed-transaction decoding and typed covenant interpretation.

use elements::taproot::ControlBlock;
use elements::{OutPoint, TxOut};
use simplex::simplicityhl::simplicity::Value;
use simplex::simplicityhl::simplicity::dag::{DagLike as _, InternalSharing};
use simplex::simplicityhl::simplicity::node::Inner;
use thiserror::Error;

use crate::finalized_spend::{FinalizedSimplicitySpend, FinalizedSimplicitySpendError};

mod binary_market;

pub use binary_market::{
    BinaryMarketContinuation, BinaryMarketInterpretation, BinaryMarketLiveOutputs,
    interpret_binary_market_spend, interpret_binary_market_spend_with_compiled,
};

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
    #[error("unexpected key-path spend")]
    UnexpectedKeySpend,
    #[error("invalid finalized Simplicity spend: {0}")]
    FinalizedSpend(#[from] FinalizedSimplicitySpendError),
    #[error("decoded Simplicity CMR does not match the compiled contract")]
    CmrMismatch,
    #[error("required decoded witness value is missing: {0}")]
    MissingWitness(&'static str),
    #[error("transaction contradicts its decoded covenant witness: {0}")]
    Inconsistent(&'static str),
    #[error("binary-market economics rejected the spend: {0}")]
    BinaryEconomics(#[from] crate::binary_market::BinaryMarketError),
    #[error("binary-market layout rejected the spend: {0}")]
    BinaryLayout(#[from] crate::binary_market::BinaryMarketLayoutError),
    #[error("binary-market compilation failed: {0}")]
    BinaryCompilation(#[from] crate::binary_market::CompiledBinaryMarketError),
    #[error("transaction index does not fit the v1 u32 witness domain")]
    IndexOverflow,
}

/// A decoded finalized Simplicity script-path witness.
///
/// `values` contains witness values in deterministic post-order; source-level
/// names are not present in the serialized Simplicity program. Contract-specific
/// interpreters must therefore identify values by their complete structural
/// types and decode the source-level witness ABI exactly.
#[derive(Clone)]
pub struct DecodedSimplicityWitness {
    finalized_spend: FinalizedSimplicitySpend,
    values: Vec<Value>,
}

impl DecodedSimplicityWitness {
    #[must_use]
    pub const fn cmr(&self) -> [u8; 32] {
        self.finalized_spend.cmr()
    }

    #[must_use]
    pub const fn control_block(&self) -> &ControlBlock {
        self.finalized_spend.control_block()
    }

    #[must_use]
    pub const fn finalized_spend(&self) -> &FinalizedSimplicitySpend {
        &self.finalized_spend
    }

    #[must_use]
    pub fn values(&self) -> &[Value] {
        &self.values
    }
}

/// Decode the four-element smplx script-path stack
/// `[witness_bits, program_bits, cmr, control_block]` and validate its
/// canonical minimal budget annex.
pub fn decode_simplicity_witness(
    stack: &[Vec<u8>],
) -> Result<DecodedSimplicityWitness, InterpretError> {
    let finalized_spend = FinalizedSimplicitySpend::parse_witness_stack(stack)?;

    let mut values = Vec::new();
    for item in finalized_spend
        .redeem_node()
        .as_ref()
        .post_order_iter::<InternalSharing>()
    {
        if let Inner::Witness(value) = item.node.inner() {
            values.push(value.shallow_clone());
        }
    }
    Ok(DecodedSimplicityWitness {
        finalized_spend,
        values,
    })
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

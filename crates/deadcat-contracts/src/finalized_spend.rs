//! Typed, canonical finalized Simplicity script-path spends.

use std::sync::Arc;

use elements::taproot::{ControlBlock, TaprootError};
use simplex::simplicityhl::simplicity::jet::Elements;
use simplex::simplicityhl::simplicity::{
    BitIter, DecodeError, HasCmr as _, NodeBounds, RedeemNode,
};
use thiserror::Error;

const CORE_STACK_ITEMS: usize = 4;
const WITNESS_ENCODING_INDEX: usize = 0;
const PROGRAM_ENCODING_INDEX: usize = 1;
const CMR_INDEX: usize = 2;
const CONTROL_BLOCK_INDEX: usize = 3;
const TAPROOT_ANNEX_TAG: u8 = 0x50;

/// Encoded sizes of a finalized Simplicity script-path witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizedSimplicitySpendSizes {
    /// Raw bytes in the compact Simplicity witness encoding.
    pub witness_bytes: usize,
    /// Raw bytes in the Simplicity program encoding.
    pub program_bytes: usize,
    /// Raw bytes in the Taproot control block.
    pub control_block_bytes: usize,
    /// Raw bytes in the optional Taproot annex, including its `0x50` tag.
    pub annex_bytes: usize,
    /// Consensus-encoded size of the four-item core stack.
    pub core_stack_bytes: usize,
    /// Consensus-encoded size of the complete witness stack.
    pub stack_bytes: usize,
}

/// Errors constructing or decoding a finalized Simplicity spend.
#[derive(Debug, Error)]
pub enum FinalizedSimplicitySpendError {
    #[error("expected exactly four core Simplicity stack items, got {len}")]
    CoreStackShape { len: usize },
    #[error(
        "expected four core Simplicity stack items plus at most one Taproot annex, got {len} items"
    )]
    WitnessStackShape { len: usize },
    #[error("fifth finalized Simplicity stack item is not a Taproot annex")]
    InvalidAnnex,
    #[error("encoded Simplicity CMR must be 32 bytes, got {len}")]
    CmrLength { len: usize },
    #[error("failed to decode finalized Simplicity program: {0}")]
    Decode(#[source] DecodeError),
    #[error("decoded Simplicity CMR does not match the encoded CMR stack item")]
    CmrMismatch,
    #[error("invalid Taproot control block: {0}")]
    InvalidControlBlock(#[source] TaprootError),
    #[error(
        "Taproot annex is not the canonical minimal Simplicity budget padding (expected {expected_len:?} bytes, got {actual_len:?})"
    )]
    NonCanonicalAnnex {
        expected_len: Option<usize>,
        actual_len: Option<usize>,
    },
    #[error("canonical Simplicity budget padding does not provide a sufficient execution budget")]
    InsufficientBudget,
}

/// A decoded, canonically budgeted finalized Simplicity script-path spend.
///
/// The serialized witness is always exactly
/// `[witness, program, cmr, control_block]`, followed by the exact minimal
/// budget annex when one is required. Fields stay private so callers cannot
/// invalidate the decoded node, CMR, or budget relationship.
#[derive(Clone)]
pub struct FinalizedSimplicitySpend {
    witness_stack: Vec<Vec<u8>>,
    redeem_node: Arc<RedeemNode>,
    cmr: [u8; 32],
    control_block: ControlBlock,
    bounds: NodeBounds,
    encoded_sizes: FinalizedSimplicitySpendSizes,
}

impl FinalizedSimplicitySpend {
    /// Decode a four-item core stack and add the exact minimal budget annex if
    /// its execution cost requires one.
    pub fn from_core_stack(
        core_stack: [Vec<u8>; CORE_STACK_ITEMS],
    ) -> Result<Self, FinalizedSimplicitySpendError> {
        let mut witness_stack = Vec::from(core_stack);
        let (redeem_node, cmr, control_block) = decode_core_stack(&witness_stack)?;
        let bounds = redeem_node.bounds();
        if let Some(annex) = bounds.cost.get_padding(&witness_stack) {
            witness_stack.push(annex);
        }
        Self::from_decoded(witness_stack, redeem_node, cmr, control_block, bounds)
    }

    /// Decode and validate an owned finalized witness stack.
    ///
    /// Any annex must be byte-for-byte equal to the minimal padding returned
    /// for the decoded program's cost and four-item core stack.
    pub fn from_witness_stack(
        witness_stack: Vec<Vec<u8>>,
    ) -> Result<Self, FinalizedSimplicitySpendError> {
        validate_witness_shape(&witness_stack)?;
        let (redeem_node, cmr, control_block) =
            decode_core_stack(&witness_stack[..CORE_STACK_ITEMS])?;
        let bounds = redeem_node.bounds();
        Self::from_decoded(witness_stack, redeem_node, cmr, control_block, bounds)
    }

    /// Decode and validate a borrowed finalized witness stack.
    pub fn parse_witness_stack(
        witness_stack: &[Vec<u8>],
    ) -> Result<Self, FinalizedSimplicitySpendError> {
        Self::from_witness_stack(witness_stack.to_vec())
    }

    fn from_decoded(
        witness_stack: Vec<Vec<u8>>,
        redeem_node: Arc<RedeemNode>,
        cmr: [u8; 32],
        control_block: ControlBlock,
        bounds: NodeBounds,
    ) -> Result<Self, FinalizedSimplicitySpendError> {
        validate_witness_shape(&witness_stack)?;
        let core_stack = witness_stack[..CORE_STACK_ITEMS].to_vec();
        let expected_annex = bounds.cost.get_padding(&core_stack);
        let actual_annex = witness_stack.get(CORE_STACK_ITEMS);
        if expected_annex.as_deref() != actual_annex.map(Vec::as_slice) {
            return Err(FinalizedSimplicitySpendError::NonCanonicalAnnex {
                expected_len: expected_annex.as_ref().map(Vec::len),
                actual_len: actual_annex.map(Vec::len),
            });
        }
        if !bounds.cost.is_budget_valid(&witness_stack) {
            return Err(FinalizedSimplicitySpendError::InsufficientBudget);
        }
        let encoded_sizes = FinalizedSimplicitySpendSizes {
            witness_bytes: witness_stack[WITNESS_ENCODING_INDEX].len(),
            program_bytes: witness_stack[PROGRAM_ENCODING_INDEX].len(),
            control_block_bytes: witness_stack[CONTROL_BLOCK_INDEX].len(),
            annex_bytes: actual_annex.map_or(0, Vec::len),
            core_stack_bytes: elements::encode::serialize(&core_stack).len(),
            stack_bytes: elements::encode::serialize(&witness_stack).len(),
        };
        Ok(Self {
            witness_stack,
            redeem_node,
            cmr,
            control_block,
            bounds,
            encoded_sizes,
        })
    }

    /// The decoded Simplicity redeem node, including its decoded witnesses.
    #[must_use]
    pub fn redeem_node(&self) -> &Arc<RedeemNode> {
        &self.redeem_node
    }

    /// The commitment Merkle root committed to by the stack.
    #[must_use]
    pub const fn cmr(&self) -> [u8; 32] {
        self.cmr
    }

    /// The parsed Taproot control block.
    #[must_use]
    pub const fn control_block(&self) -> &ControlBlock {
        &self.control_block
    }

    /// The canonical minimal budget annex, if one is required.
    #[must_use]
    pub fn annex(&self) -> Option<&[u8]> {
        self.witness_stack.get(CORE_STACK_ITEMS).map(Vec::as_slice)
    }

    /// Execution resource bounds of the decoded redeem node.
    #[must_use]
    pub const fn bounds(&self) -> NodeBounds {
        self.bounds
    }

    /// Raw and consensus-encoded sizes of this finalized witness.
    #[must_use]
    pub const fn encoded_sizes(&self) -> FinalizedSimplicitySpendSizes {
        self.encoded_sizes
    }

    /// The complete canonical witness stack.
    #[must_use]
    pub fn witness_stack(&self) -> &[Vec<u8>] {
        &self.witness_stack
    }

    /// Consume this value and return the complete canonical witness stack.
    #[must_use]
    pub fn into_witness_stack(self) -> Vec<Vec<u8>> {
        self.witness_stack
    }
}

fn validate_witness_shape(witness_stack: &[Vec<u8>]) -> Result<(), FinalizedSimplicitySpendError> {
    match witness_stack.len() {
        CORE_STACK_ITEMS => Ok(()),
        len if len == CORE_STACK_ITEMS + 1 => {
            if witness_stack[CORE_STACK_ITEMS].first() == Some(&TAPROOT_ANNEX_TAG) {
                Ok(())
            } else {
                Err(FinalizedSimplicitySpendError::InvalidAnnex)
            }
        }
        len => Err(FinalizedSimplicitySpendError::WitnessStackShape { len }),
    }
}

fn decode_core_stack(
    core_stack: &[Vec<u8>],
) -> Result<(Arc<RedeemNode>, [u8; 32], ControlBlock), FinalizedSimplicitySpendError> {
    if core_stack.len() != CORE_STACK_ITEMS {
        return Err(FinalizedSimplicitySpendError::CoreStackShape {
            len: core_stack.len(),
        });
    }
    if core_stack[CMR_INDEX].len() != 32 {
        return Err(FinalizedSimplicitySpendError::CmrLength {
            len: core_stack[CMR_INDEX].len(),
        });
    }
    let control_block = ControlBlock::from_slice(&core_stack[CONTROL_BLOCK_INDEX])
        .map_err(FinalizedSimplicitySpendError::InvalidControlBlock)?;
    let redeem_node = RedeemNode::decode::<_, _, Elements>(
        BitIter::from(core_stack[PROGRAM_ENCODING_INDEX].iter().copied()),
        BitIter::from(core_stack[WITNESS_ENCODING_INDEX].iter().copied()),
    )
    .map_err(FinalizedSimplicitySpendError::Decode)?;
    if redeem_node.cmr().as_ref() != core_stack[CMR_INDEX].as_slice() {
        return Err(FinalizedSimplicitySpendError::CmrMismatch);
    }
    let mut cmr = [0_u8; 32];
    cmr.copy_from_slice(&core_stack[CMR_INDEX]);
    Ok((redeem_node, cmr, control_block))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_core_shapes_before_decode() {
        let error = FinalizedSimplicitySpend::from_witness_stack(vec![Vec::new(); 3])
            .err()
            .expect("bad shape");
        assert!(matches!(
            error,
            FinalizedSimplicitySpendError::WitnessStackShape { len: 3 }
        ));
    }

    #[test]
    fn rejects_a_fifth_item_without_the_annex_tag() {
        let error = FinalizedSimplicitySpend::from_witness_stack(vec![Vec::new(); 5])
            .err()
            .expect("invalid annex");
        assert!(matches!(error, FinalizedSimplicitySpendError::InvalidAnnex));
    }

    #[test]
    fn reports_the_cmr_length_separately_from_decode_errors() {
        let error = FinalizedSimplicitySpend::from_witness_stack(vec![Vec::new(); 4])
            .err()
            .expect("invalid CMR");
        assert!(matches!(
            error,
            FinalizedSimplicitySpendError::CmrLength { len: 0 }
        ));
    }

    #[test]
    fn reports_invalid_control_blocks_separately_from_decode_errors() {
        let error = FinalizedSimplicitySpend::from_witness_stack(vec![
            Vec::new(),
            Vec::new(),
            vec![0; 32],
            Vec::new(),
        ])
        .err()
        .expect("invalid control block");
        assert!(matches!(
            error,
            FinalizedSimplicitySpendError::InvalidControlBlock(_)
        ));
    }
}

//! Public A/B reissuance-token blinding schedule.

use std::cmp::Ordering;

use elements::confidential::{Asset, AssetBlindingFactor, Value, ValueBlindingFactor};
use elements::secp256k1_zkp::Secp256k1;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// secp256k1 group order, big-endian.
pub const SECP256K1_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Asset blinding factor for side A of every market RT.
pub const ABF_A: [u8; 32] = [1; 32];

/// Asset blinding factor for side B of every market RT.
pub const ABF_B: [u8; 32] = [2; 32];

/// Commitment blinding factor for the YES RT leg.
///
/// The NO leg uses its additive inverse, so the two one-unit RT outputs
/// balance locally at market creation without a confidential wallet change
/// output.
pub const YES_CBF: [u8; 32] = [3; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtFactors {
    pub abf: [u8; 32],
    pub vbf: [u8; 32],
    pub cbf: [u8; 32],
}

/// One of the two independently reissuable market outcome-token legs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RtLeg {
    Yes,
    No,
}

/// The currently live member of an RT leg's two-state commitment schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RtSide {
    A,
    B,
}

impl RtSide {
    /// The side required for the next continuation or terminal burn.
    #[must_use]
    pub const fn flip(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }

    #[must_use]
    pub const fn abf(self) -> [u8; 32] {
        match self {
            Self::A => ABF_A,
            Self::B => ABF_B,
        }
    }
}

/// Materialize the confidential one-unit asset/value commitments enforced by
/// the market covenant. Nonce and rangeproof construction remain a client
/// responsibility and are deliberately not part of this helper.
pub fn commitments(
    asset_id: elements::AssetId,
    factors: RtFactors,
) -> Result<(Asset, Value), RtCommitmentError> {
    let abf = AssetBlindingFactor::from_slice(&factors.abf)
        .map_err(|_| RtCommitmentError::InvalidAssetBlindingFactor)?;
    let vbf = ValueBlindingFactor::from_slice(&factors.vbf)
        .map_err(|_| RtCommitmentError::InvalidValueBlindingFactor)?;
    let secp = Secp256k1::new();
    let asset = Asset::new_confidential(&secp, asset_id, abf);
    let generator = asset
        .commitment()
        .expect("new_confidential always returns a generator");
    let value = Value::new_confidential(&secp, 1, generator, vbf);
    Ok((asset, value))
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RtCommitmentError {
    #[error("invalid RT asset blinding factor")]
    InvalidAssetBlindingFactor,
    #[error("invalid RT value blinding factor")]
    InvalidValueBlindingFactor,
}

#[must_use]
pub fn tagged_hash(tag: &str, message: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hash = Sha256::new();
    hash.update(tag_hash);
    hash.update(tag_hash);
    hash.update(message);
    hash.finalize().into()
}

/// Reduce one 256-bit hash modulo the secp256k1 group order.
///
/// Since the input is below `2^256` and the group order is above `2^255`, at
/// most one subtraction is required. Zero is a valid protocol scalar value.
#[must_use]
pub fn reduce_scalar(mut value: [u8; 32]) -> [u8; 32] {
    if compare(&value, &SECP256K1_ORDER) != Ordering::Less {
        value = subtract_same_width(value, SECP256K1_ORDER).1;
    }
    value
}

#[must_use]
pub fn hash_to_scalar(domain: &str, message: &[u8]) -> [u8; 32] {
    reduce_scalar(tagged_hash(domain, message))
}

/// Commitment blinding factor for the NO RT leg.
#[must_use]
pub fn no_cbf() -> [u8; 32] {
    subtract_mod_order([0; 32], YES_CBF)
}

#[must_use]
pub fn cbf(leg: RtLeg) -> [u8; 32] {
    match leg {
        RtLeg::Yes => YES_CBF,
        RtLeg::No => no_cbf(),
    }
}

/// Materialize the public blinding factors for one RT leg and side.
#[must_use]
pub fn factors(leg: RtLeg, side: RtSide) -> RtFactors {
    let abf = side.abf();
    let cbf = cbf(leg);
    let vbf = subtract_mod_order(cbf, abf);
    RtFactors { abf, vbf, cbf }
}

/// Infer the live A/B side solely from the on-chain asset and value
/// commitments.
pub fn infer_side(
    leg: RtLeg,
    asset_id: elements::AssetId,
    asset: Asset,
    value: Value,
) -> Result<RtSide, SideInferenceError> {
    let a = commitments(asset_id, factors(leg, RtSide::A))?;
    let b = commitments(asset_id, factors(leg, RtSide::B))?;
    match ((asset, value) == a, (asset, value) == b) {
        (true, false) => Ok(RtSide::A),
        (false, true) => Ok(RtSide::B),
        (false, false) => Err(SideInferenceError::UnknownCommitment),
        (true, true) => Err(SideInferenceError::AmbiguousCommitment),
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SideInferenceError {
    #[error("invalid public A/B factors: {0}")]
    Commitment(#[from] RtCommitmentError),
    #[error("RT commitment matches neither public side")]
    UnknownCommitment,
    #[error("RT commitment matches both public sides")]
    AmbiguousCommitment,
}

#[must_use]
pub fn add_mod_order(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let left = reduce_scalar(left);
    let right = reduce_scalar(right);
    let mut sum = [0_u8; 33];
    let mut carry = 0_u16;
    for index in (0..32).rev() {
        let word = u16::from(left[index]) + u16::from(right[index]) + carry;
        sum[index + 1] = word as u8;
        carry = word >> 8;
    }
    sum[0] = carry as u8;

    let mut order = [0_u8; 33];
    order[1..].copy_from_slice(&SECP256K1_ORDER);
    if compare(&sum, &order) != Ordering::Less {
        sum = subtract_same_width(sum, order).1;
    }
    sum[1..].try_into().expect("fixed slice")
}

#[must_use]
pub fn subtract_mod_order(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let left = reduce_scalar(left);
    let right = reduce_scalar(right);
    if compare(&left, &right) != Ordering::Less {
        subtract_same_width(left, right).1
    } else {
        let difference = subtract_same_width(right, left).1;
        subtract_same_width(SECP256K1_ORDER, difference).1
    }
}

fn compare<const N: usize>(left: &[u8; N], right: &[u8; N]) -> Ordering {
    left.as_slice().cmp(right.as_slice())
}

fn subtract_same_width<const N: usize>(left: [u8; N], right: [u8; N]) -> (bool, [u8; N]) {
    let mut output = [0_u8; N];
    let mut borrow = 0_i16;
    for index in (0..N).rev() {
        let value = i16::from(left[index]) - i16::from(right[index]) - borrow;
        if value < 0 {
            output[index] = (value + 256) as u8;
            borrow = 1;
        } else {
            output[index] = value as u8;
            borrow = 0;
        }
    }
    (borrow != 0, output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(value: u8) -> [u8; 32] {
        let mut scalar = [0_u8; 32];
        scalar[31] = value;
        scalar
    }

    #[test]
    fn scalar_reduction_covers_group_order_boundary() {
        assert_eq!(reduce_scalar(SECP256K1_ORDER), [0; 32]);
        let mut order_plus_one = SECP256K1_ORDER;
        order_plus_one[31] += 1;
        assert_eq!(reduce_scalar(order_plus_one), scalar(1));
    }

    #[test]
    fn modular_addition_and_subtraction_wrap() {
        let order_minus_one = subtract_same_width(SECP256K1_ORDER, scalar(1)).1;
        assert_eq!(add_mod_order(order_minus_one, scalar(2)), scalar(1));
        assert_eq!(subtract_mod_order(scalar(1), scalar(2)), order_minus_one);
    }

    #[test]
    fn complementary_leg_cbfs_balance() {
        assert_eq!(add_mod_order(cbf(RtLeg::Yes), cbf(RtLeg::No)), [0; 32]);
    }

    #[test]
    fn sides_round_trip_through_commitments() {
        let asset = elements::AssetId::from_slice(&[0x33; 32]).expect("asset");
        for leg in [RtLeg::Yes, RtLeg::No] {
            for side in [RtSide::A, RtSide::B] {
                let committed = commitments(asset, factors(leg, side)).expect("commitments");
                assert_eq!(infer_side(leg, asset, committed.0, committed.1), Ok(side));
                assert!(committed.0.is_confidential());
                assert!(committed.1.is_confidential());
            }
            assert_eq!(factors(leg, RtSide::A).cbf, factors(leg, RtSide::B).cbf);
            assert_ne!(factors(leg, RtSide::A).abf, factors(leg, RtSide::B).abf);
        }
    }

    #[test]
    fn public_schedule_has_stable_scalar_vectors() {
        assert_eq!(ABF_A, [1; 32]);
        assert_eq!(ABF_B, [2; 32]);
        assert_eq!(YES_CBF, [3; 32]);
        assert_eq!(
            no_cbf(),
            [
                0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc,
                0xfc, 0xfb, 0xb7, 0xab, 0xd9, 0xe3, 0xac, 0x45, 0x9d, 0x38, 0xbc, 0xcf, 0x5b, 0x89,
                0xcd, 0x33, 0x3e, 0x3e,
            ]
        );
    }
}

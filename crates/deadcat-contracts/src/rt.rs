//! Deterministic reissuance-token blinding factors.

use std::cmp::Ordering;

use elements::OutPoint;
use elements::confidential::{Asset, AssetBlindingFactor, Value, ValueBlindingFactor};
use elements::secp256k1_zkp::Secp256k1;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// secp256k1 group order, big-endian.
pub const SECP256K1_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtFactors {
    pub abf: [u8; 32],
    pub vbf: [u8; 32],
    pub cbf: [u8; 32],
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

/// Elements consensus outpoint serialization: internal txid bytes followed by
/// little-endian `vout`. This differs from the redb key's big-endian integer.
#[must_use]
pub fn serialize_outpoint(outpoint: OutPoint) -> [u8; 36] {
    elements::encode::serialize(&outpoint)
        .try_into()
        .expect("Elements outpoints always serialize to 36 bytes")
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

#[must_use]
pub fn creation_factors(defining_outpoint: OutPoint) -> RtFactors {
    let encoded = serialize_outpoint(defining_outpoint);
    let abf = hash_to_scalar("deadcat/rt_abf", &encoded);
    let vbf = hash_to_scalar("deadcat/rt_vbf", &encoded);
    let cbf = add_mod_order(abf, vbf);
    RtFactors { abf, vbf, cbf }
}

#[must_use]
pub fn continuation_factors(spent_rt_outpoint: OutPoint, input_cbf: [u8; 32]) -> RtFactors {
    let abf = hash_to_scalar("deadcat/rt_abf", &serialize_outpoint(spent_rt_outpoint));
    let cbf = reduce_scalar(input_cbf);
    let vbf = subtract_mod_order(cbf, abf);
    RtFactors { abf, vbf, cbf }
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
    use elements::Txid;
    use elements::hashes::Hash as _;

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
    fn outpoint_encoding_uses_consensus_little_endian_vout() {
        let outpoint = OutPoint::new(Txid::from_byte_array([0x11; 32]), 0x0102_0304);
        let encoded = serialize_outpoint(outpoint);
        assert_eq!(&encoded[..32], &[0x11; 32]);
        assert_eq!(&encoded[32..], &[4, 3, 2, 1]);
    }

    #[test]
    fn continuation_preserves_cbf_and_recomputes_vbf() {
        let defining = OutPoint::new(Txid::from_byte_array([0x22; 32]), 7);
        let creation = creation_factors(defining);
        let continuation = continuation_factors(defining, creation.cbf);
        assert_eq!(continuation.cbf, creation.cbf);
        assert_eq!(
            add_mod_order(continuation.abf, continuation.vbf),
            continuation.cbf
        );
    }

    #[test]
    fn commitments_are_deterministic_and_confidential() {
        let asset = elements::AssetId::from_slice(&[0x33; 32]).expect("asset");
        let factors = creation_factors(OutPoint::new(Txid::from_byte_array([0x44; 32]), 2));
        let first = commitments(asset, factors).expect("commitments");
        let second = commitments(asset, factors).expect("commitments");
        assert_eq!(first, second);
        assert!(first.0.is_confidential());
        assert!(first.1.is_confidential());
    }
}

//! A/B asset blinders with complementary, per-leg constant CBFs.

use deadcat_contracts::rt::{RtCommitmentError, RtFactors, commitments, subtract_mod_order};
use elements::AssetId;
use elements::confidential::{Asset, Value};
use thiserror::Error;

pub const ABF_A: [u8; 32] = [1; 32];
pub const ABF_B: [u8; 32] = [2; 32];
pub const YES_CBF: [u8; 32] = [3; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RtLeg {
    Yes,
    No,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RtSide {
    A,
    B,
}

impl RtSide {
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

#[must_use]
pub fn factors(leg: RtLeg, side: RtSide) -> RtFactors {
    let abf = side.abf();
    let cbf = cbf(leg);
    let vbf = subtract_mod_order(cbf, abf);
    RtFactors { abf, vbf, cbf }
}

pub fn infer_side(
    leg: RtLeg,
    asset_id: AssetId,
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

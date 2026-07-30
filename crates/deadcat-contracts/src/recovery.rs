//! Byte-exact v1 OP_RETURN recovery payloads.

use elements::confidential::{Asset, Nonce, Value};
use elements::{AssetId, Script, TxOut, TxOutWitness};
use thiserror::Error;

pub const MARKET_V1_TAG: u8 = 0x10;

pub const BASE_PAYOUTS: [u64; 16] = [
    100, 200, 500, 1_000, 2_000, 5_000, 10_000, 20_000, 50_000, 100_000, 200_000, 500_000,
    1_000_000, 2_000_000, 5_000_000, 10_000_000,
];

pub const MARKET_KNOWN_PAYLOAD_LEN: usize = 38;
pub const MARKET_EXOTIC_PAYLOAD_LEN: usize = 70;
pub const MAX_RECOVERY_PAYLOAD_LEN: usize = MARKET_EXOTIC_PAYLOAD_LEN;

/// Build the exact canonical OP_RETURN used by v1 recovery outputs.
pub fn recovery_script(payload: &[u8]) -> Result<Script, RecoveryError> {
    if payload.is_empty() || payload.len() > MAX_RECOVERY_PAYLOAD_LEN {
        return Err(RecoveryError::InvalidPayloadLength(payload.len()));
    }
    let mut bytes = Vec::with_capacity(payload.len() + 2);
    bytes.push(0x6a);
    bytes.push(payload.len() as u8);
    bytes.extend_from_slice(payload);
    Ok(Script::from(bytes))
}

/// Extract a payload only from the exact canonical v1 push shape.
pub fn parse_recovery_script(script: &Script) -> Result<&[u8], RecoveryError> {
    let bytes = script.as_bytes();
    if bytes.len() < 3 || bytes[0] != 0x6a {
        return Err(RecoveryError::InvalidRecoveryScript);
    }
    let payload_len = usize::from(bytes[1]);
    if payload_len == 0 || payload_len > MAX_RECOVERY_PAYLOAD_LEN || bytes.len() != payload_len + 2
    {
        return Err(RecoveryError::InvalidRecoveryScript);
    }
    Ok(&bytes[2..])
}

/// Construct the canonical zero-value policy-asset recovery output.
pub fn recovery_txout(policy_asset: AssetId, payload: &[u8]) -> Result<TxOut, RecoveryError> {
    Ok(TxOut {
        asset: Asset::Explicit(policy_asset),
        value: Value::Explicit(0),
        nonce: Nonce::Null,
        script_pubkey: recovery_script(payload)?,
        witness: TxOutWitness::default(),
    })
}

pub fn validate_recovery_txout(
    txout: &TxOut,
    policy_asset: AssetId,
) -> Result<&[u8], RecoveryError> {
    if txout.asset != Asset::Explicit(policy_asset)
        || txout.value != Value::Explicit(0)
        || txout.nonce != Nonce::Null
        || txout.witness != TxOutWitness::default()
    {
        return Err(RecoveryError::InvalidRecoveryOutput);
    }
    parse_recovery_script(&txout.script_pubkey)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarketCollateral {
    PolicyAsset,
    LiquidMainnetUsdt,
    Asset(AssetId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarketRecoveryHint {
    pub oracle_public_key: [u8; 32],
    pub collateral: MarketCollateral,
    pub base_payout: u64,
    /// CLTV-style height threshold, first confirmable in block `H + 1`.
    pub expiry_height: u32,
}

impl MarketRecoveryHint {
    pub fn encode(self) -> Result<Vec<u8>, RecoveryError> {
        validate_expiry_height(self.expiry_height)?;
        let payout_index = BASE_PAYOUTS
            .iter()
            .position(|candidate| *candidate == self.base_payout)
            .ok_or(RecoveryError::InvalidBasePayout)? as u8;

        let (collateral_index, asset) = match self.collateral {
            MarketCollateral::PolicyAsset => (0_u8, None),
            MarketCollateral::LiquidMainnetUsdt => (1, None),
            MarketCollateral::Asset(asset) => (15, Some(asset)),
        };

        let mut payload = Vec::with_capacity(if asset.is_some() {
            MARKET_EXOTIC_PAYLOAD_LEN
        } else {
            MARKET_KNOWN_PAYLOAD_LEN
        });
        payload.push(MARKET_V1_TAG);
        payload.extend_from_slice(&self.oracle_public_key);
        payload.push((collateral_index << 4) | payout_index);
        payload.extend_from_slice(&self.expiry_height.to_be_bytes());
        if let Some(asset) = asset {
            payload.extend_from_slice(&asset.into_inner().to_byte_array());
        }
        Ok(payload)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, RecoveryError> {
        if payload.len() != MARKET_KNOWN_PAYLOAD_LEN && payload.len() != MARKET_EXOTIC_PAYLOAD_LEN {
            return Err(RecoveryError::InvalidLength {
                expected: "38 or 70",
                actual: payload.len(),
            });
        }
        if payload[0] != MARKET_V1_TAG {
            return Err(RecoveryError::UnknownTag(payload[0]));
        }

        let mut oracle_public_key = [0_u8; 32];
        oracle_public_key.copy_from_slice(&payload[1..33]);
        let collateral_index = payload[33] >> 4;
        let payout_index = usize::from(payload[33] & 0x0f);
        let expiry_height = u32::from_be_bytes(payload[34..38].try_into().expect("fixed slice"));
        validate_expiry_height(expiry_height)?;

        let collateral = match (collateral_index, payload.len()) {
            (0, MARKET_KNOWN_PAYLOAD_LEN) => MarketCollateral::PolicyAsset,
            (1, MARKET_KNOWN_PAYLOAD_LEN) => MarketCollateral::LiquidMainnetUsdt,
            (15, MARKET_EXOTIC_PAYLOAD_LEN) => {
                let asset = AssetId::from_slice(&payload[38..70])
                    .map_err(|_| RecoveryError::InvalidAssetId)?;
                MarketCollateral::Asset(asset)
            }
            (2..=14, _) => return Err(RecoveryError::ReservedCollateralIndex(collateral_index)),
            _ => return Err(RecoveryError::CollateralLengthMismatch(collateral_index)),
        };

        Ok(Self {
            oracle_public_key,
            collateral,
            base_payout: BASE_PAYOUTS[payout_index],
            expiry_height,
        })
    }
}

fn validate_expiry_height(height: u32) -> Result<(), RecoveryError> {
    if height == 0 || height >= 500_000_000 {
        return Err(RecoveryError::InvalidExpiryHeight(height));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RecoveryError {
    #[error("unknown recovery tag {0:#04x}")]
    UnknownTag(u8),
    #[error("invalid payload length: expected {expected}, got {actual}")]
    InvalidLength {
        expected: &'static str,
        actual: usize,
    },
    #[error("invalid base payout")]
    InvalidBasePayout,
    #[error("reserved collateral index {0}")]
    ReservedCollateralIndex(u8),
    #[error("collateral index {0} does not match payload length")]
    CollateralLengthMismatch(u8),
    #[error("invalid collateral asset id")]
    InvalidAssetId,
    #[error("expiry height must be in 1..500000000, got {0}")]
    InvalidExpiryHeight(u32),
    #[error("recovery payload must contain 1..=70 bytes, got {0}")]
    InvalidPayloadLength(usize),
    #[error("invalid recovery OP_RETURN script")]
    InvalidRecoveryScript,
    #[error("invalid recovery output asset, value, nonce, or proofs")]
    InvalidRecoveryOutput,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_market_round_trip_is_38_bytes() {
        let hint = MarketRecoveryHint {
            oracle_public_key: [0x11; 32],
            collateral: MarketCollateral::PolicyAsset,
            base_payout: 10_000,
            expiry_height: 123_456,
        };
        let payload = hint.encode().expect("encode");
        assert_eq!(payload.len(), MARKET_KNOWN_PAYLOAD_LEN);
        assert_eq!(payload[33], 0x06);
        assert_eq!(MarketRecoveryHint::decode(&payload), Ok(hint));
    }

    #[test]
    fn exotic_market_round_trip_is_70_bytes() {
        let asset = AssetId::from_slice(&[0x22; 32]).expect("asset");
        let hint = MarketRecoveryHint {
            oracle_public_key: [0x33; 32],
            collateral: MarketCollateral::Asset(asset),
            base_payout: 10_000_000,
            expiry_height: 499_999_999,
        };
        let payload = hint.encode().expect("encode");
        assert_eq!(payload.len(), MARKET_EXOTIC_PAYLOAD_LEN);
        assert_eq!(payload[33], 0xff);
        assert_eq!(MarketRecoveryHint::decode(&payload), Ok(hint));
    }

    #[test]
    fn malformed_market_lengths_are_rejected() {
        assert!(matches!(
            MarketRecoveryHint::decode(&[MARKET_V1_TAG; 39]),
            Err(RecoveryError::InvalidLength { .. })
        ));
    }

    #[test]
    fn recovery_output_is_exact_single_direct_push() {
        let policy = AssetId::from_slice(&[0x66; 32]).expect("asset");
        let payload = MarketRecoveryHint {
            oracle_public_key: [0x77; 32],
            collateral: MarketCollateral::PolicyAsset,
            base_payout: 1_000,
            expiry_height: 1,
        }
        .encode()
        .expect("payload");
        let output = recovery_txout(policy, &payload).expect("output");
        assert_eq!(output.script_pubkey.len(), 40);
        assert_eq!(
            validate_recovery_txout(&output, policy),
            Ok(payload.as_slice())
        );

        let nonminimal = Script::from([vec![0x6a, 0x4c, payload.len() as u8], payload].concat());
        assert_eq!(
            parse_recovery_script(&nonminimal),
            Err(RecoveryError::InvalidRecoveryScript)
        );
    }
}

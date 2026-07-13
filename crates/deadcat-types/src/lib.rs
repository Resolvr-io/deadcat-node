//! Canonical domain types shared by Deadcat's internal crates.
//!
//! This crate is deliberately `publish = false`. It prevents semantic drift
//! between the contracts, client, RPC, and node without promising a stable
//! third-party "core" API.

use elements::hashes::Hash as _;
use elements::{AssetId, BlockHash, OutPoint, Txid};
use serde::{Deserialize, Serialize};

/// A compiled contract family and its on-chain creation instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractId {
    #[serde(with = "hex::serde")]
    pub cmr: [u8; 32],
    pub creation_txid: Txid,
}

impl ContractId {
    /// Stable redb key encoding: `cmr || elements-internal txid bytes`.
    #[must_use]
    pub fn to_fixed_key(self) -> [u8; 64] {
        let mut key = [0_u8; 64];
        key[..32].copy_from_slice(&self.cmr);
        key[32..].copy_from_slice(&self.creation_txid.to_byte_array());
        key
    }
}

/// Canonical transaction ordering within the confirmed chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainPosition {
    pub block_height: u32,
    pub tx_index: u32,
}

impl ChainPosition {
    #[must_use]
    pub fn to_fixed_key(self) -> [u8; 8] {
        let mut key = [0_u8; 8];
        key[..4].copy_from_slice(&self.block_height.to_be_bytes());
        key[4..].copy_from_slice(&self.tx_index.to_be_bytes());
        key
    }
}

/// A block-height/hash pair anchoring a consistent response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainAnchor {
    pub height: u32,
    pub hash: BlockHash,
}

/// Cross-language-stable outpoint representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeadcatOutPoint {
    pub txid: Txid,
    pub vout: u32,
}

impl DeadcatOutPoint {
    #[must_use]
    pub const fn new(txid: Txid, vout: u32) -> Self {
        Self { txid, vout }
    }

    #[must_use]
    pub fn to_fixed_key(self) -> [u8; 36] {
        let mut key = [0_u8; 36];
        key[..32].copy_from_slice(&self.txid.to_byte_array());
        key[32..].copy_from_slice(&self.vout.to_be_bytes());
        key
    }
}

impl From<OutPoint> for DeadcatOutPoint {
    fn from(value: OutPoint) -> Self {
        Self::new(value.txid, value.vout)
    }
}

impl From<DeadcatOutPoint> for OutPoint {
    fn from(value: DeadcatOutPoint) -> Self {
        Self::new(value.txid, value.vout)
    }
}

/// Durable subscription cursor. Epoch changes on destructive rebuild/restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventCursor {
    #[serde(with = "hex::serde")]
    pub epoch: [u8; 16],
    #[serde(with = "serde_u64_string")]
    pub sequence: u64,
}

impl EventCursor {
    #[must_use]
    pub fn to_fixed_key(self) -> [u8; 24] {
        let mut key = [0_u8; 24];
        key[..16].copy_from_slice(&self.epoch);
        key[16..].copy_from_slice(&self.sequence.to_be_bytes());
        key
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryHintLocation {
    pub position: ChainPosition,
    pub output_index: u32,
}

/// Liquid chain selected by a node or client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidNetwork {
    Liquid,
    LiquidTestnet,
    ElementsRegtest,
}

/// Canonical v1 contract family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractKind {
    BinaryMarketV1,
    MakerOrderV1,
    /// Reserved for capability negotiation; registration is unsupported in v1.
    LmsrV1Reserved,
}

/// Binary market parameters committed by the compiled covenant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryMarketParams {
    #[serde(with = "hex::serde")]
    pub oracle_public_key: [u8; 32],
    pub collateral_asset_id: AssetId,
    pub yes_token_asset_id: AssetId,
    pub no_token_asset_id: AssetId,
    pub yes_reissuance_token_id: AssetId,
    pub no_reissuance_token_id: AssetId,
    #[serde(with = "serde_u64_string")]
    pub base_payout: u64,
    pub expiry_height: u32,
}

impl BinaryMarketParams {
    /// Collateral required for one YES/NO pair.
    pub fn collateral_per_pair(self) -> Option<u64> {
        self.base_payout.checked_mul(2)
    }
}

/// Which outcome token an order trades against collateral.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderSide {
    Yes,
    No,
}

/// Asset held by an active maker order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderDirection {
    SellBase,
    SellQuote,
}

impl OrderDirection {
    #[must_use]
    pub const fn protocol_byte(self) -> u8 {
        match self {
            Self::SellBase => 0,
            Self::SellQuote => 1,
        }
    }
}

/// Public parameters needed to compile and validate a maker order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MakerOrderParams {
    pub base_asset_id: AssetId,
    pub quote_asset_id: AssetId,
    pub price: u32,
    pub min_active_base: u32,
    pub direction: OrderDirection,
    #[serde(with = "hex::serde")]
    pub maker_receive_spk_hash: [u8; 32],
    #[serde(with = "hex::serde")]
    pub maker_pubkey: [u8; 32],
}

/// Confirmed binary-market materialized state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryMarketState {
    Trading {
        #[serde(with = "serde_u64_string")]
        outstanding_pairs: u64,
    },
    ResolvedYes {
        #[serde(with = "serde_u64_string")]
        collateral_unredeemed: u64,
    },
    ResolvedNo {
        #[serde(with = "serde_u64_string")]
        collateral_unredeemed: u64,
    },
    Expired {
        #[serde(with = "serde_u64_string")]
        collateral_unredeemed: u64,
    },
}

/// Confirmed maker-order materialized state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MakerOrderState {
    Active {
        #[serde(with = "serde_u64_string")]
        remaining_base: u64,
        #[serde(with = "serde_u64_string")]
        total_filled_base: u64,
    },
    Consumed,
    Cancelled,
}

/// Whether a verified registration has replayed through the indexed tip.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractSyncState {
    CatchingUp { synced_through: ChainAnchor },
    Ready { synced_through: ChainAnchor },
}

/// Global hint-discovery mode and coverage, distinct from contract sync.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryCoverage {
    pub mode: DiscoveryMode,
    pub from: ChainAnchor,
    pub scanned_through: ChainAnchor,
    pub target_tip: ChainAnchor,
    pub canonical_market_complete: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMode {
    FullHintScan,
    AdvisoryOnly,
}

/// JSON codec for `u64` values that must round-trip through JavaScript.
pub mod serde_u64_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_id_fixed_key_is_cmr_then_internal_txid_bytes() {
        let txid = Txid::from_byte_array([0x22; 32]);
        let id = ContractId {
            cmr: [0x11; 32],
            creation_txid: txid,
        };

        let key = id.to_fixed_key();
        assert_eq!(&key[..32], &[0x11; 32]);
        assert_eq!(&key[32..], &[0x22; 32]);
    }

    #[test]
    fn payout_multiplication_is_checked() {
        let params = BinaryMarketParams {
            oracle_public_key: [0; 32],
            collateral_asset_id: AssetId::from_slice(&[1; 32]).expect("asset"),
            yes_token_asset_id: AssetId::from_slice(&[2; 32]).expect("asset"),
            no_token_asset_id: AssetId::from_slice(&[3; 32]).expect("asset"),
            yes_reissuance_token_id: AssetId::from_slice(&[4; 32]).expect("asset"),
            no_reissuance_token_id: AssetId::from_slice(&[5; 32]).expect("asset"),
            base_payout: u64::MAX,
            expiry_height: 1,
        };

        assert_eq!(params.collateral_per_pair(), None);
    }

    #[test]
    fn stable_key_components_use_big_endian_integers() {
        let position = ChainPosition {
            block_height: 0x0102_0304,
            tx_index: 0x0506_0708,
        };
        assert_eq!(position.to_fixed_key(), [1, 2, 3, 4, 5, 6, 7, 8]);

        let txid = Txid::from_byte_array([0x33; 32]);
        let outpoint = DeadcatOutPoint::new(txid, 0x0102_0304);
        assert_eq!(&outpoint.to_fixed_key()[32..], &[1, 2, 3, 4]);

        let cursor = EventCursor {
            epoch: [0x44; 16],
            sequence: 0x0102_0304_0506_0708,
        };
        assert_eq!(&cursor.to_fixed_key()[16..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn monetary_u64_values_are_json_strings() {
        let state = BinaryMarketState::Trading {
            outstanding_pairs: u64::MAX,
        };
        let json = serde_json::to_string(&state).expect("serialize");
        assert!(json.contains("18446744073709551615"));
        assert_eq!(
            serde_json::from_str::<BinaryMarketState>(&json).expect("deserialize"),
            state
        );
    }
}

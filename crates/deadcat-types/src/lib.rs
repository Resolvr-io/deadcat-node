//! Canonical domain types shared by Deadcat's internal crates.
//!
//! This crate is deliberately `publish = false`. It prevents semantic drift
//! between the contracts, client, RPC, and node without promising a stable
//! third-party "core" API.

use elements::hashes::Hash as _;
use elements::{AssetId, BlockHash, OutPoint, Txid};
use serde::ser::SerializeStruct as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

pub const CONTRACT_PACKAGE_FORMAT_VERSION: u16 = 1;
pub const MAX_CONTRACT_PACKAGE_DECLARATIONS: usize = 64;
pub const MAX_CONTRACT_PACKAGE_ROOTS: usize = 16;

/// The canonical creation-anchor outpoint of one on-chain contract instance.
///
/// This is a nominal type so an arbitrary live or wallet outpoint cannot be
/// used accidentally where a stable contract identity is required. Possessing
/// a `ContractId` is not evidence that the referenced contract is valid.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContractId(OutPoint);

impl ContractId {
    #[must_use]
    pub const fn new(creation_anchor: OutPoint) -> Self {
        Self(creation_anchor)
    }

    #[must_use]
    pub const fn creation_anchor(self) -> OutPoint {
        self.0
    }

    #[must_use]
    pub const fn txid(self) -> Txid {
        self.0.txid
    }

    #[must_use]
    pub const fn vout(self) -> u32 {
        self.0.vout
    }

    /// Stable redb key encoding: Elements-internal txid bytes followed by the
    /// output index in big-endian order.
    #[must_use]
    pub fn to_fixed_key(self) -> [u8; 36] {
        let mut key = [0_u8; 36];
        key[..32].copy_from_slice(&self.txid().to_byte_array());
        key[32..].copy_from_slice(&self.vout().to_be_bytes());
        key
    }
}

impl From<OutPoint> for ContractId {
    fn from(value: OutPoint) -> Self {
        Self::new(value)
    }
}

impl From<ContractId> for OutPoint {
    fn from(value: ContractId) -> Self {
        value.creation_anchor()
    }
}

impl fmt::Display for ContractId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.txid(), self.vout())
    }
}

impl FromStr for ContractId {
    type Err = <OutPoint as FromStr>::Err;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.parse::<OutPoint>().map(Self::new)
    }
}

impl Serialize for ContractId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ContractId", 2)?;
        state.serialize_field("txid", &self.txid())?;
        state.serialize_field("vout", &self.vout())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for ContractId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ContractIdWire {
            txid: Txid,
            vout: u32,
        }

        let value = ContractIdWire::deserialize(deserializer)?;
        Ok(Self::new(OutPoint::new(value.txid, value.vout)))
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

/// Exact chain on which the declarations in a contract package must exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainIdentity {
    pub network: LiquidNetwork,
    pub genesis_hash: BlockHash,
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

/// Complete public semantics needed to compile and independently verify one
/// supported contract family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ContractDescriptor {
    BinaryMarketV1 {
        params: BinaryMarketParams,
    },
    MakerOrderV1 {
        parent_market: ContractId,
        side: OrderSide,
        params: MakerOrderParams,
    },
}

impl ContractDescriptor {
    #[must_use]
    pub const fn kind(self) -> ContractKind {
        match self {
            Self::BinaryMarketV1 { .. } => ContractKind::BinaryMarketV1,
            Self::MakerOrderV1 { .. } => ContractKind::MakerOrderV1,
        }
    }

    #[must_use]
    pub const fn parent(self) -> Option<ContractId> {
        match self {
            Self::BinaryMarketV1 { .. } => None,
            Self::MakerOrderV1 { parent_market, .. } => Some(parent_market),
        }
    }
}

/// An untrusted claim that an exact creation-anchor outpoint instantiates a
/// particular contract descriptor. A node must verify the claim from its own
/// chain source before retaining it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractDeclaration {
    pub contract_id: ContractId,
    pub descriptor: ContractDescriptor,
}

/// Portable ingestion unit. Roots identify the contracts requested by the
/// sender; declarations may additionally carry their dependency closure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractPackage {
    pub format_version: u16,
    pub chain: ChainIdentity,
    pub roots: Vec<ContractId>,
    pub declarations: Vec<ContractDeclaration>,
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

/// Stable object-form serde for ordinary Elements outpoints. The upstream
/// type deliberately uses `"txid:vout"` for human-readable formats, while the
/// Deadcat wire schema keeps the two fields independently typed and strict.
pub mod serde_outpoint_object {
    use elements::{OutPoint, Txid};
    use serde::ser::SerializeStruct as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(outpoint: &OutPoint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("OutPoint", 2)?;
        state.serialize_field("txid", &outpoint.txid)?;
        state.serialize_field("vout", &outpoint.vout)?;
        state.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<OutPoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct OutPointWire {
            txid: Txid,
            vout: u32,
        }

        let value = OutPointWire::deserialize(deserializer)?;
        Ok(OutPoint::new(value.txid, value.vout))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_id_fixed_key_is_internal_txid_bytes_then_big_endian_vout() {
        let txid_bytes = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let txid = Txid::from_byte_array(txid_bytes);
        let id = ContractId::new(OutPoint::new(txid, 0x0102_0304));

        let key = id.to_fixed_key();
        assert_eq!(&key[..32], &txid_bytes);
        assert_eq!(&key[32..], &[1, 2, 3, 4]);
    }

    #[test]
    fn contract_id_has_stable_strict_object_json() {
        let id = ContractId::new(OutPoint::new(Txid::from_byte_array([0x22; 32]), 7));
        let json = serde_json::to_value(id).expect("serialize");

        assert_eq!(json["txid"], id.txid().to_string());
        assert_eq!(json["vout"], 7);
        assert_eq!(
            serde_json::from_value::<ContractId>(json).expect("deserialize"),
            id
        );

        let with_unknown = format!(r#"{{"txid":"{}","vout":7,"unknown":true}}"#, id.txid());
        assert!(serde_json::from_str::<ContractId>(&with_unknown).is_err());
        assert!(serde_json::from_str::<ContractId>(&format!(r#""{id}""#)).is_err());
    }

    #[test]
    fn contract_id_converts_and_round_trips_as_txid_colon_vout() {
        let anchor = OutPoint::new(Txid::from_byte_array([0x33; 32]), 42);
        let id = ContractId::from(anchor);

        assert_eq!(id.creation_anchor(), anchor);
        assert_eq!(id.txid(), anchor.txid);
        assert_eq!(id.vout(), anchor.vout);
        assert_eq!(OutPoint::from(id), anchor);
        assert_eq!(id.to_string().parse::<ContractId>().expect("parse"), id);
    }

    #[test]
    fn contract_package_round_trips_as_a_strict_versioned_chain_scoped_value() {
        let contract_id = ContractId::new(OutPoint::new(Txid::from_byte_array([0x33; 32]), 2));
        let params = BinaryMarketParams {
            oracle_public_key: [0x02; 32],
            collateral_asset_id: AssetId::from_slice(&[1; 32]).expect("asset"),
            yes_token_asset_id: AssetId::from_slice(&[2; 32]).expect("asset"),
            no_token_asset_id: AssetId::from_slice(&[3; 32]).expect("asset"),
            yes_reissuance_token_id: AssetId::from_slice(&[4; 32]).expect("asset"),
            no_reissuance_token_id: AssetId::from_slice(&[5; 32]).expect("asset"),
            base_payout: 100,
            expiry_height: 500,
        };
        let package = ContractPackage {
            format_version: CONTRACT_PACKAGE_FORMAT_VERSION,
            chain: ChainIdentity {
                network: LiquidNetwork::ElementsRegtest,
                genesis_hash: BlockHash::from_byte_array([0x44; 32]),
            },
            roots: vec![contract_id],
            declarations: vec![ContractDeclaration {
                contract_id,
                descriptor: ContractDescriptor::BinaryMarketV1 { params },
            }],
        };
        let mut json = serde_json::to_value(&package).expect("serialize");
        assert_eq!(
            serde_json::from_value::<ContractPackage>(json.clone()).expect("deserialize"),
            package
        );
        json.as_object_mut()
            .expect("package object")
            .insert("unknown".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<ContractPackage>(json).is_err());
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

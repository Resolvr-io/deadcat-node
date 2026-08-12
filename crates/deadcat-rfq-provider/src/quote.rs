//! Transport-free construction of exact, inventory-backed RFQ quotes.
//!
//! A quote describes only the provider's symbolic transaction contribution.
//! It deliberately does not contain a taker funding outpoint or a complete
//! PSET, so a client can combine the contribution with other venue legs.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use deadcat_types::{ChainIdentity, ContractId};
use elements::secp256k1_zkp::PublicKey;
use elements::{AssetId, OutPoint, Script, TxOut};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::inventory::{EligibleInventory, InventoryCoordinator, InventoryCoordinatorError};
use crate::model::{
    Clock, FeePolicy, IdempotencyKey, InventoryBinding, MAX_RESERVATION_INPUTS, OwnerId,
    ProviderIdentity, QuoteCommitment, QuoteRequestDigest, ReservationId, ReservationView,
    UnixMillis,
};
use crate::store::ProviderError;
use crate::wallet::{
    ConfidentialDestination, DestinationPurpose, DestinationSource, InventorySnapshotCommitment,
    InventorySource, WalletOwnedOutput, WalletScanAnchor,
};

const REQUEST_DOMAIN: &[u8] = b"deadcat/rfq/firm-quote-request/v1";
const QUOTE_DOMAIN: &[u8] = b"deadcat/rfq/firm-quote/v1";
const RECOVERY_METADATA_DOMAIN: &[u8] = b"deadcat/rfq/recovery-metadata/v1";
const STATIC_PRICING_DOMAIN: &[u8] = b"deadcat/rfq/static-rational-pricing/v1";

mod inventory_binding_serde {
    use serde::{Deserialize as _, Deserializer, Serialize as _, Serializer};

    use crate::model::InventoryBinding;

    pub(super) fn serialize<S>(value: &InventoryBinding, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.to_bytes().serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<InventoryBinding, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(InventoryBinding::new(<[u8; 32]>::deserialize(
            deserializer,
        )?))
    }
}

mod wallet_scan_anchor_serde {
    use elements::BlockHash;
    use elements::hashes::Hash as _;
    use serde::{Deserialize as _, Deserializer, Serialize as _, Serializer};

    use crate::wallet::WalletScanAnchor;

    pub(super) fn serialize<S>(value: &WalletScanAnchor, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (value.block_hash().to_byte_array(), value.block_height()).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<WalletScanAnchor, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (block_hash, block_height) = <([u8; 32], u32)>::deserialize(deserializer)?;
        Ok(WalletScanAnchor::new(
            BlockHash::from_byte_array(block_hash),
            block_height,
        ))
    }
}

mod inventory_snapshot_commitment_serde {
    use serde::{Deserialize as _, Deserializer, Serialize as _, Serializer};

    use crate::wallet::InventorySnapshotCommitment;

    pub(super) fn serialize<S>(
        value: &InventorySnapshotCommitment,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.to_bytes().serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<InventorySnapshotCommitment, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(InventorySnapshotCommitment::from_bytes(
            <[u8; 32]>::deserialize(deserializer)?,
        ))
    }
}

mod txout_serde {
    use elements::secp256k1_zkp::{RangeProof, SurjectionProof};
    use elements::{TxOut, TxOutWitness};
    use serde::de::Error as _;
    use serde::{Deserialize as _, Deserializer, Serialize as _, Serializer};

    #[derive(serde::Serialize, serde::Deserialize)]
    struct StoredTxOut {
        base: Vec<u8>,
        surjection_proof: Option<Vec<u8>>,
        rangeproof: Option<Vec<u8>>,
    }

    pub(super) fn serialize<S>(value: &TxOut, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        StoredTxOut {
            base: elements::encode::serialize(value),
            surjection_proof: value
                .witness
                .surjection_proof
                .as_deref()
                .map(SurjectionProof::serialize),
            rangeproof: value
                .witness
                .rangeproof
                .as_deref()
                .map(RangeProof::serialize),
        }
        .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<TxOut, D::Error>
    where
        D: Deserializer<'de>,
    {
        let stored = StoredTxOut::deserialize(deserializer)?;
        let mut txout =
            elements::encode::deserialize::<TxOut>(&stored.base).map_err(D::Error::custom)?;
        txout.witness = TxOutWitness {
            surjection_proof: stored
                .surjection_proof
                .map(|proof| SurjectionProof::from_slice(&proof).map(Box::new))
                .transpose()
                .map_err(D::Error::custom)?,
            rangeproof: stored
                .rangeproof
                .map(|proof| RangeProof::from_slice(&proof).map(Box::new))
                .transpose()
                .map_err(D::Error::custom)?,
        };
        Ok(txout)
    }
}

/// Initial provider-input limit, leaving room below the 64-input durable
/// safety ceiling and the client's whole-transaction resource limits.
pub const DEFAULT_MAX_QUOTE_INPUTS: usize = 8;
/// Initial duration used by tests and local configuration. Production should
/// tune this from measured preparation and signing latency.
pub const DEFAULT_QUOTE_LIFETIME_MILLIS: u64 = 30_000;
/// Initial per-owner count limit for live, uncommitted firm reservations.
pub const DEFAULT_MAX_LIVE_QUOTES_PER_OWNER: usize = 4;
/// Maximum search nodes spent looking for an exact bounded inventory subset
/// after the deterministic greedy selector cannot make policy-compliant
/// change. Hitting the budget is reported distinctly from true fragmentation.
pub const DEFAULT_SELECTION_SEARCH_NODE_BUDGET: usize = 250_000;
/// Maximum accepted taker destination script, aligned with the client
/// transaction composer's default resource limit.
pub const MAX_QUOTE_RECIPIENT_SCRIPT_BYTES: usize = 10_000;

/// Exact chain and market context bound by a firm quote.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteContext {
    chain: ChainIdentity,
    market: ContractId,
    policy_asset: AssetId,
}

impl QuoteContext {
    #[must_use]
    pub const fn new(chain: ChainIdentity, market: ContractId, policy_asset: AssetId) -> Self {
        Self {
            chain,
            market,
            policy_asset,
        }
    }

    #[must_use]
    pub const fn chain(self) -> ChainIdentity {
        self.chain
    }

    #[must_use]
    pub const fn market(self) -> ContractId {
        self.market
    }

    #[must_use]
    pub const fn policy_asset(self) -> AssetId {
        self.policy_asset
    }
}

/// Exact amount of one Liquid asset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetAmount {
    asset: AssetId,
    amount: u64,
}

impl AssetAmount {
    pub fn new(asset: AssetId, amount: u64) -> Result<Self, QuoteModelError> {
        if amount == 0 {
            return Err(QuoteModelError::ZeroAmount);
        }
        Ok(Self { asset, amount })
    }

    #[must_use]
    pub const fn asset(self) -> AssetId {
        self.asset
    }

    #[must_use]
    pub const fn amount(self) -> u64 {
        self.amount
    }
}

/// Confidential destination selected by the taker or provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteRecipient {
    script_pubkey: Script,
    blinding_public_key: PublicKey,
}

impl QuoteRecipient {
    pub fn new(
        script_pubkey: Script,
        blinding_public_key: PublicKey,
    ) -> Result<Self, QuoteModelError> {
        if script_pubkey.is_empty()
            || script_pubkey.is_provably_unspendable()
            || script_pubkey.len() > MAX_QUOTE_RECIPIENT_SCRIPT_BYTES
        {
            return Err(QuoteModelError::InvalidRecipientScript);
        }
        Ok(Self {
            script_pubkey,
            blinding_public_key,
        })
    }

    #[must_use]
    pub const fn script_pubkey(&self) -> &Script {
        &self.script_pubkey
    }

    #[must_use]
    pub const fn blinding_public_key(&self) -> PublicKey {
        self.blinding_public_key
    }

    fn validate(&self) -> Result<(), QuoteModelError> {
        if self.script_pubkey.is_empty()
            || self.script_pubkey.is_provably_unspendable()
            || self.script_pubkey.len() > MAX_QUOTE_RECIPIENT_SCRIPT_BYTES
        {
            return Err(QuoteModelError::InvalidRecipientScript);
        }
        Ok(())
    }
}

impl From<&ConfidentialDestination> for QuoteRecipient {
    fn from(value: &ConfidentialDestination) -> Self {
        Self {
            script_pubkey: value.script_pubkey().clone(),
            blinding_public_key: value.blinding_public_key(),
        }
    }
}

/// Exact-side semantics and the taker's per-leg economic guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuoteKind {
    ExactIn {
        input: AssetAmount,
        output_asset: AssetId,
        minimum_output: u64,
    },
    ExactOut {
        input_asset: AssetId,
        maximum_input: u64,
        output: AssetAmount,
    },
}

impl QuoteKind {
    fn validate(self) -> Result<Self, QuoteModelError> {
        let (input_asset, input_bound, output_asset, output_bound) = match self {
            Self::ExactIn {
                input,
                output_asset,
                minimum_output,
            } => (input.asset, input.amount, output_asset, minimum_output),
            Self::ExactOut {
                input_asset,
                maximum_input,
                output,
            } => (input_asset, maximum_input, output.asset, output.amount),
        };
        if input_asset == output_asset {
            return Err(QuoteModelError::SameAssetPair);
        }
        if input_bound == 0 || output_bound == 0 {
            return Err(QuoteModelError::ZeroAmount);
        }
        Ok(self)
    }

    #[must_use]
    pub const fn pair(self) -> (AssetId, AssetId) {
        match self {
            Self::ExactIn {
                input,
                output_asset,
                ..
            } => (input.asset, output_asset),
            Self::ExactOut {
                input_asset,
                output,
                ..
            } => (input_asset, output.asset),
        }
    }
}

/// Validated semantic request.
///
/// The engine does not authenticate callers. Its embedding transport must
/// authenticate the caller and derive the separately supplied [`OwnerId`]
/// from that identity; neither owner nor idempotency key is sent to a pricing
/// policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirmQuoteRequest {
    context: QuoteContext,
    kind: QuoteKind,
    recipient: QuoteRecipient,
    maximum_input_asset_venue_fee: u64,
}

impl FirmQuoteRequest {
    pub fn new(
        context: QuoteContext,
        kind: QuoteKind,
        recipient: QuoteRecipient,
        maximum_input_asset_venue_fee: u64,
    ) -> Result<Self, QuoteModelError> {
        recipient.validate()?;
        Ok(Self {
            context,
            kind: kind.validate()?,
            recipient,
            maximum_input_asset_venue_fee,
        })
    }

    #[must_use]
    pub const fn context(&self) -> QuoteContext {
        self.context
    }

    #[must_use]
    pub const fn kind(&self) -> QuoteKind {
        self.kind
    }

    #[must_use]
    pub const fn recipient(&self) -> &QuoteRecipient {
        &self.recipient
    }

    #[must_use]
    pub const fn maximum_input_asset_venue_fee(&self) -> u64 {
        self.maximum_input_asset_venue_fee
    }

    fn validate(&self) -> Result<(), QuoteAdmissionError> {
        self.kind.validate().map_err(QuoteAdmissionError::from)?;
        self.recipient.validate().map_err(QuoteAdmissionError::from)
    }
}

/// Assets belonging to one binary market.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BinaryMarketAssets {
    collateral: AssetId,
    yes: AssetId,
    no: AssetId,
}

impl BinaryMarketAssets {
    pub fn new(
        collateral: AssetId,
        yes: AssetId,
        no: AssetId,
    ) -> Result<Self, QuoteConfigurationError> {
        if collateral == yes || collateral == no || yes == no {
            return Err(QuoteConfigurationError::MarketAssetsNotDistinct);
        }
        Ok(Self {
            collateral,
            yes,
            no,
        })
    }

    #[must_use]
    pub const fn collateral(self) -> AssetId {
        self.collateral
    }

    #[must_use]
    pub const fn yes(self) -> AssetId {
        self.yes
    }

    #[must_use]
    pub const fn no(self) -> AssetId {
        self.no
    }

    fn contains(self, asset: AssetId) -> bool {
        asset == self.collateral || asset == self.yes || asset == self.no
    }

    fn is_launch_pair(self, input: AssetId, output: AssetId) -> bool {
        self.contains(input)
            && self.contains(output)
            && input != output
            && (input == self.collateral || output == self.collateral)
    }
}

/// Inclusive nonzero amount range in atomic asset units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AmountRange {
    minimum: u64,
    maximum: u64,
}

impl AmountRange {
    pub fn new(minimum: u64, maximum: u64) -> Result<Self, QuoteConfigurationError> {
        if minimum == 0 || minimum > maximum {
            return Err(QuoteConfigurationError::InvalidAmountRange { minimum, maximum });
        }
        Ok(Self { minimum, maximum })
    }

    #[must_use]
    pub const fn minimum(self) -> u64 {
        self.minimum
    }

    #[must_use]
    pub const fn maximum(self) -> u64 {
        self.maximum
    }

    fn contains(self, amount: u64) -> bool {
        (self.minimum..=self.maximum).contains(&amount)
    }
}

/// Resource and fill limits for one directed pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairLimits {
    input: AmountRange,
    output: AmountRange,
    maximum_provider_inputs: usize,
    minimum_positive_change: u64,
    selection_search_node_budget: usize,
}

impl PairLimits {
    pub fn new(
        input: AmountRange,
        output: AmountRange,
        maximum_provider_inputs: usize,
        minimum_positive_change: u64,
    ) -> Result<Self, QuoteConfigurationError> {
        if maximum_provider_inputs == 0 || maximum_provider_inputs > MAX_RESERVATION_INPUTS {
            return Err(QuoteConfigurationError::InvalidProviderInputLimit {
                actual: maximum_provider_inputs,
                maximum: MAX_RESERVATION_INPUTS,
            });
        }
        Ok(Self {
            input,
            output,
            maximum_provider_inputs,
            minimum_positive_change,
            selection_search_node_budget: DEFAULT_SELECTION_SEARCH_NODE_BUDGET,
        })
    }

    #[must_use]
    pub fn launch_default(input: AmountRange, output: AmountRange) -> Self {
        Self {
            input,
            output,
            maximum_provider_inputs: DEFAULT_MAX_QUOTE_INPUTS,
            minimum_positive_change: 0,
            selection_search_node_budget: DEFAULT_SELECTION_SEARCH_NODE_BUDGET,
        }
    }

    #[must_use]
    pub const fn input(self) -> AmountRange {
        self.input
    }

    #[must_use]
    pub const fn output(self) -> AmountRange {
        self.output
    }

    #[must_use]
    pub const fn maximum_provider_inputs(self) -> usize {
        self.maximum_provider_inputs
    }

    #[must_use]
    pub const fn minimum_positive_change(self) -> u64 {
        self.minimum_positive_change
    }

    /// Bound the exact-subset fallback used when greedy selection would create
    /// dust. This is primarily useful for deterministic tests and deployments
    /// with unusually fragmented wallets.
    pub fn with_selection_search_node_budget(
        mut self,
        selection_search_node_budget: usize,
    ) -> Result<Self, QuoteConfigurationError> {
        if selection_search_node_budget == 0 {
            return Err(QuoteConfigurationError::ZeroSelectionSearchNodeBudget);
        }
        self.selection_search_node_budget = selection_search_node_budget;
        Ok(self)
    }

    #[must_use]
    pub const fn selection_search_node_budget(self) -> usize {
        self.selection_search_node_budget
    }
}

/// One independently configured quote direction. Reverse rates and limits are
/// never inferred.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairRule {
    input_asset: AssetId,
    output_asset: AssetId,
    limits: PairLimits,
}

impl PairRule {
    #[must_use]
    pub const fn new(input_asset: AssetId, output_asset: AssetId, limits: PairLimits) -> Self {
        Self {
            input_asset,
            output_asset,
            limits,
        }
    }

    #[must_use]
    pub const fn input_asset(self) -> AssetId {
        self.input_asset
    }

    #[must_use]
    pub const fn output_asset(self) -> AssetId {
        self.output_asset
    }

    #[must_use]
    pub const fn limits(self) -> PairLimits {
        self.limits
    }
}

/// Configured binary market and its enabled launch directions.
///
/// This type checks internal consistency only. The embedding service must
/// construct it from independently chain-validated canonical market
/// parameters; a [`ContractId`] alone does not authenticate these asset IDs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarketQuoteConfig {
    context: QuoteContext,
    assets: BinaryMarketAssets,
    pairs: Vec<PairRule>,
}

impl MarketQuoteConfig {
    pub fn new(
        context: QuoteContext,
        assets: BinaryMarketAssets,
        mut pairs: Vec<PairRule>,
    ) -> Result<Self, QuoteConfigurationError> {
        let anchor = context.market.creation_anchor();
        if anchor.is_null() || anchor.vout & 0xc000_0000 != 0 {
            return Err(QuoteConfigurationError::InvalidMarketId(context.market));
        }
        if pairs.is_empty() {
            return Err(QuoteConfigurationError::NoEnabledPairs);
        }
        pairs.sort_by_key(|rule| {
            (
                rule.input_asset.into_inner().to_byte_array(),
                rule.output_asset.into_inner().to_byte_array(),
            )
        });
        let mut seen = BTreeSet::new();
        for rule in &pairs {
            if !assets.is_launch_pair(rule.input_asset, rule.output_asset) {
                return Err(QuoteConfigurationError::UnsupportedPair {
                    input: rule.input_asset,
                    output: rule.output_asset,
                });
            }
            if !seen.insert((
                rule.input_asset.into_inner().to_byte_array(),
                rule.output_asset.into_inner().to_byte_array(),
            )) {
                return Err(QuoteConfigurationError::DuplicatePair {
                    input: rule.input_asset,
                    output: rule.output_asset,
                });
            }
        }
        Ok(Self {
            context,
            assets,
            pairs,
        })
    }

    #[must_use]
    pub const fn context(&self) -> QuoteContext {
        self.context
    }

    #[must_use]
    pub const fn assets(&self) -> BinaryMarketAssets {
        self.assets
    }

    #[must_use]
    pub fn pairs(&self) -> &[PairRule] {
        &self.pairs
    }
}

#[derive(Clone, Debug)]
struct PairCatalog {
    markets: Vec<MarketQuoteConfig>,
}

impl PairCatalog {
    fn new(
        identity: ProviderIdentity,
        mut markets: Vec<MarketQuoteConfig>,
    ) -> Result<Self, QuoteConfigurationError> {
        if markets.is_empty() {
            return Err(QuoteConfigurationError::NoMarkets);
        }
        markets.sort_by_key(|market| market.context.market);
        let mut previous = None;
        for market in &markets {
            if market.context.chain.genesis_hash != identity.genesis_hash() {
                return Err(QuoteConfigurationError::WrongGenesis);
            }
            if market.context.policy_asset != identity.policy_asset() {
                return Err(QuoteConfigurationError::WrongPolicyAsset);
            }
            if previous == Some(market.context.market) {
                return Err(QuoteConfigurationError::DuplicateMarket(
                    market.context.market,
                ));
            }
            previous = Some(market.context.market);
        }
        Ok(Self { markets })
    }

    fn resolve(
        &self,
        context: QuoteContext,
        input: AssetId,
        output: AssetId,
    ) -> Result<(&MarketQuoteConfig, PairRule), QuoteAdmissionError> {
        let market = self
            .markets
            .iter()
            .find(|market| market.context == context)
            .ok_or(QuoteAdmissionError::MarketNotConfigured)?;
        let pair = market
            .pairs
            .iter()
            .copied()
            .find(|rule| rule.input_asset == input && rule.output_asset == output)
            .ok_or(QuoteAdmissionError::PairNotConfigured)?;
        Ok((market, pair))
    }
}

/// Reduced inventory information exposed to pricing. It contains no
/// outpoints, denominations, openings, wallet locators, keys, or recipient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InventorySummary {
    balances: Vec<AssetAmount>,
}

impl InventorySummary {
    #[must_use]
    pub fn balances(&self) -> &[AssetAmount] {
        &self.balances
    }

    #[must_use]
    pub fn amount(&self, asset: AssetId) -> u64 {
        self.balances
            .iter()
            .find(|balance| balance.asset == asset)
            .map_or(0, |balance| balance.amount)
    }
}

/// Normalized positive rational, interpreted as output units per input unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RationalRate {
    numerator: u64,
    denominator: u64,
}

impl RationalRate {
    pub fn new(numerator: u64, denominator: u64) -> Result<Self, QuoteModelError> {
        if numerator == 0 || denominator == 0 {
            return Err(QuoteModelError::ZeroRate);
        }
        let divisor = gcd(numerator, denominator);
        Ok(Self {
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        })
    }

    #[must_use]
    pub const fn numerator(self) -> u64 {
        self.numerator
    }

    #[must_use]
    pub const fn denominator(self) -> u64 {
        self.denominator
    }
}

const fn gcd(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

/// Stable identity of a pricing configuration or implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PricingPolicyId([u8; 32]);

impl PricingPolicyId {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Monotonic operator-selected revision of a pricing policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PricingRevision(u64);

impl PricingRevision {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Exact-side amount visible to the price policy, without the user's guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PricingSide {
    ExactIn { gross_input: AssetAmount },
    ExactOut { output: AssetAmount },
}

/// Redacted pricing request.
#[derive(Clone, Copy, Debug)]
pub struct PricingRequest<'a> {
    context: QuoteContext,
    input_asset: AssetId,
    output_asset: AssetId,
    side: PricingSide,
    inventory: &'a InventorySummary,
}

impl PricingRequest<'_> {
    #[must_use]
    pub const fn context(&self) -> QuoteContext {
        self.context
    }

    #[must_use]
    pub const fn input_asset(&self) -> AssetId {
        self.input_asset
    }

    #[must_use]
    pub const fn output_asset(&self) -> AssetId {
        self.output_asset
    }

    #[must_use]
    pub const fn side(&self) -> PricingSide {
        self.side
    }

    #[must_use]
    pub const fn inventory(&self) -> &InventorySummary {
        self.inventory
    }
}

/// Pricing result. The fee is denominated in the trade input asset and is
/// included in the taker's gross debit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PricingDecision {
    rate: RationalRate,
    input_asset_venue_fee: u64,
    policy_id: PricingPolicyId,
    revision: PricingRevision,
}

impl PricingDecision {
    #[must_use]
    pub const fn new(
        rate: RationalRate,
        input_asset_venue_fee: u64,
        policy_id: PricingPolicyId,
        revision: PricingRevision,
    ) -> Self {
        Self {
            rate,
            input_asset_venue_fee,
            policy_id,
            revision,
        }
    }

    #[must_use]
    pub const fn rate(self) -> RationalRate {
        self.rate
    }

    #[must_use]
    pub const fn input_asset_venue_fee(self) -> u64 {
        self.input_asset_venue_fee
    }

    #[must_use]
    pub const fn policy_id(self) -> PricingPolicyId {
        self.policy_id
    }

    #[must_use]
    pub const fn revision(self) -> PricingRevision {
        self.revision
    }

    fn validate(self) -> Result<(), QuoteAdmissionError> {
        if self.rate.numerator == 0 || self.rate.denominator == 0 {
            return Err(QuoteAdmissionError::InvalidPricingDecision);
        }
        if gcd(self.rate.numerator, self.rate.denominator) != 1 {
            return Err(QuoteAdmissionError::InvalidPricingDecision);
        }
        Ok(())
    }
}

/// Injected pricing strategy. The engine, not the strategy, applies and checks
/// exact integer rounding.
pub trait PricingPolicy {
    type Error: Error + Send + Sync + 'static;

    fn price(&self, request: PricingRequest<'_>) -> Result<PricingDecision, Self::Error>;
}

/// One independently configured static directed rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaticRateRule {
    market: ContractId,
    input_asset: AssetId,
    output_asset: AssetId,
    rate: RationalRate,
}

impl StaticRateRule {
    #[must_use]
    pub const fn new(
        market: ContractId,
        input_asset: AssetId,
        output_asset: AssetId,
        rate: RationalRate,
    ) -> Self {
        Self {
            market,
            input_asset,
            output_asset,
            rate,
        }
    }
}

/// Simple spread-only pricing suitable for configuration and deterministic
/// tests. Every enabled direction must have its own explicit rate.
#[derive(Clone, Debug)]
pub struct StaticRationalPricing {
    rules: Vec<StaticRateRule>,
    policy_id: PricingPolicyId,
    revision: PricingRevision,
}

impl StaticRationalPricing {
    pub fn new(
        mut rules: Vec<StaticRateRule>,
        revision: PricingRevision,
    ) -> Result<Self, StaticPricingError> {
        if rules.is_empty() {
            return Err(StaticPricingError::NoRates);
        }
        rules.sort_by_key(static_rate_key);
        if let Some(duplicate) = rules
            .windows(2)
            .find(|pair| static_rate_key(&pair[0]) == static_rate_key(&pair[1]))
            .map(|pair| pair[0])
        {
            return Err(StaticPricingError::DuplicateRate {
                market: duplicate.market,
                input: duplicate.input_asset,
                output: duplicate.output_asset,
            });
        }
        let transcript = rules
            .iter()
            .map(|rule| StoredStaticRateV1 {
                market: rule.market.creation_anchor(),
                input_asset: rule.input_asset,
                output_asset: rule.output_asset,
                numerator: rule.rate.numerator,
                denominator: rule.rate.denominator,
            })
            .collect::<Vec<_>>();
        let policy_id = PricingPolicyId(domain_digest(
            STATIC_PRICING_DOMAIN,
            &StoredStaticPricingV1 {
                revision: revision.value(),
                rules: &transcript,
            },
        )?);
        Ok(Self {
            rules,
            policy_id,
            revision,
        })
    }

    #[must_use]
    pub const fn policy_id(&self) -> PricingPolicyId {
        self.policy_id
    }
}

impl PricingPolicy for StaticRationalPricing {
    type Error = StaticPricingError;

    fn price(&self, request: PricingRequest<'_>) -> Result<PricingDecision, Self::Error> {
        let rule = self
            .rules
            .iter()
            .find(|rule| {
                rule.market == request.context.market
                    && rule.input_asset == request.input_asset
                    && rule.output_asset == request.output_asset
            })
            .ok_or(StaticPricingError::RateNotConfigured)?;
        Ok(PricingDecision::new(
            rule.rate,
            0,
            self.policy_id,
            self.revision,
        ))
    }
}

fn static_rate_key(rule: &StaticRateRule) -> ([u8; 36], [u8; 32], [u8; 32]) {
    (
        rule.market.to_fixed_key(),
        rule.input_asset.into_inner().to_byte_array(),
        rule.output_asset.into_inner().to_byte_array(),
    )
}

/// Exact gross taker debit and net taker receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteExecution {
    input: AssetAmount,
    output: AssetAmount,
    input_asset_venue_fee: u64,
}

impl QuoteExecution {
    #[must_use]
    pub const fn input(self) -> AssetAmount {
        self.input
    }

    #[must_use]
    pub const fn output(self) -> AssetAmount {
        self.output
    }

    #[must_use]
    pub const fn input_asset_venue_fee(self) -> u64 {
        self.input_asset_venue_fee
    }
}

/// Quote-local symbolic input identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct QuoteInputId(u16);

impl QuoteInputId {
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// Quote-local symbolic output identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct QuoteOutputId(u16);

impl QuoteOutputId {
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// Input responsible for blinding an exact quoted output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuoteBlinderRole {
    /// Resolved client-side to whichever taker input funds the route.
    TakerPaymentInput,
    /// One provider input local to this quote contribution.
    ProviderInput(QuoteInputId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuoteOutputRole {
    ProviderPayment,
    TakerReceive,
    ProviderChange,
}

/// Full public provider prevout required by client transaction composition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotedProviderInput {
    id: QuoteInputId,
    outpoint: OutPoint,
    #[serde(with = "txout_serde")]
    witness_utxo: TxOut,
    #[serde(with = "inventory_binding_serde")]
    inventory_binding: InventoryBinding,
}

impl QuotedProviderInput {
    #[must_use]
    pub const fn id(&self) -> QuoteInputId {
        self.id
    }

    #[must_use]
    pub const fn outpoint(&self) -> OutPoint {
        self.outpoint
    }

    #[must_use]
    pub const fn witness_utxo(&self) -> &TxOut {
        &self.witness_utxo
    }

    #[must_use]
    pub const fn inventory_binding(&self) -> InventoryBinding {
        self.inventory_binding
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotedOutput {
    id: QuoteOutputId,
    role: QuoteOutputRole,
    asset: AssetId,
    amount: u64,
    destination: QuoteRecipient,
    blinder: QuoteBlinderRole,
}

impl QuotedOutput {
    #[must_use]
    pub const fn id(&self) -> QuoteOutputId {
        self.id
    }

    #[must_use]
    pub const fn role(&self) -> QuoteOutputRole {
        self.role
    }

    #[must_use]
    pub const fn asset(&self) -> AssetId {
        self.asset
    }

    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount
    }

    #[must_use]
    pub const fn destination(&self) -> &QuoteRecipient {
        &self.destination
    }

    #[must_use]
    pub const fn blinder(&self) -> QuoteBlinderRole {
        self.blinder
    }
}

/// Provider-owned symbolic fragment. V1 inputs use final sequence and the
/// contribution makes no transaction locktime claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteContribution {
    inputs: Vec<QuotedProviderInput>,
    outputs: Vec<QuotedOutput>,
}

impl QuoteContribution {
    #[must_use]
    pub fn inputs(&self) -> &[QuotedProviderInput] {
        &self.inputs
    }

    #[must_use]
    pub fn outputs(&self) -> &[QuotedOutput] {
        &self.outputs
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteSnapshotEvidence {
    #[serde(with = "wallet_scan_anchor_serde")]
    anchor: WalletScanAnchor,
    #[serde(with = "inventory_snapshot_commitment_serde")]
    commitment: InventorySnapshotCommitment,
    allocation_revision: u64,
    eligible_commitment: [u8; 32],
}

impl QuoteSnapshotEvidence {
    #[must_use]
    pub const fn anchor(self) -> WalletScanAnchor {
        self.anchor
    }

    #[must_use]
    pub const fn commitment(self) -> InventorySnapshotCommitment {
        self.commitment
    }

    /// Durable allocation revision used for the final compare-and-swap.
    #[must_use]
    pub const fn allocation_revision(self) -> u64 {
        self.allocation_revision
    }

    /// Commitment to the exact inventory set presented to pricing.
    #[must_use]
    pub const fn eligible_commitment(self) -> [u8; 32] {
        self.eligible_commitment
    }
}

/// Exact non-secret quote artifact durably replayed for one semantic request.
///
/// This internal artifact is not a wire message, provider signature, or
/// attestation. A remote RFQ protocol must authenticate its caller-provided
/// owner and authenticate whatever response envelope carries this value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirmQuote {
    reservation_id: ReservationId,
    provider: ProviderIdentity,
    request: FirmQuoteRequest,
    execution: QuoteExecution,
    pricing: PricingDecision,
    snapshot: QuoteSnapshotEvidence,
    contribution: QuoteContribution,
    created_at: UnixMillis,
    accept_before: UnixMillis,
    fee_policy: FeePolicy,
    recovery_metadata_commitment: [u8; 32],
    commitment: QuoteCommitment,
}

impl FirmQuote {
    #[must_use]
    pub const fn reservation_id(&self) -> ReservationId {
        self.reservation_id
    }

    #[must_use]
    pub const fn provider(&self) -> ProviderIdentity {
        self.provider
    }

    #[must_use]
    pub const fn request(&self) -> &FirmQuoteRequest {
        &self.request
    }

    #[must_use]
    pub const fn execution(&self) -> QuoteExecution {
        self.execution
    }

    #[must_use]
    pub const fn pricing(&self) -> PricingDecision {
        self.pricing
    }

    #[must_use]
    pub const fn snapshot(&self) -> QuoteSnapshotEvidence {
        self.snapshot
    }

    #[must_use]
    pub const fn contribution(&self) -> &QuoteContribution {
        &self.contribution
    }

    #[must_use]
    pub const fn created_at(&self) -> UnixMillis {
        self.created_at
    }

    #[must_use]
    pub const fn accept_before(&self) -> UnixMillis {
        self.accept_before
    }

    #[must_use]
    pub const fn fee_policy(&self) -> FeePolicy {
        self.fee_policy
    }

    /// Opaque binding to provider-only receive/change recovery metadata.
    ///
    /// The preimage contains wallet locators and is deliberately never exposed
    /// by a firm quote. This commitment only detects accidental durable-state
    /// disagreement; it is not provider authentication.
    #[must_use]
    pub const fn recovery_metadata_commitment(&self) -> [u8; 32] {
        self.recovery_metadata_commitment
    }

    #[must_use]
    pub const fn commitment(&self) -> QuoteCommitment {
        self.commitment
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirmQuoteOutcome {
    quote: FirmQuote,
    reservation: ReservationView,
    created: bool,
}

impl FirmQuoteOutcome {
    #[must_use]
    pub const fn quote(&self) -> &FirmQuote {
        &self.quote
    }

    #[must_use]
    pub const fn reservation(&self) -> &ReservationView {
        &self.reservation
    }

    /// Whether this outcome created the reservation in this call.
    ///
    /// A `false` outcome is exact durable replay and may be terminal. Callers
    /// must inspect [`ReservationView::state`] before treating the quote as
    /// currently acceptable; replay never resurrects an expired, cancelled,
    /// committed, or signed reservation.
    #[must_use]
    pub const fn created(&self) -> bool {
        self.created
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DestinationRecovery {
    pub(crate) internal_key: [u8; 32],
    pub(crate) wallet_locator: [u8; 32],
}

impl From<&ConfidentialDestination> for DestinationRecovery {
    fn from(value: &ConfidentialDestination) -> Self {
        Self {
            internal_key: value.internal_key().serialize(),
            wallet_locator: value.wallet_locator().to_bytes(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct FirmQuoteDraft {
    pub(crate) request: FirmQuoteRequest,
    pub(crate) execution: QuoteExecution,
    pub(crate) pricing: PricingDecision,
    pub(crate) snapshot: QuoteSnapshotEvidence,
    pub(crate) contribution: QuoteContribution,
    pub(crate) provider_receive_recovery: DestinationRecovery,
    pub(crate) provider_change_recovery: Option<DestinationRecovery>,
    pub(crate) selected_asset: AssetId,
    pub(crate) selected_amount: u64,
}

impl FirmQuoteDraft {
    pub(crate) fn selected_outpoints(&self) -> Vec<OutPoint> {
        self.contribution
            .inputs
            .iter()
            .map(|input| input.outpoint)
            .collect()
    }

    pub(crate) fn validate(&self) -> Result<(), QuoteAdmissionError> {
        self.request.validate()?;
        self.pricing.validate()?;
        if self.selected_amount == 0 || self.selected_asset != self.execution.output.asset {
            return Err(QuoteAdmissionError::InvalidDerivedQuote);
        }
        let change = self
            .selected_amount
            .checked_sub(self.execution.output.amount)
            .ok_or(QuoteAdmissionError::InvalidDerivedQuote)?;
        if self.contribution.inputs.is_empty()
            || self.contribution.inputs.len() > MAX_RESERVATION_INPUTS
        {
            return Err(QuoteAdmissionError::InvalidDerivedQuote);
        }
        for (index, input) in self.contribution.inputs.iter().enumerate() {
            let id =
                u16::try_from(index + 1).map_err(|_| QuoteAdmissionError::InvalidDerivedQuote)?;
            if input.id.value() != id {
                return Err(QuoteAdmissionError::InvalidDerivedQuote);
            }
        }
        let expected_output_count = if change == 0 { 2 } else { 3 };
        if self.contribution.outputs.len() != expected_output_count {
            return Err(QuoteAdmissionError::InvalidDerivedQuote);
        }
        let outputs = &self.contribution.outputs;
        let provider_blinder = QuoteBlinderRole::ProviderInput(self.contribution.inputs[0].id);
        if outputs[0].id != QuoteOutputId(1)
            || outputs[0].role != QuoteOutputRole::ProviderPayment
            || outputs[0].asset != self.execution.input.asset
            || outputs[0].amount != self.execution.input.amount
            || outputs[0].blinder != QuoteBlinderRole::TakerPaymentInput
            || outputs[1].id != QuoteOutputId(2)
            || outputs[1].role != QuoteOutputRole::TakerReceive
            || outputs[1].asset != self.execution.output.asset
            || outputs[1].amount != self.execution.output.amount
            || outputs[1].destination != self.request.recipient
            || outputs[1].blinder != provider_blinder
        {
            return Err(QuoteAdmissionError::InvalidDerivedQuote);
        }
        if change != 0
            && (outputs[2].id != QuoteOutputId(3)
                || outputs[2].role != QuoteOutputRole::ProviderChange
                || outputs[2].asset != self.selected_asset
                || outputs[2].amount != change
                || outputs[2].blinder != provider_blinder)
        {
            return Err(QuoteAdmissionError::InvalidDerivedQuote);
        }
        Ok(())
    }
}

/// Service-level firm-quote policy. Per-asset amount caps and reserve floors
/// are deployment-specific and can be added without changing quote semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuoteEnginePolicy {
    quote_lifetime_millis: u64,
    maximum_live_quotes_per_owner: usize,
    maximum_live_quotes_global: usize,
    fee_policy: FeePolicy,
}

impl QuoteEnginePolicy {
    pub fn new(
        quote_lifetime_millis: u64,
        maximum_live_quotes_per_owner: usize,
        maximum_live_quotes_global: usize,
        fee_policy: FeePolicy,
    ) -> Result<Self, QuoteConfigurationError> {
        if quote_lifetime_millis == 0 {
            return Err(QuoteConfigurationError::ZeroQuoteLifetime);
        }
        if maximum_live_quotes_per_owner == 0 || maximum_live_quotes_global == 0 {
            return Err(QuoteConfigurationError::ZeroLiveQuoteLimit);
        }
        if maximum_live_quotes_per_owner > maximum_live_quotes_global {
            return Err(QuoteConfigurationError::OwnerLimitExceedsGlobal);
        }
        Ok(Self {
            quote_lifetime_millis,
            maximum_live_quotes_per_owner,
            maximum_live_quotes_global,
            fee_policy,
        })
    }

    #[must_use]
    pub fn launch_default(fee_policy: FeePolicy) -> Self {
        Self {
            quote_lifetime_millis: DEFAULT_QUOTE_LIFETIME_MILLIS,
            maximum_live_quotes_per_owner: DEFAULT_MAX_LIVE_QUOTES_PER_OWNER,
            maximum_live_quotes_global: 1_024,
            fee_policy,
        }
    }

    #[must_use]
    pub const fn quote_lifetime_millis(self) -> u64 {
        self.quote_lifetime_millis
    }

    #[must_use]
    pub const fn maximum_live_quotes_per_owner(self) -> usize {
        self.maximum_live_quotes_per_owner
    }

    #[must_use]
    pub const fn maximum_live_quotes_global(self) -> usize {
        self.maximum_live_quotes_global
    }

    #[must_use]
    pub const fn fee_policy(self) -> FeePolicy {
        self.fee_policy
    }
}

/// Exact quote construction over fresh wallet inventory.
///
/// The embedding service must supply chain-validated market configuration,
/// authenticate `owner` at its transport boundary, enforce request-rate and
/// durable-retention policy, and restart the whole quote operation after
/// [`ProviderError::EligibleInventoryChanged`]. Retrying only the final
/// reservation with a stale draft is invalid, and destinations already issued
/// during a lost race must remain permanently burned.
pub struct QuoteEngine<S, D, P> {
    inventory: InventoryCoordinator<S>,
    destinations: D,
    pricing: P,
    catalog: PairCatalog,
    policy: QuoteEnginePolicy,
}

impl<S, D, P> QuoteEngine<S, D, P>
where
    S: InventorySource,
    D: DestinationSource,
    P: PricingPolicy,
{
    pub fn new(
        inventory: InventoryCoordinator<S>,
        destinations: D,
        pricing: P,
        markets: Vec<MarketQuoteConfig>,
        policy: QuoteEnginePolicy,
    ) -> Result<Self, QuoteConfigurationError> {
        let identity = inventory.identity();
        if policy.fee_policy.policy_asset() != identity.policy_asset() {
            return Err(QuoteConfigurationError::WrongPolicyAsset);
        }
        Ok(Self {
            catalog: PairCatalog::new(identity, markets)?,
            inventory,
            destinations,
            pricing,
            policy,
        })
    }

    #[must_use]
    pub const fn inventory(&self) -> &InventoryCoordinator<S> {
        &self.inventory
    }

    /// Issue or exactly replay one inventory-backed firm quote.
    #[allow(clippy::type_complexity)]
    pub fn firm_quote<C: Clock>(
        &self,
        owner: OwnerId,
        key: IdempotencyKey,
        request: FirmQuoteRequest,
        clock: &C,
    ) -> Result<FirmQuoteOutcome, QuoteEngineError<S::Error, D::Error, P::Error>> {
        request.validate().map_err(QuoteEngineError::Admission)?;
        let request_digest = quote_request_digest(self.inventory.identity(), owner, key, &request)
            .map_err(QuoteEngineError::Provider)?;
        if let Some(replayed) = self
            .inventory
            .reservation_book()
            .preflight_firm_quote(owner, key, request_digest, self.policy, clock)
            .map_err(QuoteEngineError::Provider)?
        {
            return Ok(replayed);
        }

        // The bounded preflight sweep keeps each write predictable, but there
        // may be more than one batch of expired allocations. Re-evaluate the
        // current asset view after each committed batch before pricing or
        // destination generation; otherwise an expired output beyond the first
        // batch could look unavailable and cause a false insufficient-inventory
        // rejection. This loop is intentionally outside any one redb write.
        loop {
            let expired = self
                .inventory
                .reservation_book()
                .expire_due(clock, crate::store::MAX_EXPIRATION_BATCH)
                .map_err(QuoteEngineError::Provider)?;
            if expired.len() < crate::store::MAX_EXPIRATION_BATCH {
                break;
            }
        }

        let (input_asset, output_asset) = request.kind.pair();
        let (market, pair) = self
            .catalog
            .resolve(request.context, input_asset, output_asset)
            .map_err(QuoteEngineError::Admission)?;
        let eligible = self
            .inventory
            .eligible(clock)
            .map_err(QuoteEngineError::Inventory)?;
        let summary =
            inventory_summary(&eligible, market.assets).map_err(QuoteEngineError::Admission)?;
        let side = match request.kind {
            QuoteKind::ExactIn { input, .. } => PricingSide::ExactIn { gross_input: input },
            QuoteKind::ExactOut { output, .. } => PricingSide::ExactOut { output },
        };
        let pricing = self
            .pricing
            .price(PricingRequest {
                context: request.context,
                input_asset,
                output_asset,
                side,
                inventory: &summary,
            })
            .map_err(QuoteEngineError::Pricing)?;
        pricing.validate().map_err(QuoteEngineError::Admission)?;
        let execution = calculate_execution(&request, pricing, pair.limits)
            .map_err(QuoteEngineError::Admission)?;
        let selected = select_inventory(
            &eligible,
            output_asset,
            execution.output.amount,
            pair.limits,
        )
        .map_err(QuoteEngineError::Admission)?;
        let selected_amount = selected
            .iter()
            .try_fold(0_u64, |total, output| total.checked_add(output.amount()));
        let selected_amount = selected_amount.ok_or(QuoteEngineError::Admission(
            QuoteAdmissionError::AmountOverflow,
        ))?;
        let change = selected_amount.checked_sub(execution.output.amount).ok_or(
            QuoteEngineError::Admission(QuoteAdmissionError::AmountOverflow),
        )?;
        let provider_receive = self
            .destinations
            .fresh_confidential_destination(DestinationPurpose::SettlementReceive)
            .map_err(QuoteEngineError::Destination)?;
        let provider_change = if change == 0 {
            None
        } else {
            Some(
                self.destinations
                    .fresh_confidential_destination(DestinationPurpose::SettlementChange)
                    .map_err(QuoteEngineError::Destination)?,
            )
        };
        if provider_change.as_ref().is_some_and(|destination| {
            destination.script_pubkey() == provider_receive.script_pubkey()
                || destination.blinding_public_key() == provider_receive.blinding_public_key()
                || destination.wallet_locator() == provider_receive.wallet_locator()
        }) {
            return Err(QuoteEngineError::Admission(
                QuoteAdmissionError::ReusedProviderDestination,
            ));
        }
        let contribution = quote_contribution(
            &selected,
            execution,
            request.recipient.clone(),
            &provider_receive,
            provider_change.as_ref(),
            change,
        )
        .map_err(QuoteEngineError::Admission)?;
        let draft = FirmQuoteDraft {
            request,
            execution,
            pricing,
            snapshot: QuoteSnapshotEvidence {
                anchor: eligible.anchor(),
                commitment: eligible.token().snapshot(),
                allocation_revision: eligible.allocation_revision(),
                eligible_commitment: eligible.eligible_commitment(),
            },
            contribution,
            provider_receive_recovery: DestinationRecovery::from(&provider_receive),
            provider_change_recovery: provider_change.as_ref().map(DestinationRecovery::from),
            selected_asset: output_asset,
            selected_amount,
        };
        self.inventory
            .reserve_firm_quote(
                &eligible,
                owner,
                key,
                request_digest,
                &draft,
                self.policy,
                clock,
            )
            .map_err(QuoteEngineError::Inventory)
    }
}

fn inventory_summary(
    eligible: &EligibleInventory,
    assets: BinaryMarketAssets,
) -> Result<InventorySummary, QuoteAdmissionError> {
    let mut totals = BTreeMap::<[u8; 32], (AssetId, u64)>::new();
    for output in eligible.outputs() {
        if !assets.contains(output.asset()) {
            continue;
        }
        let key = output.asset().into_inner().to_byte_array();
        let entry = totals.entry(key).or_insert((output.asset(), 0));
        entry.1 = entry
            .1
            .checked_add(output.amount())
            .ok_or(QuoteAdmissionError::AmountOverflow)?;
    }
    Ok(InventorySummary {
        balances: totals
            .into_values()
            .map(|(asset, amount)| AssetAmount { asset, amount })
            .collect(),
    })
}

fn calculate_execution(
    request: &FirmQuoteRequest,
    pricing: PricingDecision,
    limits: PairLimits,
) -> Result<QuoteExecution, QuoteAdmissionError> {
    request.validate()?;
    pricing.validate()?;
    let fee = pricing.input_asset_venue_fee;
    if fee > request.maximum_input_asset_venue_fee {
        return Err(QuoteAdmissionError::VenueFeeLimitExceeded);
    }
    let (input, output) = match request.kind {
        QuoteKind::ExactIn {
            input,
            output_asset,
            minimum_output,
        } => {
            let priced_input = input
                .amount
                .checked_sub(fee)
                .filter(|amount| *amount != 0)
                .ok_or(QuoteAdmissionError::FeeConsumesInput)?;
            let output_amount = multiply_divide_floor(
                priced_input,
                pricing.rate.numerator,
                pricing.rate.denominator,
            )?;
            if output_amount < minimum_output {
                return Err(QuoteAdmissionError::MinimumOutputNotMet);
            }
            (input, AssetAmount::new(output_asset, output_amount)?)
        }
        QuoteKind::ExactOut {
            input_asset,
            maximum_input,
            output,
        } => {
            let priced_input = multiply_divide_ceil(
                output.amount,
                pricing.rate.denominator,
                pricing.rate.numerator,
            )?;
            let gross_input = priced_input
                .checked_add(fee)
                .ok_or(QuoteAdmissionError::AmountOverflow)?;
            if gross_input > maximum_input {
                return Err(QuoteAdmissionError::MaximumInputExceeded);
            }
            (AssetAmount::new(input_asset, gross_input)?, output)
        }
    };
    if !limits.input.contains(input.amount) || !limits.output.contains(output.amount) {
        return Err(QuoteAdmissionError::FillOutsideConfiguredRange);
    }
    Ok(QuoteExecution {
        input,
        output,
        input_asset_venue_fee: fee,
    })
}

fn multiply_divide_floor(
    value: u64,
    multiplier: u64,
    divisor: u64,
) -> Result<u64, QuoteAdmissionError> {
    let quotient = u128::from(value) * u128::from(multiplier) / u128::from(divisor);
    let quotient = u64::try_from(quotient).map_err(|_| QuoteAdmissionError::AmountOverflow)?;
    if quotient == 0 {
        return Err(QuoteAdmissionError::RoundedAmountIsZero);
    }
    Ok(quotient)
}

fn multiply_divide_ceil(
    value: u64,
    multiplier: u64,
    divisor: u64,
) -> Result<u64, QuoteAdmissionError> {
    let product = u128::from(value) * u128::from(multiplier);
    let divisor = u128::from(divisor);
    let quotient = product / divisor + u128::from(!product.is_multiple_of(divisor));
    let quotient = u64::try_from(quotient).map_err(|_| QuoteAdmissionError::AmountOverflow)?;
    if quotient == 0 {
        return Err(QuoteAdmissionError::RoundedAmountIsZero);
    }
    Ok(quotient)
}

fn select_inventory(
    eligible: &EligibleInventory,
    asset: AssetId,
    required: u64,
    limits: PairLimits,
) -> Result<Vec<&WalletOwnedOutput>, QuoteAdmissionError> {
    let mut candidates = eligible
        .outputs()
        .iter()
        .filter(|output| output.asset() == asset)
        .collect::<Vec<_>>();
    candidates.sort_by_key(|output| output.outpoint());

    if let Some(exact) = candidates
        .iter()
        .copied()
        .find(|output| output.amount() == required)
    {
        return Ok(vec![exact]);
    }
    if let Some(singleton) = candidates
        .iter()
        .copied()
        .filter(|output| valid_selected_total(output.amount(), required, limits))
        .min_by_key(|output| (output.amount(), output.outpoint()))
    {
        return Ok(vec![singleton]);
    }

    let total = candidates
        .iter()
        .try_fold(0_u64, |sum, output| sum.checked_add(output.amount()));
    let total = total.ok_or(QuoteAdmissionError::AmountOverflow)?;
    if total < required {
        return Err(QuoteAdmissionError::InsufficientInventory);
    }

    candidates.sort_by_key(|output| (std::cmp::Reverse(output.amount()), output.outpoint()));
    let mut selected = Vec::new();
    let mut selected_total = 0_u64;
    for output in &candidates {
        if selected.len() == limits.maximum_provider_inputs {
            break;
        }
        selected_total = selected_total
            .checked_add(output.amount())
            .ok_or(QuoteAdmissionError::AmountOverflow)?;
        selected.push(*output);
        if valid_selected_total(selected_total, required, limits) {
            selected.sort_by_key(|output| output.outpoint());
            return Ok(selected);
        }
    }

    let maximum_selected_total = selected_total;
    if maximum_selected_total < required {
        return Err(QuoteAdmissionError::InventoryTooFragmented);
    }

    // If the largest admissible set falls into the forbidden positive-change
    // band, a smaller exact subset can still be valid. Search only for that
    // exact target: no other subset can make enough positive change when the
    // maximum sum cannot. The hard node budget prevents adversarially
    // fragmented inventory from turning quote admission into unbounded work.
    let exact_candidates = candidates
        .into_iter()
        .filter(|output| output.amount() <= required)
        .collect::<Vec<_>>();
    let mut search = ExactSubsetSearch {
        candidates: &exact_candidates,
        required,
        maximum_inputs: limits.maximum_provider_inputs,
        remaining_nodes: limits.selection_search_node_budget,
        exhausted_budget: false,
    };
    if let Some(mut exact) = search.find()? {
        exact.sort_by_key(|output| output.outpoint());
        return Ok(exact);
    }
    Err(QuoteAdmissionError::InventoryTooFragmented)
}

struct ExactSubsetSearch<'search, 'inventory> {
    candidates: &'search [&'inventory WalletOwnedOutput],
    required: u64,
    maximum_inputs: usize,
    remaining_nodes: usize,
    exhausted_budget: bool,
}

impl<'inventory> ExactSubsetSearch<'_, 'inventory> {
    fn find(&mut self) -> Result<Option<Vec<&'inventory WalletOwnedOutput>>, QuoteAdmissionError> {
        for cardinality in 2..=self.maximum_inputs.min(self.candidates.len()) {
            let mut selected = Vec::with_capacity(cardinality);
            if self.visit(0, cardinality, 0, &mut selected) {
                return Ok(Some(selected));
            }
            if self.exhausted_budget {
                return Err(QuoteAdmissionError::SelectionSearchBudgetExceeded);
            }
        }
        Ok(None)
    }

    fn visit(
        &mut self,
        start: usize,
        slots: usize,
        sum: u64,
        selected: &mut Vec<&'inventory WalletOwnedOutput>,
    ) -> bool {
        if self.remaining_nodes == 0 {
            self.exhausted_budget = true;
            return false;
        }
        self.remaining_nodes -= 1;
        if slots == 0 {
            return sum == self.required;
        }
        if self.candidates.len().saturating_sub(start) < slots || sum >= self.required {
            return false;
        }

        let need = self.required - sum;
        let maximum = self.candidates[start..]
            .iter()
            .take(slots)
            .fold(0_u128, |total, output| total + u128::from(output.amount()));
        let minimum = self.candidates[self.candidates.len() - slots..]
            .iter()
            .fold(0_u128, |total, output| total + u128::from(output.amount()));
        if u128::from(need) > maximum || u128::from(need) < minimum {
            return false;
        }

        let last_start = self.candidates.len() - slots;
        let mut index = start;
        let mut previous_amount = None;
        while index <= last_start {
            let output = self.candidates[index];
            if previous_amount == Some(output.amount()) {
                index += 1;
                continue;
            }
            previous_amount = Some(output.amount());
            let Some(next_sum) = sum.checked_add(output.amount()) else {
                index += 1;
                continue;
            };
            if next_sum <= self.required {
                selected.push(output);
                if self.visit(index + 1, slots - 1, next_sum, selected) {
                    return true;
                }
                selected.pop();
                if self.exhausted_budget {
                    return false;
                }
            }
            index += 1;
        }
        false
    }
}

fn valid_selected_total(total: u64, required: u64, limits: PairLimits) -> bool {
    total == required
        || total
            .checked_sub(required)
            .is_some_and(|change| change >= limits.minimum_positive_change)
}

fn quote_contribution(
    selected: &[&WalletOwnedOutput],
    execution: QuoteExecution,
    recipient: QuoteRecipient,
    provider_receive: &ConfidentialDestination,
    provider_change: Option<&ConfidentialDestination>,
    change: u64,
) -> Result<QuoteContribution, QuoteAdmissionError> {
    let inputs = selected
        .iter()
        .enumerate()
        .map(|(index, output)| {
            let id = u16::try_from(index + 1)
                .map(QuoteInputId)
                .map_err(|_| QuoteAdmissionError::TooManyProviderInputs)?;
            Ok(QuotedProviderInput {
                id,
                outpoint: output.outpoint(),
                witness_utxo: output.txout().clone(),
                inventory_binding: output.binding(),
            })
        })
        .collect::<Result<Vec<_>, QuoteAdmissionError>>()?;
    let provider_blinder = inputs
        .first()
        .map(|input| QuoteBlinderRole::ProviderInput(input.id))
        .ok_or(QuoteAdmissionError::InsufficientInventory)?;
    let mut outputs = vec![
        QuotedOutput {
            id: QuoteOutputId(1),
            role: QuoteOutputRole::ProviderPayment,
            asset: execution.input.asset,
            amount: execution.input.amount,
            destination: QuoteRecipient::from(provider_receive),
            blinder: QuoteBlinderRole::TakerPaymentInput,
        },
        QuotedOutput {
            id: QuoteOutputId(2),
            role: QuoteOutputRole::TakerReceive,
            asset: execution.output.asset,
            amount: execution.output.amount,
            destination: recipient,
            blinder: provider_blinder,
        },
    ];
    if change != 0 {
        let destination = provider_change.ok_or(QuoteAdmissionError::MissingChangeDestination)?;
        outputs.push(QuotedOutput {
            id: QuoteOutputId(3),
            role: QuoteOutputRole::ProviderChange,
            asset: execution.output.asset,
            amount: change,
            destination: QuoteRecipient::from(destination),
            blinder: provider_blinder,
        });
    }
    Ok(QuoteContribution { inputs, outputs })
}

pub(crate) fn quote_request_digest(
    provider: ProviderIdentity,
    owner: OwnerId,
    key: IdempotencyKey,
    request: &FirmQuoteRequest,
) -> Result<QuoteRequestDigest, ProviderError> {
    Ok(QuoteRequestDigest::new(domain_digest(
        REQUEST_DOMAIN,
        &StoredQuoteRequestV1::from_domain(provider, owner, key, request),
    )?))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn finalize_quote(
    provider: ProviderIdentity,
    owner: OwnerId,
    key: IdempotencyKey,
    request_digest: QuoteRequestDigest,
    reservation_id: ReservationId,
    draft: &FirmQuoteDraft,
    created_at: UnixMillis,
    accept_before: UnixMillis,
    fee_policy: FeePolicy,
) -> Result<FirmQuote, ProviderError> {
    let recovery_metadata_commitment = recovery_metadata_commitment(
        provider,
        reservation_id,
        draft.provider_receive_recovery,
        draft
            .provider_change_recovery
            .map(|recovery| recovery.internal_key),
        draft
            .provider_change_recovery
            .map(|recovery| recovery.wallet_locator),
    )?;
    let mut quote = FirmQuote {
        reservation_id,
        provider,
        request: draft.request.clone(),
        execution: draft.execution,
        pricing: draft.pricing,
        snapshot: draft.snapshot,
        contribution: draft.contribution.clone(),
        created_at,
        accept_before,
        fee_policy,
        recovery_metadata_commitment,
        commitment: QuoteCommitment::new([0; 32]),
    };
    let transcript = StoredQuoteTranscriptV1::from_domain(owner, key, request_digest, &quote);
    quote.commitment = QuoteCommitment::new(domain_digest(QUOTE_DOMAIN, &transcript)?);
    Ok(quote)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn quote_from_stored_parts(
    reservation_id: ReservationId,
    provider: ProviderIdentity,
    request: FirmQuoteRequest,
    execution: QuoteExecution,
    pricing: PricingDecision,
    snapshot: QuoteSnapshotEvidence,
    contribution: QuoteContribution,
    created_at: UnixMillis,
    accept_before: UnixMillis,
    fee_policy: FeePolicy,
    recovery_metadata_commitment: [u8; 32],
    commitment: QuoteCommitment,
) -> FirmQuote {
    FirmQuote {
        reservation_id,
        provider,
        request,
        execution,
        pricing,
        snapshot,
        contribution,
        created_at,
        accept_before,
        fee_policy,
        recovery_metadata_commitment,
        commitment,
    }
}

pub(crate) fn recovery_metadata_commitment(
    provider: ProviderIdentity,
    reservation_id: ReservationId,
    provider_receive: DestinationRecovery,
    provider_change_internal_key: Option<[u8; 32]>,
    provider_change_wallet_locator: Option<[u8; 32]>,
) -> Result<[u8; 32], ProviderError> {
    domain_digest(
        RECOVERY_METADATA_DOMAIN,
        &StoredRecoveryMetadataV1 {
            provider: provider.provider().to_bytes(),
            genesis_hash: provider.genesis_hash(),
            policy_asset: provider.policy_asset(),
            reservation_id: reservation_id.to_bytes(),
            provider_receive_internal_key: provider_receive.internal_key,
            provider_receive_wallet_locator: provider_receive.wallet_locator,
            provider_change_internal_key,
            provider_change_wallet_locator,
        },
    )
}

pub(crate) fn quote_outcome(
    quote: FirmQuote,
    reservation: ReservationView,
    created: bool,
) -> FirmQuoteOutcome {
    FirmQuoteOutcome {
        quote,
        reservation,
        created,
    }
}

pub(crate) fn recompute_quote_commitment(
    owner: OwnerId,
    key: IdempotencyKey,
    request_digest: QuoteRequestDigest,
    quote: &FirmQuote,
) -> Result<QuoteCommitment, ProviderError> {
    Ok(QuoteCommitment::new(domain_digest(
        QUOTE_DOMAIN,
        &StoredQuoteTranscriptV1::from_domain(owner, key, request_digest, quote),
    )?))
}

fn domain_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<[u8; 32], ProviderError> {
    let encoded = postcard::to_allocvec(value)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}

#[derive(Serialize)]
struct StoredQuoteRequestV1<'a> {
    provider: [u8; 32],
    genesis_hash: elements::BlockHash,
    provider_policy_asset: AssetId,
    owner: [u8; 32],
    idempotency_key: [u8; 32],
    network: deadcat_types::LiquidNetwork,
    market: OutPoint,
    policy_asset: AssetId,
    kind: StoredQuoteKindV1,
    recipient_script: &'a Script,
    recipient_blinding_key: Vec<u8>,
    maximum_input_asset_venue_fee: u64,
}

impl<'a> StoredQuoteRequestV1<'a> {
    fn from_domain(
        provider: ProviderIdentity,
        owner: OwnerId,
        key: IdempotencyKey,
        request: &'a FirmQuoteRequest,
    ) -> Self {
        Self {
            provider: provider.provider().to_bytes(),
            genesis_hash: provider.genesis_hash(),
            provider_policy_asset: provider.policy_asset(),
            owner: owner.to_bytes(),
            idempotency_key: key.to_bytes(),
            network: request.context.chain.network,
            market: request.context.market.creation_anchor(),
            policy_asset: request.context.policy_asset,
            kind: request.kind.into(),
            recipient_script: &request.recipient.script_pubkey,
            recipient_blinding_key: request.recipient.blinding_public_key.serialize().to_vec(),
            maximum_input_asset_venue_fee: request.maximum_input_asset_venue_fee,
        }
    }
}

#[derive(Clone, Copy, Serialize)]
enum StoredQuoteKindV1 {
    ExactIn {
        input_asset: AssetId,
        input_amount: u64,
        output_asset: AssetId,
        minimum_output: u64,
    },
    ExactOut {
        input_asset: AssetId,
        maximum_input: u64,
        output_asset: AssetId,
        output_amount: u64,
    },
}

impl From<QuoteKind> for StoredQuoteKindV1 {
    fn from(value: QuoteKind) -> Self {
        match value {
            QuoteKind::ExactIn {
                input,
                output_asset,
                minimum_output,
            } => Self::ExactIn {
                input_asset: input.asset,
                input_amount: input.amount,
                output_asset,
                minimum_output,
            },
            QuoteKind::ExactOut {
                input_asset,
                maximum_input,
                output,
            } => Self::ExactOut {
                input_asset,
                maximum_input,
                output_asset: output.asset,
                output_amount: output.amount,
            },
        }
    }
}

#[derive(Serialize)]
struct StoredStaticRateV1 {
    market: OutPoint,
    input_asset: AssetId,
    output_asset: AssetId,
    numerator: u64,
    denominator: u64,
}

#[derive(Serialize)]
struct StoredStaticPricingV1<'a> {
    revision: u64,
    rules: &'a [StoredStaticRateV1],
}

#[derive(Serialize)]
struct StoredQuoteTranscriptV1<'a> {
    request_digest: [u8; 32],
    owner: [u8; 32],
    idempotency_key: [u8; 32],
    reservation_id: [u8; 32],
    provider: [u8; 32],
    genesis_hash: elements::BlockHash,
    provider_policy_asset: AssetId,
    request: StoredQuoteRequestV1<'a>,
    execution_input_asset: AssetId,
    execution_input_amount: u64,
    execution_output_asset: AssetId,
    execution_output_amount: u64,
    input_asset_venue_fee: u64,
    rate_numerator: u64,
    rate_denominator: u64,
    pricing_policy_id: [u8; 32],
    pricing_revision: u64,
    snapshot_hash: elements::BlockHash,
    snapshot_height: u32,
    snapshot_commitment: [u8; 32],
    allocation_revision: u64,
    eligible_commitment: [u8; 32],
    inputs: Vec<StoredQuotedInputV1<'a>>,
    outputs: Vec<StoredQuotedOutputV1<'a>>,
    created_at: u64,
    accept_before: u64,
    fee_policy_asset: AssetId,
    minimum_sats_per_kvb: u64,
    minimum_absolute_fee: u64,
    maximum_transaction_weight: u64,
    fee_size_metric: u8,
    recovery_metadata_commitment: [u8; 32],
}

impl<'a> StoredQuoteTranscriptV1<'a> {
    fn from_domain(
        owner: OwnerId,
        key: IdempotencyKey,
        request_digest: QuoteRequestDigest,
        quote: &'a FirmQuote,
    ) -> Self {
        Self {
            request_digest: request_digest.to_bytes(),
            owner: owner.to_bytes(),
            idempotency_key: key.to_bytes(),
            reservation_id: quote.reservation_id.to_bytes(),
            provider: quote.provider.provider().to_bytes(),
            genesis_hash: quote.provider.genesis_hash(),
            provider_policy_asset: quote.provider.policy_asset(),
            request: StoredQuoteRequestV1::from_domain(quote.provider, owner, key, &quote.request),
            execution_input_asset: quote.execution.input.asset,
            execution_input_amount: quote.execution.input.amount,
            execution_output_asset: quote.execution.output.asset,
            execution_output_amount: quote.execution.output.amount,
            input_asset_venue_fee: quote.execution.input_asset_venue_fee,
            rate_numerator: quote.pricing.rate.numerator,
            rate_denominator: quote.pricing.rate.denominator,
            pricing_policy_id: quote.pricing.policy_id.to_bytes(),
            pricing_revision: quote.pricing.revision.value(),
            snapshot_hash: quote.snapshot.anchor.block_hash(),
            snapshot_height: quote.snapshot.anchor.block_height(),
            snapshot_commitment: quote.snapshot.commitment.to_bytes(),
            allocation_revision: quote.snapshot.allocation_revision,
            eligible_commitment: quote.snapshot.eligible_commitment,
            inputs: quote
                .contribution
                .inputs
                .iter()
                .map(StoredQuotedInputV1::from)
                .collect(),
            outputs: quote
                .contribution
                .outputs
                .iter()
                .map(StoredQuotedOutputV1::from)
                .collect(),
            created_at: quote.created_at.value(),
            accept_before: quote.accept_before.value(),
            fee_policy_asset: quote.fee_policy.policy_asset(),
            minimum_sats_per_kvb: quote.fee_policy.minimum_sats_per_kvb(),
            minimum_absolute_fee: quote.fee_policy.minimum_absolute_fee(),
            maximum_transaction_weight: quote.fee_policy.maximum_transaction_weight(),
            fee_size_metric: match quote.fee_policy.size_metric() {
                crate::model::FeeSizeMetric::RegularVbytes => 0,
                crate::model::FeeSizeMetric::DiscountVbytes => 1,
            },
            recovery_metadata_commitment: quote.recovery_metadata_commitment,
        }
    }
}

#[derive(Serialize)]
struct StoredRecoveryMetadataV1 {
    provider: [u8; 32],
    genesis_hash: elements::BlockHash,
    policy_asset: AssetId,
    reservation_id: [u8; 32],
    provider_receive_internal_key: [u8; 32],
    provider_receive_wallet_locator: [u8; 32],
    provider_change_internal_key: Option<[u8; 32]>,
    provider_change_wallet_locator: Option<[u8; 32]>,
}

#[derive(Serialize)]
struct StoredQuotedInputV1<'a> {
    id: u16,
    outpoint: OutPoint,
    witness_utxo: &'a TxOut,
    inventory_binding: [u8; 32],
}

impl<'a> From<&'a QuotedProviderInput> for StoredQuotedInputV1<'a> {
    fn from(value: &'a QuotedProviderInput) -> Self {
        Self {
            id: value.id.value(),
            outpoint: value.outpoint,
            witness_utxo: &value.witness_utxo,
            inventory_binding: value.inventory_binding.to_bytes(),
        }
    }
}

#[derive(Serialize)]
struct StoredQuotedOutputV1<'a> {
    id: u16,
    role: u8,
    asset: AssetId,
    amount: u64,
    script_pubkey: &'a Script,
    blinding_public_key: Vec<u8>,
    blinder_kind: u8,
    blinder_input: u16,
}

impl<'a> From<&'a QuotedOutput> for StoredQuotedOutputV1<'a> {
    fn from(value: &'a QuotedOutput) -> Self {
        let role = match value.role {
            QuoteOutputRole::ProviderPayment => 0,
            QuoteOutputRole::TakerReceive => 1,
            QuoteOutputRole::ProviderChange => 2,
        };
        let (blinder_kind, blinder_input) = match value.blinder {
            QuoteBlinderRole::TakerPaymentInput => (0, 0),
            QuoteBlinderRole::ProviderInput(id) => (1, id.value()),
        };
        Self {
            id: value.id.value(),
            role,
            asset: value.asset,
            amount: value.amount,
            script_pubkey: &value.destination.script_pubkey,
            blinding_public_key: value.destination.blinding_public_key.serialize().to_vec(),
            blinder_kind,
            blinder_input,
        }
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QuoteModelError {
    #[error("quote amounts must be nonzero")]
    ZeroAmount,
    #[error("input and output assets must differ")]
    SameAssetPair,
    #[error("quote recipient script must be spendable and nonempty")]
    InvalidRecipientScript,
    #[error("rational pricing numerator and denominator must be nonzero")]
    ZeroRate,
}

impl From<QuoteModelError> for QuoteAdmissionError {
    fn from(value: QuoteModelError) -> Self {
        match value {
            QuoteModelError::ZeroAmount => Self::RoundedAmountIsZero,
            QuoteModelError::SameAssetPair
            | QuoteModelError::InvalidRecipientScript
            | QuoteModelError::ZeroRate => Self::InvalidDerivedQuote,
        }
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QuoteConfigurationError {
    #[error("binary-market collateral, YES, and NO assets must be distinct")]
    MarketAssetsNotDistinct,
    #[error("market ID is not a valid contract anchor: {0}")]
    InvalidMarketId(ContractId),
    #[error("a market must enable at least one quote pair")]
    NoEnabledPairs,
    #[error("quote engine must configure at least one market")]
    NoMarkets,
    #[error("invalid amount range {minimum}..={maximum}")]
    InvalidAmountRange { minimum: u64, maximum: u64 },
    #[error("provider-input limit {actual} is outside 1..={maximum}")]
    InvalidProviderInputLimit { actual: usize, maximum: usize },
    #[error("unsupported launch pair {input} -> {output}")]
    UnsupportedPair { input: AssetId, output: AssetId },
    #[error("duplicate configured pair {input} -> {output}")]
    DuplicatePair { input: AssetId, output: AssetId },
    #[error("duplicate configured market {0}")]
    DuplicateMarket(ContractId),
    #[error("configured market uses the wrong Liquid genesis hash")]
    WrongGenesis,
    #[error("configured policy or fee asset disagrees with provider identity")]
    WrongPolicyAsset,
    #[error("quote lifetime must be nonzero")]
    ZeroQuoteLifetime,
    #[error("live quote limits must be nonzero")]
    ZeroLiveQuoteLimit,
    #[error("inventory subset-search node budget must be nonzero")]
    ZeroSelectionSearchNodeBudget,
    #[error("per-owner live quote limit exceeds the global limit")]
    OwnerLimitExceedsGlobal,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QuoteAdmissionError {
    #[error("market context is not configured")]
    MarketNotConfigured,
    #[error("directed asset pair is not configured")]
    PairNotConfigured,
    #[error("calculated fill is outside configured pair limits")]
    FillOutsideConfiguredRange,
    #[error("firm quote exceeds the taker's venue-fee bound")]
    VenueFeeLimitExceeded,
    #[error("pricing policy returned an invalid or non-normalized decision")]
    InvalidPricingDecision,
    #[error("the input-asset fee consumes the entire exact input")]
    FeeConsumesInput,
    #[error("calculated output is below the taker's minimum")]
    MinimumOutputNotMet,
    #[error("calculated input exceeds the taker's maximum")]
    MaximumInputExceeded,
    #[error("quote amount arithmetic overflowed")]
    AmountOverflow,
    #[error("exact pricing rounded a nonzero amount to zero")]
    RoundedAmountIsZero,
    #[error("provider has insufficient eligible inventory")]
    InsufficientInventory,
    #[error("eligible inventory is too fragmented for the configured input cap")]
    InventoryTooFragmented,
    #[error("inventory subset search reached its configured work budget")]
    SelectionSearchBudgetExceeded,
    #[error("quote contains too many provider inputs")]
    TooManyProviderInputs,
    #[error("positive change has no provider destination")]
    MissingChangeDestination,
    #[error("wallet reused one provider destination within a quote")]
    ReusedProviderDestination,
    #[error("derived quote is internally invalid")]
    InvalidDerivedQuote,
}

#[derive(Debug, Error)]
pub enum StaticPricingError {
    #[error("static pricing must configure at least one directed rate")]
    NoRates,
    #[error("duplicate static rate for market {market}, {input} -> {output}")]
    DuplicateRate {
        market: ContractId,
        input: AssetId,
        output: AssetId,
    },
    #[error("static rate is not configured")]
    RateNotConfigured,
    #[error("failed to commit static pricing configuration: {0}")]
    Commitment(#[from] ProviderError),
}

#[derive(Debug, Error)]
pub enum QuoteEngineError<SourceError, DestinationError, PricingError>
where
    SourceError: Error + Send + Sync + 'static,
    DestinationError: Error + Send + Sync + 'static,
    PricingError: Error + Send + Sync + 'static,
{
    #[error("provider state rejected the quote: {0}")]
    Provider(#[source] ProviderError),
    #[error("inventory admission failed: {0}")]
    Inventory(#[source] InventoryCoordinatorError<SourceError>),
    #[error("quote admission failed: {0}")]
    Admission(#[source] QuoteAdmissionError),
    #[error("provider destination generation failed: {0}")]
    Destination(#[source] DestinationError),
    #[error("pricing policy failed: {0}")]
    Pricing(#[source] PricingError),
}

#[cfg(test)]
mod tests;

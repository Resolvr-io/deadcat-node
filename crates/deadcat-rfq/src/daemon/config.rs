use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, bail};
use deadcat_rfq::{HandlerConfig, elements::ElementsCoreConfig};
use deadcat_rfq_iroh::{DiscoveryMode, ServerConfig};
use deadcat_rfq_provider::{
    AmountRange, BinaryMarketAssets, FeePolicy, FeeSizeMetric, InventoryFreshnessPolicy,
    MarketQuoteConfig, PairLimits, PairRule, PricingRevision, QuoteContext, QuoteEnginePolicy,
    RationalRate, StaticRateRule, StaticRationalPricing,
};
use deadcat_types::{ChainIdentity, ContractId, LiquidNetwork};
use elements::{AssetId, BlockHash};
use serde::Deserialize;

use super::state::validate_private_file;

const CONFIG_SCHEMA_VERSION: u32 = 1;
const MAX_QUOTE_LIFETIME_MILLIS: u64 = 5 * 60 * 1_000;
const MAX_INVENTORY_AGE_MILLIS: u64 = 60 * 60 * 1_000;
const MAX_RUNTIME_INTERVAL_MILLIS: u64 = 60 * 60 * 1_000;
const MAX_CONFIGURED_INVENTORY_OUTPUTS: usize = 10_000;
const MAX_CONFIGURED_LIVE_QUOTES_PER_OWNER: usize = 1_024;
const MAX_CONFIGURED_LIVE_QUOTES_GLOBAL: usize = 100_000;
const MAX_SELECTION_SEARCH_NODE_BUDGET: usize = 1_000_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileConfig {
    schema_version: u32,
    profile: DeploymentProfile,
    network: LiquidNetwork,
    genesis_hash: BlockHash,
    policy_asset: AssetId,
    elements: ElementsFileConfig,
    fee_policy: FeePolicyFileConfig,
    pricing_revision: u64,
    markets: Vec<MarketFileConfig>,
    #[serde(default)]
    runtime: RuntimeFileConfig,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DeploymentProfile {
    /// Explicitly constrained first daemon profile. Static operator market
    /// tuples are not sufficient evidence for a production Liquid deployment.
    RegtestStaticV1,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ElementsFileConfig {
    url: String,
    #[serde(default)]
    auth: ElementsAuthFileConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ElementsAuthFileConfig {
    #[default]
    None,
    CookieFile {
        path: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FeePolicyFileConfig {
    minimum_sats_per_kvb: u64,
    minimum_absolute_fee: u64,
    maximum_transaction_weight: u64,
    size_metric: FeeMetricFileConfig,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FeeMetricFileConfig {
    RegularVbytes,
    DiscountVbytes,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MarketFileConfig {
    market_id: ContractId,
    collateral_asset: AssetId,
    yes_asset: AssetId,
    no_asset: AssetId,
    pairs: Vec<PairFileConfig>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairFileConfig {
    input: AssetRole,
    output: AssetRole,
    minimum_input: u64,
    maximum_input: u64,
    minimum_output: u64,
    maximum_output: u64,
    maximum_provider_inputs: usize,
    #[serde(default)]
    minimum_positive_change: u64,
    #[serde(default = "default_selection_search_node_budget")]
    selection_search_node_budget: usize,
    rate_numerator: u64,
    rate_denominator: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AssetRole {
    Collateral,
    Yes,
    No,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RuntimeFileConfig {
    max_inventory_age_millis: u64,
    max_inventory_outputs: usize,
    quote_lifetime_millis: u64,
    maximum_live_quotes_per_owner: usize,
    maximum_live_quotes_global: usize,
    execute_queue_capacity: usize,
    max_blocking_operations: usize,
    recovery_batch_size: usize,
    recovery_interval_millis: u64,
    inventory_refresh_interval_millis: u64,
    direct_only: bool,
}

impl Default for RuntimeFileConfig {
    fn default() -> Self {
        let handler = HandlerConfig::default();
        Self {
            max_inventory_age_millis: 30_000,
            max_inventory_outputs: 10_000,
            quote_lifetime_millis: 15_000,
            maximum_live_quotes_per_owner: 4,
            maximum_live_quotes_global: 1_024,
            execute_queue_capacity: handler.execute_queue_capacity,
            max_blocking_operations: handler.max_blocking_operations,
            recovery_batch_size: handler.recovery_batch_size,
            recovery_interval_millis: duration_millis(handler.recovery_interval),
            inventory_refresh_interval_millis: duration_millis(handler.inventory_refresh_interval),
            direct_only: false,
        }
    }
}

fn default_selection_search_node_budget() -> usize {
    deadcat_rfq_provider::DEFAULT_SELECTION_SEARCH_NODE_BUDGET
}

const fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis() as u64
}

pub(super) struct ValidatedConfig {
    pub(super) chain: ChainIdentity,
    pub(super) policy_asset: AssetId,
    pub(super) elements: ElementsCoreConfig,
    pub(super) inventory: InventoryFreshnessPolicy,
    pub(super) quote: QuoteEnginePolicy,
    pub(super) handler: HandlerConfig,
    pub(super) server: ServerConfig,
    pub(super) discovery: DiscoveryMode,
    pub(super) markets: Vec<MarketQuoteConfig>,
    pub(super) pricing: StaticRationalPricing,
}

impl FileConfig {
    pub(super) fn validate(self) -> anyhow::Result<ValidatedConfig> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            bail!(
                "unsupported RFQ configuration schema {}; expected {CONFIG_SCHEMA_VERSION}",
                self.schema_version
            );
        }
        if self.profile != DeploymentProfile::RegtestStaticV1
            || self.network != LiquidNetwork::ElementsRegtest
        {
            bail!(
                "the regtest_static_v1 profile is restricted to elements_regtest until canonical market evidence is wired"
            );
        }
        validate_runtime_bounds(&self.runtime)?;
        let elements = self.elements.runtime()?;
        let chain = ChainIdentity {
            network: self.network,
            genesis_hash: self.genesis_hash,
        };
        let fee_policy = FeePolicy::new(
            self.policy_asset,
            self.fee_policy.minimum_sats_per_kvb,
            self.fee_policy.minimum_absolute_fee,
            self.fee_policy.maximum_transaction_weight,
            match self.fee_policy.size_metric {
                FeeMetricFileConfig::RegularVbytes => FeeSizeMetric::RegularVbytes,
                FeeMetricFileConfig::DiscountVbytes => FeeSizeMetric::DiscountVbytes,
            },
        )
        .context("validate RFQ transaction fee policy")?;
        let quote = QuoteEnginePolicy::new(
            self.runtime.quote_lifetime_millis,
            self.runtime.maximum_live_quotes_per_owner,
            self.runtime.maximum_live_quotes_global,
            fee_policy,
        )
        .context("validate firm-quote admission policy")?;
        let inventory = InventoryFreshnessPolicy::new(
            self.runtime.max_inventory_age_millis,
            self.runtime.max_inventory_outputs,
        )
        .context("validate inventory freshness policy")?;
        let (markets, rates) = build_markets(chain, self.policy_asset, self.markets)?;
        let pricing =
            StaticRationalPricing::new(rates, PricingRevision::new(self.pricing_revision))
                .context("validate static pricing policy")?;
        let handler = HandlerConfig {
            execute_queue_capacity: self.runtime.execute_queue_capacity,
            max_blocking_operations: self.runtime.max_blocking_operations,
            recovery_batch_size: self.runtime.recovery_batch_size,
            recovery_interval: Duration::from_millis(self.runtime.recovery_interval_millis),
            inventory_refresh_interval: Duration::from_millis(
                self.runtime.inventory_refresh_interval_millis,
            ),
        };
        handler
            .validate()
            .context("validate RFQ daemon supervision policy")?;
        Ok(ValidatedConfig {
            chain,
            policy_asset: self.policy_asset,
            elements,
            inventory,
            quote,
            handler,
            server: ServerConfig::default(),
            discovery: if self.runtime.direct_only {
                DiscoveryMode::Disabled
            } else {
                DiscoveryMode::N0Defaults
            },
            markets,
            pricing,
        })
    }
}

impl ElementsFileConfig {
    fn runtime(self) -> anyhow::Result<ElementsCoreConfig> {
        let url = reqwest::Url::parse(&self.url).context("parse Elements Core RPC URL")?;
        if url.scheme() == "http" && !is_loopback(&url) {
            bail!("unencrypted Elements Core RPC is permitted only on a loopback address");
        }
        let auth = match self.auth {
            ElementsAuthFileConfig::None => deadcat_rfq::elements::ElementsCoreAuth::None,
            ElementsAuthFileConfig::CookieFile { path } => {
                if !path.is_absolute() {
                    bail!("Elements Core cookie path must be absolute");
                }
                validate_private_file(&path).context("validate Elements Core cookie file")?;
                deadcat_rfq::elements::ElementsCoreAuth::CookieFile(path)
            }
        };
        Ok(ElementsCoreConfig::new(self.url, auth))
    }
}

fn is_loopback(url: &reqwest::Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(host) => host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback()),
        None => false,
    }
}

fn validate_runtime_bounds(runtime: &RuntimeFileConfig) -> anyhow::Result<()> {
    if runtime.quote_lifetime_millis == 0
        || runtime.quote_lifetime_millis > MAX_QUOTE_LIFETIME_MILLIS
    {
        bail!("quote_lifetime_millis must be in 1..={MAX_QUOTE_LIFETIME_MILLIS}");
    }
    if runtime.max_inventory_age_millis == 0
        || runtime.max_inventory_age_millis > MAX_INVENTORY_AGE_MILLIS
    {
        bail!("max_inventory_age_millis must be in 1..={MAX_INVENTORY_AGE_MILLIS}");
    }
    if runtime.max_inventory_outputs == 0
        || runtime.max_inventory_outputs > MAX_CONFIGURED_INVENTORY_OUTPUTS
    {
        bail!("max_inventory_outputs must be in 1..={MAX_CONFIGURED_INVENTORY_OUTPUTS}");
    }
    if runtime.maximum_live_quotes_per_owner == 0
        || runtime.maximum_live_quotes_per_owner > MAX_CONFIGURED_LIVE_QUOTES_PER_OWNER
        || runtime.maximum_live_quotes_global == 0
        || runtime.maximum_live_quotes_global > MAX_CONFIGURED_LIVE_QUOTES_GLOBAL
    {
        bail!("configured live-quote limits exceed daemon safety bounds");
    }
    if runtime.recovery_interval_millis == 0
        || runtime.recovery_interval_millis > MAX_RUNTIME_INTERVAL_MILLIS
        || runtime.inventory_refresh_interval_millis == 0
        || runtime.inventory_refresh_interval_millis > MAX_RUNTIME_INTERVAL_MILLIS
    {
        bail!("worker intervals must be nonzero and at most one hour");
    }
    if runtime.inventory_refresh_interval_millis >= runtime.max_inventory_age_millis {
        bail!("inventory refresh interval must be shorter than maximum inventory age");
    }
    Ok(())
}

fn build_markets(
    chain: ChainIdentity,
    policy_asset: AssetId,
    markets: Vec<MarketFileConfig>,
) -> anyhow::Result<(Vec<MarketQuoteConfig>, Vec<StaticRateRule>)> {
    if markets.is_empty() {
        bail!("at least one RFQ market must be configured");
    }
    let mut runtime_markets = Vec::with_capacity(markets.len());
    let mut rates = Vec::new();
    let mut market_ids = BTreeSet::new();
    for market in markets {
        if !market_ids.insert(market.market_id) {
            bail!("market {} is configured more than once", market.market_id);
        }
        let assets =
            BinaryMarketAssets::new(market.collateral_asset, market.yes_asset, market.no_asset)
                .with_context(|| format!("validate assets for market {}", market.market_id))?;
        let mut pairs = Vec::with_capacity(market.pairs.len());
        for pair in market.pairs {
            if pair.selection_search_node_budget > MAX_SELECTION_SEARCH_NODE_BUDGET {
                bail!(
                    "pair selection_search_node_budget exceeds {MAX_SELECTION_SEARCH_NODE_BUDGET}"
                );
            }
            let input_asset = resolve_role(assets, pair.input);
            let output_asset = resolve_role(assets, pair.output);
            let limits = PairLimits::new(
                AmountRange::new(pair.minimum_input, pair.maximum_input)
                    .context("validate pair input range")?,
                AmountRange::new(pair.minimum_output, pair.maximum_output)
                    .context("validate pair output range")?,
                pair.maximum_provider_inputs,
                pair.minimum_positive_change,
            )
            .context("validate pair resource limits")?
            .with_selection_search_node_budget(pair.selection_search_node_budget)
            .context("validate pair selection budget")?;
            pairs.push(PairRule::new(input_asset, output_asset, limits));
            rates.push(StaticRateRule::new(
                market.market_id,
                input_asset,
                output_asset,
                RationalRate::new(pair.rate_numerator, pair.rate_denominator)
                    .context("validate pair rational rate")?,
            ));
        }
        runtime_markets.push(
            MarketQuoteConfig::new(
                QuoteContext::new(chain, market.market_id, policy_asset),
                assets,
                pairs,
            )
            .with_context(|| format!("validate market {}", market.market_id))?,
        );
    }
    Ok((runtime_markets, rates))
}

const fn resolve_role(assets: BinaryMarketAssets, role: AssetRole) -> AssetId {
    match role {
        AssetRole::Collateral => assets.collateral(),
        AssetRole::Yes => assets.yes(),
        AssetRole::No => assets.no(),
    }
}

#[cfg(test)]
mod tests {
    use elements::hashes::Hash as _;
    use elements::{OutPoint, Txid};

    use super::*;

    fn valid_config() -> FileConfig {
        FileConfig {
            schema_version: 1,
            profile: DeploymentProfile::RegtestStaticV1,
            network: LiquidNetwork::ElementsRegtest,
            genesis_hash: BlockHash::from_byte_array([1; 32]),
            policy_asset: AssetId::from_byte_array([2; 32]),
            elements: ElementsFileConfig {
                url: "http://127.0.0.1:7041".to_owned(),
                auth: ElementsAuthFileConfig::None,
            },
            fee_policy: FeePolicyFileConfig {
                minimum_sats_per_kvb: 100,
                minimum_absolute_fee: 100,
                maximum_transaction_weight: 400_000,
                size_metric: FeeMetricFileConfig::DiscountVbytes,
            },
            pricing_revision: 1,
            markets: vec![MarketFileConfig {
                market_id: ContractId::new(OutPoint::new(Txid::from_byte_array([3; 32]), 0)),
                collateral_asset: AssetId::from_byte_array([4; 32]),
                yes_asset: AssetId::from_byte_array([5; 32]),
                no_asset: AssetId::from_byte_array([6; 32]),
                pairs: vec![PairFileConfig {
                    input: AssetRole::Collateral,
                    output: AssetRole::Yes,
                    minimum_input: 1,
                    maximum_input: 100,
                    minimum_output: 1,
                    maximum_output: 100,
                    maximum_provider_inputs: 4,
                    minimum_positive_change: 1,
                    selection_search_node_budget: 1_000,
                    rate_numerator: 2,
                    rate_denominator: 1,
                }],
            }],
            runtime: RuntimeFileConfig::default(),
        }
    }

    #[test]
    fn builds_matching_pair_and_static_rate_catalogs() {
        let validated = valid_config().validate().expect("valid configuration");
        assert_eq!(validated.markets.len(), 1);
        assert_eq!(validated.markets[0].pairs().len(), 1);
    }

    #[test]
    fn production_networks_cannot_use_static_operator_market_tuples() {
        let mut config = valid_config();
        config.network = LiquidNetwork::Liquid;
        assert!(config.validate().is_err());
    }

    #[test]
    fn refresh_must_keep_inventory_fresh() {
        let mut config = valid_config();
        config.runtime.inventory_refresh_interval_millis = config.runtime.max_inventory_age_millis;
        assert!(config.validate().is_err());
    }

    #[test]
    fn daemon_resource_limits_fail_during_configuration_validation() {
        let mut config = valid_config();
        config.runtime.execute_queue_capacity = 0;
        assert!(config.validate().is_err());

        let mut config = valid_config();
        config.markets[0].pairs[0].selection_search_node_budget =
            MAX_SELECTION_SEARCH_NODE_BUDGET + 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn duplicate_market_ids_fail_even_when_their_pairs_do_not_overlap() {
        let mut config = valid_config();
        let (market_id, collateral_asset, yes_asset, no_asset) = {
            let first = &config.markets[0];
            (
                first.market_id,
                first.collateral_asset,
                first.yes_asset,
                first.no_asset,
            )
        };
        config.markets.push(MarketFileConfig {
            market_id,
            collateral_asset,
            yes_asset,
            no_asset,
            pairs: vec![PairFileConfig {
                input: AssetRole::Yes,
                output: AssetRole::Collateral,
                minimum_input: 1,
                maximum_input: 100,
                minimum_output: 1,
                maximum_output: 100,
                maximum_provider_inputs: 4,
                minimum_positive_change: 1,
                selection_search_node_budget: 1_000,
                rate_numerator: 1,
                rate_denominator: 2,
            }],
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn remote_plaintext_rpc_is_rejected() {
        let mut config = valid_config();
        config.elements.url = "http://example.com:7041".to_owned();
        assert!(config.validate().is_err());
    }

    #[test]
    fn unknown_json_fields_fail_closed() {
        let json = r#"{
            "schema_version": 1,
            "profile": "regtest_static_v1",
            "network": "elements_regtest",
            "genesis_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "policy_asset": "0000000000000000000000000000000000000000000000000000000000000000",
            "elements": { "url": "http://127.0.0.1:7041", "surprise": true },
            "fee_policy": {
                "minimum_sats_per_kvb": 1,
                "minimum_absolute_fee": 0,
                "maximum_transaction_weight": 1,
                "size_metric": "regular_vbytes"
            },
            "pricing_revision": 1,
            "markets": []
        }"#;
        assert!(serde_json::from_str::<FileConfig>(json).is_err());
    }
}

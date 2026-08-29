//! Production chain, market, and wallet evidence for taker orchestration.
//!
//! The concrete source deliberately combines two different authorities. A
//! pinned Deadcat node supplies the materialized binary-market view, while the
//! taker's Elements Core authenticates the chain, required ancestry, and
//! current mempool-aware UTXO set. A market view is accepted only when the
//! node's exact snapshot anchor equals Core's stable tip. Proving merely that
//! an older node anchor remains canonical would permit stale `Trading` state
//! after a later resolution or expiry.
//!
//! This first production profile still trusts the pinned Deadcat node not to
//! fabricate or omit contract history. Structural validation plus an
//! independently authenticated anchor does not prove complete history replay.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use deadcat_client::validation::{ValidationError, validate_market_snapshot};
use deadcat_elements_core::{
    CoreOperation, ElementsCoreClient, ElementsCoreConfig, ElementsCoreError, OperationBudget,
};
use deadcat_rfq_client::{
    AuthoritativeTakerPrevout, RfqVenueError, TakerSettlementSnapshot,
    TakerSettlementSnapshotRequest, TakerSettlementSource, TradingMarket,
};
use deadcat_rfq_wallet::{PersistentRfqWallet, PersistentWalletError, TakerWalletUtxo};
use deadcat_rpc::{Capability, MarketSnapshot, NodeInfo, SyncStatus};
use deadcat_types::{ChainAnchor, ChainIdentity, ContractId, LiquidNetwork};
use elements::{AssetId, BlockHash, OutPoint, Script, TxOut};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use thiserror::Error;
use tokio::sync::{OnceCell, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

use crate::node::{IrohTakerNodeSource, TakerNodeSource};

/// Default maximum number of source-owned blocking tasks that may run at once.
pub const DEFAULT_MAX_BLOCKING_TASKS: usize = 4;

/// Default number of attempts to converge the node and Core on one exact tip.
pub const DEFAULT_MAX_SNAPSHOT_ATTEMPTS: usize = 3;

/// Default pause before retrying an ordinary node/Core tip race.
pub const DEFAULT_SNAPSHOT_RETRY_DELAY: Duration = Duration::from_millis(25);

/// Authoritative, coherent inventory scan for one taker wallet.
///
/// Implementations must return only currently spendable outputs authenticated
/// by the wallet, preserve complete confidential output witnesses, and fail if
/// the wallet catalog or chain anchor changes during the scan. Runtime refresh
/// obtains an exclusion revision token before invoking this method; startup
/// instead holds the wallet-wide funding authority throughout its initial scan
/// and journal reconstruction.
/// Implementations may perform network or blocking Core work, but must expose
/// it through this asynchronous boundary. A blocking adapter must move the
/// whole bounded scan onto an explicit blocking-task executor rather than
/// blocking an async runtime worker.
#[async_trait]
pub trait TakerInventorySource: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    async fn inventory(&self) -> Result<Vec<TakerWalletUtxo>, Self::Error>;
}

/// Current, independently anchored market state used before requesting a quote.
///
/// This capability is preparation evidence only. Final settlement
/// authorization obtains another same-tip market and prevout snapshot after
/// provider blinding and before the taker wallet is allowed to sign.
#[async_trait]
pub trait TakerMarketSource: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    async fn trading_market(&self, market: ContractId) -> Result<TradingMarket, Self::Error>;
}

/// Async scheduling and convergence policy for [`crate::TrustedNodeTakerSource`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ElementsTakerSourceConfig {
    /// Maximum detached-or-active blocking jobs shared by all source clones.
    pub max_blocking_tasks: usize,
    /// Maximum complete node/Core observations under one Core deadline.
    pub max_snapshot_attempts: usize,
    /// Pause between retryable observations. The Core deadline remains in force.
    pub snapshot_retry_delay: Duration,
}

impl Default for ElementsTakerSourceConfig {
    fn default() -> Self {
        Self {
            max_blocking_tasks: DEFAULT_MAX_BLOCKING_TASKS,
            max_snapshot_attempts: DEFAULT_MAX_SNAPSHOT_ATTEMPTS,
            snapshot_retry_delay: DEFAULT_SNAPSHOT_RETRY_DELAY,
        }
    }
}

trait SourceOperationBudget: Clone + Send + Sync + 'static {
    fn check(&self) -> Result<(), ElementsCoreError>;

    fn remaining(&self) -> Result<Duration, ElementsCoreError>;

    fn operation(&self) -> CoreOperation;
}

impl SourceOperationBudget for Arc<OperationBudget> {
    fn check(&self) -> Result<(), ElementsCoreError> {
        OperationBudget::check(self)
    }

    fn remaining(&self) -> Result<Duration, ElementsCoreError> {
        OperationBudget::remaining(self)
    }

    fn operation(&self) -> CoreOperation {
        OperationBudget::operation(self)
    }
}

#[derive(Clone)]
struct SourcePrevout {
    outpoint: OutPoint,
    txout: TxOut,
}

#[derive(Clone)]
struct SourcePrevoutSnapshot {
    anchor: ChainAnchor,
    prevouts: Vec<SourcePrevout>,
}

trait CoreEvidenceHandle: Clone + Send + Sync + 'static {
    type Budget: SourceOperationBudget;

    fn begin_operation(&self, operation: CoreOperation) -> Result<Self::Budget, ElementsCoreError>;

    fn canonical_tip(
        &self,
        budget: &Self::Budget,
        anchor: ChainAnchor,
    ) -> Result<ChainAnchor, ElementsCoreError>;

    fn unspent_prevouts(
        &self,
        budget: &Self::Budget,
        outpoints: &[OutPoint],
        required_anchors: &[ChainAnchor],
    ) -> Result<SourcePrevoutSnapshot, ElementsCoreError>;
}

#[derive(Clone)]
struct ElementsCoreEvidence(ElementsCoreClient);

impl CoreEvidenceHandle for ElementsCoreEvidence {
    type Budget = Arc<OperationBudget>;

    fn begin_operation(&self, operation: CoreOperation) -> Result<Self::Budget, ElementsCoreError> {
        self.0.begin_operation(operation).map(Arc::new)
    }

    fn canonical_tip(
        &self,
        budget: &Self::Budget,
        anchor: ChainAnchor,
    ) -> Result<ChainAnchor, ElementsCoreError> {
        self.0.validate_canonical_anchor_with_budget(budget, anchor)
    }

    fn unspent_prevouts(
        &self,
        budget: &Self::Budget,
        outpoints: &[OutPoint],
        required_anchors: &[ChainAnchor],
    ) -> Result<SourcePrevoutSnapshot, ElementsCoreError> {
        let observed = self
            .0
            .unspent_prevouts_with_budget(budget, outpoints, required_anchors)?;
        Ok(SourcePrevoutSnapshot {
            anchor: observed.anchor(),
            prevouts: observed
                .into_prevouts()
                .into_iter()
                .map(|prevout| SourcePrevout {
                    outpoint: prevout.outpoint(),
                    txout: prevout.into_txout(),
                })
                .collect(),
        })
    }
}

struct SourceInner<R, N> {
    wallet: Arc<PersistentRfqWallet<R>>,
    core: ElementsCoreClient,
    node: N,
    chain: ChainIdentity,
    policy_asset: AssetId,
    max_scan_scripts: usize,
    policy: ElementsTakerSourceConfig,
    blocking_tasks: Arc<Semaphore>,
    core_verified: OnceCell<()>,
}

/// Trusted-node taker evidence backed by one wallet and Elements Core.
///
/// Clones share the exact wallet, Core client, node connection, request-ID
/// sequence, and blocking-task gate. Dropping an async caller cannot cancel a
/// blocking system call, so the acquired permit moves into the blocking task;
/// abandoned work therefore remains concurrency-bounded. Tokio may delay a
/// queued blocking job past its deadline if its global blocking pool is
/// saturated; once scheduled, the expired Core budget makes it fail closed.
pub struct ElementsTakerSource<R = OsRng, N = IrohTakerNodeSource> {
    inner: Arc<SourceInner<R, N>>,
}

impl<R, N> Clone for ElementsTakerSource<R, N> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<R, N> ElementsTakerSource<R, N>
where
    R: RngCore + CryptoRng + Send,
{
    /// Construct a source with conservative default scheduling policy.
    pub fn new(
        core: ElementsCoreConfig,
        chain: ChainIdentity,
        policy_asset: AssetId,
        wallet: Arc<PersistentRfqWallet<R>>,
        node: N,
    ) -> Result<Self, ElementsTakerSourceError> {
        Self::with_config(
            core,
            chain,
            policy_asset,
            wallet,
            node,
            ElementsTakerSourceConfig::default(),
        )
    }

    /// Construct a source with explicit scheduling and convergence bounds.
    pub fn with_config(
        core_config: ElementsCoreConfig,
        chain: ChainIdentity,
        policy_asset: AssetId,
        wallet: Arc<PersistentRfqWallet<R>>,
        node: N,
        policy: ElementsTakerSourceConfig,
    ) -> Result<Self, ElementsTakerSourceError> {
        validate_source_config(policy)?;
        if core_config.max_required_anchors < 2 {
            return Err(ElementsTakerSourceError::InvalidConfiguration(
                "Elements Core required-anchor maximum must be at least two",
            ));
        }
        let wallet_identity = wallet.identity();
        if wallet_identity.genesis_hash() != chain.genesis_hash {
            return Err(ElementsTakerSourceError::WalletChainMismatch {
                wallet: wallet_identity.genesis_hash(),
                configured: chain.genesis_hash,
            });
        }
        if wallet_identity.policy_asset() != policy_asset {
            return Err(ElementsTakerSourceError::WalletPolicyAssetMismatch {
                wallet: wallet_identity.policy_asset(),
                configured: policy_asset,
            });
        }
        let max_scan_scripts = core_config.max_scan_scripts;
        let core = ElementsCoreClient::new(core_config, chain)?;
        Ok(Self {
            inner: Arc::new(SourceInner {
                wallet,
                core,
                node,
                chain,
                policy_asset,
                max_scan_scripts,
                policy,
                blocking_tasks: Arc::new(Semaphore::new(policy.max_blocking_tasks)),
                core_verified: OnceCell::new(),
            }),
        })
    }

    #[must_use]
    pub fn chain(&self) -> ChainIdentity {
        self.inner.chain
    }

    #[must_use]
    pub fn policy_asset(&self) -> AssetId {
        self.inner.policy_asset
    }

    async fn acquire_blocking(
        &self,
        budget: &OperationBudget,
    ) -> Result<OwnedSemaphorePermit, ElementsTakerSourceError> {
        let operation = budget.operation();
        let remaining = budget.remaining()?;
        match timeout(
            remaining,
            Arc::clone(&self.inner.blocking_tasks).acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => {
                budget.check()?;
                Ok(permit)
            }
            Ok(Err(_)) => Err(ElementsTakerSourceError::BlockingGateClosed),
            Err(_) => Err(ElementsTakerSourceError::OperationTimedOut { operation }),
        }
    }

    async fn ensure_core_verified(&self) -> Result<(), ElementsTakerSourceError> {
        self.inner
            .core_verified
            .get_or_try_init(|| async {
                let budget = Arc::new(self.inner.core.begin_operation(CoreOperation::Startup)?);
                let core = self.inner.core.clone();
                let task_budget = Arc::clone(&budget);
                let status = run_source_blocking(&self.inner.blocking_tasks, &budget, move || {
                    core.probe_with_budget(&task_budget)
                })
                .await??;
                validate_core_policy_asset(self.inner.policy_asset, status.pegged_asset())?;
                budget.check()?;
                Ok(())
            })
            .await
            .map(|_| ())
    }
}

impl<R, N> fmt::Debug for ElementsTakerSource<R, N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ElementsTakerSource")
            .field("chain", &self.inner.chain)
            .field("policy_asset", &self.inner.policy_asset)
            .field("wallet", &"[unlocked and redacted]")
            .field("core", &self.inner.core)
            .field("node", &"[authenticated and redacted]")
            .field("policy", &self.inner.policy)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct InventoryScanOutput {
    script_pubkey: Script,
    outpoint: OutPoint,
    txout: TxOut,
}

#[derive(Clone)]
struct InventoryScanSnapshot {
    outputs: Vec<InventoryScanOutput>,
}

trait InventoryScanHandle {
    fn check(&self) -> Result<(), ElementsCoreError>;

    fn scan_unspent_scripts(
        &self,
        scripts: &[Script],
    ) -> Result<InventoryScanSnapshot, ElementsCoreError>;
}

impl InventoryScanHandle for deadcat_elements_core::ScriptScanOperation<'_> {
    fn check(&self) -> Result<(), ElementsCoreError> {
        deadcat_elements_core::ScriptScanOperation::check(self)
    }

    fn scan_unspent_scripts(
        &self,
        scripts: &[Script],
    ) -> Result<InventoryScanSnapshot, ElementsCoreError> {
        let observed =
            deadcat_elements_core::ScriptScanOperation::scan_unspent_scripts(self, scripts)?;
        Ok(InventoryScanSnapshot {
            outputs: observed
                .into_outputs()
                .into_iter()
                .map(|output| InventoryScanOutput {
                    script_pubkey: output.script_pubkey().clone(),
                    outpoint: output.outpoint(),
                    txout: output.into_txout(),
                })
                .collect(),
        })
    }
}

fn inventory_with_scan<R>(
    wallet: &PersistentRfqWallet<R>,
    max_scan_scripts: usize,
    scan: &impl InventoryScanHandle,
) -> Result<Vec<TakerWalletUtxo>, ElementsTakerSourceError>
where
    R: RngCore + CryptoRng + Send,
{
    let catalog = wallet.catalog_snapshot();
    scan.check()?;
    let catalog = catalog?;
    if catalog.locators().len() > max_scan_scripts {
        return Err(ElementsTakerSourceError::CatalogTooLarge {
            maximum: max_scan_scripts,
            actual: catalog.locators().len(),
        });
    }

    let mut by_script = BTreeMap::new();
    for locator in catalog.locators() {
        let destination = wallet.recover_confidential_destination(*locator);
        scan.check()?;
        let destination = destination?;
        let script = destination.script_pubkey().clone();
        if by_script
            .insert(script.as_bytes().to_vec(), (script, *locator))
            .is_some()
        {
            return Err(ElementsTakerSourceError::DuplicateCatalogScript);
        }
    }

    let scripts = by_script
        .values()
        .map(|(script, _)| script.clone())
        .collect::<Vec<_>>();
    let observed = scan.scan_unspent_scripts(&scripts)?;
    let mut outputs = Vec::with_capacity(observed.outputs.len());
    for output in observed.outputs {
        let locator = by_script
            .get(output.script_pubkey.as_bytes())
            .map(|(_, locator)| *locator)
            .ok_or(ElementsTakerSourceError::UnexpectedScanScript(
                output.outpoint,
            ))?;
        outputs.push((locator, output.outpoint, output.txout));
    }

    // Authenticate the catalog and recover every observed output under one
    // wallet operation lock. Besides avoiding one database read per UTXO,
    // this makes the scan fail closed if a destination was issued after the
    // catalog snapshot but before its results were recovered.
    let recovered = wallet.recover_taker_inventory(&catalog, outputs);
    scan.check()?;
    Ok(recovered?)
}

#[async_trait]
impl<R, N> TakerInventorySource for ElementsTakerSource<R, N>
where
    R: RngCore + CryptoRng + Send + 'static,
    N: Send + Sync + 'static,
{
    type Error = ElementsTakerSourceError;

    async fn inventory(&self) -> Result<Vec<TakerWalletUtxo>, Self::Error> {
        self.ensure_core_verified().await?;
        // Start the Core deadline before waiting for a blocking worker. The
        // scan gate is then acquired inside that same budget before any wallet
        // catalog work, preventing an overtaking scan from escaping the bound.
        let budget = self.inner.core.begin_operation(CoreOperation::Scan)?;
        let permit = self.acquire_blocking(&budget).await?;
        let remaining = budget.remaining()?;
        let core = self.inner.core.clone();
        let wallet = Arc::clone(&self.inner.wallet);
        let max_scan_scripts = self.inner.max_scan_scripts;
        let operation = budget.operation();
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let scan = core.begin_script_scan_with_budget(budget)?;
            inventory_with_scan(&wallet, max_scan_scripts, &scan)
        });
        match timeout(remaining, task).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(ElementsTakerSourceError::BlockingTaskPanicked { operation }),
            Err(_) => Err(ElementsTakerSourceError::OperationTimedOut { operation }),
        }
    }
}

struct NodeMarketObservation {
    snapshot: MarketSnapshot,
    anchor: ChainAnchor,
}

#[derive(Clone)]
struct SettlementQuery {
    chain: ChainIdentity,
    market: ContractId,
    quote_anchor: ChainAnchor,
    outpoints: Vec<OutPoint>,
}

async fn acquire_source_blocking<B>(
    blocking_tasks: &Arc<Semaphore>,
    budget: &B,
) -> Result<OwnedSemaphorePermit, ElementsTakerSourceError>
where
    B: SourceOperationBudget,
{
    let operation = budget.operation();
    match timeout(
        budget.remaining()?,
        Arc::clone(blocking_tasks).acquire_owned(),
    )
    .await
    {
        Ok(Ok(permit)) => {
            budget.check()?;
            Ok(permit)
        }
        Ok(Err(_)) => Err(ElementsTakerSourceError::BlockingGateClosed),
        Err(_) => Err(ElementsTakerSourceError::OperationTimedOut { operation }),
    }
}

async fn run_source_blocking<B, T, F>(
    blocking_tasks: &Arc<Semaphore>,
    budget: &B,
    job: F,
) -> Result<T, ElementsTakerSourceError>
where
    B: SourceOperationBudget,
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let permit = acquire_source_blocking(blocking_tasks, budget).await?;
    let operation = budget.operation();
    let remaining = budget.remaining()?;
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        job()
    });
    match timeout(remaining, task).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(_)) => Err(ElementsTakerSourceError::BlockingTaskPanicked { operation }),
        Err(_) => Err(ElementsTakerSourceError::OperationTimedOut { operation }),
    }
}

async fn node_market_observation<N, B>(
    node: &N,
    budget: &B,
    market: ContractId,
    chain: ChainIdentity,
    policy_asset: AssetId,
) -> Result<NodeMarketObservation, ElementsTakerSourceError>
where
    N: TakerNodeSource + ?Sized,
    B: SourceOperationBudget,
{
    let operation = budget.operation();
    let info = timeout(budget.remaining()?, node.get_info())
        .await
        .map_err(|_| ElementsTakerSourceError::OperationTimedOut { operation })?
        .map_err(ElementsTakerSourceError::node)?;
    validate_node_info(&info, chain, policy_asset)?;
    budget.check()?;

    let snapshot = timeout(budget.remaining()?, node.market_snapshot(market))
        .await
        .map_err(|_| ElementsTakerSourceError::OperationTimedOut { operation })?
        .map_err(ElementsTakerSourceError::node)?;
    budget.check()?;
    if snapshot.contract.contract_id != market {
        return Err(ElementsTakerSourceError::WrongMarketSnapshot {
            requested: market,
            returned: snapshot.contract.contract_id,
        });
    }
    if snapshot.snapshot.as_of != info.indexed_tip {
        return Err(ElementsTakerSourceError::NodeSnapshotTipMismatch {
            info: info.indexed_tip,
            snapshot: snapshot.snapshot.as_of,
        });
    }
    Ok(NodeMarketObservation {
        anchor: snapshot.snapshot.as_of,
        snapshot,
    })
}

async fn retry_with_budget<B>(budget: &B, delay: Duration) -> Result<(), ElementsTakerSourceError>
where
    B: SourceOperationBudget,
{
    if delay.is_zero() {
        tokio::task::yield_now().await;
    } else {
        let operation = budget.operation();
        timeout(budget.remaining()?, tokio::time::sleep(delay))
            .await
            .map_err(|_| ElementsTakerSourceError::OperationTimedOut { operation })?;
    }
    budget.check()?;
    Ok(())
}

fn should_retry(
    policy: ElementsTakerSourceConfig,
    attempt: usize,
    error: &ElementsTakerSourceError,
) -> bool {
    attempt + 1 < policy.max_snapshot_attempts && error.is_convergence_race()
}

fn should_retry_market_anchor(
    policy: ElementsTakerSourceConfig,
    attempt: usize,
    error: &ElementsTakerSourceError,
    market_anchor: ChainAnchor,
) -> bool {
    attempt + 1 < policy.max_snapshot_attempts
        && (error.is_convergence_race() || error.is_noncanonical_anchor(market_anchor))
}

fn should_retry_settlement_core(
    policy: ElementsTakerSourceConfig,
    attempt: usize,
    error: &ElementsTakerSourceError,
    quote_anchor: ChainAnchor,
    market_anchor: ChainAnchor,
) -> bool {
    attempt + 1 < policy.max_snapshot_attempts
        && (error.is_convergence_race()
            // A freshly observed market anchor can lose a same-height race
            // while the node and Core converge. A noncanonical quote anchor is
            // fixed provider evidence, however, and must remain terminal. If
            // the two anchors are equal, preserve that stricter quote rule.
            || (market_anchor != quote_anchor && error.is_noncanonical_anchor(market_anchor)))
}

async fn trading_market_with<C, N>(
    core: C,
    node: &N,
    blocking_tasks: &Arc<Semaphore>,
    chain: ChainIdentity,
    policy_asset: AssetId,
    policy: ElementsTakerSourceConfig,
    market: ContractId,
) -> Result<TradingMarket, ElementsTakerSourceError>
where
    C: CoreEvidenceHandle,
    N: TakerNodeSource + ?Sized,
{
    let budget = core.begin_operation(CoreOperation::Anchor)?;
    for attempt in 0..policy.max_snapshot_attempts {
        let observation =
            match node_market_observation(node, &budget, market, chain, policy_asset).await {
                Ok(observation) => observation,
                Err(error) if should_retry(policy, attempt, &error) => {
                    retry_with_budget(&budget, policy.snapshot_retry_delay).await?;
                    continue;
                }
                Err(error) => return Err(error),
            };
        let attempt_core = core.clone();
        let attempt_budget = budget.clone();
        let core_tip = run_source_blocking(blocking_tasks, &budget, move || {
            attempt_core.canonical_tip(&attempt_budget, observation.anchor)
        })
        .await?;
        let core_tip = match core_tip {
            Ok(core_tip) => core_tip,
            Err(error) => {
                let error = ElementsTakerSourceError::Core(error);
                if should_retry_market_anchor(policy, attempt, &error, observation.anchor) {
                    retry_with_budget(&budget, policy.snapshot_retry_delay).await?;
                    continue;
                }
                return Err(error);
            }
        };
        if core_tip != observation.anchor {
            let error = ElementsTakerSourceError::CoreNodeTipMismatch {
                node: observation.anchor,
                core: core_tip,
            };
            if should_retry(policy, attempt, &error) {
                retry_with_budget(&budget, policy.snapshot_retry_delay).await?;
                continue;
            }
            return Err(error);
        }
        let market =
            validated_trading_market(&observation.snapshot, core_tip, chain, policy_asset)?;
        budget.check()?;
        return Ok(market);
    }
    unreachable!("source configuration requires at least one snapshot attempt")
}

async fn settlement_snapshot_with<C, N, F>(
    core: C,
    node: &N,
    blocking_tasks: &Arc<Semaphore>,
    configured_chain: ChainIdentity,
    policy_asset: AssetId,
    policy: ElementsTakerSourceConfig,
    query: SettlementQuery,
    clock: F,
) -> Result<TakerSettlementSnapshot, ElementsTakerSourceError>
where
    C: CoreEvidenceHandle,
    N: TakerNodeSource + ?Sized,
    F: Fn() -> Result<u64, ElementsTakerSourceError>,
{
    // Reject a cross-chain provider response before either authority is
    // queried. This is both cheaper and makes the no-I/O failure boundary
    // observable in tests and production telemetry.
    if query.chain != configured_chain {
        return Err(ElementsTakerSourceError::RequestChainMismatch {
            expected: configured_chain,
            actual: query.chain,
        });
    }
    let budget = core.begin_operation(CoreOperation::Prevouts)?;

    for attempt in 0..policy.max_snapshot_attempts {
        let observation = match node_market_observation(
            node,
            &budget,
            query.market,
            configured_chain,
            policy_asset,
        )
        .await
        {
            Ok(observation) => observation,
            Err(error) if should_retry(policy, attempt, &error) => {
                retry_with_budget(&budget, policy.snapshot_retry_delay).await?;
                continue;
            }
            Err(error) => return Err(error),
        };
        let required_anchors = match required_anchors(query.quote_anchor, observation.anchor) {
            Ok(required_anchors) => required_anchors,
            Err(error) if should_retry(policy, attempt, &error) => {
                retry_with_budget(&budget, policy.snapshot_retry_delay).await?;
                continue;
            }
            Err(error) => return Err(error),
        };
        let attempt_core = core.clone();
        let attempt_budget = budget.clone();
        let outpoints = query.outpoints.clone();
        let prevouts = run_source_blocking(blocking_tasks, &budget, move || {
            attempt_core.unspent_prevouts(&attempt_budget, &outpoints, &required_anchors)
        })
        .await?;
        let prevouts = match prevouts {
            Ok(prevouts) => prevouts,
            Err(error) => {
                let error = ElementsTakerSourceError::Core(error);
                if should_retry_settlement_core(
                    policy,
                    attempt,
                    &error,
                    query.quote_anchor,
                    observation.anchor,
                ) {
                    retry_with_budget(&budget, policy.snapshot_retry_delay).await?;
                    continue;
                }
                return Err(error);
            }
        };
        if prevouts.anchor != observation.anchor {
            let error = ElementsTakerSourceError::CoreNodeTipMismatch {
                node: observation.anchor,
                core: prevouts.anchor,
            };
            if should_retry(policy, attempt, &error) {
                retry_with_budget(&budget, policy.snapshot_retry_delay).await?;
                continue;
            }
            return Err(error);
        }
        let market = validated_trading_market(
            &observation.snapshot,
            prevouts.anchor,
            configured_chain,
            policy_asset,
        )?;
        let prevouts = map_prevouts(&query.outpoints, prevouts)?;
        // Clock sampling is last so quote expiry is checked against the
        // freshest local time possible. A final budget check prevents a result
        // from crossing the operation deadline after that sample.
        let observed_at_millis = clock()?;
        budget.check()?;
        return Ok(TakerSettlementSnapshot::new(
            observed_at_millis,
            market,
            prevouts,
        ));
    }
    unreachable!("source configuration requires at least one snapshot attempt")
}

#[async_trait]
impl<R, N> TakerMarketSource for ElementsTakerSource<R, N>
where
    R: RngCore + CryptoRng + Send + 'static,
    N: TakerNodeSource + 'static,
{
    type Error = ElementsTakerSourceError;

    async fn trading_market(&self, market: ContractId) -> Result<TradingMarket, Self::Error> {
        self.ensure_core_verified().await?;
        trading_market_with(
            ElementsCoreEvidence(self.inner.core.clone()),
            &self.inner.node,
            &self.inner.blocking_tasks,
            self.inner.chain,
            self.inner.policy_asset,
            self.inner.policy,
            market,
        )
        .await
    }
}

#[async_trait]
impl<R, N> TakerSettlementSource for ElementsTakerSource<R, N>
where
    R: RngCore + CryptoRng + Send + 'static,
    N: TakerNodeSource + 'static,
{
    type Error = ElementsTakerSourceError;

    async fn settlement_snapshot(
        &self,
        request: TakerSettlementSnapshotRequest,
    ) -> Result<TakerSettlementSnapshot, Self::Error> {
        if request.chain() != self.inner.chain {
            return Err(ElementsTakerSourceError::RequestChainMismatch {
                expected: self.inner.chain,
                actual: request.chain(),
            });
        }
        self.ensure_core_verified().await?;
        let query = SettlementQuery {
            chain: request.chain(),
            market: request.market(),
            quote_anchor: request.quote_anchor(),
            outpoints: request.outpoints().to_vec(),
        };
        settlement_snapshot_with(
            ElementsCoreEvidence(self.inner.core.clone()),
            &self.inner.node,
            &self.inner.blocking_tasks,
            self.inner.chain,
            self.inner.policy_asset,
            self.inner.policy,
            query,
            system_time_millis,
        )
        .await
    }
}

fn validate_source_config(
    config: ElementsTakerSourceConfig,
) -> Result<(), ElementsTakerSourceError> {
    if config.max_blocking_tasks == 0 {
        return Err(ElementsTakerSourceError::InvalidConfiguration(
            "maximum blocking tasks must be nonzero",
        ));
    }
    if config.max_blocking_tasks > Semaphore::MAX_PERMITS {
        return Err(ElementsTakerSourceError::InvalidConfiguration(
            "maximum blocking tasks exceeds the async semaphore limit",
        ));
    }
    if config.max_snapshot_attempts == 0 {
        return Err(ElementsTakerSourceError::InvalidConfiguration(
            "maximum snapshot attempts must be nonzero",
        ));
    }
    if Instant::now()
        .checked_add(config.snapshot_retry_delay)
        .is_none()
    {
        return Err(ElementsTakerSourceError::InvalidConfiguration(
            "snapshot retry delay exceeds the monotonic clock range",
        ));
    }
    Ok(())
}

fn validate_node_info(
    info: &NodeInfo,
    chain: ChainIdentity,
    policy_asset: AssetId,
) -> Result<(), ElementsTakerSourceError> {
    if info.network != chain.network {
        return Err(ElementsTakerSourceError::NodeNetworkMismatch {
            expected: chain.network,
            actual: info.network,
        });
    }
    if info.genesis_hash != chain.genesis_hash {
        return Err(ElementsTakerSourceError::NodeChainMismatch {
            expected: chain.genesis_hash,
            actual: info.genesis_hash,
        });
    }
    if info.policy_asset != policy_asset {
        return Err(ElementsTakerSourceError::NodePolicyAssetMismatch {
            expected: policy_asset,
            actual: info.policy_asset,
        });
    }
    if info.sync_status != SyncStatus::Ready {
        return Err(ElementsTakerSourceError::NodeNotReady(info.sync_status));
    }
    if info.source_tip != Some(info.indexed_tip) {
        return Err(ElementsTakerSourceError::NodeTipsIncoherent {
            observed_source_tip: info.source_tip,
            indexed: info.indexed_tip,
        });
    }
    for required in [Capability::BinaryMarketV1, Capability::EvidenceQueries] {
        if !info.capabilities.contains(&required) {
            return Err(ElementsTakerSourceError::MissingNodeCapability(required));
        }
    }
    Ok(())
}

fn validate_core_policy_asset(
    expected: AssetId,
    actual: AssetId,
) -> Result<(), ElementsTakerSourceError> {
    if actual != expected {
        return Err(ElementsTakerSourceError::CorePolicyAssetMismatch { expected, actual });
    }
    Ok(())
}

fn validated_trading_market(
    snapshot: &MarketSnapshot,
    trusted_anchor: ChainAnchor,
    chain: ChainIdentity,
    policy_asset: AssetId,
) -> Result<TradingMarket, ElementsTakerSourceError> {
    let validated = validate_market_snapshot(snapshot, trusted_anchor)?;
    TradingMarket::from_validated(&validated, chain, policy_asset).map_err(Into::into)
}

fn required_anchors(
    quote: ChainAnchor,
    market: ChainAnchor,
) -> Result<Vec<ChainAnchor>, ElementsTakerSourceError> {
    if quote == market {
        return Ok(vec![quote]);
    }
    if quote.height == market.height {
        return Err(ElementsTakerSourceError::ConflictingAnchors { quote, market });
    }
    if quote.height > market.height {
        return Err(ElementsTakerSourceError::QuoteAnchorAfterMarket { quote, market });
    }
    Ok(vec![quote, market])
}

fn map_prevouts(
    requested: &[OutPoint],
    observed: SourcePrevoutSnapshot,
) -> Result<Vec<AuthoritativeTakerPrevout>, ElementsTakerSourceError> {
    if requested.len() != observed.prevouts.len()
        || requested
            .iter()
            .zip(&observed.prevouts)
            .any(|(requested, returned)| requested != &returned.outpoint)
    {
        return Err(ElementsTakerSourceError::PrevoutOrderMismatch);
    }
    Ok(observed
        .prevouts
        .into_iter()
        .map(|prevout| AuthoritativeTakerPrevout::new(prevout.outpoint, prevout.txout))
        .collect())
}

fn system_time_millis() -> Result<u64, ElementsTakerSourceError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ElementsTakerSourceError::ClockBeforeUnixEpoch)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| ElementsTakerSourceError::ClockOverflow)
}

/// Fail-closed trusted-node taker-source error.
#[derive(Debug, Error)]
pub enum ElementsTakerSourceError {
    #[error("invalid taker source configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error(transparent)]
    Core(#[from] ElementsCoreError),
    #[error("authenticated Deadcat node request failed")]
    Node(#[source] Box<dyn Error + Send + Sync>),
    #[error("taker wallet is bound to genesis {wallet}, but source is configured for {configured}")]
    WalletChainMismatch {
        wallet: BlockHash,
        configured: BlockHash,
    },
    #[error(
        "taker wallet is bound to policy asset {wallet}, but source is configured for {configured}"
    )]
    WalletPolicyAssetMismatch {
        wallet: AssetId,
        configured: AssetId,
    },
    #[error("settlement request targets {actual:?}, expected {expected:?}")]
    RequestChainMismatch {
        expected: ChainIdentity,
        actual: ChainIdentity,
    },
    #[error("node network {actual:?} does not match configured {expected:?}")]
    NodeNetworkMismatch {
        expected: LiquidNetwork,
        actual: LiquidNetwork,
    },
    #[error("node genesis {actual} does not match configured {expected}")]
    NodeChainMismatch {
        expected: BlockHash,
        actual: BlockHash,
    },
    #[error("node policy asset {actual} does not match configured {expected}")]
    NodePolicyAssetMismatch { expected: AssetId, actual: AssetId },
    #[error("Core pegged asset {actual} does not match configured {expected}")]
    CorePolicyAssetMismatch { expected: AssetId, actual: AssetId },
    #[error("node is not ready: {0:?}")]
    NodeNotReady(SyncStatus),
    #[error("node source tip {observed_source_tip:?} does not equal indexed tip {indexed:?}")]
    NodeTipsIncoherent {
        observed_source_tip: Option<ChainAnchor>,
        indexed: ChainAnchor,
    },
    #[error("node does not advertise required capability {0:?}")]
    MissingNodeCapability(Capability),
    #[error("node returned market {returned:?}, requested {requested:?}")]
    WrongMarketSnapshot {
        requested: ContractId,
        returned: ContractId,
    },
    #[error("node info tip {info:?} does not equal market snapshot tip {snapshot:?}")]
    NodeSnapshotTipMismatch {
        info: ChainAnchor,
        snapshot: ChainAnchor,
    },
    #[error("node market tip {node:?} does not equal independent Core tip {core:?}")]
    CoreNodeTipMismatch {
        node: ChainAnchor,
        core: ChainAnchor,
    },
    #[error("quote anchor {quote:?} conflicts with market anchor {market:?}")]
    ConflictingAnchors {
        quote: ChainAnchor,
        market: ChainAnchor,
    },
    #[error("quote anchor {quote:?} is newer than market anchor {market:?}")]
    QuoteAnchorAfterMarket {
        quote: ChainAnchor,
        market: ChainAnchor,
    },
    #[error("Core returned prevouts in a different count or order")]
    PrevoutOrderMismatch,
    #[error("wallet catalog has {actual} scripts; scan maximum is {maximum}")]
    CatalogTooLarge { maximum: usize, actual: usize },
    #[error("wallet catalog resolves two locators to the same script")]
    DuplicateCatalogScript,
    #[error("wallet-neutral Core scan returned an unrequested script at {0:?}")]
    UnexpectedScanScript(OutPoint),
    #[error(transparent)]
    Wallet(#[from] PersistentWalletError),
    #[error("source blocking-task gate unexpectedly closed")]
    BlockingGateClosed,
    #[error("source {operation:?} blocking task panicked")]
    BlockingTaskPanicked { operation: CoreOperation },
    #[error("source {operation:?} operation exceeded its shared deadline")]
    OperationTimedOut { operation: CoreOperation },
    #[error("system clock is before the Unix epoch")]
    ClockBeforeUnixEpoch,
    #[error("system clock milliseconds do not fit u64")]
    ClockOverflow,
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Venue(#[from] RfqVenueError),
}

impl ElementsTakerSourceError {
    fn node<E>(error: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self::Node(Box::new(error))
    }

    fn is_convergence_race(&self) -> bool {
        matches!(
            self,
            Self::NodeSnapshotTipMismatch { .. }
                | Self::CoreNodeTipMismatch { .. }
                | Self::QuoteAnchorAfterMarket { .. }
                | Self::Core(
                    ElementsCoreError::TipChanged { .. }
                        | ElementsCoreError::AnchorAboveTip { .. }
                        | ElementsCoreError::InconsistentChainTip { .. }
                        | ElementsCoreError::PrevoutViewChanged(_)
                )
        )
    }

    fn is_noncanonical_anchor(&self, expected: ChainAnchor) -> bool {
        matches!(
            self,
            Self::Core(ElementsCoreError::AnchorNotCanonical { anchor, .. })
                if *anchor == expected
        )
    }
}

#[cfg(test)]
mod tests;

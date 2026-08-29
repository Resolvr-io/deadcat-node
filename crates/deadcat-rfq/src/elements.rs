//! Provider-wallet adapter over the wallet-neutral Elements Core client.
//!
//! [`deadcat_elements_core`] owns bounded RPC transport, exact chain binding,
//! coherent script scans, authoritative prevout materialization, and exact
//! transaction relay. This module adds only the provider wallet catalog,
//! output recovery, and provider-domain result conversions.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

pub use deadcat_elements_core::{
    COINBASE_MATURITY_CONFIRMATIONS, DEFAULT_ANCHOR_TIMEOUT, DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_MAX_MATERIALIZED_TXOUT_BYTES, DEFAULT_MAX_PREVOUTS, DEFAULT_MAX_RAW_TRANSACTION_BYTES,
    DEFAULT_MAX_REQUEST_BYTES, DEFAULT_MAX_REQUIRED_ANCHORS, DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_MAX_SCAN_RESULTS, DEFAULT_MAX_SCAN_SCRIPTS, DEFAULT_PREVOUT_TIMEOUT,
    DEFAULT_RELAY_TIMEOUT, DEFAULT_REQUEST_TIMEOUT, DEFAULT_SCAN_TIMEOUT, DEFAULT_STARTUP_TIMEOUT,
    ElementsCoreAuth, ElementsCoreChainStatus, ElementsCoreConfig,
};
use deadcat_elements_core::{
    CoreOperation, CoreRelayObservation, ElementsCoreClient, ElementsCoreError, ExactTransaction,
};
use deadcat_rfq_provider::{
    AuthoritativePrevout, InventorySnapshot, InventorySource, ProviderIdentity,
    RelayAttempt as DurableRelayAttempt, RelayFailureClass, RelayObservation,
    SettlementChainSource, WalletBoundaryError, WalletKeyLocator, WalletScanAnchor,
};
use deadcat_rfq_wallet::PersistentWalletError;
use deadcat_types::{ChainAnchor, ChainIdentity};
use elements::{BlockHash, OutPoint, Script, TxOut};
use thiserror::Error;

use crate::SharedRfqWallet;
use crate::relay::{ProviderRelaySource, RelayAttemptResult, RelaySourceError};

/// Probe one configured Core endpoint against an exact expected chain.
///
/// This does not open or inspect a provider wallet. A successful result also
/// proves that Core is out of IBD, exposes a synchronized transaction index,
/// and reports a self-consistent pegged asset and canonical tip.
pub fn probe_elements_core(
    config: &ElementsCoreConfig,
    chain: ChainIdentity,
) -> Result<ElementsCoreChainStatus, ElementsCoreError> {
    ElementsCoreClient::new(config.clone(), chain)?.probe()
}

#[derive(Clone)]
struct InventoryScanOutput {
    script_pubkey: Script,
    outpoint: OutPoint,
    txout: TxOut,
}

#[derive(Clone)]
struct InventoryScanSnapshot {
    anchor: ChainAnchor,
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
            anchor: observed.anchor(),
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

struct SourceInner {
    wallet: SharedRfqWallet,
    core: ElementsCoreClient,
    max_scan_scripts: usize,
}

/// Blocking provider adapter shared by inventory, settlement validation, and
/// the durable relay worker.
///
/// Clones share the exact wallet, Core client, and Core script-scan gate. Async
/// runtimes must move complete calls behind a blocking-task boundary.
#[derive(Clone)]
pub struct ElementsCoreSource {
    inner: Arc<SourceInner>,
}

impl ElementsCoreSource {
    pub fn new(
        config: ElementsCoreConfig,
        chain: ChainIdentity,
        wallet: SharedRfqWallet,
    ) -> Result<Self, ElementsCoreSourceError> {
        let max_scan_scripts = config.max_scan_scripts;
        let core = ElementsCoreClient::new(config, chain)?;
        Self::from_client(core, max_scan_scripts, wallet)
    }

    fn from_client(
        core: ElementsCoreClient,
        max_scan_scripts: usize,
        wallet: SharedRfqWallet,
    ) -> Result<Self, ElementsCoreSourceError> {
        let identity = wallet.identity();
        if core.chain().genesis_hash != identity.genesis_hash() {
            return Err(ElementsCoreSourceError::WalletChainMismatch {
                wallet: identity.genesis_hash(),
                configured: core.chain().genesis_hash,
            });
        }
        Ok(Self {
            inner: Arc::new(SourceInner {
                wallet,
                core,
                max_scan_scripts,
            }),
        })
    }

    #[must_use]
    pub fn identity(&self) -> ProviderIdentity {
        self.inner.wallet.identity()
    }

    fn inventory_snapshot_inner(&self) -> Result<InventorySnapshot, ElementsCoreSourceError> {
        // The scan handle intentionally starts the deadline and acquires the
        // shared scantxoutset gate before any wallet work. Otherwise a slow
        // catalog read/recovery could escape the advertised operation bound,
        // and another clone could overtake this coherent scan.
        let scan = self.inner.core.begin_script_scan()?;
        inventory_snapshot_with_scan(&self.inner.wallet, self.inner.max_scan_scripts, &scan)
    }

    fn unspent_prevouts_inner(
        &self,
        outpoints: &[OutPoint],
    ) -> Result<Vec<AuthoritativePrevout>, ElementsCoreSourceError> {
        let budget = self.inner.core.begin_operation(CoreOperation::Prevouts)?;
        let observed = self
            .inner
            .core
            .unspent_prevouts_with_budget(&budget, outpoints, &[])?;
        let authoritative = observed
            .into_prevouts()
            .into_iter()
            .map(|prevout| AuthoritativePrevout::new(prevout.outpoint(), prevout.into_txout()))
            .collect();
        budget.check()?;
        Ok(authoritative)
    }

    fn relay_once_inner(
        &self,
        attempt: &DurableRelayAttempt,
    ) -> Result<RelayAttemptResult, ElementsCoreSourceError> {
        // Start before even validating/materializing the durable exact bytes;
        // the provider reports success only while this same budget is live.
        let budget = self.inner.core.begin_operation(CoreOperation::Relay)?;
        let exact =
            ExactTransaction::new(attempt.txid(), attempt.wtxid(), attempt.transaction_bytes());
        let result = self.inner.core.relay_exact_with_budget(&budget, exact)?;
        let mapped = provider_relay_result(result.observation(), result.was_policy_rejected());
        if result.was_policy_rejected() {
            tracing::warn!(
                txid = %attempt.txid(),
                reason = result.policy_rejection_reason().unwrap_or("unspecified policy rejection"),
                "Elements Core policy rejected exact RFQ settlement"
            );
        }
        budget.check()?;
        Ok(mapped)
    }
}

fn inventory_snapshot_with_scan(
    wallet: &SharedRfqWallet,
    max_scan_scripts: usize,
    scan: &impl InventoryScanHandle,
) -> Result<InventorySnapshot, ElementsCoreSourceError> {
    let catalog = wallet.catalog_snapshot();
    scan.check()?;
    let catalog = catalog?;
    if catalog.locators().len() > max_scan_scripts {
        return Err(ElementsCoreSourceError::CatalogTooLarge {
            maximum: max_scan_scripts,
            actual: catalog.locators().len(),
        });
    }

    let mut by_script = BTreeMap::<Vec<u8>, (Script, WalletKeyLocator)>::new();
    for locator in catalog.locators() {
        let destination = wallet.recover_confidential_destination(*locator);
        scan.check()?;
        let destination = destination?;
        let script = destination.script_pubkey().clone();
        if by_script
            .insert(script.as_bytes().to_vec(), (script, *locator))
            .is_some()
        {
            return Err(ElementsCoreSourceError::DuplicateCatalogScript);
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
            .ok_or(ElementsCoreSourceError::UnexpectedScanScript(
                output.outpoint,
            ))?;
        let recovered = wallet.recover_owned_output(locator, output.outpoint, output.txout);
        scan.check()?;
        outputs.push(recovered?);
    }

    let current_revision = wallet.catalog_revision();
    scan.check()?;
    let current_revision = current_revision?;
    if current_revision != catalog.revision() {
        return Err(ElementsCoreSourceError::CatalogChangedDuringScan {
            before: catalog.revision(),
            after: current_revision,
        });
    }
    let snapshot = InventorySnapshot::new(
        wallet.identity(),
        WalletScanAnchor::new(observed.anchor.hash, observed.anchor.height),
        outputs,
    )?;
    scan.check()?;
    Ok(snapshot)
}

impl fmt::Debug for ElementsCoreSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ElementsCoreSource")
            .field("identity", &self.identity())
            .field("wallet", &"[unlocked and redacted]")
            .field("core", &self.inner.core)
            .field("max_scan_scripts", &self.inner.max_scan_scripts)
            .finish_non_exhaustive()
    }
}

impl InventorySource for ElementsCoreSource {
    type Error = ElementsCoreSourceError;

    fn inventory_snapshot(&self) -> Result<InventorySnapshot, Self::Error> {
        self.inventory_snapshot_inner()
    }
}

impl SettlementChainSource for ElementsCoreSource {
    type Error = ElementsCoreSourceError;

    fn genesis_hash(&self) -> BlockHash {
        self.identity().genesis_hash()
    }

    fn unspent_prevouts(
        &self,
        outpoints: &[OutPoint],
    ) -> Result<Vec<AuthoritativePrevout>, Self::Error> {
        self.unspent_prevouts_inner(outpoints)
    }
}

impl ProviderRelaySource for ElementsCoreSource {
    type Error = ElementsCoreSourceError;

    fn relay_once(
        &self,
        attempt: &DurableRelayAttempt,
    ) -> Result<RelayAttemptResult, RelaySourceError<Self::Error>> {
        self.relay_once_inner(attempt)
            .map_err(|error| RelaySourceError::new(relay_failure_class(&error), error))
    }
}

const fn provider_observation(observation: CoreRelayObservation) -> RelayObservation {
    match observation {
        CoreRelayObservation::BroadcastAccepted => RelayObservation::BroadcastAccepted,
        CoreRelayObservation::Mempool => RelayObservation::Mempool,
        CoreRelayObservation::Confirmed {
            block_hash,
            block_height,
        } => RelayObservation::Confirmed {
            block_hash,
            block_height,
        },
        CoreRelayObservation::Absent => RelayObservation::Absent,
        CoreRelayObservation::Conflicted {
            spent_input,
            conflicting_txid,
        } => RelayObservation::Conflicted {
            spent_input,
            conflicting_txid,
        },
    }
}

const fn provider_relay_result(
    observation: CoreRelayObservation,
    policy_rejected: bool,
) -> RelayAttemptResult {
    let observation = provider_observation(observation);
    if policy_rejected {
        RelayAttemptResult::policy_rejected(observation)
    } else {
        RelayAttemptResult::observed(observation)
    }
}

fn relay_failure_class(error: &ElementsCoreSourceError) -> RelayFailureClass {
    match error {
        ElementsCoreSourceError::Core(error) if error.is_backend_unavailable() => {
            RelayFailureClass::BackendUnavailable
        }
        _ => RelayFailureClass::InvalidBackendData,
    }
}

/// Fail-closed provider-wallet adaptation error.
#[derive(Debug, Error)]
pub enum ElementsCoreSourceError {
    #[error(transparent)]
    Core(#[from] ElementsCoreError),
    #[error(
        "provider wallet is bound to genesis {wallet}, but Core client is configured for {configured}"
    )]
    WalletChainMismatch {
        wallet: BlockHash,
        configured: BlockHash,
    },
    #[error("wallet catalog has {actual} scripts; scan maximum is {maximum}")]
    CatalogTooLarge { maximum: usize, actual: usize },
    #[error("wallet catalog resolves two locators to the same script")]
    DuplicateCatalogScript,
    #[error("wallet-neutral Core scan returned an unrequested script at {0:?}")]
    UnexpectedScanScript(OutPoint),
    #[error("wallet catalog revision changed from {before} to {after} during scan")]
    CatalogChangedDuringScan { before: u64, after: u64 },
    #[error(transparent)]
    Wallet(#[from] PersistentWalletError),
    #[error(transparent)]
    WalletBoundary(#[from] WalletBoundaryError),
}

#[cfg(test)]
mod tests;

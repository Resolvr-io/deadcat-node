//! Bounded synchronous Elements Core adapter for provider inventory and final
//! settlement validation.
//!
//! Inventory discovery is intentionally walletless from Elements Core's point
//! of view. The adapter scans the confirmed UTXO set for the durable custom-
//! wallet script catalog, fetches each complete creating transaction, and asks
//! the custom wallet to authenticate and unblind matching outputs. Settlement
//! validation separately uses mempool-aware `gettxout` checks immediately
//! before commitment and returns complete ordered prevouts from raw creating
//! transactions.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::Read as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use deadcat_rfq_provider::{
    AuthoritativePrevout, InventorySnapshot, InventorySource, ProviderIdentity,
    SettlementChainSource, WalletBoundaryError, WalletKeyLocator, WalletScanAnchor,
};
use deadcat_rfq_wallet::PersistentWalletError;
use elements::encode::deserialize;
use elements::{BlockHash, OutPoint, Script, Transaction, TxOut, Txid};
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::{Method, StatusCode, Url};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value as JsonValue, json};
use thiserror::Error;

use crate::SharedRfqWallet;

/// Default TCP/TLS connection timeout.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default timeout for one complete RPC, including a UTXO-set scan.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Default wall-clock deadline for one complete inventory snapshot operation.
pub const DEFAULT_INVENTORY_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Default wall-clock deadline for one complete settlement prevout operation.
pub const DEFAULT_SETTLEMENT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default maximum serialized JSON request size.
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;
/// Default maximum serialized JSON response size.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
/// Default maximum number of historical wallet scripts in one coherent scan.
pub const DEFAULT_MAX_SCAN_SCRIPTS: usize = 100_000;
/// Default maximum number of matching UTXOs returned by one scan.
pub const DEFAULT_MAX_SCAN_RESULTS: usize = 10_000;
/// Default maximum number of settlement prevouts checked in one operation.
pub const DEFAULT_MAX_SETTLEMENT_PREVOUTS: usize = 32;
/// Default maximum decoded size of one raw creating transaction.
pub const DEFAULT_MAX_RAW_TRANSACTION_BYTES: usize = 4 * 1024 * 1024;
/// Confirmations required before a coinbase output may be spent.
///
/// Elements inherits Bitcoin's 100-block coinbase maturity rule. A coinbase
/// output is eligible when `gettxout` reports at least this many confirmations,
/// which makes it spendable in the next block.
pub const COINBASE_MATURITY_CONFIRMATIONS: u64 = 100;

const MAX_COOKIE_BYTES: usize = 4 * 1024;
const MAX_BACKEND_ERROR_CHARS: usize = 512;
const INVENTORY_OPERATION: &str = "inventory";
const SETTLEMENT_OPERATION: &str = "settlement";

/// Authentication for the provider's trusted Elements Core RPC endpoint.
#[derive(Clone, PartialEq, Eq)]
pub enum ElementsCoreAuth {
    None,
    Basic {
        username: String,
        password: String,
    },
    /// Bitcoin-style `username:password` cookie, re-read for every request.
    CookieFile(PathBuf),
}

impl fmt::Debug for ElementsCoreAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => formatter.write_str("None"),
            Self::Basic { username, .. } => formatter
                .debug_struct("Basic")
                .field("username", username)
                .field("password", &"[redacted]")
                .finish(),
            Self::CookieFile(path) => formatter.debug_tuple("CookieFile").field(path).finish(),
        }
    }
}

/// Bounded connection and result policy for Elements Core.
#[derive(Clone, Debug)]
pub struct ElementsCoreConfig {
    pub url: String,
    pub auth: ElementsCoreAuth,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub inventory_timeout: Duration,
    pub settlement_timeout: Duration,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_scan_scripts: usize,
    pub max_scan_results: usize,
    pub max_settlement_prevouts: usize,
    pub max_raw_transaction_bytes: usize,
}

impl ElementsCoreConfig {
    #[must_use]
    pub fn new(url: impl Into<String>, auth: ElementsCoreAuth) -> Self {
        Self {
            url: url.into(),
            auth,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            inventory_timeout: DEFAULT_INVENTORY_TIMEOUT,
            settlement_timeout: DEFAULT_SETTLEMENT_TIMEOUT,
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_scan_scripts: DEFAULT_MAX_SCAN_SCRIPTS,
            max_scan_results: DEFAULT_MAX_SCAN_RESULTS,
            max_settlement_prevouts: DEFAULT_MAX_SETTLEMENT_PREVOUTS,
            max_raw_transaction_bytes: DEFAULT_MAX_RAW_TRANSACTION_BYTES,
        }
    }

    fn validate(&self) -> Result<Url, ElementsCoreSourceError> {
        if self.connect_timeout.is_zero()
            || self.request_timeout.is_zero()
            || self.inventory_timeout.is_zero()
            || self.settlement_timeout.is_zero()
        {
            return Err(ElementsCoreSourceError::InvalidConfiguration(
                "Elements RPC and operation timeouts must be nonzero",
            ));
        }
        let now = Instant::now();
        if now.checked_add(self.inventory_timeout).is_none()
            || now.checked_add(self.settlement_timeout).is_none()
        {
            return Err(ElementsCoreSourceError::InvalidConfiguration(
                "Elements operation timeout exceeds the monotonic clock range",
            ));
        }
        if self.max_request_bytes == 0
            || self.max_response_bytes == 0
            || self.max_scan_scripts == 0
            || self.max_scan_results == 0
            || self.max_settlement_prevouts == 0
            || self.max_raw_transaction_bytes == 0
        {
            return Err(ElementsCoreSourceError::InvalidConfiguration(
                "Elements RPC bounds must be nonzero",
            ));
        }
        let minimum_raw_response = self
            .max_raw_transaction_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(1_024))
            .ok_or(ElementsCoreSourceError::InvalidConfiguration(
                "raw-transaction response bound overflows",
            ))?;
        if self.max_response_bytes < minimum_raw_response {
            return Err(ElementsCoreSourceError::InvalidConfiguration(
                "response bound cannot contain the configured raw transaction bound",
            ));
        }
        match &self.auth {
            ElementsCoreAuth::Basic { username, password }
                if username.is_empty() || password.is_empty() =>
            {
                return Err(ElementsCoreSourceError::InvalidConfiguration(
                    "basic-auth username and password must be nonempty",
                ));
            }
            ElementsCoreAuth::CookieFile(path) if path.as_os_str().is_empty() => {
                return Err(ElementsCoreSourceError::InvalidConfiguration(
                    "cookie path must be nonempty",
                ));
            }
            _ => {}
        }
        let url = Url::parse(&self.url).map_err(|error| {
            ElementsCoreSourceError::InvalidUrl(format!("invalid Elements RPC URL: {error}"))
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ElementsCoreSourceError::InvalidConfiguration(
                "Elements RPC URL must use http or https",
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ElementsCoreSourceError::InvalidConfiguration(
                "put Elements RPC credentials in ElementsCoreAuth, not in the URL",
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(ElementsCoreSourceError::InvalidConfiguration(
                "Elements RPC URL cannot contain a query or fragment",
            ));
        }
        Ok(url)
    }
}

#[derive(Clone, Copy, Debug)]
struct SourceLimits {
    request_timeout: Duration,
    inventory_timeout: Duration,
    settlement_timeout: Duration,
    max_scan_scripts: usize,
    max_scan_results: usize,
    max_settlement_prevouts: usize,
    max_raw_transaction_bytes: usize,
}

impl SourceLimits {
    fn from_config(config: &ElementsCoreConfig) -> Self {
        Self {
            request_timeout: config.request_timeout,
            inventory_timeout: config.inventory_timeout,
            settlement_timeout: config.settlement_timeout,
            max_scan_scripts: config.max_scan_scripts,
            max_scan_results: config.max_scan_results,
            max_settlement_prevouts: config.max_settlement_prevouts,
            max_raw_transaction_bytes: config.max_raw_transaction_bytes,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct OperationDeadline {
    operation: &'static str,
    expires_at: Instant,
}

impl OperationDeadline {
    fn start(operation: &'static str, timeout: Duration) -> Result<Self, ElementsCoreSourceError> {
        let expires_at = Instant::now().checked_add(timeout).ok_or(
            ElementsCoreSourceError::InvalidConfiguration(
                "Elements operation timeout exceeds the monotonic clock range",
            ),
        )?;
        Ok(Self {
            operation,
            expires_at,
        })
    }

    fn remaining(self) -> Result<Duration, ElementsCoreSourceError> {
        self.expires_at
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(ElementsCoreSourceError::OperationTimedOut {
                operation: self.operation,
            })
    }

    fn check(self) -> Result<(), ElementsCoreSourceError> {
        self.remaining().map(|_| ())
    }

    fn rpc_budget(self, request_timeout: Duration) -> RpcCallBudget {
        RpcCallBudget {
            deadline: self,
            request_timeout,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct RpcCallBudget {
    deadline: OperationDeadline,
    request_timeout: Duration,
}

impl RpcCallBudget {
    fn timeout(self) -> Result<RpcCallTimeout, ElementsCoreSourceError> {
        let remaining = self.deadline.remaining()?;
        Ok(RpcCallTimeout {
            duration: remaining.min(self.request_timeout),
            operation: self.deadline.operation,
            operation_limited: remaining <= self.request_timeout,
            expires_at: self.deadline.expires_at,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct RpcCallTimeout {
    duration: Duration,
    operation: &'static str,
    operation_limited: bool,
    expires_at: Instant,
}

impl RpcCallTimeout {
    fn timeout_error(self, method: &str, error: &reqwest::Error) -> ElementsCoreSourceError {
        if self.operation_limited && error.is_timeout() && Instant::now() >= self.expires_at {
            ElementsCoreSourceError::OperationTimedOut {
                operation: self.operation,
            }
        } else {
            transport_error(method, error)
        }
    }
}

trait RpcTransport: Send + Sync {
    fn call(
        &self,
        method: &'static str,
        params: JsonValue,
        budget: RpcCallBudget,
    ) -> Result<JsonValue, ElementsCoreSourceError>;
}

struct HttpRpcTransport {
    client: Client,
    url: Url,
    auth: ElementsCoreAuth,
    max_request_bytes: usize,
    max_response_bytes: usize,
    next_id: AtomicU64,
}

impl fmt::Debug for HttpRpcTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpRpcTransport")
            .field("url", &self.url)
            .field("auth", &self.auth)
            .field("max_request_bytes", &self.max_request_bytes)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

impl HttpRpcTransport {
    fn new(config: ElementsCoreConfig, url: Url) -> Result<Self, ElementsCoreSourceError> {
        let client = Client::builder()
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .build()
            .map_err(|error| {
                ElementsCoreSourceError::BackendUnavailable(format!(
                    "cannot build Elements RPC client: {error}"
                ))
            })?;
        Ok(Self {
            client,
            url,
            auth: config.auth,
            max_request_bytes: config.max_request_bytes,
            max_response_bytes: config.max_response_bytes,
            next_id: AtomicU64::new(1),
        })
    }

    fn authenticated(
        &self,
        request: RequestBuilder,
    ) -> Result<RequestBuilder, ElementsCoreSourceError> {
        match &self.auth {
            ElementsCoreAuth::None => Ok(request),
            ElementsCoreAuth::Basic { username, password } => {
                Ok(request.basic_auth(username, Some(password)))
            }
            ElementsCoreAuth::CookieFile(path) => {
                let (username, password) = read_cookie(path)?;
                Ok(request.basic_auth(username, Some(password)))
            }
        }
    }
}

impl RpcTransport for HttpRpcTransport {
    fn call(
        &self,
        method: &'static str,
        params: JsonValue,
        budget: RpcCallBudget,
    ) -> Result<JsonValue, ElementsCoreSourceError> {
        let id = self
            .next_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| ElementsCoreSourceError::RpcIdExhausted)?;
        let payload = serde_json::to_vec(&json!({
            "jsonrpc": "1.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .map_err(|error| {
            ElementsCoreSourceError::InvalidRpcResponse(format!(
                "cannot encode {method} request: {error}"
            ))
        })?;
        if payload.len() > self.max_request_bytes {
            return Err(ElementsCoreSourceError::RequestTooLarge {
                maximum: self.max_request_bytes,
                actual: payload.len(),
            });
        }
        let request = self.authenticated(
            self.client
                .request(Method::POST, self.url.clone())
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(payload),
        )?;
        // Calculate this after request encoding and cookie authentication so
        // every HTTP request gets only the operation time that is still left.
        let timeout = budget.timeout()?;
        let response = request
            .timeout(timeout.duration)
            .send()
            .map_err(|error| timeout.timeout_error(method, &error))?;
        let (status, body) = read_bounded(response, self.max_response_bytes)?;
        parse_rpc_envelope(method, id, status, &body)
    }
}

#[derive(Default)]
struct InventoryGate {
    active: Mutex<bool>,
    available: Condvar,
}

impl InventoryGate {
    fn acquire(
        &self,
        deadline: OperationDeadline,
    ) -> Result<InventoryPermit<'_>, ElementsCoreSourceError> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| ElementsCoreSourceError::InventoryLockPoisoned)?;
        loop {
            deadline.check()?;
            if !*active {
                *active = true;
                return Ok(InventoryPermit { gate: self });
            }
            let (next, waited) = self
                .available
                .wait_timeout(active, deadline.remaining()?)
                .map_err(|_| ElementsCoreSourceError::InventoryLockPoisoned)?;
            active = next;
            if waited.timed_out() {
                return Err(ElementsCoreSourceError::OperationTimedOut {
                    operation: deadline.operation,
                });
            }
        }
    }
}

struct InventoryPermit<'a> {
    gate: &'a InventoryGate,
}

impl Drop for InventoryPermit<'_> {
    fn drop(&mut self) {
        let mut active = self
            .gate
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *active = false;
        self.gate.available.notify_one();
    }
}

struct SourceInner {
    wallet: SharedRfqWallet,
    rpc: Arc<dyn RpcTransport>,
    limits: SourceLimits,
    inventory_gate: InventoryGate,
}

/// Elements Core source shared by the inventory coordinator and final-PSET
/// validator.
///
/// Clones share the same wallet, transport, and inventory gate. Inventory scans
/// are serialized because Elements Core permits only one `scantxoutset` scan at
/// a time. Settlement checks deliberately bypass that gate, so a long inventory
/// refresh cannot delay a final pre-commitment check. Elements Core state can
/// still change immediately after either operation returns.
///
/// This adapter performs synchronous, blocking HTTP and wallet I/O. Async
/// daemons must invoke it behind their runtime's blocking-task boundary rather
/// than on an async executor worker.
#[derive(Clone)]
pub struct ElementsCoreSource {
    inner: Arc<SourceInner>,
}

impl ElementsCoreSource {
    pub fn new(
        config: ElementsCoreConfig,
        wallet: SharedRfqWallet,
    ) -> Result<Self, ElementsCoreSourceError> {
        let url = config.validate()?;
        let limits = SourceLimits::from_config(&config);
        let transport = Arc::new(HttpRpcTransport::new(config, url)?);
        Ok(Self::with_parts(limits, wallet, transport))
    }

    #[cfg(test)]
    fn from_parts(
        config: &ElementsCoreConfig,
        wallet: SharedRfqWallet,
        rpc: Arc<dyn RpcTransport>,
    ) -> Self {
        Self::with_parts(SourceLimits::from_config(config), wallet, rpc)
    }

    fn with_parts(
        limits: SourceLimits,
        wallet: SharedRfqWallet,
        rpc: Arc<dyn RpcTransport>,
    ) -> Self {
        Self {
            inner: Arc::new(SourceInner {
                wallet,
                rpc,
                limits,
                inventory_gate: InventoryGate::default(),
            }),
        }
    }

    #[must_use]
    pub fn identity(&self) -> ProviderIdentity {
        self.inner.wallet.identity()
    }

    fn lock_inventory(
        &self,
        deadline: OperationDeadline,
    ) -> Result<InventoryPermit<'_>, ElementsCoreSourceError> {
        self.inner.inventory_gate.acquire(deadline)
    }

    fn call<T: DeserializeOwned>(
        &self,
        method: &'static str,
        params: JsonValue,
        deadline: OperationDeadline,
    ) -> Result<T, ElementsCoreSourceError> {
        deadline.check()?;
        let value = self.inner.rpc.call(
            method,
            params,
            deadline.rpc_budget(self.inner.limits.request_timeout),
        )?;
        let result = serde_json::from_value(value).map_err(|error| {
            ElementsCoreSourceError::InvalidRpcResponse(format!("invalid {method} result: {error}"))
        })?;
        deadline.check()?;
        Ok(result)
    }

    fn block_hash(
        &self,
        height: u32,
        deadline: OperationDeadline,
    ) -> Result<BlockHash, ElementsCoreSourceError> {
        self.call("getblockhash", json!([height]), deadline)
    }

    fn best_block_hash(
        &self,
        deadline: OperationDeadline,
    ) -> Result<BlockHash, ElementsCoreSourceError> {
        self.call("getbestblockhash", json!([]), deadline)
    }

    fn validate_chain_identity(
        &self,
        deadline: OperationDeadline,
    ) -> Result<(), ElementsCoreSourceError> {
        let actual = self.block_hash(0, deadline)?;
        let expected = self.identity().genesis_hash();
        if actual != expected {
            return Err(ElementsCoreSourceError::WrongChain { expected, actual });
        }
        Ok(())
    }

    fn validate_txindex(&self, deadline: OperationDeadline) -> Result<(), ElementsCoreSourceError> {
        let indexes: JsonValue = self.call("getindexinfo", json!([]), deadline)?;
        let txindex = indexes
            .as_object()
            .and_then(|indexes| indexes.get("txindex"))
            .and_then(JsonValue::as_object)
            .ok_or(ElementsCoreSourceError::TxIndexUnavailable)?;
        if txindex.get("synced").and_then(JsonValue::as_bool) != Some(true) {
            return Err(ElementsCoreSourceError::TxIndexNotSynced);
        }
        Ok(())
    }

    fn gettxout(
        &self,
        outpoint: OutPoint,
        deadline: OperationDeadline,
    ) -> Result<Option<GetTxOutResult>, ElementsCoreSourceError> {
        self.call(
            "gettxout",
            json!([outpoint.txid, outpoint.vout, true]),
            deadline,
        )
    }

    fn raw_transaction(
        &self,
        txid: Txid,
        block_hash: Option<BlockHash>,
        deadline: OperationDeadline,
    ) -> Result<Transaction, ElementsCoreSourceError> {
        let raw: String = match block_hash {
            Some(block_hash) => self.call(
                "getrawtransaction",
                json!([txid, false, block_hash]),
                deadline,
            )?,
            None => self.call("getrawtransaction", json!([txid, false]), deadline)?,
        };
        let maximum_hex = self
            .inner
            .limits
            .max_raw_transaction_bytes
            .checked_mul(2)
            .ok_or(ElementsCoreSourceError::RawTransactionTooLarge {
                maximum: self.inner.limits.max_raw_transaction_bytes,
                actual: usize::MAX,
            })?;
        if raw.len() > maximum_hex {
            return Err(ElementsCoreSourceError::RawTransactionTooLarge {
                maximum: self.inner.limits.max_raw_transaction_bytes,
                actual: raw.len().div_ceil(2),
            });
        }
        if !raw.len().is_multiple_of(2) {
            return Err(ElementsCoreSourceError::InvalidRawTransaction(
                "raw transaction hex has odd length",
            ));
        }
        let bytes = hex::decode(&raw).map_err(|_| {
            ElementsCoreSourceError::InvalidRawTransaction("raw transaction contains invalid hex")
        })?;
        if bytes.len() > self.inner.limits.max_raw_transaction_bytes {
            return Err(ElementsCoreSourceError::RawTransactionTooLarge {
                maximum: self.inner.limits.max_raw_transaction_bytes,
                actual: bytes.len(),
            });
        }
        let transaction = deserialize::<Transaction>(&bytes).map_err(|_| {
            ElementsCoreSourceError::InvalidRawTransaction(
                "raw transaction failed consensus decoding",
            )
        })?;
        if transaction.txid() != txid {
            return Err(ElementsCoreSourceError::TransactionIdMismatch {
                requested: txid,
                actual: transaction.txid(),
            });
        }
        Ok(transaction)
    }

    fn transaction_output(
        outpoint: OutPoint,
        transaction: &Transaction,
    ) -> Result<TxOut, ElementsCoreSourceError> {
        validate_outpoint(outpoint)?;
        let index = usize::try_from(outpoint.vout)
            .map_err(|_| ElementsCoreSourceError::MissingTransactionOutput(outpoint))?;
        transaction
            .output
            .get(index)
            .cloned()
            .ok_or(ElementsCoreSourceError::MissingTransactionOutput(outpoint))
    }

    fn inventory_snapshot_inner(&self) -> Result<InventorySnapshot, ElementsCoreSourceError> {
        let deadline =
            OperationDeadline::start(INVENTORY_OPERATION, self.inner.limits.inventory_timeout)?;
        let _inventory_permit = self.lock_inventory(deadline)?;
        self.validate_chain_identity(deadline)?;

        let catalog = self.inner.wallet.catalog_snapshot()?;
        deadline.check()?;
        if catalog.locators().len() > self.inner.limits.max_scan_scripts {
            return Err(ElementsCoreSourceError::CatalogTooLarge {
                maximum: self.inner.limits.max_scan_scripts,
                actual: catalog.locators().len(),
            });
        }

        let mut by_script = BTreeMap::<Vec<u8>, (Script, WalletKeyLocator)>::new();
        for locator in catalog.locators() {
            let destination = self
                .inner
                .wallet
                .recover_confidential_destination(*locator)?;
            deadline.check()?;
            let script = destination.script_pubkey().clone();
            let script_bytes = script.as_bytes().to_vec();
            if by_script.insert(script_bytes, (script, *locator)).is_some() {
                return Err(ElementsCoreSourceError::DuplicateCatalogScript);
            }
        }
        if by_script.is_empty() {
            let tip: BlockchainInfo = self.call("getblockchaininfo", json!([]), deadline)?;
            let height = u32::try_from(tip.blocks).map_err(|_| {
                ElementsCoreSourceError::InvalidScanResult("chain height exceeds u32")
            })?;
            self.validate_chain_identity(deadline)?;
            let canonical = self.block_hash(height, deadline)?;
            if canonical != tip.best_block {
                return Err(ElementsCoreSourceError::ScanAnchorChanged {
                    expected: tip.best_block,
                    actual: canonical,
                });
            }
            let current_revision = self.inner.wallet.catalog_revision()?;
            if current_revision != catalog.revision() {
                return Err(ElementsCoreSourceError::CatalogChangedDuringScan {
                    before: catalog.revision(),
                    after: current_revision,
                });
            }
            let snapshot = InventorySnapshot::new(
                self.identity(),
                WalletScanAnchor::new(tip.best_block, height),
                Vec::new(),
            )
            .map_err(ElementsCoreSourceError::from)?;
            deadline.check()?;
            return Ok(snapshot);
        }
        let descriptors = by_script
            .keys()
            .map(|script| format!("raw({})", hex::encode(script)))
            .collect::<Vec<_>>();
        let scan: ScanResult =
            self.call("scantxoutset", json!(["start", descriptors]), deadline)?;
        if !scan.success {
            return Err(ElementsCoreSourceError::ScanAborted);
        }
        if scan.unspents.len() > self.inner.limits.max_scan_results {
            return Err(ElementsCoreSourceError::ScanResultTooLarge {
                maximum: self.inner.limits.max_scan_results,
                actual: scan.unspents.len(),
            });
        }
        let height = u32::try_from(scan.height)
            .map_err(|_| ElementsCoreSourceError::InvalidScanResult("scan height exceeds u32"))?;
        let mut seen = BTreeSet::new();
        let mut outputs = Vec::with_capacity(scan.unspents.len());
        let mut creation_blocks = BTreeMap::<u32, BlockHash>::new();
        let mut transactions = BTreeMap::<Txid, (BlockHash, Transaction)>::new();
        for unspent in scan.unspents {
            deadline.check()?;
            if unspent.height > scan.height {
                return Err(ElementsCoreSourceError::InvalidScanResult(
                    "UTXO creation height exceeds scan height",
                ));
            }
            let outpoint = OutPoint::new(unspent.txid, unspent.vout);
            validate_outpoint(outpoint)?;
            if !seen.insert(outpoint) {
                return Err(ElementsCoreSourceError::DuplicateScanOutpoint(outpoint));
            }
            let (_, locator) = by_script
                .get(unspent.script_pub_key.as_bytes())
                .ok_or(ElementsCoreSourceError::UnexpectedScanScript(outpoint))?;
            let creation_height = u32::try_from(unspent.height).map_err(|_| {
                ElementsCoreSourceError::InvalidScanResult("UTXO height exceeds u32")
            })?;
            let Some(observed) = self.gettxout(outpoint, deadline)? else {
                // `scantxoutset` excludes mempool effects. A null mempool-aware
                // lookup means this confirmed candidate has since been spent;
                // omit it from the complete currently spendable snapshot.
                continue;
            };
            if observed.best_block != scan.best_block {
                return Err(ElementsCoreSourceError::ScanAnchorChanged {
                    expected: scan.best_block,
                    actual: observed.best_block,
                });
            }
            let expected_confirmations = scan
                .height
                .checked_sub(unspent.height)
                .and_then(|depth| depth.checked_add(1))
                .ok_or(ElementsCoreSourceError::InvalidScanResult(
                    "UTXO confirmation count overflows",
                ))?;
            if observed.confirmations != expected_confirmations {
                return Err(ElementsCoreSourceError::ScanConfirmationMismatch {
                    outpoint,
                    expected: expected_confirmations,
                    actual: observed.confirmations,
                });
            }
            if observed.coinbase && observed.confirmations < COINBASE_MATURITY_CONFIRMATIONS {
                // An immature coinbase is confirmed but cannot yet be spent.
                // Omit it just like a candidate spent after `scantxoutset`.
                continue;
            }
            let creation_block = if let Some(cached) = creation_blocks.get(&creation_height) {
                *cached
            } else {
                let fetched = self.block_hash(creation_height, deadline)?;
                creation_blocks.insert(creation_height, fetched);
                fetched
            };
            let transaction = match transactions.entry(outpoint.txid) {
                std::collections::btree_map::Entry::Occupied(entry) => {
                    if entry.get().0 != creation_block {
                        return Err(ElementsCoreSourceError::InvalidScanResult(
                            "one creating transaction was reported at multiple block heights",
                        ));
                    }
                    &entry.into_mut().1
                }
                std::collections::btree_map::Entry::Vacant(entry) => {
                    let transaction =
                        self.raw_transaction(outpoint.txid, Some(creation_block), deadline)?;
                    &entry.insert((creation_block, transaction)).1
                }
            };
            let txout = Self::transaction_output(outpoint, transaction)?;
            let observed_script = hex::decode(&observed.script_pub_key.hex).map_err(|_| {
                ElementsCoreSourceError::InvalidRpcResponse(
                    "gettxout scriptPubKey contains invalid hex".to_owned(),
                )
            })?;
            if txout.script_pubkey != unspent.script_pub_key
                || observed_script != txout.script_pubkey.as_bytes()
            {
                return Err(ElementsCoreSourceError::ScanOutputMismatch(outpoint));
            }
            outputs.push(
                self.inner
                    .wallet
                    .recover_owned_output(*locator, outpoint, txout)?,
            );
            deadline.check()?;
        }

        self.validate_chain_identity(deadline)?;
        let canonical_anchor = self.block_hash(height, deadline)?;
        if canonical_anchor != scan.best_block {
            return Err(ElementsCoreSourceError::ScanAnchorChanged {
                expected: scan.best_block,
                actual: canonical_anchor,
            });
        }
        let current_revision = self.inner.wallet.catalog_revision()?;
        if current_revision != catalog.revision() {
            return Err(ElementsCoreSourceError::CatalogChangedDuringScan {
                before: catalog.revision(),
                after: current_revision,
            });
        }
        let snapshot = InventorySnapshot::new(
            self.identity(),
            WalletScanAnchor::new(scan.best_block, height),
            outputs,
        )
        .map_err(ElementsCoreSourceError::from)?;
        deadline.check()?;
        Ok(snapshot)
    }

    fn unspent_prevouts_inner(
        &self,
        outpoints: &[OutPoint],
    ) -> Result<Vec<AuthoritativePrevout>, ElementsCoreSourceError> {
        let deadline =
            OperationDeadline::start(SETTLEMENT_OPERATION, self.inner.limits.settlement_timeout)?;
        if outpoints.len() > self.inner.limits.max_settlement_prevouts {
            return Err(ElementsCoreSourceError::TooManySettlementPrevouts {
                maximum: self.inner.limits.max_settlement_prevouts,
                actual: outpoints.len(),
            });
        }
        let mut unique = BTreeSet::new();
        for outpoint in outpoints {
            deadline.check()?;
            validate_outpoint(*outpoint)?;
            if !unique.insert(*outpoint) {
                return Err(ElementsCoreSourceError::DuplicateSettlementOutpoint(
                    *outpoint,
                ));
            }
        }

        self.validate_chain_identity(deadline)?;
        self.validate_txindex(deadline)?;
        let tip = self.best_block_hash(deadline)?;
        let mut authoritative = Vec::with_capacity(outpoints.len());
        let mut transactions = BTreeMap::<Txid, Transaction>::new();
        for outpoint in outpoints {
            let observed = self
                .gettxout(*outpoint, deadline)?
                .ok_or(ElementsCoreSourceError::MissingOrSpentPrevout(*outpoint))?;
            if observed.best_block != tip {
                return Err(ElementsCoreSourceError::SettlementTipChanged {
                    expected: tip,
                    actual: observed.best_block,
                });
            }
            if observed.coinbase && observed.confirmations < COINBASE_MATURITY_CONFIRMATIONS {
                return Err(ElementsCoreSourceError::ImmatureCoinbasePrevout {
                    outpoint: *outpoint,
                    confirmations: observed.confirmations,
                });
            }
            let transaction = match transactions.entry(outpoint.txid) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => {
                    let transaction = self.raw_transaction(outpoint.txid, None, deadline)?;
                    entry.insert(transaction)
                }
            };
            let txout = Self::transaction_output(*outpoint, transaction)?;
            let script = hex::decode(&observed.script_pub_key.hex).map_err(|_| {
                ElementsCoreSourceError::InvalidRpcResponse(
                    "gettxout scriptPubKey contains invalid hex".to_owned(),
                )
            })?;
            if script != txout.script_pubkey.as_bytes() {
                return Err(ElementsCoreSourceError::AuthoritativeOutputMismatch(
                    *outpoint,
                ));
            }
            authoritative.push(AuthoritativePrevout::new(*outpoint, txout));
        }
        self.validate_chain_identity(deadline)?;
        let final_tip = self.best_block_hash(deadline)?;
        if final_tip != tip {
            return Err(ElementsCoreSourceError::SettlementTipChanged {
                expected: tip,
                actual: final_tip,
            });
        }
        deadline.check()?;
        Ok(authoritative)
    }
}

impl fmt::Debug for ElementsCoreSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ElementsCoreSource")
            .field("identity", &self.identity())
            .field("wallet", &"[unlocked and redacted]")
            .field("limits", &self.inner.limits)
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

#[derive(Deserialize)]
struct ScanResult {
    success: bool,
    height: u64,
    #[serde(rename = "bestblock")]
    best_block: BlockHash,
    unspents: Vec<ScanUnspent>,
}

#[derive(Deserialize)]
struct BlockchainInfo {
    blocks: u64,
    #[serde(rename = "bestblockhash")]
    best_block: BlockHash,
}

#[derive(Deserialize)]
struct ScanUnspent {
    txid: Txid,
    vout: u32,
    height: u64,
    #[serde(rename = "scriptPubKey")]
    script_pub_key: Script,
}

#[derive(Deserialize)]
struct GetTxOutResult {
    #[serde(rename = "bestblock")]
    best_block: BlockHash,
    confirmations: u64,
    coinbase: bool,
    #[serde(rename = "scriptPubKey")]
    script_pub_key: GetTxOutScript,
}

#[derive(Deserialize)]
struct GetTxOutScript {
    hex: String,
}

fn validate_outpoint(outpoint: OutPoint) -> Result<(), ElementsCoreSourceError> {
    if outpoint.is_null() || outpoint.vout & 0xc000_0000 != 0 {
        return Err(ElementsCoreSourceError::InvalidOutpoint(outpoint));
    }
    Ok(())
}

fn read_cookie(path: &PathBuf) -> Result<(String, String), ElementsCoreSourceError> {
    let file = File::open(path).map_err(|error| {
        ElementsCoreSourceError::BackendUnavailable(format!(
            "cannot open Elements RPC cookie {}: {error}",
            path.display()
        ))
    })?;
    if file
        .metadata()
        .map_err(|error| {
            ElementsCoreSourceError::BackendUnavailable(format!(
                "cannot inspect Elements RPC cookie {}: {error}",
                path.display()
            ))
        })?
        .len()
        > MAX_COOKIE_BYTES as u64
    {
        return Err(ElementsCoreSourceError::InvalidCookie);
    }
    let mut bytes = Vec::new();
    file.take((MAX_COOKIE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            ElementsCoreSourceError::BackendUnavailable(format!(
                "cannot read Elements RPC cookie {}: {error}",
                path.display()
            ))
        })?;
    if bytes.len() > MAX_COOKIE_BYTES {
        return Err(ElementsCoreSourceError::InvalidCookie);
    }
    let cookie = std::str::from_utf8(&bytes)
        .map_err(|_| ElementsCoreSourceError::InvalidCookie)?
        .trim_end_matches(['\r', '\n']);
    let (username, password) = cookie
        .split_once(':')
        .ok_or(ElementsCoreSourceError::InvalidCookie)?;
    if username.is_empty() || password.is_empty() || password.contains(['\r', '\n']) {
        return Err(ElementsCoreSourceError::InvalidCookie);
    }
    Ok((username.to_owned(), password.to_owned()))
}

fn read_bounded(
    mut response: Response,
    maximum: usize,
) -> Result<(StatusCode, Vec<u8>), ElementsCoreSourceError> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(ElementsCoreSourceError::ResponseTooLarge {
            maximum,
            actual: response.content_length().unwrap_or(u64::MAX),
        });
    }
    let mut body = Vec::new();
    response
        .by_ref()
        .take((maximum as u64).saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|error| {
            ElementsCoreSourceError::BackendUnavailable(format!(
                "cannot read Elements RPC response: {error}"
            ))
        })?;
    if body.len() > maximum {
        return Err(ElementsCoreSourceError::ResponseTooLarge {
            maximum,
            actual: body.len() as u64,
        });
    }
    Ok((status, body))
}

fn parse_rpc_envelope(
    method: &'static str,
    expected_id: u64,
    status: StatusCode,
    body: &[u8],
) -> Result<JsonValue, ElementsCoreSourceError> {
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        return Err(ElementsCoreSourceError::AuthenticationFailed);
    }
    let envelope: JsonValue = serde_json::from_slice(body).map_err(|error| {
        ElementsCoreSourceError::InvalidRpcResponse(format!(
            "invalid {method} JSON-RPC response: {error}"
        ))
    })?;
    let object = envelope.as_object().ok_or_else(|| {
        ElementsCoreSourceError::InvalidRpcResponse(format!(
            "{method} JSON-RPC response is not an object"
        ))
    })?;
    if object.get("id").and_then(JsonValue::as_u64) != Some(expected_id) {
        return Err(ElementsCoreSourceError::InvalidRpcResponse(format!(
            "{method} JSON-RPC response id does not match request"
        )));
    }
    let error = object.get("error").ok_or_else(|| {
        ElementsCoreSourceError::InvalidRpcResponse(format!(
            "{method} JSON-RPC response is missing error"
        ))
    })?;
    let result = object.get("result").ok_or_else(|| {
        ElementsCoreSourceError::InvalidRpcResponse(format!(
            "{method} JSON-RPC response is missing result"
        ))
    })?;
    if !error.is_null() {
        if !result.is_null() {
            return Err(ElementsCoreSourceError::InvalidRpcResponse(format!(
                "{method} JSON-RPC response contains both result and error"
            )));
        }
        let failure: RpcFailure = serde_json::from_value(error.clone()).map_err(|parse_error| {
            ElementsCoreSourceError::InvalidRpcResponse(format!(
                "invalid {method} JSON-RPC error: {parse_error}"
            ))
        })?;
        return Err(ElementsCoreSourceError::RpcRejected {
            method,
            code: failure.code,
            message: bounded_excerpt(&failure.message),
        });
    }
    if !status.is_success() {
        return Err(ElementsCoreSourceError::BackendUnavailable(format!(
            "Elements RPC {method} returned HTTP {status}"
        )));
    }
    Ok(result.clone())
}

fn bounded_excerpt(message: &str) -> String {
    let mut bounded = message
        .chars()
        .take(MAX_BACKEND_ERROR_CHARS)
        .collect::<String>();
    if message.chars().count() > MAX_BACKEND_ERROR_CHARS {
        bounded.push('…');
    }
    bounded
}

fn transport_error(method: &str, error: &reqwest::Error) -> ElementsCoreSourceError {
    let kind = if error.is_timeout() {
        "request timed out"
    } else if error.is_connect() {
        "connection failed"
    } else {
        "transport failed"
    };
    ElementsCoreSourceError::BackendUnavailable(format!("Elements RPC {method} {kind}: {error}"))
}

#[derive(Deserialize)]
struct RpcFailure {
    code: i64,
    message: String,
}

/// Fail-closed Elements Core, catalog, or wallet discovery error.
#[derive(Debug, Error)]
pub enum ElementsCoreSourceError {
    #[error("invalid Elements Core configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("invalid Elements Core URL: {0}")]
    InvalidUrl(String),
    #[error("Elements Core backend unavailable: {0}")]
    BackendUnavailable(String),
    #[error("Elements Core authentication failed")]
    AuthenticationFailed,
    #[error("Elements RPC request-id space is exhausted")]
    RpcIdExhausted,
    #[error("Elements Core cookie is malformed or exceeds its bound")]
    InvalidCookie,
    #[error("Elements RPC request has {actual} bytes; maximum is {maximum}")]
    RequestTooLarge { maximum: usize, actual: usize },
    #[error("Elements RPC response has at least {actual} bytes; maximum is {maximum}")]
    ResponseTooLarge { maximum: usize, actual: u64 },
    #[error("invalid Elements RPC response: {0}")]
    InvalidRpcResponse(String),
    #[error("Elements RPC {method} rejected request with code {code}: {message}")]
    RpcRejected {
        method: &'static str,
        code: i64,
        message: String,
    },
    #[error("Elements source is on genesis {actual}, expected {expected}")]
    WrongChain {
        expected: BlockHash,
        actual: BlockHash,
    },
    #[error("wallet catalog has {actual} scripts; scan maximum is {maximum}")]
    CatalogTooLarge { maximum: usize, actual: usize },
    #[error("wallet catalog resolves two locators to the same script")]
    DuplicateCatalogScript,
    #[error("Elements Core aborted the UTXO-set scan")]
    ScanAborted,
    #[error("UTXO-set scan returned {actual} matches; maximum is {maximum}")]
    ScanResultTooLarge { maximum: usize, actual: usize },
    #[error("invalid UTXO-set scan result: {0}")]
    InvalidScanResult(&'static str),
    #[error("UTXO-set scan returned duplicate outpoint {0:?}")]
    DuplicateScanOutpoint(OutPoint),
    #[error("UTXO-set scan returned an unrequested script at {0:?}")]
    UnexpectedScanScript(OutPoint),
    #[error("raw creating transaction disagrees with scan result at {0:?}")]
    ScanOutputMismatch(OutPoint),
    #[error(
        "gettxout reports {actual} confirmations for {outpoint:?}; scan anchor requires {expected}"
    )]
    ScanConfirmationMismatch {
        outpoint: OutPoint,
        expected: u64,
        actual: u64,
    },
    #[error("scan anchor changed from {expected} to {actual} while materializing inventory")]
    ScanAnchorChanged {
        expected: BlockHash,
        actual: BlockHash,
    },
    #[error("wallet catalog revision changed from {before} to {after} during scan")]
    CatalogChangedDuringScan { before: u64, after: u64 },
    #[error("raw transaction has {actual} bytes; maximum is {maximum}")]
    RawTransactionTooLarge { maximum: usize, actual: usize },
    #[error("invalid raw transaction: {0}")]
    InvalidRawTransaction(&'static str),
    #[error("raw transaction hashes to {actual}, requested {requested}")]
    TransactionIdMismatch { requested: Txid, actual: Txid },
    #[error("raw transaction is missing requested output {0:?}")]
    MissingTransactionOutput(OutPoint),
    #[error("invalid Elements outpoint {0:?}")]
    InvalidOutpoint(OutPoint),
    #[error("settlement has {actual} prevouts; maximum is {maximum}")]
    TooManySettlementPrevouts { maximum: usize, actual: usize },
    #[error("settlement repeats outpoint {0:?}")]
    DuplicateSettlementOutpoint(OutPoint),
    #[error("Elements Core txindex is required for complete settlement prevouts")]
    TxIndexUnavailable,
    #[error("Elements Core txindex is not synchronized")]
    TxIndexNotSynced,
    #[error("settlement prevout is missing or spent: {0:?}")]
    MissingOrSpentPrevout(OutPoint),
    #[error(
        "settlement coinbase prevout {outpoint:?} has {confirmations} confirmations; {COINBASE_MATURITY_CONFIRMATIONS} required"
    )]
    ImmatureCoinbasePrevout {
        outpoint: OutPoint,
        confirmations: u64,
    },
    #[error("gettxout and the raw creating transaction disagree at {0:?}")]
    AuthoritativeOutputMismatch(OutPoint),
    #[error("settlement chain tip changed from {expected} to {actual} during prevout lookup")]
    SettlementTipChanged {
        expected: BlockHash,
        actual: BlockHash,
    },
    #[error("Elements inventory serialization lock is poisoned")]
    InventoryLockPoisoned,
    #[error("Elements {operation} operation exceeded its deadline")]
    OperationTimedOut { operation: &'static str },
    #[error(transparent)]
    Wallet(#[from] PersistentWalletError),
    #[error(transparent)]
    WalletBoundary(#[from] WalletBoundaryError),
}

#[cfg(test)]
mod tests;

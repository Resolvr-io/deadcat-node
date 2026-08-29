//! Bounded, wallet-neutral synchronous access to one trusted Elements Core.
//!
//! The client binds every operation to an exact [`ChainIdentity`], bounds
//! requests, responses, decoded transactions and batch sizes, and gives each
//! multi-RPC operation one wall-clock deadline. Script scans and prevout
//! snapshots retain complete consensus [`TxOut`] witnesses. Prevout snapshots
//! can additionally prove arbitrary [`ChainAnchor`] values as canonical
//! ancestors under the same stable tip used for every mempool-aware lookup.
//!
//! This crate deliberately owns neither wallet keys nor Deadcat market state.
//! Async runtimes must move a complete operation onto a blocking executor.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::OpenOptions;
use std::io::Read as _;
use std::path::PathBuf;
use std::str::FromStr as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use deadcat_types::{ChainAnchor, ChainIdentity, LiquidNetwork};
use elements::encode::{deserialize, serialize};
use elements::{AssetId, BlockHash, OutPoint, Script, Transaction, TxOut, Txid, Wtxid};
use reqwest::blocking::{Client as HttpClient, RequestBuilder, Response};
use reqwest::{Method, StatusCode, Url};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value as JsonValue, json};
use thiserror::Error;
use zeroize::Zeroizing;

/// Default TCP/TLS connection timeout.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default timeout for any one RPC request.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Default deadline for a complete startup probe.
pub const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
/// Default deadline for a complete script scan.
pub const DEFAULT_SCAN_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Default deadline for a canonical-anchor check.
pub const DEFAULT_ANCHOR_TIMEOUT: Duration = Duration::from_secs(30);
/// Default deadline for a complete ordered-prevout snapshot.
pub const DEFAULT_PREVOUT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default deadline for one exact relay/reconciliation attempt.
pub const DEFAULT_RELAY_TIMEOUT: Duration = Duration::from_secs(30);
/// Default maximum serialized JSON request size.
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;
/// Default maximum serialized JSON response size.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
/// Default maximum number of scripts in one coherent scan.
pub const DEFAULT_MAX_SCAN_SCRIPTS: usize = 100_000;
/// Default maximum number of matching UTXOs returned by one scan.
pub const DEFAULT_MAX_SCAN_RESULTS: usize = 10_000;
/// Default maximum retained serialized bytes across all materialized outputs.
pub const DEFAULT_MAX_MATERIALIZED_TXOUT_BYTES: usize = 64 * 1024 * 1024;
/// Default maximum number of prevouts checked in one operation.
pub const DEFAULT_MAX_PREVOUTS: usize = 32;
/// Default maximum number of ancestry anchors bound to one prevout snapshot.
pub const DEFAULT_MAX_REQUIRED_ANCHORS: usize = 4;
/// Default maximum decoded size of one raw transaction.
pub const DEFAULT_MAX_RAW_TRANSACTION_BYTES: usize = 4 * 1024 * 1024;
/// Confirmations required before a coinbase output may be spent.
pub const COINBASE_MATURITY_CONFIRMATIONS: u64 = 100;

const MAX_COOKIE_BYTES: usize = 4 * 1024;
const MAX_BACKEND_ERROR_CHARS: usize = 512;

/// Authentication for a trusted Elements Core RPC endpoint.
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

/// Bounded connection, operation and result policy.
#[derive(Clone, Debug)]
pub struct ElementsCoreConfig {
    pub url: String,
    pub auth: ElementsCoreAuth,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub startup_timeout: Duration,
    pub scan_timeout: Duration,
    pub anchor_timeout: Duration,
    pub prevout_timeout: Duration,
    pub relay_timeout: Duration,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_scan_scripts: usize,
    pub max_scan_results: usize,
    pub max_materialized_txout_bytes: usize,
    pub max_prevouts: usize,
    pub max_required_anchors: usize,
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
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
            scan_timeout: DEFAULT_SCAN_TIMEOUT,
            anchor_timeout: DEFAULT_ANCHOR_TIMEOUT,
            prevout_timeout: DEFAULT_PREVOUT_TIMEOUT,
            relay_timeout: DEFAULT_RELAY_TIMEOUT,
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_scan_scripts: DEFAULT_MAX_SCAN_SCRIPTS,
            max_scan_results: DEFAULT_MAX_SCAN_RESULTS,
            max_materialized_txout_bytes: DEFAULT_MAX_MATERIALIZED_TXOUT_BYTES,
            max_prevouts: DEFAULT_MAX_PREVOUTS,
            max_required_anchors: DEFAULT_MAX_REQUIRED_ANCHORS,
            max_raw_transaction_bytes: DEFAULT_MAX_RAW_TRANSACTION_BYTES,
        }
    }

    fn validate(&self) -> Result<Url, ElementsCoreError> {
        let timeouts = [
            self.connect_timeout,
            self.request_timeout,
            self.startup_timeout,
            self.scan_timeout,
            self.anchor_timeout,
            self.prevout_timeout,
            self.relay_timeout,
        ];
        if timeouts.contains(&Duration::ZERO) {
            return Err(ElementsCoreError::InvalidConfiguration(
                "Elements RPC and operation timeouts must be nonzero",
            ));
        }
        let now = Instant::now();
        if timeouts
            .into_iter()
            .any(|timeout| now.checked_add(timeout).is_none())
        {
            return Err(ElementsCoreError::InvalidConfiguration(
                "Elements operation timeout exceeds the monotonic clock range",
            ));
        }
        if self.max_request_bytes == 0
            || self.max_response_bytes == 0
            || self.max_scan_scripts == 0
            || self.max_scan_results == 0
            || self.max_materialized_txout_bytes == 0
            || self.max_prevouts == 0
            || self.max_required_anchors == 0
            || self.max_raw_transaction_bytes == 0
        {
            return Err(ElementsCoreError::InvalidConfiguration(
                "Elements RPC bounds must be nonzero",
            ));
        }
        let minimum_raw_response = self
            .max_raw_transaction_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(1_024))
            .ok_or(ElementsCoreError::InvalidConfiguration(
                "raw-transaction response bound overflows",
            ))?;
        if self.max_response_bytes < minimum_raw_response {
            return Err(ElementsCoreError::InvalidConfiguration(
                "response bound cannot contain the configured raw transaction bound",
            ));
        }
        match &self.auth {
            ElementsCoreAuth::Basic { username, password }
                if username.is_empty() || password.is_empty() =>
            {
                return Err(ElementsCoreError::InvalidConfiguration(
                    "basic-auth username and password must be nonempty",
                ));
            }
            ElementsCoreAuth::CookieFile(path) if path.as_os_str().is_empty() => {
                return Err(ElementsCoreError::InvalidConfiguration(
                    "cookie path must be nonempty",
                ));
            }
            _ => {}
        }
        let url = Url::parse(&self.url).map_err(|error| {
            ElementsCoreError::InvalidUrl(format!("invalid Elements RPC URL: {error}"))
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ElementsCoreError::InvalidConfiguration(
                "Elements RPC URL must use http or https",
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ElementsCoreError::InvalidConfiguration(
                "put Elements RPC credentials in ElementsCoreAuth, not in the URL",
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(ElementsCoreError::InvalidConfiguration(
                "Elements RPC URL cannot contain a query or fragment",
            ));
        }
        Ok(url)
    }
}

/// One bounded multi-RPC operation kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreOperation {
    Startup,
    Scan,
    Anchor,
    Prevouts,
    Relay,
}

impl CoreOperation {
    const fn name(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Scan => "scan",
            Self::Anchor => "anchor",
            Self::Prevouts => "prevouts",
            Self::Relay => "relay",
        }
    }
}

/// Opaque operation-wide budget that callers may start before local work.
///
/// Provider and taker adapters use this seam to include wallet catalog and
/// recovery work in the same deadline as the subsequent Core operation.
pub struct OperationBudget {
    owner: Arc<()>,
    operation: CoreOperation,
    deadline: OperationDeadline,
}

impl OperationBudget {
    /// Fail if this operation has exhausted its wall-clock budget.
    pub fn check(&self) -> Result<(), ElementsCoreError> {
        self.deadline.check()
    }

    /// Return the remaining wall-clock budget.
    ///
    /// Cross-service adapters can use this value to cap caller-owned I/O so
    /// that it remains inside the same deadline as the subsequent Core work.
    pub fn remaining(&self) -> Result<Duration, ElementsCoreError> {
        self.deadline.remaining()
    }

    #[must_use]
    pub const fn operation(&self) -> CoreOperation {
        self.operation
    }
}

impl fmt::Debug for OperationBudget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationBudget")
            .field("operation", &self.operation)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug)]
struct ClientLimits {
    request_timeout: Duration,
    startup_timeout: Duration,
    scan_timeout: Duration,
    anchor_timeout: Duration,
    prevout_timeout: Duration,
    relay_timeout: Duration,
    max_scan_scripts: usize,
    max_scan_results: usize,
    max_materialized_txout_bytes: usize,
    max_prevouts: usize,
    max_required_anchors: usize,
    max_raw_transaction_bytes: usize,
}

impl ClientLimits {
    fn from_config(config: &ElementsCoreConfig) -> Self {
        Self {
            request_timeout: config.request_timeout,
            startup_timeout: config.startup_timeout,
            scan_timeout: config.scan_timeout,
            anchor_timeout: config.anchor_timeout,
            prevout_timeout: config.prevout_timeout,
            relay_timeout: config.relay_timeout,
            max_scan_scripts: config.max_scan_scripts,
            max_scan_results: config.max_scan_results,
            max_materialized_txout_bytes: config.max_materialized_txout_bytes,
            max_prevouts: config.max_prevouts,
            max_required_anchors: config.max_required_anchors,
            max_raw_transaction_bytes: config.max_raw_transaction_bytes,
        }
    }

    const fn timeout(self, operation: CoreOperation) -> Duration {
        match operation {
            CoreOperation::Startup => self.startup_timeout,
            CoreOperation::Scan => self.scan_timeout,
            CoreOperation::Anchor => self.anchor_timeout,
            CoreOperation::Prevouts => self.prevout_timeout,
            CoreOperation::Relay => self.relay_timeout,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct OperationDeadline {
    operation: &'static str,
    expires_at: Instant,
}

impl OperationDeadline {
    fn start(operation: &'static str, timeout: Duration) -> Result<Self, ElementsCoreError> {
        let expires_at =
            Instant::now()
                .checked_add(timeout)
                .ok_or(ElementsCoreError::InvalidConfiguration(
                    "Elements operation timeout exceeds the monotonic clock range",
                ))?;
        Ok(Self {
            operation,
            expires_at,
        })
    }

    fn remaining(self) -> Result<Duration, ElementsCoreError> {
        self.expires_at
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(ElementsCoreError::OperationTimedOut {
                operation: self.operation,
            })
    }

    fn check(self) -> Result<(), ElementsCoreError> {
        self.remaining().map(|_| ())
    }

    const fn rpc_budget(self, request_timeout: Duration) -> RpcCallBudget {
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
    fn timeout(self) -> Result<RpcCallTimeout, ElementsCoreError> {
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
    fn timeout_error(self, method: &str, error: &reqwest::Error) -> ElementsCoreError {
        if self.operation_limited && error.is_timeout() && Instant::now() >= self.expires_at {
            ElementsCoreError::OperationTimedOut {
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
    ) -> Result<JsonValue, ElementsCoreError>;
}

fn call_rpc<T: DeserializeOwned>(
    rpc: &dyn RpcTransport,
    request_timeout: Duration,
    method: &'static str,
    params: JsonValue,
    deadline: OperationDeadline,
) -> Result<T, ElementsCoreError> {
    deadline.check()?;
    let value = rpc.call(method, params, deadline.rpc_budget(request_timeout))?;
    let result = serde_json::from_value(value).map_err(|error| {
        ElementsCoreError::InvalidRpcResponse(format!("invalid {method} result: {error}"))
    })?;
    deadline.check()?;
    Ok(result)
}

struct HttpRpcTransport {
    client: HttpClient,
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
    fn new(config: ElementsCoreConfig, url: Url) -> Result<Self, ElementsCoreError> {
        let client = HttpClient::builder()
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .build()
            .map_err(|error| {
                ElementsCoreError::BackendUnavailable(format!(
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

    fn authenticated(&self, request: RequestBuilder) -> Result<RequestBuilder, ElementsCoreError> {
        match &self.auth {
            ElementsCoreAuth::None => Ok(request),
            ElementsCoreAuth::Basic { username, password } => {
                Ok(request.basic_auth(username, Some(password)))
            }
            ElementsCoreAuth::CookieFile(path) => {
                let (username, password) = read_cookie(path)?;
                Ok(request.basic_auth(username.as_str(), Some(password.as_str())))
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
    ) -> Result<JsonValue, ElementsCoreError> {
        let id = self
            .next_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| ElementsCoreError::RpcIdExhausted)?;
        let payload = serde_json::to_vec(&json!({
            "jsonrpc": "1.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .map_err(|error| {
            ElementsCoreError::InvalidRpcResponse(format!(
                "cannot encode {method} request: {error}"
            ))
        })?;
        if payload.len() > self.max_request_bytes {
            return Err(ElementsCoreError::RequestTooLarge {
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
struct ScanGate {
    active: Mutex<bool>,
    available: Condvar,
}

impl ScanGate {
    fn acquire(&self, deadline: OperationDeadline) -> Result<ScanPermit<'_>, ElementsCoreError> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| ElementsCoreError::ScanLockPoisoned)?;
        loop {
            deadline.check()?;
            if !*active {
                *active = true;
                return Ok(ScanPermit { gate: self });
            }
            let (next, waited) = self
                .available
                .wait_timeout(active, deadline.remaining()?)
                .map_err(|_| ElementsCoreError::ScanLockPoisoned)?;
            active = next;
            if waited.timed_out() {
                return Err(ElementsCoreError::OperationTimedOut {
                    operation: deadline.operation,
                });
            }
        }
    }
}

struct ScanPermit<'a> {
    gate: &'a ScanGate,
}

impl Drop for ScanPermit<'_> {
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

struct ClientInner {
    chain: ChainIdentity,
    rpc: Arc<dyn RpcTransport>,
    limits: ClientLimits,
    marker: Arc<()>,
    scan_gate: ScanGate,
}

/// Cheap-clone bounded client bound to one exact Liquid chain.
///
/// Clones share the RPC request-id sequence and the process-local scan gate.
#[derive(Clone)]
pub struct ElementsCoreClient {
    inner: Arc<ClientInner>,
}

impl ElementsCoreClient {
    pub fn new(
        config: ElementsCoreConfig,
        chain: ChainIdentity,
    ) -> Result<Self, ElementsCoreError> {
        let url = config.validate()?;
        let limits = ClientLimits::from_config(&config);
        let transport = Arc::new(HttpRpcTransport::new(config, url)?);
        Ok(Self::with_parts(chain, limits, transport))
    }

    #[cfg(test)]
    fn from_parts(
        config: &ElementsCoreConfig,
        chain: ChainIdentity,
        rpc: Arc<dyn RpcTransport>,
    ) -> Self {
        Self::with_parts(chain, ClientLimits::from_config(config), rpc)
    }

    fn with_parts(chain: ChainIdentity, limits: ClientLimits, rpc: Arc<dyn RpcTransport>) -> Self {
        Self {
            inner: Arc::new(ClientInner {
                chain,
                rpc,
                limits,
                marker: Arc::new(()),
                scan_gate: ScanGate::default(),
            }),
        }
    }

    #[must_use]
    pub fn chain(&self) -> ChainIdentity {
        self.inner.chain
    }

    /// Start an operation budget before caller-local work.
    pub fn begin_operation(
        &self,
        operation: CoreOperation,
    ) -> Result<OperationBudget, ElementsCoreError> {
        Ok(OperationBudget {
            owner: Arc::clone(&self.inner.marker),
            operation,
            deadline: OperationDeadline::start(
                operation.name(),
                self.inner.limits.timeout(operation),
            )?,
        })
    }

    /// Acquire the shared scan gate and deadline before wallet catalog work.
    pub fn begin_script_scan(&self) -> Result<ScriptScanOperation<'_>, ElementsCoreError> {
        let budget = self.begin_operation(CoreOperation::Scan)?;
        self.begin_script_scan_with_budget(budget)
    }

    /// Acquire the shared scan gate with a caller-started scan budget.
    ///
    /// Async adapters start this budget before waiting for their bounded
    /// blocking-task permit. Moving it into this method ensures queueing,
    /// wallet catalog work, and the Core scan all share one deadline.
    pub fn begin_script_scan_with_budget(
        &self,
        budget: OperationBudget,
    ) -> Result<ScriptScanOperation<'_>, ElementsCoreError> {
        let deadline = self.validate_budget(&budget, CoreOperation::Scan)?;
        let permit = self.inner.scan_gate.acquire(deadline)?;
        Ok(ScriptScanOperation {
            client: self,
            budget,
            _permit: permit,
        })
    }

    fn validate_budget(
        &self,
        budget: &OperationBudget,
        expected: CoreOperation,
    ) -> Result<OperationDeadline, ElementsCoreError> {
        if !Arc::ptr_eq(&self.inner.marker, &budget.owner) {
            return Err(ElementsCoreError::ForeignOperationBudget);
        }
        if budget.operation != expected {
            return Err(ElementsCoreError::WrongOperationBudget {
                expected,
                actual: budget.operation,
            });
        }
        budget.check()?;
        Ok(budget.deadline)
    }

    fn call<T: DeserializeOwned>(
        &self,
        method: &'static str,
        params: JsonValue,
        deadline: OperationDeadline,
    ) -> Result<T, ElementsCoreError> {
        call_rpc(
            self.inner.rpc.as_ref(),
            self.inner.limits.request_timeout,
            method,
            params,
            deadline,
        )
    }

    fn block_hash(
        &self,
        height: u32,
        deadline: OperationDeadline,
    ) -> Result<BlockHash, ElementsCoreError> {
        self.call("getblockhash", json!([height]), deadline)
    }

    fn validate_chain_identity(
        &self,
        deadline: OperationDeadline,
    ) -> Result<(), ElementsCoreError> {
        let actual = self.block_hash(0, deadline)?;
        let expected = self.chain().genesis_hash;
        if actual != expected {
            return Err(ElementsCoreError::WrongChain { expected, actual });
        }
        Ok(())
    }

    fn validate_txindex(&self, deadline: OperationDeadline) -> Result<(), ElementsCoreError> {
        let indexes: JsonValue = self.call("getindexinfo", json!([]), deadline)?;
        validate_txindex_result(&indexes)
    }

    fn blockchain_info(
        &self,
        deadline: OperationDeadline,
    ) -> Result<BlockchainInfo, ElementsCoreError> {
        self.call("getblockchaininfo", json!([]), deadline)
    }

    fn stable_tip(&self, deadline: OperationDeadline) -> Result<ChainAnchor, ElementsCoreError> {
        self.validate_chain_identity(deadline)?;
        let info = self.blockchain_info(deadline)?;
        validate_network(&info.chain, self.chain().network)?;
        if info.initial_block_download {
            return Err(ElementsCoreError::InitialBlockDownload);
        }
        let height = u32::try_from(info.blocks)
            .map_err(|_| ElementsCoreError::InvalidChainStatus("chain height exceeds u32"))?;
        let canonical = self.block_hash(height, deadline)?;
        if canonical != info.best_block {
            return Err(ElementsCoreError::InconsistentChainTip {
                height,
                reported: info.best_block,
                actual: canonical,
            });
        }
        Ok(ChainAnchor {
            height,
            hash: info.best_block,
        })
    }

    fn require_anchor(
        &self,
        anchor: ChainAnchor,
        tip: ChainAnchor,
        deadline: OperationDeadline,
    ) -> Result<(), ElementsCoreError> {
        if anchor.height > tip.height {
            return Err(ElementsCoreError::AnchorAboveTip { anchor, tip });
        }
        let actual = self.block_hash(anchor.height, deadline)?;
        if actual != anchor.hash {
            return Err(ElementsCoreError::AnchorNotCanonical { anchor, actual });
        }
        Ok(())
    }

    fn gettxout(
        &self,
        outpoint: OutPoint,
        deadline: OperationDeadline,
    ) -> Result<Option<GetTxOutResult>, ElementsCoreError> {
        self.call(
            "gettxout",
            json!([outpoint.txid, outpoint.vout, true]),
            deadline,
        )
    }

    fn require_mempool_transaction(
        &self,
        outpoint: OutPoint,
        deadline: OperationDeadline,
    ) -> Result<Wtxid, ElementsCoreError> {
        let result: Result<MempoolEntry, ElementsCoreError> =
            self.call("getmempoolentry", json!([outpoint.txid]), deadline);
        match result {
            Ok(entry) => Ok(entry.wtxid),
            Err(error) if rpc_not_found(&error, "getmempoolentry") => {
                Err(ElementsCoreError::PrevoutViewChanged(outpoint))
            }
            Err(error) => Err(error),
        }
    }

    fn authoritative_prevout_transaction(
        &self,
        outpoint: OutPoint,
        confirmations: u64,
        tip: ChainAnchor,
        deadline: OperationDeadline,
    ) -> Result<Transaction, ElementsCoreError> {
        if confirmations == 0 {
            // An unqualified txindex lookup may select a stale-block witness
            // for a repeated txid. Prove mempool presence on both sides of
            // the raw lookup so the returned witness is bound to the live
            // mempool view instead.
            let expected_wtxid = self.require_mempool_transaction(outpoint, deadline)?;
            let transaction = self.raw_transaction(outpoint.txid, None, deadline)?;
            if transaction.wtxid() != expected_wtxid {
                return Err(ElementsCoreError::WitnessTransactionIdMismatch {
                    expected: expected_wtxid,
                    actual: transaction.wtxid(),
                });
            }
            if self.require_mempool_transaction(outpoint, deadline)? != expected_wtxid {
                return Err(ElementsCoreError::PrevoutViewChanged(outpoint));
            }
            return Ok(transaction);
        }

        let depth =
            confirmations
                .checked_sub(1)
                .ok_or(ElementsCoreError::InvalidPrevoutConfirmations {
                    outpoint,
                    confirmations,
                    tip,
                })?;
        let depth =
            u32::try_from(depth).map_err(|_| ElementsCoreError::InvalidPrevoutConfirmations {
                outpoint,
                confirmations,
                tip,
            })?;
        let creation_height = tip.height.checked_sub(depth).ok_or(
            ElementsCoreError::InvalidPrevoutConfirmations {
                outpoint,
                confirmations,
                tip,
            },
        )?;
        let creation_block = self.block_hash(creation_height, deadline)?;
        self.raw_transaction(outpoint.txid, Some(creation_block), deadline)
    }

    fn raw_transaction(
        &self,
        txid: Txid,
        block_hash: Option<BlockHash>,
        deadline: OperationDeadline,
    ) -> Result<Transaction, ElementsCoreError> {
        let raw: String = match block_hash {
            Some(block_hash) => self.call(
                "getrawtransaction",
                json!([txid, false, block_hash]),
                deadline,
            )?,
            None => self.call("getrawtransaction", json!([txid, false]), deadline)?,
        };
        let transaction = self.decode_raw_transaction(&raw)?;
        if transaction.txid() != txid {
            return Err(ElementsCoreError::TransactionIdMismatch {
                requested: txid,
                actual: transaction.txid(),
            });
        }
        Ok(transaction)
    }

    fn decode_raw_transaction(&self, raw: &str) -> Result<Transaction, ElementsCoreError> {
        let maximum = self.inner.limits.max_raw_transaction_bytes;
        let maximum_hex =
            maximum
                .checked_mul(2)
                .ok_or(ElementsCoreError::RawTransactionTooLarge {
                    maximum,
                    actual: usize::MAX,
                })?;
        if raw.len() > maximum_hex {
            return Err(ElementsCoreError::RawTransactionTooLarge {
                maximum,
                actual: raw.len().div_ceil(2),
            });
        }
        if !raw.len().is_multiple_of(2) {
            return Err(ElementsCoreError::InvalidRawTransaction(
                "raw transaction hex has odd length",
            ));
        }
        let bytes = hex::decode(raw).map_err(|_| {
            ElementsCoreError::InvalidRawTransaction("raw transaction contains invalid hex")
        })?;
        if bytes.len() > maximum {
            return Err(ElementsCoreError::RawTransactionTooLarge {
                maximum,
                actual: bytes.len(),
            });
        }
        deserialize::<Transaction>(&bytes).map_err(|_| {
            ElementsCoreError::InvalidRawTransaction("raw transaction failed consensus decoding")
        })
    }

    fn transaction_output(
        outpoint: OutPoint,
        transaction: &Transaction,
    ) -> Result<TxOut, ElementsCoreError> {
        validate_outpoint(outpoint)?;
        let index = usize::try_from(outpoint.vout)
            .map_err(|_| ElementsCoreError::MissingTransactionOutput(outpoint))?;
        transaction
            .output
            .get(index)
            .cloned()
            .ok_or(ElementsCoreError::MissingTransactionOutput(outpoint))
    }

    /// Probe chain/network identity, IBD state, pegged asset, canonical tip and txindex.
    pub fn probe(&self) -> Result<ElementsCoreChainStatus, ElementsCoreError> {
        let budget = self.begin_operation(CoreOperation::Startup)?;
        self.probe_with_budget(&budget)
    }

    pub fn probe_with_budget(
        &self,
        budget: &OperationBudget,
    ) -> Result<ElementsCoreChainStatus, ElementsCoreError> {
        let deadline = self.validate_budget(budget, CoreOperation::Startup)?;
        let genesis_hash = self.block_hash(0, deadline)?;
        if genesis_hash != self.chain().genesis_hash {
            return Err(ElementsCoreError::WrongChain {
                expected: self.chain().genesis_hash,
                actual: genesis_hash,
            });
        }
        let tip = self.blockchain_info(deadline)?;
        validate_network(&tip.chain, self.chain().network)?;
        if tip.initial_block_download {
            return Err(ElementsCoreError::InitialBlockDownload);
        }
        let sidechain_info: JsonValue = self.call("getsidechaininfo", json!([]), deadline)?;
        let pegged_asset = parse_pegged_asset(&sidechain_info)?;
        let labels: JsonValue = self.call("dumpassetlabels", json!([]), deadline)?;
        let bitcoin_label_asset = parse_builtin_bitcoin_asset_label(&labels)?;
        if bitcoin_label_asset != pegged_asset {
            return Err(ElementsCoreError::BitcoinAssetLabelMismatch {
                pegged_asset,
                label_asset: bitcoin_label_asset,
            });
        }
        let tip_height = u32::try_from(tip.blocks)
            .map_err(|_| ElementsCoreError::InvalidChainStatus("chain height exceeds u32"))?;
        let canonical_tip = self.block_hash(tip_height, deadline)?;
        if canonical_tip != tip.best_block {
            return Err(ElementsCoreError::InconsistentChainTip {
                height: tip_height,
                reported: tip.best_block,
                actual: canonical_tip,
            });
        }
        self.validate_txindex(deadline)?;
        budget.check()?;
        Ok(ElementsCoreChainStatus {
            network: self.chain().network,
            genesis_hash,
            pegged_asset,
            tip: ChainAnchor {
                height: tip_height,
                hash: tip.best_block,
            },
        })
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
    chain: String,
    blocks: u64,
    #[serde(rename = "bestblockhash")]
    best_block: BlockHash,
    #[serde(rename = "initialblockdownload")]
    initial_block_download: bool,
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

#[derive(Deserialize)]
struct MempoolEntry {
    wtxid: Wtxid,
}

#[derive(Deserialize)]
struct RelayRawTransactionStatus {
    txid: Txid,
    hash: Wtxid,
    blockhash: Option<BlockHash>,
    confirmations: Option<i64>,
}

#[derive(Deserialize)]
struct RelayBlockHeader {
    hash: BlockHash,
    height: u32,
}

#[derive(Deserialize)]
struct MempoolAcceptance {
    txid: Option<Txid>,
    wtxid: Option<Wtxid>,
    allowed: bool,
    #[serde(rename = "reject-reason")]
    reject_reason: Option<String>,
}

fn expected_chain_name(network: LiquidNetwork) -> &'static str {
    match network {
        LiquidNetwork::Liquid => "liquidv1",
        LiquidNetwork::LiquidTestnet => "liquidtestnet",
        LiquidNetwork::ElementsRegtest => "liquidregtest",
    }
}

fn validate_network(actual: &str, expected: LiquidNetwork) -> Result<(), ElementsCoreError> {
    if actual == expected_chain_name(expected) {
        Ok(())
    } else {
        Err(ElementsCoreError::WrongNetwork {
            expected,
            actual: bounded_excerpt(actual),
        })
    }
}

fn parse_pegged_asset(sidechain_info: &JsonValue) -> Result<AssetId, ElementsCoreError> {
    let sidechain_info = sidechain_info
        .as_object()
        .ok_or(ElementsCoreError::InvalidPeggedAsset)?;
    let encoded = sidechain_info
        .get("pegged_asset")
        .ok_or(ElementsCoreError::MissingPeggedAsset)?
        .as_str()
        .ok_or(ElementsCoreError::InvalidPeggedAsset)?;
    AssetId::from_str(encoded).map_err(|_| ElementsCoreError::InvalidPeggedAsset)
}

fn parse_builtin_bitcoin_asset_label(labels: &JsonValue) -> Result<AssetId, ElementsCoreError> {
    let labels = labels
        .as_object()
        .ok_or(ElementsCoreError::InvalidBitcoinAssetLabel)?;
    let encoded = labels
        .get("bitcoin")
        .ok_or(ElementsCoreError::MissingBitcoinAssetLabel)?
        .as_str()
        .ok_or(ElementsCoreError::InvalidBitcoinAssetLabel)?;
    AssetId::from_str(encoded).map_err(|_| ElementsCoreError::InvalidBitcoinAssetLabel)
}

fn validate_txindex_result(indexes: &JsonValue) -> Result<(), ElementsCoreError> {
    let txindex = indexes
        .as_object()
        .and_then(|indexes| indexes.get("txindex"))
        .and_then(JsonValue::as_object)
        .ok_or(ElementsCoreError::TxIndexUnavailable)?;
    if txindex.get("synced").and_then(JsonValue::as_bool) != Some(true) {
        return Err(ElementsCoreError::TxIndexNotSynced);
    }
    Ok(())
}

fn validate_outpoint(outpoint: OutPoint) -> Result<(), ElementsCoreError> {
    if outpoint.is_null() || outpoint.vout & 0xc000_0000 != 0 {
        return Err(ElementsCoreError::InvalidOutpoint(outpoint));
    }
    Ok(())
}

fn read_cookie(
    path: &PathBuf,
) -> Result<(Zeroizing<String>, Zeroizing<String>), ElementsCoreError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(|error| {
        ElementsCoreError::BackendUnavailable(format!(
            "cannot open Elements RPC cookie {}: {error}",
            path.display()
        ))
    })?;
    let metadata = file.metadata().map_err(|error| {
        ElementsCoreError::BackendUnavailable(format!(
            "cannot inspect Elements RPC cookie {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(ElementsCoreError::InvalidCookie);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(ElementsCoreError::InvalidCookie);
        }
    }
    if metadata.len() > MAX_COOKIE_BYTES as u64 {
        return Err(ElementsCoreError::InvalidCookie);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((MAX_COOKIE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            ElementsCoreError::BackendUnavailable(format!(
                "cannot read Elements RPC cookie {}: {error}",
                path.display()
            ))
        })?;
    if bytes.len() > MAX_COOKIE_BYTES {
        return Err(ElementsCoreError::InvalidCookie);
    }
    let cookie = std::str::from_utf8(&bytes)
        .map_err(|_| ElementsCoreError::InvalidCookie)?
        .trim_end_matches(['\r', '\n']);
    let (username, password) = cookie
        .split_once(':')
        .ok_or(ElementsCoreError::InvalidCookie)?;
    if username.is_empty() || password.is_empty() || password.contains(['\r', '\n']) {
        return Err(ElementsCoreError::InvalidCookie);
    }
    Ok((
        Zeroizing::new(username.to_owned()),
        Zeroizing::new(password.to_owned()),
    ))
}

fn read_bounded(
    mut response: Response,
    maximum: usize,
) -> Result<(StatusCode, Vec<u8>), ElementsCoreError> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(ElementsCoreError::ResponseTooLarge {
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
            ElementsCoreError::BackendUnavailable(format!(
                "cannot read Elements RPC response: {error}"
            ))
        })?;
    if body.len() > maximum {
        return Err(ElementsCoreError::ResponseTooLarge {
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
) -> Result<JsonValue, ElementsCoreError> {
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        return Err(ElementsCoreError::AuthenticationFailed);
    }
    let envelope: JsonValue = serde_json::from_slice(body).map_err(|error| {
        ElementsCoreError::InvalidRpcResponse(format!(
            "invalid {method} JSON-RPC response: {error}"
        ))
    })?;
    let object = envelope.as_object().ok_or_else(|| {
        ElementsCoreError::InvalidRpcResponse(format!(
            "{method} JSON-RPC response is not an object"
        ))
    })?;
    if object.get("id").and_then(JsonValue::as_u64) != Some(expected_id) {
        return Err(ElementsCoreError::InvalidRpcResponse(format!(
            "{method} JSON-RPC response id does not match request"
        )));
    }
    let error = object.get("error").ok_or_else(|| {
        ElementsCoreError::InvalidRpcResponse(format!(
            "{method} JSON-RPC response is missing error"
        ))
    })?;
    let result = object.get("result").ok_or_else(|| {
        ElementsCoreError::InvalidRpcResponse(format!(
            "{method} JSON-RPC response is missing result"
        ))
    })?;
    if !error.is_null() {
        if !result.is_null() {
            return Err(ElementsCoreError::InvalidRpcResponse(format!(
                "{method} JSON-RPC response contains both result and error"
            )));
        }
        let failure: RpcFailure = serde_json::from_value(error.clone()).map_err(|parse_error| {
            ElementsCoreError::InvalidRpcResponse(format!(
                "invalid {method} JSON-RPC error: {parse_error}"
            ))
        })?;
        return Err(ElementsCoreError::RpcRejected {
            method,
            code: failure.code,
            message: bounded_excerpt(&failure.message),
        });
    }
    if !status.is_success() {
        return Err(ElementsCoreError::BackendUnavailable(format!(
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

fn rpc_not_found(error: &ElementsCoreError, expected_method: &'static str) -> bool {
    matches!(
        error,
        ElementsCoreError::RpcRejected {
            method,
            code: -5,
            ..
        } if *method == expected_method
    )
}

fn relay_policy_rejection_reason<'a>(
    error: &'a ElementsCoreError,
    expected_method: &'static str,
) -> Option<&'a str> {
    match error {
        ElementsCoreError::RpcRejected {
            method,
            code: -25 | -26,
            message,
        } if *method == expected_method => Some(message),
        _ => None,
    }
}

fn transport_error(method: &str, error: &reqwest::Error) -> ElementsCoreError {
    let kind = if error.is_timeout() {
        "request timed out"
    } else if error.is_connect() {
        "connection failed"
    } else {
        "transport failed"
    };
    ElementsCoreError::BackendUnavailable(format!("Elements RPC {method} {kind}: {error}"))
}

#[derive(Deserialize)]
struct RpcFailure {
    code: i64,
    message: String,
}

/// Fail-closed Elements Core client error.
#[derive(Debug, Error)]
pub enum ElementsCoreError {
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
    #[error("Elements Core network `{actual}` does not match {expected:?}")]
    WrongNetwork {
        expected: LiquidNetwork,
        actual: String,
    },
    #[error("Elements Core is still in initial block download")]
    InitialBlockDownload,
    #[error("Elements Core sidechain info does not contain `pegged_asset`")]
    MissingPeggedAsset,
    #[error("Elements Core's `pegged_asset` sidechain-info field is invalid")]
    InvalidPeggedAsset,
    #[error("Elements Core asset labels do not contain the built-in `bitcoin` label")]
    MissingBitcoinAssetLabel,
    #[error("Elements Core's built-in `bitcoin` asset-label mapping is invalid")]
    InvalidBitcoinAssetLabel,
    #[error(
        "Elements Core's built-in `bitcoin` asset label {label_asset} does not match its sidechain pegged asset {pegged_asset}"
    )]
    BitcoinAssetLabelMismatch {
        pegged_asset: AssetId,
        label_asset: AssetId,
    },
    #[error("invalid Elements Core chain status: {0}")]
    InvalidChainStatus(&'static str),
    #[error(
        "Elements Core reported tip {reported} at height {height}, but getblockhash returned {actual}"
    )]
    InconsistentChainTip {
        height: u32,
        reported: BlockHash,
        actual: BlockHash,
    },
    #[error("anchor {anchor:?} is above stable tip {tip:?}")]
    AnchorAboveTip {
        anchor: ChainAnchor,
        tip: ChainAnchor,
    },
    #[error("anchor {anchor:?} is not canonical; active hash at its height is {actual}")]
    AnchorNotCanonical {
        anchor: ChainAnchor,
        actual: BlockHash,
    },
    #[error("chain tip changed from {expected:?} to {actual:?} during operation")]
    TipChanged {
        expected: ChainAnchor,
        actual: ChainAnchor,
    },
    #[error("scan has {actual} scripts; maximum is {maximum}")]
    TooManyScanScripts { maximum: usize, actual: usize },
    #[error("script scan contains the same script more than once")]
    DuplicateScanScript,
    #[error("Elements Core aborted the UTXO-set scan")]
    ScanAborted,
    #[error("UTXO-set scan returned {actual} matches; maximum is {maximum}")]
    TooManyScanResults { maximum: usize, actual: usize },
    #[error("materialized complete outputs retain {actual} bytes; maximum is {maximum}")]
    MaterializedTxoutsTooLarge { maximum: usize, actual: usize },
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
    #[error("scan tip changed from {expected:?} to {actual:?}")]
    ScanTipChanged {
        expected: ChainAnchor,
        actual: ChainAnchor,
    },
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
    #[error("prevout snapshot has {actual} outpoints; maximum is {maximum}")]
    TooManyPrevouts { maximum: usize, actual: usize },
    #[error("prevout snapshot repeats outpoint {0:?}")]
    DuplicatePrevout(OutPoint),
    #[error("prevout snapshot has {actual} required anchors; maximum is {maximum}")]
    TooManyRequiredAnchors { maximum: usize, actual: usize },
    #[error("prevout snapshot repeats required anchor {0:?}")]
    DuplicateRequiredAnchor(ChainAnchor),
    #[error("required anchors conflict at height {height}: first {first}, second {second}")]
    ConflictingRequiredAnchors {
        height: u32,
        first: BlockHash,
        second: BlockHash,
    },
    #[error("Elements Core txindex is required for complete prevouts")]
    TxIndexUnavailable,
    #[error("Elements Core txindex is not synchronized")]
    TxIndexNotSynced,
    #[error("prevout is missing or spent: {0:?}")]
    MissingOrSpentPrevout(OutPoint),
    #[error(
        "prevout {outpoint:?} reports {confirmations} confirmations under tip {tip:?}, which is impossible"
    )]
    InvalidPrevoutConfirmations {
        outpoint: OutPoint,
        confirmations: u64,
        tip: ChainAnchor,
    },
    #[error("mempool view changed while resolving prevout {0:?}")]
    PrevoutViewChanged(OutPoint),
    #[error(
        "coinbase prevout {outpoint:?} has {confirmations} confirmations; {COINBASE_MATURITY_CONFIRMATIONS} required"
    )]
    ImmatureCoinbasePrevout {
        outpoint: OutPoint,
        confirmations: u64,
    },
    #[error("gettxout and the raw creating transaction disagree at {0:?}")]
    AuthoritativeOutputMismatch(OutPoint),
    #[error("relay input contains an invalid exact transaction: {0}")]
    InvalidRelayTransaction(&'static str),
    #[error("relay transaction witness id is {actual}, expected {expected}")]
    WitnessTransactionIdMismatch { expected: Wtxid, actual: Wtxid },
    #[error("relay transaction view changed while reconciling exact bytes")]
    RelayViewChanged,
    #[error(
        "relay transaction claimed block {reported} at height {height}, but canonical block is {actual}"
    )]
    RelayBlockNotCanonical {
        height: u32,
        reported: BlockHash,
        actual: BlockHash,
    },
    #[error("Elements script-scan serialization lock is poisoned")]
    ScanLockPoisoned,
    #[error("Elements {operation} operation exceeded its deadline")]
    OperationTimedOut { operation: &'static str },
    #[error("operation budget belongs to another Elements Core client")]
    ForeignOperationBudget,
    #[error("expected a {expected:?} operation budget, received {actual:?}")]
    WrongOperationBudget {
        expected: CoreOperation,
        actual: CoreOperation,
    },
}

impl ElementsCoreError {
    /// Whether a provider should treat this failure as temporary backend
    /// unavailability rather than invalid backend data.
    ///
    /// This stable predicate keeps adapters from exhaustively coupling their
    /// admission policy to every error variant in this crate.
    #[must_use]
    pub const fn is_backend_unavailable(&self) -> bool {
        matches!(
            self,
            Self::BackendUnavailable(_)
                | Self::AuthenticationFailed
                | Self::InvalidCookie
                | Self::InitialBlockDownload
                | Self::TxIndexNotSynced
                | Self::OperationTimedOut { .. }
                | Self::RelayViewChanged
                | Self::RelayBlockNotCanonical { .. }
                | Self::TipChanged { .. }
                | Self::PrevoutViewChanged(_)
                | Self::RpcRejected { code: -5 | -28, .. }
        )
    }
}

/// Exact durable transaction identity supplied to the relay boundary.
#[derive(Clone, Copy)]
pub struct ExactTransaction<'a> {
    txid: Txid,
    wtxid: Wtxid,
    bytes: &'a [u8],
}

impl fmt::Debug for ExactTransaction<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactTransaction")
            .field("txid", &self.txid)
            .field("wtxid", &self.wtxid)
            .field("bytes_len", &self.bytes.len())
            .finish()
    }
}

impl<'a> ExactTransaction<'a> {
    #[must_use]
    pub const fn new(txid: Txid, wtxid: Wtxid, bytes: &'a [u8]) -> Self {
        Self { txid, wtxid, bytes }
    }

    #[must_use]
    pub const fn txid(self) -> Txid {
        self.txid
    }

    #[must_use]
    pub const fn wtxid(self) -> Wtxid {
        self.wtxid
    }

    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
}

/// Exact transaction status resolved by one relay attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreRelayObservation {
    BroadcastAccepted,
    Mempool,
    Confirmed {
        block_hash: BlockHash,
        block_height: u32,
    },
    Absent,
    Conflicted {
        spent_input: OutPoint,
        conflicting_txid: Option<Txid>,
    },
}

/// Completed exact relay attempt, including a non-fatal policy rejection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreRelayAttemptResult {
    observation: CoreRelayObservation,
    policy_rejected: bool,
    policy_rejection_reason: Option<String>,
}

impl CoreRelayAttemptResult {
    const fn observed(observation: CoreRelayObservation) -> Self {
        Self {
            observation,
            policy_rejected: false,
            policy_rejection_reason: None,
        }
    }

    fn policy_rejected(
        observation: CoreRelayObservation,
        policy_rejection_reason: Option<String>,
    ) -> Self {
        Self {
            observation,
            policy_rejected: true,
            policy_rejection_reason,
        }
    }

    #[must_use]
    pub const fn observation(&self) -> CoreRelayObservation {
        self.observation
    }

    #[must_use]
    pub const fn was_policy_rejected(&self) -> bool {
        self.policy_rejected
    }

    /// Bounded backend diagnostic for a non-fatal policy rejection, when Core
    /// supplied one.
    #[must_use]
    pub fn policy_rejection_reason(&self) -> Option<&str> {
        self.policy_rejection_reason.as_deref()
    }
}

impl ElementsCoreClient {
    fn relay_transaction(
        &self,
        exact: ExactTransaction<'_>,
    ) -> Result<Transaction, ElementsCoreError> {
        if exact.bytes.len() > self.inner.limits.max_raw_transaction_bytes {
            return Err(ElementsCoreError::RawTransactionTooLarge {
                maximum: self.inner.limits.max_raw_transaction_bytes,
                actual: exact.bytes.len(),
            });
        }
        let transaction = deserialize::<Transaction>(exact.bytes)
            .map_err(|_| ElementsCoreError::InvalidRelayTransaction("invalid consensus bytes"))?;
        if serialize(&transaction) != exact.bytes {
            return Err(ElementsCoreError::InvalidRelayTransaction(
                "transaction bytes are not canonical",
            ));
        }
        if transaction.txid() != exact.txid {
            return Err(ElementsCoreError::TransactionIdMismatch {
                requested: exact.txid,
                actual: transaction.txid(),
            });
        }
        if transaction.wtxid() != exact.wtxid {
            return Err(ElementsCoreError::WitnessTransactionIdMismatch {
                expected: exact.wtxid,
                actual: transaction.wtxid(),
            });
        }
        if transaction.input.is_empty() {
            return Err(ElementsCoreError::InvalidRelayTransaction(
                "transaction has no inputs",
            ));
        }
        for input in &transaction.input {
            validate_outpoint(input.previous_output)?;
        }
        Ok(transaction)
    }

    fn exact_relay_observation(
        &self,
        exact: ExactTransaction<'_>,
        transaction: &Transaction,
        deadline: OperationDeadline,
    ) -> Result<Option<CoreRelayObservation>, ElementsCoreError> {
        let status: RelayRawTransactionStatus =
            match self.call("getrawtransaction", json!([exact.txid, true]), deadline) {
                Ok(status) => status,
                Err(error) if rpc_not_found(&error, "getrawtransaction") => return Ok(None),
                Err(error) => return Err(error),
            };
        if status.txid != exact.txid {
            return Err(ElementsCoreError::TransactionIdMismatch {
                requested: exact.txid,
                actual: status.txid,
            });
        }
        let raw: String = match self.call("getrawtransaction", json!([exact.txid, false]), deadline)
        {
            Ok(raw) => raw,
            Err(error) if rpc_not_found(&error, "getrawtransaction") => {
                return Err(ElementsCoreError::RelayViewChanged);
            }
            Err(error) => return Err(error),
        };
        let observed = self.decode_raw_transaction(&raw)?;
        if observed.txid() != exact.txid {
            return Err(ElementsCoreError::TransactionIdMismatch {
                requested: exact.txid,
                actual: observed.txid(),
            });
        }
        if status.hash != observed.wtxid() {
            return Err(ElementsCoreError::InvalidRpcResponse(
                "verbose and raw relay transaction witness IDs disagree".to_owned(),
            ));
        }
        let confirmed_block = match status.blockhash {
            Some(block_hash) => {
                let Some(confirmations) = status.confirmations else {
                    return Err(ElementsCoreError::InvalidRpcResponse(
                        "block-associated relay transaction has no confirmation count".to_owned(),
                    ));
                };
                if confirmations <= 0 {
                    return Ok(None);
                }
                Some(block_hash)
            }
            None => {
                if status
                    .confirmations
                    .is_some_and(|confirmations| confirmations > 0)
                {
                    return Err(ElementsCoreError::InvalidRpcResponse(
                        "unconfirmed relay transaction has positive confirmations".to_owned(),
                    ));
                }
                None
            }
        };
        if serialize(&observed) != exact.bytes || observed.wtxid() != exact.wtxid {
            let spent_input = transaction
                .input
                .iter()
                .map(|input| input.previous_output)
                .min()
                .ok_or(ElementsCoreError::InvalidRelayTransaction(
                    "transaction has no inputs",
                ))?;
            return Ok(Some(CoreRelayObservation::Conflicted {
                spent_input,
                conflicting_txid: Some(exact.txid),
            }));
        }
        match confirmed_block {
            Some(block_hash) => {
                let header: RelayBlockHeader =
                    match self.call("getblockheader", json!([block_hash, true]), deadline) {
                        Ok(header) => header,
                        Err(error) if rpc_not_found(&error, "getblockheader") => {
                            return Err(ElementsCoreError::RelayViewChanged);
                        }
                        Err(error) => return Err(error),
                    };
                if header.hash != block_hash {
                    return Err(ElementsCoreError::InvalidRpcResponse(
                        "getblockheader returned a different relay block".to_owned(),
                    ));
                }
                let canonical = self.block_hash(header.height, deadline)?;
                if canonical != block_hash {
                    return Err(ElementsCoreError::RelayBlockNotCanonical {
                        height: header.height,
                        reported: block_hash,
                        actual: canonical,
                    });
                }
                Ok(Some(CoreRelayObservation::Confirmed {
                    block_hash,
                    block_height: header.height,
                }))
            }
            None => Ok(Some(CoreRelayObservation::Mempool)),
        }
    }

    fn absent_relay_observation(
        &self,
        exact: ExactTransaction<'_>,
        transaction: &Transaction,
        deadline: OperationDeadline,
    ) -> Result<CoreRelayObservation, ElementsCoreError> {
        let tip = self.stable_tip(deadline)?;
        let mut spent_input = None;
        for input in &transaction.input {
            let outpoint = input.previous_output;
            match self.gettxout(outpoint, deadline)? {
                Some(observed) => {
                    if observed.best_block != tip.hash {
                        return Err(ElementsCoreError::TipChanged {
                            expected: tip,
                            actual: ChainAnchor {
                                height: tip.height,
                                hash: observed.best_block,
                            },
                        });
                    }
                }
                None => {
                    spent_input = Some(
                        spent_input.map_or(outpoint, |current: OutPoint| current.min(outpoint)),
                    );
                }
            }
        }
        let final_tip = self.stable_tip(deadline)?;
        if final_tip != tip {
            return Err(ElementsCoreError::TipChanged {
                expected: tip,
                actual: final_tip,
            });
        }
        let Some(spent_input) = spent_input else {
            return Ok(CoreRelayObservation::Absent);
        };
        if let Some(observation) = self.exact_relay_observation(exact, transaction, deadline)? {
            return Ok(observation);
        }
        Ok(CoreRelayObservation::Conflicted {
            spent_input,
            conflicting_txid: None,
        })
    }

    fn reconcile_after_external_call(
        &self,
        exact: ExactTransaction<'_>,
        transaction: &Transaction,
        deadline: OperationDeadline,
    ) -> Result<CoreRelayObservation, ElementsCoreError> {
        if let Some(observation) = self.exact_relay_observation(exact, transaction, deadline)? {
            return Ok(observation);
        }
        self.absent_relay_observation(exact, transaction, deadline)
    }

    /// Reconcile, policy-check and relay one exact canonical transaction.
    pub fn relay_exact(
        &self,
        exact: ExactTransaction<'_>,
    ) -> Result<CoreRelayAttemptResult, ElementsCoreError> {
        let budget = self.begin_operation(CoreOperation::Relay)?;
        self.relay_exact_with_budget(&budget, exact)
    }

    pub fn relay_exact_with_budget(
        &self,
        budget: &OperationBudget,
        exact: ExactTransaction<'_>,
    ) -> Result<CoreRelayAttemptResult, ElementsCoreError> {
        let deadline = self.validate_budget(budget, CoreOperation::Relay)?;
        let transaction = self.relay_transaction(exact)?;
        self.validate_chain_identity(deadline)?;
        self.validate_txindex(deadline)?;
        if let Some(observation) = self.exact_relay_observation(exact, &transaction, deadline)? {
            budget.check()?;
            return Ok(CoreRelayAttemptResult::observed(observation));
        }
        let absent = self.absent_relay_observation(exact, &transaction, deadline)?;
        if absent != CoreRelayObservation::Absent {
            budget.check()?;
            return Ok(CoreRelayAttemptResult::observed(absent));
        }

        let raw = hex::encode(exact.bytes);
        let acceptance: Vec<MempoolAcceptance> =
            self.call("testmempoolaccept", json!([[raw], 0]), deadline)?;
        let [acceptance] = acceptance.as_slice() else {
            return Err(ElementsCoreError::InvalidRpcResponse(format!(
                "testmempoolaccept returned {} entries for one relay transaction",
                acceptance.len()
            )));
        };
        if acceptance.txid.is_some_and(|txid| txid != exact.txid)
            || acceptance.wtxid.is_some_and(|wtxid| wtxid != exact.wtxid)
        {
            return Err(ElementsCoreError::InvalidRpcResponse(
                "testmempoolaccept returned a different relay transaction".to_owned(),
            ));
        }
        if !acceptance.allowed {
            let observation = self.reconcile_after_external_call(exact, &transaction, deadline)?;
            budget.check()?;
            return Ok(if observation == CoreRelayObservation::Absent {
                CoreRelayAttemptResult::policy_rejected(
                    observation,
                    acceptance.reject_reason.as_deref().map(bounded_excerpt),
                )
            } else {
                CoreRelayAttemptResult::observed(observation)
            });
        }

        let reported: Result<Txid, ElementsCoreError> =
            self.call("sendrawtransaction", json!([raw, 0]), deadline);
        let result = match reported {
            Ok(reported) if reported == exact.txid => {
                CoreRelayAttemptResult::observed(CoreRelayObservation::BroadcastAccepted)
            }
            Ok(reported) => {
                let observation =
                    self.reconcile_after_external_call(exact, &transaction, deadline)?;
                if observation != CoreRelayObservation::Absent {
                    CoreRelayAttemptResult::observed(observation)
                } else {
                    return Err(ElementsCoreError::TransactionIdMismatch {
                        requested: exact.txid,
                        actual: reported,
                    });
                }
            }
            Err(send_error) => {
                let observation =
                    self.reconcile_after_external_call(exact, &transaction, deadline)?;
                if observation != CoreRelayObservation::Absent {
                    CoreRelayAttemptResult::observed(observation)
                } else if let Some(reason) =
                    relay_policy_rejection_reason(&send_error, "sendrawtransaction")
                {
                    CoreRelayAttemptResult::policy_rejected(
                        CoreRelayObservation::Absent,
                        Some(bounded_excerpt(reason)),
                    )
                } else {
                    return Err(send_error);
                }
            }
        };
        budget.check()?;
        Ok(result)
    }
}

impl fmt::Debug for ElementsCoreClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ElementsCoreClient")
            .field("chain", &self.chain())
            .field("limits", &self.inner.limits)
            .finish_non_exhaustive()
    }
}

/// Scan operation holding both the process-local `scantxoutset` gate and its
/// operation-wide deadline across caller-owned wallet work.
pub struct ScriptScanOperation<'a> {
    client: &'a ElementsCoreClient,
    budget: OperationBudget,
    _permit: ScanPermit<'a>,
}

impl ScriptScanOperation<'_> {
    pub fn check(&self) -> Result<(), ElementsCoreError> {
        self.budget.check()
    }

    pub fn scan_unspent_scripts(
        &self,
        scripts: &[Script],
    ) -> Result<ScriptScanSnapshot, ElementsCoreError> {
        self.client
            .scan_unspent_scripts_with_budget(&self.budget, scripts)
    }
}

impl fmt::Debug for ScriptScanOperation<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScriptScanOperation")
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

/// Wallet-independent status returned by a successful startup probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ElementsCoreChainStatus {
    network: LiquidNetwork,
    genesis_hash: BlockHash,
    pegged_asset: AssetId,
    tip: ChainAnchor,
}

impl ElementsCoreChainStatus {
    #[must_use]
    pub const fn network(self) -> LiquidNetwork {
        self.network
    }

    #[must_use]
    pub const fn genesis_hash(self) -> BlockHash {
        self.genesis_hash
    }

    #[must_use]
    pub const fn pegged_asset(self) -> AssetId {
        self.pegged_asset
    }

    #[must_use]
    pub const fn tip(self) -> ChainAnchor {
        self.tip
    }
}

/// One complete active-chain output matched by a requested script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScannedOutput {
    script_pubkey: Script,
    outpoint: OutPoint,
    txout: TxOut,
}

impl ScannedOutput {
    #[must_use]
    pub const fn script_pubkey(&self) -> &Script {
        &self.script_pubkey
    }

    #[must_use]
    pub const fn outpoint(&self) -> OutPoint {
        self.outpoint
    }

    #[must_use]
    pub const fn txout(&self) -> &TxOut {
        &self.txout
    }

    #[must_use]
    pub fn into_txout(self) -> TxOut {
        self.txout
    }
}

/// Complete script scan under one canonical chain anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptScanSnapshot {
    anchor: ChainAnchor,
    outputs: Vec<ScannedOutput>,
}

impl ScriptScanSnapshot {
    #[must_use]
    pub const fn anchor(&self) -> ChainAnchor {
        self.anchor
    }

    #[must_use]
    pub fn outputs(&self) -> &[ScannedOutput] {
        &self.outputs
    }

    #[must_use]
    pub fn into_outputs(self) -> Vec<ScannedOutput> {
        self.outputs
    }
}

/// One complete chain-authoritative unspent output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorePrevout {
    outpoint: OutPoint,
    txout: TxOut,
}

impl CorePrevout {
    #[must_use]
    pub const fn outpoint(&self) -> OutPoint {
        self.outpoint
    }

    #[must_use]
    pub const fn txout(&self) -> &TxOut {
        &self.txout
    }

    #[must_use]
    pub fn into_txout(self) -> TxOut {
        self.txout
    }
}

/// Ordered prevouts and ancestry proofs observed under one stable Core tip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrevoutSnapshot {
    anchor: ChainAnchor,
    prevouts: Vec<CorePrevout>,
}

impl PrevoutSnapshot {
    #[must_use]
    pub const fn anchor(&self) -> ChainAnchor {
        self.anchor
    }

    #[must_use]
    pub fn prevouts(&self) -> &[CorePrevout] {
        &self.prevouts
    }

    #[must_use]
    pub fn into_prevouts(self) -> Vec<CorePrevout> {
        self.prevouts
    }
}

impl ElementsCoreClient {
    /// Scan the active confirmed UTXO set for exact scripts.
    pub fn scan_unspent_scripts(
        &self,
        scripts: &[Script],
    ) -> Result<ScriptScanSnapshot, ElementsCoreError> {
        self.begin_script_scan()?.scan_unspent_scripts(scripts)
    }

    fn scan_unspent_scripts_with_budget(
        &self,
        budget: &OperationBudget,
        scripts: &[Script],
    ) -> Result<ScriptScanSnapshot, ElementsCoreError> {
        let deadline = self.validate_budget(budget, CoreOperation::Scan)?;
        if scripts.len() > self.inner.limits.max_scan_scripts {
            return Err(ElementsCoreError::TooManyScanScripts {
                maximum: self.inner.limits.max_scan_scripts,
                actual: scripts.len(),
            });
        }
        let mut requested = BTreeSet::<Vec<u8>>::new();
        for script in scripts {
            deadline.check()?;
            if !requested.insert(script.as_bytes().to_vec()) {
                return Err(ElementsCoreError::DuplicateScanScript);
            }
        }

        if requested.is_empty() {
            let anchor = self.stable_tip(deadline)?;
            let final_anchor = self.stable_tip(deadline)?;
            if final_anchor != anchor {
                return Err(ElementsCoreError::ScanTipChanged {
                    expected: anchor,
                    actual: final_anchor,
                });
            }
            budget.check()?;
            return Ok(ScriptScanSnapshot {
                anchor,
                outputs: Vec::new(),
            });
        }

        self.validate_chain_identity(deadline)?;
        let descriptors = requested
            .iter()
            .map(|script| format!("raw({})", hex::encode(script)))
            .collect::<Vec<_>>();
        let scan: ScanResult =
            self.call("scantxoutset", json!(["start", descriptors]), deadline)?;
        if !scan.success {
            return Err(ElementsCoreError::ScanAborted);
        }
        if scan.unspents.len() > self.inner.limits.max_scan_results {
            return Err(ElementsCoreError::TooManyScanResults {
                maximum: self.inner.limits.max_scan_results,
                actual: scan.unspents.len(),
            });
        }
        let height = u32::try_from(scan.height)
            .map_err(|_| ElementsCoreError::InvalidScanResult("scan height exceeds u32"))?;
        let anchor = ChainAnchor {
            height,
            hash: scan.best_block,
        };
        let mut seen = BTreeSet::new();
        let mut group_indexes = BTreeMap::<Txid, usize>::new();
        let mut groups = Vec::<Vec<ScanUnspent>>::new();
        for unspent in scan.unspents {
            deadline.check()?;
            if unspent.height > scan.height {
                return Err(ElementsCoreError::InvalidScanResult(
                    "UTXO creation height exceeds scan height",
                ));
            }
            let outpoint = OutPoint::new(unspent.txid, unspent.vout);
            validate_outpoint(outpoint)?;
            if !seen.insert(outpoint) {
                return Err(ElementsCoreError::DuplicateScanOutpoint(outpoint));
            }
            if !requested.contains(unspent.script_pub_key.as_bytes()) {
                return Err(ElementsCoreError::UnexpectedScanScript(outpoint));
            }
            if let Some(index) = group_indexes.get(&unspent.txid).copied() {
                groups[index].push(unspent);
            } else {
                let index = groups.len();
                group_indexes.insert(unspent.txid, index);
                groups.push(vec![unspent]);
            }
        }

        let mut outputs = Vec::with_capacity(seen.len());
        let mut retained_output_bytes = 0_usize;
        let mut creation_blocks = BTreeMap::<u32, BlockHash>::new();
        for group in groups {
            let creation_height = group[0].height;
            if group
                .iter()
                .any(|unspent| unspent.height != creation_height)
            {
                return Err(ElementsCoreError::InvalidScanResult(
                    "one creating transaction was reported at multiple block heights",
                ));
            }
            let creation_height = u32::try_from(creation_height)
                .map_err(|_| ElementsCoreError::InvalidScanResult("UTXO height exceeds u32"))?;
            let mut candidates = Vec::with_capacity(group.len());
            for unspent in group {
                let outpoint = OutPoint::new(unspent.txid, unspent.vout);
                let Some(observed) = self.gettxout(outpoint, deadline)? else {
                    // `scantxoutset` excludes mempool effects. Omit a
                    // confirmed candidate that a mempool transaction spent.
                    continue;
                };
                if observed.best_block != scan.best_block {
                    return Err(ElementsCoreError::ScanTipChanged {
                        expected: anchor,
                        actual: ChainAnchor {
                            height,
                            hash: observed.best_block,
                        },
                    });
                }
                let expected_confirmations = scan
                    .height
                    .checked_sub(unspent.height)
                    .and_then(|depth| depth.checked_add(1))
                    .ok_or(ElementsCoreError::InvalidScanResult(
                        "UTXO confirmation count overflows",
                    ))?;
                if observed.confirmations != expected_confirmations {
                    return Err(ElementsCoreError::ScanConfirmationMismatch {
                        outpoint,
                        expected: expected_confirmations,
                        actual: observed.confirmations,
                    });
                }
                if observed.coinbase && observed.confirmations < COINBASE_MATURITY_CONFIRMATIONS {
                    continue;
                }
                let observed_script = hex::decode(&observed.script_pub_key.hex).map_err(|_| {
                    ElementsCoreError::InvalidRpcResponse(
                        "gettxout scriptPubKey contains invalid hex".to_owned(),
                    )
                })?;
                candidates.push((unspent, observed_script));
            }
            if candidates.is_empty() {
                continue;
            }

            let creation_block = if let Some(cached) = creation_blocks.get(&creation_height) {
                *cached
            } else {
                let fetched = self.block_hash(creation_height, deadline)?;
                creation_blocks.insert(creation_height, fetched);
                fetched
            };
            let transaction =
                self.raw_transaction(candidates[0].0.txid, Some(creation_block), deadline)?;
            for (unspent, observed_script) in candidates {
                deadline.check()?;
                let outpoint = OutPoint::new(unspent.txid, unspent.vout);
                let txout = Self::transaction_output(outpoint, &transaction)?;
                if txout.script_pubkey != unspent.script_pub_key
                    || observed_script != txout.script_pubkey.as_bytes()
                {
                    return Err(ElementsCoreError::ScanOutputMismatch(outpoint));
                }
                let retained = serialize(&txout)
                    .len()
                    .checked_add(serialize(&txout.witness).len())
                    .ok_or(ElementsCoreError::MaterializedTxoutsTooLarge {
                        maximum: self.inner.limits.max_materialized_txout_bytes,
                        actual: usize::MAX,
                    })?;
                retained_output_bytes = retained_output_bytes.checked_add(retained).ok_or(
                    ElementsCoreError::MaterializedTxoutsTooLarge {
                        maximum: self.inner.limits.max_materialized_txout_bytes,
                        actual: usize::MAX,
                    },
                )?;
                if retained_output_bytes > self.inner.limits.max_materialized_txout_bytes {
                    return Err(ElementsCoreError::MaterializedTxoutsTooLarge {
                        maximum: self.inner.limits.max_materialized_txout_bytes,
                        actual: retained_output_bytes,
                    });
                }
                outputs.push(ScannedOutput {
                    script_pubkey: txout.script_pubkey.clone(),
                    outpoint,
                    txout,
                });
            }
        }

        let final_anchor = self.stable_tip(deadline)?;
        if final_anchor != anchor {
            return Err(ElementsCoreError::ScanTipChanged {
                expected: anchor,
                actual: final_anchor,
            });
        }
        outputs.sort_by_key(ScannedOutput::outpoint);
        budget.check()?;
        Ok(ScriptScanSnapshot { anchor, outputs })
    }

    /// Validate an anchor and return the unchanged tip that committed to it.
    pub fn validate_canonical_anchor(
        &self,
        anchor: ChainAnchor,
    ) -> Result<ChainAnchor, ElementsCoreError> {
        let budget = self.begin_operation(CoreOperation::Anchor)?;
        self.validate_canonical_anchor_with_budget(&budget, anchor)
    }

    pub fn validate_canonical_anchor_with_budget(
        &self,
        budget: &OperationBudget,
        anchor: ChainAnchor,
    ) -> Result<ChainAnchor, ElementsCoreError> {
        let deadline = self.validate_budget(budget, CoreOperation::Anchor)?;
        let tip = self.stable_tip(deadline)?;
        self.require_anchor(anchor, tip, deadline)?;
        let final_tip = self.stable_tip(deadline)?;
        if final_tip != tip {
            return Err(ElementsCoreError::TipChanged {
                expected: tip,
                actual: final_tip,
            });
        }
        self.require_anchor(anchor, final_tip, deadline)?;
        budget.check()?;
        Ok(tip)
    }

    /// Resolve ordered complete prevouts and required ancestry under one tip.
    pub fn unspent_prevouts(
        &self,
        outpoints: &[OutPoint],
        required_anchors: &[ChainAnchor],
    ) -> Result<PrevoutSnapshot, ElementsCoreError> {
        let budget = self.begin_operation(CoreOperation::Prevouts)?;
        self.unspent_prevouts_with_budget(&budget, outpoints, required_anchors)
    }

    pub fn unspent_prevouts_with_budget(
        &self,
        budget: &OperationBudget,
        outpoints: &[OutPoint],
        required_anchors: &[ChainAnchor],
    ) -> Result<PrevoutSnapshot, ElementsCoreError> {
        let deadline = self.validate_budget(budget, CoreOperation::Prevouts)?;
        if outpoints.len() > self.inner.limits.max_prevouts {
            return Err(ElementsCoreError::TooManyPrevouts {
                maximum: self.inner.limits.max_prevouts,
                actual: outpoints.len(),
            });
        }
        if required_anchors.len() > self.inner.limits.max_required_anchors {
            return Err(ElementsCoreError::TooManyRequiredAnchors {
                maximum: self.inner.limits.max_required_anchors,
                actual: required_anchors.len(),
            });
        }
        let mut unique = BTreeSet::new();
        for outpoint in outpoints {
            deadline.check()?;
            validate_outpoint(*outpoint)?;
            if !unique.insert(*outpoint) {
                return Err(ElementsCoreError::DuplicatePrevout(*outpoint));
            }
        }
        let mut anchor_by_height = BTreeMap::new();
        for anchor in required_anchors {
            if let Some(previous) = anchor_by_height.insert(anchor.height, anchor.hash) {
                if previous == anchor.hash {
                    return Err(ElementsCoreError::DuplicateRequiredAnchor(*anchor));
                }
                return Err(ElementsCoreError::ConflictingRequiredAnchors {
                    height: anchor.height,
                    first: previous,
                    second: anchor.hash,
                });
            }
        }

        self.validate_txindex(deadline)?;
        let tip = self.stable_tip(deadline)?;
        for anchor in required_anchors {
            self.require_anchor(*anchor, tip, deadline)?;
        }
        let mut prevouts = Vec::with_capacity(outpoints.len());
        let mut retained_output_bytes = 0_usize;
        let mut transactions = BTreeMap::<Txid, (u64, Transaction)>::new();
        for outpoint in outpoints {
            let observed = self
                .gettxout(*outpoint, deadline)?
                .ok_or(ElementsCoreError::MissingOrSpentPrevout(*outpoint))?;
            if observed.best_block != tip.hash {
                return Err(ElementsCoreError::TipChanged {
                    expected: tip,
                    actual: ChainAnchor {
                        height: tip.height,
                        hash: observed.best_block,
                    },
                });
            }
            if observed.coinbase && observed.confirmations < COINBASE_MATURITY_CONFIRMATIONS {
                return Err(ElementsCoreError::ImmatureCoinbasePrevout {
                    outpoint: *outpoint,
                    confirmations: observed.confirmations,
                });
            }
            let transaction = match transactions.entry(outpoint.txid) {
                std::collections::btree_map::Entry::Occupied(entry) => {
                    if entry.get().0 != observed.confirmations {
                        return Err(ElementsCoreError::InvalidPrevoutConfirmations {
                            outpoint: *outpoint,
                            confirmations: observed.confirmations,
                            tip,
                        });
                    }
                    &mut entry.into_mut().1
                }
                std::collections::btree_map::Entry::Vacant(entry) => {
                    let transaction = self.authoritative_prevout_transaction(
                        *outpoint,
                        observed.confirmations,
                        tip,
                        deadline,
                    )?;
                    &mut entry.insert((observed.confirmations, transaction)).1
                }
            };
            let txout = Self::transaction_output(*outpoint, transaction)?;
            let script = hex::decode(&observed.script_pub_key.hex).map_err(|_| {
                ElementsCoreError::InvalidRpcResponse(
                    "gettxout scriptPubKey contains invalid hex".to_owned(),
                )
            })?;
            if script != txout.script_pubkey.as_bytes() {
                return Err(ElementsCoreError::AuthoritativeOutputMismatch(*outpoint));
            }
            let retained = serialize(&txout)
                .len()
                .checked_add(serialize(&txout.witness).len())
                .ok_or(ElementsCoreError::MaterializedTxoutsTooLarge {
                    maximum: self.inner.limits.max_materialized_txout_bytes,
                    actual: usize::MAX,
                })?;
            retained_output_bytes = retained_output_bytes.checked_add(retained).ok_or(
                ElementsCoreError::MaterializedTxoutsTooLarge {
                    maximum: self.inner.limits.max_materialized_txout_bytes,
                    actual: usize::MAX,
                },
            )?;
            if retained_output_bytes > self.inner.limits.max_materialized_txout_bytes {
                return Err(ElementsCoreError::MaterializedTxoutsTooLarge {
                    maximum: self.inner.limits.max_materialized_txout_bytes,
                    actual: retained_output_bytes,
                });
            }
            prevouts.push(CorePrevout {
                outpoint: *outpoint,
                txout,
            });
        }
        let final_tip = self.stable_tip(deadline)?;
        if final_tip != tip {
            return Err(ElementsCoreError::TipChanged {
                expected: tip,
                actual: final_tip,
            });
        }
        for anchor in required_anchors {
            self.require_anchor(*anchor, final_tip, deadline)?;
        }
        budget.check()?;
        Ok(PrevoutSnapshot {
            anchor: tip,
            prevouts,
        })
    }
}

#[cfg(test)]
mod tests;

//! Authenticated Elements Core JSON-RPC implementation of
//! [`ChainSource`](super::ChainSource).

use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use deadcat_types::ChainAnchor;
use elements::encode::{deserialize, serialize};
use elements::{AssetId, Block, BlockHash, OutPoint, Script, Transaction, Txid};
use reqwest::{Method, RequestBuilder, StatusCode, Url};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::http::{
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_REQUEST_TIMEOUT, build_client,
    error_excerpt, read_bounded, transport_error,
};
use super::{ChainSource, ChainSourceError, Outspend, TransactionStatus};

#[derive(Clone)]
pub enum ElementsRpcAuth {
    None,
    Basic {
        username: String,
        password: String,
    },
    /// A Bitcoin-style cookie (`username:password`), re-read for every request
    /// so an elementsd restart can rotate it without restarting deadcat-node.
    CookieFile(PathBuf),
}

impl fmt::Debug for ElementsRpcAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => formatter.write_str("None"),
            Self::Basic { username, .. } => formatter
                .debug_struct("Basic")
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
            Self::CookieFile(path) => formatter.debug_tuple("CookieFile").field(path).finish(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ElementsRpcConfig {
    pub url: String,
    pub auth: ElementsRpcAuth,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
}

impl ElementsRpcConfig {
    #[must_use]
    pub fn new(url: impl Into<String>, auth: ElementsRpcAuth) -> Self {
        Self {
            url: url.into(),
            auth,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

pub struct ElementsRpcChainSource {
    client: reqwest::Client,
    url: Url,
    auth: ElementsRpcAuth,
    max_response_bytes: usize,
    next_id: AtomicU64,
}

impl fmt::Debug for ElementsRpcChainSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ElementsRpcChainSource")
            .field("url", &self.url)
            .field("auth", &self.auth)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

impl ElementsRpcChainSource {
    pub fn new(config: ElementsRpcConfig) -> Result<Self, ChainSourceError> {
        if config.max_response_bytes == 0 {
            return Err(ChainSourceError::InvalidData(
                "Elements RPC response limit must be non-zero".to_owned(),
            ));
        }
        let url = Url::parse(&config.url).map_err(|error| {
            ChainSourceError::InvalidData(format!("invalid Elements RPC URL: {error}"))
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ChainSourceError::InvalidData(
                "Elements RPC URL must use http or https".to_owned(),
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ChainSourceError::InvalidData(
                "put Elements RPC credentials in ElementsRpcAuth, not in the URL".to_owned(),
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(ChainSourceError::InvalidData(
                "Elements RPC URL cannot contain a query or fragment".to_owned(),
            ));
        }
        validate_auth(&config.auth)?;

        Ok(Self {
            client: build_client(config.connect_timeout, config.request_timeout)?,
            url,
            auth: config.auth,
            max_response_bytes: config.max_response_bytes,
            next_id: AtomicU64::new(1),
        })
    }

    fn authenticated(&self, request: RequestBuilder) -> Result<RequestBuilder, ChainSourceError> {
        match &self.auth {
            ElementsRpcAuth::None => Ok(request),
            ElementsRpcAuth::Basic { username, password } => {
                Ok(request.basic_auth(username, Some(password)))
            }
            ElementsRpcAuth::CookieFile(path) => {
                let cookie = std::fs::read_to_string(path).map_err(|error| {
                    ChainSourceError::Unavailable(format!(
                        "cannot read Elements RPC cookie {}: {error}",
                        path.display()
                    ))
                })?;
                let (username, password) = parse_cookie(&cookie)?;
                Ok(request.basic_auth(username, Some(password)))
            }
        }
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value, RpcCallError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let payload = json!({
            "jsonrpc": "1.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let request = self.authenticated(
            self.client
                .request(Method::POST, self.url.clone())
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .json(&payload),
        )?;
        let response = request
            .send()
            .await
            .map_err(|error| transport_error(&error))?;
        let (status, body) = read_bounded(response, self.max_response_bytes).await?;

        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
            return Err(ChainSourceError::Unavailable(format!(
                "Elements RPC authentication failed (HTTP {status})"
            ))
            .into());
        }
        if matches!(
            status,
            StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS
        ) || status.is_server_error() && !looks_like_json(&body)
        {
            return Err(ChainSourceError::Unavailable(format!(
                "Elements RPC HTTP {status}: {}",
                error_excerpt(&body)
            ))
            .into());
        }
        if !status.is_success() && !status.is_server_error() {
            return Err(ChainSourceError::InvalidData(format!(
                "Elements RPC HTTP {status}: {}",
                error_excerpt(&body)
            ))
            .into());
        }
        parse_rpc_envelope(&body, id, status)
    }

    async fn rpc_typed<T>(&self, method: &str, params: Value) -> Result<T, RpcCallError>
    where
        T: DeserializeOwned,
    {
        let value = self.rpc(method, params).await?;
        serde_json::from_value(value).map_err(|error| {
            ChainSourceError::InvalidData(format!("invalid {method} JSON-RPC result: {error}"))
                .into()
        })
    }

    async fn rpc_string(&self, method: &str, params: Value) -> Result<String, RpcCallError> {
        self.rpc_typed(method, params).await
    }

    async fn block_txids(&self, hash: BlockHash) -> Result<Vec<Txid>, ChainSourceError> {
        let response: BlockResponse = self
            .rpc_typed("getblock", json!([hash, 1]))
            .await
            .map_err(|error| map_lookup_error(error, format!("block {hash}")))?;
        if response.hash != hash {
            return Err(ChainSourceError::InvalidData(format!(
                "getblock returned {}, requested {hash}",
                response.hash
            )));
        }
        validate_block_txids(&response.tx)?;
        Ok(response.tx)
    }

    async fn status_from_block(
        &self,
        txid: Txid,
        hash: BlockHash,
    ) -> Result<TransactionStatus, ChainSourceError> {
        let header: BlockHeaderResponse = self
            .rpc_typed("getblockheader", json!([hash, true]))
            .await
            .map_err(|error| map_lookup_error(error, format!("block {hash}")))?;
        if header.hash != hash {
            return Err(ChainSourceError::InvalidData(format!(
                "getblockheader returned {}, requested {hash}",
                header.hash
            )));
        }
        if self.block_hash(header.height).await? != hash {
            return Err(ChainSourceError::BranchChanged);
        }
        let index = self
            .block_txids(hash)
            .await?
            .iter()
            .position(|candidate| *candidate == txid)
            .ok_or_else(|| {
                ChainSourceError::InvalidData(format!(
                    "transaction {txid} is absent from claimed block {hash}"
                ))
            })?;
        let tx_index = u32::try_from(index).map_err(|_| {
            ChainSourceError::InvalidData("block transaction index exceeds u32".to_owned())
        })?;
        Ok(TransactionStatus::Confirmed {
            anchor: ChainAnchor {
                height: header.height,
                hash,
            },
            tx_index,
        })
    }
}

#[async_trait]
impl ChainSource for ElementsRpcChainSource {
    async fn tip(&self) -> Result<ChainAnchor, ChainSourceError> {
        let info: BlockchainInfo = self
            .rpc_typed("getblockchaininfo", json!([]))
            .await
            .map_err(|error| map_general_error(error, "getblockchaininfo"))?;
        let canonical = self.block_hash(info.blocks).await?;
        if canonical != info.bestblockhash {
            return Err(ChainSourceError::BranchChanged);
        }
        Ok(ChainAnchor {
            height: info.blocks,
            hash: info.bestblockhash,
        })
    }

    async fn block_hash(&self, height: u32) -> Result<BlockHash, ChainSourceError> {
        self.rpc_typed("getblockhash", json!([height]))
            .await
            .map_err(|error| map_lookup_error(error, format!("block at height {height}")))
    }

    async fn block(&self, hash: BlockHash) -> Result<Block, ChainSourceError> {
        let raw = self
            .rpc_string("getblock", json!([hash, 0]))
            .await
            .map_err(|error| map_lookup_error(error, format!("block {hash}")))?;
        let bytes = decode_hex(&raw, "raw block")?;
        let block: Block = deserialize(&bytes).map_err(|error| {
            ChainSourceError::InvalidData(format!("invalid raw block {hash}: {error}"))
        })?;
        if block.block_hash() != hash {
            return Err(ChainSourceError::InvalidData(format!(
                "raw block hashes to {}, requested {hash}",
                block.block_hash()
            )));
        }
        Ok(block)
    }

    async fn transaction(&self, txid: Txid) -> Result<Transaction, ChainSourceError> {
        let raw = self
            .rpc_string("getrawtransaction", json!([txid, false]))
            .await
            .map_err(|error| map_lookup_error(error, format!("transaction {txid}")))?;
        let bytes = decode_hex(&raw, "raw transaction")?;
        let transaction: Transaction = deserialize(&bytes).map_err(|error| {
            ChainSourceError::InvalidData(format!("invalid raw transaction {txid}: {error}"))
        })?;
        if transaction.txid() != txid {
            return Err(ChainSourceError::InvalidData(format!(
                "raw transaction hashes to {}, requested {txid}",
                transaction.txid()
            )));
        }
        Ok(transaction)
    }

    async fn transaction_status(&self, txid: Txid) -> Result<TransactionStatus, ChainSourceError> {
        let response: RawTransactionResponse = self
            .rpc_typed("getrawtransaction", json!([txid, true]))
            .await
            .map_err(|error| map_lookup_error(error, format!("transaction {txid}")))?;
        if response.txid != txid {
            return Err(ChainSourceError::InvalidData(format!(
                "getrawtransaction returned {}, requested {txid}",
                response.txid
            )));
        }
        match response.blockhash {
            Some(hash) => {
                if response
                    .confirmations
                    .is_some_and(|confirmations| confirmations <= 0)
                {
                    return Err(ChainSourceError::InvalidData(
                        "transaction has a block hash but non-positive confirmations".to_owned(),
                    ));
                }
                self.status_from_block(txid, hash).await
            }
            None => {
                if response
                    .confirmations
                    .is_some_and(|confirmations| confirmations > 0)
                {
                    return Err(ChainSourceError::InvalidData(
                        "transaction has confirmations but no block hash".to_owned(),
                    ));
                }
                Ok(TransactionStatus::Unconfirmed)
            }
        }
    }

    async fn outspend(&self, outpoint: OutPoint) -> Result<Option<Outspend>, ChainSourceError> {
        let source = self.transaction(outpoint.txid).await?;
        let output_index = usize::try_from(outpoint.vout)
            .map_err(|_| ChainSourceError::NotFound(format!("output {outpoint:?}")))?;
        if output_index >= source.output.len() {
            return Err(ChainSourceError::NotFound(format!("output {outpoint:?}")));
        }

        let query = json!([[{"txid": outpoint.txid, "vout": outpoint.vout}]]);
        match self
            .rpc_typed::<Vec<SpendingPrevout>>("gettxspendingprevout", query)
            .await
        {
            Ok(response) => {
                if response.len() != 1 {
                    return Err(ChainSourceError::InvalidData(format!(
                        "gettxspendingprevout returned {} entries for one outpoint",
                        response.len()
                    )));
                }
                if response[0].txid != outpoint.txid || response[0].vout != outpoint.vout {
                    return Err(ChainSourceError::InvalidData(
                        "gettxspendingprevout returned a different outpoint".to_owned(),
                    ));
                }
                if let Some(spending_txid) = response[0].spendingtxid {
                    let spender = self.transaction(spending_txid).await?;
                    let input_index = spender
                        .input
                        .iter()
                        .position(|input| {
                            input.previous_output.txid == outpoint.txid
                                && input.previous_output.vout == outpoint.vout
                        })
                        .ok_or_else(|| {
                            ChainSourceError::InvalidData(format!(
                                "reported spender {spending_txid} does not spend {outpoint:?}"
                            ))
                        })?;
                    let input_index = u32::try_from(input_index).map_err(|_| {
                        ChainSourceError::InvalidData(
                            "transaction input index exceeds u32".to_owned(),
                        )
                    })?;
                    return Ok(Some(Outspend {
                        spending_txid,
                        input_index,
                        status: self.transaction_status(spending_txid).await?,
                    }));
                }
            }
            Err(RpcCallError::Rpc(error)) if error.code == -32601 => {}
            Err(error) => {
                return Err(map_general_error(error, "gettxspendingprevout"));
            }
        }

        let unspent = self
            .rpc("gettxout", json!([outpoint.txid, outpoint.vout, true]))
            .await
            .map_err(|error| map_general_error(error, "gettxout"))?;
        if !unspent.is_null() {
            if !unspent.is_object() {
                return Err(ChainSourceError::InvalidData(
                    "gettxout returned neither an object nor null".to_owned(),
                ));
            }
            return Ok(None);
        }

        Err(ChainSourceError::Unsupported(
            "Elements Core can detect a spent output but cannot identify its confirmed spender; use the node index or Esplora"
                .to_owned(),
        ))
    }

    async fn script_history(&self, _script: &Script) -> Result<Vec<Txid>, ChainSourceError> {
        Err(ChainSourceError::Unsupported(
            "Elements Core has no arbitrary script-history index; use the node index or Esplora"
                .to_owned(),
        ))
    }

    async fn issuance_transaction(
        &self,
        _asset_id: AssetId,
    ) -> Result<Option<Txid>, ChainSourceError> {
        Err(ChainSourceError::Unsupported(
            "Elements Core has no global asset-to-issuance index; use the node index or Esplora"
                .to_owned(),
        ))
    }

    async fn estimate_fee_rate(&self, target_blocks: u16) -> Result<f64, ChainSourceError> {
        if target_blocks == 0 {
            return Err(ChainSourceError::InvalidData(
                "fee target must be at least one block".to_owned(),
            ));
        }
        let response: FeeEstimate = self
            .rpc_typed("estimatesmartfee", json!([target_blocks]))
            .await
            .map_err(|error| map_general_error(error, "estimatesmartfee"))?;
        let btc_per_kvb = response.feerate.ok_or_else(|| {
            let detail = response
                .errors
                .unwrap_or_default()
                .into_iter()
                .take(4)
                .collect::<Vec<_>>()
                .join("; ");
            ChainSourceError::Unavailable(if detail.is_empty() {
                "Elements Core returned no fee estimate".to_owned()
            } else {
                format!("Elements Core returned no fee estimate: {detail}")
            })
        })?;
        let sat_per_vbyte = btc_per_kvb * 100_000.0;
        if !sat_per_vbyte.is_finite() || sat_per_vbyte <= 0.0 {
            return Err(ChainSourceError::InvalidData(
                "Elements Core fee estimate is not positive and finite".to_owned(),
            ));
        }
        Ok(sat_per_vbyte)
    }

    async fn broadcast(&self, transaction: &Transaction) -> Result<Txid, ChainSourceError> {
        let expected = transaction.txid();
        let raw = hex::encode(serialize(transaction));
        let reported: Txid = self
            .rpc_typed("sendrawtransaction", json!([raw]))
            .await
            .map_err(map_broadcast_error)?;
        if reported != expected {
            return Err(ChainSourceError::InvalidData(format!(
                "broadcast returned txid {reported}, expected {expected}"
            )));
        }
        Ok(reported)
    }
}

fn validate_auth(auth: &ElementsRpcAuth) -> Result<(), ChainSourceError> {
    match auth {
        ElementsRpcAuth::None | ElementsRpcAuth::CookieFile(_) => Ok(()),
        ElementsRpcAuth::Basic { username, password }
            if !username.is_empty() && !password.is_empty() =>
        {
            Ok(())
        }
        ElementsRpcAuth::Basic { .. } => Err(ChainSourceError::InvalidData(
            "Elements RPC username and password must be non-empty".to_owned(),
        )),
    }
}

fn parse_cookie(cookie: &str) -> Result<(&str, &str), ChainSourceError> {
    let cookie = cookie.trim_end_matches(['\r', '\n']);
    let (username, password) = cookie.split_once(':').ok_or_else(|| {
        ChainSourceError::InvalidData(
            "Elements RPC cookie must contain username:password".to_owned(),
        )
    })?;
    if username.is_empty() || password.is_empty() {
        return Err(ChainSourceError::InvalidData(
            "Elements RPC cookie username and password must be non-empty".to_owned(),
        ));
    }
    Ok((username, password))
}

fn decode_hex(text: &str, context: &str) -> Result<Vec<u8>, ChainSourceError> {
    if text.trim() != text {
        return Err(ChainSourceError::InvalidData(format!(
            "{context} hex contains surrounding whitespace"
        )));
    }
    hex::decode(text)
        .map_err(|error| ChainSourceError::InvalidData(format!("invalid {context} hex: {error}")))
}

fn validate_block_txids(txids: &[Txid]) -> Result<(), ChainSourceError> {
    if txids.is_empty() {
        return Err(ChainSourceError::InvalidData(
            "block transaction list is empty".to_owned(),
        ));
    }
    let mut unique = HashSet::with_capacity(txids.len());
    if txids.iter().any(|txid| !unique.insert(*txid)) {
        return Err(ChainSourceError::InvalidData(
            "block transaction list contains duplicates".to_owned(),
        ));
    }
    Ok(())
}

fn looks_like_json(body: &[u8]) -> bool {
    body.iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| matches!(byte, b'{' | b'['))
}

fn parse_rpc_envelope(
    body: &[u8],
    expected_id: u64,
    status: StatusCode,
) -> Result<Value, RpcCallError> {
    let envelope: Value = serde_json::from_slice(body).map_err(|error| {
        ChainSourceError::InvalidData(format!("invalid JSON-RPC response: {error}"))
    })?;
    let object = envelope.as_object().ok_or_else(|| {
        ChainSourceError::InvalidData("JSON-RPC response is not an object".to_owned())
    })?;
    let id = object.get("id").ok_or_else(|| {
        ChainSourceError::InvalidData("JSON-RPC response is missing id".to_owned())
    })?;
    if id.as_u64() != Some(expected_id) {
        return Err(ChainSourceError::InvalidData(format!(
            "JSON-RPC response id {id} does not match request {expected_id}"
        ))
        .into());
    }
    let error = object.get("error").ok_or_else(|| {
        ChainSourceError::InvalidData("JSON-RPC response is missing error field".to_owned())
    })?;
    let result = object.get("result").ok_or_else(|| {
        ChainSourceError::InvalidData("JSON-RPC response is missing result field".to_owned())
    })?;
    if !error.is_null() {
        let failure: RpcFailure = serde_json::from_value(error.clone()).map_err(|parse_error| {
            ChainSourceError::InvalidData(format!("invalid JSON-RPC error object: {parse_error}"))
        })?;
        if !result.is_null() {
            return Err(ChainSourceError::InvalidData(
                "JSON-RPC response contains both result and error".to_owned(),
            )
            .into());
        }
        return Err(RpcCallError::Rpc(failure));
    }
    if !status.is_success() {
        return Err(ChainSourceError::Unavailable(format!(
            "Elements RPC returned result with HTTP {status}"
        ))
        .into());
    }
    Ok(result.clone())
}

fn map_lookup_error(error: RpcCallError, resource: String) -> ChainSourceError {
    match error {
        RpcCallError::Source(error) => error,
        RpcCallError::Rpc(error) if matches!(error.code, -5 | -8) => {
            ChainSourceError::NotFound(resource)
        }
        RpcCallError::Rpc(error) if error.code == -32601 => {
            ChainSourceError::Unsupported(format!("JSON-RPC method unavailable: {}", error.message))
        }
        RpcCallError::Rpc(error) if error.code == -28 => {
            ChainSourceError::Unavailable(format!("Elements Core is warming up: {}", error.message))
        }
        RpcCallError::Rpc(error) => ChainSourceError::InvalidData(format!(
            "Elements RPC rejected lookup (code {}): {}",
            error.code, error.message
        )),
    }
}

fn map_general_error(error: RpcCallError, method: &str) -> ChainSourceError {
    match error {
        RpcCallError::Source(error) => error,
        RpcCallError::Rpc(error) if error.code == -32601 => {
            ChainSourceError::Unsupported(format!("{method} is unavailable: {}", error.message))
        }
        RpcCallError::Rpc(error) if error.code == -28 => {
            ChainSourceError::Unavailable(format!("Elements Core is warming up: {}", error.message))
        }
        RpcCallError::Rpc(error) => ChainSourceError::Unavailable(format!(
            "Elements RPC {method} failed (code {}): {}",
            error.code, error.message
        )),
    }
}

fn map_broadcast_error(error: RpcCallError) -> ChainSourceError {
    match error {
        RpcCallError::Source(error) => error,
        RpcCallError::Rpc(error) => ChainSourceError::BroadcastRejected(format!(
            "Elements RPC code {}: {}",
            error.code, error.message
        )),
    }
}

#[derive(Debug)]
enum RpcCallError {
    Source(ChainSourceError),
    Rpc(RpcFailure),
}

impl From<ChainSourceError> for RpcCallError {
    fn from(error: ChainSourceError) -> Self {
        Self::Source(error)
    }
}

#[derive(Debug, Deserialize)]
struct RpcFailure {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct BlockchainInfo {
    blocks: u32,
    bestblockhash: BlockHash,
}

#[derive(Deserialize)]
struct BlockHeaderResponse {
    hash: BlockHash,
    height: u32,
}

#[derive(Deserialize)]
struct BlockResponse {
    hash: BlockHash,
    tx: Vec<Txid>,
}

#[derive(Deserialize)]
struct RawTransactionResponse {
    txid: Txid,
    blockhash: Option<BlockHash>,
    confirmations: Option<i64>,
}

#[derive(Deserialize)]
struct SpendingPrevout {
    txid: Txid,
    vout: u32,
    spendingtxid: Option<Txid>,
}

#[derive(Deserialize)]
struct FeeEstimate {
    feerate: Option<f64>,
    errors: Option<Vec<String>>,
}

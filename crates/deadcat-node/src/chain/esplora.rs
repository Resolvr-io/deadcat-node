//! Liquid Esplora implementation of [`ChainSource`](super::ChainSource).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use deadcat_types::ChainAnchor;
use elements::encode::{deserialize, serialize};
use elements::hashes::{Hash, sha256};
use elements::{AssetId, Block, BlockHash, OutPoint, Script, Transaction, Txid};
use reqwest::{Method, RequestBuilder, StatusCode, Url};
use serde::Deserialize;

use super::http::{
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_REQUEST_TIMEOUT, build_client,
    error_excerpt, read_bounded, transport_error, utf8_text,
};
use super::{ChainSource, ChainSourceError, Outspend, TransactionStatus};

const ESPLORA_HISTORY_PAGE_SIZE: usize = 25;
const DEFAULT_MAX_HISTORY_PAGES: usize = 10_000;

#[async_trait]
pub trait EsploraTokenProvider: Send + Sync + 'static {
    /// Return a current bearer token. OAuth implementations may refresh and
    /// cache the token before returning it.
    async fn bearer_token(&self) -> Result<String, ChainSourceError>;
}

#[derive(Clone, Default)]
pub enum EsploraAuth {
    #[default]
    None,
    Bearer(String),
    TokenProvider(Arc<dyn EsploraTokenProvider>),
}

impl fmt::Debug for EsploraAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => formatter.write_str("None"),
            Self::Bearer(_) => formatter.write_str("Bearer(<redacted>)"),
            Self::TokenProvider(_) => formatter.write_str("TokenProvider(<dynamic>)"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct EsploraConfig {
    pub base_url: String,
    pub auth: EsploraAuth,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
    pub max_history_pages: usize,
}

impl EsploraConfig {
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            auth: EsploraAuth::None,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_history_pages: DEFAULT_MAX_HISTORY_PAGES,
        }
    }
}

#[derive(Clone)]
pub struct EsploraChainSource {
    client: reqwest::Client,
    base_url: Url,
    auth: EsploraAuth,
    max_response_bytes: usize,
    max_history_pages: usize,
}

impl fmt::Debug for EsploraChainSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EsploraChainSource")
            .field("base_url", &self.base_url)
            .field("auth", &self.auth)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_history_pages", &self.max_history_pages)
            .finish_non_exhaustive()
    }
}

impl EsploraChainSource {
    pub fn new(config: EsploraConfig) -> Result<Self, ChainSourceError> {
        if config.max_response_bytes == 0 {
            return Err(ChainSourceError::InvalidData(
                "Esplora response limit must be non-zero".to_owned(),
            ));
        }
        if config.max_history_pages == 0 {
            return Err(ChainSourceError::InvalidData(
                "Esplora history page limit must be non-zero".to_owned(),
            ));
        }
        if matches!(&config.auth, EsploraAuth::Bearer(token) if token.is_empty()) {
            return Err(ChainSourceError::InvalidData(
                "Esplora bearer token must be non-empty".to_owned(),
            ));
        }

        let mut base_url = Url::parse(&config.base_url).map_err(|error| {
            ChainSourceError::InvalidData(format!("invalid Esplora URL: {error}"))
        })?;
        if !matches!(base_url.scheme(), "http" | "https") {
            return Err(ChainSourceError::InvalidData(
                "Esplora URL must use http or https".to_owned(),
            ));
        }
        if !base_url.username().is_empty() || base_url.password().is_some() {
            return Err(ChainSourceError::InvalidData(
                "put Esplora credentials in EsploraAuth, not in the URL".to_owned(),
            ));
        }
        if base_url.query().is_some() || base_url.fragment().is_some() {
            return Err(ChainSourceError::InvalidData(
                "Esplora base URL cannot contain a query or fragment".to_owned(),
            ));
        }
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }

        Ok(Self {
            client: build_client(config.connect_timeout, config.request_timeout)?,
            base_url,
            auth: config.auth,
            max_response_bytes: config.max_response_bytes,
            max_history_pages: config.max_history_pages,
        })
    }

    fn url(&self, path: &str) -> Result<Url, ChainSourceError> {
        self.base_url
            .join(path.trim_start_matches('/'))
            .map_err(|error| {
                ChainSourceError::InvalidData(format!("cannot construct Esplora URL: {error}"))
            })
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
    ) -> Result<RequestBuilder, ChainSourceError> {
        let request = self.client.request(method, self.url(path)?);
        Ok(match &self.auth {
            EsploraAuth::None => request,
            EsploraAuth::Bearer(token) => request.bearer_auth(token),
            EsploraAuth::TokenProvider(provider) => {
                let token = provider.bearer_token().await?;
                if token.is_empty() {
                    return Err(ChainSourceError::InvalidData(
                        "Esplora token provider returned an empty token".to_owned(),
                    ));
                }
                request.bearer_auth(token)
            }
        })
    }

    async fn response(
        &self,
        request: RequestBuilder,
    ) -> Result<(StatusCode, Vec<u8>), ChainSourceError> {
        let response = request
            .send()
            .await
            .map_err(|error| transport_error(&error))?;
        read_bounded(response, self.max_response_bytes).await
    }

    async fn get(&self, path: &str) -> Result<Vec<u8>, ChainSourceError> {
        let (status, body) = self
            .response(self.request(Method::GET, path).await?)
            .await?;
        if status.is_success() {
            Ok(body)
        } else {
            Err(map_http_error(status, &body, path, false))
        }
    }

    async fn block_txids(&self, hash: BlockHash) -> Result<Vec<Txid>, ChainSourceError> {
        let body = self.get(&format!("block/{hash}/txids")).await?;
        let txids: Vec<Txid> = serde_json::from_slice(&body).map_err(|error| {
            ChainSourceError::InvalidData(format!("invalid block txid list: {error}"))
        })?;
        validate_block_txids(&txids)?;
        Ok(txids)
    }

    async fn canonical_status(
        &self,
        txid: Txid,
        status: &EsploraStatus,
    ) -> Result<TransactionStatus, ChainSourceError> {
        if !status.confirmed {
            if status.block_height.is_some() || status.block_hash.is_some() {
                return Err(ChainSourceError::InvalidData(
                    "unconfirmed transaction status contains a block anchor".to_owned(),
                ));
            }
            return Ok(TransactionStatus::Unconfirmed);
        }

        let height = status.block_height.ok_or_else(|| {
            ChainSourceError::InvalidData("confirmed status is missing block height".to_owned())
        })?;
        let hash = status.block_hash.ok_or_else(|| {
            ChainSourceError::InvalidData("confirmed status is missing block hash".to_owned())
        })?;
        if self.block_hash(height).await? != hash {
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
            anchor: ChainAnchor { height, hash },
            tx_index,
        })
    }

    async fn history_page(
        &self,
        script_hash: &str,
        after: Option<Txid>,
    ) -> Result<Vec<HistoryEntry>, ChainSourceError> {
        let path = match after {
            Some(txid) => format!("scripthash/{script_hash}/txs/chain/{txid}"),
            None => format!("scripthash/{script_hash}/txs"),
        };
        let body = self.get(&path).await?;
        serde_json::from_slice(&body).map_err(|error| {
            ChainSourceError::InvalidData(format!("invalid script history page: {error}"))
        })
    }
}

#[async_trait]
impl ChainSource for EsploraChainSource {
    async fn tip(&self) -> Result<ChainAnchor, ChainSourceError> {
        let hash_text = utf8_text(self.get("blocks/tip/hash").await?, "tip hash")?;
        let hash = parse_trimmed(&hash_text, "tip block hash")?;
        let body = self.get(&format!("block/{hash}")).await?;
        let metadata: BlockMetadata = serde_json::from_slice(&body).map_err(|error| {
            ChainSourceError::InvalidData(format!("invalid tip block metadata: {error}"))
        })?;
        if metadata.id != hash {
            return Err(ChainSourceError::InvalidData(format!(
                "tip metadata identifies {}, requested {hash}",
                metadata.id
            )));
        }
        Ok(ChainAnchor {
            height: metadata.height,
            hash,
        })
    }

    async fn block_hash(&self, height: u32) -> Result<BlockHash, ChainSourceError> {
        let text = utf8_text(
            self.get(&format!("block-height/{height}")).await?,
            "block hash",
        )?;
        parse_trimmed(&text, "block hash")
    }

    async fn block(&self, hash: BlockHash) -> Result<Block, ChainSourceError> {
        let raw = self.get(&format!("block/{hash}/raw")).await?;
        let block: Block = deserialize(&raw).map_err(|error| {
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
        let raw = self.get(&format!("tx/{txid}/raw")).await?;
        let transaction: Transaction = deserialize(&raw).map_err(|error| {
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
        let body = self.get(&format!("tx/{txid}/status")).await?;
        let status: EsploraStatus = serde_json::from_slice(&body).map_err(|error| {
            ChainSourceError::InvalidData(format!("invalid transaction status: {error}"))
        })?;
        self.canonical_status(txid, &status).await
    }

    async fn outspend(&self, outpoint: OutPoint) -> Result<Option<Outspend>, ChainSourceError> {
        let body = self
            .get(&format!("tx/{}/outspend/{}", outpoint.txid, outpoint.vout))
            .await?;
        let response: EsploraOutspend = serde_json::from_slice(&body).map_err(|error| {
            ChainSourceError::InvalidData(format!("invalid outspend response: {error}"))
        })?;
        if !response.spent {
            if response.txid.is_some() || response.vin.is_some() || response.status.is_some() {
                return Err(ChainSourceError::InvalidData(
                    "unspent outspend response contains spender data".to_owned(),
                ));
            }
            return Ok(None);
        }

        let spending_txid = response.txid.ok_or_else(|| {
            ChainSourceError::InvalidData("spent outpoint is missing spender txid".to_owned())
        })?;
        let input_index = response.vin.ok_or_else(|| {
            ChainSourceError::InvalidData("spent outpoint is missing input index".to_owned())
        })?;
        let embedded_status = response.status.ok_or_else(|| {
            ChainSourceError::InvalidData("spent outpoint is missing transaction status".to_owned())
        })?;
        let status = self
            .canonical_status(spending_txid, &embedded_status)
            .await?;
        Ok(Some(Outspend {
            spending_txid,
            input_index,
            status,
        }))
    }

    async fn script_history(&self, script: &Script) -> Result<Vec<Txid>, ChainSourceError> {
        let digest = sha256::Hash::hash(script.as_bytes()).to_byte_array();
        let script_hash = hex::encode(digest);

        let mut entries = Vec::new();
        let mut seen = HashSet::new();
        let mut after = None;
        for page_number in 0..self.max_history_pages {
            let page = self.history_page(&script_hash, after).await?;
            let confirmed = page
                .iter()
                .filter(|entry| entry.status.confirmed)
                .collect::<Vec<_>>();
            if page.iter().any(|entry| {
                !entry.status.confirmed
                    && (entry.status.block_height.is_some() || entry.status.block_hash.is_some())
            }) {
                return Err(ChainSourceError::InvalidData(
                    "unconfirmed history entry contains a block anchor".to_owned(),
                ));
            }
            for entry in &confirmed {
                if !seen.insert(entry.txid) {
                    return Err(ChainSourceError::InvalidData(format!(
                        "script history repeats transaction {}",
                        entry.txid
                    )));
                }
                let height = entry.status.block_height.ok_or_else(|| {
                    ChainSourceError::InvalidData(
                        "confirmed history entry is missing block height".to_owned(),
                    )
                })?;
                let hash = entry.status.block_hash.ok_or_else(|| {
                    ChainSourceError::InvalidData(
                        "confirmed history entry is missing block hash".to_owned(),
                    )
                })?;
                entries.push((entry.txid, height, hash));
            }

            if confirmed.len() < ESPLORA_HISTORY_PAGE_SIZE {
                break;
            }
            after = confirmed.last().map(|entry| entry.txid);
            if page_number + 1 == self.max_history_pages {
                return Err(ChainSourceError::InvalidData(format!(
                    "script history exceeds configured {} page limit",
                    self.max_history_pages
                )));
            }
        }

        let mut canonical_hashes = HashMap::new();
        let mut txids_by_block = HashMap::new();
        let mut positioned = Vec::with_capacity(entries.len());
        for (txid, height, hash) in entries {
            if let std::collections::hash_map::Entry::Vacant(entry) = canonical_hashes.entry(height)
            {
                let canonical = self.block_hash(height).await?;
                entry.insert(canonical);
            }
            if canonical_hashes.get(&height) != Some(&hash) {
                return Err(ChainSourceError::BranchChanged);
            }
            if let std::collections::hash_map::Entry::Vacant(entry) = txids_by_block.entry(hash) {
                let txids = self.block_txids(hash).await?;
                entry.insert(txids);
            }
            let block_txids = txids_by_block.get(&hash).ok_or_else(|| {
                ChainSourceError::InvalidData("block txid cache insertion failed".to_owned())
            })?;
            let index = block_txids
                .iter()
                .position(|candidate| *candidate == txid)
                .ok_or_else(|| {
                    ChainSourceError::InvalidData(format!(
                        "history transaction {txid} is absent from claimed block {hash}"
                    ))
                })?;
            let tx_index = u32::try_from(index).map_err(|_| {
                ChainSourceError::InvalidData("block transaction index exceeds u32".to_owned())
            })?;
            positioned.push((height, tx_index, txid));
        }
        positioned.sort_unstable();
        Ok(positioned.into_iter().map(|(_, _, txid)| txid).collect())
    }

    async fn issuance_transaction(
        &self,
        asset_id: AssetId,
    ) -> Result<Option<Txid>, ChainSourceError> {
        let path = format!("asset/{asset_id}");
        let (status, body) = self
            .response(self.request(Method::GET, &path).await?)
            .await?;
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(map_http_error(status, &body, &path, false));
        }
        let asset: AssetResponse = serde_json::from_slice(&body).map_err(|error| {
            ChainSourceError::InvalidData(format!("invalid asset response: {error}"))
        })?;
        if asset.asset_id.is_some_and(|reported| reported != asset_id) {
            return Err(ChainSourceError::InvalidData(format!(
                "asset response does not identify requested asset {asset_id}"
            )));
        }
        Ok(Some(asset.issuance_txin.txid))
    }

    async fn estimate_fee_rate(&self, target_blocks: u16) -> Result<f64, ChainSourceError> {
        if target_blocks == 0 {
            return Err(ChainSourceError::InvalidData(
                "fee target must be at least one block".to_owned(),
            ));
        }
        let body = self.get("fee-estimates").await?;
        let estimates: BTreeMap<String, f64> = serde_json::from_slice(&body).map_err(|error| {
            ChainSourceError::InvalidData(format!("invalid fee estimates: {error}"))
        })?;
        let parsed = estimates
            .into_iter()
            .map(|(target, rate)| {
                let target = target.parse::<u16>().map_err(|_| {
                    ChainSourceError::InvalidData(format!(
                        "fee estimate target is not a u16: {target}"
                    ))
                })?;
                if !rate.is_finite() || rate <= 0.0 {
                    return Err(ChainSourceError::InvalidData(format!(
                        "fee estimate for target {target} is not positive and finite"
                    )));
                }
                Ok((target, rate))
            })
            .collect::<Result<Vec<_>, ChainSourceError>>()?;
        parsed
            .iter()
            .filter(|(target, _)| *target <= target_blocks)
            .max_by_key(|(target, _)| *target)
            .or_else(|| parsed.iter().min_by_key(|(target, _)| *target))
            .map(|(_, rate)| *rate)
            .ok_or_else(|| {
                ChainSourceError::Unavailable("Esplora returned no fee estimates".to_owned())
            })
    }

    async fn broadcast(&self, transaction: &Transaction) -> Result<Txid, ChainSourceError> {
        let expected = transaction.txid();
        let request = self
            .request(Method::POST, "tx")
            .await?
            .header(reqwest::header::CONTENT_TYPE, "text/plain")
            .body(hex::encode(serialize(transaction)));
        let (status, body) = self.response(request).await?;
        if !status.is_success() {
            return Err(map_http_error(status, &body, "tx", true));
        }
        let text = utf8_text(body, "broadcast")?;
        let reported = parse_trimmed::<Txid>(&text, "broadcast txid")?;
        if reported != expected {
            return Err(ChainSourceError::InvalidData(format!(
                "broadcast returned txid {reported}, expected {expected}"
            )));
        }
        Ok(reported)
    }
}

fn parse_trimmed<T>(text: &str, context: &str) -> Result<T, ChainSourceError>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    text.trim()
        .parse()
        .map_err(|error| ChainSourceError::InvalidData(format!("invalid {context}: {error}")))
}

fn map_http_error(
    status: StatusCode,
    body: &[u8],
    resource: &str,
    broadcast: bool,
) -> ChainSourceError {
    let detail = error_excerpt(body);
    if broadcast {
        return ChainSourceError::BroadcastRejected(format!("HTTP {status}: {detail}"));
    }
    match status {
        StatusCode::NOT_FOUND => ChainSourceError::NotFound(resource.to_owned()),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            ChainSourceError::Unavailable(format!("Esplora authentication failed (HTTP {status})"))
        }
        StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS => {
            ChainSourceError::Unavailable(format!("Esplora HTTP {status}: {detail}"))
        }
        _ if status.is_server_error() => {
            ChainSourceError::Unavailable(format!("Esplora HTTP {status}: {detail}"))
        }
        _ => ChainSourceError::InvalidData(format!("Esplora HTTP {status}: {detail}")),
    }
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

#[derive(Deserialize)]
struct BlockMetadata {
    id: BlockHash,
    height: u32,
}

#[derive(Clone, Deserialize)]
struct EsploraStatus {
    confirmed: bool,
    block_height: Option<u32>,
    block_hash: Option<BlockHash>,
}

#[derive(Deserialize)]
struct EsploraOutspend {
    spent: bool,
    txid: Option<Txid>,
    vin: Option<u32>,
    status: Option<EsploraStatus>,
}

#[derive(Deserialize)]
struct HistoryEntry {
    txid: Txid,
    status: EsploraStatus,
}

#[derive(Deserialize)]
struct AssetResponse {
    asset_id: Option<AssetId>,
    issuance_txin: IssuanceTxin,
}

#[derive(Deserialize)]
struct IssuanceTxin {
    txid: Txid,
}

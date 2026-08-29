//! Authenticated, bounded reads from one pinned Deadcat node.

use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use deadcat_iroh::{Client, ClientError};
use deadcat_rpc::{
    MarketSnapshot, NodeInfo, Request, RequestEnvelope, RequestId, Response, RpcErrorCode,
    SCHEMA_VERSION,
};
use deadcat_types::ContractId;
use thiserror::Error;

/// Minimal authenticated node-read boundary needed by a production taker.
///
/// Implementations must bound transport work and response sizes. A returned
/// market snapshot is still untrusted until its anchor has been checked against
/// the taker's independent chain source and its contents have passed structural
/// validation. The first production profile still trusts its pinned node for
/// complete market-history semantics.
#[async_trait]
pub trait TakerNodeSource: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    async fn get_info(&self) -> Result<NodeInfo, Self::Error>;

    async fn market_snapshot(&self, market_id: ContractId) -> Result<MarketSnapshot, Self::Error>;
}

#[derive(Debug, Default)]
struct RequestIds {
    last_issued: AtomicU64,
}

impl RequestIds {
    fn next(&self) -> Result<RequestId, TakerNodeSourceError> {
        let previous = self
            .last_issued
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| TakerNodeSourceError::RequestIdExhausted)?;
        Ok(RequestId(
            previous
                .checked_add(1)
                .expect("fetch_update rejects request-id overflow"),
        ))
    }

    #[cfg(test)]
    fn with_last_issued(last_issued: u64) -> Self {
        Self {
            last_issued: AtomicU64::new(last_issued),
        }
    }
}

/// Cheap-clone reader over one already connected, pinned Iroh node.
///
/// [`Client`] authenticates the remote endpoint ID supplied when connecting,
/// enforces the Deadcat ALPN, bounds frames and concurrent inbound bytes, and
/// applies connection/request deadlines. Callers must construct that client
/// from the configured node `EndpointId`, rather than accepting an untrusted
/// discovered identity.
#[derive(Clone)]
pub struct IrohTakerNodeSource {
    client: Arc<Client>,
    request_ids: Arc<RequestIds>,
}

impl IrohTakerNodeSource {
    #[must_use]
    pub fn new(client: Client) -> Self {
        Self::from_shared(Arc::new(client))
    }

    #[must_use]
    pub fn from_shared(client: Arc<Client>) -> Self {
        Self {
            client,
            request_ids: Arc::new(RequestIds::default()),
        }
    }

    async fn call(&self, request: Request) -> Result<Response, TakerNodeSourceError> {
        let request_id = self.request_ids.next()?;
        let envelope = RequestEnvelope {
            schema_version: SCHEMA_VERSION,
            request_id,
            request,
        };
        self.client.call(envelope).await.map_err(map_client_error)
    }
}

impl fmt::Debug for IrohTakerNodeSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IrohTakerNodeSource")
            .field("client", &"[authenticated Iroh connection]")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl TakerNodeSource for IrohTakerNodeSource {
    type Error = TakerNodeSourceError;

    async fn get_info(&self) -> Result<NodeInfo, Self::Error> {
        info_response(self.call(Request::GetInfo).await?)
    }

    async fn market_snapshot(&self, market_id: ContractId) -> Result<MarketSnapshot, Self::Error> {
        market_snapshot_response(self.call(Request::GetMarketSnapshot { market_id }).await?)
    }
}

fn info_response(response: Response) -> Result<NodeInfo, TakerNodeSourceError> {
    match response {
        Response::Info { info } => Ok(info),
        _ => Err(TakerNodeSourceError::WrongResponseShape),
    }
}

fn market_snapshot_response(response: Response) -> Result<MarketSnapshot, TakerNodeSourceError> {
    match response {
        Response::MarketSnapshot { snapshot } => Ok(snapshot),
        _ => Err(TakerNodeSourceError::WrongResponseShape),
    }
}

fn map_client_error(error: ClientError) -> TakerNodeSourceError {
    match error {
        ClientError::Timeout => TakerNodeSourceError::Timeout,
        ClientError::Rpc(error) => TakerNodeSourceError::Remote { code: error.code },
        ClientError::Connect(_)
        | ClientError::Connection(_)
        | ClientError::Iroh(_)
        | ClientError::SubscriptionEnded(_) => TakerNodeSourceError::Unavailable,
        ClientError::InvalidConfig(_)
        | ClientError::Wire(_)
        | ClientError::SchemaMismatch { .. }
        | ClientError::RequestIdMismatch { .. }
        | ClientError::WrongResponseShape => TakerNodeSourceError::InvalidResponse,
    }
}

/// Stable, redacted failure surface for authenticated node reads.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum TakerNodeSourceError {
    #[error("taker node request-id space is exhausted")]
    RequestIdExhausted,
    #[error("taker node request timed out")]
    Timeout,
    #[error("taker node is unavailable")]
    Unavailable,
    #[error("taker node returned an invalid protocol response")]
    InvalidResponse,
    #[error("taker node returned the wrong response shape")]
    WrongResponseShape,
    #[error("taker node rejected the request with code {code:?}")]
    Remote { code: RpcErrorCode },
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::thread;

    use deadcat_rpc::FeeRateEstimate;

    use super::*;

    #[test]
    fn request_ids_are_shared_nonzero_and_unique_under_concurrency() {
        let ids = Arc::new(RequestIds::default());
        let workers = (0..8)
            .map(|_| {
                let ids = Arc::clone(&ids);
                thread::spawn(move || {
                    (0..64)
                        .map(|_| ids.next().expect("request id").0)
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        let issued = workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("request-id worker"))
            .collect::<BTreeSet<_>>();
        assert_eq!(issued.len(), 8 * 64);
        assert_eq!(issued.first(), Some(&1));
        assert_eq!(issued.last(), Some(&(8 * 64)));
    }

    #[test]
    fn request_id_allocator_issues_max_once_then_fails_closed() {
        let ids = RequestIds::with_last_issued(u64::MAX - 1);
        assert_eq!(ids.next().expect("last request id"), RequestId(u64::MAX));
        assert_eq!(ids.next(), Err(TakerNodeSourceError::RequestIdExhausted));
    }

    #[test]
    fn response_helpers_reject_every_unexpected_variant() {
        let wrong = || Response::Feerate {
            estimate: FeeRateEstimate {
                target_blocks: 2,
                sats_per_kvb: 100,
            },
        };
        assert_eq!(
            info_response(wrong()),
            Err(TakerNodeSourceError::WrongResponseShape)
        );
        assert_eq!(
            market_snapshot_response(wrong()),
            Err(TakerNodeSourceError::WrongResponseShape)
        );
    }

    #[test]
    fn remote_error_mapping_discards_the_backend_message() {
        let secret = "operator filesystem and backend details";
        let mapped = map_client_error(ClientError::Rpc(deadcat_rpc::RpcError::new(
            RpcErrorCode::BackendUnavailable,
            secret,
        )));
        assert_eq!(
            mapped,
            TakerNodeSourceError::Remote {
                code: RpcErrorCode::BackendUnavailable,
            }
        );
        assert!(!mapped.to_string().contains(secret));
    }
}

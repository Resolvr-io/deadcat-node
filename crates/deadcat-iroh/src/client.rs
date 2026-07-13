//! Native Iroh client for Deadcat RPC.

use std::sync::Arc;
use std::time::Duration;

use deadcat_rpc::{
    EventEnvelope, Request, RequestEnvelope, RequestId, Response, RpcError, RpcOutcome,
    SCHEMA_VERSION, ServerEnvelope, ServerFrame, SubscriptionEnd,
};
use deadcat_types::EventCursor;
use iroh::endpoint::{Connection, RecvStream, presets};
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::ALPN;
use crate::wire::{
    DEFAULT_INBOUND_BUDGET_BYTES, InboundBudget, MAX_FRAME_BYTES, WireError, read_message,
    write_message,
};

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub max_in_flight_requests: usize,
    pub inbound_budget_bytes: usize,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            max_in_flight_requests: 64,
            inbound_budget_bytes: DEFAULT_INBOUND_BUDGET_BYTES,
            connect_timeout: Duration::from_secs(20),
            request_timeout: Duration::from_secs(30),
        }
    }
}

impl ClientConfig {
    fn validate(&self) -> Result<(), ClientError> {
        if self.max_in_flight_requests == 0 {
            return Err(ClientError::InvalidConfig(
                "max_in_flight_requests must be nonzero",
            ));
        }
        if self.inbound_budget_bytes < MAX_FRAME_BYTES
            || self.inbound_budget_bytes > usize::try_from(u32::MAX).expect("u32 fits usize")
        {
            return Err(ClientError::InvalidConfig(
                "inbound_budget_bytes must fit at least one maximum frame and be <= u32::MAX",
            ));
        }
        if self.connect_timeout == Duration::ZERO || self.request_timeout == Duration::ZERO {
            return Err(ClientError::InvalidConfig("timeouts must be nonzero"));
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("invalid client configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("Iroh connect error: {0}")]
    Connect(#[from] iroh::endpoint::ConnectError),
    #[error("Iroh connection error: {0}")]
    Connection(#[from] iroh::endpoint::ConnectionError),
    #[error("wire error: {0}")]
    Wire(#[from] WireError),
    #[error("server returned RPC error: {0:?}")]
    Rpc(RpcError),
    #[error("request timed out")]
    Timeout,
    #[error("response schema {actual} does not match expected schema {expected}")]
    SchemaMismatch { expected: u32, actual: u32 },
    #[error("response request id {actual:?} does not match request id {expected:?}")]
    RequestIdMismatch {
        expected: RequestId,
        actual: RequestId,
    },
    #[error("wrong response shape for request")]
    WrongResponseShape,
    #[error("subscription ended: {0:?}")]
    SubscriptionEnded(SubscriptionEnd),
    #[error("Iroh endpoint error: {0}")]
    Iroh(String),
}

/// Connected native Iroh client.
pub struct Client {
    endpoint: Endpoint,
    connection: Connection,
    config: ClientConfig,
    inbound_budget: InboundBudget,
    in_flight: Arc<Semaphore>,
}

impl Client {
    pub async fn connect(
        target: impl Into<EndpointAddr>,
        config: ClientConfig,
    ) -> Result<Self, ClientError> {
        config.validate()?;
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(SecretKey::generate())
            .bind()
            .await
            .map_err(|error| ClientError::Iroh(error.to_string()))?;
        Self::connect_endpoint(endpoint, target.into(), config).await
    }

    pub async fn dial_direct(
        target: EndpointAddr,
        config: ClientConfig,
    ) -> Result<Self, ClientError> {
        Self::dial_direct_with_key(target, SecretKey::generate(), config).await
    }

    pub async fn dial_direct_with_key(
        target: EndpointAddr,
        secret_key: SecretKey,
        config: ClientConfig,
    ) -> Result<Self, ClientError> {
        config.validate()?;
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(secret_key)
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .map_err(|error| ClientError::Iroh(error.to_string()))?;
        Self::connect_endpoint(endpoint, target, config).await
    }

    async fn connect_endpoint(
        endpoint: Endpoint,
        target: EndpointAddr,
        config: ClientConfig,
    ) -> Result<Self, ClientError> {
        let connection =
            tokio::time::timeout(config.connect_timeout, endpoint.connect(target, ALPN))
                .await
                .map_err(|_| ClientError::Timeout)??;
        Ok(Self {
            endpoint,
            connection,
            inbound_budget: InboundBudget::new(config.inbound_budget_bytes),
            in_flight: Arc::new(Semaphore::new(config.max_in_flight_requests)),
            config,
        })
    }

    /// Execute a non-subscription request.
    pub async fn call(&self, envelope: RequestEnvelope) -> Result<Response, ClientError> {
        if matches!(envelope.request, Request::SubscribeEvents { .. }) {
            return Err(ClientError::WrongResponseShape);
        }
        envelope.validate_version().map_err(ClientError::Rpc)?;
        let permit = self.acquire_permit().await?;
        tokio::time::timeout(self.config.request_timeout, async {
            let _permit = permit;
            let (mut send, mut recv) = self.connection.open_bi().await?;
            write_message(&mut send, &envelope).await?;
            send.finish()
                .map_err(|error| ClientError::Iroh(error.to_string()))?;
            let response: ServerEnvelope = read_message(&mut recv, &self.inbound_budget).await?;
            validate_response(&response, envelope.request_id)?;
            match response.frame {
                ServerFrame::Unary { outcome } => outcome_value(outcome),
                _ => Err(ClientError::WrongResponseShape),
            }
        })
        .await
        .map_err(|_| ClientError::Timeout)?
    }

    #[must_use]
    pub fn endpoint_id(&self) -> iroh::EndpointId {
        self.endpoint.id()
    }

    /// Open a durable event subscription. The in-flight permit is held until
    /// the returned stream is dropped.
    pub async fn subscribe(&self, envelope: RequestEnvelope) -> Result<EventStream, ClientError> {
        if !matches!(envelope.request, Request::SubscribeEvents { .. }) {
            return Err(ClientError::WrongResponseShape);
        }
        envelope.validate_version().map_err(ClientError::Rpc)?;
        let permit = self.acquire_permit().await?;
        tokio::time::timeout(self.config.request_timeout, async {
            let (mut send, mut recv) = self.connection.open_bi().await?;
            write_message(&mut send, &envelope).await?;
            send.finish()
                .map_err(|error| ClientError::Iroh(error.to_string()))?;
            let response: ServerEnvelope = read_message(&mut recv, &self.inbound_budget).await?;
            validate_response(&response, envelope.request_id)?;
            match response.frame {
                ServerFrame::SubscriptionOpened { through } => Ok(EventStream {
                    recv,
                    request_id: envelope.request_id,
                    opened_through: through,
                    inbound_budget: self.inbound_budget.clone(),
                    _permit: permit,
                    ended: false,
                }),
                ServerFrame::Unary { outcome } => {
                    let _ = outcome_value(outcome)?;
                    Err(ClientError::WrongResponseShape)
                }
                _ => Err(ClientError::WrongResponseShape),
            }
        })
        .await
        .map_err(|_| ClientError::Timeout)?
    }

    async fn acquire_permit(&self) -> Result<OwnedSemaphorePermit, ClientError> {
        tokio::time::timeout(
            self.config.request_timeout,
            Arc::clone(&self.in_flight).acquire_owned(),
        )
        .await
        .map_err(|_| ClientError::Timeout)?
        .map_err(|_| ClientError::Iroh("client request semaphore closed".into()))
    }

    pub async fn close(self) {
        self.connection.close(0_u32.into(), b"client closed");
        self.endpoint.close().await;
    }
}

fn outcome_value(outcome: RpcOutcome<Response>) -> Result<Response, ClientError> {
    match outcome {
        RpcOutcome::Success { value } => Ok(value),
        RpcOutcome::Error { error } => Err(ClientError::Rpc(error)),
    }
}

fn validate_response(response: &ServerEnvelope, request_id: RequestId) -> Result<(), ClientError> {
    if response.schema_version != SCHEMA_VERSION {
        return Err(ClientError::SchemaMismatch {
            expected: SCHEMA_VERSION,
            actual: response.schema_version,
        });
    }
    if response.request_id != request_id {
        return Err(ClientError::RequestIdMismatch {
            expected: request_id,
            actual: response.request_id,
        });
    }
    Ok(())
}

/// Pull-based durable event stream.
pub struct EventStream {
    recv: RecvStream,
    request_id: RequestId,
    opened_through: EventCursor,
    inbound_budget: InboundBudget,
    _permit: OwnedSemaphorePermit,
    ended: bool,
}

impl EventStream {
    #[must_use]
    pub const fn opened_through(&self) -> EventCursor {
        self.opened_through
    }

    pub async fn next(&mut self) -> Result<Option<EventEnvelope>, ClientError> {
        if self.ended {
            return Ok(None);
        }
        let response: ServerEnvelope = read_message(&mut self.recv, &self.inbound_budget).await?;
        validate_response(&response, self.request_id)?;
        match response.frame {
            ServerFrame::SubscriptionEvent { event } => Ok(Some(event)),
            ServerFrame::SubscriptionEnded {
                reason: SubscriptionEnd::ServerShutdown,
            } => {
                self.ended = true;
                Ok(None)
            }
            ServerFrame::SubscriptionEnded { reason } => {
                self.ended = true;
                Err(ClientError::SubscriptionEnded(reason))
            }
            _ => Err(ClientError::WrongResponseShape),
        }
    }
}

//! Bounded native Iroh server for Deadcat RPC.

use std::sync::Arc;
use std::time::Duration;

use deadcat_rpc::{
    Request, RequestEnvelope, Response, RpcError, RpcErrorCode, RpcOutcome, SCHEMA_VERSION,
    ServerEnvelope, ServerFrame, SubscriptionEnd,
};
use iroh::endpoint::{Connection, RecvStream, SendStream, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};

use crate::ALPN;
use crate::handler::{ClientId, RequestHandler, Subscription, SubscriptionItem};
use crate::wire::{self, DEFAULT_INBOUND_BUDGET_BYTES, InboundBudget, MAX_FRAME_BYTES, WireError};

/// Server-side resource and timeout policy.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub max_connections: usize,
    pub max_streams_per_connection: usize,
    pub max_in_flight_requests: usize,
    pub inbound_budget_bytes: usize,
    pub handshake_timeout: Duration,
    pub request_read_timeout: Duration,
    pub handler_timeout: Duration,
    pub response_write_timeout: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_connections: 256,
            max_streams_per_connection: 64,
            max_in_flight_requests: 512,
            inbound_budget_bytes: DEFAULT_INBOUND_BUDGET_BYTES,
            handshake_timeout: Duration::from_secs(15),
            request_read_timeout: Duration::from_secs(30),
            handler_timeout: Duration::from_secs(30),
            response_write_timeout: Duration::from_secs(30),
        }
    }
}

impl ServerConfig {
    fn validate(&self) -> Result<(), ServerError> {
        if self.max_connections == 0 {
            return Err(ServerError::InvalidConfig(
                "max_connections must be nonzero",
            ));
        }
        if self.max_streams_per_connection == 0 {
            return Err(ServerError::InvalidConfig(
                "max_streams_per_connection must be nonzero",
            ));
        }
        if self.max_in_flight_requests == 0 {
            return Err(ServerError::InvalidConfig(
                "max_in_flight_requests must be nonzero",
            ));
        }
        if self.inbound_budget_bytes < MAX_FRAME_BYTES
            || self.inbound_budget_bytes > usize::try_from(u32::MAX).expect("u32 fits usize")
        {
            return Err(ServerError::InvalidConfig(
                "inbound_budget_bytes must fit at least one maximum frame and be <= u32::MAX",
            ));
        }
        if self.max_streams_per_connection > u32::MAX as usize {
            return Err(ServerError::InvalidConfig(
                "max_streams_per_connection must fit u32",
            ));
        }
        if [
            self.handshake_timeout,
            self.request_read_timeout,
            self.handler_timeout,
            self.response_write_timeout,
        ]
        .contains(&Duration::ZERO)
        {
            return Err(ServerError::InvalidConfig("timeouts must be nonzero"));
        }
        Ok(())
    }
}

/// Iroh discovery and relay policy for the server endpoint.
#[derive(Clone, Copy, Debug)]
pub enum DiscoveryMode {
    N0Defaults,
    Disabled,
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("invalid server configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("failed to bind Iroh endpoint: {0}")]
    Bind(String),
    #[error("server task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
}

/// Bound Iroh endpoint paired with a request handler.
pub struct Server<H: RequestHandler> {
    endpoint: Endpoint,
    handler: Arc<H>,
    config: ServerConfig,
    inbound_budget: InboundBudget,
    global_requests: Arc<Semaphore>,
}

impl<H: RequestHandler> Server<H> {
    pub async fn bind(
        secret_key: SecretKey,
        discovery: DiscoveryMode,
        config: ServerConfig,
        handler: Arc<H>,
    ) -> Result<Self, ServerError> {
        config.validate()?;
        let mut builder = Endpoint::builder(presets::N0)
            .secret_key(secret_key)
            .alpns(vec![ALPN.to_vec()]);
        if matches!(discovery, DiscoveryMode::Disabled) {
            builder = builder.relay_mode(RelayMode::Disabled);
        }
        let endpoint = builder
            .bind()
            .await
            .map_err(|error| ServerError::Bind(error.to_string()))?;
        Ok(Self {
            endpoint,
            handler,
            inbound_budget: InboundBudget::new(config.inbound_budget_bytes),
            global_requests: Arc::new(Semaphore::new(config.max_in_flight_requests)),
            config,
        })
    }

    #[must_use]
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    #[must_use]
    pub fn endpoint_addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// Run until the endpoint closes, reaping completed tasks while accepting.
    pub async fn run(self) {
        let Self {
            endpoint,
            handler,
            config,
            inbound_budget,
            global_requests,
        } = self;
        let connection_limit = Arc::new(Semaphore::new(config.max_connections));
        let mut connections = JoinSet::new();

        loop {
            tokio::select! {
                joined = connections.join_next(), if !connections.is_empty() => {
                    log_task_result(joined, "Iroh connection task");
                }
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        break;
                    };
                    let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            tracing::warn!(max = config.max_connections, "Iroh connection cap reached");
                            incoming.refuse();
                            continue;
                        }
                    };
                    let handler = Arc::clone(&handler);
                    let config = config.clone();
                    let inbound_budget = inbound_budget.clone();
                    let global_requests = Arc::clone(&global_requests);
                    connections.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = handle_connection(
                            incoming,
                            handler,
                            config,
                            inbound_budget,
                            global_requests,
                        )
                        .await
                        {
                            tracing::debug!(%error, "Iroh connection ended with an error");
                        }
                    });
                }
            }
        }

        while let Some(joined) = connections.join_next().await {
            log_task_result(Some(joined), "Iroh connection task during shutdown");
        }
    }

    #[must_use]
    pub fn spawn(self) -> SpawnedServer {
        let endpoint = self.endpoint.clone();
        let task = tokio::spawn(self.run());
        SpawnedServer { endpoint, task }
    }
}

/// Handle for a background server task.
pub struct SpawnedServer {
    endpoint: Endpoint,
    task: JoinHandle<()>,
}

impl SpawnedServer {
    /// Close all connections and wait until connection and stream tasks drain.
    pub async fn shutdown_and_join(self) -> Result<(), ServerError> {
        self.endpoint.close().await;
        self.task.await?;
        Ok(())
    }
}

fn log_task_result(result: Option<Result<(), tokio::task::JoinError>>, label: &'static str) {
    if let Some(Err(error)) = result
        && !error.is_cancelled()
    {
        tracing::warn!(%error, task = label, "transport task panicked");
    }
}

async fn handle_connection<H: RequestHandler>(
    incoming: iroh::endpoint::Incoming,
    handler: Arc<H>,
    config: ServerConfig,
    inbound_budget: InboundBudget,
    global_requests: Arc<Semaphore>,
) -> Result<(), StreamError> {
    let mut accepting = incoming
        .accept()
        .map_err(|error| StreamError::Transport(error.to_string()))?;
    let alpn = tokio::time::timeout(config.handshake_timeout, accepting.alpn())
        .await
        .map_err(|_| StreamError::Timeout("ALPN handshake"))?
        .map_err(|error| StreamError::Transport(error.to_string()))?;
    if alpn != ALPN {
        return Err(StreamError::Transport("unexpected ALPN".into()));
    }
    let connection = tokio::time::timeout(config.handshake_timeout, accepting)
        .await
        .map_err(|_| StreamError::Timeout("connection handshake"))?
        .map_err(|error| StreamError::Transport(error.to_string()))?;
    connection.set_max_concurrent_uni_streams(0_u32.into());
    connection.set_max_concurrent_bi_streams(
        u32::try_from(config.max_streams_per_connection)
            .expect("validated above")
            .into(),
    );
    let peer = *connection.remote_id().as_bytes();
    let mut streams = JoinSet::new();

    loop {
        if streams.len() >= config.max_streams_per_connection {
            log_task_result(streams.join_next().await, "Iroh stream task");
            continue;
        }

        tokio::select! {
            joined = streams.join_next(), if !streams.is_empty() => {
                log_task_result(joined, "Iroh stream task");
            }
            _ = connection.closed() => break,
            accepted = connection.accept_bi() => {
                let (send, recv) = match accepted {
                    Ok(streams) => streams,
                    Err(_) => break,
                };
                let permit = match Arc::clone(&global_requests).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::warn!("global Iroh request cap reached; refusing stream");
                        drop(send);
                        drop(recv);
                        continue;
                    }
                };
                let handler = Arc::clone(&handler);
                let connection = connection.clone();
                let config = config.clone();
                let inbound_budget = inbound_budget.clone();
                streams.spawn(async move {
                    if let Err(error) = handle_stream(
                        send,
                        recv,
                        handler,
                        connection,
                        peer,
                        config,
                        inbound_budget,
                        permit,
                    )
                    .await
                    {
                        tracing::debug!(%error, "Iroh stream ended with an error");
                    }
                });
            }
        }
    }

    while let Some(joined) = streams.join_next().await {
        log_task_result(Some(joined), "Iroh stream task during connection shutdown");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_stream<H: RequestHandler>(
    mut send: SendStream,
    mut recv: RecvStream,
    handler: Arc<H>,
    connection: Connection,
    peer: ClientId,
    config: ServerConfig,
    inbound_budget: InboundBudget,
    _permit: OwnedSemaphorePermit,
) -> Result<(), StreamError> {
    let envelope: RequestEnvelope = tokio::time::timeout(
        config.request_read_timeout,
        wire::read_message(&mut recv, &inbound_budget),
    )
    .await
    .map_err(|_| StreamError::Timeout("request read"))??;

    if let Err(error) = handler.validate(peer, &envelope) {
        write_rpc_error(&mut send, envelope.request_id, error, &config).await?;
        finish(send)?;
        return Ok(());
    }

    let request_id = envelope.request_id;
    if matches!(envelope.request, Request::SubscribeEvents { .. }) {
        let subscription = match tokio::time::timeout(
            config.handler_timeout,
            handler.subscribe(peer, envelope.request),
        )
        .await
        {
            Ok(Ok(subscription)) => subscription,
            Ok(Err(error)) => {
                write_rpc_error(&mut send, request_id, error, &config).await?;
                finish(send)?;
                return Ok(());
            }
            Err(_) => {
                write_rpc_error(&mut send, request_id, timeout_rpc_error(), &config).await?;
                finish(send)?;
                return Ok(());
            }
        };
        run_subscription(&mut send, request_id, subscription, &connection, &config).await?;
    } else {
        let outcome = match tokio::time::timeout(
            config.handler_timeout,
            handler.handle(peer, envelope.request),
        )
        .await
        {
            Ok(Ok(value)) => RpcOutcome::Success { value },
            Ok(Err(error)) => RpcOutcome::Error { error },
            Err(_) => RpcOutcome::Error {
                error: timeout_rpc_error(),
            },
        };
        let response = ServerEnvelope {
            schema_version: SCHEMA_VERSION,
            request_id,
            frame: ServerFrame::Unary { outcome },
        };
        write_envelope(&mut send, &response, &config).await?;
    }

    finish(send)?;
    Ok(())
}

async fn run_subscription(
    send: &mut SendStream,
    request_id: deadcat_rpc::RequestId,
    mut subscription: Subscription,
    connection: &Connection,
    config: &ServerConfig,
) -> Result<(), StreamError> {
    write_envelope(
        send,
        &ServerEnvelope {
            schema_version: SCHEMA_VERSION,
            request_id,
            frame: ServerFrame::SubscriptionOpened {
                through: subscription.through,
            },
        },
        config,
    )
    .await?;

    loop {
        tokio::select! {
            _ = connection.closed() => return Ok(()),
            next = subscription.events.recv() => {
                let (frame, ended) = match next {
                    Some(SubscriptionItem::Event(event)) => {
                        (ServerFrame::SubscriptionEvent { event }, false)
                    }
                    Some(SubscriptionItem::End(reason)) => {
                        (ServerFrame::SubscriptionEnded { reason }, true)
                    }
                    None => (
                        ServerFrame::SubscriptionEnded {
                            reason: SubscriptionEnd::ServerShutdown,
                        },
                        true,
                    ),
                };
                write_envelope(
                    send,
                    &ServerEnvelope {
                        schema_version: SCHEMA_VERSION,
                        request_id,
                        frame,
                    },
                    config,
                )
                .await?;
                if ended {
                    return Ok(());
                }
            }
        }
    }
}

async fn write_rpc_error(
    send: &mut SendStream,
    request_id: deadcat_rpc::RequestId,
    error: RpcError,
    config: &ServerConfig,
) -> Result<(), StreamError> {
    write_envelope(
        send,
        &ServerEnvelope {
            schema_version: SCHEMA_VERSION,
            request_id,
            frame: ServerFrame::Unary {
                outcome: RpcOutcome::<Response>::Error { error },
            },
        },
        config,
    )
    .await
}

async fn write_envelope(
    send: &mut SendStream,
    response: &ServerEnvelope,
    config: &ServerConfig,
) -> Result<(), StreamError> {
    tokio::time::timeout(
        config.response_write_timeout,
        wire::write_message(send, response),
    )
    .await
    .map_err(|_| StreamError::Timeout("response write"))??;
    Ok(())
}

fn timeout_rpc_error() -> RpcError {
    RpcError::new(
        RpcErrorCode::BackendUnavailable,
        "request handler timed out",
    )
}

fn finish(mut send: SendStream) -> Result<(), StreamError> {
    send.finish()
        .map_err(|error| StreamError::Transport(error.to_string()))
}

#[derive(Debug, thiserror::Error)]
enum StreamError {
    #[error("wire error: {0}")]
    Wire(#[from] WireError),
    #[error("{0} timed out")]
    Timeout(&'static str),
    #[error("transport error: {0}")]
    Transport(String),
}

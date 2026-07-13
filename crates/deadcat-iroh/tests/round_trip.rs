use std::sync::{Arc, Mutex};
use std::time::Duration;

use deadcat_iroh::{
    Client, ClientConfig, ClientError, DiscoveryMode, RequestHandler, Server, ServerConfig,
    Subscription, SubscriptionItem,
};
use deadcat_rpc::{
    Event, EventEnvelope, EventFilter, Request, RequestEnvelope, RequestId, Response, RpcError,
    RpcErrorCode, SCHEMA_VERSION, SyncStatus,
};
use deadcat_types::EventCursor;
use iroh::SecretKey;
use tokio::sync::mpsc;

fn request(request_id: u64, request: Request) -> RequestEnvelope {
    RequestEnvelope {
        schema_version: SCHEMA_VERSION,
        request_id: RequestId(request_id),
        request,
    }
}

fn cursor(sequence: u64) -> EventCursor {
    EventCursor {
        epoch: [0x42; 16],
        sequence,
    }
}

struct StubHandler {
    seen_peer: Arc<Mutex<Option<[u8; 32]>>>,
}

impl RequestHandler for StubHandler {
    async fn handle(&self, peer: [u8; 32], _request: Request) -> Result<Response, RpcError> {
        *self.seen_peer.lock().expect("peer mutex") = Some(peer);
        Ok(Response::Contract { contract: None })
    }

    async fn subscribe(&self, _peer: [u8; 32], request: Request) -> Result<Subscription, RpcError> {
        if !matches!(request, Request::SubscribeEvents { .. }) {
            return Err(RpcError::new(
                RpcErrorCode::InvalidTransaction,
                "expected subscription request",
            ));
        }
        let (send, recv) = mpsc::channel(2);
        tokio::spawn(async move {
            send.send(SubscriptionItem::Event(EventEnvelope {
                cursor: cursor(8),
                event: Event::SyncStatusChanged {
                    status: SyncStatus::Ready,
                },
            }))
            .await
            .expect("test subscriber remains alive");
        });
        Ok(Subscription {
            through: cursor(7),
            events: recv,
        })
    }
}

async fn fixture(
    handler: Arc<StubHandler>,
    server_config: ServerConfig,
) -> (deadcat_iroh::SpawnedServer, Client) {
    let server = Server::bind(
        SecretKey::generate(),
        DiscoveryMode::Disabled,
        server_config,
        handler,
    )
    .await
    .expect("server bind");
    let address = server.endpoint_addr();
    let spawned = server.spawn();
    tokio::task::yield_now().await;
    let client = Client::dial_direct(address, ClientConfig::default())
        .await
        .expect("client dial");
    (spawned, client)
}

#[tokio::test(flavor = "multi_thread")]
async fn unary_round_trip_preserves_authenticated_peer() {
    let seen_peer = Arc::new(Mutex::new(None));
    let handler = Arc::new(StubHandler {
        seen_peer: Arc::clone(&seen_peer),
    });
    let (server, client) = fixture(handler, ServerConfig::default()).await;
    let expected_peer = *client.endpoint_id().as_bytes();

    let response = client
        .call(request(11, Request::GetInfo))
        .await
        .expect("unary response");
    assert_eq!(response, Response::Contract { contract: None });
    assert_eq!(*seen_peer.lock().expect("peer mutex"), Some(expected_peer));

    client.close().await;
    server.shutdown_and_join().await.expect("server shutdown");
}

#[tokio::test(flavor = "multi_thread")]
async fn subscription_opens_streams_and_ends_explicitly() {
    let handler = Arc::new(StubHandler {
        seen_peer: Arc::new(Mutex::new(None)),
    });
    let (server, client) = fixture(handler, ServerConfig::default()).await;
    let mut stream = client
        .subscribe(request(
            12,
            Request::SubscribeEvents {
                after: Some(cursor(6)),
                filter: EventFilter::All,
            },
        ))
        .await
        .expect("subscription open");
    assert_eq!(stream.opened_through(), cursor(7));

    let event = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("event timeout")
        .expect("event result")
        .expect("one event");
    assert_eq!(event.cursor, cursor(8));
    assert!(matches!(
        event.event,
        Event::SyncStatusChanged {
            status: SyncStatus::Ready
        }
    ));
    assert!(
        tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("end timeout")
            .expect("end result")
            .is_none()
    );

    drop(stream);
    client.close().await;
    server.shutdown_and_join().await.expect("server shutdown");
}

struct RejectingValidator;

impl RequestHandler for RejectingValidator {
    fn validate(&self, _peer: [u8; 32], _envelope: &RequestEnvelope) -> Result<(), RpcError> {
        Err(RpcError::new(
            RpcErrorCode::Unauthorized,
            "rejected by hook",
        ))
    }

    async fn handle(&self, _peer: [u8; 32], _request: Request) -> Result<Response, RpcError> {
        panic!("validation should run before dispatch")
    }

    async fn subscribe(
        &self,
        _peer: [u8; 32],
        _request: Request,
    ) -> Result<Subscription, RpcError> {
        panic!("validation should run before dispatch")
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn validation_hook_returns_typed_rpc_error_before_dispatch() {
    let server = Server::bind(
        SecretKey::generate(),
        DiscoveryMode::Disabled,
        ServerConfig::default(),
        Arc::new(RejectingValidator),
    )
    .await
    .expect("server bind");
    let address = server.endpoint_addr();
    let server = server.spawn();
    let client = Client::dial_direct(address, ClientConfig::default())
        .await
        .expect("client dial");

    let error = client
        .call(request(13, Request::GetInfo))
        .await
        .expect_err("validation failure");
    assert!(matches!(
        error,
        ClientError::Rpc(RpcError {
            code: RpcErrorCode::Unauthorized,
            ..
        })
    ));

    client.close().await;
    server.shutdown_and_join().await.expect("server shutdown");
}

struct SlowHandler;

impl RequestHandler for SlowHandler {
    async fn handle(&self, _peer: [u8; 32], _request: Request) -> Result<Response, RpcError> {
        tokio::time::sleep(Duration::from_secs(1)).await;
        Ok(Response::Contract { contract: None })
    }

    async fn subscribe(
        &self,
        _peer: [u8; 32],
        _request: Request,
    ) -> Result<Subscription, RpcError> {
        unreachable!()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn server_handler_timeout_is_returned_as_typed_error() {
    let config = ServerConfig {
        handler_timeout: Duration::from_millis(20),
        ..ServerConfig::default()
    };
    let server = Server::bind(
        SecretKey::generate(),
        DiscoveryMode::Disabled,
        config,
        Arc::new(SlowHandler),
    )
    .await
    .expect("server bind");
    let address = server.endpoint_addr();
    let server = server.spawn();
    let client = Client::dial_direct(address, ClientConfig::default())
        .await
        .expect("client dial");

    let error = client
        .call(request(14, Request::GetInfo))
        .await
        .expect_err("handler timeout");
    assert!(matches!(
        error,
        ClientError::Rpc(RpcError {
            code: RpcErrorCode::BackendUnavailable,
            ..
        })
    ));

    client.close().await;
    server.shutdown_and_join().await.expect("server shutdown");
}

struct IdleSubscriptionHandler {
    keepalive: Mutex<Option<mpsc::Sender<SubscriptionItem>>>,
}

impl RequestHandler for IdleSubscriptionHandler {
    async fn handle(&self, _peer: [u8; 32], _request: Request) -> Result<Response, RpcError> {
        Ok(Response::Contract { contract: None })
    }

    async fn subscribe(
        &self,
        _peer: [u8; 32],
        _request: Request,
    ) -> Result<Subscription, RpcError> {
        let (send, recv) = mpsc::channel(1);
        *self.keepalive.lock().expect("keepalive mutex") = Some(send);
        Ok(Subscription {
            through: cursor(0),
            events: recv,
        })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn graceful_shutdown_reaps_idle_subscription_tasks() {
    let server = Server::bind(
        SecretKey::generate(),
        DiscoveryMode::Disabled,
        ServerConfig::default(),
        Arc::new(IdleSubscriptionHandler {
            keepalive: Mutex::new(None),
        }),
    )
    .await
    .expect("server bind");
    let address = server.endpoint_addr();
    let server = server.spawn();
    let client = Client::dial_direct(address, ClientConfig::default())
        .await
        .expect("client dial");
    let _stream = client
        .subscribe(request(
            15,
            Request::SubscribeEvents {
                after: None,
                filter: EventFilter::All,
            },
        ))
        .await
        .expect("subscription open");

    tokio::time::timeout(Duration::from_secs(5), server.shutdown_and_join())
        .await
        .expect("shutdown timeout")
        .expect("server shutdown");
}

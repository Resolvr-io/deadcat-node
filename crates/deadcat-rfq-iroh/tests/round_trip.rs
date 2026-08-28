use std::sync::{Arc, Mutex};
use std::time::Duration;

use deadcat_rfq_iroh::{
    Client, ClientConfig, ClientError, DiscoveryMode, RequestHandler, Server, ServerConfig,
};
use deadcat_rfq_rpc::{
    FixedBytes32, ProviderCapability, ProviderInfo, Request, RequestEnvelope, RequestId, Response,
    RpcError, RpcErrorCode,
};
use deadcat_types::LiquidNetwork;
use iroh::SecretKey;

fn request(request_id: u64) -> RequestEnvelope {
    RequestEnvelope::new(RequestId(request_id), Request::GetInfo)
}

fn info_response(provider_endpoint: [u8; 32]) -> Response {
    Response::Info {
        info: ProviderInfo {
            provider_endpoint: FixedBytes32::new(provider_endpoint),
            network: LiquidNetwork::ElementsRegtest,
            genesis_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .expect("test block hash"),
            policy_asset: "0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .expect("test asset id"),
            capabilities: vec![ProviderCapability::FirmQuotes],
        },
    }
}

struct RecordingHandler {
    seen_peers: Arc<Mutex<Vec<[u8; 32]>>>,
    provider_endpoint: [u8; 32],
}

impl RequestHandler for RecordingHandler {
    async fn handle(&self, peer: [u8; 32], request: Request) -> Result<Response, RpcError> {
        assert_eq!(request, Request::GetInfo);
        self.seen_peers.lock().expect("peer mutex").push(peer);
        Ok(info_response(self.provider_endpoint))
    }
}

async fn bind_recording_server(
    seen_peers: Arc<Mutex<Vec<[u8; 32]>>>,
) -> (
    deadcat_rfq_iroh::SpawnedServer,
    deadcat_rfq_iroh::EndpointAddr,
    deadcat_rfq_iroh::EndpointId,
) {
    let server_key = SecretKey::generate();
    let provider_endpoint = *server_key.public().as_bytes();
    let server = Server::bind(
        server_key,
        DiscoveryMode::Disabled,
        ServerConfig::default(),
        Arc::new(RecordingHandler {
            seen_peers,
            provider_endpoint,
        }),
    )
    .await
    .expect("server bind");
    let address = server.endpoint_addr();
    let endpoint_id = server.endpoint_id();
    (server.spawn(), address, endpoint_id)
}

#[tokio::test(flavor = "multi_thread")]
async fn unary_round_trip_passes_authenticated_peer() {
    let seen_peers = Arc::new(Mutex::new(Vec::new()));
    let (server, address, provider_endpoint) = bind_recording_server(Arc::clone(&seen_peers)).await;
    let client_key = SecretKey::generate();
    let expected_peer = *client_key.public().as_bytes();
    let client = Client::dial_direct(address, client_key, ClientConfig::default())
        .await
        .expect("client dial");

    let response = client.call(request(11)).await.expect("RFQ response");
    assert!(matches!(response, Response::Info { .. }));
    assert_eq!(client.endpoint_id().as_bytes(), &expected_peer);
    assert_eq!(client.provider_endpoint_id(), provider_endpoint);
    assert_eq!(
        seen_peers.lock().expect("peer mutex").as_slice(),
        &[expected_peer]
    );

    client.close().await;
    server.shutdown_and_join().await.expect("server shutdown");
}

#[tokio::test(flavor = "multi_thread")]
async fn reconnect_retains_persisted_identity_and_a_different_key_does_not() {
    let seen_peers = Arc::new(Mutex::new(Vec::new()));
    let (server, address, _) = bind_recording_server(Arc::clone(&seen_peers)).await;
    let persistent_key = SecretKey::generate();
    let persistent_peer = *persistent_key.public().as_bytes();

    let first = Client::dial_direct(
        address.clone(),
        persistent_key.clone(),
        ClientConfig::default(),
    )
    .await
    .expect("first dial");
    first.call(request(20)).await.expect("first request");
    first.close().await;

    let second = Client::dial_direct(address.clone(), persistent_key, ClientConfig::default())
        .await
        .expect("second dial");
    second.call(request(21)).await.expect("second request");
    second.close().await;

    let other_key = SecretKey::generate();
    let other_peer = *other_key.public().as_bytes();
    let other = Client::dial_direct(address, other_key, ClientConfig::default())
        .await
        .expect("other dial");
    other.call(request(22)).await.expect("other request");
    other.close().await;

    assert_ne!(persistent_peer, other_peer);
    assert_eq!(
        seen_peers.lock().expect("peer mutex").as_slice(),
        &[persistent_peer, persistent_peer, other_peer]
    );
    server.shutdown_and_join().await.expect("server shutdown");
}

struct RejectingValidator;

impl RequestHandler for RejectingValidator {
    fn validate(&self, _peer: [u8; 32], _envelope: &RequestEnvelope) -> Result<(), RpcError> {
        Err(
            RpcError::new(RpcErrorCode::InvalidRequest, "rejected by validation hook")
                .expect("bounded test error"),
        )
    }

    async fn handle(&self, _peer: [u8; 32], _request: Request) -> Result<Response, RpcError> {
        panic!("validation must run before dispatch")
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn validation_error_is_returned_without_dispatch() {
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
    let client = Client::dial_direct(address, SecretKey::generate(), ClientConfig::default())
        .await
        .expect("client dial");

    let error = client
        .call(request(30))
        .await
        .expect_err("validation failure");
    assert!(
        matches!(error, ClientError::Rpc(error) if error.code() == RpcErrorCode::InvalidRequest)
    );

    client.close().await;
    server.shutdown_and_join().await.expect("server shutdown");
}

struct SlowHandler;

impl RequestHandler for SlowHandler {
    async fn handle(&self, _peer: [u8; 32], _request: Request) -> Result<Response, RpcError> {
        tokio::time::sleep(Duration::from_secs(1)).await;
        Ok(info_response([0x42; 32]))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn handler_timeout_is_returned_as_a_typed_error() {
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
    let client = Client::dial_direct(address, SecretKey::generate(), ClientConfig::default())
        .await
        .expect("client dial");

    let error = client.call(request(31)).await.expect_err("handler timeout");
    assert!(
        matches!(error, ClientError::Rpc(error) if error.code() == RpcErrorCode::BackendUnavailable)
    );

    client.close().await;
    server.shutdown_and_join().await.expect("server shutdown");
}

#[tokio::test]
async fn schema_version_is_rejected_before_network_dispatch() {
    let seen_peers = Arc::new(Mutex::new(Vec::new()));
    let (server, address, _) = bind_recording_server(Arc::clone(&seen_peers)).await;
    let client = Client::dial_direct(address, SecretKey::generate(), ClientConfig::default())
        .await
        .expect("client dial");
    let mut invalid = request(32);
    invalid.schema_version += 1;

    let error = client.call(invalid).await.expect_err("schema failure");
    assert!(
        matches!(error, ClientError::Rpc(error) if error.code() == RpcErrorCode::UnsupportedVersion)
    );
    assert!(seen_peers.lock().expect("peer mutex").is_empty());

    client.close().await;
    server.shutdown_and_join().await.expect("server shutdown");
}

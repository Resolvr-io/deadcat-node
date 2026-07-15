use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use deadcat_types::ChainAnchor;
use elements::encode::serialize;
use elements::{BlockHash, LockTime, OutPoint, Script, Transaction, TxIn, TxOut, Txid};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::elements_rpc::{ElementsRpcAuth, ElementsRpcChainSource, ElementsRpcConfig};
use super::esplora::{EsploraAuth, EsploraChainSource, EsploraConfig};
use super::{ChainSource, ChainSourceError, Outspend, TransactionStatus};

#[tokio::test]
async fn both_backends_obey_transaction_fee_and_broadcast_contract() {
    let transaction = fixture_transaction();
    let txid = transaction.txid();
    let raw = serialize(&transaction);

    let (esplora_url, esplora_requests, esplora_server) = MockServer::start(vec![
        MockResponse::bytes(200, raw.clone()),
        MockResponse::json(200, json!({"1": 1.0, "3": 0.5})),
        MockResponse::text(200, txid.to_string()),
    ])
    .await;
    let mut esplora_config = EsploraConfig::new(esplora_url);
    esplora_config.auth = EsploraAuth::Bearer("esplora-secret".to_owned());
    let esplora = EsploraChainSource::new(esplora_config).expect("valid config");
    exercise_common_contract(&esplora, &transaction).await;
    esplora_server.await.expect("mock server");

    {
        let requests = esplora_requests.lock().expect("requests");
        assert_eq!(requests.len(), 3);
        assert_request(&requests[0], "GET", &format!("/tx/{txid}/raw"));
        assert_request(&requests[1], "GET", "/fee-estimates");
        assert_request(&requests[2], "POST", "/tx");
        for request in requests.iter() {
            assert_eq!(
                request.headers.get("authorization").map(String::as_str),
                Some("Bearer esplora-secret")
            );
        }
        assert_eq!(requests[2].body, hex::encode(&raw).as_bytes());
    }

    let (rpc_url, rpc_requests, rpc_server) = MockServer::start(vec![
        MockResponse::rpc(1, Value::String(hex::encode(&raw))),
        MockResponse::rpc(2, json!({"feerate": 0.00001, "blocks": 1})),
        MockResponse::rpc(3, json!(txid)),
    ])
    .await;
    let rpc = ElementsRpcChainSource::new(ElementsRpcConfig::new(
        rpc_url,
        ElementsRpcAuth::Basic {
            username: "user".to_owned(),
            password: "pass".to_owned(),
        },
    ))
    .expect("valid config");
    exercise_common_contract(&rpc, &transaction).await;
    rpc_server.await.expect("mock server");

    let requests = rpc_requests.lock().expect("requests");
    assert_eq!(requests.len(), 3);
    for request in requests.iter() {
        assert_request(request, "POST", "/");
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some("Basic dXNlcjpwYXNz")
        );
    }
    assert_rpc_request(&requests[0], "getrawtransaction", json!([txid, false]));
    assert_rpc_request(&requests[1], "estimatesmartfee", json!([2]));
    assert_rpc_request(
        &requests[2],
        "sendrawtransaction",
        json!([hex::encode(raw)]),
    );
}

#[tokio::test]
async fn both_backends_return_a_canonical_confirmed_position() {
    let txid = fixture_transaction().txid();
    let other_txid = repeated_txid(0x11);
    let block_hash = repeated_block_hash(0x22);
    let expected = TransactionStatus::Confirmed {
        anchor: ChainAnchor {
            height: 42,
            hash: block_hash,
        },
        tx_index: 1,
    };

    let (url, requests, server) = MockServer::start(vec![
        MockResponse::json(
            200,
            json!({
                "confirmed": true,
                "block_height": 42,
                "block_hash": block_hash,
            }),
        ),
        MockResponse::text(200, block_hash.to_string()),
        MockResponse::json(200, json!([other_txid, txid])),
    ])
    .await;
    let esplora = EsploraChainSource::new(EsploraConfig::new(url)).expect("valid config");
    assert_eq!(esplora.transaction_status(txid).await.unwrap(), expected);
    server.await.expect("mock server");
    {
        let requests = requests.lock().expect("requests");
        assert_request(&requests[0], "GET", &format!("/tx/{txid}/status"));
        assert_request(&requests[1], "GET", "/block-height/42");
        assert_request(&requests[2], "GET", &format!("/block/{block_hash}/txids"));
    }

    let (url, requests, server) = MockServer::start(vec![
        MockResponse::rpc(
            1,
            json!({
                "txid": txid,
                "blockhash": block_hash,
                "confirmations": 2,
            }),
        ),
        MockResponse::rpc(2, json!({"hash": block_hash, "height": 42})),
        MockResponse::rpc(3, json!(block_hash)),
        MockResponse::rpc(4, json!({"hash": block_hash, "tx": [other_txid, txid]})),
    ])
    .await;
    let rpc = ElementsRpcChainSource::new(ElementsRpcConfig::new(url, ElementsRpcAuth::None))
        .expect("valid config");
    assert_eq!(rpc.transaction_status(txid).await.unwrap(), expected);
    server.await.expect("mock server");
    let requests = requests.lock().expect("requests");
    assert_rpc_request(&requests[0], "getrawtransaction", json!([txid, true]));
    assert_rpc_request(&requests[1], "getblockheader", json!([block_hash, true]));
    assert_rpc_request(&requests[2], "getblockhash", json!([42]));
    assert_rpc_request(&requests[3], "getblock", json!([block_hash, 1]));
}

#[tokio::test]
async fn both_backends_identify_an_unconfirmed_outspend() {
    let source_transaction = fixture_transaction();
    let source_outpoint = OutPoint::new(source_transaction.txid(), 0);
    let spender = spending_transaction(source_outpoint);
    let expected = Some(Outspend {
        spending_txid: spender.txid(),
        input_index: 0,
        status: TransactionStatus::Unconfirmed,
    });

    let (url, _requests, server) = MockServer::start(vec![MockResponse::json(
        200,
        json!({
            "spent": true,
            "txid": spender.txid(),
            "vin": 0,
            "status": {"confirmed": false},
        }),
    )])
    .await;
    let esplora = EsploraChainSource::new(EsploraConfig::new(url)).expect("valid config");
    assert_eq!(esplora.outspend(source_outpoint).await.unwrap(), expected);
    server.await.expect("mock server");

    let (url, requests, server) = MockServer::start(vec![
        MockResponse::rpc(
            1,
            Value::String(hex::encode(serialize(&source_transaction))),
        ),
        MockResponse::rpc(
            2,
            json!([{
                "txid": source_outpoint.txid,
                "vout": source_outpoint.vout,
                "spendingtxid": spender.txid(),
            }]),
        ),
        MockResponse::rpc(3, Value::String(hex::encode(serialize(&spender)))),
        MockResponse::rpc(4, json!({"txid": spender.txid()})),
    ])
    .await;
    let rpc = ElementsRpcChainSource::new(ElementsRpcConfig::new(url, ElementsRpcAuth::None))
        .expect("valid config");
    assert_eq!(rpc.outspend(source_outpoint).await.unwrap(), expected);
    server.await.expect("mock server");
    let requests = requests.lock().expect("requests");
    assert_rpc_request(
        &requests[1],
        "gettxspendingprevout",
        json!([[{"txid": source_outpoint.txid, "vout": 0}]]),
    );
}

#[tokio::test]
async fn esplora_history_excludes_mempool_and_returns_canonical_order() {
    let older = repeated_txid(0x31);
    let newer = repeated_txid(0x32);
    let mempool = repeated_txid(0x33);
    let older_hash = repeated_block_hash(0x41);
    let newer_hash = repeated_block_hash(0x42);
    let (url, _requests, server) = MockServer::start(vec![
        MockResponse::json(
            200,
            json!([
                {
                    "txid": mempool,
                    "status": {"confirmed": false},
                },
                {
                    "txid": newer,
                    "status": {
                        "confirmed": true,
                        "block_height": 11,
                        "block_hash": newer_hash,
                    },
                },
                {
                    "txid": older,
                    "status": {
                        "confirmed": true,
                        "block_height": 10,
                        "block_hash": older_hash,
                    },
                },
            ]),
        ),
        MockResponse::text(200, newer_hash.to_string()),
        MockResponse::json(200, json!([newer])),
        MockResponse::text(200, older_hash.to_string()),
        MockResponse::json(200, json!([older])),
    ])
    .await;
    let source = EsploraChainSource::new(EsploraConfig::new(url)).expect("valid config");

    assert_eq!(
        source.script_history(&Script::new()).await.unwrap(),
        vec![older, newer]
    );
    server.await.expect("mock server");
}

#[tokio::test]
async fn esplora_uses_electrum_scripthash_byte_order() {
    let (url, requests, server) = MockServer::start(vec![MockResponse::json(200, json!([]))]).await;
    let source = EsploraChainSource::new(EsploraConfig::new(url)).expect("valid config");

    assert!(
        source
            .script_history(&Script::new())
            .await
            .unwrap()
            .is_empty()
    );
    server.await.expect("mock server");

    let requests = requests.lock().expect("requests");
    assert_request(
        &requests[0],
        "GET",
        "/scripthash/55b852781b9995a44c939b64e441ae2724b96f99c8f4fb9a141cfc9842c4b0e3/txs",
    );
}

#[tokio::test]
async fn adapters_reject_oversized_responses_before_decoding() {
    let transaction = fixture_transaction();
    let txid = transaction.txid();
    let (url, _requests, server) = MockServer::start(vec![
        MockResponse::text(200, "00").with_declared_length(10_000),
    ])
    .await;
    let mut config = EsploraConfig::new(url);
    config.max_response_bytes = 32;
    let source = EsploraChainSource::new(config).expect("valid config");

    assert!(matches!(
        source.transaction(txid).await,
        Err(ChainSourceError::InvalidData(message)) if message.contains("exceeds 32 byte limit")
    ));
    server.await.expect("mock server");
}

#[tokio::test]
async fn elements_core_reports_only_genuine_index_gaps_as_unsupported() {
    let (url, _requests, server) = MockServer::start(Vec::new()).await;
    let source = ElementsRpcChainSource::new(ElementsRpcConfig::new(url, ElementsRpcAuth::None))
        .expect("valid config");

    assert!(matches!(
        source.script_history(&Script::new()).await,
        Err(ChainSourceError::Unsupported(_))
    ));
    assert!(matches!(
        source
            .issuance_transaction(elements::AssetId::LIQUID_BTC)
            .await,
        Err(ChainSourceError::Unsupported(_))
    ));
    server.await.expect("mock server");
}

async fn exercise_common_contract<S: ChainSource>(source: &S, expected: &Transaction) {
    assert_eq!(
        source.transaction(expected.txid()).await.unwrap(),
        *expected
    );
    assert_eq!(source.estimate_fee_rate(2).await.unwrap(), 1.0);
    assert_eq!(source.broadcast(expected).await.unwrap(), expected.txid());
}

fn fixture_transaction() -> Transaction {
    Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut::default()],
    }
}

fn spending_transaction(outpoint: OutPoint) -> Transaction {
    let input = TxIn {
        previous_output: outpoint,
        ..TxIn::default()
    };
    Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: vec![TxOut::default()],
    }
}

fn repeated_txid(byte: u8) -> Txid {
    Txid::from_str(&hex::encode([byte; 32])).expect("valid repeated txid")
}

fn repeated_block_hash(byte: u8) -> BlockHash {
    BlockHash::from_str(&hex::encode([byte; 32])).expect("valid repeated block hash")
}

fn assert_request(request: &RecordedRequest, method: &str, path: &str) {
    assert_eq!(request.method, method);
    assert_eq!(request.path, path);
}

fn assert_rpc_request(request: &RecordedRequest, method: &str, params: Value) {
    let body: Value = serde_json::from_slice(&request.body).expect("JSON-RPC request");
    assert_eq!(body["jsonrpc"], "1.0");
    assert_eq!(body["method"], method);
    assert_eq!(body["params"], params);
    drop(params);
}

struct MockServer;

impl MockServer {
    async fn start(
        responses: Vec<MockResponse>,
    ) -> (
        String,
        Arc<Mutex<Vec<RecordedRequest>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
        let address = listener.local_addr().expect("mock address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            for response in responses {
                let (mut socket, _) = listener.accept().await.expect("accept request");
                let request = read_request(&mut socket).await;
                recorded.lock().expect("requests").push(request);
                let reason = match response.status {
                    200 => "OK",
                    400 => "Bad Request",
                    404 => "Not Found",
                    500 => "Internal Server Error",
                    _ => "Response",
                };
                let declared_length = response.declared_length.unwrap_or(response.body.len());
                let header = format!(
                    "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.status, reason, response.content_type, declared_length
                );
                socket.write_all(header.as_bytes()).await.expect("header");
                socket.write_all(&response.body).await.expect("body");
                socket.shutdown().await.expect("shutdown");
            }
        });
        (format!("http://{address}"), requests, task)
    }
}

struct MockResponse {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
    declared_length: Option<usize>,
}

impl MockResponse {
    fn bytes(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: "application/octet-stream",
            body,
            declared_length: None,
        }
    }

    fn text(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: "text/plain",
            body: body.into().into_bytes(),
            declared_length: None,
        }
    }

    fn json(status: u16, body: Value) -> Self {
        let encoded = serde_json::to_vec(&body).expect("serialize mock response");
        drop(body);
        Self {
            status,
            content_type: "application/json",
            body: encoded,
            declared_length: None,
        }
    }

    fn rpc(id: u64, result: Value) -> Self {
        let response = json!({"result": result, "error": null, "id": id});
        drop(result);
        Self::json(200, response)
    }

    fn with_declared_length(mut self, length: usize) -> Self {
        self.declared_length = Some(length);
        self
    }
}

struct RecordedRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

async fn read_request(socket: &mut tokio::net::TcpStream) -> RecordedRequest {
    const MAX_REQUEST_BYTES: usize = 1024 * 1024;
    let mut bytes = Vec::new();
    let header_end = loop {
        assert!(bytes.len() < MAX_REQUEST_BYTES, "mock request is too large");
        let mut buffer = [0_u8; 4096];
        let count = socket.read(&mut buffer).await.expect("read request");
        assert!(count > 0, "connection closed before HTTP headers");
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let header_text = std::str::from_utf8(&bytes[..header_end]).expect("ASCII HTTP headers");
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().expect("request line");
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().expect("method").to_owned();
    let path = request_parts.next().expect("path").to_owned();
    let mut headers = BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').expect("header");
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let content_length = headers
        .get("content-length")
        .map(|length| length.parse::<usize>().expect("content length"))
        .unwrap_or(0);
    while bytes.len() - header_end < content_length {
        assert!(bytes.len() < MAX_REQUEST_BYTES, "mock request is too large");
        let mut buffer = [0_u8; 4096];
        let count = socket.read(&mut buffer).await.expect("read body");
        assert!(count > 0, "connection closed before HTTP body");
        bytes.extend_from_slice(&buffer[..count]);
    }
    RecordedRequest {
        method,
        path,
        headers,
        body: bytes[header_end..header_end + content_length].to_vec(),
    }
}

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread;

use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::encode::{serialize, serialize_hex};
use elements::hashes::Hash as _;
use elements::secp256k1_zkp::rand::thread_rng;
use elements::secp256k1_zkp::{Keypair, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use elements::{LockTime, Transaction, TxIn, TxOutSecrets, TxOutWitness};

use super::*;

const TIP_HEIGHT: u32 = 11;
const CREATION_HEIGHT: u32 = 9;

fn hash(marker: u8) -> BlockHash {
    BlockHash::from_byte_array([marker; 32])
}

fn asset(marker: u8) -> AssetId {
    AssetId::from_byte_array([marker; 32])
}

fn chain() -> ChainIdentity {
    ChainIdentity {
        network: LiquidNetwork::ElementsRegtest,
        genesis_hash: hash(1),
    }
}

fn tip(marker: u8) -> ChainAnchor {
    ChainAnchor {
        height: TIP_HEIGHT,
        hash: hash(marker),
    }
}

fn config() -> ElementsCoreConfig {
    ElementsCoreConfig::new("http://127.0.0.1:7041", ElementsCoreAuth::None)
}

fn p2tr_script(marker: u8) -> Script {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[marker.max(1); 32]).expect("fixture secret");
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let (internal_key, _) = XOnlyPublicKey::from_keypair(&keypair);
    Script::new_v1_p2tr(&secp, internal_key, None)
}

struct ScriptedCall {
    method: &'static str,
    params: JsonValue,
    result: Result<JsonValue, ElementsCoreError>,
}

impl ScriptedCall {
    fn ok(method: &'static str, params: JsonValue, result: JsonValue) -> Self {
        Self {
            method,
            params,
            result: Ok(result),
        }
    }

    fn error(method: &'static str, params: JsonValue, error: ElementsCoreError) -> Self {
        Self {
            method,
            params,
            result: Err(error),
        }
    }
}

struct ScriptedRpc {
    calls: Mutex<VecDeque<ScriptedCall>>,
    timeouts: Mutex<Vec<RpcCallTimeout>>,
}

impl ScriptedRpc {
    fn new(calls: impl IntoIterator<Item = ScriptedCall>) -> Self {
        Self {
            calls: Mutex::new(calls.into_iter().collect()),
            timeouts: Mutex::new(Vec::new()),
        }
    }

    fn assert_finished(&self) {
        let calls = self.calls.lock().expect("scripted calls");
        assert!(
            calls.is_empty(),
            "{} calls remain, beginning with {}",
            calls.len(),
            calls.front().map_or("none", |call| call.method)
        );
    }
}

impl RpcTransport for ScriptedRpc {
    fn call(
        &self,
        method: &'static str,
        params: JsonValue,
        budget: RpcCallBudget,
    ) -> Result<JsonValue, ElementsCoreError> {
        self.timeouts
            .lock()
            .expect("timeouts")
            .push(budget.timeout()?);
        let call = self
            .calls
            .lock()
            .expect("scripted calls")
            .pop_front()
            .unwrap_or_else(|| panic!("unexpected {method} call with {params}"));
        assert_eq!(call.method, method);
        assert_eq!(call.params, params, "unexpected {method} parameters");
        call.result
    }
}

fn client(calls: impl IntoIterator<Item = ScriptedCall>) -> (ElementsCoreClient, Arc<ScriptedRpc>) {
    client_with_config(&config(), calls)
}

fn client_with_config(
    config: &ElementsCoreConfig,
    calls: impl IntoIterator<Item = ScriptedCall>,
) -> (ElementsCoreClient, Arc<ScriptedRpc>) {
    let rpc = Arc::new(ScriptedRpc::new(calls));
    let client = ElementsCoreClient::from_parts(config, chain(), rpc.clone());
    (client, rpc)
}

fn blockchain_info(anchor: ChainAnchor) -> JsonValue {
    json!({
        "chain": "liquidregtest",
        "blocks": anchor.height,
        "bestblockhash": anchor.hash,
        "initialblockdownload": false,
    })
}

fn stable_tip_calls(anchor: ChainAnchor) -> Vec<ScriptedCall> {
    vec![
        ScriptedCall::ok("getblockhash", json!([0]), json!(chain().genesis_hash)),
        ScriptedCall::ok("getblockchaininfo", json!([]), blockchain_info(anchor)),
        ScriptedCall::ok("getblockhash", json!([anchor.height]), json!(anchor.hash)),
    ]
}

fn txindex_call() -> ScriptedCall {
    ScriptedCall::ok(
        "getindexinfo",
        json!([]),
        json!({"txindex": {"synced": true}}),
    )
}

fn confidential_transaction(script: Script, marker: u8, amount: u64) -> Transaction {
    let explicit = TxOut {
        asset: Asset::Explicit(asset(marker)),
        value: Value::Explicit(amount),
        nonce: Nonce::Null,
        script_pubkey: script,
        witness: TxOutWitness::default(),
    };
    let secret = SecretKey::from_slice(&[marker.max(1); 32]).expect("fixture secret");
    let blinding_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
    let (confidential, _, _, _) = explicit
        .to_non_last_confidential(
            &mut thread_rng(),
            &Secp256k1::new(),
            blinding_key,
            &[TxOutSecrets::new(
                asset(marker),
                AssetBlindingFactor::zero(),
                amount,
                ValueBlindingFactor::zero(),
            )],
        )
        .expect("blind fixture output");
    Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([marker.wrapping_add(1); 32]), 0),
            ..TxIn::default()
        }],
        output: vec![confidential],
    }
}

fn gettxout(anchor: ChainAnchor, transaction: &Transaction, outpoint: OutPoint) -> JsonValue {
    json!({
        "bestblock": anchor.hash,
        "confirmations": u64::from(anchor.height - CREATION_HEIGHT) + 1,
        "coinbase": false,
        "scriptPubKey": {
            "hex": hex::encode(transaction.output[outpoint.vout as usize].script_pubkey.as_bytes())
        },
    })
}

#[test]
fn probe_binds_network_genesis_tip_assets_and_txindex() {
    let observed_tip = tip(2);
    let policy = asset(3);
    let calls = [
        ScriptedCall::ok("getblockhash", json!([0]), json!(chain().genesis_hash)),
        ScriptedCall::ok(
            "getblockchaininfo",
            json!([]),
            blockchain_info(observed_tip),
        ),
        ScriptedCall::ok(
            "getsidechaininfo",
            json!([]),
            json!({"pegged_asset": policy.to_string()}),
        ),
        ScriptedCall::ok(
            "dumpassetlabels",
            json!([]),
            json!({"bitcoin": policy.to_string()}),
        ),
        ScriptedCall::ok(
            "getblockhash",
            json!([observed_tip.height]),
            json!(observed_tip.hash),
        ),
        txindex_call(),
    ];
    let (client, rpc) = client(calls);

    let status = client.probe().expect("probe");
    assert_eq!(status.network(), LiquidNetwork::ElementsRegtest);
    assert_eq!(status.genesis_hash(), chain().genesis_hash);
    assert_eq!(status.pegged_asset(), policy);
    assert_eq!(status.tip(), observed_tip);
    rpc.assert_finished();
}

#[test]
fn script_scan_returns_full_outputs_and_anchor_in_canonical_order() {
    let anchor = tip(4);
    let first_script = p2tr_script(8);
    let second_script = p2tr_script(9);
    let first = confidential_transaction(first_script.clone(), 10, 1_000);
    let second = confidential_transaction(second_script.clone(), 11, 2_000);
    assert!(first.output[0].witness.rangeproof.is_some());
    let first_outpoint = OutPoint::new(first.txid(), 0);
    let second_outpoint = OutPoint::new(second.txid(), 0);
    let creation_hash = hash(5);
    let calls = [
        ScriptedCall::ok("getblockhash", json!([0]), json!(chain().genesis_hash)),
        ScriptedCall::ok(
            "scantxoutset",
            json!([
                "start",
                [
                    format!("raw({})", hex::encode(first_script.as_bytes())),
                    format!("raw({})", hex::encode(second_script.as_bytes())),
                ]
            ]),
            json!({
                "success": true,
                "height": anchor.height,
                "bestblock": anchor.hash,
                "unspents": [
                    {"txid": second.txid(), "vout": 0, "height": CREATION_HEIGHT, "scriptPubKey": second_script},
                    {"txid": first.txid(), "vout": 0, "height": CREATION_HEIGHT, "scriptPubKey": first_script},
                ],
            }),
        ),
        ScriptedCall::ok(
            "gettxout",
            json!([second.txid(), 0, true]),
            gettxout(anchor, &second, second_outpoint),
        ),
        ScriptedCall::ok(
            "getblockhash",
            json!([CREATION_HEIGHT]),
            json!(creation_hash),
        ),
        ScriptedCall::ok(
            "getrawtransaction",
            json!([second.txid(), false, creation_hash]),
            json!(serialize_hex(&second)),
        ),
        ScriptedCall::ok(
            "gettxout",
            json!([first.txid(), 0, true]),
            gettxout(anchor, &first, first_outpoint),
        ),
        ScriptedCall::ok(
            "getrawtransaction",
            json!([first.txid(), false, creation_hash]),
            json!(serialize_hex(&first)),
        ),
        ScriptedCall::ok("getblockhash", json!([0]), json!(chain().genesis_hash)),
        ScriptedCall::ok("getblockchaininfo", json!([]), blockchain_info(anchor)),
        ScriptedCall::ok("getblockhash", json!([anchor.height]), json!(anchor.hash)),
    ];
    let (client, rpc) = client(calls);

    let snapshot = client
        .scan_unspent_scripts(&[first_script, second_script])
        .expect("scan");
    assert_eq!(snapshot.anchor(), anchor);
    assert_eq!(snapshot.outputs().len(), 2);
    assert!(snapshot.outputs()[0].outpoint() < snapshot.outputs()[1].outpoint());
    for output in snapshot.outputs() {
        assert_eq!(output.script_pubkey(), &output.txout().script_pubkey);
        assert!(output.txout().witness.rangeproof.is_some());
    }
    rpc.assert_finished();
}

#[test]
fn script_scan_rejects_a_tip_advance_after_materializing_results() {
    let scan_anchor = tip(4);
    let advanced_tip = ChainAnchor {
        height: scan_anchor.height + 1,
        hash: hash(6),
    };
    let script = p2tr_script(10);
    let transaction = confidential_transaction(script.clone(), 12, 3_000);
    let outpoint = OutPoint::new(transaction.txid(), 0);
    let creation_hash = hash(5);
    let calls = [
        ScriptedCall::ok("getblockhash", json!([0]), json!(chain().genesis_hash)),
        ScriptedCall::ok(
            "scantxoutset",
            json!([
                "start",
                [format!("raw({})", hex::encode(script.as_bytes()))]
            ]),
            json!({
                "success": true,
                "height": scan_anchor.height,
                "bestblock": scan_anchor.hash,
                "unspents": [{
                    "txid": transaction.txid(),
                    "vout": 0,
                    "height": CREATION_HEIGHT,
                    "scriptPubKey": script,
                }],
            }),
        ),
        ScriptedCall::ok(
            "gettxout",
            json!([transaction.txid(), 0, true]),
            gettxout(scan_anchor, &transaction, outpoint),
        ),
        ScriptedCall::ok(
            "getblockhash",
            json!([CREATION_HEIGHT]),
            json!(creation_hash),
        ),
        ScriptedCall::ok(
            "getrawtransaction",
            json!([transaction.txid(), false, creation_hash]),
            json!(serialize_hex(&transaction)),
        ),
        ScriptedCall::ok("getblockhash", json!([0]), json!(chain().genesis_hash)),
        ScriptedCall::ok(
            "getblockchaininfo",
            json!([]),
            blockchain_info(advanced_tip),
        ),
        ScriptedCall::ok(
            "getblockhash",
            json!([advanced_tip.height]),
            json!(advanced_tip.hash),
        ),
    ];
    let (client, rpc) = client(calls);

    assert!(matches!(
        client.scan_unspent_scripts(&[script]),
        Err(ElementsCoreError::ScanTipChanged { expected, actual })
            if expected == scan_anchor && actual == advanced_tip
    ));
    rpc.assert_finished();
}

#[test]
fn script_scan_omits_candidate_spent_in_mempool() {
    let anchor = tip(7);
    let script = p2tr_script(13);
    let transaction = confidential_transaction(script.clone(), 14, 4_000);
    let outpoint = OutPoint::new(transaction.txid(), 0);
    let calls = [
        ScriptedCall::ok("getblockhash", json!([0]), json!(chain().genesis_hash)),
        ScriptedCall::ok(
            "scantxoutset",
            json!([
                "start",
                [format!("raw({})", hex::encode(script.as_bytes()))]
            ]),
            json!({
                "success": true,
                "height": anchor.height,
                "bestblock": anchor.hash,
                "unspents": [{
                    "txid": transaction.txid(),
                    "vout": 0,
                    "height": CREATION_HEIGHT,
                    "scriptPubKey": script,
                }],
            }),
        ),
        ScriptedCall::ok(
            "gettxout",
            json!([outpoint.txid, outpoint.vout, true]),
            JsonValue::Null,
        ),
        ScriptedCall::ok("getblockhash", json!([0]), json!(chain().genesis_hash)),
        ScriptedCall::ok("getblockchaininfo", json!([]), blockchain_info(anchor)),
        ScriptedCall::ok("getblockhash", json!([anchor.height]), json!(anchor.hash)),
    ];
    let (client, rpc) = client(calls);

    let snapshot = client
        .scan_unspent_scripts(&[script])
        .expect("spent scan candidate omitted");
    assert!(snapshot.outputs().is_empty());
    rpc.assert_finished();
}

#[test]
fn empty_script_scan_uses_one_exact_stable_tip_without_scantxoutset() {
    let anchor = tip(8);
    let mut calls = stable_tip_calls(anchor);
    calls.extend(stable_tip_calls(anchor));
    let (client, rpc) = client(calls);

    let snapshot = client.scan_unspent_scripts(&[]).expect("empty scan");
    assert_eq!(snapshot.anchor(), anchor);
    assert!(snapshot.outputs().is_empty());
    rpc.assert_finished();
}

#[test]
fn immature_coinbase_is_excluded_from_scan_and_rejected_as_prevout() {
    let anchor = ChainAnchor {
        height: 120,
        hash: hash(9),
    };
    let script = p2tr_script(15);
    let transaction = confidential_transaction(script.clone(), 16, 5_000);
    let outpoint = OutPoint::new(transaction.txid(), 0);
    let confirmations = COINBASE_MATURITY_CONFIRMATIONS - 1;
    let scan_calls = [
        ScriptedCall::ok("getblockhash", json!([0]), json!(chain().genesis_hash)),
        ScriptedCall::ok(
            "scantxoutset",
            json!([
                "start",
                [format!("raw({})", hex::encode(script.as_bytes()))]
            ]),
            json!({
                "success": true,
                "height": anchor.height,
                "bestblock": anchor.hash,
                "unspents": [{
                    "txid": transaction.txid(),
                    "vout": 0,
                    "height": u64::from(anchor.height) - confirmations + 1,
                    "scriptPubKey": script,
                }],
            }),
        ),
        ScriptedCall::ok(
            "gettxout",
            json!([outpoint.txid, outpoint.vout, true]),
            json!({
                "bestblock": anchor.hash,
                "confirmations": confirmations,
                "coinbase": true,
                "scriptPubKey": {"hex": hex::encode(transaction.output[0].script_pubkey.as_bytes())},
            }),
        ),
        ScriptedCall::ok("getblockhash", json!([0]), json!(chain().genesis_hash)),
        ScriptedCall::ok("getblockchaininfo", json!([]), blockchain_info(anchor)),
        ScriptedCall::ok("getblockhash", json!([anchor.height]), json!(anchor.hash)),
    ];
    let (scan_client, scan_rpc) = client(scan_calls);
    let snapshot = scan_client
        .scan_unspent_scripts(&[script])
        .expect("immature coinbase omitted");
    assert!(snapshot.outputs().is_empty());
    scan_rpc.assert_finished();

    let mut prevout_calls = vec![txindex_call()];
    prevout_calls.extend(stable_tip_calls(anchor));
    prevout_calls.push(ScriptedCall::ok(
        "gettxout",
        json!([outpoint.txid, outpoint.vout, true]),
        json!({
            "bestblock": anchor.hash,
            "confirmations": confirmations,
            "coinbase": true,
            "scriptPubKey": {"hex": hex::encode(transaction.output[0].script_pubkey.as_bytes())},
        }),
    ));
    let (prevout_client, prevout_rpc) = client(prevout_calls);
    assert!(matches!(
        prevout_client.unspent_prevouts(&[outpoint], &[]),
        Err(ElementsCoreError::ImmatureCoinbasePrevout {
            outpoint: actual,
            confirmations: actual_confirmations,
        }) if actual == outpoint && actual_confirmations == confirmations
    ));
    prevout_rpc.assert_finished();
}

#[test]
fn script_scan_fetches_a_shared_transaction_once_and_bounds_retained_outputs() {
    let anchor = tip(7);
    let first_script = p2tr_script(13);
    let second_script = p2tr_script(14);
    let mut transaction = confidential_transaction(first_script.clone(), 15, 5_000);
    transaction.output.push(
        confidential_transaction(second_script.clone(), 16, 6_000)
            .output
            .remove(0),
    );
    let first_outpoint = OutPoint::new(transaction.txid(), 0);
    let second_outpoint = OutPoint::new(transaction.txid(), 1);
    let creation_block = hash(8);
    let scan_result = json!({
        "success": true,
        "height": anchor.height,
        "bestblock": anchor.hash,
        "unspents": [
            {"txid": transaction.txid(), "vout": 0, "height": CREATION_HEIGHT, "scriptPubKey": first_script},
            {"txid": transaction.txid(), "vout": 1, "height": CREATION_HEIGHT, "scriptPubKey": second_script},
        ],
    });
    let mut descriptor_set = vec![
        format!("raw({})", hex::encode(first_script.as_bytes())),
        format!("raw({})", hex::encode(second_script.as_bytes())),
    ];
    descriptor_set.sort();
    let descriptors = json!(["start", descriptor_set]);
    let mut calls = vec![
        ScriptedCall::ok("getblockhash", json!([0]), json!(chain().genesis_hash)),
        ScriptedCall::ok("scantxoutset", descriptors.clone(), scan_result.clone()),
        ScriptedCall::ok(
            "gettxout",
            json!([transaction.txid(), 0, true]),
            gettxout(anchor, &transaction, first_outpoint),
        ),
        ScriptedCall::ok(
            "gettxout",
            json!([transaction.txid(), 1, true]),
            gettxout(anchor, &transaction, second_outpoint),
        ),
        ScriptedCall::ok(
            "getblockhash",
            json!([CREATION_HEIGHT]),
            json!(creation_block),
        ),
        // Both requested outputs are extracted from this one bounded raw
        // response; the full transaction is dropped before the next group.
        ScriptedCall::ok(
            "getrawtransaction",
            json!([transaction.txid(), false, creation_block]),
            json!(serialize_hex(&transaction)),
        ),
    ];
    calls.extend(stable_tip_calls(anchor));
    let (client, rpc) = client(calls);
    let snapshot = client
        .scan_unspent_scripts(&[first_script.clone(), second_script.clone()])
        .expect("shared transaction scan");
    assert_eq!(snapshot.outputs().len(), 2);
    rpc.assert_finished();

    let mut bounded = config();
    bounded.max_materialized_txout_bytes = 1;
    let calls = [
        ScriptedCall::ok("getblockhash", json!([0]), json!(chain().genesis_hash)),
        ScriptedCall::ok("scantxoutset", descriptors, scan_result),
        ScriptedCall::ok(
            "gettxout",
            json!([transaction.txid(), 0, true]),
            gettxout(anchor, &transaction, first_outpoint),
        ),
        ScriptedCall::ok(
            "gettxout",
            json!([transaction.txid(), 1, true]),
            gettxout(anchor, &transaction, second_outpoint),
        ),
        ScriptedCall::ok(
            "getblockhash",
            json!([CREATION_HEIGHT]),
            json!(creation_block),
        ),
        ScriptedCall::ok(
            "getrawtransaction",
            json!([transaction.txid(), false, creation_block]),
            json!(serialize_hex(&transaction)),
        ),
    ];
    let (client, rpc) = client_with_config(&bounded, calls);
    assert!(matches!(
        client.scan_unspent_scripts(&[first_script, second_script]),
        Err(ElementsCoreError::MaterializedTxoutsTooLarge {
            maximum: 1,
            actual,
        }) if actual > 1
    ));
    rpc.assert_finished();
}

#[test]
fn prevouts_and_required_anchors_share_one_unchanged_tip() {
    let stable = tip(20);
    let quote_anchor = ChainAnchor {
        height: 7,
        hash: hash(17),
    };
    let market_anchor = stable;
    let first_script = p2tr_script(18);
    let second_script = p2tr_script(19);
    let first = confidential_transaction(first_script, 21, 1_000);
    let second = confidential_transaction(second_script, 22, 2_000);
    let first_outpoint = OutPoint::new(first.txid(), 0);
    let second_outpoint = OutPoint::new(second.txid(), 0);
    let mut calls = vec![txindex_call()];
    calls.extend(stable_tip_calls(stable));
    calls.extend([
        ScriptedCall::ok(
            "getblockhash",
            json!([quote_anchor.height]),
            json!(quote_anchor.hash),
        ),
        ScriptedCall::ok(
            "getblockhash",
            json!([market_anchor.height]),
            json!(market_anchor.hash),
        ),
        ScriptedCall::ok(
            "gettxout",
            json!([second.txid(), 0, true]),
            gettxout(stable, &second, second_outpoint),
        ),
        ScriptedCall::ok("getblockhash", json!([CREATION_HEIGHT]), json!(hash(40))),
        ScriptedCall::ok(
            "getrawtransaction",
            json!([second.txid(), false, hash(40)]),
            json!(serialize_hex(&second)),
        ),
        ScriptedCall::ok(
            "gettxout",
            json!([first.txid(), 0, true]),
            gettxout(stable, &first, first_outpoint),
        ),
        ScriptedCall::ok("getblockhash", json!([CREATION_HEIGHT]), json!(hash(40))),
        ScriptedCall::ok(
            "getrawtransaction",
            json!([first.txid(), false, hash(40)]),
            json!(serialize_hex(&first)),
        ),
    ]);
    calls.extend(stable_tip_calls(stable));
    calls.extend([
        ScriptedCall::ok(
            "getblockhash",
            json!([quote_anchor.height]),
            json!(quote_anchor.hash),
        ),
        ScriptedCall::ok(
            "getblockhash",
            json!([market_anchor.height]),
            json!(market_anchor.hash),
        ),
    ]);
    let (client, rpc) = client(calls);

    let requested = [second_outpoint, first_outpoint];
    let snapshot = client
        .unspent_prevouts(&requested, &[quote_anchor, market_anchor])
        .expect("prevout snapshot");
    assert_eq!(snapshot.anchor(), stable);
    assert_eq!(
        snapshot
            .prevouts()
            .iter()
            .map(CorePrevout::outpoint)
            .collect::<Vec<_>>(),
        requested
    );
    assert_eq!(snapshot.prevouts()[0].txout(), &second.output[0]);
    assert!(snapshot.prevouts()[0].txout().witness.rangeproof.is_some());
    rpc.assert_finished();
}

#[test]
fn confirmed_prevout_is_block_qualified_against_a_stale_same_txid_witness() {
    let stable = tip(23);
    let script = p2tr_script(24);
    let active = confidential_transaction(script, 25, 4_000);
    let mut stale = active.clone();
    stale.output[0].witness.rangeproof = None;
    assert_eq!(stale.txid(), active.txid());
    assert_ne!(stale.wtxid(), active.wtxid());
    let outpoint = OutPoint::new(active.txid(), 0);
    let creation_block = hash(26);
    let mut calls = vec![txindex_call()];
    calls.extend(stable_tip_calls(stable));
    calls.extend([
        ScriptedCall::ok(
            "gettxout",
            json!([active.txid(), 0, true]),
            gettxout(stable, &active, outpoint),
        ),
        ScriptedCall::ok(
            "getblockhash",
            json!([CREATION_HEIGHT]),
            json!(creation_block),
        ),
        // Supplying the canonical block hash prevents Core from selecting the
        // stale branch's same-txid transaction with different CT witnesses.
        ScriptedCall::ok(
            "getrawtransaction",
            json!([active.txid(), false, creation_block]),
            json!(serialize_hex(&active)),
        ),
    ]);
    calls.extend(stable_tip_calls(stable));
    let (client, rpc) = client(calls);

    let snapshot = client
        .unspent_prevouts(&[outpoint], &[])
        .expect("canonical prevout");
    assert_eq!(snapshot.prevouts()[0].txout(), &active.output[0]);
    assert_ne!(snapshot.prevouts()[0].txout(), &stale.output[0]);
    rpc.assert_finished();
}

#[test]
fn changing_tip_or_noncanonical_anchor_fails_closed() {
    let stable = tip(30);
    let changed = tip(31);
    let required = ChainAnchor {
        height: 7,
        hash: hash(27),
    };
    let mut calls = stable_tip_calls(stable);
    calls.push(ScriptedCall::ok(
        "getblockhash",
        json!([required.height]),
        json!(required.hash),
    ));
    calls.extend(stable_tip_calls(changed));
    let (changing_client, rpc) = client(calls);
    assert!(matches!(
        changing_client.validate_canonical_anchor(required),
        Err(ElementsCoreError::TipChanged { expected, actual })
            if expected == stable && actual == changed
    ));
    rpc.assert_finished();

    let mut calls = stable_tip_calls(stable);
    calls.push(ScriptedCall::ok(
        "getblockhash",
        json!([required.height]),
        json!(hash(99)),
    ));
    let (noncanonical_client, _) = client(calls);
    assert!(matches!(
        noncanonical_client.validate_canonical_anchor(required),
        Err(ElementsCoreError::AnchorNotCanonical { anchor, .. }) if anchor == required
    ));
}

#[test]
fn operation_budget_is_client_and_operation_bound() {
    let (first, _) = client([]);
    let (second, _) = client([]);
    let budget = first
        .begin_operation(CoreOperation::Anchor)
        .expect("budget");
    let remaining = budget.remaining().expect("remaining budget");
    assert!(!remaining.is_zero());
    assert!(remaining <= DEFAULT_ANCHOR_TIMEOUT);
    assert!(matches!(
        second.validate_canonical_anchor_with_budget(&budget, tip(1)),
        Err(ElementsCoreError::ForeignOperationBudget)
    ));
    assert!(matches!(
        first.unspent_prevouts_with_budget(&budget, &[], &[]),
        Err(ElementsCoreError::WrongOperationBudget {
            expected: CoreOperation::Prevouts,
            actual: CoreOperation::Anchor,
        })
    ));
}

#[test]
fn scan_gate_and_deadline_start_before_caller_wallet_work() {
    let mut bounded = config();
    bounded.scan_timeout = Duration::from_millis(20);
    let (client, _) = client_with_config(&bounded, []);
    let operation = client.begin_script_scan().expect("first scan operation");
    let contender = client.clone();
    let join = thread::spawn(move || contender.begin_script_scan().map(drop));
    assert!(matches!(
        join.join().expect("contender thread"),
        Err(ElementsCoreError::OperationTimedOut { operation: "scan" })
    ));
    drop(operation);

    let mut bounded = config();
    bounded.scan_timeout = Duration::from_millis(10);
    let (client, _) = client_with_config(&bounded, []);
    let operation = client.begin_script_scan().expect("scan operation");
    thread::sleep(Duration::from_millis(20));
    assert!(matches!(
        operation.scan_unspent_scripts(&[]),
        Err(ElementsCoreError::OperationTimedOut { operation: "scan" })
    ));
    // Release the scan gate so the next assertion can fail only because the
    // caller-started budget expired, not because it timed out behind this scan.
    drop(operation);

    let budget = client
        .begin_operation(CoreOperation::Scan)
        .expect("caller-started scan budget");
    thread::sleep(Duration::from_millis(20));
    assert!(matches!(
        client.begin_script_scan_with_budget(budget),
        Err(ElementsCoreError::OperationTimedOut { operation: "scan" })
    ));
}

#[test]
fn held_scan_gate_does_not_block_prevouts_on_a_clone() {
    let anchor = tip(72);
    let mut calls = vec![txindex_call()];
    calls.extend(stable_tip_calls(anchor));
    calls.extend(stable_tip_calls(anchor));
    let (client, rpc) = client(calls);
    let scan = client.begin_script_scan().expect("held scan operation");
    let contender = client.clone();
    let (finished_tx, finished_rx) = std::sync::mpsc::channel();
    let join = thread::spawn(move || {
        let result = contender.unspent_prevouts(&[], &[]);
        finished_tx.send(result).expect("report prevout result");
    });

    let snapshot = finished_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("prevouts must finish while scan gate remains held")
        .expect("empty prevout snapshot");
    assert_eq!(snapshot.anchor(), anchor);
    assert!(snapshot.prevouts().is_empty());
    drop(scan);
    join.join().expect("prevout worker");
    rpc.assert_finished();
}

fn relay_transaction() -> Transaction {
    relay_transaction_with_inputs(&[50])
}

fn relay_transaction_with_inputs(markers: &[u8]) -> Transaction {
    Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: markers
            .iter()
            .enumerate()
            .map(|(index, marker)| TxIn {
                previous_output: OutPoint::new(
                    Txid::from_byte_array([*marker; 32]),
                    u32::try_from(index).expect("fixture input index"),
                ),
                ..TxIn::default()
            })
            .collect(),
        output: vec![TxOut {
            asset: Asset::Explicit(asset(51)),
            value: Value::Explicit(1_000),
            nonce: Nonce::Null,
            script_pubkey: Script::new(),
            witness: TxOutWitness::default(),
        }],
    }
}

fn transaction_not_found() -> ElementsCoreError {
    ElementsCoreError::RpcRejected {
        method: "getrawtransaction",
        code: -5,
        message: "No such mempool or blockchain transaction".to_owned(),
    }
}

fn exact_lookup_not_found(txid: Txid) -> ScriptedCall {
    ScriptedCall::error(
        "getrawtransaction",
        json!([txid, true]),
        transaction_not_found(),
    )
}

fn exact_lookup_calls(
    expected_txid: Txid,
    observed: &Transaction,
    block_hash: Option<BlockHash>,
    confirmations: i64,
) -> [ScriptedCall; 2] {
    [
        ScriptedCall::ok(
            "getrawtransaction",
            json!([expected_txid, true]),
            json!({
                "txid": observed.txid(),
                "hash": observed.wtxid(),
                "blockhash": block_hash,
                "confirmations": confirmations,
            }),
        ),
        ScriptedCall::ok(
            "getrawtransaction",
            json!([expected_txid, false]),
            json!(serialize_hex(observed)),
        ),
    ]
}

fn relay_prefix() -> Vec<ScriptedCall> {
    vec![
        ScriptedCall::ok("getblockhash", json!([0]), json!(chain().genesis_hash)),
        txindex_call(),
    ]
}

fn unspent_result(anchor: ChainAnchor) -> JsonValue {
    json!({
        "bestblock": anchor.hash,
        "confirmations": 1,
        "coinbase": false,
        "scriptPubKey": {"hex": ""},
    })
}

fn absent_unspent_calls(transaction: &Transaction, anchor: ChainAnchor) -> Vec<ScriptedCall> {
    let mut calls = stable_tip_calls(anchor);
    calls.extend(transaction.input.iter().map(|input| {
        ScriptedCall::ok(
            "gettxout",
            json!([input.previous_output.txid, input.previous_output.vout, true]),
            unspent_result(anchor),
        )
    }));
    calls.extend(stable_tip_calls(anchor));
    calls
}

fn mempool_acceptance(transaction: &Transaction, allowed: bool) -> JsonValue {
    json!([{
        "txid": transaction.txid(),
        "wtxid": transaction.wtxid(),
        "allowed": allowed,
        "reject-reason": (!allowed).then_some("min relay fee not met"),
    }])
}

#[test]
fn exact_transaction_debug_redacts_raw_bytes() {
    let transaction = relay_transaction();
    let bytes = serialize(&transaction);
    let exact = ExactTransaction::new(transaction.txid(), transaction.wtxid(), &bytes);
    let debug = format!("{exact:?}");

    assert!(debug.contains(&transaction.txid().to_string()));
    assert!(debug.contains(&transaction.wtxid().to_string()));
    assert!(debug.contains(&format!("bytes_len: {}", bytes.len())));
    assert!(!debug.contains(&hex::encode(bytes)));
}

#[test]
fn relay_observes_exact_mempool_bytes_without_broadcasting() {
    let transaction = relay_transaction();
    let bytes = serialize(&transaction);
    let exact = ExactTransaction::new(transaction.txid(), transaction.wtxid(), &bytes);
    let calls = [
        ScriptedCall::ok("getblockhash", json!([0]), json!(chain().genesis_hash)),
        txindex_call(),
        ScriptedCall::ok(
            "getrawtransaction",
            json!([transaction.txid(), true]),
            json!({
                "txid": transaction.txid(),
                "hash": transaction.wtxid(),
                "blockhash": null,
                "confirmations": 0,
            }),
        ),
        ScriptedCall::ok(
            "getrawtransaction",
            json!([transaction.txid(), false]),
            json!(serialize_hex(&transaction)),
        ),
    ];
    let (client, rpc) = client(calls);
    let result = client.relay_exact(exact).expect("relay observation");
    assert_eq!(result.observation(), CoreRelayObservation::Mempool);
    assert!(!result.was_policy_rejected());
    rpc.assert_finished();
}

#[test]
fn relay_absence_is_policy_checked_and_broadcast_exactly() {
    let transaction = relay_transaction();
    let bytes = serialize(&transaction);
    let exact = ExactTransaction::new(transaction.txid(), transaction.wtxid(), &bytes);
    let stable = tip(60);
    let input = transaction.input[0].previous_output;
    let mut calls = vec![
        ScriptedCall::ok("getblockhash", json!([0]), json!(chain().genesis_hash)),
        txindex_call(),
        ScriptedCall::error(
            "getrawtransaction",
            json!([transaction.txid(), true]),
            ElementsCoreError::RpcRejected {
                method: "getrawtransaction",
                code: -5,
                message: "not found".to_owned(),
            },
        ),
    ];
    calls.extend(stable_tip_calls(stable));
    calls.push(ScriptedCall::ok(
        "gettxout",
        json!([input.txid, input.vout, true]),
        json!({
            "bestblock": stable.hash,
            "confirmations": 1,
            "coinbase": false,
            "scriptPubKey": {"hex": ""},
        }),
    ));
    calls.extend(stable_tip_calls(stable));
    let raw = hex::encode(&bytes);
    calls.extend([
        ScriptedCall::ok(
            "testmempoolaccept",
            json!([[raw.clone()], 0]),
            json!([{
                "txid": transaction.txid(),
                "wtxid": transaction.wtxid(),
                "allowed": true,
            }]),
        ),
        ScriptedCall::ok(
            "sendrawtransaction",
            json!([raw, 0]),
            json!(transaction.txid()),
        ),
    ]);
    let (client, rpc) = client(calls);
    let result = client.relay_exact(exact).expect("broadcast");
    assert_eq!(
        result.observation(),
        CoreRelayObservation::BroadcastAccepted
    );
    assert!(!result.was_policy_rejected());
    rpc.assert_finished();
}

#[test]
fn relay_ambiguous_send_recovers_by_observing_exact_bytes() {
    let transaction = relay_transaction_with_inputs(&[14]);
    let bytes = serialize(&transaction);
    let exact = ExactTransaction::new(transaction.txid(), transaction.wtxid(), &bytes);
    let raw = hex::encode(&bytes);
    let anchor = tip(92);
    let mut calls = relay_prefix();
    calls.push(exact_lookup_not_found(transaction.txid()));
    calls.extend(absent_unspent_calls(&transaction, anchor));
    calls.extend([
        ScriptedCall::ok(
            "testmempoolaccept",
            json!([[raw.clone()], 0]),
            mempool_acceptance(&transaction, true),
        ),
        ScriptedCall::error(
            "sendrawtransaction",
            json!([raw, 0]),
            ElementsCoreError::BackendUnavailable(
                "response lost after Core accepted transaction".to_owned(),
            ),
        ),
    ]);
    calls.extend(exact_lookup_calls(
        transaction.txid(),
        &transaction,
        None,
        0,
    ));
    let (client, rpc) = client(calls);

    let result = client.relay_exact(exact).expect("ambiguous send recovered");
    assert_eq!(result.observation(), CoreRelayObservation::Mempool);
    assert!(!result.was_policy_rejected());
    rpc.assert_finished();
}

#[test]
fn relay_policy_rejection_remains_absent() {
    let transaction = relay_transaction_with_inputs(&[15]);
    let bytes = serialize(&transaction);
    let exact = ExactTransaction::new(transaction.txid(), transaction.wtxid(), &bytes);
    let raw = hex::encode(&bytes);
    let anchor = tip(93);
    let mut calls = relay_prefix();
    calls.push(exact_lookup_not_found(transaction.txid()));
    calls.extend(absent_unspent_calls(&transaction, anchor));
    calls.push(ScriptedCall::ok(
        "testmempoolaccept",
        json!([[raw], 0]),
        mempool_acceptance(&transaction, false),
    ));
    calls.push(exact_lookup_not_found(transaction.txid()));
    calls.extend(absent_unspent_calls(&transaction, anchor));
    let (client, rpc) = client(calls);

    let result = client.relay_exact(exact).expect("durable policy rejection");
    assert_eq!(result.observation(), CoreRelayObservation::Absent);
    assert!(result.was_policy_rejected());
    assert_eq!(
        result.policy_rejection_reason(),
        Some("min relay fee not met")
    );
    rpc.assert_finished();
}

#[test]
fn relay_spent_inputs_conflict_only_after_second_exact_lookup() {
    let transaction = relay_transaction_with_inputs(&[22, 16]);
    let bytes = serialize(&transaction);
    let exact = ExactTransaction::new(transaction.txid(), transaction.wtxid(), &bytes);
    let anchor = tip(94);
    let expected_spent = transaction
        .input
        .iter()
        .map(|input| input.previous_output)
        .min()
        .expect("fixture input");
    let mut calls = relay_prefix();
    calls.push(exact_lookup_not_found(transaction.txid()));
    calls.extend(stable_tip_calls(anchor));
    calls.extend(transaction.input.iter().map(|input| {
        ScriptedCall::ok(
            "gettxout",
            json!([input.previous_output.txid, input.previous_output.vout, true]),
            JsonValue::Null,
        )
    }));
    calls.extend(stable_tip_calls(anchor));
    calls.push(exact_lookup_not_found(transaction.txid()));
    let (client, rpc) = client(calls);

    let result = client.relay_exact(exact).expect("confirmed conflict");
    assert_eq!(
        result.observation(),
        CoreRelayObservation::Conflicted {
            spent_input: expected_spent,
            conflicting_txid: None,
        }
    );
    rpc.assert_finished();
}

#[test]
fn relay_same_txid_with_different_witness_is_exact_artifact_conflict() {
    let transaction = relay_transaction_with_inputs(&[17]);
    let bytes = serialize(&transaction);
    let exact = ExactTransaction::new(transaction.txid(), transaction.wtxid(), &bytes);
    let mut observed = transaction.clone();
    observed.input[0]
        .witness
        .script_witness
        .push(vec![0x51, 0x21]);
    assert_eq!(observed.txid(), transaction.txid());
    assert_ne!(observed.wtxid(), transaction.wtxid());
    let mut calls = relay_prefix();
    calls.extend(exact_lookup_calls(transaction.txid(), &observed, None, 0));
    let (client, rpc) = client(calls);

    let result = client.relay_exact(exact).expect("exact-artifact conflict");
    assert_eq!(
        result.observation(),
        CoreRelayObservation::Conflicted {
            spent_input: transaction.input[0].previous_output,
            conflicting_txid: Some(transaction.txid()),
        }
    );
    rpc.assert_finished();
}

#[test]
fn relay_confirmed_observation_requires_canonical_block() {
    let transaction = relay_transaction_with_inputs(&[18]);
    let bytes = serialize(&transaction);
    let exact = ExactTransaction::new(transaction.txid(), transaction.wtxid(), &bytes);
    let block_hash = hash(95);
    let block_height = 8;
    let mut calls = relay_prefix();
    calls.extend(exact_lookup_calls(
        transaction.txid(),
        &transaction,
        Some(block_hash),
        2,
    ));
    calls.extend([
        ScriptedCall::ok(
            "getblockheader",
            json!([block_hash, true]),
            json!({"hash": block_hash, "height": block_height}),
        ),
        ScriptedCall::ok("getblockhash", json!([block_height]), json!(block_hash)),
    ]);
    let (client, rpc) = client(calls);

    let result = client.relay_exact(exact).expect("canonical confirmation");
    assert_eq!(
        result.observation(),
        CoreRelayObservation::Confirmed {
            block_hash,
            block_height,
        }
    );
    rpc.assert_finished();
}

#[test]
fn relay_rebroadcasts_exact_bytes_found_only_in_stale_block() {
    let transaction = relay_transaction_with_inputs(&[20]);
    let bytes = serialize(&transaction);
    let exact = ExactTransaction::new(transaction.txid(), transaction.wtxid(), &bytes);
    let raw = hex::encode(&bytes);
    let stale_block = hash(98);
    let anchor = tip(99);
    let mut calls = relay_prefix();
    calls.extend(exact_lookup_calls(
        transaction.txid(),
        &transaction,
        Some(stale_block),
        0,
    ));
    calls.extend(absent_unspent_calls(&transaction, anchor));
    calls.extend([
        ScriptedCall::ok(
            "testmempoolaccept",
            json!([[raw.clone()], 0]),
            mempool_acceptance(&transaction, true),
        ),
        ScriptedCall::ok(
            "sendrawtransaction",
            json!([raw, 0]),
            json!(transaction.txid()),
        ),
    ]);
    let (client, rpc) = client(calls);

    let result = client.relay_exact(exact).expect("stale tx rebroadcast");
    assert_eq!(
        result.observation(),
        CoreRelayObservation::BroadcastAccepted
    );
    rpc.assert_finished();
}

#[test]
fn relay_rebroadcasts_when_different_witness_exists_only_in_stale_block() {
    let transaction = relay_transaction_with_inputs(&[21]);
    let bytes = serialize(&transaction);
    let exact = ExactTransaction::new(transaction.txid(), transaction.wtxid(), &bytes);
    let raw = hex::encode(&bytes);
    let mut stale = transaction.clone();
    stale.input[0].witness.script_witness.push(vec![0x51, 0x22]);
    assert_eq!(stale.txid(), transaction.txid());
    assert_ne!(stale.wtxid(), transaction.wtxid());
    let mut calls = relay_prefix();
    calls.extend(exact_lookup_calls(
        transaction.txid(),
        &stale,
        Some(hash(100)),
        0,
    ));
    calls.extend(absent_unspent_calls(&transaction, tip(101)));
    calls.extend([
        ScriptedCall::ok(
            "testmempoolaccept",
            json!([[raw.clone()], 0]),
            mempool_acceptance(&transaction, true),
        ),
        ScriptedCall::ok(
            "sendrawtransaction",
            json!([raw, 0]),
            json!(transaction.txid()),
        ),
    ]);
    let (client, rpc) = client(calls);

    let result = client.relay_exact(exact).expect("exact bytes rebroadcast");
    assert_eq!(
        result.observation(),
        CoreRelayObservation::BroadcastAccepted
    );
    rpc.assert_finished();
}

#[test]
fn relay_absence_fails_closed_when_tip_changes() {
    let transaction = relay_transaction_with_inputs(&[19]);
    let bytes = serialize(&transaction);
    let exact = ExactTransaction::new(transaction.txid(), transaction.wtxid(), &bytes);
    let original = tip(96);
    let changed = tip(97);
    let input = transaction.input[0].previous_output;
    let mut calls = relay_prefix();
    calls.push(exact_lookup_not_found(transaction.txid()));
    calls.extend(stable_tip_calls(original));
    calls.push(ScriptedCall::ok(
        "gettxout",
        json!([input.txid, input.vout, true]),
        unspent_result(original),
    ));
    calls.extend(stable_tip_calls(changed));
    let (client, rpc) = client(calls);

    assert!(matches!(
        client.relay_exact(exact),
        Err(ElementsCoreError::TipChanged { expected, actual })
            if expected == original && actual == changed
    ));
    rpc.assert_finished();
}

#[test]
fn relay_policy_rejection_reason_is_bounded_and_exposed() {
    let long_reason = "x".repeat(MAX_BACKEND_ERROR_CHARS + 100);
    let acceptance: MempoolAcceptance = serde_json::from_value(json!({
        "allowed": false,
        "reject-reason": long_reason,
    }))
    .expect("mempool acceptance");
    let result = CoreRelayAttemptResult::policy_rejected(
        CoreRelayObservation::Absent,
        acceptance.reject_reason.as_deref().map(bounded_excerpt),
    );

    assert!(result.was_policy_rejected());
    let reason = result.policy_rejection_reason().expect("rejection reason");
    assert!(reason.ends_with('…'));
    assert_eq!(reason.chars().count(), MAX_BACKEND_ERROR_CHARS + 1);
}

#[test]
fn bounds_duplicates_and_invalid_config_fail_before_rpc() {
    let mut bounded = config();
    bounded.max_scan_scripts = 1;
    bounded.max_prevouts = 1;
    bounded.max_required_anchors = 1;
    let (client, rpc) = client_with_config(&bounded, []);
    let script = Script::from(vec![0x51]);
    assert!(matches!(
        client.scan_unspent_scripts(&[script, Script::from(vec![0x52])]),
        Err(ElementsCoreError::TooManyScanScripts { .. })
    ));
    let outpoint = OutPoint::new(Txid::from_byte_array([70; 32]), 0);
    assert!(matches!(
        client.unspent_prevouts(&[outpoint, outpoint], &[]),
        Err(ElementsCoreError::TooManyPrevouts { .. })
    ));
    assert!(matches!(
        client.unspent_prevouts(&[], &[tip(1), tip(2)]),
        Err(ElementsCoreError::TooManyRequiredAnchors { .. })
    ));
    rpc.assert_finished();

    let mut invalid = config();
    invalid.max_response_bytes = 1;
    assert!(matches!(
        ElementsCoreClient::new(invalid, chain()),
        Err(ElementsCoreError::InvalidConfiguration(_))
    ));
}

#[test]
fn operation_request_and_raw_transaction_bounds_are_enforced() {
    let mut bounded = config();
    bounded.request_timeout = Duration::from_millis(25);
    bounded.scan_timeout = Duration::from_secs(1);
    let anchor = tip(71);
    let mut calls = stable_tip_calls(anchor);
    calls.extend(stable_tip_calls(anchor));
    let (client, rpc) = client_with_config(&bounded, calls);
    client
        .scan_unspent_scripts(&[])
        .expect("bounded empty scan");
    let timeouts = rpc.timeouts.lock().expect("recorded timeouts");
    assert!(!timeouts.is_empty());
    assert!(timeouts.iter().all(|timeout| {
        !timeout.operation_limited && timeout.duration <= bounded.request_timeout
    }));
    drop(timeouts);
    rpc.assert_finished();

    let mut request_bounded = config();
    request_bounded.url = "http://127.0.0.1:1".to_owned();
    request_bounded.max_request_bytes = 1;
    let client = ElementsCoreClient::new(request_bounded, chain()).expect("bounded client");
    assert!(matches!(
        client.probe(),
        Err(ElementsCoreError::RequestTooLarge { maximum: 1, .. })
    ));

    let transaction = relay_transaction();
    let bytes = serialize(&transaction);
    let exact = ExactTransaction::new(transaction.txid(), transaction.wtxid(), &bytes);
    let mut raw_bounded = config();
    raw_bounded.max_raw_transaction_bytes = bytes.len() - 1;
    let (client, rpc) = client_with_config(&raw_bounded, []);
    assert!(matches!(
        client.relay_exact(exact),
        Err(ElementsCoreError::RawTransactionTooLarge { .. })
    ));
    rpc.assert_finished();
}

#[test]
fn envelope_validation_and_auth_debug_are_bounded_and_redacted() {
    assert!(matches!(
        parse_rpc_envelope(
            "test",
            1,
            StatusCode::OK,
            br#"{"result":{},"error":null,"id":2}"#,
        ),
        Err(ElementsCoreError::InvalidRpcResponse(_))
    ));
    let long = "x".repeat(MAX_BACKEND_ERROR_CHARS + 100);
    let body = serde_json::to_vec(&json!({
        "result": null,
        "error": {"code": -1, "message": long},
        "id": 1,
    }))
    .expect("envelope");
    let ElementsCoreError::RpcRejected { message, .. } =
        parse_rpc_envelope("test", 1, StatusCode::INTERNAL_SERVER_ERROR, &body)
            .expect_err("RPC rejection")
    else {
        panic!("wrong error");
    };
    assert!(message.chars().count() <= MAX_BACKEND_ERROR_CHARS + 1);

    let auth = ElementsCoreAuth::Basic {
        username: "alice".to_owned(),
        password: "super secret".to_owned(),
    };
    let debug = format!("{auth:?}");
    assert!(debug.contains("alice"));
    assert!(!debug.contains("super secret"));
}

#[test]
fn backend_unavailability_classification_is_stable() {
    let unavailable = [
        ElementsCoreError::BackendUnavailable("offline".to_owned()),
        ElementsCoreError::AuthenticationFailed,
        ElementsCoreError::InvalidCookie,
        ElementsCoreError::InitialBlockDownload,
        ElementsCoreError::TxIndexNotSynced,
        ElementsCoreError::OperationTimedOut { operation: "probe" },
        ElementsCoreError::RelayViewChanged,
        ElementsCoreError::RelayBlockNotCanonical {
            height: TIP_HEIGHT,
            reported: hash(1),
            actual: hash(2),
        },
        ElementsCoreError::TipChanged {
            expected: tip(1),
            actual: tip(2),
        },
        ElementsCoreError::RpcRejected {
            method: "getrawtransaction",
            code: -5,
            message: "not found".to_owned(),
        },
        ElementsCoreError::RpcRejected {
            method: "getblockchaininfo",
            code: -28,
            message: "loading".to_owned(),
        },
    ];
    assert!(
        unavailable
            .iter()
            .all(ElementsCoreError::is_backend_unavailable)
    );

    assert!(!ElementsCoreError::InvalidRpcResponse("bad data".to_owned()).is_backend_unavailable());
    assert!(
        !ElementsCoreError::RpcRejected {
            method: "sendrawtransaction",
            code: -26,
            message: "policy rejection".to_owned(),
        }
        .is_backend_unavailable()
    );
}

#[test]
#[cfg(unix)]
fn cookie_requires_an_owner_only_regular_file() {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let directory = tempfile::tempdir().expect("temporary directory");
    let cookie = directory.path().join(".cookie");
    fs::write(&cookie, b"user:password\n").expect("write cookie");
    fs::set_permissions(&cookie, fs::Permissions::from_mode(0o600)).expect("protect cookie");
    let (user, password) = read_cookie(&cookie).expect("valid cookie");
    assert_eq!(user.as_str(), "user");
    assert_eq!(password.as_str(), "password");

    fs::set_permissions(&cookie, fs::Permissions::from_mode(0o644)).expect("weaken cookie");
    assert!(matches!(
        read_cookie(&cookie),
        Err(ElementsCoreError::InvalidCookie)
    ));

    fs::set_permissions(&cookie, fs::Permissions::from_mode(0o600)).expect("restore cookie mode");
    let alias = directory.path().join("cookie-link");
    symlink(&cookie, &alias).expect("create cookie symlink");
    assert!(read_cookie(&alias).is_err());
}

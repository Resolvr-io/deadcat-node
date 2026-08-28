use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use deadcat_rfq_provider::{
    InventorySource as _, ProviderId, ProviderIdentity, SettlementChainSource as _,
};
use deadcat_rfq_wallet::{KdfParams, PersistentRfqWallet};
use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::encode::serialize_hex;
use elements::hashes::Hash as _;
use elements::secp256k1_zkp::Secp256k1;
use elements::secp256k1_zkp::rand::thread_rng;
use elements::{
    AssetId, BlockHash, LockTime, OutPoint, Transaction, TxIn, TxOut, TxOutSecrets, TxOutWitness,
    Txid,
};
use tempfile::{TempDir, tempdir};

use super::*;

const PASSPHRASE: &[u8] = b"elements-source unit-test passphrase";
const SCAN_HEIGHT: u32 = 11;
const CREATION_HEIGHT: u32 = 9;

fn hash(marker: u8) -> BlockHash {
    BlockHash::from_byte_array([marker; 32])
}

fn asset(marker: u8) -> AssetId {
    AssetId::from_byte_array([marker; 32])
}

fn identity() -> ProviderIdentity {
    ProviderIdentity::new(ProviderId::new([41; 32]), hash(42), asset(43))
}

fn test_wallet() -> (TempDir, SharedRfqWallet) {
    let directory = tempdir().expect("temporary wallet directory");
    let persistent = PersistentRfqWallet::create_with_kdf(
        directory.path().join("wallet.redb"),
        identity(),
        PASSPHRASE,
        KdfParams::new(8 * 1_024, 1, 1).expect("bounded test KDF"),
    )
    .expect("persistent wallet");
    (directory, SharedRfqWallet::new(persistent))
}

fn config() -> ElementsCoreConfig {
    ElementsCoreConfig::new("http://127.0.0.1:7041", ElementsCoreAuth::None)
}

fn assert_runtime_source<T>()
where
    T: Clone
        + Send
        + Sync
        + InventorySource<Error = ElementsCoreSourceError>
        + SettlementChainSource<Error = ElementsCoreSourceError>,
{
}

fn confidential_transaction(
    destination: &deadcat_rfq_provider::ConfidentialDestination,
    asset: AssetId,
    amount: u64,
) -> Transaction {
    let explicit = TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(amount),
        nonce: Nonce::Null,
        script_pubkey: destination.script_pubkey().clone(),
        witness: TxOutWitness::default(),
    };
    let (confidential, _, _, _) = explicit
        .to_non_last_confidential(
            &mut thread_rng(),
            &Secp256k1::new(),
            destination.blinding_public_key(),
            &[TxOutSecrets::new(
                asset,
                AssetBlindingFactor::zero(),
                amount,
                ValueBlindingFactor::zero(),
            )],
        )
        .expect("blind fixture output");
    Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![confidential],
    }
}

#[derive(Clone)]
struct ScanEntry {
    outpoint: OutPoint,
    height: u32,
    script: Script,
}

struct MockState {
    block_hashes: BTreeMap<u32, VecDeque<BlockHash>>,
    best_blocks: VecDeque<BlockHash>,
    chain: String,
    initial_block_download: bool,
    sidechain_info: JsonValue,
    asset_labels: JsonValue,
    blockchain_height: u32,
    scan_best_block: BlockHash,
    scan_success: bool,
    scan_entries: Vec<ScanEntry>,
    transactions: BTreeMap<Txid, Transaction>,
    unspent: BTreeSet<OutPoint>,
    coinbase: BTreeSet<OutPoint>,
    confirmations: BTreeMap<OutPoint, u64>,
    gettxout_best_block: BlockHash,
    txindex: Option<bool>,
    calls: Vec<(&'static str, JsonValue)>,
    rpc_timeouts: Vec<(&'static str, RpcCallTimeout)>,
    call_delays: BTreeMap<&'static str, Duration>,
}

impl MockState {
    fn new() -> Self {
        let genesis = identity().genesis_hash();
        let tip = hash(90);
        Self {
            block_hashes: BTreeMap::from([
                (0, VecDeque::from([genesis])),
                (CREATION_HEIGHT, VecDeque::from([hash(89)])),
                (SCAN_HEIGHT, VecDeque::from([tip])),
            ]),
            best_blocks: VecDeque::from([tip]),
            chain: ELEMENTS_REGTEST_CHAIN.to_owned(),
            initial_block_download: false,
            sidechain_info: json!({"pegged_asset": identity().policy_asset().to_string()}),
            asset_labels: json!({"bitcoin": identity().policy_asset().to_string()}),
            blockchain_height: SCAN_HEIGHT,
            scan_best_block: tip,
            scan_success: true,
            scan_entries: Vec::new(),
            transactions: BTreeMap::new(),
            unspent: BTreeSet::new(),
            coinbase: BTreeSet::new(),
            confirmations: BTreeMap::new(),
            gettxout_best_block: tip,
            txindex: Some(true),
            calls: Vec::new(),
            rpc_timeouts: Vec::new(),
            call_delays: BTreeMap::new(),
        }
    }

    fn next_block_hash(&mut self, height: u32) -> BlockHash {
        let hashes = self
            .block_hashes
            .get_mut(&height)
            .unwrap_or_else(|| panic!("unexpected block height {height}"));
        if hashes.len() > 1 {
            hashes.pop_front().expect("nonempty block-hash sequence")
        } else {
            *hashes.front().expect("nonempty block-hash sequence")
        }
    }

    fn next_best_block(&mut self) -> BlockHash {
        if self.best_blocks.len() > 1 {
            self.best_blocks
                .pop_front()
                .expect("nonempty best-block sequence")
        } else {
            *self
                .best_blocks
                .front()
                .expect("nonempty best-block sequence")
        }
    }
}

struct MockRpc {
    state: Mutex<MockState>,
    after_scan: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl MockRpc {
    fn new(state: MockState) -> Self {
        Self {
            state: Mutex::new(state),
            after_scan: Mutex::new(None),
        }
    }

    fn set_after_scan(&self, hook: impl FnOnce() + Send + 'static) {
        *self.after_scan.lock().expect("after-scan lock") = Some(Box::new(hook));
    }

    fn calls(&self) -> Vec<(&'static str, JsonValue)> {
        self.state.lock().expect("mock state").calls.clone()
    }

    fn rpc_timeouts(&self) -> Vec<(&'static str, RpcCallTimeout)> {
        self.state.lock().expect("mock state").rpc_timeouts.clone()
    }
}

impl RpcTransport for MockRpc {
    fn call(
        &self,
        method: &'static str,
        params: JsonValue,
        budget: RpcCallBudget,
    ) -> Result<JsonValue, ElementsCoreSourceError> {
        let timeout = budget.timeout()?;
        let delay = {
            let mut state = self.state.lock().expect("mock state");
            state.calls.push((method, params.clone()));
            state.rpc_timeouts.push((method, timeout));
            state.call_delays.get(method).copied()
        };
        if let Some(delay) = delay {
            if delay >= timeout.duration {
                thread::sleep(timeout.duration);
                return if timeout.operation_limited {
                    Err(ElementsCoreSourceError::OperationTimedOut {
                        operation: timeout.operation,
                    })
                } else {
                    Err(ElementsCoreSourceError::BackendUnavailable(format!(
                        "mock Elements RPC {method} request timed out"
                    )))
                };
            }
            thread::sleep(delay);
        }
        let result = {
            let mut state = self.state.lock().expect("mock state");
            match method {
                "getblockhash" => {
                    let height = params[0].as_u64().expect("numeric block height");
                    let height = u32::try_from(height).expect("u32 block height");
                    json!(state.next_block_hash(height))
                }
                "getbestblockhash" => json!(state.next_best_block()),
                "getblockchaininfo" => json!({
                    "chain": state.chain,
                    "blocks": state.blockchain_height,
                    "bestblockhash": state.scan_best_block,
                    "initialblockdownload": state.initial_block_download,
                }),
                "getsidechaininfo" => state.sidechain_info.clone(),
                "dumpassetlabels" => state.asset_labels.clone(),
                "getindexinfo" => match state.txindex {
                    Some(synced) => json!({"txindex": {"synced": synced}}),
                    None => json!({}),
                },
                "scantxoutset" => {
                    let unspents = state
                        .scan_entries
                        .iter()
                        .map(|entry| {
                            json!({
                                "txid": entry.outpoint.txid,
                                "vout": entry.outpoint.vout,
                                "height": entry.height,
                                "scriptPubKey": entry.script,
                            })
                        })
                        .collect::<Vec<_>>();
                    json!({
                        "success": state.scan_success,
                        "height": state.blockchain_height,
                        "bestblock": state.scan_best_block,
                        "unspents": unspents,
                    })
                }
                "gettxout" => {
                    assert_eq!(params[2], json!(true), "lookup must include mempool");
                    let txid: Txid =
                        serde_json::from_value(params[0].clone()).expect("txid parameter");
                    let vout = params[1].as_u64().expect("vout parameter");
                    let outpoint = OutPoint::new(txid, u32::try_from(vout).expect("u32 vout"));
                    if !state.unspent.contains(&outpoint) {
                        JsonValue::Null
                    } else {
                        let txout = &state.transactions[&txid].output[outpoint.vout as usize];
                        let confirmations = state
                            .confirmations
                            .get(&outpoint)
                            .copied()
                            .or_else(|| {
                                state
                                    .scan_entries
                                    .iter()
                                    .find(|entry| entry.outpoint == outpoint)
                                    .map(|entry| {
                                        u64::from(state.blockchain_height - entry.height) + 1
                                    })
                            })
                            .unwrap_or(COINBASE_MATURITY_CONFIRMATIONS);
                        json!({
                            "bestblock": state.gettxout_best_block,
                            "confirmations": confirmations,
                            "coinbase": state.coinbase.contains(&outpoint),
                            "scriptPubKey": {"hex": hex::encode(txout.script_pubkey.as_bytes())},
                        })
                    }
                }
                "getrawtransaction" => {
                    let txid: Txid =
                        serde_json::from_value(params[0].clone()).expect("txid parameter");
                    json!(serialize_hex(
                        state.transactions.get(&txid).expect("fixture transaction")
                    ))
                }
                _ => panic!("unexpected RPC method {method}"),
            }
        };
        if method == "scantxoutset"
            && let Some(hook) = self.after_scan.lock().expect("after-scan lock").take()
        {
            hook();
        }
        Ok(result)
    }
}

fn test_source(wallet: SharedRfqWallet, rpc: Arc<MockRpc>) -> ElementsCoreSource {
    ElementsCoreSource::from_parts(&config(), wallet, rpc)
}

fn test_probe(
    config: &ElementsCoreConfig,
    rpc: &MockRpc,
) -> Result<ElementsCoreChainStatus, ElementsCoreSourceError> {
    probe_elements_core_with_transport(rpc, config.request_timeout, config.startup_timeout)
}

fn funded_inventory_fixture(
    wallet: &SharedRfqWallet,
) -> (
    deadcat_rfq_provider::ConfidentialDestination,
    Transaction,
    OutPoint,
) {
    let destination = wallet
        .fresh_inventory_destination()
        .expect("inventory destination");
    let transaction = confidential_transaction(&destination, asset(71), 42_000);
    let outpoint = OutPoint::new(transaction.txid(), 0);
    (destination, transaction, outpoint)
}

#[test]
fn startup_probe_is_wallet_independent_and_pins_the_reported_tip() {
    let rpc = MockRpc::new(MockState::new());
    let status = test_probe(&config(), &rpc).expect("healthy Elements Core");

    assert_eq!(status.network(), ElementsCoreNetwork::ElementsRegtest);
    assert_eq!(status.genesis_hash(), identity().genesis_hash());
    assert_eq!(status.pegged_asset(), identity().policy_asset());
    assert_eq!(status.tip_height(), SCAN_HEIGHT);
    assert_eq!(status.tip_hash(), hash(90));
    assert_eq!(
        rpc.calls(),
        vec![
            ("getblockhash", json!([0])),
            ("getblockchaininfo", json!([])),
            ("getsidechaininfo", json!([])),
            ("dumpassetlabels", json!([])),
            ("getblockhash", json!([SCAN_HEIGHT])),
            ("getindexinfo", json!([])),
        ]
    );
}

#[test]
fn startup_probe_requires_exact_regtest_chain_and_completed_ibd() {
    let mut wrong_network = MockState::new();
    wrong_network.chain = "liquidv1".to_owned();
    assert!(matches!(
        test_probe(&config(), &MockRpc::new(wrong_network)),
        Err(ElementsCoreSourceError::UnsupportedChain { actual }) if actual == "liquidv1"
    ));

    let mut downloading = MockState::new();
    downloading.initial_block_download = true;
    assert!(matches!(
        test_probe(&config(), &MockRpc::new(downloading)),
        Err(ElementsCoreSourceError::InitialBlockDownload)
    ));
}

#[test]
fn startup_probe_requires_a_valid_sidechain_pegged_asset() {
    let mut missing = MockState::new();
    missing.sidechain_info = json!({});
    assert!(matches!(
        test_probe(&config(), &MockRpc::new(missing)),
        Err(ElementsCoreSourceError::MissingPeggedAsset)
    ));

    let mut malformed = MockState::new();
    malformed.sidechain_info = json!({"pegged_asset": "not-an-asset-id"});
    assert!(matches!(
        test_probe(&config(), &MockRpc::new(malformed)),
        Err(ElementsCoreSourceError::InvalidPeggedAsset)
    ));

    let mut wrong_shape = MockState::new();
    wrong_shape.sidechain_info = json!([]);
    assert!(matches!(
        test_probe(&config(), &MockRpc::new(wrong_shape)),
        Err(ElementsCoreSourceError::InvalidPeggedAsset)
    ));
}

#[test]
fn startup_probe_requires_a_valid_builtin_bitcoin_asset_label() {
    let mut missing = MockState::new();
    missing.asset_labels = json!({"not-bitcoin": asset(99).to_string()});
    assert!(matches!(
        test_probe(&config(), &MockRpc::new(missing)),
        Err(ElementsCoreSourceError::MissingBitcoinAssetLabel)
    ));

    let mut malformed = MockState::new();
    malformed.asset_labels = json!({"bitcoin": "not-an-asset-id"});
    assert!(matches!(
        test_probe(&config(), &MockRpc::new(malformed)),
        Err(ElementsCoreSourceError::InvalidBitcoinAssetLabel)
    ));

    let mut wrong_type = MockState::new();
    wrong_type.asset_labels = json!({"bitcoin": 42});
    assert!(matches!(
        test_probe(&config(), &MockRpc::new(wrong_type)),
        Err(ElementsCoreSourceError::InvalidBitcoinAssetLabel)
    ));
}

#[test]
fn startup_probe_requires_the_builtin_bitcoin_label_to_match_the_pegged_asset() {
    let mut mismatch = MockState::new();
    mismatch.asset_labels = json!({"bitcoin": asset(99).to_string()});

    assert!(matches!(
        test_probe(&config(), &MockRpc::new(mismatch)),
        Err(ElementsCoreSourceError::BitcoinAssetLabelMismatch {
            pegged_asset,
            label_asset,
        }) if pegged_asset == identity().policy_asset() && label_asset == asset(99)
    ));
}

#[test]
fn startup_probe_rejects_an_inconsistent_tip_and_unusable_txindex() {
    let mut inconsistent = MockState::new();
    inconsistent
        .block_hashes
        .insert(SCAN_HEIGHT, VecDeque::from([hash(91)]));
    let error = test_probe(&config(), &MockRpc::new(inconsistent))
        .expect_err("reported tip must be pinned by height");
    assert!(matches!(
        error,
        ElementsCoreSourceError::InconsistentChainTip {
            height: SCAN_HEIGHT,
            reported,
            actual,
        } if reported == hash(90) && actual == hash(91)
    ));

    let mut missing = MockState::new();
    missing.txindex = None;
    assert!(matches!(
        test_probe(&config(), &MockRpc::new(missing)),
        Err(ElementsCoreSourceError::TxIndexUnavailable)
    ));

    let mut unsynced = MockState::new();
    unsynced.txindex = Some(false);
    assert!(matches!(
        test_probe(&config(), &MockRpc::new(unsynced)),
        Err(ElementsCoreSourceError::TxIndexNotSynced)
    ));
}

#[test]
fn startup_probe_has_one_bounded_whole_operation_deadline() {
    let mut bounded = config();
    bounded.request_timeout = Duration::from_secs(1);
    bounded.startup_timeout = Duration::from_millis(20);
    let mut state = MockState::new();
    state
        .call_delays
        .insert("getblockhash", Duration::from_secs(1));
    let rpc = MockRpc::new(state);

    assert!(matches!(
        test_probe(&bounded, &rpc),
        Err(ElementsCoreSourceError::OperationTimedOut {
            operation: STARTUP_OPERATION
        })
    ));
    let timeouts = rpc.rpc_timeouts();
    assert_eq!(timeouts.len(), 1);
    assert!(timeouts[0].1.operation_limited);
    assert!(timeouts[0].1.duration <= bounded.startup_timeout);
}

#[test]
fn confirmed_scan_recovers_exact_full_wallet_output() {
    let (_directory, wallet) = test_wallet();
    let (destination, transaction, outpoint) = funded_inventory_fixture(&wallet);
    let mut state = MockState::new();
    state.scan_entries.push(ScanEntry {
        outpoint,
        height: CREATION_HEIGHT,
        script: destination.script_pubkey().clone(),
    });
    state
        .transactions
        .insert(transaction.txid(), transaction.clone());
    state.unspent.insert(outpoint);
    let rpc = Arc::new(MockRpc::new(state));
    let source = test_source(wallet, rpc.clone());

    let snapshot = source.inventory_snapshot().expect("inventory snapshot");
    assert_eq!(snapshot.identity(), identity());
    assert_eq!(
        snapshot.anchor(),
        WalletScanAnchor::new(hash(90), SCAN_HEIGHT)
    );
    assert_eq!(snapshot.outputs().len(), 1);
    let output = &snapshot.outputs()[0];
    assert_eq!(output.outpoint(), outpoint);
    assert_eq!(output.asset(), asset(71));
    assert_eq!(output.amount(), 42_000);
    assert_eq!(output.txout(), &transaction.output[0]);
    assert!(output.txout().witness.rangeproof.is_some());
    assert!(output.txout().witness.surjection_proof.is_some());

    let scan = rpc
        .calls()
        .into_iter()
        .find(|(method, _)| *method == "scantxoutset")
        .expect("scan call");
    assert_eq!(
        scan.1[1][0],
        json!(format!(
            "raw({})",
            hex::encode(destination.script_pubkey().as_bytes())
        ))
    );
}

#[test]
fn scan_match_spent_in_mempool_is_excluded_from_inventory() {
    let (_directory, wallet) = test_wallet();
    let (destination, transaction, outpoint) = funded_inventory_fixture(&wallet);
    let mut state = MockState::new();
    state.scan_entries.push(ScanEntry {
        outpoint,
        height: CREATION_HEIGHT,
        script: destination.script_pubkey().clone(),
    });
    state.transactions.insert(transaction.txid(), transaction);
    let source = test_source(wallet, Arc::new(MockRpc::new(state)));

    let snapshot = source
        .inventory_snapshot()
        .expect("spent candidate is conservatively omitted");
    assert!(snapshot.outputs().is_empty());
}

#[test]
fn catalog_and_scan_anchor_races_fail_closed() {
    let (_directory, wallet) = test_wallet();
    let (_destination, _transaction, _outpoint) = funded_inventory_fixture(&wallet);
    let rpc = Arc::new(MockRpc::new(MockState::new()));
    let racing_wallet = wallet.clone();
    rpc.set_after_scan(move || {
        racing_wallet
            .fresh_inventory_destination()
            .expect("concurrent durable destination");
    });
    let source = test_source(wallet, rpc);
    assert!(matches!(
        source.inventory_snapshot(),
        Err(ElementsCoreSourceError::CatalogChangedDuringScan {
            before: 1,
            after: 2
        })
    ));

    let (_directory, wallet) = test_wallet();
    let (_destination, _transaction, _outpoint) = funded_inventory_fixture(&wallet);
    let mut state = MockState::new();
    state
        .block_hashes
        .insert(SCAN_HEIGHT, VecDeque::from([hash(91)]));
    let source = test_source(wallet, Arc::new(MockRpc::new(state)));
    assert!(matches!(
        source.inventory_snapshot(),
        Err(ElementsCoreSourceError::ScanAnchorChanged {
            expected,
            actual
        }) if expected == hash(90) && actual == hash(91)
    ));

    let (_directory, wallet) = test_wallet();
    let (destination, transaction, outpoint) = funded_inventory_fixture(&wallet);
    let mut state = MockState::new();
    state.scan_entries.push(ScanEntry {
        outpoint,
        height: CREATION_HEIGHT,
        script: destination.script_pubkey().clone(),
    });
    state.transactions.insert(transaction.txid(), transaction);
    state.unspent.insert(outpoint);
    state.gettxout_best_block = hash(91);
    let source = test_source(wallet, Arc::new(MockRpc::new(state)));
    assert!(matches!(
        source.inventory_snapshot(),
        Err(ElementsCoreSourceError::ScanAnchorChanged {
            expected,
            actual
        }) if expected == hash(90) && actual == hash(91)
    ));
}

#[test]
fn empty_catalog_uses_a_pinned_tip_without_scantxoutset() {
    let (_directory, wallet) = test_wallet();
    let rpc = Arc::new(MockRpc::new(MockState::new()));
    let snapshot = test_source(wallet, rpc.clone())
        .inventory_snapshot()
        .expect("empty inventory snapshot");
    assert!(snapshot.outputs().is_empty());
    assert_eq!(
        snapshot.anchor(),
        WalletScanAnchor::new(hash(90), SCAN_HEIGHT)
    );
    assert!(
        rpc.calls()
            .iter()
            .all(|(method, _)| *method != "scantxoutset")
    );
}

#[test]
fn settlement_prevouts_are_mempool_checked_ordered_and_complete() {
    let (_directory, wallet) = test_wallet();
    let first_destination = wallet
        .fresh_inventory_destination()
        .expect("first destination");
    let second_destination = wallet
        .fresh_inventory_destination()
        .expect("second destination");
    let first = confidential_transaction(&first_destination, asset(72), 1_000);
    let second = confidential_transaction(&second_destination, asset(73), 2_000);
    let first_outpoint = OutPoint::new(first.txid(), 0);
    let second_outpoint = OutPoint::new(second.txid(), 0);
    let mut state = MockState::new();
    state.transactions.insert(first.txid(), first.clone());
    state.transactions.insert(second.txid(), second.clone());
    state.unspent.extend([first_outpoint, second_outpoint]);
    let rpc = Arc::new(MockRpc::new(state));
    let source = test_source(wallet, rpc.clone());

    let requested = [second_outpoint, first_outpoint];
    let prevouts = source
        .unspent_prevouts(&requested)
        .expect("authoritative prevouts");
    assert_eq!(
        prevouts
            .iter()
            .map(|prevout| prevout.outpoint())
            .collect::<Vec<_>>(),
        requested
    );
    assert_eq!(prevouts[0].txout(), &second.output[0]);
    assert_eq!(prevouts[1].txout(), &first.output[0]);
    assert!(prevouts[0].txout().witness.rangeproof.is_some());
    assert_eq!(
        rpc.calls()
            .iter()
            .filter(|(method, params)| *method == "gettxout" && params[2] == json!(true))
            .count(),
        2
    );
}

#[test]
fn coinbase_maturity_excludes_inventory_and_is_enforced_at_settlement_boundary() {
    let (_directory, wallet) = test_wallet();
    let (destination, transaction, outpoint) = funded_inventory_fixture(&wallet);
    let mut state = MockState::new();
    state.scan_entries.push(ScanEntry {
        outpoint,
        height: CREATION_HEIGHT,
        script: destination.script_pubkey().clone(),
    });
    state
        .transactions
        .insert(transaction.txid(), transaction.clone());
    state.unspent.insert(outpoint);
    state.coinbase.insert(outpoint);
    let rpc = Arc::new(MockRpc::new(state));
    let source = test_source(wallet, rpc.clone());

    let snapshot = source
        .inventory_snapshot()
        .expect("immature coinbase is conservatively omitted");
    assert!(snapshot.outputs().is_empty());
    assert_eq!(
        rpc.calls()
            .iter()
            .filter(|(method, _)| *method == "getrawtransaction")
            .count(),
        0,
        "an immature coinbase must be rejected before materialization"
    );

    rpc.state
        .lock()
        .expect("mock state")
        .confirmations
        .insert(outpoint, COINBASE_MATURITY_CONFIRMATIONS - 1);
    assert!(matches!(
        source.unspent_prevouts(&[outpoint]),
        Err(ElementsCoreSourceError::ImmatureCoinbasePrevout {
            outpoint: actual,
            confirmations
        }) if actual == outpoint && confirmations == COINBASE_MATURITY_CONFIRMATIONS - 1
    ));

    rpc.state
        .lock()
        .expect("mock state")
        .confirmations
        .insert(outpoint, COINBASE_MATURITY_CONFIRMATIONS);
    let prevouts = source
        .unspent_prevouts(&[outpoint])
        .expect("coinbase is eligible at exactly 100 confirmations");
    assert_eq!(prevouts[0].outpoint(), outpoint);
    assert_eq!(prevouts[0].txout(), &transaction.output[0]);

    let mature_scan_height = CREATION_HEIGHT + COINBASE_MATURITY_CONFIRMATIONS as u32 - 1;
    {
        let mut state = rpc.state.lock().expect("mock state");
        state.blockchain_height = mature_scan_height;
        state
            .block_hashes
            .insert(mature_scan_height, VecDeque::from([hash(90)]));
    }
    let mature_snapshot = source
        .inventory_snapshot()
        .expect("coinbase is inventory-eligible at exactly 100 confirmations");
    assert_eq!(mature_snapshot.outputs().len(), 1);
    assert_eq!(mature_snapshot.outputs()[0].outpoint(), outpoint);
}

#[test]
fn materialization_caches_shared_creation_blocks_and_transactions_per_operation() {
    let (_directory, wallet) = test_wallet();
    let first_destination = wallet
        .fresh_inventory_destination()
        .expect("first destination");
    let second_destination = wallet
        .fresh_inventory_destination()
        .expect("second destination");
    let first = confidential_transaction(&first_destination, asset(76), 5_000);
    let second = confidential_transaction(&second_destination, asset(77), 6_000);
    let transaction = Transaction {
        output: vec![first.output[0].clone(), second.output[0].clone()],
        ..first
    };
    let first_outpoint = OutPoint::new(transaction.txid(), 0);
    let second_outpoint = OutPoint::new(transaction.txid(), 1);
    let mut state = MockState::new();
    state.scan_entries.extend([
        ScanEntry {
            outpoint: first_outpoint,
            height: CREATION_HEIGHT,
            script: first_destination.script_pubkey().clone(),
        },
        ScanEntry {
            outpoint: second_outpoint,
            height: CREATION_HEIGHT,
            script: second_destination.script_pubkey().clone(),
        },
    ]);
    state.transactions.insert(transaction.txid(), transaction);
    state.unspent.extend([first_outpoint, second_outpoint]);
    let rpc = Arc::new(MockRpc::new(state));
    let source = test_source(wallet, rpc.clone());

    let snapshot = source.inventory_snapshot().expect("inventory snapshot");
    assert_eq!(snapshot.outputs().len(), 2);
    let inventory_calls = rpc.calls();
    assert_eq!(
        inventory_calls
            .iter()
            .filter(|(method, params)| {
                *method == "getblockhash" && params[0] == json!(CREATION_HEIGHT)
            })
            .count(),
        1
    );
    assert_eq!(
        inventory_calls
            .iter()
            .filter(|(method, _)| *method == "getrawtransaction")
            .count(),
        1
    );

    let prevouts = source
        .unspent_prevouts(&[second_outpoint, first_outpoint])
        .expect("settlement prevouts");
    assert_eq!(prevouts.len(), 2);
    assert_eq!(
        rpc.calls()
            .iter()
            .filter(|(method, _)| *method == "getrawtransaction")
            .count(),
        2,
        "each operation should fetch the shared creating transaction once"
    );
}

#[test]
fn inventory_scan_does_not_block_settlement_checks() {
    let (_directory, wallet) = test_wallet();
    wallet
        .fresh_inventory_destination()
        .expect("inventory destination");
    let settlement_destination = wallet
        .fresh_inventory_destination()
        .expect("settlement destination");
    let transaction = confidential_transaction(&settlement_destination, asset(78), 7_000);
    let outpoint = OutPoint::new(transaction.txid(), 0);
    let mut state = MockState::new();
    state.transactions.insert(transaction.txid(), transaction);
    state.unspent.insert(outpoint);
    let rpc = Arc::new(MockRpc::new(state));
    let source = test_source(wallet, rpc.clone());

    let (scan_started_sender, scan_started_receiver) = mpsc::sync_channel(0);
    let (release_scan_sender, release_scan_receiver) = mpsc::sync_channel(0);
    rpc.set_after_scan(move || {
        scan_started_sender
            .send(())
            .expect("announce blocked inventory scan");
        release_scan_receiver
            .recv()
            .expect("release blocked inventory scan");
    });
    let inventory_source = source.clone();
    let inventory_thread = thread::spawn(move || inventory_source.inventory_snapshot());
    scan_started_receiver
        .recv_timeout(Duration::from_secs(1))
        .expect("inventory reached the scan hook");

    let settlement_source = source;
    let (settlement_sender, settlement_receiver) = mpsc::sync_channel(1);
    let settlement_thread = thread::spawn(move || {
        settlement_sender
            .send(settlement_source.unspent_prevouts(&[outpoint]))
            .expect("report settlement result");
    });
    let settlement_result = settlement_receiver.recv_timeout(Duration::from_secs(1));
    release_scan_sender
        .send(())
        .expect("release inventory after settlement check");
    let inventory_result = inventory_thread.join().expect("inventory thread");
    settlement_thread.join().expect("settlement thread");

    assert!(inventory_result.is_ok());
    assert!(
        settlement_result
            .expect("settlement must not wait for the inventory gate")
            .is_ok()
    );
}

#[test]
fn operation_deadlines_bound_inventory_and_settlement_rpc_calls() {
    let (_directory, wallet) = test_wallet();
    let mut inventory_config = config();
    inventory_config.request_timeout = Duration::from_secs(1);
    inventory_config.inventory_timeout = Duration::from_millis(20);
    let mut inventory_state = MockState::new();
    inventory_state
        .call_delays
        .insert("getblockhash", Duration::from_secs(1));
    let inventory_rpc = Arc::new(MockRpc::new(inventory_state));
    let inventory_source =
        ElementsCoreSource::from_parts(&inventory_config, wallet.clone(), inventory_rpc.clone());
    assert!(matches!(
        inventory_source.inventory_snapshot(),
        Err(ElementsCoreSourceError::OperationTimedOut {
            operation: INVENTORY_OPERATION
        })
    ));
    let inventory_timeouts = inventory_rpc.rpc_timeouts();
    assert_eq!(inventory_timeouts.len(), 1);
    assert!(inventory_timeouts[0].1.operation_limited);
    assert!(inventory_timeouts[0].1.duration <= inventory_config.inventory_timeout);

    let mut settlement_config = config();
    settlement_config.request_timeout = Duration::from_secs(1);
    settlement_config.settlement_timeout = Duration::from_millis(20);
    let mut settlement_state = MockState::new();
    settlement_state
        .call_delays
        .insert("getblockhash", Duration::from_secs(1));
    let settlement_rpc = Arc::new(MockRpc::new(settlement_state));
    let settlement_source =
        ElementsCoreSource::from_parts(&settlement_config, wallet, settlement_rpc.clone());
    assert!(matches!(
        settlement_source.unspent_prevouts(&[]),
        Err(ElementsCoreSourceError::OperationTimedOut {
            operation: SETTLEMENT_OPERATION
        })
    ));
    let settlement_timeouts = settlement_rpc.rpc_timeouts();
    assert_eq!(settlement_timeouts.len(), 1);
    assert!(settlement_timeouts[0].1.operation_limited);
    assert!(settlement_timeouts[0].1.duration <= settlement_config.settlement_timeout);
}

#[test]
fn request_timeout_caps_each_rpc_when_operation_has_more_time_remaining() {
    let (_directory, wallet) = test_wallet();
    let mut bounded = config();
    bounded.request_timeout = Duration::from_millis(25);
    bounded.inventory_timeout = Duration::from_secs(1);
    let rpc = Arc::new(MockRpc::new(MockState::new()));
    let snapshot = ElementsCoreSource::from_parts(&bounded, wallet, rpc.clone())
        .inventory_snapshot()
        .expect("empty snapshot within operation deadline");
    assert!(snapshot.outputs().is_empty());
    let timeouts = rpc.rpc_timeouts();
    assert!(!timeouts.is_empty());
    assert!(timeouts.iter().all(|(_, timeout)| {
        !timeout.operation_limited && timeout.duration <= bounded.request_timeout
    }));
}

#[test]
fn spent_prevout_tip_change_and_missing_txindex_fail_closed() {
    let (_directory, wallet) = test_wallet();
    let destination = wallet.fresh_inventory_destination().expect("destination");
    let transaction = confidential_transaction(&destination, asset(74), 3_000);
    let outpoint = OutPoint::new(transaction.txid(), 0);

    let mut spent = MockState::new();
    spent
        .transactions
        .insert(transaction.txid(), transaction.clone());
    let source = test_source(wallet.clone(), Arc::new(MockRpc::new(spent)));
    assert!(matches!(
        source.unspent_prevouts(&[outpoint]),
        Err(ElementsCoreSourceError::MissingOrSpentPrevout(actual)) if actual == outpoint
    ));

    let mut reorg = MockState::new();
    reorg
        .transactions
        .insert(transaction.txid(), transaction.clone());
    reorg.unspent.insert(outpoint);
    reorg.best_blocks = VecDeque::from([hash(90), hash(91)]);
    let source = test_source(wallet.clone(), Arc::new(MockRpc::new(reorg)));
    assert!(matches!(
        source.unspent_prevouts(&[outpoint]),
        Err(ElementsCoreSourceError::SettlementTipChanged {
            expected,
            actual
        }) if expected == hash(90) && actual == hash(91)
    ));

    let mut no_index = MockState::new();
    no_index
        .transactions
        .insert(transaction.txid(), transaction);
    no_index.unspent.insert(outpoint);
    no_index.txindex = None;
    let source = test_source(wallet, Arc::new(MockRpc::new(no_index)));
    assert!(matches!(
        source.unspent_prevouts(&[outpoint]),
        Err(ElementsCoreSourceError::TxIndexUnavailable)
    ));
}

#[test]
fn configured_bounds_duplicates_and_wrong_chain_are_rejected() {
    let (_directory, wallet) = test_wallet();
    let destination = wallet.fresh_inventory_destination().expect("destination");
    let transaction = confidential_transaction(&destination, asset(75), 4_000);
    let outpoint = OutPoint::new(transaction.txid(), 0);
    let mut state = MockState::new();
    state.transactions.insert(transaction.txid(), transaction);
    state.unspent.insert(outpoint);
    let rpc = Arc::new(MockRpc::new(state));
    let mut bounded = config();
    bounded.max_settlement_prevouts = 1;
    let source = ElementsCoreSource::from_parts(&bounded, wallet.clone(), rpc);
    assert!(matches!(
        source.unspent_prevouts(&[outpoint, outpoint]),
        Err(ElementsCoreSourceError::TooManySettlementPrevouts {
            maximum: 1,
            actual: 2
        })
    ));

    let source = test_source(wallet.clone(), Arc::new(MockRpc::new(MockState::new())));
    assert!(matches!(
        source.unspent_prevouts(&[outpoint, outpoint]),
        Err(ElementsCoreSourceError::DuplicateSettlementOutpoint(actual)) if actual == outpoint
    ));

    let mut wrong_chain = MockState::new();
    wrong_chain
        .block_hashes
        .insert(0, VecDeque::from([hash(99)]));
    let source = test_source(wallet, Arc::new(MockRpc::new(wrong_chain)));
    assert!(matches!(
        source.inventory_snapshot(),
        Err(ElementsCoreSourceError::WrongChain { expected, actual })
            if expected == identity().genesis_hash() && actual == hash(99)
    ));
}

#[test]
fn inventory_catalog_and_result_bounds_are_checked_before_materialization() {
    let (_directory, wallet) = test_wallet();
    let first = wallet
        .fresh_inventory_destination()
        .expect("first destination");
    wallet
        .fresh_inventory_destination()
        .expect("second destination");
    let mut bounded = config();
    bounded.max_scan_scripts = 1;
    let source = ElementsCoreSource::from_parts(
        &bounded,
        wallet.clone(),
        Arc::new(MockRpc::new(MockState::new())),
    );
    assert!(matches!(
        source.inventory_snapshot(),
        Err(ElementsCoreSourceError::CatalogTooLarge {
            maximum: 1,
            actual: 2
        })
    ));

    let mut state = MockState::new();
    state.scan_entries.extend([
        ScanEntry {
            outpoint: OutPoint::new(Txid::from_byte_array([81; 32]), 0),
            height: CREATION_HEIGHT,
            script: first.script_pubkey().clone(),
        },
        ScanEntry {
            outpoint: OutPoint::new(Txid::from_byte_array([82; 32]), 0),
            height: CREATION_HEIGHT,
            script: first.script_pubkey().clone(),
        },
    ]);
    bounded.max_scan_scripts = 2;
    bounded.max_scan_results = 1;
    let source = ElementsCoreSource::from_parts(&bounded, wallet, Arc::new(MockRpc::new(state)));
    assert!(matches!(
        source.inventory_snapshot(),
        Err(ElementsCoreSourceError::ScanResultTooLarge {
            maximum: 1,
            actual: 2
        })
    ));
}

#[test]
fn authentication_and_source_debug_are_redacted() {
    assert_runtime_source::<ElementsCoreSource>();
    let auth = ElementsCoreAuth::Basic {
        username: "provider".to_owned(),
        password: "do-not-print-this".to_owned(),
    };
    let auth_debug = format!("{auth:?}");
    assert!(auth_debug.contains("provider"));
    assert!(auth_debug.contains("[redacted]"));
    assert!(!auth_debug.contains("do-not-print-this"));

    let (_directory, wallet) = test_wallet();
    let source = test_source(wallet, Arc::new(MockRpc::new(MockState::new())));
    let source_debug = format!("{source:?}");
    assert!(source_debug.contains("[unlocked and redacted]"));
    assert!(!source_debug.contains("passphrase"));
}

#[cfg(unix)]
#[test]
fn cookie_reloads_require_an_owner_only_real_file() {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let directory = tempdir().expect("temporary cookie directory");
    let cookie = directory.path().join(".cookie");
    fs::write(&cookie, b"provider:secret\n").expect("write cookie");
    fs::set_permissions(&cookie, fs::Permissions::from_mode(0o600)).expect("secure cookie");
    let (username, password) = read_cookie(&cookie).expect("read secure cookie");
    assert_eq!(username.as_str(), "provider");
    assert_eq!(password.as_str(), "secret");

    fs::set_permissions(&cookie, fs::Permissions::from_mode(0o640)).expect("widen cookie mode");
    assert!(matches!(
        read_cookie(&cookie),
        Err(ElementsCoreSourceError::InvalidCookie)
    ));

    fs::set_permissions(&cookie, fs::Permissions::from_mode(0o600)).expect("restore cookie mode");
    let alias = directory.path().join("cookie-link");
    symlink(&cookie, &alias).expect("create cookie symlink");
    assert!(read_cookie(&alias).is_err());
}

#[test]
fn invalid_transport_configuration_is_rejected_without_network_access() {
    let (_directory, wallet) = test_wallet();
    let mut invalid = config();
    invalid.url = "http://user:secret@127.0.0.1:7041".to_owned();
    assert!(matches!(
        ElementsCoreSource::new(invalid, wallet.clone()),
        Err(ElementsCoreSourceError::InvalidConfiguration(_))
    ));

    let mut impossible = config();
    impossible.max_response_bytes = 1;
    assert!(matches!(
        ElementsCoreSource::new(impossible, wallet),
        Err(ElementsCoreSourceError::InvalidConfiguration(_))
    ));

    let (_directory, wallet) = test_wallet();
    let mut no_inventory_deadline = config();
    no_inventory_deadline.inventory_timeout = Duration::ZERO;
    assert!(matches!(
        ElementsCoreSource::new(no_inventory_deadline, wallet.clone()),
        Err(ElementsCoreSourceError::InvalidConfiguration(_))
    ));

    let mut no_startup_deadline = config();
    no_startup_deadline.startup_timeout = Duration::ZERO;
    assert!(matches!(
        probe_elements_core(&no_startup_deadline),
        Err(ElementsCoreSourceError::InvalidConfiguration(_))
    ));

    let mut no_settlement_deadline = config();
    no_settlement_deadline.settlement_timeout = Duration::ZERO;
    assert!(matches!(
        ElementsCoreSource::new(no_settlement_deadline, wallet),
        Err(ElementsCoreSourceError::InvalidConfiguration(_))
    ));
}

#[test]
fn production_transport_enforces_request_bound_before_connecting() {
    let (_directory, wallet) = test_wallet();
    let mut bounded = config();
    bounded.url = "http://127.0.0.1:1".to_owned();
    bounded.max_request_bytes = 1;
    let source = ElementsCoreSource::new(bounded, wallet).expect("valid bounded client config");
    assert!(matches!(
        source.inventory_snapshot(),
        Err(ElementsCoreSourceError::RequestTooLarge { maximum: 1, .. })
    ));
}

#[test]
fn rpc_envelope_validation_rejects_mismatched_ids_and_bounds_errors() {
    let body = serde_json::to_vec(&json!({
        "id": 8,
        "result": null,
        "error": null,
    }))
    .expect("JSON response");
    assert!(matches!(
        parse_rpc_envelope("fixture", 7, StatusCode::OK, &body),
        Err(ElementsCoreSourceError::InvalidRpcResponse(_))
    ));

    let long_message = "x".repeat(MAX_BACKEND_ERROR_CHARS + 100);
    let body = serde_json::to_vec(&json!({
        "id": 7,
        "result": null,
        "error": {"code": -1, "message": long_message},
    }))
    .expect("JSON response");
    let error = parse_rpc_envelope("fixture", 7, StatusCode::INTERNAL_SERVER_ERROR, &body)
        .expect_err("RPC failure");
    let ElementsCoreSourceError::RpcRejected { message, .. } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert!(message.ends_with('…'));
    assert_eq!(message.chars().count(), MAX_BACKEND_ERROR_CHARS + 1);
}

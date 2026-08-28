//! Live liquidregtest assurance for the production RFQ Elements source.
//!
//! This test is ignored by ordinary `cargo test` because it starts an isolated
//! `elementsd`. It exercises the real JSON-RPC transport, the durable custom
//! wallet, confidential wallet funding, UTXO-set discovery, output unblinding,
//! complete prevout recovery, and restart-safe rescanning.

use std::str::FromStr as _;

use bitcoind::bitcoincore_rpc::{Auth, Client, RpcApi as _};
use bitcoind::{BitcoinD, Conf, P2P};
use deadcat_rfq::SharedRfqWallet;
use deadcat_rfq::elements::{ElementsCoreAuth, ElementsCoreConfig, ElementsCoreSource};
use deadcat_rfq_provider::{
    ConfidentialDestination, InventorySource as _, ProviderId, ProviderIdentity,
    SettlementChainSource as _,
};
use deadcat_rfq_wallet::{KdfParams, PersistentRfqWallet};
use elements::encode::deserialize;
use elements::{Address, AddressParams, AssetId, BlockHash, OutPoint, Transaction, TxOut, Txid};
use serde_json::{Value as JsonValue, json};
use smplx_sdk::provider::ElementsRpc;
use tempfile::tempdir;

const PASSPHRASE: &[u8] = b"live RFQ Elements source test passphrase";
const FIRST_AMOUNT: u64 = 12_345;
const SECOND_AMOUNT: u64 = 23_456;

#[derive(Clone)]
struct ExpectedInventoryOutput {
    outpoint: OutPoint,
    txout: TxOut,
    amount: u64,
    destination: ConfidentialDestination,
}

fn elements_node() -> BitcoinD {
    let mut config = Conf::default();
    config.args = vec![
        "-fallbackfee=0.0001",
        "-dustrelayfee=0.00000001",
        "-acceptdiscountct=1",
        "-rest",
        "-evbparams=simplicity:-1:::",
        "-minrelaytxfee=0",
        "-blockmintxfee=0",
        "-chain=liquidregtest",
        "-txindex=1",
        "-validatepegin=0",
        "-initialfreecoins=2100000000000000",
        "-multi_data_permitted",
    ];
    config.network = "liquidregtest";
    config.p2p = P2P::No;
    BitcoinD::with_conf("elementsd", &config).expect("isolated liquidregtest elementsd")
}

fn default_policy_asset(rpc: &Client) -> AssetId {
    let sidechain_info: JsonValue = rpc
        .call("getsidechaininfo", &[])
        .expect("query real liquidregtest sidechain info");
    let policy_asset = AssetId::from_str(
        sidechain_info
            .get("pegged_asset")
            .and_then(JsonValue::as_str)
            .expect("liquidregtest sidechain pegged asset"),
    )
    .expect("pegged asset id");
    let labels: JsonValue = rpc
        .call("dumpassetlabels", &[])
        .expect("dump real liquidregtest asset labels");
    let bitcoin_label_asset = AssetId::from_str(
        labels
            .get("bitcoin")
            .and_then(JsonValue::as_str)
            .expect("liquidregtest built-in bitcoin asset label"),
    )
    .expect("bitcoin label asset id");
    assert_eq!(
        bitcoin_label_asset, policy_asset,
        "supported profile requires the built-in bitcoin label to match the pegged asset"
    );
    policy_asset
}

fn issue_distinct_asset(rpc: &Client, miner: &ElementsRpc) -> AssetId {
    let issuance: JsonValue = rpc
        .call("issueasset", &[json!(1.0), json!(0), json!(false)])
        .expect("issue inventory fixture asset");
    let asset = AssetId::from_str(
        issuance
            .get("asset")
            .and_then(JsonValue::as_str)
            .expect("issueasset returns an asset id"),
    )
    .expect("issued inventory asset id");
    miner.generate_blocks(1).expect("mine fixture issuance");
    asset
}

fn prepare_funded_node_wallet(miner: &ElementsRpc) {
    // The liquidregtest genesis allocation is not automatically associated
    // with the named wallet that `bitcoind` creates for this process. Follow
    // the canonical smplx setup: discover it, sweep it into the wallet, then
    // mature the sweep before issuing or funding assets.
    miner
        .generate_blocks(1)
        .expect("mine initial regtest block");
    miner
        .rescan_blockchain(None, None)
        .expect("discover liquidregtest initial free coins");
    miner
        .sweep_initialfreecoins()
        .expect("sweep initial free coins into the node wallet");
    miner
        .generate_blocks(100)
        .expect("confirm and mature the wallet sweep");
}

fn confidential_address(destination: &ConfidentialDestination) -> Address {
    Address::from_script(
        destination.script_pubkey(),
        Some(destination.blinding_public_key()),
        &AddressParams::ELEMENTS,
    )
    .expect("tree-less P2TR script has an Elements address")
}

fn raw_transaction(rpc: &Client, txid: Txid) -> Transaction {
    let raw: String = rpc
        .call(
            "getrawtransaction",
            &[json!(txid.to_string()), json!(false)],
        )
        .expect("get complete raw transaction through txindex");
    deserialize(&hex::decode(raw).expect("raw transaction hex"))
        .expect("consensus-decode raw Elements transaction")
}

fn expected_output(
    rpc: &Client,
    txid: Txid,
    destination: ConfidentialDestination,
    amount: u64,
) -> ExpectedInventoryOutput {
    let transaction = raw_transaction(rpc, txid);
    let (vout, txout) = transaction
        .output
        .into_iter()
        .enumerate()
        .find(|(_, output)| output.script_pubkey == *destination.script_pubkey())
        .expect("funding transaction contains the requested inventory output");
    assert!(txout.asset.is_confidential());
    assert!(txout.value.is_confidential());
    assert!(txout.nonce.is_confidential());
    assert!(txout.witness.surjection_proof.is_some());
    assert!(
        txout
            .witness
            .rangeproof
            .as_deref()
            .is_some_and(|proof| !proof.is_empty())
    );
    ExpectedInventoryOutput {
        outpoint: OutPoint::new(txid, u32::try_from(vout).expect("output index fits in u32")),
        txout,
        amount,
        destination,
    }
}

fn assert_inventory_output(
    output: &deadcat_rfq_provider::WalletOwnedOutput,
    expected: &ExpectedInventoryOutput,
    asset: AssetId,
) {
    assert_eq!(output.outpoint(), expected.outpoint);
    assert_eq!(output.txout(), &expected.txout);
    assert_eq!(output.asset(), asset);
    assert_eq!(output.amount(), expected.amount);
    assert_eq!(
        output.wallet_locator(),
        expected.destination.wallet_locator()
    );
    assert_eq!(output.internal_key(), expected.destination.internal_key());
}

#[test]
#[ignore = "starts elementsd from the Nix development shell"]
fn persistent_wallet_inventory_is_discovered_unblinded_and_recovered_after_restart() {
    let node = elements_node();
    let rpc_url = node.rpc_url();
    let cookie_path = node.params.cookie_file.clone();
    let auth = Auth::CookieFile(cookie_path.clone());
    let rpc = Client::new(&rpc_url, auth.clone()).expect("raw Elements RPC");
    let miner = ElementsRpc::new(rpc_url.clone(), auth).expect("Elements RPC");
    prepare_funded_node_wallet(&miner);
    let genesis_hash = BlockHash::from_str(
        &rpc.get_block_hash(0)
            .expect("real regtest genesis block")
            .to_string(),
    )
    .expect("Elements genesis hash");
    let policy_asset = default_policy_asset(&rpc);
    let inventory_asset = issue_distinct_asset(&rpc, &miner);
    assert_ne!(inventory_asset, policy_asset);

    let identity = ProviderIdentity::new(ProviderId::new([0x71; 32]), genesis_hash, policy_asset);
    let directory = tempdir().expect("temporary persistent wallet directory");
    let wallet_path = directory.path().join("rfq-wallet.redb");
    let persistent = PersistentRfqWallet::create_with_kdf(
        &wallet_path,
        identity,
        PASSPHRASE,
        KdfParams::new(8 * 1_024, 1, 1).expect("bounded live-test KDF"),
    )
    .expect("create identity-bound persistent RFQ wallet");
    let wallet = SharedRfqWallet::new(persistent);
    let first_destination = wallet
        .fresh_inventory_destination()
        .expect("first durable inventory destination");
    let second_destination = wallet
        .fresh_inventory_destination()
        .expect("second durable inventory destination");
    let source_config = ElementsCoreConfig::new(rpc_url, ElementsCoreAuth::CookieFile(cookie_path));
    let source = ElementsCoreSource::new(source_config.clone(), wallet.clone())
        .expect("production Elements inventory source");
    assert_eq!(source.identity(), identity);
    assert_eq!(source.genesis_hash(), genesis_hash);

    let first_txid = miner
        .send_to_address(
            &confidential_address(&first_destination),
            FIRST_AMOUNT,
            Some(inventory_asset),
        )
        .expect("fund first confidential inventory destination");
    let second_txid = miner
        .send_to_address(
            &confidential_address(&second_destination),
            SECOND_AMOUNT,
            Some(inventory_asset),
        )
        .expect("fund second confidential inventory destination");

    // `scantxoutset` is deliberately confirmed-chain-only. A transaction in
    // the node's mempool must not become quote-eligible inventory.
    let unconfirmed = source
        .inventory_snapshot()
        .expect("coherent inventory snapshot before confirmation");
    assert!(unconfirmed.outputs().is_empty());

    miner
        .generate_blocks(1)
        .expect("confirm confidential inventory funding");
    let first = expected_output(&rpc, first_txid, first_destination, FIRST_AMOUNT);
    let second = expected_output(&rpc, second_txid, second_destination, SECOND_AMOUNT);
    let confirmed = source
        .inventory_snapshot()
        .expect("scan and unblind confirmed custom-wallet inventory");
    assert_eq!(confirmed.identity(), identity);
    assert_eq!(confirmed.outputs().len(), 2);
    let expected = [&first, &second];
    for expected in expected {
        let output = confirmed
            .outputs()
            .iter()
            .find(|output| output.outpoint() == expected.outpoint)
            .expect("exact funded output appears in the inventory snapshot");
        assert_inventory_output(output, expected, inventory_asset);
    }

    // Settlement lookup must preserve caller order and return each complete
    // consensus prevout, including the confidential output witness.
    let requested = [second.outpoint, first.outpoint];
    let authoritative = source
        .unspent_prevouts(&requested)
        .expect("authoritative ordered settlement prevouts");
    assert_eq!(authoritative.len(), requested.len());
    for ((actual, outpoint), expected) in authoritative.iter().zip(requested).zip([&second, &first])
    {
        assert_eq!(actual.outpoint(), outpoint);
        assert_eq!(actual.txout(), &expected.txout);
        assert!(actual.txout().witness.surjection_proof.is_some());
        assert!(actual.txout().witness.rangeproof.is_some());
    }

    let confirmed_outputs = confirmed.outputs().to_vec();
    let confirmed_anchor = confirmed.anchor();
    let confirmed_commitment = confirmed.commitment();
    drop(source);
    drop(wallet);

    let reopened_wallet = SharedRfqWallet::new(
        PersistentRfqWallet::open(&wallet_path, identity, PASSPHRASE)
            .expect("reopen the same durable RFQ wallet"),
    );
    let reopened_source = ElementsCoreSource::new(source_config, reopened_wallet)
        .expect("Elements source after wallet restart");
    let rescanned = reopened_source
        .inventory_snapshot()
        .expect("rescan exact inventory after wallet restart");
    assert_eq!(rescanned.anchor(), confirmed_anchor);
    assert_eq!(rescanned.commitment(), confirmed_commitment);
    assert_eq!(rescanned.outputs(), confirmed_outputs);
}

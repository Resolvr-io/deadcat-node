//! Live liquidregtest assurance for the production RFQ Elements source and
//! provider process.
//!
//! These tests are ignored by ordinary `cargo test` because they start an
//! isolated `elementsd`; the process gate also starts `deadcat-rfq`. Together
//! they exercise the real JSON-RPC transport, durable custom wallets,
//! confidential funding and settlement, direct Iroh, provider signing and
//! relay, and both wallet and hard-process restart recovery.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, BufRead as _, BufReader, Read as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::str::FromStr as _;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bitcoind::bitcoincore_rpc::{Auth, Client, RpcApi as _};
use bitcoind::{BitcoinD, Conf, P2P};
use deadcat_client::composition::CompositionLimits;
use deadcat_client::validation::validate_contract_view;
use deadcat_client::venue::{AssetAmount, VenueContext};
use deadcat_contracts::binary_market::BinaryMarketSlot;
use deadcat_rfq::SharedRfqWallet;
use deadcat_rfq::elements::{ElementsCoreAuth, ElementsCoreConfig, ElementsCoreSource};
use deadcat_rfq_client::{
    AuthoritativeTakerPrevout, ExecutionJournalBinding, ExecutionJournalKey,
    ExecutionJournalObservation, ProviderTarget, RedbExecutionJournal, RfqSession, SessionConfig,
    TakerSettlementSnapshot, TakerSettlementSnapshotRequest, TakerSettlementSource, TradingMarket,
};
use deadcat_rfq_iroh::{ClientConfig, EndpointAddr, SecretKey};
use deadcat_rfq_provider::{
    ConfidentialDestination, InventorySource as _, ProviderId, ProviderIdentity,
    SettlementChainSource as _,
};
use deadcat_rfq_rpc::{
    FixedBytes32, IdempotencyKeyDto, RelayObservationDto, RelayStatusDto, ReservationStateDto,
    ReservationStatusDto,
};
use deadcat_rfq_taker::{ExactInRfqTrade, RfqTakerConfig, RfqTakerRuntime, TakerInventorySource};
use deadcat_rfq_wallet::{
    KdfParams, PersistentRfqWallet, TakerFundingLimits, TakerWalletIdentity, TakerWalletUtxo,
};
use deadcat_rpc::{ContractParametersView, ContractStateView, ContractView, LiveOutpoint};
use deadcat_types::{
    BinaryMarketParams, BinaryMarketState, ChainAnchor, ChainIdentity, ChainPosition, ContractId,
    ContractKind, ContractSyncState, LiquidNetwork,
};
use elements::encode::deserialize;
use elements::hashes::Hash as _;
use elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey as SecpSecretKey};
use elements::{Address, AddressParams, AssetId, BlockHash, OutPoint, Transaction, TxOut, Txid};
use rand::rngs::OsRng;
use serde_json::{Value as JsonValue, json};
use smplx_sdk::provider::ElementsRpc;
use tempfile::tempdir;

const PASSPHRASE: &[u8] = b"live RFQ Elements source test passphrase";
const FIRST_AMOUNT: u64 = 12_345;
const SECOND_AMOUNT: u64 = 23_456;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(60);
const PROVIDER_INVENTORY_AMOUNT: u64 = 10_000;
const TAKER_FUNDING_AMOUNT: u64 = 50_000;
const TRADE_INPUT_AMOUNT: u64 = 1_000;
const TRADE_OUTPUT_AMOUNT: u64 = 2_000;

#[derive(Clone)]
struct ExpectedInventoryOutput {
    outpoint: OutPoint,
    txout: TxOut,
    amount: u64,
    destination: ConfidentialDestination,
}

#[derive(Clone)]
struct LiveTakerSource {
    rpc_url: String,
    auth: Auth,
    chain: ChainIdentity,
    market: TradingMarket,
    inventory: Vec<TakerWalletUtxo>,
}

impl LiveTakerSource {
    fn rpc(&self) -> Result<Client, io::Error> {
        Client::new(&self.rpc_url, self.auth.clone()).map_err(source_error)
    }

    fn best_block_hash(rpc: &Client) -> Result<BlockHash, io::Error> {
        let value: String = rpc.call("getbestblockhash", &[]).map_err(source_error)?;
        BlockHash::from_str(&value).map_err(source_error)
    }

    fn authoritative_prevout(
        rpc: &Client,
        outpoint: OutPoint,
    ) -> Result<AuthoritativeTakerPrevout, io::Error> {
        let observed: JsonValue = rpc
            .call(
                "gettxout",
                &[
                    json!(outpoint.txid.to_string()),
                    json!(outpoint.vout),
                    json!(true),
                ],
            )
            .map_err(source_error)?;
        if observed.is_null() {
            return Err(io::Error::other(format!(
                "requested RFQ prevout {outpoint} is no longer unspent"
            )));
        }
        let raw: String = rpc
            .call(
                "getrawtransaction",
                &[json!(outpoint.txid.to_string()), json!(false)],
            )
            .map_err(source_error)?;
        let transaction: Transaction =
            deserialize(&hex::decode(raw).map_err(source_error)?).map_err(source_error)?;
        let txout = transaction
            .output
            .get(usize::try_from(outpoint.vout).map_err(source_error)?)
            .cloned()
            .ok_or_else(|| io::Error::other(format!("missing RFQ prevout {outpoint}")))?;
        Ok(AuthoritativeTakerPrevout::new(outpoint, txout))
    }

    fn inventory_sync(&self) -> Result<Vec<TakerWalletUtxo>, io::Error> {
        let rpc = self.rpc()?;
        let initial_tip = Self::best_block_hash(&rpc)?;
        for utxo in &self.inventory {
            Self::authoritative_prevout(&rpc, utxo.outpoint())?;
        }
        let final_tip = Self::best_block_hash(&rpc)?;
        if final_tip != initial_tip {
            return Err(io::Error::other(
                "Elements tip changed during taker inventory validation",
            ));
        }
        Ok(self.inventory.clone())
    }

    fn settlement_snapshot_sync(
        &self,
        request: TakerSettlementSnapshotRequest,
    ) -> Result<TakerSettlementSnapshot, io::Error> {
        if request.chain() != self.chain
            || request.market() != self.market.contract_id()
            || request.quote_anchor() != self.market.observed_at()
        {
            return Err(io::Error::other("RFQ settlement snapshot binding mismatch"));
        }
        let rpc = self.rpc()?;
        let initial_tip = Self::best_block_hash(&rpc)?;
        if initial_tip != request.quote_anchor().hash {
            return Err(io::Error::other(
                "RFQ settlement snapshot is not at the quoted chain anchor",
            ));
        }
        let mut unique = BTreeSet::new();
        let mut prevouts = Vec::with_capacity(request.outpoints().len());
        for outpoint in request.outpoints() {
            if !unique.insert(*outpoint) {
                return Err(io::Error::other("duplicate RFQ settlement prevout"));
            }
            prevouts.push(Self::authoritative_prevout(&rpc, *outpoint)?);
        }
        let final_tip = Self::best_block_hash(&rpc)?;
        if final_tip != initial_tip {
            return Err(io::Error::other(
                "Elements tip changed during RFQ settlement validation",
            ));
        }
        Ok(TakerSettlementSnapshot::new(
            unix_millis()?,
            self.market.clone(),
            prevouts,
        ))
    }
}

#[async_trait]
impl TakerInventorySource for LiveTakerSource {
    type Error = io::Error;

    async fn inventory(&self) -> Result<Vec<TakerWalletUtxo>, Self::Error> {
        let source = self.clone();
        tokio::task::spawn_blocking(move || source.inventory_sync())
            .await
            .map_err(source_error)?
    }
}

#[async_trait]
impl TakerSettlementSource for LiveTakerSource {
    type Error = io::Error;

    async fn settlement_snapshot(
        &self,
        request: TakerSettlementSnapshotRequest,
    ) -> Result<TakerSettlementSnapshot, Self::Error> {
        let source = self.clone();
        tokio::task::spawn_blocking(move || source.settlement_snapshot_sync(request))
            .await
            .map_err(source_error)?
    }
}

fn source_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

fn unix_millis() -> Result<u64, io::Error> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(source_error)?;
    u64::try_from(elapsed.as_millis()).map_err(source_error)
}

struct RfqProcess {
    child: KillOnDropChild,
    endpoint: EndpointAddr,
    provider_id: String,
}

struct KillOnDropChild {
    child: Option<Child>,
}

impl KillOnDropChild {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("owned child process")
    }

    fn id(&self) -> u32 {
        self.child.as_ref().expect("owned child process").id()
    }

    fn kill_and_wait(&mut self) -> io::Result<std::process::ExitStatus> {
        let Some(mut child) = self.child.take() else {
            return Err(io::Error::other("child process was already reaped"));
        };
        if let Err(error) = child.kill()
            && error.kind() != io::ErrorKind::InvalidInput
        {
            let _ = child.wait();
            return Err(error);
        }
        child.wait()
    }

    fn wait_timeout(&mut self, timeout: Duration) -> io::Result<std::process::ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.child_mut().try_wait() {
                Ok(Some(status)) => {
                    self.child.take();
                    return Ok(status);
                }
                Ok(None) => {}
                Err(error) => {
                    let _ = self.kill_and_wait();
                    return Err(error);
                }
            }
            if Instant::now() >= deadline {
                let _ = self.kill_and_wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "child process did not exit before timeout",
                ));
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for KillOnDropChild {
    fn drop(&mut self) {
        if self.child.is_some() {
            let _ = self.kill_and_wait();
        }
    }
}

impl RfqProcess {
    fn spawn(binary: &Path, config: &Path, state: &Path, passphrase: &Path) -> Self {
        let mut command = rfq_command(binary, "run", config, state, passphrase);
        command
            .env("RUST_LOG", "deadcat_rfq=warn")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let child = command
            .spawn()
            .unwrap_or_else(|error| panic!("failed to spawn {}: {error}", binary.display()));
        // Establish kill-on-drop ownership before any fallible readiness
        // parsing so a timeout, EOF, or malformed readiness line cannot leave
        // a provider daemon running after this test unwinds.
        let mut child = KillOnDropChild::new(child);
        let stdout = child.child_mut().stdout.take().expect("RFQ daemon stdout");
        let (send, receive) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            let result = reader.read_line(&mut line).and_then(|read| {
                if read == 0 {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "RFQ daemon exited before readiness",
                    ))
                } else {
                    Ok(line)
                }
            });
            let _ = send.send(result);
            let _ = io::copy(&mut reader, &mut io::sink());
        });
        let ready_line = receive
            .recv_timeout(PROCESS_TIMEOUT)
            .expect("RFQ daemon readiness timed out")
            .expect("read RFQ daemon readiness");
        let ready: JsonValue = serde_json::from_str(ready_line.trim())
            .unwrap_or_else(|error| panic!("invalid RFQ readiness {ready_line:?}: {error}"));
        assert_eq!(ready["status"], "ready");
        let endpoint: EndpointAddr =
            serde_json::from_value(ready["endpoint"].clone()).expect("RFQ readiness endpoint");
        let provider_id = ready["provider_id"]
            .as_str()
            .expect("RFQ readiness provider id")
            .to_owned();
        assert!(
            endpoint.ip_addrs().next().is_some(),
            "direct-only RFQ daemon must advertise an IP address"
        );
        Self {
            child,
            endpoint,
            provider_id,
        }
    }

    fn kill_hard(&mut self) {
        self.child
            .kill_and_wait()
            .expect("SIGKILL and reap RFQ daemon");
    }

    fn stop_gracefully(&mut self) {
        let signal = Command::new("kill")
            .arg("-INT")
            .arg(self.child.id().to_string())
            .status()
            .expect("send SIGINT to RFQ daemon");
        assert!(signal.success(), "send SIGINT to RFQ daemon");
        let status = self
            .child
            .wait_timeout(PROCESS_TIMEOUT)
            .unwrap_or_else(|error| panic!("RFQ daemon shutdown failed: {error}"));
        assert!(
            status.success(),
            "RFQ daemon exited unsuccessfully: {status}"
        );
    }
}

fn rfq_command(
    binary: &Path,
    subcommand: &str,
    config: &Path,
    state: &Path,
    passphrase: &Path,
) -> Command {
    let mut command = Command::new(binary);
    command
        .arg(subcommand)
        .arg("--config")
        .arg(config)
        .arg("--state-dir")
        .arg(state)
        .arg("--passphrase-file")
        .arg(passphrase);
    command
}

fn run_rfq_once(
    binary: &Path,
    subcommand: &str,
    config: &Path,
    state: &Path,
    passphrase: &Path,
) -> JsonValue {
    let mut command = rfq_command(binary, subcommand, config, state, passphrase);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = command
        .spawn()
        .unwrap_or_else(|error| panic!("failed to run RFQ {subcommand}: {error}"));
    // Own the child before taking its pipes. On every panic/error path the
    // guard kills and reaps it, while the explicit timeout bounds commands
    // that never produce an exit status.
    let mut child = KillOnDropChild::new(child);
    let mut stdout = child
        .child_mut()
        .stdout
        .take()
        .expect("one-shot RFQ stdout");
    let mut stderr = child
        .child_mut()
        .stderr
        .take()
        .expect("one-shot RFQ stderr");
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    let status = child.wait_timeout(PROCESS_TIMEOUT);
    let stdout = stdout_reader
        .join()
        .expect("one-shot RFQ stdout reader panicked")
        .expect("read one-shot RFQ stdout");
    let stderr = stderr_reader
        .join()
        .expect("one-shot RFQ stderr reader panicked")
        .expect("read one-shot RFQ stderr");
    let output = Output {
        status: status.unwrap_or_else(|error| {
            panic!(
                "RFQ {subcommand} timed out: {error}; stdout={} stderr={}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            )
        }),
        stdout,
        stderr,
    };
    assert!(
        output.status.success(),
        "RFQ {subcommand} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid RFQ {subcommand} output {}: {error}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
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

fn process_market_id() -> ContractId {
    ContractId::new(OutPoint::new(Txid::from_byte_array([0x31; 32]), 0))
}

fn marker_asset(marker: u8) -> AssetId {
    AssetId::from_byte_array([marker; 32])
}

fn process_market(
    chain: ChainIdentity,
    policy_asset: AssetId,
    yes_asset: AssetId,
    no_asset: AssetId,
    observed_at: ChainAnchor,
) -> TradingMarket {
    let oracle_secret = SecpSecretKey::from_slice(&[0x32; 32]).expect("fixture oracle secret key");
    let oracle = Keypair::from_secret_key(&Secp256k1::new(), &oracle_secret)
        .x_only_public_key()
        .0
        .serialize();
    let params = BinaryMarketParams {
        oracle_public_key: oracle,
        collateral_asset_id: policy_asset,
        yes_token_asset_id: yes_asset,
        no_token_asset_id: no_asset,
        yes_reissuance_token_id: marker_asset(0x44),
        no_reissuance_token_id: marker_asset(0x45),
        base_payout: 100,
        expiry_height: observed_at
            .height
            .checked_add(1_000)
            .expect("future market expiry"),
    };
    let creation = process_market_id().creation_anchor();
    let view = ContractView {
        contract_id: process_market_id(),
        kind: ContractKind::BinaryMarketV1,
        sync_state: ContractSyncState::Ready {
            synced_through: observed_at,
        },
        creation_position: ChainPosition {
            block_height: 1,
            tx_index: 0,
        },
        parameters: ContractParametersView::BinaryMarket { params },
        state: ContractStateView::BinaryMarket {
            state: BinaryMarketState::Trading {
                outstanding_pairs: 0,
            },
        },
        live_outpoints: vec![
            LiveOutpoint {
                role: BinaryMarketSlot::DormantYesRt as u8,
                outpoint: creation,
            },
            LiveOutpoint {
                role: BinaryMarketSlot::DormantNoRt as u8,
                outpoint: OutPoint::new(creation.txid, 1),
            },
        ],
    };
    let validated = validate_contract_view(&view).expect("valid process-test market view");
    TradingMarket::from_validated(&validated, chain, policy_asset)
        .expect("open process-test trading market")
}

fn chain_tip(rpc: &Client) -> ChainAnchor {
    let height = u32::try_from(rpc.get_block_count().expect("RFQ process-test block count"))
        .expect("liquidregtest height fits u32");
    let hash = BlockHash::from_str(
        &rpc.get_block_hash(u64::from(height))
            .expect("RFQ process-test tip hash")
            .to_string(),
    )
    .expect("Elements block hash");
    ChainAnchor { height, hash }
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write private RFQ fixture file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("protect RFQ fixture file");
    }
}

fn write_process_config(
    path: &Path,
    rpc_url: &str,
    cookie_path: &Path,
    genesis_hash: BlockHash,
    policy_asset: AssetId,
    yes_asset: AssetId,
    no_asset: AssetId,
) {
    let config = json!({
        "schema_version": 1,
        "profile": "regtest_static_v1",
        "network": "elements_regtest",
        "genesis_hash": genesis_hash,
        "policy_asset": policy_asset,
        "elements": {
            "url": rpc_url,
            "auth": { "type": "cookie_file", "path": cookie_path },
        },
        "fee_policy": {
            "minimum_sats_per_kvb": 100,
            "minimum_absolute_fee": 100,
            "maximum_transaction_weight": 100_000,
            "size_metric": "discount_vbytes",
        },
        "pricing_revision": 1,
        "markets": [{
            "market_id": process_market_id(),
            "collateral_asset": policy_asset,
            "yes_asset": yes_asset,
            "no_asset": no_asset,
            "pairs": [{
                "input": "collateral",
                "output": "yes",
                "minimum_input": 1,
                "maximum_input": 100_000,
                "minimum_output": 1,
                "maximum_output": 200_000,
                "maximum_provider_inputs": 4,
                "minimum_positive_change": 1,
                "selection_search_node_budget": 10_000,
                "rate_numerator": 2,
                "rate_denominator": 1,
            }],
        }],
        "runtime": {
            "max_inventory_age_millis": 30_000,
            "max_inventory_outputs": 100,
            "quote_lifetime_millis": 30_000,
            "maximum_live_quotes_per_owner": 4,
            "maximum_live_quotes_global": 32,
            "execute_queue_capacity": 4,
            "max_blocking_operations": 8,
            "recovery_batch_size": 8,
            "recovery_interval_millis": 100,
            "inventory_refresh_interval_millis": 1_000,
            "direct_only": true,
        },
    });
    write_private(
        path,
        &serde_json::to_vec_pretty(&config).expect("serialize RFQ process config"),
    );
}

fn signed_relay(status: &ReservationStatusDto) -> Option<&RelayStatusDto> {
    match &status.state {
        ReservationStateDto::Signed { relay, .. } => Some(relay),
        ReservationStateDto::Reserved
        | ReservationStateDto::Released { .. }
        | ReservationStateDto::Committed { .. } => None,
    }
}

async fn wait_for_signed_relay(
    runtime: &RfqTakerRuntime<OsRng, RedbExecutionJournal>,
    session: &RfqSession,
    key: ExecutionJournalKey,
    mut predicate: impl FnMut(&RelayStatusDto) -> bool,
) -> ReservationStatusDto {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let recovered = runtime
            .recover(session, key)
            .await
            .expect("recover exact RFQ execution status");
        if let ExecutionJournalObservation::Signed(status) = recovered.observation()
            && signed_relay(status).is_some_and(&mut predicate)
        {
            return status.clone();
        }
        assert!(
            Instant::now() < deadline,
            "RFQ relay did not reach the expected state"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
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

#[tokio::test(flavor = "multi_thread")]
#[ignore = "starts elementsd and the deadcat-rfq process from the Nix development shell"]
async fn provider_daemon_quotes_signs_relays_and_recovers_after_restart() {
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_deadcat-rfq"));
    assert!(binary.is_file(), "RFQ process-test binary is missing");

    let node = elements_node();
    let rpc_url = node.rpc_url();
    let cookie_path = node.params.cookie_file.clone();
    let auth = Auth::CookieFile(cookie_path.clone());
    let rpc = Client::new(&rpc_url, auth.clone()).expect("raw Elements RPC");
    let miner = ElementsRpc::new(rpc_url.clone(), auth.clone()).expect("Elements RPC");
    prepare_funded_node_wallet(&miner);
    let genesis_hash = BlockHash::from_str(
        &rpc.get_block_hash(0)
            .expect("real regtest genesis block")
            .to_string(),
    )
    .expect("Elements genesis hash");
    let policy_asset = default_policy_asset(&rpc);
    let yes_asset = issue_distinct_asset(&rpc, &miner);
    let no_asset = issue_distinct_asset(&rpc, &miner);
    assert_ne!(yes_asset, no_asset);

    let directory = tempdir().expect("RFQ provider process directory");
    let config_path = directory.path().join("deadcat-rfq.json");
    let passphrase_path = directory.path().join("wallet.passphrase");
    let state_path = directory.path().join("provider-state");
    write_private(
        &passphrase_path,
        b"live RFQ provider process test passphrase\n",
    );
    write_process_config(
        &config_path,
        &rpc_url,
        &cookie_path,
        genesis_hash,
        policy_asset,
        yes_asset,
        no_asset,
    );

    let initialized = run_rfq_once(&binary, "init", &config_path, &state_path, &passphrase_path);
    assert_eq!(initialized["status"], "initialized");
    let provider_id = initialized["provider_id"]
        .as_str()
        .expect("initialized provider id")
        .to_owned();
    let deposit = run_rfq_once(
        &binary,
        "deposit-address",
        &config_path,
        &state_path,
        &passphrase_path,
    );
    let provider_address = Address::from_str(
        deposit["address"]
            .as_str()
            .expect("provider deposit address"),
    )
    .expect("valid provider deposit address");
    assert_eq!(deposit["provider_id"], provider_id);

    let client_key = SecretKey::from_bytes(&[0x52; 32]);
    let chain = ChainIdentity {
        network: LiquidNetwork::ElementsRegtest,
        genesis_hash,
    };
    let taker_identity =
        TakerWalletIdentity::new(*client_key.public().as_bytes(), genesis_hash, policy_asset)
            .expect("taker wallet identity");
    let taker_wallet = Arc::new(
        PersistentRfqWallet::create_taker_with_kdf(
            directory.path().join("taker-wallet.redb"),
            taker_identity,
            b"live RFQ taker wallet passphrase",
            KdfParams::new(8 * 1_024, 1, 1).expect("bounded live-test KDF"),
        )
        .expect("persistent taker wallet"),
    );
    let taker_destination = taker_wallet
        .fresh_inventory_destination()
        .expect("durable taker funding destination");

    miner
        .send_to_address(
            &provider_address,
            PROVIDER_INVENTORY_AMOUNT,
            Some(yes_asset),
        )
        .expect("fund provider YES inventory");
    let taker_funding_txid = miner
        .send_to_address(
            &confidential_address(&taker_destination),
            TAKER_FUNDING_AMOUNT,
            None,
        )
        .expect("fund taker policy-asset input");
    miner
        .generate_blocks(1)
        .expect("confirm provider and taker RFQ funding");

    let taker_funding = expected_output(
        &rpc,
        taker_funding_txid,
        taker_destination,
        TAKER_FUNDING_AMOUNT,
    );
    let taker_utxo = taker_wallet
        .recover_taker_utxo(
            taker_funding.destination.wallet_locator(),
            taker_funding.outpoint,
            taker_funding.txout.clone(),
        )
        .expect("wallet-authenticated taker funding output");
    let observed_at = chain_tip(&rpc);
    let market = process_market(chain, policy_asset, yes_asset, no_asset, observed_at);
    let source = LiveTakerSource {
        rpc_url: rpc_url.clone(),
        auth: auth.clone(),
        chain,
        market: market.clone(),
        inventory: vec![taker_utxo],
    };

    let mut process = RfqProcess::spawn(&binary, &config_path, &state_path, &passphrase_path);
    assert_eq!(process.provider_id, provider_id);
    let original_provider_endpoint = process.endpoint.id;
    let target = ProviderTarget::new(process.endpoint.clone(), chain, policy_asset);
    let session_config = SessionConfig::new(
        ClientConfig {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(10),
            ..ClientConfig::default()
        },
        60_000,
        5_000,
    )
    .expect("valid RFQ session configuration");
    let session = RfqSession::dial_direct(target, client_key.clone(), session_config.clone())
        .await
        .expect("connect to the real RFQ provider process");

    let journal_binding = ExecutionJournalBinding::new(
        FixedBytes32::new([0x53; 32]),
        FixedBytes32::new(taker_wallet.instance_id().to_bytes()),
        client_key.public(),
        chain,
        policy_asset,
    )
    .expect("taker execution journal binding");
    let journal =
        RedbExecutionJournal::create(directory.path().join("taker-journal.redb"), journal_binding)
            .expect("durable taker execution journal");
    let runtime = RfqTakerRuntime::from_source(
        Arc::clone(&taker_wallet),
        taker_identity,
        &source,
        journal,
        RfqTakerConfig::new(
            TakerFundingLimits::default(),
            CompositionLimits::default(),
            100,
        )
        .expect("valid taker runtime configuration"),
    )
    .await
    .expect("initialize taker runtime from live Core evidence");
    let context = VenueContext {
        chain,
        market: process_market_id(),
        policy_asset,
    };
    let reserved = runtime
        .reserve_exact_in(
            &market,
            ExactInRfqTrade::new(
                context,
                AssetAmount::new(policy_asset, TRADE_INPUT_AMOUNT).expect("nonzero trade input"),
                yes_asset,
                TRADE_OUTPUT_AMOUNT,
                0,
                20_000,
            ),
        )
        .expect("reserve complete taker funding before quote I/O");
    let prepared = reserved
        .request_quote(&session, IdempotencyKeyDto::new([0x86; 32]))
        .await
        .expect("real provider firm quote");
    assert_eq!(
        prepared.quote().quote().execution.output.amount,
        TRADE_OUTPUT_AMOUNT
    );
    let accepted = runtime
        .accept(&session, &source, prepared)
        .await
        .expect("blind, authorize, sign, and execute against the real provider");
    let execution_key = accepted.key();
    let relayed = wait_for_signed_relay(&runtime, &session, execution_key, |relay| {
        matches!(
            relay.observation,
            RelayObservationDto::BroadcastAccepted | RelayObservationDto::Mempool
        )
    })
    .await;
    let (signed_pset, before_restart_relay) = match &relayed.state {
        ReservationStateDto::Signed {
            signed_pset, relay, ..
        } => (signed_pset.clone(), relay.clone()),
        other => panic!("expected signed RFQ status, got {other:?}"),
    };
    // Kill as soon as the first completed relay attempt is observable. Any
    // later Core inspection or transport cleanup must happen with the original
    // provider process gone so it cannot create the observation attributed to
    // startup recovery below.
    process.kill_hard();
    session.close().await;
    let settlement = signed_pset
        .to_pset()
        .expect("signed provider PSET")
        .extract_tx()
        .expect("fully signed provider settlement");
    assert_eq!(before_restart_relay.txid, settlement.txid());
    assert_eq!(before_restart_relay.wtxid, settlement.wtxid());
    assert_eq!(raw_transaction(&rpc, settlement.txid()), settlement);

    let now = unix_millis().expect("current test time");
    let due = before_restart_relay
        .next_attempt_at_millis
        .expect("relayed settlement remains scheduled");
    let wait_millis = due.saturating_sub(now).saturating_add(100);
    assert!(
        wait_millis <= 10_000,
        "mempool relay retry should become due promptly, got {wait_millis}ms"
    );
    tokio::time::sleep(Duration::from_millis(wait_millis)).await;

    let restart_started_at = unix_millis().expect("provider restart start time");
    let mut restarted = RfqProcess::spawn(&binary, &config_path, &state_path, &passphrase_path);
    assert_eq!(restarted.provider_id, provider_id);
    assert_eq!(restarted.endpoint.id, original_provider_endpoint);
    let restarted_session = RfqSession::dial_direct(
        ProviderTarget::new(restarted.endpoint.clone(), chain, policy_asset),
        client_key,
        session_config,
    )
    .await
    .expect("reconnect with the same authenticated taker identity");
    let after_restart =
        wait_for_signed_relay(&runtime, &restarted_session, execution_key, |relay| {
            relay.observation == RelayObservationDto::Mempool
                && relay
                    .last_observed_at_millis
                    .is_some_and(|observed_at| observed_at >= restart_started_at)
        })
        .await;
    let after_restart_relay = signed_relay(&after_restart).expect("signed relay after restart");
    assert_eq!(after_restart_relay.txid, settlement.txid());
    assert_eq!(after_restart_relay.wtxid, settlement.wtxid());
    assert!(
        after_restart_relay.attempt_count > before_restart_relay.attempt_count,
        "startup must reconcile relay work that became due while the daemon was stopped"
    );
    assert!(
        after_restart_relay
            .last_observed_at_millis
            .is_some_and(|observed_at| observed_at >= restart_started_at),
        "the qualifying mempool observation must be recorded by the restarted daemon"
    );
    let ReservationStateDto::Signed {
        signed_pset: restarted_pset,
        ..
    } = &after_restart.state
    else {
        panic!("expected signed status after restart")
    };
    assert_eq!(restarted_pset, &signed_pset);

    miner
        .generate_blocks(1)
        .expect("confirm relayed RFQ settlement");
    let confirmed_tip = chain_tip(&rpc);
    let confirmed = wait_for_signed_relay(&runtime, &restarted_session, execution_key, |relay| {
        matches!(relay.observation, RelayObservationDto::Confirmed { .. })
    })
    .await;
    let confirmed_relay = signed_relay(&confirmed).expect("confirmed signed relay");
    assert!(matches!(
        confirmed_relay.observation,
        RelayObservationDto::Confirmed {
            block_hash,
            block_height,
        } if block_hash == confirmed_tip.hash && block_height == confirmed_tip.height
    ));
    assert_eq!(confirmed_relay.txid, settlement.txid());
    assert_eq!(raw_transaction(&rpc, settlement.txid()), settlement);

    restarted_session.close().await;
    restarted.stop_gracefully();
}

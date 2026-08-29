use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::ThreadId;

use deadcat_contracts::binary_market::BinaryMarketSlot;
use deadcat_rfq_wallet::{KdfParams, TakerWalletIdentity};
use deadcat_rpc::{
    BackendKind, ContractParametersView, ContractStateView, ContractView, LiveOutpoint,
    SnapshotMetadata,
};
use deadcat_types::{
    BinaryMarketParams, BinaryMarketState, ChainPosition, ContractKind, ContractSyncState,
    DiscoveryCoverage, DiscoveryMode, EventCursor,
};
use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::hashes::Hash as _;
use elements::secp256k1_zkp::{Secp256k1, SecretKey};
use elements::{RangeProofMessage, TxOutWitness, Txid};
use tempfile::{TempDir, tempdir};

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Begin,
    NodeInfo,
    MarketSnapshot,
    CoreAnchor,
    CorePrevouts,
    Clock,
    BudgetCheck,
}

type Events = Arc<Mutex<Vec<Event>>>;

#[derive(Clone)]
struct FakeBudget {
    operation: CoreOperation,
    events: Events,
    deadline: std::time::Instant,
}

impl SourceOperationBudget for FakeBudget {
    fn check(&self) -> Result<(), ElementsCoreError> {
        self.events.lock().expect("events").push(Event::BudgetCheck);
        if std::time::Instant::now() < self.deadline {
            Ok(())
        } else {
            Err(ElementsCoreError::OperationTimedOut { operation: "fake" })
        }
    }

    fn remaining(&self) -> Result<Duration, ElementsCoreError> {
        match self
            .deadline
            .checked_duration_since(std::time::Instant::now())
        {
            Some(remaining) if !remaining.is_zero() => Ok(remaining),
            _ => Err(ElementsCoreError::OperationTimedOut { operation: "fake" }),
        }
    }

    fn operation(&self) -> CoreOperation {
        self.operation
    }
}

struct FakeCoreState {
    begin_calls: Vec<CoreOperation>,
    canonical: VecDeque<Result<ChainAnchor, ElementsCoreError>>,
    prevouts: VecDeque<Result<SourcePrevoutSnapshot, ElementsCoreError>>,
    canonical_calls: Vec<(ChainAnchor, ThreadId)>,
    prevout_calls: Vec<(Vec<OutPoint>, Vec<ChainAnchor>, ThreadId)>,
}

#[derive(Clone)]
struct FakeCore {
    state: Arc<Mutex<FakeCoreState>>,
    events: Events,
    budget_duration: Duration,
}

impl FakeCore {
    fn new(
        events: Events,
        canonical: Vec<Result<ChainAnchor, ElementsCoreError>>,
        prevouts: Vec<Result<SourcePrevoutSnapshot, ElementsCoreError>>,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(FakeCoreState {
                begin_calls: Vec::new(),
                canonical: canonical.into(),
                prevouts: prevouts.into(),
                canonical_calls: Vec::new(),
                prevout_calls: Vec::new(),
            })),
            events,
            budget_duration: Duration::from_secs(5),
        }
    }

    fn with_budget_duration(mut self, duration: Duration) -> Self {
        self.budget_duration = duration;
        self
    }
}

impl CoreEvidenceHandle for FakeCore {
    type Budget = FakeBudget;

    fn begin_operation(&self, operation: CoreOperation) -> Result<Self::Budget, ElementsCoreError> {
        self.events.lock().expect("events").push(Event::Begin);
        self.state
            .lock()
            .expect("core state")
            .begin_calls
            .push(operation);
        Ok(FakeBudget {
            operation,
            events: Arc::clone(&self.events),
            deadline: std::time::Instant::now() + self.budget_duration,
        })
    }

    fn canonical_tip(
        &self,
        _budget: &Self::Budget,
        anchor: ChainAnchor,
    ) -> Result<ChainAnchor, ElementsCoreError> {
        self.events.lock().expect("events").push(Event::CoreAnchor);
        let mut state = self.state.lock().expect("core state");
        state
            .canonical_calls
            .push((anchor, std::thread::current().id()));
        state
            .canonical
            .pop_front()
            .expect("scripted canonical result")
    }

    fn unspent_prevouts(
        &self,
        _budget: &Self::Budget,
        outpoints: &[OutPoint],
        required_anchors: &[ChainAnchor],
    ) -> Result<SourcePrevoutSnapshot, ElementsCoreError> {
        self.events
            .lock()
            .expect("events")
            .push(Event::CorePrevouts);
        let mut state = self.state.lock().expect("core state");
        state.prevout_calls.push((
            outpoints.to_vec(),
            required_anchors.to_vec(),
            std::thread::current().id(),
        ));
        state.prevouts.pop_front().expect("scripted prevout result")
    }
}

#[derive(Clone, Copy, Debug, Error)]
#[error("fake node failure")]
struct FakeNodeError;

struct FakeNodeState {
    infos: VecDeque<NodeInfo>,
    snapshots: VecDeque<MarketSnapshot>,
    info_calls: usize,
    snapshot_calls: usize,
}

#[derive(Clone)]
struct FakeNode {
    state: Arc<Mutex<FakeNodeState>>,
    events: Events,
}

impl FakeNode {
    fn new(events: Events, infos: Vec<NodeInfo>, snapshots: Vec<MarketSnapshot>) -> Self {
        Self {
            state: Arc::new(Mutex::new(FakeNodeState {
                infos: infos.into(),
                snapshots: snapshots.into(),
                info_calls: 0,
                snapshot_calls: 0,
            })),
            events,
        }
    }
}

#[async_trait]
impl TakerNodeSource for FakeNode {
    type Error = FakeNodeError;

    async fn get_info(&self) -> Result<NodeInfo, Self::Error> {
        self.events.lock().expect("events").push(Event::NodeInfo);
        let mut state = self.state.lock().expect("node state");
        state.info_calls += 1;
        Ok(state.infos.pop_front().expect("scripted node info"))
    }

    async fn market_snapshot(&self, _market_id: ContractId) -> Result<MarketSnapshot, Self::Error> {
        self.events
            .lock()
            .expect("events")
            .push(Event::MarketSnapshot);
        let mut state = self.state.lock().expect("node state");
        state.snapshot_calls += 1;
        Ok(state
            .snapshots
            .pop_front()
            .expect("scripted market snapshot"))
    }
}

#[derive(Clone, Default)]
struct PendingNode {
    info_calls: Arc<AtomicUsize>,
    snapshot_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl TakerNodeSource for PendingNode {
    type Error = FakeNodeError;

    async fn get_info(&self) -> Result<NodeInfo, Self::Error> {
        self.info_calls.fetch_add(1, Ordering::Relaxed);
        std::future::pending().await
    }

    async fn market_snapshot(&self, _market_id: ContractId) -> Result<MarketSnapshot, Self::Error> {
        self.snapshot_calls.fetch_add(1, Ordering::Relaxed);
        Err(FakeNodeError)
    }
}

#[derive(Clone)]
struct StaticScan {
    snapshot: InventoryScanSnapshot,
}

impl InventoryScanHandle for StaticScan {
    fn check(&self) -> Result<(), ElementsCoreError> {
        Ok(())
    }

    fn scan_unspent_scripts(
        &self,
        _scripts: &[Script],
    ) -> Result<InventoryScanSnapshot, ElementsCoreError> {
        Ok(self.snapshot.clone())
    }
}

struct CatalogChangingScan {
    wallet: Arc<PersistentRfqWallet>,
}

impl InventoryScanHandle for CatalogChangingScan {
    fn check(&self) -> Result<(), ElementsCoreError> {
        Ok(())
    }

    fn scan_unspent_scripts(
        &self,
        _scripts: &[Script],
    ) -> Result<InventoryScanSnapshot, ElementsCoreError> {
        self.wallet
            .fresh_inventory_destination()
            .expect("concurrent catalog mutation");
        Ok(InventoryScanSnapshot {
            outputs: Vec::new(),
        })
    }
}

fn anchor(height: u32, marker: u8) -> ChainAnchor {
    ChainAnchor {
        height,
        hash: BlockHash::from_byte_array([marker; 32]),
    }
}

fn asset(marker: u8) -> AssetId {
    AssetId::from_slice(&[marker; 32]).expect("asset")
}

fn chain() -> ChainIdentity {
    ChainIdentity {
        network: LiquidNetwork::ElementsRegtest,
        genesis_hash: BlockHash::from_byte_array([0x91; 32]),
    }
}

fn test_wallet() -> (TempDir, Arc<PersistentRfqWallet>) {
    let directory = tempdir().expect("temporary wallet directory");
    let identity = TakerWalletIdentity::new([0x81; 32], chain().genesis_hash, asset(9))
        .expect("taker identity");
    let wallet = PersistentRfqWallet::create_taker_with_kdf(
        directory.path().join("wallet.redb"),
        identity,
        b"source unit-test passphrase",
        KdfParams::new(8 * 1_024, 1, 1).expect("bounded test KDF"),
    )
    .expect("taker wallet");
    (directory, Arc::new(wallet))
}

fn params() -> BinaryMarketParams {
    let secret = SecretKey::from_slice(&[0x31; 32]).expect("oracle secret");
    let keypair = elements::secp256k1_zkp::Keypair::from_secret_key(&Secp256k1::new(), &secret);
    BinaryMarketParams {
        oracle_public_key: keypair.x_only_public_key().0.serialize(),
        collateral_asset_id: asset(1),
        yes_token_asset_id: asset(2),
        no_token_asset_id: asset(3),
        yes_reissuance_token_id: asset(4),
        no_reissuance_token_id: asset(5),
        base_payout: 100,
        expiry_height: 500,
    }
}

fn market_id() -> ContractId {
    ContractId::new(OutPoint::new(Txid::from_byte_array([0x21; 32]), 0))
}

fn market_snapshot(at: ChainAnchor) -> MarketSnapshot {
    let params = params();
    let creation_txid = market_id().txid();
    let live_outpoints = vec![
        LiveOutpoint {
            role: BinaryMarketSlot::DormantYesRt as u8,
            outpoint: OutPoint::new(creation_txid, 0),
        },
        LiveOutpoint {
            role: BinaryMarketSlot::DormantNoRt as u8,
            outpoint: OutPoint::new(creation_txid, 1),
        },
    ];
    let state = BinaryMarketState::Trading {
        outstanding_pairs: 0,
    };
    let contract = ContractView {
        contract_id: market_id(),
        kind: ContractKind::BinaryMarketV1,
        sync_state: ContractSyncState::Ready { synced_through: at },
        creation_position: ChainPosition {
            block_height: 1,
            tx_index: 0,
        },
        parameters: ContractParametersView::BinaryMarket { params },
        state: ContractStateView::BinaryMarket { state },
        live_outpoints: live_outpoints.clone(),
    };
    MarketSnapshot {
        snapshot: SnapshotMetadata {
            as_of: at,
            event_high_watermark: EventCursor {
                epoch: [7; 16],
                sequence: 9,
            },
        },
        contract,
        params,
        state,
        live_outpoints,
    }
}

fn resolved_market_snapshot(at: ChainAnchor) -> MarketSnapshot {
    let mut snapshot = market_snapshot(at);
    let state = BinaryMarketState::ResolvedYes {
        collateral_unredeemed: 0,
    };
    snapshot.state = state;
    snapshot.live_outpoints.clear();
    snapshot.contract.state = ContractStateView::BinaryMarket { state };
    snapshot.contract.live_outpoints.clear();
    snapshot
}

fn node_info(at: ChainAnchor) -> NodeInfo {
    NodeInfo {
        network: chain().network,
        genesis_hash: chain().genesis_hash,
        policy_asset: asset(9),
        backend: BackendKind::ElementsRpc,
        source_tip: Some(at),
        indexed_tip: at,
        sync_status: SyncStatus::Ready,
        rollback_retention_blocks: 2,
        discovery: DiscoveryCoverage {
            mode: DiscoveryMode::AdvisoryOnly,
            from: at,
            scanned_through: at,
            target_tip: at,
            canonical_market_complete: false,
        },
        capabilities: vec![Capability::EvidenceQueries, Capability::BinaryMarketV1],
        event_high_watermark: EventCursor {
            epoch: [7; 16],
            sequence: 9,
        },
    }
}

fn policy(attempts: usize) -> ElementsTakerSourceConfig {
    ElementsTakerSourceConfig {
        max_blocking_tasks: 1,
        max_snapshot_attempts: attempts,
        snapshot_retry_delay: Duration::ZERO,
    }
}

fn witnessed_txout(marker: u8) -> TxOut {
    let asset_id = asset(marker);
    let script = Script::from(vec![0x51, marker]);
    let secp = Secp256k1::new();
    let abf = AssetBlindingFactor::from_slice(&[marker; 32]).expect("abf");
    let vbf = ValueBlindingFactor::from_slice(&[marker.wrapping_add(1); 32]).expect("vbf");
    let rewind = SecretKey::from_slice(&[marker.wrapping_add(2); 32]).expect("rewind");
    let message = RangeProofMessage {
        asset: asset_id,
        bf: abf,
    };
    let (value, rangeproof) = Value::Explicit(42)
        .blind_with_shared_secret(&secp, vbf, rewind, &script, &message)
        .expect("rangeproof");
    TxOut {
        asset: Asset::Explicit(asset_id),
        value,
        nonce: Nonce::Null,
        script_pubkey: script,
        witness: TxOutWitness {
            surjection_proof: None,
            rangeproof: Some(Box::new(rangeproof)),
        },
    }
}

fn explicit_txout(script_pubkey: Script) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset(0x44)),
        value: Value::Explicit(1),
        nonce: Nonce::Null,
        script_pubkey,
        witness: TxOutWitness::default(),
    }
}

#[test]
fn source_defaults_and_configuration_are_bounded() {
    let config = ElementsTakerSourceConfig::default();
    assert!(config.max_blocking_tasks > 0);
    assert!(config.max_snapshot_attempts > 0);
    assert!(matches!(
        validate_source_config(ElementsTakerSourceConfig {
            max_blocking_tasks: 0,
            ..config
        }),
        Err(ElementsTakerSourceError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        validate_source_config(ElementsTakerSourceConfig {
            max_snapshot_attempts: 0,
            ..config
        }),
        Err(ElementsTakerSourceError::InvalidConfiguration(_))
    ));
}

#[test]
fn inventory_scan_rejects_catalog_bounds_revision_races_and_unrequested_scripts() {
    let (_directory, wallet) = test_wallet();
    wallet
        .fresh_inventory_destination()
        .expect("first catalog destination");
    wallet
        .fresh_inventory_destination()
        .expect("second catalog destination");
    let empty = StaticScan {
        snapshot: InventoryScanSnapshot {
            outputs: Vec::new(),
        },
    };
    assert!(matches!(
        inventory_with_scan(&wallet, 1, &empty),
        Err(ElementsTakerSourceError::CatalogTooLarge {
            maximum: 1,
            actual: 2,
        })
    ));

    let (_directory, wallet) = test_wallet();
    wallet
        .fresh_inventory_destination()
        .expect("initial catalog destination");
    assert!(matches!(
        inventory_with_scan(
            &wallet,
            2,
            &CatalogChangingScan {
                wallet: Arc::clone(&wallet),
            },
        ),
        Err(ElementsTakerSourceError::Wallet(
            PersistentWalletError::TakerCatalogSnapshotMismatch,
        ))
    ));

    let (_directory, wallet) = test_wallet();
    wallet
        .fresh_inventory_destination()
        .expect("catalog destination");
    let outpoint = OutPoint::new(Txid::from_byte_array([0x45; 32]), 0);
    let unexpected = Script::from(vec![0x51]);
    let scan = StaticScan {
        snapshot: InventoryScanSnapshot {
            outputs: vec![InventoryScanOutput {
                script_pubkey: unexpected.clone(),
                outpoint,
                txout: explicit_txout(unexpected),
            }],
        },
    };
    assert!(matches!(
        inventory_with_scan(&wallet, 1, &scan),
        Err(ElementsTakerSourceError::UnexpectedScanScript(observed)) if observed == outpoint
    ));
}

#[test]
fn inventory_scan_requires_wallet_authentication_and_accepts_an_empty_catalog() {
    let (_directory, wallet) = test_wallet();
    assert!(
        inventory_with_scan(
            &wallet,
            1,
            &StaticScan {
                snapshot: InventoryScanSnapshot {
                    outputs: Vec::new(),
                },
            },
        )
        .expect("empty inventory")
        .is_empty()
    );

    let destination = wallet
        .fresh_inventory_destination()
        .expect("catalog destination");
    let script = destination.script_pubkey().clone();
    let scan = StaticScan {
        snapshot: InventoryScanSnapshot {
            outputs: vec![InventoryScanOutput {
                script_pubkey: script.clone(),
                outpoint: OutPoint::new(Txid::from_byte_array([0x46; 32]), 0),
                txout: explicit_txout(script),
            }],
        },
    };
    assert!(matches!(
        inventory_with_scan(&wallet, 1, &scan),
        Err(ElementsTakerSourceError::Wallet(_))
    ));
}

#[test]
fn node_info_requires_exact_identity_ready_tips_and_capabilities() {
    let at = anchor(10, 0x10);
    let expected_chain = chain();
    let policy_asset = asset(9);
    let valid = node_info(at);
    validate_node_info(&valid, expected_chain, policy_asset).expect("valid info");

    let mut wrong = valid.clone();
    wrong.network = LiquidNetwork::LiquidTestnet;
    assert!(matches!(
        validate_node_info(&wrong, expected_chain, policy_asset),
        Err(ElementsTakerSourceError::NodeNetworkMismatch { .. })
    ));
    let mut wrong = valid.clone();
    wrong.genesis_hash = BlockHash::from_byte_array([0xaa; 32]);
    assert!(matches!(
        validate_node_info(&wrong, expected_chain, policy_asset),
        Err(ElementsTakerSourceError::NodeChainMismatch { .. })
    ));
    let mut wrong = valid.clone();
    wrong.policy_asset = asset(0xaa);
    assert!(matches!(
        validate_node_info(&wrong, expected_chain, policy_asset),
        Err(ElementsTakerSourceError::NodePolicyAssetMismatch { .. })
    ));
    for status in [
        SyncStatus::Starting,
        SyncStatus::Syncing,
        SyncStatus::RescanRequired,
        SyncStatus::BackendUnavailable,
    ] {
        let mut wrong = valid.clone();
        wrong.sync_status = status;
        assert!(matches!(
            validate_node_info(&wrong, expected_chain, policy_asset),
            Err(ElementsTakerSourceError::NodeNotReady(actual)) if actual == status
        ));
    }
    let mut wrong = valid.clone();
    wrong.source_tip = None;
    assert!(matches!(
        validate_node_info(&wrong, expected_chain, policy_asset),
        Err(ElementsTakerSourceError::NodeTipsIncoherent { .. })
    ));
    let mut wrong = valid.clone();
    wrong.source_tip = Some(anchor(11, 0x11));
    assert!(matches!(
        validate_node_info(&wrong, expected_chain, policy_asset),
        Err(ElementsTakerSourceError::NodeTipsIncoherent { .. })
    ));
    for missing in [Capability::BinaryMarketV1, Capability::EvidenceQueries] {
        let mut wrong = valid.clone();
        wrong
            .capabilities
            .retain(|capability| *capability != missing);
        assert!(matches!(
            validate_node_info(&wrong, expected_chain, policy_asset),
            Err(ElementsTakerSourceError::MissingNodeCapability(actual)) if actual == missing
        ));
    }
}

#[test]
fn core_policy_asset_must_match_the_wallet_and_node_configuration() {
    let expected = asset(9);
    validate_core_policy_asset(expected, expected).expect("matching Core policy asset");
    assert!(matches!(
        validate_core_policy_asset(expected, asset(10)),
        Err(ElementsTakerSourceError::CorePolicyAssetMismatch {
            expected: observed_expected,
            actual,
        }) if observed_expected == expected && actual == asset(10)
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn canonical_but_stale_market_is_rejected_under_newer_core_tip() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let stale = anchor(10, 0x10);
    let current = anchor(11, 0x11);
    let node = FakeNode::new(
        Arc::clone(&events),
        vec![node_info(stale)],
        vec![market_snapshot(stale)],
    );
    // Returning `current` means the fake Core accepted `stale` as canonical
    // ancestry but observed a newer stable tip. That is insufficient for a
    // current market-state decision and must fail exact-tip equality.
    let core = FakeCore::new(Arc::clone(&events), vec![Ok(current)], vec![]);
    let result = trading_market_with(
        core.clone(),
        &node,
        &Arc::new(Semaphore::new(1)),
        chain(),
        asset(9),
        policy(1),
        market_id(),
    )
    .await;
    assert!(matches!(
        result,
        Err(ElementsTakerSourceError::CoreNodeTipMismatch { node, core })
            if node == stale && core == current
    ));
    let state = core.state.lock().expect("core state");
    assert_eq!(state.begin_calls, vec![CoreOperation::Anchor]);
    assert_eq!(state.canonical_calls.len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn signing_snapshot_rejects_a_canonical_but_stale_trading_market() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let quote = anchor(8, 0x08);
    let stale = anchor(10, 0x10);
    let current = anchor(11, 0x11);
    let node = FakeNode::new(
        Arc::clone(&events),
        vec![node_info(stale)],
        vec![market_snapshot(stale)],
    );
    let core = FakeCore::new(
        Arc::clone(&events),
        vec![],
        vec![Ok(SourcePrevoutSnapshot {
            anchor: current,
            prevouts: Vec::new(),
        })],
    );
    let result = settlement_snapshot_with(
        core,
        &node,
        &Arc::new(Semaphore::new(1)),
        chain(),
        asset(9),
        policy(1),
        SettlementQuery {
            chain: chain(),
            market: market_id(),
            quote_anchor: quote,
            outpoints: Vec::new(),
        },
        || Ok(1),
    )
    .await;
    assert!(matches!(
        result,
        Err(ElementsTakerSourceError::CoreNodeTipMismatch { node, core })
            if node == stale && core == current
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn stale_trading_retry_observes_resolution_before_signing() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let quote = anchor(8, 0x08);
    let stale = anchor(10, 0x10);
    let current = anchor(11, 0x11);
    let node = FakeNode::new(
        Arc::clone(&events),
        vec![node_info(stale), node_info(current)],
        vec![market_snapshot(stale), resolved_market_snapshot(current)],
    );
    let core = FakeCore::new(
        Arc::clone(&events),
        vec![],
        vec![
            Ok(SourcePrevoutSnapshot {
                anchor: current,
                prevouts: Vec::new(),
            }),
            Ok(SourcePrevoutSnapshot {
                anchor: current,
                prevouts: Vec::new(),
            }),
        ],
    );
    let result = settlement_snapshot_with(
        core,
        &node,
        &Arc::new(Semaphore::new(1)),
        chain(),
        asset(9),
        policy(2),
        SettlementQuery {
            chain: chain(),
            market: market_id(),
            quote_anchor: quote,
            outpoints: Vec::new(),
        },
        || Ok(1),
    )
    .await;
    assert!(matches!(
        result,
        Err(ElementsTakerSourceError::Venue(
            RfqVenueError::MarketNotTrading
        ))
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn tip_race_retries_the_entire_node_core_pair_under_one_budget() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let stale = anchor(10, 0x10);
    let current = anchor(11, 0x11);
    let node = FakeNode::new(
        Arc::clone(&events),
        vec![node_info(stale), node_info(current)],
        vec![market_snapshot(stale), market_snapshot(current)],
    );
    let core = FakeCore::new(Arc::clone(&events), vec![Ok(current), Ok(current)], vec![]);
    let market = trading_market_with(
        core.clone(),
        &node,
        &Arc::new(Semaphore::new(1)),
        chain(),
        asset(9),
        policy(2),
        market_id(),
    )
    .await
    .expect("second exact-tip observation");
    assert_eq!(market.observed_at(), current);
    let core_state = core.state.lock().expect("core state");
    assert_eq!(core_state.begin_calls, vec![CoreOperation::Anchor]);
    assert_eq!(core_state.canonical_calls.len(), 2);
    let node_state = node.state.lock().expect("node state");
    assert_eq!(node_state.info_calls, 2);
    assert_eq!(node_state.snapshot_calls, 2);
}

#[tokio::test(flavor = "current_thread")]
async fn same_height_market_reorg_retries_fresh_node_evidence() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let stale = anchor(10, 0x10);
    let current = anchor(10, 0x11);
    let node = FakeNode::new(
        Arc::clone(&events),
        vec![node_info(stale), node_info(current)],
        vec![market_snapshot(stale), market_snapshot(current)],
    );
    let core = FakeCore::new(
        Arc::clone(&events),
        vec![
            Err(ElementsCoreError::AnchorNotCanonical {
                anchor: stale,
                actual: current.hash,
            }),
            Ok(current),
        ],
        vec![],
    );

    let market = trading_market_with(
        core.clone(),
        &node,
        &Arc::new(Semaphore::new(1)),
        chain(),
        asset(9),
        policy(2),
        market_id(),
    )
    .await
    .expect("node and Core converge after a same-height reorg");

    assert_eq!(market.observed_at(), current);
    assert_eq!(
        core.state.lock().expect("core state").canonical_calls.len(),
        2
    );
    assert_eq!(node.state.lock().expect("node state").info_calls, 2);
}

#[tokio::test(flavor = "current_thread")]
async fn settlement_retries_only_a_noncanonical_fresh_market_anchor() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let quote = anchor(8, 0x08);
    let stale = anchor(10, 0x10);
    let current = anchor(10, 0x11);
    let node = FakeNode::new(
        Arc::clone(&events),
        vec![node_info(stale), node_info(current)],
        vec![market_snapshot(stale), market_snapshot(current)],
    );
    let core = FakeCore::new(
        Arc::clone(&events),
        vec![],
        vec![
            Err(ElementsCoreError::AnchorNotCanonical {
                anchor: stale,
                actual: current.hash,
            }),
            Ok(SourcePrevoutSnapshot {
                anchor: current,
                prevouts: Vec::new(),
            }),
        ],
    );

    let snapshot = settlement_snapshot_with(
        core.clone(),
        &node,
        &Arc::new(Semaphore::new(1)),
        chain(),
        asset(9),
        policy(2),
        SettlementQuery {
            chain: chain(),
            market: market_id(),
            quote_anchor: quote,
            outpoints: Vec::new(),
        },
        || Ok(1),
    )
    .await
    .expect("fresh market anchor converges after a same-height reorg");

    assert_eq!(snapshot.market().observed_at(), current);
    let state = core.state.lock().expect("core state");
    assert_eq!(state.prevout_calls.len(), 2);
    assert_eq!(state.prevout_calls[0].1, vec![quote, stale]);
    assert_eq!(state.prevout_calls[1].1, vec![quote, current]);
}

#[tokio::test(flavor = "current_thread")]
async fn noncanonical_provider_quote_anchor_is_terminal() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let quote = anchor(8, 0x08);
    let market = anchor(10, 0x10);
    let node = FakeNode::new(
        Arc::clone(&events),
        vec![node_info(market), node_info(market)],
        vec![market_snapshot(market), market_snapshot(market)],
    );
    let core = FakeCore::new(
        Arc::clone(&events),
        vec![],
        vec![
            Err(ElementsCoreError::AnchorNotCanonical {
                anchor: quote,
                actual: BlockHash::from_byte_array([0xff; 32]),
            }),
            Ok(SourcePrevoutSnapshot {
                anchor: market,
                prevouts: Vec::new(),
            }),
        ],
    );

    let result = settlement_snapshot_with(
        core.clone(),
        &node,
        &Arc::new(Semaphore::new(1)),
        chain(),
        asset(9),
        policy(2),
        SettlementQuery {
            chain: chain(),
            market: market_id(),
            quote_anchor: quote,
            outpoints: Vec::new(),
        },
        || Ok(1),
    )
    .await;

    assert!(matches!(
        result,
        Err(ElementsTakerSourceError::Core(
            ElementsCoreError::AnchorNotCanonical { anchor, .. }
        )) if anchor == quote
    ));
    assert_eq!(
        core.state.lock().expect("core state").prevout_calls.len(),
        1
    );
    assert_eq!(node.state.lock().expect("node state").info_calls, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn persistent_tip_mismatch_exhausts_the_exact_attempt_bound() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let stale = anchor(10, 0x10);
    let current = anchor(11, 0x11);
    let node = FakeNode::new(
        Arc::clone(&events),
        vec![node_info(stale); 3],
        vec![market_snapshot(stale); 3],
    );
    let core = FakeCore::new(
        Arc::clone(&events),
        vec![Ok(current), Ok(current), Ok(current)],
        vec![],
    );
    let result = trading_market_with(
        core.clone(),
        &node,
        &Arc::new(Semaphore::new(1)),
        chain(),
        asset(9),
        policy(3),
        market_id(),
    )
    .await;
    assert!(matches!(
        result,
        Err(ElementsTakerSourceError::CoreNodeTipMismatch { .. })
    ));
    assert_eq!(
        core.state.lock().expect("core state").canonical_calls.len(),
        3
    );
    assert_eq!(node.state.lock().expect("node state").info_calls, 3);
}

#[tokio::test(flavor = "current_thread")]
async fn settlement_preserves_requested_order_witnesses_and_operation_ordering() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let quote = anchor(8, 0x08);
    let current = anchor(11, 0x11);
    let first = OutPoint::new(Txid::from_byte_array([0x42; 32]), 1);
    let second = OutPoint::new(Txid::from_byte_array([0x41; 32]), 0);
    let first_txout = witnessed_txout(0x21);
    let second_txout = witnessed_txout(0x22);
    assert!(first_txout.witness.rangeproof.is_some());
    assert!(second_txout.witness.rangeproof.is_some());
    let node = FakeNode::new(
        Arc::clone(&events),
        vec![node_info(current)],
        vec![market_snapshot(current)],
    );
    let core = FakeCore::new(
        Arc::clone(&events),
        vec![],
        vec![Ok(SourcePrevoutSnapshot {
            anchor: current,
            prevouts: vec![
                SourcePrevout {
                    outpoint: first,
                    txout: first_txout.clone(),
                },
                SourcePrevout {
                    outpoint: second,
                    txout: second_txout.clone(),
                },
            ],
        })],
    );
    let runtime_thread = std::thread::current().id();
    let clock_events = Arc::clone(&events);
    let result = settlement_snapshot_with(
        core.clone(),
        &node,
        &Arc::new(Semaphore::new(1)),
        chain(),
        asset(9),
        policy(1),
        SettlementQuery {
            chain: chain(),
            market: market_id(),
            quote_anchor: quote,
            outpoints: vec![first, second],
        },
        move || {
            clock_events.lock().expect("events").push(Event::Clock);
            Ok(123_456)
        },
    )
    .await
    .expect("coherent settlement snapshot");

    assert_eq!(result.observed_at_millis(), 123_456);
    assert_eq!(result.market().observed_at(), current);
    assert_eq!(result.prevouts()[0].outpoint(), first);
    assert_eq!(result.prevouts()[0].txout(), &first_txout);
    assert_eq!(result.prevouts()[1].outpoint(), second);
    assert_eq!(result.prevouts()[1].txout(), &second_txout);
    let state = core.state.lock().expect("core state");
    assert_eq!(state.begin_calls, vec![CoreOperation::Prevouts]);
    assert_eq!(state.prevout_calls.len(), 1);
    assert_eq!(state.prevout_calls[0].0, vec![first, second]);
    assert_eq!(state.prevout_calls[0].1, vec![quote, current]);
    assert_ne!(state.prevout_calls[0].2, runtime_thread);
    drop(state);

    let events = events.lock().expect("events");
    let beginning = events
        .iter()
        .filter(|event| {
            matches!(
                event,
                Event::Begin | Event::NodeInfo | Event::MarketSnapshot | Event::CorePrevouts
            )
        })
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(
        beginning,
        vec![
            Event::Begin,
            Event::NodeInfo,
            Event::MarketSnapshot,
            Event::CorePrevouts
        ]
    );
    assert_eq!(
        events[events.len() - 2..],
        [Event::Clock, Event::BudgetCheck]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn request_chain_mismatch_fails_before_node_or_core_io() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let node = FakeNode::new(Arc::clone(&events), vec![], vec![]);
    let core = FakeCore::new(Arc::clone(&events), vec![], vec![]);
    let mut wrong_chain = chain();
    wrong_chain.genesis_hash = BlockHash::from_byte_array([0xff; 32]);
    let result = settlement_snapshot_with(
        core.clone(),
        &node,
        &Arc::new(Semaphore::new(1)),
        chain(),
        asset(9),
        policy(1),
        SettlementQuery {
            chain: wrong_chain,
            market: market_id(),
            quote_anchor: anchor(8, 8),
            outpoints: Vec::new(),
        },
        || Ok(1),
    )
    .await;
    assert!(matches!(
        result,
        Err(ElementsTakerSourceError::RequestChainMismatch { .. })
    ));
    assert!(
        core.state
            .lock()
            .expect("core state")
            .begin_calls
            .is_empty()
    );
    assert_eq!(node.state.lock().expect("node state").info_calls, 0);
    assert!(events.lock().expect("events").is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn stalled_node_is_deadline_bounded_without_starting_core_prevout_work() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let node = PendingNode::default();
    let core = FakeCore::new(Arc::clone(&events), vec![], vec![])
        .with_budget_duration(Duration::from_millis(20));
    let result = settlement_snapshot_with(
        core.clone(),
        &node,
        &Arc::new(Semaphore::new(1)),
        chain(),
        asset(9),
        policy(1),
        SettlementQuery {
            chain: chain(),
            market: market_id(),
            quote_anchor: anchor(8, 8),
            outpoints: Vec::new(),
        },
        || Ok(1),
    )
    .await;
    assert!(matches!(
        result,
        Err(ElementsTakerSourceError::OperationTimedOut {
            operation: CoreOperation::Prevouts
        })
    ));
    assert_eq!(node.info_calls.load(Ordering::Relaxed), 1);
    assert_eq!(node.snapshot_calls.load(Ordering::Relaxed), 0);
    assert!(
        core.state
            .lock()
            .expect("core state")
            .prevout_calls
            .is_empty()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn conflicting_same_height_quote_anchor_fails_before_prevout_io() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let current = anchor(11, 0x11);
    let node = FakeNode::new(
        Arc::clone(&events),
        vec![node_info(current)],
        vec![market_snapshot(current)],
    );
    let core = FakeCore::new(Arc::clone(&events), vec![], vec![]);
    let result = settlement_snapshot_with(
        core.clone(),
        &node,
        &Arc::new(Semaphore::new(1)),
        chain(),
        asset(9),
        policy(1),
        SettlementQuery {
            chain: chain(),
            market: market_id(),
            quote_anchor: anchor(11, 0x12),
            outpoints: Vec::new(),
        },
        || Ok(1),
    )
    .await;
    assert!(matches!(
        result,
        Err(ElementsTakerSourceError::ConflictingAnchors { .. })
    ));
    assert!(
        core.state
            .lock()
            .expect("core state")
            .prevout_calls
            .is_empty()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn node_behind_quote_retries_until_the_market_tip_catches_up() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let stale = anchor(10, 0x10);
    let current = anchor(11, 0x11);
    let node = FakeNode::new(
        Arc::clone(&events),
        vec![node_info(stale), node_info(current)],
        vec![market_snapshot(stale), market_snapshot(current)],
    );
    let core = FakeCore::new(
        Arc::clone(&events),
        vec![],
        vec![Ok(SourcePrevoutSnapshot {
            anchor: current,
            prevouts: Vec::new(),
        })],
    );
    let snapshot = settlement_snapshot_with(
        core.clone(),
        &node,
        &Arc::new(Semaphore::new(1)),
        chain(),
        asset(9),
        policy(2),
        SettlementQuery {
            chain: chain(),
            market: market_id(),
            quote_anchor: current,
            outpoints: Vec::new(),
        },
        || Ok(1),
    )
    .await
    .expect("node catches up to the quote anchor");
    assert_eq!(snapshot.market().observed_at(), current);
    assert_eq!(node.state.lock().expect("node state").info_calls, 2);
    let state = core.state.lock().expect("core state");
    assert_eq!(state.prevout_calls.len(), 1);
    assert_eq!(state.prevout_calls[0].1, vec![current]);
}

#[test]
fn retry_classification_is_narrow() {
    let expected = anchor(10, 0x10);
    let actual = anchor(11, 0x11);
    assert!(
        ElementsTakerSourceError::Core(ElementsCoreError::TipChanged { expected, actual })
            .is_convergence_race()
    );
    assert!(
        ElementsTakerSourceError::Core(ElementsCoreError::AnchorAboveTip {
            anchor: actual,
            tip: expected,
        })
        .is_convergence_race()
    );
    assert!(
        ElementsTakerSourceError::Core(ElementsCoreError::PrevoutViewChanged(OutPoint::new(
            Txid::from_byte_array([3; 32]),
            0,
        )))
        .is_convergence_race()
    );
    assert!(
        ElementsTakerSourceError::Core(ElementsCoreError::InconsistentChainTip {
            height: expected.height,
            reported: expected.hash,
            actual: actual.hash,
        })
        .is_convergence_race()
    );
    assert!(
        ElementsTakerSourceError::QuoteAnchorAfterMarket {
            quote: actual,
            market: expected,
        }
        .is_convergence_race()
    );
    assert!(
        !ElementsTakerSourceError::Core(ElementsCoreError::MissingOrSpentPrevout(OutPoint::new(
            Txid::from_byte_array([4; 32]),
            0
        ),))
        .is_convergence_race()
    );
}

#[test]
fn wrong_prevout_order_is_defensively_rejected() {
    let first = OutPoint::new(Txid::from_byte_array([1; 32]), 0);
    let second = OutPoint::new(Txid::from_byte_array([2; 32]), 0);
    let result = map_prevouts(
        &[first, second],
        SourcePrevoutSnapshot {
            anchor: anchor(1, 1),
            prevouts: vec![
                SourcePrevout {
                    outpoint: second,
                    txout: witnessed_txout(0x31),
                },
                SourcePrevout {
                    outpoint: first,
                    txout: witnessed_txout(0x32),
                },
            ],
        },
    );
    assert!(matches!(
        result,
        Err(ElementsTakerSourceError::PrevoutOrderMismatch)
    ));
}

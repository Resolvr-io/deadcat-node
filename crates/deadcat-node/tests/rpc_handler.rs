use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use deadcat_iroh::{RequestHandler as _, SubscriptionItem};
use deadcat_node::chain::{ChainSource, ChainSourceError, Outspend, TransactionStatus};
use deadcat_node::rpc_handler::{NodeRpcHandler, RpcHandlerConfig};
use deadcat_node::store::{
    AssetBinding, AssetRelationKind as StoreAssetRelationKind, BlockDelta,
    ChainIdentity as StoreChainIdentity, ChainTxDelta, ContractParameters, ContractRecord,
    ContractState, RecoveryHintDelta, ScriptBinding, Store, TrackedOutpoint,
};
use deadcat_rpc::{
    AssetRelationKind, BackendKind, Capability, Event, EventFilter, PageRequest, RecoveryFamily,
    Request, Response, RpcErrorCode, SubscriptionEnd,
};
use deadcat_types::{
    BinaryMarketParams, BinaryMarketState, CONTRACT_PACKAGE_FORMAT_VERSION, ChainAnchor,
    ChainIdentity, ChainPosition, ContractDeclaration, ContractDescriptor, ContractId,
    ContractKind, ContractPackage, ContractSyncState, DiscoveryCoverage, DiscoveryMode,
    LiquidNetwork, RecoveryHintLocation,
};
use elements::hashes::Hash as _;
use elements::{
    AssetId, Block, BlockHash, LockTime, OutPoint, Script, Transaction, TxIn, TxOut, Txid,
};

#[derive(Clone, Copy)]
struct MockSource {
    tip: Option<ChainAnchor>,
}

#[async_trait]
impl ChainSource for MockSource {
    async fn tip(&self) -> Result<ChainAnchor, ChainSourceError> {
        self.tip.ok_or_else(|| {
            ChainSourceError::Unavailable("deliberately unavailable test backend".to_owned())
        })
    }

    async fn block_hash(&self, _height: u32) -> Result<BlockHash, ChainSourceError> {
        Err(unused_backend_call())
    }

    async fn block(&self, _hash: BlockHash) -> Result<Block, ChainSourceError> {
        Err(unused_backend_call())
    }

    async fn transaction(&self, _txid: Txid) -> Result<Transaction, ChainSourceError> {
        Err(unused_backend_call())
    }

    async fn transaction_status(&self, _txid: Txid) -> Result<TransactionStatus, ChainSourceError> {
        Err(unused_backend_call())
    }

    async fn outspend(&self, _outpoint: OutPoint) -> Result<Option<Outspend>, ChainSourceError> {
        Err(unused_backend_call())
    }

    async fn script_history(&self, _script: &Script) -> Result<Vec<Txid>, ChainSourceError> {
        Err(unused_backend_call())
    }

    async fn issuance_transaction(
        &self,
        _asset_id: AssetId,
    ) -> Result<Option<Txid>, ChainSourceError> {
        Err(unused_backend_call())
    }

    async fn estimate_fee_rate(&self, _target_blocks: u16) -> Result<f64, ChainSourceError> {
        Err(unused_backend_call())
    }

    async fn broadcast(&self, _transaction: &Transaction) -> Result<Txid, ChainSourceError> {
        Err(unused_backend_call())
    }
}

fn unused_backend_call() -> ChainSourceError {
    ChainSourceError::Unavailable("unexpected mock backend call".to_owned())
}

struct Fixture {
    _directory: tempfile::TempDir,
    store: Arc<Store>,
    handler: NodeRpcHandler<MockSource>,
    market: ContractRecord,
    other_market: ContractRecord,
    transactions: Vec<Transaction>,
    collateral: AssetId,
}

fn block_hash(byte: u8) -> BlockHash {
    BlockHash::from_byte_array([byte; 32])
}

fn anchor(height: u32) -> ChainAnchor {
    ChainAnchor {
        height,
        hash: block_hash(u8::try_from(height).expect("small test height")),
    }
}

fn asset(byte: u8) -> AssetId {
    AssetId::from_slice(&[byte; 32]).expect("asset id")
}

fn transaction(tag: u32) -> Transaction {
    Transaction {
        version: 2,
        lock_time: LockTime::from_consensus(tag),
        input: vec![TxIn::default()],
        output: vec![TxOut::new_fee(u64::from(tag) + 1, asset(0xf0))],
    }
}

fn market_record(marker: u8, transaction: &Transaction, tx_index: u32) -> ContractRecord {
    let collateral = asset(0x20);
    let params = BinaryMarketParams {
        oracle_public_key: [marker.wrapping_add(1); 32],
        collateral_asset_id: collateral,
        yes_token_asset_id: asset(marker.wrapping_add(2)),
        no_token_asset_id: asset(marker.wrapping_add(3)),
        yes_reissuance_token_id: asset(marker.wrapping_add(4)),
        no_reissuance_token_id: asset(marker.wrapping_add(5)),
        base_payout: 100,
        expiry_height: 500,
    };
    let contract_id = ContractId::new(OutPoint::new(transaction.txid(), 0));
    ContractRecord {
        contract_id,
        kind: ContractKind::BinaryMarketV1,
        params: ContractParameters::BinaryMarket(params),
        creation_position: ChainPosition {
            block_height: 1,
            tx_index,
        },
        state: ContractState::BinaryMarket(BinaryMarketState::Trading {
            outstanding_pairs: 10,
        }),
        sync_state: ContractSyncState::Ready {
            synced_through: anchor(1),
        },
        scripts: vec![ScriptBinding {
            role: 0,
            script_pubkey: vec![0x51, marker],
        }],
        assets: vec![
            AssetBinding {
                asset_id: collateral,
                relation: StoreAssetRelationKind::Collateral,
                role: 0,
            },
            AssetBinding {
                asset_id: params.yes_token_asset_id,
                relation: StoreAssetRelationKind::YesToken,
                role: 1,
            },
        ],
        outpoints: vec![TrackedOutpoint {
            role: 0,
            outpoint: OutPoint::new(transaction.txid(), 0),
        }],
    }
}

fn rpc_config(discovery: DiscoveryCoverage) -> RpcHandlerConfig {
    RpcHandlerConfig {
        backend: match discovery.mode {
            DiscoveryMode::FullHintScan => BackendKind::ElementsRpc,
            DiscoveryMode::AdvisoryOnly => BackendKind::Esplora,
        },
        registration_bearer_token: Some("registration-secret".to_owned()),
        max_concurrent_registrations: 1,
        max_concurrent_broadcasts: 1,
        subscription_buffer: 16,
        subscription_poll_interval: Duration::from_millis(1),
    }
}

fn new_store() -> (tempfile::TempDir, Arc<Store>) {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = Arc::new(Store::open(directory.path().join("deadcat.redb")).expect("open store"));
    store
        .initialize_chain(
            StoreChainIdentity {
                network: LiquidNetwork::ElementsRegtest,
                genesis_hash: block_hash(0),
                policy_asset: asset(0x20),
            },
            anchor(0),
        )
        .expect("initialize chain");
    (directory, store)
}

fn fixture() -> Fixture {
    let (directory, store) = new_store();
    let transactions = (1..=2).map(transaction).collect::<Vec<_>>();
    let market = market_record(0x31, &transactions[0], 0);
    let other_market = market_record(0x32, &transactions[1], 1);
    let records = vec![market.clone(), other_market.clone()];
    let relevant_transactions = transactions
        .iter()
        .zip(records)
        .enumerate()
        .map(|(index, (transaction, record))| ChainTxDelta {
            position: ChainPosition {
                block_height: 1,
                tx_index: u32::try_from(index).expect("small transaction count"),
            },
            block_hash: anchor(1).hash,
            txid: transaction.txid(),
            raw_tx: transaction.clone(),
            created_contracts: vec![record],
            state_updates: Vec::new(),
        })
        .collect();
    store
        .apply_block(&BlockDelta {
            anchor: anchor(1),
            prev_block_hash: anchor(0).hash,
            ordered_txids: transactions.iter().map(Transaction::txid).collect(),
            relevant_transactions,
            recovery_hints: vec![RecoveryHintDelta {
                location: RecoveryHintLocation {
                    position: ChainPosition {
                        block_height: 1,
                        tx_index: 0,
                    },
                    output_index: 0,
                },
                creation_txid: transactions[0].txid(),
                family: RecoveryFamily::BinaryMarketV1,
                payload: vec![0xdc, 1],
                associated_contract: Some(market.contract_id),
            }],
        })
        .expect("apply fixture block");

    let discovery = DiscoveryCoverage {
        mode: DiscoveryMode::FullHintScan,
        from: anchor(0),
        scanned_through: anchor(1),
        target_tip: anchor(1),
        canonical_market_complete: true,
    };
    let handler = NodeRpcHandler::new(
        Arc::new(MockSource {
            tip: Some(anchor(1)),
        }),
        Arc::clone(&store),
        rpc_config(discovery),
    )
    .expect("RPC handler");
    Fixture {
        _directory: directory,
        store,
        handler,
        market,
        other_market,
        transactions,
        collateral: asset(0x20),
    }
}

async fn request(
    handler: &NodeRpcHandler<MockSource>,
    request: Request,
) -> Result<Response, deadcat_rpc::RpcError> {
    handler.handle([0x55; 32], request).await
}

#[tokio::test]
async fn market_pages_are_atomic_and_invalidate_after_snapshot_changes() {
    let fixture = fixture();
    let Response::Markets { page: first } = request(
        &fixture.handler,
        Request::ListMarkets {
            page: PageRequest {
                cursor: None,
                limit: 1,
            },
        },
    )
    .await
    .expect("first market page") else {
        panic!("unexpected response")
    };
    assert_eq!(first.contracts.len(), 1);
    let cursor = first.next.expect("second page cursor");
    let Response::Markets { page: second } = request(
        &fixture.handler,
        Request::ListMarkets {
            page: PageRequest {
                cursor: Some(cursor.clone()),
                limit: 1,
            },
        },
    )
    .await
    .expect("stable second page") else {
        panic!("unexpected response")
    };
    assert_eq!(second.snapshot, first.snapshot);
    assert_eq!(second.contracts.len(), 1);
    assert_ne!(
        first.contracts[0].contract_id,
        second.contracts[0].contract_id
    );
    assert_eq!(
        [
            first.contracts[0].contract_id,
            second.contracts[0].contract_id
        ]
        .into_iter()
        .collect::<std::collections::HashSet<_>>(),
        [fixture.market.contract_id, fixture.other_market.contract_id]
            .into_iter()
            .collect()
    );

    fixture
        .store
        .set_sync_status(deadcat_rpc::SyncStatus::Ready)
        .expect("advance event watermark");
    let error = request(
        &fixture.handler,
        Request::ListMarkets {
            page: PageRequest {
                cursor: Some(cursor),
                limit: 1,
            },
        },
    )
    .await
    .expect_err("changed snapshot must invalidate cursor");
    assert_eq!(error.code, RpcErrorCode::SnapshotInvalidated);
}

#[tokio::test]
async fn materialized_hint_and_asset_queries_match_the_canonical_store() {
    let fixture = fixture();
    let Response::RecoveryHints { page: hints } = request(
        &fixture.handler,
        Request::ListRecoveryHints {
            family: None,
            page: PageRequest {
                cursor: None,
                limit: 10,
            },
        },
    )
    .await
    .expect("recovery hints") else {
        panic!("unexpected response")
    };
    assert_eq!(hints.snapshot.as_of, anchor(1));
    assert_eq!(hints.hints.len(), 1);
    assert!(hints.next.is_none());
    assert_eq!(hints.hints[0].family, RecoveryFamily::BinaryMarketV1);
    assert_eq!(
        hints.hints[0].associated_contract,
        Some(fixture.market.contract_id)
    );

    let Response::Asset { lookup } = request(
        &fixture.handler,
        Request::LookupAsset {
            asset_id: fixture.collateral,
        },
    )
    .await
    .expect("asset lookup") else {
        panic!("unexpected response")
    };
    assert!(lookup.relations.iter().any(|relation| {
        relation.contract_id == fixture.market.contract_id
            && relation.kind == AssetRelationKind::Collateral
    }));
    assert!(lookup.relations.iter().all(|relation| {
        relation.kind == AssetRelationKind::Collateral
            && [fixture.market.contract_id, fixture.other_market.contract_id]
                .contains(&relation.contract_id)
    }));
}

#[tokio::test]
async fn get_info_keeps_index_evidence_when_backend_is_unavailable() {
    let (directory, store) = new_store();
    let discovery = DiscoveryCoverage {
        mode: DiscoveryMode::AdvisoryOnly,
        from: anchor(0),
        scanned_through: anchor(0),
        target_tip: anchor(0),
        canonical_market_complete: false,
    };
    let handler = NodeRpcHandler::new(
        Arc::new(MockSource { tip: None }),
        Arc::clone(&store),
        rpc_config(discovery),
    )
    .expect("handler");
    let Response::Info { info } = request(&handler, Request::GetInfo)
        .await
        .expect("node info")
    else {
        panic!("unexpected response")
    };
    assert_eq!(info.source_tip, None);
    assert_eq!(info.indexed_tip, anchor(0));
    assert_eq!(info.discovery, discovery);
    assert!(!info.capabilities.contains(&Capability::FullHintScan));
    assert!(info.capabilities.contains(&Capability::Esplora));
    drop(directory);
}

#[tokio::test]
async fn discovery_completeness_is_derived_from_persisted_tip_status_and_live_source() {
    let (directory, store) = new_store();
    store
        .set_sync_status(deadcat_rpc::SyncStatus::Ready)
        .expect("ready status");
    let full = DiscoveryCoverage {
        mode: DiscoveryMode::FullHintScan,
        from: anchor(0),
        scanned_through: anchor(0),
        target_tip: anchor(0),
        canonical_market_complete: false,
    };
    let caught_up = NodeRpcHandler::new(
        Arc::new(MockSource {
            tip: Some(anchor(0)),
        }),
        Arc::clone(&store),
        rpc_config(full),
    )
    .expect("caught-up handler");
    let Response::Info { info } = request(&caught_up, Request::GetInfo)
        .await
        .expect("caught-up info")
    else {
        panic!("unexpected response")
    };
    assert!(info.discovery.canonical_market_complete);
    assert_eq!(info.discovery.from, anchor(0));
    assert_eq!(info.discovery.scanned_through, anchor(0));

    let advanced = NodeRpcHandler::new(
        Arc::new(MockSource {
            tip: Some(anchor(1)),
        }),
        Arc::clone(&store),
        rpc_config(full),
    )
    .expect("advanced handler");
    let Response::Info { info } = request(&advanced, Request::GetInfo)
        .await
        .expect("advanced info")
    else {
        panic!("unexpected response")
    };
    assert!(!info.discovery.canonical_market_complete);
    assert_eq!(info.discovery.scanned_through, anchor(0));
    assert_eq!(info.discovery.target_tip, anchor(1));
    drop(directory);
}

#[tokio::test]
async fn rescan_required_blocks_every_chain_derived_rpc_before_dispatch() {
    let fixture = fixture();
    let old_cursor = fixture
        .store
        .event_high_watermark()
        .expect("old event cursor");
    fixture
        .store
        .invalidate_for_rebuild()
        .expect("invalidate store");

    let ContractParameters::BinaryMarket(params) = fixture.market.params;
    let package = ContractPackage {
        format_version: CONTRACT_PACKAGE_FORMAT_VERSION,
        chain: ChainIdentity {
            network: LiquidNetwork::ElementsRegtest,
            genesis_hash: block_hash(0),
        },
        roots: vec![fixture.market.contract_id],
        declarations: vec![ContractDeclaration {
            contract_id: fixture.market.contract_id,
            descriptor: ContractDescriptor::BinaryMarketV1 { params },
        }],
    };
    let page = PageRequest {
        cursor: None,
        limit: 10,
    };
    let blocked = vec![
        Request::RegisterContractPackage {
            package,
            bearer_token: None,
        },
        Request::GetContract {
            contract_id: fixture.market.contract_id,
        },
        Request::ListMarkets { page: page.clone() },
        Request::GetMarketSnapshot {
            market_id: fixture.market.contract_id,
        },
        Request::ListRecoveryHints {
            family: None,
            page: page.clone(),
        },
        Request::GetContractHistory {
            contract_id: fixture.market.contract_id,
            after: None,
            limit: 10,
        },
        Request::GetTransaction {
            position: fixture.market.creation_position,
        },
        Request::InterpretTransaction {
            transaction: fixture.transactions[0].clone(),
        },
        Request::LookupAsset {
            asset_id: fixture.collateral,
        },
    ];
    for request_value in blocked {
        let error = request(&fixture.handler, request_value)
            .await
            .expect_err("chain-derived RPC must fail closed");
        assert_eq!(error.code, RpcErrorCode::RescanRequired);
    }

    let Response::Info { info } = request(&fixture.handler, Request::GetInfo)
        .await
        .expect("GetInfo remains available")
    else {
        panic!("unexpected info response")
    };
    assert_eq!(info.sync_status, deadcat_rpc::SyncStatus::RescanRequired);
    assert!(!info.discovery.canonical_market_complete);
    assert_ne!(info.event_high_watermark.epoch, old_cursor.epoch);

    for request_value in [
        Request::EstimateFeerate { target_blocks: 2 },
        Request::BroadcastSignedTransaction {
            transaction: fixture.transactions[0].clone(),
        },
    ] {
        let error = request(&fixture.handler, request_value)
            .await
            .expect_err("mock backend is unavailable");
        assert_eq!(error.code, RpcErrorCode::BackendUnavailable);
    }

    let mut subscription = fixture
        .handler
        .subscribe(
            [0x88; 32],
            Request::SubscribeEvents {
                after: None,
                filter: EventFilter::Contracts {
                    contract_ids: vec![fixture.market.contract_id],
                },
            },
        )
        .await
        .expect("new-epoch subscription remains available");
    let status = recv_event(&mut subscription).await;
    assert!(matches!(
        status.event,
        Event::SyncStatusChanged {
            status: deadcat_rpc::SyncStatus::RescanRequired
        }
    ));
}

#[tokio::test]
async fn registration_auth_is_checked_before_touching_the_backend() {
    let fixture = fixture();
    let package = ContractPackage {
        format_version: CONTRACT_PACKAGE_FORMAT_VERSION,
        chain: ChainIdentity {
            network: LiquidNetwork::ElementsRegtest,
            genesis_hash: block_hash(0),
        },
        roots: Vec::new(),
        declarations: Vec::new(),
    };
    let error = request(
        &fixture.handler,
        Request::RegisterContractPackage {
            package: package.clone(),
            bearer_token: Some("wrong-secret".to_owned()),
        },
    )
    .await
    .expect_err("incorrect token");
    assert_eq!(error.code, RpcErrorCode::Unauthorized);

    let error = request(
        &fixture.handler,
        Request::RegisterContractPackage {
            package,
            bearer_token: Some("registration-secret".to_owned()),
        },
    )
    .await
    .expect_err("empty package");
    assert_eq!(error.code, RpcErrorCode::InvalidRegistration);
}

#[tokio::test]
async fn transaction_evidence_consensus_decodes_the_persisted_transaction() {
    let fixture = fixture();
    let position = ChainPosition {
        block_height: 1,
        tx_index: 1,
    };
    let Response::Transaction {
        evidence: Some(evidence),
    } = request(&fixture.handler, Request::GetTransaction { position })
        .await
        .expect("transaction evidence")
    else {
        panic!("unexpected response")
    };
    assert_eq!(evidence.position, position);
    assert_eq!(evidence.transaction, fixture.transactions[1]);
    assert_eq!(evidence.txid, fixture.transactions[1].txid());
    assert_eq!(
        evidence.affected_contract_ids,
        vec![fixture.other_market.contract_id]
    );
}

#[tokio::test]
async fn subscription_replay_boundary_precedes_events_appended_after_open_without_a_gap() {
    let (_directory, store) = new_store();
    let first = store
        .set_sync_status(deadcat_rpc::SyncStatus::Syncing)
        .expect("first event");
    let discovery = DiscoveryCoverage {
        mode: DiscoveryMode::AdvisoryOnly,
        from: anchor(0),
        scanned_through: anchor(0),
        target_tip: anchor(0),
        canonical_market_complete: false,
    };
    let handler = NodeRpcHandler::new(
        Arc::new(MockSource {
            tip: Some(anchor(0)),
        }),
        Arc::clone(&store),
        rpc_config(discovery),
    )
    .expect("handler");
    let mut subscription = handler
        .subscribe(
            [0x77; 32],
            Request::SubscribeEvents {
                after: None,
                filter: EventFilter::All,
            },
        )
        .await
        .expect("subscription");
    assert_eq!(subscription.through, first);

    let second = store
        .set_sync_status(deadcat_rpc::SyncStatus::Ready)
        .expect("post-open event");
    let replay = recv_event(&mut subscription).await;
    assert_eq!(replay.cursor, first);
    assert!(matches!(
        replay.event,
        Event::SyncStatusChanged {
            status: deadcat_rpc::SyncStatus::Syncing
        }
    ));
    let boundary = recv_event(&mut subscription).await;
    assert_eq!(boundary.cursor, first);
    assert!(matches!(
        boundary.event,
        Event::CaughtUp {
            through_cursor,
            indexed_tip
        } if through_cursor == first && indexed_tip == anchor(0)
    ));
    let live = recv_event(&mut subscription).await;
    assert_eq!(live.cursor, second);
    assert_eq!(live.cursor.sequence, first.sequence + 1);
    assert!(matches!(
        live.event,
        Event::SyncStatusChanged {
            status: deadcat_rpc::SyncStatus::Ready
        }
    ));
}

#[tokio::test]
async fn subscription_opening_never_mixes_events_across_epoch_rotation() {
    let (_directory, store) = new_store();
    let old_high = store
        .set_sync_status(deadcat_rpc::SyncStatus::Syncing)
        .expect("old-epoch event");
    let discovery = DiscoveryCoverage {
        mode: DiscoveryMode::AdvisoryOnly,
        from: anchor(0),
        scanned_through: anchor(0),
        target_tip: anchor(0),
        canonical_market_complete: false,
    };
    let handler = NodeRpcHandler::new(
        Arc::new(MockSource {
            tip: Some(anchor(0)),
        }),
        Arc::clone(&store),
        rpc_config(discovery),
    )
    .expect("handler");
    let mut subscription = handler
        .subscribe(
            [0x78; 32],
            Request::SubscribeEvents {
                after: None,
                filter: EventFilter::All,
            },
        )
        .await
        .expect("subscription");
    assert_eq!(subscription.through, old_high);

    let new_high = store
        .set_sync_status(deadcat_rpc::SyncStatus::RescanRequired)
        .expect("rotate epoch");
    assert_ne!(new_high.epoch, old_high.epoch);

    loop {
        let item = tokio::time::timeout(Duration::from_secs(1), subscription.events.recv())
            .await
            .expect("subscription receive timeout")
            .expect("subscription closed without reason");
        match item {
            SubscriptionItem::Event(event) => assert_eq!(event.cursor.epoch, old_high.epoch),
            SubscriptionItem::End(SubscriptionEnd::StaleCursor) => break,
            SubscriptionItem::End(reason) => panic!("unexpected subscription end: {reason:?}"),
        }
    }
}

async fn recv_event(subscription: &mut deadcat_iroh::Subscription) -> deadcat_rpc::EventEnvelope {
    let item = tokio::time::timeout(Duration::from_secs(1), subscription.events.recv())
        .await
        .expect("subscription receive timeout")
        .expect("subscription closed");
    match item {
        SubscriptionItem::Event(event) => event,
        SubscriptionItem::End(reason) => panic!("subscription ended unexpectedly: {reason:?}"),
    }
}

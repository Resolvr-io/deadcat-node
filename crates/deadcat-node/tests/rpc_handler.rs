use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use deadcat_contracts::maker_order::CompiledMakerOrder;
use deadcat_iroh::{RequestHandler as _, SubscriptionItem};
use deadcat_node::chain::{ChainSource, ChainSourceError, Outspend, TransactionStatus};
use deadcat_node::rpc_handler::{NodeRpcHandler, RpcHandlerConfig};
use deadcat_node::store::{
    AssetBinding, AssetRelationKind as StoreAssetRelationKind, BlockDelta, ChainTxDelta,
    ContractParameters, ContractRecord, ContractState, OrderBookEntry, RecoveryHintDelta,
    RegistrationEvidence, ScriptBinding, StateUpdate, Store, TrackedOutpoint, TransitionRecord,
};
use deadcat_rpc::{
    AssetRelationKind, BackendKind, Capability, Event, EventFilter, PageRequest, RecoveryFamily,
    Request, Response, RpcErrorCode,
};
use deadcat_types::{
    BinaryMarketParams, BinaryMarketState, CONTRACT_PACKAGE_FORMAT_VERSION, ChainAnchor,
    ChainIdentity, ChainPosition, ContractDeclaration, ContractDescriptor, ContractId,
    ContractKind, ContractPackage, ContractSyncState, DiscoveryCoverage, DiscoveryMode,
    LiquidNetwork, MakerOrderParams, MakerOrderState, OrderDirection, OrderSide,
    RecoveryHintLocation,
};
use elements::confidential::{Asset, Nonce, Value};
use elements::hashes::Hash as _;
use elements::{
    AssetId, Block, BlockHash, LockTime, OutPoint, Script, Transaction, TxIn, TxOut, TxOutWitness,
    Txid,
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

#[derive(Clone)]
struct RegistrationSource {
    transaction: Transaction,
    status: TransactionStatus,
}

#[async_trait]
impl ChainSource for RegistrationSource {
    async fn tip(&self) -> Result<ChainAnchor, ChainSourceError> {
        Ok(anchor(1))
    }

    async fn block_hash(&self, _height: u32) -> Result<BlockHash, ChainSourceError> {
        Err(unused_backend_call())
    }

    async fn block(&self, _hash: BlockHash) -> Result<Block, ChainSourceError> {
        Err(unused_backend_call())
    }

    async fn transaction(&self, txid: Txid) -> Result<Transaction, ChainSourceError> {
        if txid == self.transaction.txid() {
            Ok(self.transaction.clone())
        } else {
            Err(ChainSourceError::NotFound(txid.to_string()))
        }
    }

    async fn transaction_status(&self, txid: Txid) -> Result<TransactionStatus, ChainSourceError> {
        if txid == self.transaction.txid() {
            Ok(self.status)
        } else {
            Err(ChainSourceError::NotFound(txid.to_string()))
        }
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
    orders: Vec<ContractRecord>,
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
        parent_market: None,
        outcome_side: None,
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
        order_book: None,
    }
}

#[derive(Clone, Copy)]
struct OrderSpec {
    marker: u8,
    price: u32,
    minimum: u32,
    remaining: u64,
    direction: OrderDirection,
    side: OrderSide,
}

fn order_record(
    spec: OrderSpec,
    transaction: &Transaction,
    tx_index: u32,
    market: &ContractRecord,
) -> ContractRecord {
    let ContractParameters::BinaryMarket(market_params) = market.params else {
        unreachable!("market fixture")
    };
    let base_asset_id = match spec.side {
        OrderSide::Yes => market_params.yes_token_asset_id,
        OrderSide::No => market_params.no_token_asset_id,
    };
    let params = MakerOrderParams {
        base_asset_id,
        quote_asset_id: market_params.collateral_asset_id,
        price: spec.price,
        min_active_base: spec.minimum,
        direction: spec.direction,
        maker_receive_spk_hash: [spec.marker.wrapping_add(1); 32],
        maker_pubkey: [spec.marker.wrapping_add(2); 32],
    };
    let creation_position = ChainPosition {
        block_height: 1,
        tx_index,
    };
    let contract_id = ContractId::new(OutPoint::new(transaction.txid(), 0));
    ContractRecord {
        contract_id,
        kind: ContractKind::MakerOrderV1,
        params: ContractParameters::MakerOrder(params),
        creation_position,
        state: ContractState::MakerOrder(MakerOrderState::Active {
            remaining_base: spec.remaining,
            total_filled_base: 0,
        }),
        sync_state: ContractSyncState::Ready {
            synced_through: anchor(1),
        },
        parent_market: Some(market.contract_id),
        outcome_side: Some(spec.side),
        scripts: vec![ScriptBinding {
            role: 0,
            script_pubkey: vec![0x52, spec.marker],
        }],
        assets: vec![
            AssetBinding {
                asset_id: params.base_asset_id,
                relation: StoreAssetRelationKind::OrderBase,
                role: 0,
            },
            AssetBinding {
                asset_id: params.quote_asset_id,
                relation: StoreAssetRelationKind::OrderQuote,
                role: 1,
            },
        ],
        outpoints: vec![TrackedOutpoint {
            role: 0,
            outpoint: OutPoint::new(transaction.txid(), 0),
        }],
        order_book: Some(OrderBookEntry {
            market_id: market.contract_id,
            side: spec.side,
            direction: spec.direction,
            price: spec.price,
            creation_position,
            remaining_base: spec.remaining,
        }),
    }
}

fn rpc_config(discovery: DiscoveryCoverage) -> RpcHandlerConfig {
    RpcHandlerConfig {
        network: LiquidNetwork::ElementsRegtest,
        genesis_hash: block_hash(0),
        policy_asset: asset(0x20),
        backend: BackendKind::Esplora,
        discovery,
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
    store.initialize_tip(anchor(0)).expect("initialize tip");
    (directory, store)
}

fn fixture() -> Fixture {
    let (directory, store) = new_store();
    let transactions = (1..=6).map(transaction).collect::<Vec<_>>();
    let market = market_record(0x31, &transactions[0], 0);
    let other_market = market_record(0x32, &transactions[1], 1);
    let orders = vec![
        order_record(
            OrderSpec {
                marker: 0x41,
                price: 7,
                minimum: 3,
                remaining: 6,
                direction: OrderDirection::SellBase,
                side: OrderSide::Yes,
            },
            &transactions[2],
            2,
            &market,
        ),
        order_record(
            OrderSpec {
                marker: 0x42,
                price: 3,
                minimum: 3,
                remaining: 10,
                direction: OrderDirection::SellBase,
                side: OrderSide::Yes,
            },
            &transactions[3],
            3,
            &market,
        ),
        order_record(
            OrderSpec {
                marker: 0x43,
                price: 4,
                minimum: 2,
                remaining: 5,
                direction: OrderDirection::SellQuote,
                side: OrderSide::Yes,
            },
            &transactions[4],
            4,
            &market,
        ),
        order_record(
            OrderSpec {
                marker: 0x44,
                price: 8,
                minimum: 2,
                remaining: 7,
                direction: OrderDirection::SellQuote,
                side: OrderSide::Yes,
            },
            &transactions[5],
            5,
            &market,
        ),
    ];
    let records = [vec![market.clone(), other_market.clone()], orders.clone()].concat();
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
            recovery_hints: vec![
                RecoveryHintDelta {
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
                },
                RecoveryHintDelta {
                    location: RecoveryHintLocation {
                        position: ChainPosition {
                            block_height: 1,
                            tx_index: 2,
                        },
                        output_index: 0,
                    },
                    creation_txid: transactions[2].txid(),
                    family: RecoveryFamily::MakerOrderV1,
                    payload: vec![0xdc, 2],
                    associated_contract: None,
                },
            ],
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
        orders,
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
async fn materialized_list_book_hint_and_asset_queries_match_the_canonical_store() {
    let fixture = fixture();
    let Response::Orders { page } = request(
        &fixture.handler,
        Request::ListOrders {
            market_id: fixture.market.contract_id,
            side: Some(OrderSide::Yes),
            direction: Some(OrderDirection::SellBase),
            page: PageRequest {
                cursor: None,
                limit: 10,
            },
        },
    )
    .await
    .expect("orders") else {
        panic!("unexpected response")
    };
    assert_eq!(page.contracts.len(), 2);
    assert!(page.contracts.iter().all(|order| {
        order.parent_market == Some(fixture.market.contract_id)
            && order.outcome_side == Some(OrderSide::Yes)
    }));

    let Response::Orders { page: first } = request(
        &fixture.handler,
        Request::ListOrders {
            market_id: fixture.market.contract_id,
            side: Some(OrderSide::Yes),
            direction: Some(OrderDirection::SellBase),
            page: PageRequest {
                cursor: None,
                limit: 1,
            },
        },
    )
    .await
    .expect("first order page") else {
        panic!("unexpected response")
    };
    let next = first.next.expect("second order cursor");
    let error = request(
        &fixture.handler,
        Request::ListOrders {
            market_id: fixture.market.contract_id,
            side: Some(OrderSide::Yes),
            direction: Some(OrderDirection::SellQuote),
            page: PageRequest {
                cursor: Some(next.clone()),
                limit: 1,
            },
        },
    )
    .await
    .expect_err("changing a cursor's order filter");
    assert_eq!(error.code, RpcErrorCode::SnapshotInvalidated);
    let Response::Orders { page: second } = request(
        &fixture.handler,
        Request::ListOrders {
            market_id: fixture.market.contract_id,
            side: Some(OrderSide::Yes),
            direction: Some(OrderDirection::SellBase),
            page: PageRequest {
                cursor: Some(next),
                limit: 1,
            },
        },
    )
    .await
    .expect("second order page") else {
        panic!("unexpected response")
    };
    assert_eq!(second.contracts.len(), 1);
    assert!(second.next.is_none());

    let Response::OrderBook { book } = request(
        &fixture.handler,
        Request::GetOrderBook {
            market_id: fixture.market.contract_id,
        },
    )
    .await
    .expect("order book") else {
        panic!("unexpected response")
    };
    assert_eq!(
        book.asks
            .iter()
            .map(|level| level.price)
            .collect::<Vec<_>>(),
        vec![3, 7]
    );
    assert_eq!(
        book.bids
            .iter()
            .map(|level| level.price)
            .collect::<Vec<_>>(),
        vec![8, 4]
    );

    let Response::RecoveryHints { page: hints } = request(
        &fixture.handler,
        Request::ListRecoveryHints {
            family: None,
            page: PageRequest {
                cursor: None,
                limit: 1,
            },
        },
    )
    .await
    .expect("recovery hints") else {
        panic!("unexpected response")
    };
    assert_eq!(hints.snapshot.as_of, anchor(1));
    assert_eq!(hints.hints.len(), 1);
    let next = hints.next.expect("second hint cursor");
    let error = request(
        &fixture.handler,
        Request::ListRecoveryHints {
            family: Some(RecoveryFamily::MakerOrderV1),
            page: PageRequest {
                cursor: Some(next.clone()),
                limit: 10,
            },
        },
    )
    .await
    .expect_err("changing a cursor's recovery-hint filter");
    assert_eq!(error.code, RpcErrorCode::SnapshotInvalidated);

    let Response::RecoveryHints { page: hints } = request(
        &fixture.handler,
        Request::ListRecoveryHints {
            family: None,
            page: PageRequest {
                cursor: Some(next),
                limit: 10,
            },
        },
    )
    .await
    .expect("continued recovery hints") else {
        panic!("unexpected response")
    };
    assert_eq!(hints.hints.len(), 1);
    assert_eq!(hints.hints[0].family, RecoveryFamily::MakerOrderV1);
    assert_eq!(hints.hints[0].associated_contract, None);

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
    assert_eq!(
        lookup
            .relations
            .iter()
            .filter(|relation| relation.kind == AssetRelationKind::OrderQuote)
            .count(),
        fixture.orders.len()
    );
}

#[tokio::test]
async fn advisory_routes_use_best_prices_respect_minimums_and_stop_after_resolution() {
    let fixture = fixture();
    let best_ask = fixture.orders[1].contract_id;
    let worse_ask = fixture.orders[0].contract_id;
    let Response::Route { route } = request(
        &fixture.handler,
        Request::SuggestRoute {
            market_id: fixture.market.contract_id,
            side: OrderSide::Yes,
            direction: OrderDirection::SellBase,
            base_amount: 13,
            max_orders: 10,
        },
    )
    .await
    .expect("route") else {
        panic!("unexpected response")
    };
    assert_eq!(
        route
            .legs
            .iter()
            .map(|leg| (leg.order_id, leg.base_amount, leg.quote_amount))
            .collect::<Vec<_>>(),
        vec![(best_ask, 10, 30), (worse_ask, 3, 21)]
    );
    assert_eq!(route.total_base, 13);
    assert_eq!(route.total_quote, 51);

    let Response::Route { route } = request(
        &fixture.handler,
        Request::SuggestRoute {
            market_id: fixture.market.contract_id,
            side: OrderSide::Yes,
            direction: OrderDirection::SellQuote,
            base_amount: 9,
            max_orders: 10,
        },
    )
    .await
    .expect("best-bid route") else {
        panic!("unexpected response")
    };
    assert_eq!(
        route
            .legs
            .iter()
            .map(|leg| (leg.order_id, leg.base_amount, leg.quote_amount))
            .collect::<Vec<_>>(),
        vec![
            (fixture.orders[3].contract_id, 7, 56),
            (fixture.orders[2].contract_id, 2, 8),
        ]
    );
    assert_eq!(route.total_base, 9);
    assert_eq!(route.total_quote, 64);

    let Response::Route { route } = request(
        &fixture.handler,
        Request::SuggestRoute {
            market_id: fixture.market.contract_id,
            side: OrderSide::Yes,
            direction: OrderDirection::SellBase,
            base_amount: 8,
            max_orders: 1,
        },
    )
    .await
    .expect("minimum-aware route") else {
        panic!("unexpected response")
    };
    assert_eq!(route.legs[0].base_amount, 7);
    assert_eq!(route.total_base, 7);

    resolve_market(&fixture);
    let error = request(
        &fixture.handler,
        Request::SuggestRoute {
            market_id: fixture.market.contract_id,
            side: OrderSide::Yes,
            direction: OrderDirection::SellBase,
            base_amount: 3,
            max_orders: 1,
        },
    )
    .await
    .expect_err("resolved market must not be officially routed");
    assert_eq!(error.code, RpcErrorCode::CovenantInvariantViolation);
}

fn resolve_market(fixture: &Fixture) {
    let mut resolution = transaction(100);
    resolution.input = vec![TxIn {
        previous_output: fixture.market.outpoints[0].outpoint,
        ..TxIn::default()
    }];
    let position = ChainPosition {
        block_height: 2,
        tx_index: 0,
    };
    fixture
        .store
        .apply_block(&BlockDelta {
            anchor: anchor(2),
            prev_block_hash: anchor(1).hash,
            ordered_txids: vec![resolution.txid()],
            relevant_transactions: vec![ChainTxDelta {
                position,
                block_hash: anchor(2).hash,
                txid: resolution.txid(),
                raw_tx: resolution.clone(),
                created_contracts: Vec::new(),
                state_updates: vec![StateUpdate {
                    contract_id: fixture.market.contract_id,
                    old_state: fixture.market.state,
                    new_state: ContractState::BinaryMarket(BinaryMarketState::ResolvedYes {
                        collateral_unredeemed: 2_000,
                    }),
                    spent_outpoints: fixture
                        .market
                        .outpoints
                        .iter()
                        .map(|tracked| tracked.outpoint)
                        .collect(),
                    new_outpoints: vec![TrackedOutpoint {
                        role: 0,
                        outpoint: OutPoint::new(resolution.txid(), 0),
                    }],
                    order_remaining_base: None,
                    transition: TransitionRecord {
                        kind: 9,
                        payload: vec![1],
                    },
                }],
            }],
            recovery_hints: Vec::new(),
        })
        .expect("resolve market");
}

#[tokio::test]
async fn get_info_keeps_index_evidence_when_backend_is_unavailable() {
    let (directory, store) = new_store();
    let discovery = DiscoveryCoverage {
        mode: DiscoveryMode::FullHintScan,
        from: anchor(0),
        scanned_through: anchor(0),
        target_tip: anchor(7),
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
    assert!(info.capabilities.contains(&Capability::FullHintScan));
    assert!(info.capabilities.contains(&Capability::Esplora));
    drop(directory);
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
async fn registration_package_rpc_returns_ordered_idempotent_receipts() {
    const VALID_XONLY: [u8; 32] = [
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a,
        0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80,
        0x3a, 0xc0,
    ];

    let directory = tempfile::tempdir().expect("temporary directory");
    let store = Arc::new(
        Store::open(directory.path().join("registration.redb")).expect("open registration store"),
    );
    store.initialize_tip(anchor(1)).expect("initialize tip");

    // Seed an already verified parent market without a full block row so the
    // RPC test can focus on the package boundary and exact maker anchor.
    let parent_transaction = transaction(90);
    let mut parent = market_record(0x31, &parent_transaction, 0);
    parent.sync_state = ContractSyncState::CatchingUp {
        synced_through: anchor(1),
    };
    store
        .register_contract(
            &parent,
            &RegistrationEvidence {
                anchor: anchor(1),
                transaction: Arc::new(parent_transaction),
                associated_hint: None,
            },
        )
        .expect("register parent fixture");
    let ContractParameters::BinaryMarket(parent_params) = parent.params else {
        panic!("parent market params")
    };

    let params = MakerOrderParams {
        base_asset_id: parent_params.yes_token_asset_id,
        quote_asset_id: parent_params.collateral_asset_id,
        price: 5,
        min_active_base: 3,
        direction: OrderDirection::SellBase,
        maker_receive_spk_hash: [0x42; 32],
        maker_pubkey: VALID_XONLY,
    };
    let compiled = CompiledMakerOrder::new(params).expect("compile maker order");
    let creation = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            asset: Asset::Explicit(params.base_asset_id),
            value: Value::Explicit(10),
            nonce: Nonce::Null,
            script_pubkey: compiled.script_pubkey().clone(),
            witness: TxOutWitness::default(),
        }],
    };
    let contract_id = ContractId::new(OutPoint::new(creation.txid(), 0));
    let package = ContractPackage {
        format_version: CONTRACT_PACKAGE_FORMAT_VERSION,
        chain: ChainIdentity {
            network: LiquidNetwork::ElementsRegtest,
            genesis_hash: block_hash(0),
        },
        roots: vec![contract_id],
        declarations: vec![ContractDeclaration {
            contract_id,
            descriptor: ContractDescriptor::MakerOrderV1 {
                parent_market: parent.contract_id,
                side: OrderSide::Yes,
                params,
            },
        }],
    };
    let source = RegistrationSource {
        transaction: creation,
        status: TransactionStatus::Confirmed {
            anchor: anchor(1),
            tx_index: 1,
        },
    };
    let discovery = DiscoveryCoverage {
        mode: DiscoveryMode::AdvisoryOnly,
        from: anchor(1),
        scanned_through: anchor(1),
        target_tip: anchor(1),
        canonical_market_complete: false,
    };
    let handler = NodeRpcHandler::new(Arc::new(source), Arc::clone(&store), rpc_config(discovery))
        .expect("registration handler");

    for already_registered in [false, true] {
        let response = handler
            .handle(
                [0x55; 32],
                Request::RegisterContractPackage {
                    package: package.clone(),
                    bearer_token: Some("registration-secret".to_owned()),
                },
            )
            .await
            .expect("package registration RPC");
        let Response::RegistrationAccepted { registration } = response else {
            panic!("unexpected registration response")
        };
        assert_eq!(registration.roots, vec![contract_id]);
        assert_eq!(registration.contracts.len(), 1);
        assert_eq!(registration.contracts[0].contract_id, contract_id);
        assert_eq!(
            registration.contracts[0].sync_state,
            ContractSyncState::CatchingUp {
                synced_through: anchor(1),
            }
        );
        assert_eq!(
            registration.contracts[0].already_registered,
            already_registered
        );
    }
    assert!(
        store
            .contract(contract_id)
            .expect("registered order lookup")
            .is_some()
    );
}

#[tokio::test]
async fn transaction_evidence_consensus_decodes_the_persisted_transaction() {
    let fixture = fixture();
    let position = ChainPosition {
        block_height: 1,
        tx_index: 3,
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
    assert_eq!(evidence.transaction, fixture.transactions[3]);
    assert_eq!(evidence.txid, fixture.transactions[3].txid());
    assert_eq!(
        evidence.affected_contract_ids,
        vec![fixture.orders[1].contract_id]
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

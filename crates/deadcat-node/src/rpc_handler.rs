//! Iroh RPC application handler over canonical store and chain evidence.

use std::cmp::Reverse;
use std::sync::Arc;
use std::time::Duration;

use deadcat_iroh::{ClientId, RequestHandler, Subscription, SubscriptionItem};
use deadcat_rpc::{
    AssetLookup, AssetRelation, AssetRelationKind, BackendKind, Capability, ContractHistoryPage,
    ContractPage, ContractView, Event, EventEnvelope, EventFilter, FeeRateEstimate, HistoryEntry,
    MarketSnapshot, NodeInfo, OrderBookLevel, OrderBookSnapshot, PackageRegistrationReceipt,
    PageRequest, RecoveryHintPage, RecoveryHintRecord, RegistrationReceipt, Request, Response,
    RouteLeg, RouteSuggestion, RpcError, RpcErrorCode, SnapshotCursor, SnapshotMetadata,
    SubscriptionEnd, TransactionEvidence,
};
use deadcat_types::{
    ChainPosition, ContractKind, ContractSyncState, DiscoveryCoverage, DiscoveryMode,
};
use elements::encode;
use tokio::sync::{Semaphore, mpsc};

use crate::activation::validate_policy_asset;
use crate::chain::{ChainSource, ChainSourceError};
use crate::registration::{RegistrationError, RegistrationVerifier};
use crate::store::{
    AssetRelationKind as StoreAssetRelationKind, ChainIdentity, ContractParameters, ContractRecord,
    ContractState, Store, StoreError, StoreSnapshotCursor, StoreSnapshotMetadata, StoredEvent,
    StoredEventEnvelope,
};
use crate::sync::{ChainInterpreter as _, InterpretationContext, InterpretationMode};

#[derive(Clone, Debug)]
pub struct RpcHandlerConfig {
    pub backend: BackendKind,
    pub registration_bearer_token: Option<String>,
    pub max_concurrent_registrations: usize,
    pub max_concurrent_broadcasts: usize,
    pub subscription_buffer: usize,
    pub subscription_poll_interval: Duration,
}

impl RpcHandlerConfig {
    pub fn validate(&self) -> Result<(), RpcError> {
        if self.max_concurrent_registrations == 0
            || self.max_concurrent_broadcasts == 0
            || self.subscription_buffer == 0
            || self.subscription_poll_interval == Duration::ZERO
        {
            return Err(RpcError::new(
                RpcErrorCode::InvalidTransaction,
                "RPC concurrency limits, subscription buffer, and polling interval must be nonzero",
            ));
        }
        Ok(())
    }
}

pub struct NodeRpcHandler<S> {
    source: Arc<S>,
    store: Arc<Store>,
    identity: ChainIdentity,
    config: RpcHandlerConfig,
    registrations: Arc<Semaphore>,
    broadcasts: Arc<Semaphore>,
}

impl<S> NodeRpcHandler<S>
where
    S: ChainSource,
{
    pub fn new(
        source: Arc<S>,
        store: Arc<Store>,
        config: RpcHandlerConfig,
    ) -> Result<Self, RpcError> {
        config.validate()?;
        let identity = store
            .chain_identity()
            .map_err(store_error)?
            .ok_or_else(|| {
                RpcError::new(
                    RpcErrorCode::NotSynced,
                    "database chain identity is not initialized",
                )
            })?;
        validate_policy_asset(identity.network, identity.policy_asset).map_err(|error| {
            RpcError::new(
                RpcErrorCode::NotSynced,
                format!("database chain identity violates network policy: {error}"),
            )
        })?;
        // Fail closed for embedders as well as the daemon: RPC discovery and
        // recovery metadata require the store's atomically bound activation.
        store.status_snapshot().map_err(store_error)?;
        Ok(Self {
            source,
            store,
            identity,
            registrations: Arc::new(Semaphore::new(config.max_concurrent_registrations)),
            broadcasts: Arc::new(Semaphore::new(config.max_concurrent_broadcasts)),
            config,
        })
    }

    async fn handle_request(&self, request: Request) -> Result<Response, RpcError> {
        let chain_read = Self::request_reads_chain_state(&request);
        let admitted_epoch = if chain_read {
            Some(self.available_chain_state_epoch()?)
        } else {
            self.ensure_request_available(&request)?;
            None
        };
        let response = match request {
            Request::GetInfo => self.get_info().await,
            Request::RegisterContractPackage {
                package,
                bearer_token,
            } => {
                self.authorize_registration(bearer_token.as_deref())?;
                let _permit = Arc::clone(&self.registrations)
                    .try_acquire_owned()
                    .map_err(|_| {
                        RpcError::new(
                            RpcErrorCode::RateLimited,
                            "registration concurrency limit reached",
                        )
                    })?;
                let verifier = RegistrationVerifier::new(
                    self.source.as_ref(),
                    self.store.as_ref(),
                    self.identity.network,
                    self.identity.genesis_hash,
                    self.identity.policy_asset,
                );
                let registrations = verifier
                    .verify_and_register_package(&package)
                    .await
                    .map_err(registration_error)?;
                Ok(Response::RegistrationAccepted {
                    registration: PackageRegistrationReceipt {
                        roots: package.roots,
                        contracts: registrations
                            .into_iter()
                            .map(|(verified, inserted)| RegistrationReceipt {
                                contract_id: verified.record.contract_id,
                                sync_state: verified.record.sync_state,
                                already_registered: !inserted,
                            })
                            .collect(),
                    },
                })
            }
            Request::GetContract { contract_id } => {
                let contract = self
                    .store
                    .contract(contract_id)
                    .map_err(store_error)?
                    .map(contract_view);
                Ok(Response::Contract { contract })
            }
            Request::ListMarkets { page } => self.list_markets(&page),
            Request::GetMarketSnapshot { market_id } => self.market_snapshot(market_id),
            Request::ListOrders {
                market_id,
                side,
                direction,
                page,
            } => self.list_orders(market_id, side, direction, &page),
            Request::GetOrderBook { market_id } => self.order_book(market_id),
            Request::GetContractHistory {
                contract_id,
                after,
                limit,
            } => {
                validate_limit(limit)?;
                let (snapshot, contract, mut history) = self
                    .store
                    .contract_history_snapshot(contract_id)
                    .map_err(store_error)?;
                if contract.is_none() {
                    return Err(RpcError::new(RpcErrorCode::NotFound, "contract not found"));
                }
                history.retain(|entry| after.is_none_or(|after| entry.position > after));
                history.sort_by_key(|entry| entry.position);
                let truncated = history.len() > usize::from(limit);
                history.truncate(usize::from(limit));
                let next = truncated.then(|| history.last().expect("nonzero limit").position);
                Ok(Response::ContractHistory {
                    page: ContractHistoryPage {
                        snapshot: snapshot_metadata(snapshot),
                        contract_id,
                        entries: history
                            .into_iter()
                            .map(|entry| HistoryEntry {
                                position: entry.position,
                                txid: entry.txid,
                                transition_kind: entry.transition.kind,
                                transition_payload: entry.transition.payload,
                            })
                            .collect(),
                        next,
                    },
                })
            }
            Request::GetTransaction { position } => {
                let evidence = self
                    .store
                    .transaction(position)
                    .map_err(store_error)?
                    .map(|stored| {
                        let transaction = encode::deserialize(&stored.raw_tx).map_err(|error| {
                            RpcError::new(
                                RpcErrorCode::BackendUnavailable,
                                format!("stored transaction failed consensus decoding: {error}"),
                            )
                        })?;
                        Ok(TransactionEvidence {
                            position: stored.position,
                            block_hash: stored.block_hash,
                            txid: stored.txid,
                            transaction,
                            affected_contract_ids: stored.affected_contract_ids,
                        })
                    })
                    .transpose()?;
                Ok(Response::Transaction { evidence })
            }
            Request::EstimateFeerate { target_blocks } => {
                let rate = self
                    .source
                    .estimate_fee_rate(target_blocks)
                    .await
                    .map_err(chain_error)?;
                let sats_per_kvb = (rate * 1_000.0).ceil();
                if !sats_per_kvb.is_finite()
                    || sats_per_kvb <= 0.0
                    || sats_per_kvb > u64::MAX as f64
                {
                    return Err(RpcError::new(
                        RpcErrorCode::BackendUnavailable,
                        "backend returned an unusable fee estimate",
                    ));
                }
                Ok(Response::Feerate {
                    estimate: FeeRateEstimate {
                        target_blocks,
                        sats_per_kvb: sats_per_kvb as u64,
                    },
                })
            }
            Request::BroadcastSignedTransaction { transaction } => {
                let _permit = Arc::clone(&self.broadcasts)
                    .try_acquire_owned()
                    .map_err(|_| {
                        RpcError::new(
                            RpcErrorCode::RateLimited,
                            "broadcast concurrency limit reached",
                        )
                    })?;
                let txid = self
                    .source
                    .broadcast(&transaction)
                    .await
                    .map_err(chain_error)?;
                Ok(Response::BroadcastAccepted { txid })
            }
            Request::ListRecoveryHints { family, page } => {
                validate_limit(page.limit)?;
                let cursor = page.cursor.as_ref().map(store_snapshot_cursor);
                let result = self
                    .store
                    .scan_recovery_hints(family, cursor.as_ref(), usize::from(page.limit))
                    .map_err(store_error)?;
                Ok(Response::RecoveryHints {
                    page: RecoveryHintPage {
                        snapshot: snapshot_metadata(result.snapshot),
                        hints: result
                            .items
                            .into_iter()
                            .map(|hint| RecoveryHintRecord {
                                location: hint.location,
                                creation_txid: hint.creation_txid,
                                family: hint.family,
                                payload: hint.payload,
                                associated_contract: hint.associated_contract,
                            })
                            .collect(),
                        next: result.next.map(rpc_snapshot_cursor),
                    },
                })
            }
            Request::LookupAsset { asset_id } => {
                let (_, relations) = self.store.asset_relations(asset_id).map_err(store_error)?;
                Ok(Response::Asset {
                    lookup: AssetLookup {
                        asset_id,
                        relations: relations
                            .into_iter()
                            .map(|relation| AssetRelation {
                                contract_id: relation.contract_id,
                                kind: asset_relation_kind(relation.binding.relation),
                                role: relation.binding.role,
                            })
                            .collect(),
                    },
                })
            }
            Request::InterpretTransaction { transaction } => {
                let snapshot = self.store.snapshot_metadata().map_err(store_error)?;
                let interpreter = crate::interpreter::DeadcatInterpreter::new(
                    self.identity.network,
                    self.identity.policy_asset,
                );
                let interpreted = interpreter
                    .interpret_transaction(
                        &InterpretationContext {
                            store: self.store.as_ref(),
                            anchor: snapshot.as_of,
                            position: ChainPosition {
                                block_height: snapshot.as_of.height,
                                tx_index: 0,
                            },
                            prior_transactions: &[],
                            retained_declarations: &[],
                            mode: InterpretationMode::Canonical,
                        },
                        &transaction,
                    )
                    .map_err(|error| {
                        RpcError::new(RpcErrorCode::CovenantInvariantViolation, error.to_string())
                    })?;
                Ok(Response::Interpretation {
                    interpretation: deadcat_rpc::TransactionInterpretation {
                        txid: transaction.txid(),
                        created_contracts: interpreted
                            .created_contracts
                            .into_iter()
                            .map(contract_view)
                            .collect(),
                        transitions: interpreted
                            .state_updates
                            .into_iter()
                            .map(|update| deadcat_rpc::InterpretedTransition {
                                contract_id: update.contract_id,
                                kind: update.transition.kind,
                                payload: update.transition.payload,
                            })
                            .collect(),
                    },
                })
            }
            Request::SuggestRoute {
                market_id,
                side,
                direction,
                base_amount,
                max_orders,
            } => self.suggest_route(market_id, side, direction, base_amount, max_orders),
            Request::SubscribeEvents { .. } => Err(RpcError::new(
                RpcErrorCode::InvalidTransaction,
                "subscription request used on unary handler",
            )),
        };
        if let Some(expected_epoch) = admitted_epoch {
            let current_epoch = self.available_chain_state_epoch()?;
            if current_epoch != expected_epoch {
                return Err(rescan_required_error());
            }
        }
        response
    }

    async fn get_info(&self) -> Result<Response, RpcError> {
        let source_tip = self.source.tip().await.ok();
        let persisted = self.store.status_snapshot().map_err(store_error)?;
        let indexed_tip = persisted.indexed_tip;
        let sync_status = persisted.sync_status;
        let discovery_mode = match self.config.backend {
            BackendKind::ElementsRpc => DiscoveryMode::FullHintScan,
            BackendKind::Esplora => DiscoveryMode::AdvisoryOnly,
        };
        let discovery = DiscoveryCoverage {
            mode: discovery_mode,
            from: persisted.activation_anchor,
            scanned_through: indexed_tip,
            target_tip: source_tip.unwrap_or(indexed_tip),
            canonical_market_complete: discovery_mode == DiscoveryMode::FullHintScan
                && sync_status == deadcat_rpc::SyncStatus::Ready
                && source_tip == Some(indexed_tip),
        };
        let mut capabilities = vec![
            Capability::BinaryMarketV1,
            Capability::MakerOrderV1,
            match self.config.backend {
                BackendKind::ElementsRpc => Capability::ElementsRpc,
                BackendKind::Esplora => Capability::Esplora,
            },
            Capability::RegisterContractPackage,
            Capability::BroadcastSignedTransaction,
            Capability::EvidenceQueries,
            Capability::DurableSubscriptions,
            Capability::AdvisoryRouting,
        ];
        if discovery.mode == DiscoveryMode::FullHintScan {
            capabilities.push(Capability::FullHintScan);
        }
        Ok(Response::Info {
            info: NodeInfo {
                network: self.identity.network,
                genesis_hash: self.identity.genesis_hash,
                policy_asset: self.identity.policy_asset,
                backend: self.config.backend,
                source_tip,
                indexed_tip,
                sync_status,
                rollback_retention_blocks: 2,
                discovery,
                capabilities,
                event_high_watermark: persisted.event_high_watermark,
            },
        })
    }

    fn list_markets(&self, page: &PageRequest) -> Result<Response, RpcError> {
        validate_limit(page.limit)?;
        let cursor = page.cursor.as_ref().map(store_snapshot_cursor);
        let page = self
            .store
            .ready_markets(cursor.as_ref(), usize::from(page.limit))
            .map_err(store_error)?;
        Ok(Response::Markets {
            page: ContractPage {
                snapshot: snapshot_metadata(page.snapshot),
                contracts: page.items.into_iter().map(contract_view).collect(),
                next: page.next.map(rpc_snapshot_cursor),
            },
        })
    }

    fn market_snapshot(&self, market_id: deadcat_types::ContractId) -> Result<Response, RpcError> {
        let (snapshot, record) = self
            .store
            .contract_snapshot(market_id)
            .map_err(store_error)?;
        let record =
            record.ok_or_else(|| RpcError::new(RpcErrorCode::NotFound, "market not found"))?;
        if record.kind != ContractKind::BinaryMarketV1 {
            return Err(RpcError::new(
                RpcErrorCode::InvalidTransaction,
                "contract is not a binary market",
            ));
        }
        if !matches!(record.sync_state, ContractSyncState::Ready { .. }) {
            return Err(RpcError::new(
                RpcErrorCode::NotSynced,
                "market registration is still catching up",
            ));
        }
        let params = match &record.params {
            ContractParameters::BinaryMarket(params) => *params,
            ContractParameters::MakerOrder(_) => {
                return Err(RpcError::new(
                    RpcErrorCode::BackendUnavailable,
                    "stored market parameters are corrupt",
                ));
            }
        };
        let state = match record.state {
            ContractState::BinaryMarket(state) => state,
            ContractState::MakerOrder(_) => {
                return Err(RpcError::new(
                    RpcErrorCode::BackendUnavailable,
                    "stored market state is corrupt",
                ));
            }
        };
        let live_outpoints = record
            .outpoints
            .iter()
            .map(|tracked| deadcat_rpc::LiveOutpoint {
                role: tracked.role,
                outpoint: tracked.outpoint,
            })
            .collect();
        Ok(Response::MarketSnapshot {
            snapshot: MarketSnapshot {
                snapshot: snapshot_metadata(snapshot),
                contract: contract_view(record),
                params,
                state,
                live_outpoints,
            },
        })
    }

    fn list_orders(
        &self,
        market_id: deadcat_types::ContractId,
        side: Option<deadcat_types::OrderSide>,
        direction: Option<deadcat_types::OrderDirection>,
        page: &PageRequest,
    ) -> Result<Response, RpcError> {
        validate_limit(page.limit)?;
        let cursor = page.cursor.as_ref().map(store_snapshot_cursor);
        let page = self
            .store
            .ready_orders(
                market_id,
                side,
                direction,
                cursor.as_ref(),
                usize::from(page.limit),
            )
            .map_err(store_error)?;
        Ok(Response::Orders {
            page: ContractPage {
                snapshot: snapshot_metadata(page.snapshot),
                contracts: page
                    .items
                    .into_iter()
                    .map(|order| contract_view(order.contract))
                    .collect(),
                next: page.next.map(rpc_snapshot_cursor),
            },
        })
    }

    fn order_book(&self, market_id: deadcat_types::ContractId) -> Result<Response, RpcError> {
        let (snapshot, market, orders) = self
            .store
            .order_book_entries(market_id)
            .map_err(store_error)?;
        let market =
            market.ok_or_else(|| RpcError::new(RpcErrorCode::NotFound, "market not found"))?;
        if market.kind != ContractKind::BinaryMarketV1 {
            return Err(RpcError::new(
                RpcErrorCode::InvalidTransaction,
                "contract is not a binary market",
            ));
        }
        if !matches!(market.sync_state, ContractSyncState::Ready { .. }) {
            return Err(RpcError::new(
                RpcErrorCode::NotSynced,
                "market registration is still catching up",
            ));
        }
        let mut asks = Vec::new();
        let mut bids = Vec::new();
        for order in orders {
            let level = OrderBookLevel {
                contract_id: order.contract.contract_id,
                side: order.entry.side,
                direction: order.entry.direction,
                price: order.entry.price,
                remaining_base: order.entry.remaining_base,
                creation_position: order.entry.creation_position,
            };
            match order.entry.direction {
                deadcat_types::OrderDirection::SellBase => asks.push(level),
                deadcat_types::OrderDirection::SellQuote => bids.push(level),
            }
        }
        asks.sort_by_key(order_book_ask_key);
        bids.sort_by_key(order_book_bid_key);
        Ok(Response::OrderBook {
            book: OrderBookSnapshot {
                snapshot: snapshot_metadata(snapshot),
                market_id,
                asks,
                bids,
            },
        })
    }

    fn suggest_route(
        &self,
        market_id: deadcat_types::ContractId,
        side: deadcat_types::OrderSide,
        direction: deadcat_types::OrderDirection,
        base_amount: u64,
        max_orders: u16,
    ) -> Result<Response, RpcError> {
        if base_amount == 0 || max_orders == 0 || max_orders > 1_000 {
            return Err(RpcError::new(
                RpcErrorCode::InvalidTransaction,
                "base amount must be nonzero and max_orders must be in 1..=1000",
            ));
        }
        let (snapshot, market, mut orders) = self
            .store
            .order_book_entries(market_id)
            .map_err(store_error)?;
        let market =
            market.ok_or_else(|| RpcError::new(RpcErrorCode::NotFound, "market not found"))?;
        if market.kind != ContractKind::BinaryMarketV1 {
            return Err(RpcError::new(
                RpcErrorCode::InvalidTransaction,
                "contract is not a binary market",
            ));
        }
        if !matches!(market.sync_state, ContractSyncState::Ready { .. }) {
            return Err(RpcError::new(
                RpcErrorCode::NotSynced,
                "market registration is still catching up",
            ));
        }
        if !matches!(
            market.state,
            ContractState::BinaryMarket(deadcat_types::BinaryMarketState::Trading { .. })
        ) {
            return Err(RpcError::new(
                RpcErrorCode::CovenantInvariantViolation,
                "official routing stops after the parent market terminates",
            ));
        }
        orders.retain(|order| order.entry.side == side && order.entry.direction == direction);
        orders.sort_by(|left, right| {
            let price = match direction {
                deadcat_types::OrderDirection::SellBase => left.entry.price.cmp(&right.entry.price),
                deadcat_types::OrderDirection::SellQuote => {
                    right.entry.price.cmp(&left.entry.price)
                }
            };
            price
                .then_with(|| {
                    left.entry
                        .creation_position
                        .cmp(&right.entry.creation_position)
                })
                .then_with(|| {
                    left.contract
                        .contract_id
                        .to_fixed_key()
                        .cmp(&right.contract.contract_id.to_fixed_key())
                })
        });

        let mut remaining = base_amount;
        let mut total_base = 0_u64;
        let mut total_quote = 0_u64;
        let mut legs = Vec::new();
        for order in orders {
            if remaining == 0 || legs.len() == usize::from(max_orders) {
                break;
            }
            let ContractParameters::MakerOrder(params) = order.contract.params else {
                return Err(RpcError::new(
                    RpcErrorCode::BackendUnavailable,
                    "order-book index points to non-order parameters",
                ));
            };
            let minimum = u64::from(params.min_active_base);
            let Some(fill) = feasible_route_fill(order.entry.remaining_base, minimum, remaining)
            else {
                continue;
            };
            let quote = fill
                .checked_mul(u64::from(order.entry.price))
                .ok_or_else(|| {
                    RpcError::new(
                        RpcErrorCode::InvalidTransaction,
                        "route quote amount overflows u64",
                    )
                })?;
            total_base = total_base.checked_add(fill).ok_or_else(|| {
                RpcError::new(
                    RpcErrorCode::InvalidTransaction,
                    "route base amount overflows u64",
                )
            })?;
            total_quote = total_quote.checked_add(quote).ok_or_else(|| {
                RpcError::new(
                    RpcErrorCode::InvalidTransaction,
                    "route quote amount overflows u64",
                )
            })?;
            remaining -= fill;
            legs.push(RouteLeg {
                order_id: order.contract.contract_id,
                base_amount: fill,
                quote_amount: quote,
            });
        }
        Ok(Response::Route {
            route: RouteSuggestion {
                snapshot: snapshot_metadata(snapshot),
                market_id,
                legs,
                total_base,
                total_quote,
            },
        })
    }

    fn authorize_registration(&self, supplied: Option<&str>) -> Result<(), RpcError> {
        if let Some(expected) = self.config.registration_bearer_token.as_deref()
            && supplied != Some(expected)
        {
            return Err(RpcError::new(
                RpcErrorCode::Unauthorized,
                "registration bearer token is missing or invalid",
            ));
        }
        Ok(())
    }

    fn ensure_request_available(&self, request: &Request) -> Result<(), RpcError> {
        if self
            .store
            .status_snapshot()
            .map_err(store_error)?
            .sync_status
            == deadcat_rpc::SyncStatus::RescanRequired
            && !matches!(
                request,
                Request::GetInfo
                    | Request::EstimateFeerate { .. }
                    | Request::BroadcastSignedTransaction { .. }
                    | Request::SubscribeEvents { .. }
            )
        {
            return Err(rescan_required_error());
        }
        Ok(())
    }

    fn request_reads_chain_state(request: &Request) -> bool {
        !matches!(
            request,
            Request::GetInfo
                | Request::RegisterContractPackage { .. }
                | Request::EstimateFeerate { .. }
                | Request::BroadcastSignedTransaction { .. }
                | Request::SubscribeEvents { .. }
        )
    }

    fn available_chain_state_epoch(&self) -> Result<[u8; 16], RpcError> {
        let snapshot = self.store.status_snapshot().map_err(store_error)?;
        available_chain_state_epoch(snapshot)
    }

    fn open_subscription(
        &self,
        after: Option<deadcat_types::EventCursor>,
        filter: EventFilter,
    ) -> Result<Subscription, RpcError> {
        // Capture the tip and event boundary and validate the caller's cursor
        // in one redb snapshot so epoch rotation cannot split the opening
        // frame from the replay cursor.
        let opening = self
            .store
            .subscription_snapshot(after)
            .map_err(store_error)?;
        let through = opening.event_high_watermark;
        let (sender, receiver) = mpsc::channel(self.config.subscription_buffer);
        let store = Arc::clone(&self.store);
        let poll_interval = self.config.subscription_poll_interval;
        tokio::spawn(async move {
            let mut cursor = Some(after.unwrap_or(deadcat_types::EventCursor {
                epoch: through.epoch,
                sequence: 0,
            }));
            let mut caught_up = false;
            loop {
                if !caught_up
                    && cursor.is_some_and(|cursor| {
                        cursor.epoch == through.epoch && cursor.sequence >= through.sequence
                    })
                {
                    let caught_up_event = EventEnvelope {
                        cursor: through,
                        event: Event::CaughtUp {
                            through_cursor: through,
                            indexed_tip: opening.indexed_tip,
                        },
                    };
                    if sender
                        .send(SubscriptionItem::Event(caught_up_event))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    cursor = Some(through);
                    caught_up = true;
                    continue;
                }
                match store.events_after(cursor, 256) {
                    Ok(events) => {
                        if events.is_empty() {
                            tokio::time::sleep(poll_interval).await;
                            continue;
                        }
                        for stored in events {
                            if !caught_up && stored.cursor.sequence > through.sequence {
                                // The fixed replay prefix is complete. Emit its
                                // boundary before any event appended after open.
                                cursor = Some(through);
                                break;
                            }
                            cursor = Some(stored.cursor);
                            if event_matches(&stored, &filter, &store)
                                && sender
                                    .send(SubscriptionItem::Event(EventEnvelope {
                                        cursor: stored.cursor,
                                        event: event_from_store(stored.event),
                                    }))
                                    .await
                                    .is_err()
                            {
                                return;
                            }
                        }
                    }
                    Err(StoreError::StaleCursor { .. } | StoreError::CursorAhead { .. }) => {
                        let _ = sender
                            .send(SubscriptionItem::End(SubscriptionEnd::StaleCursor))
                            .await;
                        break;
                    }
                    Err(_) => {
                        let _ = sender
                            .send(SubscriptionItem::End(SubscriptionEnd::ServerShutdown))
                            .await;
                        break;
                    }
                }
            }
        });
        Ok(Subscription {
            through,
            events: receiver,
        })
    }
}

impl<S> RequestHandler for NodeRpcHandler<S>
where
    S: ChainSource,
{
    async fn handle(&self, _peer: ClientId, request: Request) -> Result<Response, RpcError> {
        self.handle_request(request).await
    }

    async fn subscribe(&self, _peer: ClientId, request: Request) -> Result<Subscription, RpcError> {
        match request {
            Request::SubscribeEvents { after, filter } => self.open_subscription(after, filter),
            _ => Err(RpcError::new(
                RpcErrorCode::InvalidTransaction,
                "non-subscription request used on subscription handler",
            )),
        }
    }
}

fn validate_limit(limit: u16) -> Result<(), RpcError> {
    if limit == 0 || limit > 1_000 {
        return Err(RpcError::new(
            RpcErrorCode::InvalidTransaction,
            "page limit must be in 1..=1000",
        ));
    }
    Ok(())
}

fn store_snapshot_cursor(cursor: &SnapshotCursor) -> StoreSnapshotCursor {
    StoreSnapshotCursor {
        as_of: cursor.as_of,
        event_high_watermark: cursor.event_high_watermark,
        scope: cursor.scope,
        after_key: cursor.after_key.clone(),
    }
}

fn rpc_snapshot_cursor(cursor: StoreSnapshotCursor) -> SnapshotCursor {
    SnapshotCursor {
        as_of: cursor.as_of,
        event_high_watermark: cursor.event_high_watermark,
        scope: cursor.scope,
        after_key: cursor.after_key,
    }
}

const fn snapshot_metadata(snapshot: StoreSnapshotMetadata) -> SnapshotMetadata {
    SnapshotMetadata {
        as_of: snapshot.as_of,
        event_high_watermark: snapshot.event_high_watermark,
    }
}

const fn asset_relation_kind(kind: StoreAssetRelationKind) -> AssetRelationKind {
    match kind {
        StoreAssetRelationKind::Collateral => AssetRelationKind::Collateral,
        StoreAssetRelationKind::YesToken => AssetRelationKind::YesToken,
        StoreAssetRelationKind::NoToken => AssetRelationKind::NoToken,
        StoreAssetRelationKind::YesReissuanceToken => AssetRelationKind::YesReissuanceToken,
        StoreAssetRelationKind::NoReissuanceToken => AssetRelationKind::NoReissuanceToken,
        StoreAssetRelationKind::OrderBase => AssetRelationKind::OrderBase,
        StoreAssetRelationKind::OrderQuote => AssetRelationKind::OrderQuote,
    }
}

fn order_book_ask_key(level: &OrderBookLevel) -> (u8, u32, ChainPosition, [u8; 36]) {
    (
        side_byte(level.side),
        level.price,
        level.creation_position,
        level.contract_id.to_fixed_key(),
    )
}

fn order_book_bid_key(level: &OrderBookLevel) -> (u8, Reverse<u32>, ChainPosition, [u8; 36]) {
    (
        side_byte(level.side),
        Reverse(level.price),
        level.creation_position,
        level.contract_id.to_fixed_key(),
    )
}

const fn side_byte(side: deadcat_types::OrderSide) -> u8 {
    match side {
        deadcat_types::OrderSide::Yes => 0,
        deadcat_types::OrderSide::No => 1,
    }
}

/// Choose a covenant-valid greedy fill no larger than the caller's remaining
/// request. A route may be partial; `total_base` makes that explicit.
const fn feasible_route_fill(capacity: u64, minimum: u64, requested: u64) -> Option<u64> {
    if capacity < minimum || requested < minimum {
        return None;
    }
    if requested >= capacity {
        return Some(capacity);
    }
    let remainder = capacity - requested;
    if remainder >= minimum {
        return Some(requested);
    }
    let largest_partial = capacity - minimum;
    if largest_partial >= minimum && largest_partial <= requested {
        Some(largest_partial)
    } else {
        None
    }
}

fn contract_view(record: ContractRecord) -> ContractView {
    let parameters = match record.params {
        ContractParameters::BinaryMarket(params) => {
            deadcat_rpc::ContractParametersView::BinaryMarket { params }
        }
        ContractParameters::MakerOrder(params) => {
            deadcat_rpc::ContractParametersView::MakerOrder { params }
        }
    };
    let state = match record.state {
        ContractState::BinaryMarket(state) => {
            deadcat_rpc::ContractStateView::BinaryMarket { state }
        }
        ContractState::MakerOrder(state) => deadcat_rpc::ContractStateView::MakerOrder { state },
    };
    ContractView {
        contract_id: record.contract_id,
        kind: record.kind,
        sync_state: record.sync_state,
        creation_position: record.creation_position,
        parameters,
        state,
        parent_market: record.parent_market,
        outcome_side: record.outcome_side,
        live_outpoints: record
            .outpoints
            .into_iter()
            .map(|tracked| deadcat_rpc::LiveOutpoint {
                role: tracked.role,
                outpoint: tracked.outpoint,
            })
            .collect(),
    }
}

fn event_matches(event: &StoredEventEnvelope, filter: &EventFilter, store: &Store) -> bool {
    match filter {
        EventFilter::All => true,
        EventFilter::Contracts { contract_ids } => match &event.event {
            StoredEvent::ContractRegistered { contract_id }
            | StoredEvent::ContractReady { contract_id, .. }
            | StoredEvent::BackfillApplied { contract_id, .. } => {
                contract_ids.contains(contract_id)
            }
            StoredEvent::TransactionApplied {
                affected_contract_ids,
                ..
            }
            | StoredEvent::ChainRolledBack {
                affected_contract_ids,
                ..
            } => affected_contract_ids
                .iter()
                .any(|contract_id| contract_ids.contains(contract_id)),
            StoredEvent::SyncStatusChanged { .. } => true,
        },
        EventFilter::MarketTree { market_id } => match &event.event {
            StoredEvent::ContractRegistered { contract_id }
            | StoredEvent::ContractReady { contract_id, .. }
            | StoredEvent::BackfillApplied { contract_id, .. } => store
                .contract(*contract_id)
                .ok()
                .flatten()
                .is_some_and(|record| {
                    record.contract_id == *market_id || record.parent_market == Some(*market_id)
                }),
            StoredEvent::TransactionApplied {
                affected_market_ids,
                ..
            }
            | StoredEvent::ChainRolledBack {
                affected_market_ids,
                ..
            } => affected_market_ids.contains(market_id),
            StoredEvent::SyncStatusChanged { .. } => true,
        },
    }
}

fn event_from_store(event: StoredEvent) -> Event {
    match event {
        StoredEvent::ContractRegistered { contract_id } => {
            Event::ContractRegistered { contract_id }
        }
        StoredEvent::TransactionApplied {
            anchor,
            txid,
            position,
            affected_contract_ids,
            affected_market_ids,
        } => Event::TransactionApplied {
            anchor,
            txid,
            position,
            affected_contract_ids,
            affected_market_ids,
        },
        StoredEvent::BackfillApplied {
            contract_id,
            through,
            transition_count,
        } => Event::BackfillApplied {
            contract_id,
            through,
            transition_count,
        },
        StoredEvent::ContractReady {
            contract_id,
            through,
        } => Event::ContractReady {
            contract_id,
            through,
        },
        StoredEvent::ChainRolledBack {
            old_tip,
            new_tip,
            orphaned_positions,
            affected_contract_ids,
            affected_market_ids,
        } => Event::ChainRolledBack {
            old_tip,
            new_tip,
            orphaned_positions,
            affected_contract_ids,
            affected_market_ids,
        },
        StoredEvent::SyncStatusChanged { status } => Event::SyncStatusChanged { status },
    }
}

// `Result::map_err` hands ownership to this shared conversion boundary.
#[allow(clippy::needless_pass_by_value)]
fn chain_error(error: ChainSourceError) -> RpcError {
    let code = match &error {
        ChainSourceError::NotFound(_) => RpcErrorCode::NotFound,
        ChainSourceError::BroadcastRejected(_) => RpcErrorCode::InvalidTransaction,
        ChainSourceError::Unavailable(_) | ChainSourceError::BranchChanged => {
            RpcErrorCode::BackendUnavailable
        }
        ChainSourceError::InvalidData(_) => RpcErrorCode::BackendUnavailable,
        ChainSourceError::Unsupported(_) => RpcErrorCode::UnsupportedOperation,
    };
    RpcError::new(code, error.to_string())
}

fn rescan_required_error() -> RpcError {
    RpcError::new(
        RpcErrorCode::RescanRequired,
        "chain-derived state is unavailable until the required rebuild completes",
    )
}

fn available_chain_state_epoch(
    snapshot: crate::store::StoreStatusSnapshot,
) -> Result<[u8; 16], RpcError> {
    if snapshot.sync_status == deadcat_rpc::SyncStatus::RescanRequired {
        return Err(rescan_required_error());
    }
    Ok(snapshot.event_high_watermark.epoch)
}

#[allow(clippy::needless_pass_by_value)]
fn store_error(error: StoreError) -> RpcError {
    let code = match &error {
        StoreError::StaleCursor { .. } | StoreError::CursorAhead { .. } => {
            RpcErrorCode::StaleCursor
        }
        StoreError::RebuildRequired => RpcErrorCode::RescanRequired,
        StoreError::StaleSnapshotCursor { .. }
        | StoreError::InvalidSnapshotKey { .. }
        | StoreError::SnapshotScopeMismatch { .. } => RpcErrorCode::SnapshotInvalidated,
        StoreError::ContractNotFound(_) | StoreError::MaterializedMarketNotFound(_) => {
            RpcErrorCode::NotFound
        }
        StoreError::MaterializedContractIsNotMarket(_) => RpcErrorCode::InvalidTransaction,
        StoreError::MaterializedMarketNotReady(_) => RpcErrorCode::NotSynced,
        StoreError::ForkConflict { .. } => RpcErrorCode::ForkConflict,
        _ => RpcErrorCode::BackendUnavailable,
    };
    RpcError::new(code, error.to_string())
}

fn registration_error(error: RegistrationError) -> RpcError {
    let message = error.to_string();
    let code = match error {
        RegistrationError::Chain(error) => match error {
            ChainSourceError::NotFound(_) => RpcErrorCode::NotFound,
            ChainSourceError::BroadcastRejected(_) | ChainSourceError::InvalidData(_) => {
                RpcErrorCode::InvalidRegistration
            }
            ChainSourceError::Unavailable(_) | ChainSourceError::BranchChanged => {
                RpcErrorCode::BackendUnavailable
            }
            ChainSourceError::Unsupported(_) => RpcErrorCode::UnsupportedOperation,
        },
        RegistrationError::Store(error) => match error {
            StoreError::RebuildRequired => RpcErrorCode::RescanRequired,
            StoreError::ContractNotFound(_) => RpcErrorCode::NotFound,
            StoreError::ForkConflict { .. } => RpcErrorCode::ForkConflict,
            StoreError::TipNotInitialized => RpcErrorCode::NotSynced,
            StoreError::InvalidContract(_)
            | StoreError::PreActivationContract { .. }
            | StoreError::ContractAlreadyExists(_)
            | StoreError::InvalidRegistrationEvidence(_)
            | StoreError::RegistrationTransactionConflict(_)
            | StoreError::OutpointAlreadyOwned { .. } => RpcErrorCode::InvalidRegistration,
            _ => RpcErrorCode::BackendUnavailable,
        },
        RegistrationError::ParentMarketNotFound => RpcErrorCode::NotFound,
        RegistrationError::UnconfirmedCreation
        | RegistrationError::PreActivationCreation { .. }
        | RegistrationError::WrongChain
        | RegistrationError::InvalidPackage(_)
        | RegistrationError::ParentIsNotMarket
        | RegistrationError::Compilation(_)
        | RegistrationError::InvalidCreation(_) => RpcErrorCode::InvalidRegistration,
    };
    RpcError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_fill_respects_fill_and_remainder_minimums() {
        assert_eq!(feasible_route_fill(10, 3, 10), Some(10));
        assert_eq!(feasible_route_fill(10, 3, 4), Some(4));
        // Filling eight would leave dust, so the largest valid partial leaves
        // the three-unit minimum active remainder.
        assert_eq!(feasible_route_fill(10, 3, 8), Some(7));
        assert_eq!(feasible_route_fill(5, 3, 4), None);
        assert_eq!(feasible_route_fill(10, 3, 2), None);
    }

    #[test]
    fn order_book_keys_put_best_prices_first_per_side() {
        use elements::hashes::Hash as _;

        let level = |side, price, tx_byte| OrderBookLevel {
            contract_id: deadcat_types::ContractId::new(elements::OutPoint::new(
                elements::Txid::from_byte_array([tx_byte; 32]),
                u32::from(tx_byte),
            )),
            side,
            direction: deadcat_types::OrderDirection::SellBase,
            price,
            remaining_base: 1,
            creation_position: ChainPosition {
                block_height: 1,
                tx_index: u32::from(tx_byte),
            },
        };
        let low = level(deadcat_types::OrderSide::Yes, 4, 1);
        let high = level(deadcat_types::OrderSide::Yes, 9, 2);
        assert!(order_book_ask_key(&low) < order_book_ask_key(&high));
        assert!(order_book_bid_key(&high) < order_book_bid_key(&low));
    }

    #[test]
    fn registration_store_conflicts_are_reported_as_invalid_registration() {
        let error = registration_error(RegistrationError::Store(
            StoreError::InvalidRegistrationEvidence("conflict".to_owned()),
        ));
        assert_eq!(error.code, RpcErrorCode::InvalidRegistration);
    }

    #[test]
    fn handler_rejects_wrong_production_policy_before_advertising_capabilities() {
        use crate::chain::esplora::{EsploraChainSource, EsploraConfig};
        use elements::hashes::Hash as _;

        let directory = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(
            Store::open(directory.path().join("deadcat.redb")).expect("open malformed store"),
        );
        store
            .bind_chain(ChainIdentity {
                network: deadcat_types::LiquidNetwork::Liquid,
                genesis_hash: elements::BlockHash::from_byte_array([0x11; 32]),
                policy_asset: crate::activation::production_policy_asset(
                    deadcat_types::LiquidNetwork::LiquidTestnet,
                )
                .expect("testnet policy asset"),
            })
            .expect("write malformed legacy identity");
        let source = Arc::new(
            EsploraChainSource::new(EsploraConfig::new("http://127.0.0.1:1"))
                .expect("offline source"),
        );
        let error = match NodeRpcHandler::new(
            source,
            store,
            RpcHandlerConfig {
                backend: BackendKind::ElementsRpc,
                registration_bearer_token: None,
                max_concurrent_registrations: 1,
                max_concurrent_broadcasts: 1,
                subscription_buffer: 1,
                subscription_poll_interval: Duration::from_millis(1),
            },
        ) {
            Ok(_) => panic!("wrong production policy asset must reject handler construction"),
            Err(error) => error,
        };
        assert_eq!(error.code, RpcErrorCode::NotSynced);
        assert!(error.message.contains("violates network policy"));
        assert!(error.message.contains("conflicts with immutable"));
    }

    #[test]
    fn chain_state_epoch_revalidation_rejects_a_concurrent_invalidation() {
        use elements::hashes::Hash as _;

        let directory = tempfile::tempdir().expect("tempdir");
        let store = Store::open(directory.path().join("deadcat.redb")).expect("open store");
        let activation = deadcat_types::ChainAnchor {
            height: 0,
            hash: elements::BlockHash::from_byte_array([0x11; 32]),
        };
        store
            .initialize_chain(
                ChainIdentity {
                    network: deadcat_types::LiquidNetwork::ElementsRegtest,
                    genesis_hash: activation.hash,
                    policy_asset: elements::AssetId::from_slice(&[0x22; 32]).expect("asset"),
                },
                activation,
            )
            .expect("initialize chain");
        let admitted =
            available_chain_state_epoch(store.status_snapshot().expect("admission snapshot"))
                .expect("chain state initially available");
        store.invalidate_for_rebuild().expect("invalidate");
        let error =
            available_chain_state_epoch(store.status_snapshot().expect("post-dispatch snapshot"))
                .expect_err("post-dispatch epoch check must reject invalidation");
        assert_eq!(error.code, RpcErrorCode::RescanRequired);
        assert_ne!(
            admitted,
            store.event_high_watermark().expect("rotated cursor").epoch
        );
    }
}

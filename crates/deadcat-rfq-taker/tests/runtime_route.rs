use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use deadcat_client::composition::CompositionLimits;
use deadcat_client::validation::validate_contract_view;
use deadcat_client::venue::{AssetAmount, VenueContext};
use deadcat_contracts::binary_market::BinaryMarketSlot;
use deadcat_rfq_client::{
    AuthoritativeTakerPrevout, ExecutionJournal as _, ExecutionJournalObservation, ProviderTarget,
    RedbExecutionJournal, RfqSession, SessionConfig, TakerSettlementSnapshot,
    TakerSettlementSource, TradingMarket,
};
use deadcat_rfq_iroh::{ClientConfig, DiscoveryMode, RequestHandler, Server, ServerConfig};
use deadcat_rfq_rpc::{
    AssetAmountDto, BlinderRoleDto, FeePolicyDto, FeeSizeMetricDto, FirmQuoteDto, FixedBytes32,
    FixedBytes33, IdempotencyKeyDto, PricingDecisionDto, ProviderCapability, ProviderInfo,
    QuoteExecutionDto, QuoteInputDto, QuoteKindDto, QuoteOutputDto, QuoteOutputRoleDto,
    QuoteRecipientDto, Request, ReservationStateDto, ReservationStatusDto, Response, RpcError,
    SettlementPset, SignedFirmQuote, SnapshotEvidenceDto, TxOutDto,
};
use deadcat_rfq_taker::{
    ExactInRfqTrade, ExactOutRfqTrade, FeePlanningError, FundingRecoveryError, PostArmFailure,
    RfqTakerConfig, RfqTakerError, RfqTakerRuntime, TakerInventorySource,
};
use deadcat_rfq_wallet::{
    KdfParams, PersistentRfqWallet, TakerFundingError, TakerFundingLimits, TakerWalletIdentity,
    TakerWalletUtxo,
};
use deadcat_rpc::{ContractParametersView, ContractStateView, ContractView, LiveOutpoint};
use deadcat_types::{
    BinaryMarketParams, BinaryMarketState, ChainAnchor, ChainIdentity, ChainPosition, ContractId,
    ContractKind, ContractSyncState, LiquidNetwork,
};
use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::hashes::Hash as _;
use elements::secp256k1_zkp::{Keypair, PublicKey, Secp256k1, SecretKey as SecpSecretKey};
use elements::{AssetId, BlockHash, OutPoint, Script, TxOut, TxOutSecrets, TxOutWitness, Txid};
use iroh::{EndpointId, SecretKey};
use rand::SeedableRng as _;
use rand::rngs::StdRng;

const CREATED_AT_MILLIS: u64 = 1_000;
const ACCEPT_BEFORE_MILLIS: u64 = 31_000;
const AMBIGUOUS_EXECUTE_DELAY_MILLIS: usize = 1_500;
const AMBIGUOUS_REQUEST_TIMEOUT_MILLIS: u64 = 1_000;
const RESERVATION_ID: FixedBytes32 = FixedBytes32::new([0x61; 32]);
const QUOTE_COMMITMENT: FixedBytes32 = FixedBytes32::new([0x62; 32]);
const ALL_CAPABILITIES: [ProviderCapability; 5] = [
    ProviderCapability::FirmQuotes,
    ProviderCapability::ProviderBlinding,
    ProviderCapability::SettlementExecution,
    ProviderCapability::DurableStatus,
    ProviderCapability::SettlementRelay,
];

fn asset(marker: u8) -> AssetId {
    AssetId::from_slice(&[marker; 32]).expect("fixture asset")
}

fn outpoint(marker: u8, vout: u32) -> OutPoint {
    OutPoint::new(Txid::from_byte_array([marker; 32]), vout)
}

fn keypair(marker: u8) -> Keypair {
    let secret = SecpSecretKey::from_slice(&[marker; 32]).expect("fixture secret key");
    Keypair::from_secret_key(&Secp256k1::new(), &secret)
}

fn p2tr_script(marker: u8) -> Script {
    let (internal_key, _) = keypair(marker).x_only_public_key();
    Script::new_v1_p2tr(&Secp256k1::new(), internal_key, None)
}

fn blinding_public_key(marker: u8) -> PublicKey {
    let secret = SecpSecretKey::from_slice(&[marker; 32]).expect("fixture blinding key");
    PublicKey::from_secret_key(&Secp256k1::new(), &secret)
}

fn quote_recipient(spend_marker: u8, blinding_marker: u8) -> QuoteRecipientDto {
    QuoteRecipientDto {
        script_pubkey: p2tr_script(spend_marker).as_bytes().to_vec(),
        blinding_public_key: FixedBytes33::new(blinding_public_key(blinding_marker).serialize()),
    }
}

fn confidential_p2tr_txout(asset: AssetId, amount: u64) -> (TxOut, TxOutSecrets) {
    let secp = Secp256k1::new();
    let explicit = TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(amount),
        nonce: Nonce::Null,
        script_pubkey: p2tr_script(0x71),
        witness: TxOutWitness::empty(),
    };
    let mut rng = StdRng::from_seed([0x73; 32]);
    let (txout, asset_bf, value_bf, _) = explicit
        .to_non_last_confidential(
            &mut rng,
            &secp,
            blinding_public_key(0x72),
            &[TxOutSecrets::new(
                asset,
                AssetBlindingFactor::zero(),
                amount,
                ValueBlindingFactor::zero(),
            )],
        )
        .expect("confidential provider prevout");
    (txout, TxOutSecrets::new(asset, asset_bf, amount, value_bf))
}

fn chain() -> ChainIdentity {
    ChainIdentity {
        network: LiquidNetwork::ElementsRegtest,
        genesis_hash: BlockHash::from_byte_array([0x21; 32]),
    }
}

fn contract_id() -> ContractId {
    ContractId::new(outpoint(0x31, 0))
}

fn trading_market(policy_asset: AssetId, outcome_asset: AssetId) -> (TradingMarket, ChainIdentity) {
    let chain = chain();
    let creation = contract_id().creation_anchor();
    let params = BinaryMarketParams {
        oracle_public_key: keypair(0x32).x_only_public_key().0.serialize(),
        collateral_asset_id: policy_asset,
        yes_token_asset_id: outcome_asset,
        no_token_asset_id: asset(0x43),
        yes_reissuance_token_id: asset(0x44),
        no_reissuance_token_id: asset(0x45),
        base_payout: 100,
        expiry_height: 500,
    };
    let observed_at = ChainAnchor {
        height: 100,
        hash: BlockHash::from_byte_array([0x33; 32]),
    };
    let view = ContractView {
        contract_id: contract_id(),
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
    let validated = validate_contract_view(&view).expect("valid trading market view");
    let market = TradingMarket::from_validated(&validated, chain, policy_asset)
        .expect("current validated trading market");
    (market, chain)
}

fn quote(
    provider: EndpointId,
    request: &deadcat_rfq_rpc::FirmQuoteRequestDto,
    market: &TradingMarket,
    provider_prevout: &TxOut,
) -> FirmQuoteDto {
    let (input, output) = match request.kind {
        QuoteKindDto::ExactIn {
            input,
            output_asset,
            ..
        } => (
            input,
            AssetAmountDto {
                asset: output_asset,
                amount: 180,
            },
        ),
        QuoteKindDto::ExactOut {
            input_asset,
            output,
            ..
        } => (
            AssetAmountDto {
                asset: input_asset,
                amount: 100,
            },
            output,
        ),
    };
    let provider_recipient = quote_recipient(0x51, 0x52);
    FirmQuoteDto {
        reservation_id: RESERVATION_ID,
        provider_endpoint: FixedBytes32::new(*provider.as_bytes()),
        network: request.context.network,
        genesis_hash: request.context.genesis_hash,
        policy_asset: request.context.policy_asset,
        request: request.clone(),
        execution: QuoteExecutionDto {
            input,
            output,
            input_asset_venue_fee: 10,
        },
        pricing: PricingDecisionDto {
            rate: deadcat_rfq_rpc::RationalRateDto {
                numerator: 2,
                denominator: 1,
            },
            input_asset_venue_fee: 10,
            policy_id: FixedBytes32::new([0x63; 32]),
            revision: 1,
        },
        snapshot: SnapshotEvidenceDto {
            block_hash: market.observed_at().hash,
            block_height: market.observed_at().height,
            snapshot_commitment: FixedBytes32::new([0x65; 32]),
            allocation_revision: 2,
            eligible_commitment: FixedBytes32::new([0x66; 32]),
        },
        inputs: vec![QuoteInputDto {
            id: 7,
            outpoint: outpoint(0x67, 0),
            witness_utxo: TxOutDto::from_txout(provider_prevout),
            internal_key: FixedBytes32::new(keypair(0x71).x_only_public_key().0.serialize()),
            inventory_binding: FixedBytes32::new([0x68; 32]),
        }],
        outputs: vec![
            QuoteOutputDto {
                id: 11,
                role: QuoteOutputRoleDto::ProviderPayment,
                asset: input.asset,
                amount: input.amount,
                destination: provider_recipient.clone(),
                blinder: BlinderRoleDto::TakerPaymentInput,
            },
            QuoteOutputDto {
                id: 12,
                role: QuoteOutputRoleDto::TakerReceive,
                asset: output.asset,
                amount: output.amount,
                destination: request.recipient.clone(),
                blinder: BlinderRoleDto::ProviderInput { quote_input_id: 7 },
            },
            QuoteOutputDto {
                id: 13,
                role: QuoteOutputRoleDto::ProviderChange,
                asset: output.asset,
                amount: 200 - output.amount,
                destination: provider_recipient,
                blinder: BlinderRoleDto::ProviderInput { quote_input_id: 7 },
            },
        ],
        created_at_millis: CREATED_AT_MILLIS,
        accept_before_millis: ACCEPT_BEFORE_MILLIS,
        fee_policy: FeePolicyDto {
            policy_asset: request.context.policy_asset,
            minimum_sats_per_kvb: 1,
            minimum_absolute_fee: 10,
            maximum_transaction_weight: 100_000,
            size_metric: FeeSizeMetricDto::DiscountVbytes,
        },
        recovery_metadata_commitment: FixedBytes32::new([0x69; 32]),
        quote_commitment: QUOTE_COMMITMENT,
    }
}

fn status(state: ReservationStateDto) -> ReservationStatusDto {
    ReservationStatusDto {
        reservation_id: RESERVATION_ID,
        quote_commitment: QUOTE_COMMITMENT,
        created_at_millis: CREATED_AT_MILLIS,
        accept_before_millis: ACCEPT_BEFORE_MILLIS,
        state,
    }
}

fn committed_status() -> ReservationStatusDto {
    status(ReservationStateDto::Committed {
        signing_commitment: FixedBytes32::new([0x6a; 32]),
        committed_at_millis: 2_000,
    })
}

#[derive(Default)]
struct ObservedRequests {
    quote_count: usize,
    blind_count: usize,
    execute_count: usize,
    events: Vec<&'static str>,
}

struct FixtureHandler {
    provider_key: SecretKey,
    chain: ChainIdentity,
    policy_asset: AssetId,
    market: TradingMarket,
    provider_prevout: TxOut,
    provider_input_secrets: TxOutSecrets,
    observed: Arc<Mutex<ObservedRequests>>,
    committed: AtomicBool,
    execute_delay_millis: AtomicUsize,
}

impl RequestHandler for FixtureHandler {
    async fn handle(&self, peer: [u8; 32], request: Request) -> Result<Response, RpcError> {
        Ok(match request {
            Request::GetInfo => Response::Info {
                info: ProviderInfo {
                    provider_endpoint: FixedBytes32::new(*self.provider_key.public().as_bytes()),
                    network: self.chain.network,
                    genesis_hash: self.chain.genesis_hash,
                    policy_asset: self.policy_asset,
                    capabilities: ALL_CAPABILITIES.to_vec(),
                },
            },
            Request::RequestFirmQuote {
                idempotency_key,
                request,
            } => {
                let client = EndpointId::from_bytes(&peer).expect("authenticated fixture peer");
                let quote = quote(
                    self.provider_key.public(),
                    &request,
                    &self.market,
                    &self.provider_prevout,
                );
                let signed =
                    SignedFirmQuote::sign(quote, &self.provider_key, client, idempotency_key)
                        .expect("structurally valid provider quote");
                self.observed
                    .lock()
                    .expect("observed request lock")
                    .quote_count += 1;
                Response::FirmQuote {
                    quote: signed,
                    status: status(ReservationStateDto::Reserved),
                }
            }
            Request::CancelReservation { .. } => Response::ReservationCancelled {
                status: status(ReservationStateDto::Released {
                    reason: deadcat_rfq_rpc::ReleaseReasonDto::ClientCancelled,
                    at_millis: 1_500,
                }),
            },
            Request::BlindPset {
                reservation_id,
                layout,
                pset,
            } => {
                let provider_input = usize::from(
                    layout
                        .provider_inputs
                        .first()
                        .expect("fixture provider input placement")
                        .transaction_index,
                );
                let mut provider_pset = pset.to_pset().expect("submitted settlement PSET");
                provider_pset
                    .blind_non_last(
                        &mut StdRng::from_seed([0x74; 32]),
                        &Secp256k1::new(),
                        &HashMap::from([(provider_input, self.provider_input_secrets)]),
                    )
                    .expect("provider non-last blinding turn");
                self.observed
                    .lock()
                    .expect("observed request lock")
                    .blind_count += 1;
                Response::BlindedPset {
                    reservation_id,
                    pset: SettlementPset::from_pset(&provider_pset).expect("provider-blinded PSET"),
                }
            }
            Request::Execute { .. } => {
                let delay_millis = self.execute_delay_millis.load(Ordering::Relaxed);
                if delay_millis != 0 {
                    tokio::time::sleep(Duration::from_millis(delay_millis as u64)).await;
                }
                self.committed.store(true, Ordering::Release);
                let mut observed = self.observed.lock().expect("observed request lock");
                observed.execute_count += 1;
                observed.events.push("execute");
                Response::ExecutionAccepted {
                    status: committed_status(),
                }
            }
            Request::GetReservationStatus { .. } => {
                let committed = self.committed.load(Ordering::Acquire);
                self.observed
                    .lock()
                    .expect("observed request lock")
                    .events
                    .push("status");
                Response::ReservationStatus {
                    status: if committed {
                        committed_status()
                    } else {
                        status(ReservationStateDto::Reserved)
                    },
                }
            }
        })
    }
}

struct TestSource {
    chain: ChainIdentity,
    market: TradingMarket,
    inventory: Vec<TakerWalletUtxo>,
    prevouts: BTreeMap<OutPoint, TxOut>,
}

impl TakerInventorySource for TestSource {
    type Error = std::io::Error;

    fn inventory(&self) -> Result<Vec<TakerWalletUtxo>, Self::Error> {
        Ok(self.inventory.clone())
    }
}

impl TakerSettlementSource for TestSource {
    type Error = std::io::Error;

    fn settlement_snapshot(
        &self,
        chain: ChainIdentity,
        market: ContractId,
        quote_anchor: ChainAnchor,
        outpoints: &[OutPoint],
    ) -> Result<TakerSettlementSnapshot, Self::Error> {
        if chain != self.chain
            || market != self.market.contract_id()
            || quote_anchor != self.market.observed_at()
        {
            return Err(std::io::Error::other(
                "settlement snapshot binding mismatch",
            ));
        }
        let prevouts = outpoints
            .iter()
            .map(|outpoint| {
                self.prevouts
                    .get(outpoint)
                    .cloned()
                    .map(|txout| AuthoritativeTakerPrevout::new(*outpoint, txout))
                    .ok_or_else(|| std::io::Error::other("requested prevout is not unspent"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(TakerSettlementSnapshot::new(
            2_000,
            self.market.clone(),
            prevouts,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeRouteKind {
    ExactIn,
    ExactOut,
}

#[derive(Clone, Debug)]
enum FixtureTrade {
    ExactIn(ExactInRfqTrade),
    ExactOut(ExactOutRfqTrade),
}

fn taker_funding_utxo(
    wallet: &PersistentRfqWallet,
    asset: AssetId,
    amount: u64,
    outpoint_marker: u8,
    blinding_seed: u8,
) -> (OutPoint, TxOut, TakerWalletUtxo) {
    let destination = wallet
        .fresh_inventory_destination()
        .expect("durable taker funding destination");
    let explicit = TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(amount),
        nonce: Nonce::Null,
        script_pubkey: destination.script_pubkey().clone(),
        witness: TxOutWitness::empty(),
    };
    let txout = explicit
        .to_non_last_confidential(
            &mut StdRng::from_seed([blinding_seed; 32]),
            &Secp256k1::new(),
            destination.blinding_public_key(),
            &[TxOutSecrets::new(
                asset,
                AssetBlindingFactor::zero(),
                amount,
                ValueBlindingFactor::zero(),
            )],
        )
        .expect("confidential taker funding output")
        .0;
    let outpoint = outpoint(outpoint_marker, 0);
    let utxo = wallet
        .recover_taker_utxo(destination.wallet_locator(), outpoint, txout.clone())
        .expect("wallet-authenticated taker funding output");
    (outpoint, txout, utxo)
}

fn empty_taker_wallet(
    identity: TakerWalletIdentity,
) -> (tempfile::TempDir, Arc<PersistentRfqWallet>) {
    let directory = tempfile::tempdir().expect("identity-check wallet directory");
    let wallet = PersistentRfqWallet::create_taker_with_kdf(
        directory.path().join("wallet.redb"),
        identity,
        b"runtime-route-identity-check-passphrase",
        KdfParams::new(8 * 1_024, 1, 1).expect("test KDF"),
    )
    .expect("identity-check taker wallet");
    (directory, Arc::new(wallet))
}

async fn run_runtime_route(
    execute_delay_millis: usize,
    reject_foreign_runtime: bool,
    reject_wrong_session_identity: bool,
    route_kind: RuntimeRouteKind,
    maximum_network_fee: u64,
) {
    let provider_key = SecretKey::from_bytes(&[0x11; 32]);
    let client_key = SecretKey::from_bytes(&[0x12; 32]);
    let expected_client = *client_key.public().as_bytes();
    let policy_asset = asset(0x41);
    let outcome_asset = asset(0x42);
    let (market, chain) = trading_market(policy_asset, outcome_asset);
    let provider_asset = match route_kind {
        RuntimeRouteKind::ExactIn => outcome_asset,
        RuntimeRouteKind::ExactOut => policy_asset,
    };
    let (provider_prevout, provider_input_secrets) = confidential_p2tr_txout(provider_asset, 200);
    let observed = Arc::new(Mutex::new(ObservedRequests::default()));
    let handler = Arc::new(FixtureHandler {
        provider_key: provider_key.clone(),
        chain,
        policy_asset,
        market: market.clone(),
        provider_prevout: provider_prevout.clone(),
        provider_input_secrets,
        observed: Arc::clone(&observed),
        committed: AtomicBool::new(false),
        execute_delay_millis: AtomicUsize::new(execute_delay_millis),
    });
    let server = Server::bind(
        provider_key,
        DiscoveryMode::Disabled,
        ServerConfig::default(),
        Arc::clone(&handler),
    )
    .await
    .expect("bind direct RFQ server");
    let target = ProviderTarget::new(server.endpoint_addr(), chain, policy_asset);
    let server = server.spawn();
    let transport = ClientConfig {
        request_timeout: if execute_delay_millis == 0 {
            Duration::from_secs(10)
        } else {
            Duration::from_millis(AMBIGUOUS_REQUEST_TIMEOUT_MILLIS)
        },
        ..ClientConfig::default()
    };
    let session_config =
        SessionConfig::new(transport, 60_000, 1_000).expect("valid session config");
    let session = RfqSession::dial_direct(target, client_key, session_config)
        .await
        .expect("provider-pinned RFQ session");

    let wallet_directory = tempfile::tempdir().expect("taker wallet directory");
    let wallet_owner = if reject_wrong_session_identity {
        [0x91; 32]
    } else {
        expected_client
    };
    let taker_identity = TakerWalletIdentity::new(wallet_owner, chain.genesis_hash, policy_asset)
        .expect("taker wallet identity");
    let wallet = Arc::new(
        PersistentRfqWallet::create_taker_with_kdf(
            wallet_directory.path().join("wallet.redb"),
            taker_identity,
            b"runtime-route-test-passphrase",
            KdfParams::new(8 * 1_024, 1, 1).expect("test KDF"),
        )
        .expect("persistent taker wallet"),
    );
    let payer_asset = match route_kind {
        RuntimeRouteKind::ExactIn => policy_asset,
        RuntimeRouteKind::ExactOut => outcome_asset,
    };
    let payer_amount = match route_kind {
        RuntimeRouteKind::ExactIn => 200,
        RuntimeRouteKind::ExactOut => 120,
    };
    let (payer, payer_txout, payer_utxo) =
        taker_funding_utxo(&wallet, payer_asset, payer_amount, 0x83, 0x75);
    let mut inventory = vec![payer_utxo];
    let mut prevouts =
        BTreeMap::from([(payer, payer_txout), (outpoint(0x67, 0), provider_prevout)]);
    let mut expected_taker_outpoints = BTreeSet::from([payer]);
    if route_kind == RuntimeRouteKind::ExactOut {
        let (fee_outpoint, fee_txout, fee_utxo) =
            taker_funding_utxo(&wallet, policy_asset, 100, 0x84, 0x76);
        inventory.push(fee_utxo);
        prevouts.insert(fee_outpoint, fee_txout);
        expected_taker_outpoints.insert(fee_outpoint);
    }
    let source = TestSource {
        chain,
        market: market.clone(),
        inventory,
        prevouts,
    };

    let journal_directory = tempfile::tempdir().expect("execution journal directory");
    let journal_path = journal_directory.path().join("executions.redb");
    let journal = RedbExecutionJournal::create(&journal_path).expect("durable execution journal");
    let config = RfqTakerConfig::new(
        TakerFundingLimits::default(),
        CompositionLimits::default(),
        1,
    )
    .expect("valid taker runtime configuration");
    let runtime = RfqTakerRuntime::from_source(
        Arc::clone(&wallet),
        taker_identity,
        &source,
        journal,
        config,
    )
    .expect("authoritative inventory and empty journal initialize funding");
    let context = VenueContext {
        chain,
        market: contract_id(),
        policy_asset,
    };
    let trade = match route_kind {
        RuntimeRouteKind::ExactIn => FixtureTrade::ExactIn(ExactInRfqTrade::new(
            context,
            AssetAmount::new(policy_asset, 100).expect("nonzero input"),
            outcome_asset,
            170,
            10,
            maximum_network_fee,
        )),
        RuntimeRouteKind::ExactOut => FixtureTrade::ExactOut(ExactOutRfqTrade::new(
            context,
            outcome_asset,
            110,
            AssetAmount::new(policy_asset, 180).expect("nonzero output"),
            10,
            maximum_network_fee,
        )),
    };

    let reserved = match &trade {
        FixtureTrade::ExactIn(trade) => runtime.reserve_exact_in(&market, trade.clone()),
        FixtureTrade::ExactOut(trade) => runtime.reserve_exact_out(&market, trade.clone()),
    }
    .expect("full worst-case funding is leased before quote I/O");
    assert_eq!(
        observed.lock().expect("observed request lock").quote_count,
        0,
        "reserving funding does not contact the provider"
    );
    let concurrent = match &trade {
        FixtureTrade::ExactIn(trade) => runtime.reserve_exact_in(&market, trade.clone()),
        FixtureTrade::ExactOut(trade) => runtime.reserve_exact_out(&market, trade.clone()),
    };
    assert!(matches!(
        concurrent,
        Err(RfqTakerError::Funding(
            TakerFundingError::InsufficientFunds { .. }
        ))
    ));

    let prepared = reserved
        .request_quote_at(&session, IdempotencyKeyDto::new([0x86; 32]), 1_500, 1_500)
        .await;
    if reject_wrong_session_identity {
        assert!(matches!(
            prepared,
            Err(RfqTakerError::SessionClientIdentityMismatch { expected, actual })
                if expected == wallet_owner && actual == expected_client
        ));
        let observed = observed.lock().expect("observed request lock");
        assert_eq!(observed.quote_count, 0);
        assert_eq!(observed.blind_count, 0);
        assert_eq!(observed.execute_count, 0);
        drop(observed);

        session.close().await;
        server.shutdown_and_join().await.expect("server shutdown");
        return;
    }
    let prepared = prepared.expect("authenticated live quote keeps the funding lease");
    if route_kind == RuntimeRouteKind::ExactOut {
        let execution = prepared.quote().quote().execution;
        assert_eq!(execution.input.asset, outcome_asset);
        assert_eq!(execution.input.amount, 100);
        assert!(execution.input.amount < 110, "quote uses less than the cap");
        assert_eq!(execution.output.asset, policy_asset);
        assert_eq!(execution.output.amount, 180);
        assert_eq!(execution.input_asset_venue_fee, 10);
    }
    if reject_foreign_runtime {
        let foreign_wallet_directory = tempfile::tempdir().expect("foreign taker wallet directory");
        let foreign_wallet = Arc::new(
            PersistentRfqWallet::create_taker_with_kdf(
                foreign_wallet_directory.path().join("wallet.redb"),
                taker_identity,
                b"foreign-runtime-test-passphrase",
                KdfParams::new(8 * 1_024, 1, 1).expect("test KDF"),
            )
            .expect("independent foreign taker wallet"),
        );
        let foreign_source = TestSource {
            chain,
            market: market.clone(),
            inventory: Vec::new(),
            prevouts: BTreeMap::new(),
        };
        let foreign_journal_directory =
            tempfile::tempdir().expect("foreign execution journal directory");
        let foreign_journal =
            RedbExecutionJournal::create(foreign_journal_directory.path().join("executions.redb"))
                .expect("foreign durable execution journal");
        let foreign_runtime = RfqTakerRuntime::from_source(
            foreign_wallet,
            taker_identity,
            &foreign_source,
            foreign_journal,
            config,
        )
        .expect("second runtime has independent provenance");

        assert!(matches!(
            foreign_runtime
                .accept_at(&session, &source, prepared, 1_600, 1_700)
                .await,
            Err(RfqTakerError::ForeignPreparedTrade)
        ));
        let observed = observed.lock().expect("observed request lock");
        assert_eq!(observed.quote_count, 1);
        assert_eq!(observed.blind_count, 0);
        assert_eq!(observed.execute_count, 0);
        drop(observed);

        session.close().await;
        server.shutdown_and_join().await.expect("server shutdown");
        return;
    }
    let result = runtime
        .accept_at(&session, &source, prepared, 1_600, 1_700)
        .await;
    if maximum_network_fee < 25 {
        assert!(matches!(
            result,
            Err(RfqTakerError::Fee(
                FeePlanningError::MaximumNetworkFeeExceeded {
                    maximum: 24,
                    required: 25,
                }
            ))
        ));
        let observed = observed.lock().expect("observed request lock");
        assert_eq!(observed.quote_count, 1);
        assert_eq!(observed.blind_count, 0);
        assert_eq!(observed.execute_count, 0);
        drop(observed);

        let released = match &trade {
            FixtureTrade::ExactIn(trade) => runtime.reserve_exact_in(&market, trade.clone()),
            FixtureTrade::ExactOut(trade) => runtime.reserve_exact_out(&market, trade.clone()),
        };
        drop(released.expect("pre-Blind fee rejection releases the process-local lease"));

        session.close().await;
        server.shutdown_and_join().await.expect("server shutdown");
        return;
    }
    let handle = if execute_delay_millis == 0 {
        let handle = result.expect("accepted Execute response is journaled before return");
        assert!(matches!(
            handle.observation(),
            ExecutionJournalObservation::Committed(_)
        ));
        handle
    } else {
        let error = result.expect_err("the provider may commit after the client Execute timeout");
        let handle = match error {
            RfqTakerError::PostArm {
                handle,
                failure: PostArmFailure::Execute(_),
            } => handle,
            other => panic!("unexpected acceptance error: {other:?}"),
        };
        assert_eq!(handle.observation(), &ExecutionJournalObservation::Armed);
        handle
    };
    assert_eq!(handle.taker_outpoints(), &expected_taker_outpoints);
    assert!(runtime.is_ready());
    let reused = match &trade {
        FixtureTrade::ExactIn(trade) => runtime.reserve_exact_in(&market, trade.clone()),
        FixtureTrade::ExactOut(trade) => runtime.reserve_exact_out(&market, trade.clone()),
    };
    assert!(matches!(
        reused,
        Err(RfqTakerError::Funding(
            TakerFundingError::InsufficientFunds { .. }
        ))
    ));

    let recovered = if execute_delay_millis == 0 {
        handle
    } else {
        tokio::time::sleep(Duration::from_millis(
            u64::try_from(execute_delay_millis).expect("fixture delay fits u64") + 100,
        ))
        .await;
        runtime
            .recover(&session, handle.key())
            .await
            .expect("status-first recovery records the provider's committed result")
    };
    assert!(matches!(
        recovered.observation(),
        ExecutionJournalObservation::Committed(_)
    ));
    {
        let observed = observed.lock().expect("observed request lock");
        assert_eq!(observed.quote_count, 1);
        assert_eq!(observed.blind_count, 1);
        assert_eq!(observed.execute_count, 1);
        if execute_delay_millis == 0 {
            assert_eq!(observed.events, ["execute"]);
        } else {
            assert_eq!(observed.events, ["execute", "status"]);
        }
    }

    let recovered_key = recovered.key();
    drop(runtime);
    if execute_delay_millis == 0 {
        let foreign_client_identity = TakerWalletIdentity::new(
            [0x92; 32],
            taker_identity.genesis_hash(),
            taker_identity.policy_asset(),
        )
        .expect("foreign client identity");
        let (_foreign_client_directory, foreign_client_wallet) =
            empty_taker_wallet(foreign_client_identity);
        let foreign_client_journal =
            RedbExecutionJournal::open(&journal_path).expect("reopen for client identity check");
        assert!(matches!(
            RfqTakerRuntime::from_source(
                foreign_client_wallet,
                foreign_client_identity,
                &source,
                foreign_client_journal,
                config,
            ),
            Err(RfqTakerError::FundingRecovery(
                FundingRecoveryError::JournalClientEndpointMismatch { .. }
            ))
        ));

        let foreign_chain_identity = TakerWalletIdentity::new(
            taker_identity.owner(),
            BlockHash::from_byte_array([0x93; 32]),
            taker_identity.policy_asset(),
        )
        .expect("foreign chain identity");
        let (_foreign_chain_directory, foreign_chain_wallet) =
            empty_taker_wallet(foreign_chain_identity);
        let foreign_chain_journal =
            RedbExecutionJournal::open(&journal_path).expect("reopen for chain identity check");
        assert!(matches!(
            RfqTakerRuntime::from_source(
                foreign_chain_wallet,
                foreign_chain_identity,
                &source,
                foreign_chain_journal,
                config,
            ),
            Err(RfqTakerError::FundingRecovery(
                FundingRecoveryError::JournalGenesisHashMismatch { .. }
            ))
        ));

        let foreign_policy_identity = TakerWalletIdentity::new(
            taker_identity.owner(),
            taker_identity.genesis_hash(),
            asset(0x94),
        )
        .expect("foreign policy identity");
        let (_foreign_policy_directory, foreign_policy_wallet) =
            empty_taker_wallet(foreign_policy_identity);
        let foreign_policy_journal =
            RedbExecutionJournal::open(&journal_path).expect("reopen for policy identity check");
        assert!(matches!(
            RfqTakerRuntime::from_source(
                foreign_policy_wallet,
                foreign_policy_identity,
                &source,
                foreign_policy_journal,
                config,
            ),
            Err(RfqTakerError::FundingRecovery(
                FundingRecoveryError::JournalPolicyAssetMismatch { .. }
            ))
        ));
    }
    let reopened =
        RedbExecutionJournal::open(&journal_path).expect("reopen the existing durable journal");
    let durable = reopened
        .load(recovered_key)
        .expect("read journal")
        .expect("execution remains durable");
    let transaction = durable
        .attempt()
        .pset()
        .to_pset()
        .expect("journaled canonical PSET")
        .extract_tx()
        .expect("journaled finalized transaction");
    assert_eq!(
        transaction.fee_in(policy_asset),
        25,
        "100,000 WU at 1 sat/kvB selects a conservative 25-sat fee"
    );
    assert!(matches!(
        durable.observation(),
        ExecutionJournalObservation::Committed(_)
    ));
    let restarted = RfqTakerRuntime::from_source(
        Arc::clone(&wallet),
        taker_identity,
        &source,
        reopened,
        config,
    )
    .expect("restart reconstructs exclusions from the complete journal");
    let pending = restarted
        .pending_executions()
        .expect("restart discovers every non-released execution without a pre-known key");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].key(), recovered_key);
    assert_eq!(pending[0].taker_outpoints(), &expected_taker_outpoints);
    assert!(matches!(
        pending[0].observation(),
        ExecutionJournalObservation::Committed(_)
    ));
    let reused_after_restart = match trade {
        FixtureTrade::ExactIn(trade) => restarted.reserve_exact_in(&market, trade),
        FixtureTrade::ExactOut(trade) => restarted.reserve_exact_out(&market, trade),
    };
    assert!(matches!(
        reused_after_restart,
        Err(RfqTakerError::Funding(
            TakerFundingError::InsufficientFunds { .. }
        ))
    ));

    session.close().await;
    server.shutdown_and_join().await.expect("server shutdown");
}

#[tokio::test(flavor = "multi_thread")]
async fn runtime_accepts_and_journals_an_exact_in_route() {
    run_runtime_route(0, false, false, RuntimeRouteKind::ExactIn, 100).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn runtime_accepts_exact_out_below_the_gross_input_cap_with_separate_fee_funding() {
    run_runtime_route(0, false, false, RuntimeRouteKind::ExactOut, 100).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn runtime_rejects_a_fee_above_the_user_cap_before_blinding_and_releases_funding() {
    run_runtime_route(0, false, false, RuntimeRouteKind::ExactIn, 24).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn runtime_recovers_an_ambiguous_execute_without_reusing_taker_funding() {
    run_runtime_route(
        AMBIGUOUS_EXECUTE_DELAY_MILLIS,
        false,
        false,
        RuntimeRouteKind::ExactIn,
        100,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn runtime_rejects_a_trade_prepared_by_another_runtime_before_blinding() {
    run_runtime_route(0, true, false, RuntimeRouteKind::ExactIn, 100).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn runtime_rejects_a_non_wallet_session_before_requesting_a_quote() {
    run_runtime_route(0, false, true, RuntimeRouteKind::ExactIn, 100).await;
}

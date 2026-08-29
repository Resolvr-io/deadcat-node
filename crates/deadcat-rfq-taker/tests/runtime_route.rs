use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::pending;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use deadcat_client::composition::CompositionLimits;
use deadcat_client::validation::validate_contract_view;
use deadcat_client::venue::{AssetAmount, VenueContext};
use deadcat_contracts::binary_market::BinaryMarketSlot;
use deadcat_rfq_client::{
    AuthoritativeTakerPrevout, ExecutionJournal as _, ExecutionJournalBinding,
    ExecutionJournalError, ExecutionJournalObservation, ProviderTarget, RedbExecutionJournal,
    RfqSession, SessionConfig, TakerAuthorizationError, TakerSettlementSnapshot,
    TakerSettlementSnapshotRequest, TakerSettlementSource, TradingMarket,
};
use deadcat_rfq_iroh::{
    ClientConfig, DiscoveryMode, RequestHandler, Server, ServerConfig, SpawnedServer,
};
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
    KdfParams, PersistentRfqWallet, TakerFundingError, TakerFundingLimits, TakerFundingPool,
    TakerWalletIdentity, TakerWalletUtxo,
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
use tokio::sync::Notify;

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

#[async_trait]
impl TakerInventorySource for TestSource {
    type Error = std::io::Error;

    async fn inventory(&self) -> Result<Vec<TakerWalletUtxo>, Self::Error> {
        Ok(self.inventory.clone())
    }
}

#[async_trait]
impl TakerSettlementSource for TestSource {
    type Error = std::io::Error;

    async fn settlement_snapshot(
        &self,
        request: TakerSettlementSnapshotRequest,
    ) -> Result<TakerSettlementSnapshot, Self::Error> {
        if request.chain() != self.chain
            || request.market() != self.market.contract_id()
            || request.quote_anchor() != self.market.observed_at()
        {
            return Err(std::io::Error::other(
                "settlement snapshot binding mismatch",
            ));
        }
        let prevouts = request
            .outpoints()
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
    let client_endpoint = client_key.public();
    let expected_client = *client_endpoint.as_bytes();
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
    let wallet_endpoint = if reject_wrong_session_identity {
        SecretKey::from_bytes(&[0x91; 32]).public()
    } else {
        client_endpoint
    };
    let wallet_owner = *wallet_endpoint.as_bytes();
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
    let journal_binding = ExecutionJournalBinding::new(
        FixedBytes32::new([0x87; 32]),
        FixedBytes32::new(wallet.instance_id().to_bytes()),
        wallet_endpoint,
        chain,
        policy_asset,
    )
    .expect("execution journal binding");
    let journal = RedbExecutionJournal::create(&journal_path, journal_binding)
        .expect("durable execution journal");
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
    .await
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
        let foreign_journal_binding = ExecutionJournalBinding::new(
            FixedBytes32::new([0x88; 32]),
            FixedBytes32::new(foreign_wallet.instance_id().to_bytes()),
            wallet_endpoint,
            chain,
            policy_asset,
        )
        .expect("foreign execution journal binding");
        let foreign_journal = RedbExecutionJournal::create(
            foreign_journal_directory.path().join("executions.redb"),
            foreign_journal_binding,
        )
        .expect("foreign durable execution journal");
        let foreign_runtime = RfqTakerRuntime::from_source(
            foreign_wallet,
            taker_identity,
            &foreign_source,
            foreign_journal,
            config,
        )
        .await
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
        let foreign_client_journal = RedbExecutionJournal::open(&journal_path, journal_binding)
            .expect("reopen for client identity check");
        assert!(matches!(
            RfqTakerRuntime::from_source(
                foreign_client_wallet,
                foreign_client_identity,
                &source,
                foreign_client_journal,
                config,
            )
            .await,
            Err(RfqTakerError::FundingRecovery(
                FundingRecoveryError::JournalBindingClientEndpointMismatch
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
        let foreign_chain_journal = RedbExecutionJournal::open(&journal_path, journal_binding)
            .expect("reopen for chain identity check");
        assert!(matches!(
            RfqTakerRuntime::from_source(
                foreign_chain_wallet,
                foreign_chain_identity,
                &source,
                foreign_chain_journal,
                config,
            )
            .await,
            Err(RfqTakerError::FundingRecovery(
                FundingRecoveryError::JournalBindingGenesisHashMismatch
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
        let foreign_policy_journal = RedbExecutionJournal::open(&journal_path, journal_binding)
            .expect("reopen for policy identity check");
        assert!(matches!(
            RfqTakerRuntime::from_source(
                foreign_policy_wallet,
                foreign_policy_identity,
                &source,
                foreign_policy_journal,
                config,
            )
            .await,
            Err(RfqTakerError::FundingRecovery(
                FundingRecoveryError::JournalBindingPolicyAssetMismatch
            ))
        ));

        let (_foreign_wallet_directory, foreign_wallet) = empty_taker_wallet(taker_identity);
        let foreign_wallet_journal = RedbExecutionJournal::open(&journal_path, journal_binding)
            .expect("reopen for wallet instance check");
        assert!(matches!(
            RfqTakerRuntime::from_source(
                foreign_wallet,
                taker_identity,
                &source,
                foreign_wallet_journal,
                config,
            )
            .await,
            Err(RfqTakerError::FundingRecovery(
                FundingRecoveryError::JournalBindingWalletInstanceMismatch
            ))
        ));
    }
    let reopened = RedbExecutionJournal::open(&journal_path, journal_binding)
        .expect("reopen the existing durable journal");
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
    .await
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

struct PendingInventorySource {
    started: Notify,
}

#[async_trait]
impl TakerInventorySource for PendingInventorySource {
    type Error = std::io::Error;

    async fn inventory(&self) -> Result<Vec<TakerWalletUtxo>, Self::Error> {
        self.started.notify_one();
        pending().await
    }
}

#[derive(Default)]
struct CountingInventorySource {
    calls: AtomicUsize,
}

#[async_trait]
impl TakerInventorySource for CountingInventorySource {
    type Error = std::io::Error;

    async fn inventory(&self) -> Result<Vec<TakerWalletUtxo>, Self::Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(Vec::new())
    }
}

fn empty_runtime_fixture(
    owner_marker: u8,
) -> (
    tempfile::TempDir,
    Arc<PersistentRfqWallet>,
    TakerWalletIdentity,
    ChainIdentity,
    AssetId,
    RfqTakerConfig,
) {
    let endpoint = SecretKey::from_bytes(&[owner_marker; 32]).public();
    let policy_asset = asset(owner_marker.wrapping_add(1));
    let chain = ChainIdentity {
        network: LiquidNetwork::ElementsRegtest,
        genesis_hash: BlockHash::from_byte_array([owner_marker.wrapping_add(2); 32]),
    };
    let identity = TakerWalletIdentity::new(*endpoint.as_bytes(), chain.genesis_hash, policy_asset)
        .expect("empty runtime identity");
    let (directory, wallet) = empty_taker_wallet(identity);
    let config = RfqTakerConfig::new(
        TakerFundingLimits::default(),
        CompositionLimits::default(),
        1,
    )
    .expect("empty runtime configuration");
    (directory, wallet, identity, chain, policy_asset, config)
}

struct GatedInventorySource {
    started: Notify,
    release: Notify,
    inventory: Vec<TakerWalletUtxo>,
}

impl GatedInventorySource {
    fn new(inventory: Vec<TakerWalletUtxo>) -> Self {
        Self {
            started: Notify::new(),
            release: Notify::new(),
            inventory,
        }
    }
}

#[async_trait]
impl TakerInventorySource for GatedInventorySource {
    type Error = std::io::Error;

    async fn inventory(&self) -> Result<Vec<TakerWalletUtxo>, Self::Error> {
        self.started.notify_one();
        self.release.notified().await;
        Ok(self.inventory.clone())
    }
}

struct FailingInventorySource;

#[async_trait]
impl TakerInventorySource for FailingInventorySource {
    type Error = std::io::Error;

    async fn inventory(&self) -> Result<Vec<TakerWalletUtxo>, Self::Error> {
        Err(std::io::Error::other("fixture inventory failure"))
    }
}

struct PendingSettlementSource {
    started: Notify,
}

#[async_trait]
impl TakerSettlementSource for PendingSettlementSource {
    type Error = std::io::Error;

    async fn settlement_snapshot(
        &self,
        _request: TakerSettlementSnapshotRequest,
    ) -> Result<TakerSettlementSnapshot, Self::Error> {
        self.started.notify_one();
        pending().await
    }
}

struct FailingSettlementSource;

#[async_trait]
impl TakerSettlementSource for FailingSettlementSource {
    type Error = std::io::Error;

    async fn settlement_snapshot(
        &self,
        _request: TakerSettlementSnapshotRequest,
    ) -> Result<TakerSettlementSnapshot, Self::Error> {
        Err(std::io::Error::other("fixture settlement failure"))
    }
}

type AsyncTestRuntime = RfqTakerRuntime<rand::rngs::OsRng, RedbExecutionJournal>;

struct AsyncRuntimeFixture {
    _wallet_directory: tempfile::TempDir,
    _journal_directory: tempfile::TempDir,
    identity: TakerWalletIdentity,
    policy_asset: AssetId,
    runtime: AsyncTestRuntime,
    source: TestSource,
    market: TradingMarket,
    trade: ExactInRfqTrade,
    session: RfqSession,
    server: SpawnedServer,
    observed: Arc<Mutex<ObservedRequests>>,
}

impl AsyncRuntimeFixture {
    async fn shutdown(self) {
        self.session.close().await;
        self.server
            .shutdown_and_join()
            .await
            .expect("fixture server shutdown");
    }
}

async fn async_runtime_fixture(marker: u8, input_count: usize) -> AsyncRuntimeFixture {
    let provider_key = SecretKey::from_bytes(&[marker; 32]);
    let client_key = SecretKey::from_bytes(&[marker.wrapping_add(1); 32]);
    let client_endpoint = client_key.public();
    let policy_asset = asset(0x41);
    let outcome_asset = asset(0x42);
    let (market, chain) = trading_market(policy_asset, outcome_asset);
    let (provider_prevout, provider_input_secrets) = confidential_p2tr_txout(outcome_asset, 200);
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
        execute_delay_millis: AtomicUsize::new(0),
    });
    let server = Server::bind(
        provider_key,
        DiscoveryMode::Disabled,
        ServerConfig::default(),
        handler,
    )
    .await
    .expect("bind async runtime fixture server");
    let target = ProviderTarget::new(server.endpoint_addr(), chain, policy_asset);
    let server = server.spawn();
    let session = RfqSession::dial_direct(
        target,
        client_key,
        SessionConfig::new(ClientConfig::default(), 60_000, 1_000)
            .expect("async runtime fixture session config"),
    )
    .await
    .expect("dial async runtime fixture server");

    let identity = TakerWalletIdentity::new(
        *client_endpoint.as_bytes(),
        chain.genesis_hash,
        policy_asset,
    )
    .expect("async runtime fixture identity");
    let wallet_directory = tempfile::tempdir().expect("async runtime fixture wallet directory");
    let wallet = Arc::new(
        PersistentRfqWallet::create_taker_with_kdf(
            wallet_directory.path().join("wallet.redb"),
            identity,
            b"async-runtime-fixture-passphrase",
            KdfParams::new(8 * 1_024, 1, 1).expect("test KDF"),
        )
        .expect("async runtime fixture wallet"),
    );
    let mut inventory = Vec::with_capacity(input_count);
    let mut prevouts = BTreeMap::from([(outpoint(0x67, 0), provider_prevout)]);
    for index in 0..input_count {
        let index = u8::try_from(index).expect("fixture input count fits u8");
        let (outpoint, txout, utxo) = taker_funding_utxo(
            &wallet,
            policy_asset,
            200,
            marker.wrapping_add(0x10).wrapping_add(index),
            marker.wrapping_add(0x20).wrapping_add(index),
        );
        inventory.push(utxo);
        prevouts.insert(outpoint, txout);
    }
    let source = TestSource {
        chain,
        market: market.clone(),
        inventory,
        prevouts,
    };
    let journal_directory = tempfile::tempdir().expect("async runtime fixture journal directory");
    let binding = ExecutionJournalBinding::new(
        FixedBytes32::new([marker.wrapping_add(2); 32]),
        FixedBytes32::new(wallet.instance_id().to_bytes()),
        client_endpoint,
        chain,
        policy_asset,
    )
    .expect("async runtime fixture journal binding");
    let journal =
        RedbExecutionJournal::create(journal_directory.path().join("executions.redb"), binding)
            .expect("async runtime fixture journal");
    let runtime = RfqTakerRuntime::from_source(
        Arc::clone(&wallet),
        identity,
        &source,
        journal,
        RfqTakerConfig::new(
            TakerFundingLimits::default(),
            CompositionLimits::default(),
            1,
        )
        .expect("async runtime fixture configuration"),
    )
    .await
    .expect("initialize async runtime fixture");
    let trade = ExactInRfqTrade::new(
        VenueContext {
            chain,
            market: contract_id(),
            policy_asset,
        },
        AssetAmount::new(policy_asset, 100).expect("fixture exact-in amount"),
        outcome_asset,
        170,
        10,
        100,
    );

    AsyncRuntimeFixture {
        _wallet_directory: wallet_directory,
        _journal_directory: journal_directory,
        identity,
        policy_asset,
        runtime,
        source,
        market,
        trade,
        session,
        server,
        observed,
    }
}

#[tokio::test]
async fn pending_startup_holds_and_cancellation_releases_wallet_funding_authority() {
    let (_wallet_directory, wallet, identity, chain, policy_asset, config) =
        empty_runtime_fixture(0xa1);
    let journal_directory = tempfile::tempdir().expect("pending startup journal directory");
    let binding = ExecutionJournalBinding::new(
        FixedBytes32::new([0xa4; 32]),
        FixedBytes32::new(wallet.instance_id().to_bytes()),
        SecretKey::from_bytes(&[0xa1; 32]).public(),
        chain,
        policy_asset,
    )
    .expect("pending startup journal binding");
    let journal =
        RedbExecutionJournal::create(journal_directory.path().join("executions.redb"), binding)
            .expect("pending startup journal");
    let source = PendingInventorySource {
        started: Notify::new(),
    };
    let started = source.started.notified();
    tokio::pin!(started);

    {
        let startup =
            RfqTakerRuntime::from_source(Arc::clone(&wallet), identity, &source, journal, config);
        tokio::pin!(startup);
        tokio::select! {
            result = &mut startup => panic!("pending inventory unexpectedly completed: {result:?}"),
            () = &mut started => {}
        }
        assert!(matches!(
            TakerFundingPool::claim(Arc::clone(&wallet), identity),
            Err(TakerFundingError::FundingPoolAuthorityAlreadyClaimed)
        ));
    }

    let claim = TakerFundingPool::claim(wallet, identity)
        .expect("cancelling startup releases the singleton funding authority");
    drop(claim);
}

#[tokio::test]
async fn mismatched_empty_journal_fails_before_async_inventory_is_polled() {
    let (_wallet_directory, wallet, identity, chain, policy_asset, config) =
        empty_runtime_fixture(0xb1);
    let journal_directory = tempfile::tempdir().expect("mismatched journal directory");
    let binding = ExecutionJournalBinding::new(
        FixedBytes32::new([0xb4; 32]),
        FixedBytes32::new(wallet.instance_id().to_bytes()),
        SecretKey::from_bytes(&[0xb5; 32]).public(),
        chain,
        policy_asset,
    )
    .expect("mismatched journal binding");
    let journal =
        RedbExecutionJournal::create(journal_directory.path().join("executions.redb"), binding)
            .expect("mismatched empty journal");
    let source = CountingInventorySource::default();

    assert!(matches!(
        RfqTakerRuntime::from_source(wallet, identity, &source, journal, config).await,
        Err(RfqTakerError::FundingRecovery(
            FundingRecoveryError::JournalBindingClientEndpointMismatch
        ))
    ));
    assert_eq!(source.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_or_failed_inventory_refresh_preserves_the_prior_usable_inventory() {
    let fixture = async_runtime_fixture(0xc1, 1).await;
    let pending_source = PendingInventorySource {
        started: Notify::new(),
    };

    {
        let started = pending_source.started.notified();
        tokio::pin!(started);
        let refresh = fixture.runtime.refresh_inventory(&pending_source);
        tokio::pin!(refresh);
        tokio::select! {
            result = &mut refresh => panic!("pending refresh unexpectedly completed: {result:?}"),
            () = &mut started => {}
        }
    }

    let after_cancellation = fixture
        .runtime
        .reserve_exact_in(&fixture.market, fixture.trade.clone())
        .expect("cancelled refresh leaves the previous inventory usable");
    drop(after_cancellation);

    assert!(matches!(
        fixture
            .runtime
            .refresh_inventory(&FailingInventorySource)
            .await,
        Err(RfqTakerError::InventorySource(_))
    ));
    let after_source_error = fixture
        .runtime
        .reserve_exact_in(&fixture.market, fixture.trade.clone())
        .expect("failed refresh leaves the previous inventory usable");
    drop(after_source_error);
    assert!(
        fixture
            .runtime
            .pending_executions()
            .expect("empty journal remains readable")
            .is_empty()
    );

    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn durable_arm_while_inventory_refresh_is_pending_rejects_the_stale_snapshot() {
    let fixture = async_runtime_fixture(0xc2, 1).await;
    let refresh_source = GatedInventorySource::new(fixture.source.inventory.clone());

    {
        let started = refresh_source.started.notified();
        tokio::pin!(started);
        let refresh = fixture.runtime.refresh_inventory(&refresh_source);
        tokio::pin!(refresh);
        tokio::select! {
            result = &mut refresh => panic!("gated refresh unexpectedly completed: {result:?}"),
            () = &mut started => {}
        }

        let reserved = fixture
            .runtime
            .reserve_exact_in(&fixture.market, fixture.trade.clone())
            .expect("reserve funding while refresh is pending");
        let prepared = reserved
            .request_quote_at(
                &fixture.session,
                IdempotencyKeyDto::new([0xc3; 32]),
                1_500,
                1_500,
            )
            .await
            .expect("prepare trade while refresh is pending");
        let armed = fixture
            .runtime
            .accept_at(&fixture.session, &fixture.source, prepared, 1_600, 1_700)
            .await
            .expect("durably arm and execute trade while refresh is pending");
        assert!(matches!(
            armed.observation(),
            ExecutionJournalObservation::Committed(_)
        ));

        refresh_source.release.notify_one();
        assert!(matches!(
            refresh.await,
            Err(RfqTakerError::Funding(
                TakerFundingError::StaleInventoryRefresh
            ))
        ));
    }

    assert!(matches!(
        fixture
            .runtime
            .reserve_exact_in(&fixture.market, fixture.trade.clone()),
        Err(RfqTakerError::Funding(
            TakerFundingError::InsufficientFunds { .. }
        ))
    ));
    assert_eq!(
        fixture
            .runtime
            .pending_executions()
            .expect("durably armed execution is discoverable")
            .len(),
        1
    );

    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn readiness_revoked_while_inventory_refresh_is_pending_prevents_snapshot_install() {
    let fixture = async_runtime_fixture(0xc4, 2).await;
    let first = fixture
        .runtime
        .reserve_exact_in(&fixture.market, fixture.trade.clone())
        .expect("reserve first disjoint input");
    let second = fixture
        .runtime
        .reserve_exact_in(&fixture.market, fixture.trade.clone())
        .expect("reserve second disjoint input");
    let first = first
        .request_quote_at(
            &fixture.session,
            IdempotencyKeyDto::new([0xc5; 32]),
            1_500,
            1_500,
        )
        .await
        .expect("prepare first trade");
    let second = second
        .request_quote_at(
            &fixture.session,
            IdempotencyKeyDto::new([0xc6; 32]),
            1_500,
            1_500,
        )
        .await
        .expect("prepare conflicting trade");
    fixture
        .runtime
        .accept_at(&fixture.session, &fixture.source, first, 1_600, 1_700)
        .await
        .expect("first attempt establishes the journal key");

    let (foreign_directory, foreign_wallet) = empty_taker_wallet(fixture.identity);
    let (_, _, foreign_utxo) =
        taker_funding_utxo(&foreign_wallet, fixture.policy_asset, 200, 0xf1, 0xf2);
    let refresh_source = GatedInventorySource::new(vec![foreign_utxo]);
    {
        let started = refresh_source.started.notified();
        tokio::pin!(started);
        let refresh = fixture.runtime.refresh_inventory(&refresh_source);
        tokio::pin!(refresh);
        tokio::select! {
            result = &mut refresh => panic!("gated refresh unexpectedly completed: {result:?}"),
            () = &mut started => {}
        }

        assert!(matches!(
            fixture
                .runtime
                .accept_at(&fixture.session, &fixture.source, second, 1_600, 1_700)
                .await,
            Err(RfqTakerError::JournalArmAmbiguous {
                source: ExecutionJournalError::AttemptConflict,
                ..
            })
        ));
        assert!(!fixture.runtime.is_ready());

        refresh_source.release.notify_one();
        assert!(matches!(refresh.await, Err(RfqTakerError::RestartRequired)));
    }
    drop(foreign_wallet);
    drop(foreign_directory);

    assert_eq!(
        fixture
            .runtime
            .pending_executions()
            .expect("pending executions remain readable after readiness revocation")
            .len(),
        1
    );
    let observed = fixture.observed.lock().expect("observed request lock");
    assert_eq!(observed.blind_count, 2);
    assert_eq!(observed.execute_count, 1);
    drop(observed);

    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_or_failed_settlement_snapshot_leaves_trade_unarmed_and_funding_reusable() {
    let fixture = async_runtime_fixture(0xc7, 1).await;
    let pending_source = PendingSettlementSource {
        started: Notify::new(),
    };
    let first = fixture
        .runtime
        .reserve_exact_in(&fixture.market, fixture.trade.clone())
        .expect("reserve first settlement attempt")
        .request_quote_at(
            &fixture.session,
            IdempotencyKeyDto::new([0xc8; 32]),
            1_500,
            1_500,
        )
        .await
        .expect("prepare first settlement attempt");

    {
        let started = pending_source.started.notified();
        tokio::pin!(started);
        let acceptance =
            fixture
                .runtime
                .accept_at(&fixture.session, &pending_source, first, 1_600, 1_700);
        tokio::pin!(acceptance);
        tokio::select! {
            result = &mut acceptance => panic!("pending settlement unexpectedly completed: {result:?}"),
            () = &mut started => {}
        }
        let observed = fixture.observed.lock().expect("observed request lock");
        assert_eq!(observed.blind_count, 1);
        assert_eq!(observed.execute_count, 0);
    }

    assert!(
        fixture
            .runtime
            .pending_executions()
            .expect("journal remains readable after cancellation")
            .is_empty()
    );
    let second = fixture
        .runtime
        .reserve_exact_in(&fixture.market, fixture.trade.clone())
        .expect("cancelled settlement snapshot releases the funding lease")
        .request_quote_at(
            &fixture.session,
            IdempotencyKeyDto::new([0xc9; 32]),
            1_500,
            1_500,
        )
        .await
        .expect("prepare source-error settlement attempt");
    assert!(matches!(
        fixture
            .runtime
            .accept_at(
                &fixture.session,
                &FailingSettlementSource,
                second,
                1_600,
                1_700,
            )
            .await,
        Err(RfqTakerError::Authorization(
            TakerAuthorizationError::Source(_)
        ))
    ));

    assert!(
        fixture
            .runtime
            .pending_executions()
            .expect("journal remains readable after source failure")
            .is_empty()
    );
    let after_source_error = fixture
        .runtime
        .reserve_exact_in(&fixture.market, fixture.trade.clone())
        .expect("settlement source failure releases the funding lease");
    drop(after_source_error);
    let observed = fixture.observed.lock().expect("observed request lock");
    assert_eq!(observed.quote_count, 2);
    assert_eq!(observed.blind_count, 2);
    assert_eq!(observed.execute_count, 0);
    drop(observed);

    fixture.shutdown().await;
}

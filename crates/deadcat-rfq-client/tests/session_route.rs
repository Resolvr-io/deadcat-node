use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use deadcat_client::composition::{
    BlinderRef, CompositionLimits, InputId, InputSequence, InputSpec, LockTimeConstraint,
    NetworkFee, OutputId, OutputSpec, TransactionContribution,
};
use deadcat_client::validation::validate_contract_view;
use deadcat_client::venue::{AssetAmount, ExecutionRequest, LegId, ProposedLeg, VenueContext};
use deadcat_contracts::binary_market::BinaryMarketSlot;
use deadcat_rfq_client::{
    AuthoritativeTakerPrevout, ExecuteError, ExecutionJournal as _, PreparedRfqLeg, ProviderTarget,
    QuoteBounds, RedbExecutionJournal, RfqQuoteIntent, RfqSession, SessionConfig, SessionError,
    TakerAuthorizationError, TakerSettlementCoordinator, TakerSettlementPlan,
    TakerSettlementSnapshot, TakerSettlementSource, TradingMarket,
};
use deadcat_rfq_iroh::{ClientConfig, DiscoveryMode, RequestHandler, Server, ServerConfig};
use deadcat_rfq_rpc::{
    AssetAmountDto, BlinderRoleDto, FeePolicyDto, FeeSizeMetricDto, FirmQuoteDto, FixedBytes32,
    FixedBytes33, IdempotencyKeyDto, PricingDecisionDto, ProviderCapability, ProviderInfo,
    QuoteExecutionDto, QuoteInputDto, QuoteKindDto, QuoteOutputDto, QuoteOutputRoleDto,
    QuoteRecipientDto, Request, ReservationStateDto, ReservationStatusDto, Response, RpcError,
    SettlementLayoutDto, SettlementPset, SignedFirmQuote, SnapshotEvidenceDto, TxOutDto,
};
use deadcat_rfq_wallet::{
    KdfParams, PersistentRfqWallet, PersistentWalletError, TakerFundingError, TakerFundingLimits,
    TakerFundingPool, TakerWalletIdentity,
};
use deadcat_rpc::{ContractParametersView, ContractStateView, ContractView, LiveOutpoint};
use deadcat_types::{
    BinaryMarketParams, BinaryMarketState, ChainAnchor, ChainIdentity, ChainPosition, ContractId,
    ContractKind, ContractSyncState, LiquidNetwork,
};
use elements::bitcoin::PublicKey as BitcoinPublicKey;
use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::hashes::Hash as _;
use elements::secp256k1_zkp::{Keypair, PublicKey, Secp256k1, SecretKey as SecpSecretKey};
use elements::{
    AssetId, BlockHash, OutPoint, SchnorrSighashType, Script, TxOut, TxOutSecrets, TxOutWitness,
    Txid,
};
use iroh::{EndpointId, SecretKey};
use rand::SeedableRng as _;
use rand::rngs::StdRng;

const CREATED_AT_MILLIS: u64 = 1_000;
const ACCEPT_BEFORE_MILLIS: u64 = 31_000;
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
    let QuoteKindDto::ExactIn {
        input,
        output_asset,
        ..
    } = request.kind
    else {
        panic!("fixture expects an exact-in request");
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
            output: AssetAmountDto {
                asset: output_asset,
                amount: 180,
            },
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
                asset: output_asset,
                amount: 180,
                destination: request.recipient.clone(),
                blinder: BlinderRoleDto::ProviderInput { quote_input_id: 7 },
            },
            QuoteOutputDto {
                id: 13,
                role: QuoteOutputRoleDto::ProviderChange,
                asset: output_asset,
                amount: 20,
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
    quote_peer: Option<[u8; 32]>,
    quote_idempotency: Option<IdempotencyKeyDto>,
    blind: Option<(SettlementLayoutDto, SettlementPset)>,
    provider_blinded: Option<SettlementPset>,
    execute: Option<(SettlementLayoutDto, SettlementPset)>,
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
    status_calls: AtomicUsize,
    status_reserved: AtomicBool,
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
                let mut observed = self.observed.lock().expect("observed request lock");
                observed.quote_peer = Some(peer);
                observed.quote_idempotency = Some(idempotency_key);
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
                let mut provider_pset = pset.to_pset().expect("submitted settlement PSET");
                let provider_input = usize::from(
                    layout
                        .provider_inputs
                        .first()
                        .expect("fixture provider input")
                        .transaction_index,
                );
                provider_pset
                    .blind_non_last(
                        &mut StdRng::from_seed([0x74; 32]),
                        &Secp256k1::new(),
                        &HashMap::from([(provider_input, self.provider_input_secrets)]),
                    )
                    .expect("provider non-last blinding turn");
                let provider_blinded =
                    SettlementPset::from_pset(&provider_pset).expect("provider-blinded PSET");
                let mut observed = self.observed.lock().expect("observed request lock");
                observed.blind = Some((layout, pset));
                observed.provider_blinded = Some(provider_blinded.clone());
                Response::BlindedPset {
                    reservation_id,
                    pset: provider_blinded,
                }
            }
            Request::Execute { layout, pset, .. } => {
                let delay_millis = self.execute_delay_millis.load(Ordering::Relaxed);
                if delay_millis != 0 {
                    tokio::time::sleep(Duration::from_millis(delay_millis as u64)).await;
                }
                let mut observed = self.observed.lock().expect("observed request lock");
                observed.events.push("execute");
                observed.execute = Some((layout, pset));
                Response::ExecutionAccepted {
                    status: committed_status(),
                }
            }
            Request::GetReservationStatus { .. } => {
                self.observed
                    .lock()
                    .expect("observed request lock")
                    .events
                    .push("status");
                let mut returned = if self.status_reserved.load(Ordering::Relaxed) {
                    status(ReservationStateDto::Reserved)
                } else {
                    committed_status()
                };
                if !self.status_reserved.load(Ordering::Relaxed)
                    && self.status_calls.fetch_add(1, Ordering::Relaxed) != 0
                {
                    // Keep the status structurally valid and reservation-bound
                    // at transport level while violating the quote's immutable
                    // commitment. RfqSession must reject it.
                    returned.quote_commitment = FixedBytes32::new([0x7f; 32]);
                }
                Response::ReservationStatus { status: returned }
            }
        })
    }
}

struct TestSettlementSource {
    chain: ChainIdentity,
    market: TradingMarket,
    observed_at_millis: u64,
    prevouts: BTreeMap<OutPoint, TxOut>,
}

impl TakerSettlementSource for TestSettlementSource {
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
            self.observed_at_millis,
            self.market.clone(),
            prevouts,
        ))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn authenticated_session_prepares_composes_and_executes_an_exact_rfq_route() {
    let provider_key = SecretKey::from_bytes(&[0x11; 32]);
    let client_key = SecretKey::from_bytes(&[0x12; 32]);
    let expected_client = *client_key.public().as_bytes();
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
        status_calls: AtomicUsize::new(0),
        status_reserved: AtomicBool::new(false),
        execute_delay_millis: AtomicUsize::new(0),
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
    let session_config =
        SessionConfig::new(ClientConfig::default(), 60_000, 1_000).expect("valid session config");
    let session =
        RfqSession::dial_direct(target.clone(), client_key.clone(), session_config.clone())
            .await
            .expect("provider-pinned RFQ session");
    assert_eq!(session.provider_info().capabilities, ALL_CAPABILITIES);

    let wallet_directory = tempfile::tempdir().expect("taker wallet directory");
    let taker_identity =
        TakerWalletIdentity::new(expected_client, chain.genesis_hash, policy_asset)
            .expect("taker wallet identity");
    let wallet = Arc::new(
        PersistentRfqWallet::create_taker_with_kdf(
            wallet_directory.path().join("wallet.redb"),
            taker_identity,
            b"session-route-test-passphrase",
            KdfParams::new(8 * 1_024, 1, 1).expect("test KDF"),
        )
        .expect("persistent taker wallet"),
    );
    let funding_destination = wallet
        .fresh_inventory_destination()
        .expect("durable taker funding destination");
    let funding_opening = TxOutSecrets::new(
        policy_asset,
        AssetBlindingFactor::zero(),
        200,
        ValueBlindingFactor::zero(),
    );
    let explicit_funding = TxOut {
        asset: Asset::Explicit(policy_asset),
        value: Value::Explicit(200),
        nonce: Nonce::Null,
        script_pubkey: funding_destination.script_pubkey().clone(),
        witness: TxOutWitness::empty(),
    };
    let funding_txout = explicit_funding
        .to_non_last_confidential(
            &mut StdRng::from_seed([0x75; 32]),
            &Secp256k1::new(),
            funding_destination.blinding_public_key(),
            &[funding_opening],
        )
        .expect("confidential taker funding output")
        .0;
    let payer = outpoint(0x83, 0);
    let funding_utxo = wallet
        .recover_taker_utxo(
            funding_destination.wallet_locator(),
            payer,
            funding_txout.clone(),
        )
        .expect("wallet-authenticated taker funding output");
    let funding_pool = TakerFundingPool::new(
        Arc::clone(&wallet),
        taker_identity,
        vec![funding_utxo],
        BTreeSet::new(),
    )
    .expect("taker funding pool");
    let receive_destination = funding_pool
        .fresh_receive_destination()
        .expect("one-time taker receive destination");
    let receive_recipient = receive_destination
        .recipient()
        .expect("wallet receive recipient");
    let context = VenueContext {
        chain,
        market: contract_id(),
        policy_asset,
    };
    let request = ExecutionRequest::exact_in(
        context,
        AssetAmount::new(policy_asset, 100).expect("nonzero input"),
        outcome_asset,
        170,
        receive_recipient.clone(),
        BTreeMap::from([(policy_asset, 10)]),
        10,
    )
    .expect("valid user execution request");
    let funding_lease = funding_pool
        .reserve_request(&request, receive_destination, TakerFundingLimits::default())
        .expect("full worst-case funding is leased before requesting a quote");
    assert_eq!(funding_lease.selected_outpoints(), &BTreeSet::from([payer]));
    assert_eq!(funding_lease.projected_wallet_input_count(), 1);
    assert_eq!(funding_lease.maximum_change_output_count(), 1);
    let leg_request = request
        .exact_in_leg(LegId::new(9), 100, funding_lease.payer_blinder())
        .expect("exact RFQ allocation");
    let intent = RfqQuoteIntent::new(
        &leg_request,
        &market,
        QuoteBounds::ExactIn {
            minimum_output: 170,
        },
        10,
    )
    .expect("bound RFQ quote intent");
    let idempotency_key = FixedBytes32::new([0x86; 32]);
    let replay = session
        .quote_at(idempotency_key, intent.request().clone(), 1_500)
        .await
        .expect("authenticated quote replay");
    let live = replay.live_at(1_500).expect("live quote reservation");
    let cross_wired_intent = RfqQuoteIntent::new(
        &leg_request,
        &market,
        QuoteBounds::ExactIn {
            minimum_output: 171,
        },
        10,
    )
    .expect("similar but distinct quote intent");
    assert!(matches!(
        PreparedRfqLeg::prepare(leg_request.clone(), &cross_wired_intent, &live),
        Err(deadcat_rfq_client::RfqVenueError::QuoteIntentMismatch)
    ));
    let prepared = PreparedRfqLeg::prepare(leg_request.clone(), &intent, &live)
        .expect("venue-neutral prepared RFQ leg");
    let (prepared_leg, binding) = prepared.into_parts();
    let substituted = leg_request
        .authorize(
            ProposedLeg::new(
                prepared_leg.execution(),
                BTreeMap::new(),
                prepared_leg.contribution().clone(),
                prepared_leg.payment_output(),
                prepared_leg.receive_output(),
            )
            .expect("same physical contribution with different fee metadata"),
        )
        .expect("locally valid substituted leg");
    let substituted_route = request
        .clone()
        .validate_route(
            vec![substituted],
            NetworkFee::new(policy_asset, 10).expect("network fee"),
        )
        .expect("substituted route is economically valid in isolation")
        .compose(
            CompositionLimits::default(),
            TransactionContribution::new(
                vec![InputSpec::tree_less_p2tr_sighash_all(
                    InputId::new(1),
                    payer,
                    funding_txout.clone(),
                    InputSequence::Final,
                    funding_destination.internal_key(),
                )],
                vec![OutputSpec::confidential(
                    OutputId::new(1),
                    policy_asset,
                    90,
                    p2tr_script(0x82),
                    BitcoinPublicKey::new(blinding_public_key(0x83)),
                    BlinderRef::Local(InputId::new(1)),
                )],
                LockTimeConstraint::Unconstrained,
            ),
        )
        .expect("substituted route composition");
    assert!(matches!(
        binding.resolve(&substituted_route),
        Err(deadcat_rfq_client::RfqVenueError::RouteLegMismatch)
    ));
    let validated_route = request
        .validate_route(
            vec![prepared_leg],
            NetworkFee::new(policy_asset, 10).expect("network fee"),
        )
        .expect("aggregate-valid RFQ route");
    let funded_route = funding_lease
        .fund_route(validated_route, CompositionLimits::default())
        .expect("wallet-funded route composition without post-quote inputs");
    let (route, settlement_wallet) = funded_route.into_parts();
    let settlement = binding.resolve(&route).expect("exact global RFQ layout");
    let layout = settlement.layout();
    assert_eq!(layout.taker_payment_input, 0);
    assert_eq!(layout.provider_inputs.len(), 1);
    assert_eq!(layout.provider_inputs[0].quote_input_id, 7);
    assert_eq!(layout.provider_inputs[0].transaction_index, 1);
    assert_eq!(
        layout
            .quote_outputs
            .iter()
            .map(|placement| (placement.quote_output_id, placement.transaction_index))
            .collect::<Vec<_>>(),
        vec![(11, 1), (12, 2), (13, 3)]
    );
    let composed_pset = route.transaction().pset();
    assert_eq!(
        OutPoint::new(
            composed_pset.inputs()[1].previous_txid,
            composed_pset.inputs()[1].previous_output_index,
        ),
        outpoint(0x67, 0)
    );
    assert_eq!(
        composed_pset.inputs()[1].tap_internal_key,
        Some(keypair(0x71).x_only_public_key().0)
    );
    assert_eq!(
        composed_pset.inputs()[1].sighash_type,
        Some(SchnorrSighashType::All.into())
    );
    assert!(composed_pset.inputs()[1].tap_merkle_root.is_none());
    let payment = &composed_pset.outputs()[1];
    assert_eq!(payment.asset, Some(policy_asset));
    assert_eq!(payment.amount, Some(100));
    assert_eq!(payment.script_pubkey, p2tr_script(0x51));
    assert_eq!(
        payment.blinding_key,
        Some(BitcoinPublicKey::new(blinding_public_key(0x52)))
    );
    assert_eq!(payment.blinder_index, Some(0));
    let receive = &composed_pset.outputs()[2];
    assert_eq!(receive.asset, Some(outcome_asset));
    assert_eq!(receive.amount, Some(180));
    assert_eq!(receive.script_pubkey, *receive_recipient.script_pubkey());
    assert_eq!(receive.blinding_key, Some(receive_recipient.blinding_key()));
    assert_eq!(receive.blinder_index, Some(1));
    let provider_change = &composed_pset.outputs()[3];
    assert_eq!(provider_change.asset, Some(outcome_asset));
    assert_eq!(provider_change.amount, Some(20));
    assert_eq!(provider_change.script_pubkey, p2tr_script(0x51));
    assert_eq!(provider_change.blinder_index, Some(1));
    assert_eq!(
        binding
            .verified_quote()
            .quote()
            .fee_policy
            .minimum_absolute_fee,
        10
    );
    let plan = TakerSettlementPlan::new(&route, &binding)
        .expect("production plan constructor binds the route, RFQ, and exact intent market");
    let source = TestSettlementSource {
        chain,
        market: market.clone(),
        observed_at_millis: 2_000,
        prevouts: BTreeMap::from([
            (payer, funding_txout.clone()),
            (outpoint(0x67, 0), provider_prevout.clone()),
        ]),
    };

    let pset = SettlementPset::from_pset(composed_pset).expect("composed PSET");
    assert!(matches!(
        session
            .blind_at(&live, &settlement, pset.clone(), 1_499)
            .await,
        Err(SessionError::ClockMovedBackwards { .. })
    ));
    assert!(
        observed
            .lock()
            .expect("observed request lock")
            .blind
            .is_none(),
        "rollback-clock requests must fail before network dispatch"
    );
    let blinded = session
        .blind_at(&live, &settlement, pset.clone(), 1_600)
        .await
        .expect("typed provider blinding request");
    assert_ne!(blinded.pset(), &pset);
    assert_eq!(
        Some(blinded.pset()),
        observed
            .lock()
            .expect("observed request lock")
            .provider_blinded
            .as_ref(),
        "the authenticated response survives the provider serialization round trip"
    );
    let coordinator = TakerSettlementCoordinator::new(plan, &source, &settlement_wallet);
    let authorized = blinded
        .authorize_with(&coordinator)
        .expect("authoritative wallet-backed taker authorization");
    let second_signing_error = blinded
        .authorize_with(&coordinator)
        .expect_err("one settlement-scoped wallet capability signs only once");
    assert!(matches!(
        second_signing_error,
        TakerAuthorizationError::Wallet(error)
            if matches!(
                error.downcast_ref::<PersistentWalletError>(),
                Some(PersistentWalletError::TakerSettlementAlreadySigned)
            )
    ));
    drop(coordinator);
    let attempt = authorized.into_execution_attempt();
    let journal_directory = tempfile::tempdir().expect("execution journal directory");
    let journal = RedbExecutionJournal::create(journal_directory.path().join("executions.redb"))
        .expect("durable execution journal");
    let recovery = replay
        .to_recovery_record()
        .expect("self-contained quote recovery record");
    let journaled = journal
        .arm(&recovery, &attempt)
        .expect("attempt durably armed before Execute");
    let armed_funding = settlement_wallet
        .mark_durably_armed(&journaled)
        .expect("exact wallet-signed attempt promotes the lease to durable exclusions");
    assert_eq!(armed_funding.outpoints(), &BTreeSet::from([payer]));
    drop(settlement_wallet);

    let unavailable_receive = funding_pool
        .fresh_receive_destination()
        .expect("fresh destination for a later route");
    let unavailable_request = ExecutionRequest::exact_in(
        context,
        AssetAmount::new(policy_asset, 100).expect("nonzero input"),
        outcome_asset,
        170,
        unavailable_receive
            .recipient()
            .expect("later wallet receive recipient"),
        BTreeMap::from([(policy_asset, 10)]),
        10,
    )
    .expect("later user execution request");
    assert!(matches!(
        funding_pool.reserve_request(
            &unavailable_request,
            unavailable_receive,
            TakerFundingLimits::default(),
        ),
        Err(TakerFundingError::InsufficientFunds { asset }) if asset == policy_asset
    ));
    let executed = session
        .execute_at(&live, &settlement, &journaled, 1_700)
        .await
        .expect("typed provider execute request");
    assert!(matches!(
        executed.status().state,
        ReservationStateDto::Committed { .. }
    ));
    let observed_execution = journal
        .observe(journaled.key(), journaled.revision(), &executed)
        .expect("persist authenticated Execute observation");
    assert!(matches!(
        observed_execution.observation(),
        deadcat_rfq_client::ExecutionJournalObservation::Committed(_)
    ));
    assert!(matches!(
        session
            .blind_at(&live, &settlement, pset.clone(), ACCEPT_BEFORE_MILLIS)
            .await,
        Err(SessionError::Attestation(
            deadcat_rfq_rpc::AttestationError::Expired
        ))
    ));
    let recovered = session
        .status(binding.handle())
        .await
        .expect("typed durable status request");
    assert_eq!(&recovered, executed.status());

    let mismatch = session
        .status(binding.handle())
        .await
        .expect_err("status with a different quote commitment must fail");
    assert!(matches!(
        mismatch,
        SessionError::ReservationBindingMismatch("quote_commitment")
    ));

    {
        let observed = observed.lock().expect("observed request lock");
        assert_eq!(observed.quote_peer, Some(expected_client));
        assert_eq!(observed.quote_idempotency, Some(idempotency_key));
        assert_eq!(observed.blind, Some((layout.clone(), pset)));
        assert_eq!(
            observed.execute,
            Some((layout.clone(), attempt.pset().clone()))
        );
    }

    session.close().await;

    handler.status_calls.store(0, Ordering::Relaxed);
    let recovered_session =
        RfqSession::dial_direct(target.clone(), client_key.clone(), session_config.clone())
            .await
            .expect("same persistent identity reconnects");
    recovered_session
        .status(binding.handle())
        .await
        .expect("same client identity recovers the reservation");
    recovered_session.close().await;

    let other_session = RfqSession::dial_direct(
        target.clone(),
        SecretKey::generate(),
        session_config.clone(),
    )
    .await
    .expect("other authenticated client connects");
    assert!(matches!(
        other_session.status(binding.handle()).await,
        Err(SessionError::HandleClientMismatch)
    ));
    assert_eq!(handler.status_calls.load(Ordering::Relaxed), 1);
    other_session.close().await;

    // Once an execute request starts, a client timeout is deliberately
    // ambiguous: the daemon may finish processing after the response future
    // is gone. The exact attempt remains borrowed and available for retry.
    handler.execute_delay_millis.store(50, Ordering::Relaxed);
    let short_transport = ClientConfig {
        request_timeout: Duration::from_millis(10),
        ..ClientConfig::default()
    };
    let short_config = SessionConfig::new(short_transport, 60_000, 1_000)
        .expect("valid short-timeout session config");
    let ambiguous_session = RfqSession::dial_direct(target, client_key, short_config)
        .await
        .expect("short-timeout authenticated client");
    let ambiguous_replay = ambiguous_session
        .quote_at(idempotency_key, intent.request().clone(), 1_500)
        .await
        .expect("fresh authenticated replay for timeout test");
    let ambiguous_live = ambiguous_replay.live_at(1_500).expect("live timeout quote");
    let error = ambiguous_session
        .execute_at(&ambiguous_live, &settlement, &journaled, 1_700)
        .await
        .expect_err("execute response must time out");
    assert!(matches!(
        error,
        ExecuteError::SubmissionUncertain {
            attempt: digest,
            ..
        } if digest == attempt.digest()
    ));
    tokio::time::sleep(Duration::from_millis(75)).await;
    assert_eq!(
        observed
            .lock()
            .expect("observed request lock")
            .execute
            .as_ref()
            .map(|(_, pset)| pset),
        Some(attempt.pset()),
        "provider work may complete after the client timeout"
    );

    let events_before_invalid_recovery =
        observed.lock().expect("observed request lock").events.len();
    let recovery_error = ambiguous_session
        .retry_armed_execution(&journaled)
        .await
        .expect_err("invalid durable status keeps an armed outcome uncertain");
    assert!(matches!(
        recovery_error,
        ExecuteError::SubmissionUncertain {
            attempt: digest,
            ..
        } if digest == attempt.digest()
    ));
    {
        let observed = observed.lock().expect("observed request lock");
        assert_eq!(observed.events.len(), events_before_invalid_recovery + 1);
        assert_eq!(observed.events.last(), Some(&"status"));
    }

    // This quote's synthetic 1970 deadline is long past wall-clock time. An
    // armed recovery nevertheless asks durable status first and, when the
    // provider still reports Reserved, replays only the exact journaled bytes
    // without attempting to recreate a route settlement capability.
    handler.execute_delay_millis.store(0, Ordering::Relaxed);
    handler.status_reserved.store(true, Ordering::Relaxed);
    let retried = ambiguous_session
        .retry_armed_execution(&journaled)
        .await
        .expect("status-first exact retry after local expiry");
    assert!(matches!(
        retried.status().state,
        ReservationStateDto::Committed { .. }
    ));
    {
        let observed = observed.lock().expect("observed request lock");
        assert_eq!(
            &observed.events[observed.events.len() - 2..],
            &["status", "execute"],
            "recovery must status-check before exact replay"
        );
        assert_eq!(
            observed.execute,
            Some((layout.clone(), attempt.pset().clone())),
            "post-expiry recovery must replay byte-identical attempt data"
        );
    }
    ambiguous_session.close().await;
    server.shutdown_and_join().await.expect("server shutdown");
}

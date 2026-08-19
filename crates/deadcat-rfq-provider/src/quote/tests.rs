use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use deadcat_client::composition::{
    BlinderRef, InputId, InputSequence, InputSpec, LockTimeConstraint, OutputId, OutputSpec,
    TransactionContribution,
};
use deadcat_client::venue::{
    AssetAmount as ClientAssetAmount, ConfidentialRecipient as ClientRecipient,
    ExactExecution as ClientExactExecution, ExecutionError as ClientExecutionError,
    ExecutionRequest as ClientExecutionRequest, LegId, LegPreparationRequest, ProposedLeg,
    VenueContext,
};
use deadcat_types::{ChainIdentity, ContractId, LiquidNetwork};
use elements::bitcoin::PublicKey as BitcoinPublicKey;
use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::hashes::Hash as _;
use elements::secp256k1_zkp::rand::thread_rng;
use elements::secp256k1_zkp::{Keypair, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use elements::{AssetId, BlockHash, OutPoint, Script, TxOut, TxOutSecrets, TxOutWitness, Txid};
use tempfile::TempDir;
use thiserror::Error;

use super::*;
use crate::inventory::{InventoryCoordinator, InventoryFreshnessPolicy};
use crate::model::{
    FeePolicy, FeeSizeMetric, IdempotencyKey, OwnerId, ProviderId, ProviderIdentity, ReleaseReason,
    ReservationPlan, ReservationState, WalletKeyLocator,
};
use crate::store::{MAX_EXPIRATION_BATCH, ProviderError, ReservationBook};
use crate::wallet::{
    ConfidentialDestination, DestinationPurpose, DestinationSource, InventorySnapshot,
    InventorySource, WalletOwnedOutput, WalletScanAnchor,
};

const COLLATERAL_MARKER: u8 = 1;
const YES_MARKER: u8 = 2;
const NO_MARKER: u8 = 3;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
enum FixtureError {
    #[error("fixture source exhausted")]
    Exhausted,
}

#[derive(Clone)]
struct WalletFixture {
    internal_key: XOnlyPublicKey,
    blinding_public_key: PublicKey,
    script_pubkey: Script,
}

impl WalletFixture {
    fn new(spend_marker: u8, blind_marker: u8) -> Self {
        let secp = Secp256k1::new();
        let spend_secret = SecretKey::from_slice(&[spend_marker; 32]).expect("spend key");
        let spend_keypair = Keypair::from_secret_key(&secp, &spend_secret);
        let (internal_key, _) = spend_keypair.x_only_public_key();
        let blinding_secret = SecretKey::from_slice(&[blind_marker; 32]).expect("blinding key");
        let blinding_public_key = PublicKey::from_secret_key(&secp, &blinding_secret);
        let script_pubkey = Script::new_v1_p2tr(&secp, internal_key, None);
        Self {
            internal_key,
            blinding_public_key,
            script_pubkey,
        }
    }

    fn owned_output(&self, marker: u8, asset: AssetId, amount: u64) -> WalletOwnedOutput {
        let explicit = TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(amount),
            nonce: Nonce::Null,
            script_pubkey: self.script_pubkey.clone(),
            witness: TxOutWitness::default(),
        };
        let (txout, asset_bf, value_bf, _) = explicit
            .to_non_last_confidential(
                &mut thread_rng(),
                &Secp256k1::new(),
                self.blinding_public_key,
                &[TxOutSecrets::new(
                    asset,
                    AssetBlindingFactor::zero(),
                    amount,
                    ValueBlindingFactor::zero(),
                )],
            )
            .expect("confidential output");
        WalletOwnedOutput::new(
            outpoint(marker),
            txout,
            TxOutSecrets::new(asset, asset_bf, amount, value_bf),
            self.internal_key,
            WalletKeyLocator::new([marker; 32]).expect("wallet locator"),
        )
        .expect("wallet-owned output")
    }

    fn indexed_owned_outputs(
        &self,
        namespace: u8,
        count: usize,
        asset: AssetId,
        amount: u64,
    ) -> Vec<WalletOwnedOutput> {
        let explicit = TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(amount),
            nonce: Nonce::Null,
            script_pubkey: self.script_pubkey.clone(),
            witness: TxOutWitness::default(),
        };
        let (txout, asset_bf, value_bf, _) = explicit
            .to_non_last_confidential(
                &mut thread_rng(),
                &Secp256k1::new(),
                self.blinding_public_key,
                &[TxOutSecrets::new(
                    asset,
                    AssetBlindingFactor::zero(),
                    amount,
                    ValueBlindingFactor::zero(),
                )],
            )
            .expect("confidential output template");
        (0..count)
            .map(|index| {
                let index = u32::try_from(index).expect("fixture index");
                WalletOwnedOutput::new(
                    indexed_outpoint(namespace, index),
                    txout.clone(),
                    TxOutSecrets::new(asset, asset_bf, amount, value_bf),
                    self.internal_key,
                    WalletKeyLocator::new(indexed_bytes(namespace, index))
                        .expect("indexed wallet locator"),
                )
                .expect("indexed wallet-owned output")
            })
            .collect()
    }
}

struct MockSource {
    snapshots: Mutex<VecDeque<InventorySnapshot>>,
}

impl MockSource {
    fn new(snapshots: impl IntoIterator<Item = InventorySnapshot>) -> Self {
        Self {
            snapshots: Mutex::new(snapshots.into_iter().collect()),
        }
    }
}

impl InventorySource for MockSource {
    type Error = FixtureError;

    fn inventory_snapshot(&self) -> Result<InventorySnapshot, Self::Error> {
        self.snapshots
            .lock()
            .expect("snapshot fixture lock")
            .pop_front()
            .ok_or(FixtureError::Exhausted)
    }
}

#[derive(Clone)]
struct MockDestinations {
    state: Arc<Mutex<VecDeque<ConfidentialDestination>>>,
    calls: Arc<AtomicUsize>,
}

impl MockDestinations {
    fn new(destinations: impl IntoIterator<Item = ConfidentialDestination>) -> Self {
        Self {
            state: Arc::new(Mutex::new(destinations.into_iter().collect())),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl DestinationSource for MockDestinations {
    type Error = FixtureError;

    fn fresh_confidential_destination(
        &self,
        _purpose: DestinationPurpose,
    ) -> Result<ConfidentialDestination, Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.state
            .lock()
            .expect("destination fixture lock")
            .pop_front()
            .ok_or(FixtureError::Exhausted)
    }
}

#[derive(Clone)]
struct CountingPricing {
    inner: StaticRationalPricing,
    calls: Arc<AtomicUsize>,
    input_asset_venue_fee: u64,
}

impl CountingPricing {
    fn new(inner: StaticRationalPricing, calls: Arc<AtomicUsize>) -> Self {
        Self {
            inner,
            calls,
            input_asset_venue_fee: 0,
        }
    }

    fn with_input_asset_venue_fee(mut self, input_asset_venue_fee: u64) -> Self {
        self.input_asset_venue_fee = input_asset_venue_fee;
        self
    }
}

impl PricingPolicy for CountingPricing {
    type Error = StaticPricingError;

    fn price(&self, request: PricingRequest<'_>) -> Result<PricingDecision, Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let decision = self.inner.price(request)?;
        Ok(PricingDecision::new(
            decision.rate(),
            self.input_asset_venue_fee,
            decision.policy_id(),
            decision.revision(),
        ))
    }
}

fn asset(marker: u8) -> AssetId {
    AssetId::from_byte_array([marker; 32])
}

fn outpoint(marker: u8) -> OutPoint {
    OutPoint::new(Txid::from_byte_array([marker; 32]), u32::from(marker))
}

fn indexed_bytes(namespace: u8, index: u32) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[0] = namespace;
    bytes[28..].copy_from_slice(
        &index
            .checked_add(1)
            .expect("fixture index overflow")
            .to_be_bytes(),
    );
    bytes
}

fn indexed_outpoint(namespace: u8, index: u32) -> OutPoint {
    OutPoint::new(
        Txid::from_byte_array(indexed_bytes(namespace, index)),
        index,
    )
}

fn identity(marker: u8) -> ProviderIdentity {
    ProviderIdentity::new(
        ProviderId::new([marker; 32]),
        BlockHash::from_byte_array([marker.wrapping_add(1); 32]),
        asset(COLLATERAL_MARKER),
    )
}

fn quote_context(identity: ProviderIdentity) -> QuoteContext {
    QuoteContext::new(
        ChainIdentity {
            network: LiquidNetwork::ElementsRegtest,
            genesis_hash: identity.genesis_hash(),
        },
        ContractId::new(outpoint(90)),
        identity.policy_asset(),
    )
}

fn snapshot(
    identity: ProviderIdentity,
    marker: u8,
    outputs: Vec<WalletOwnedOutput>,
) -> InventorySnapshot {
    InventorySnapshot::new(
        identity,
        WalletScanAnchor::new(BlockHash::from_byte_array([marker; 32]), u32::from(marker)),
        outputs,
    )
    .expect("inventory snapshot")
}

fn destination(spend_marker: u8, blind_marker: u8, locator_marker: u8) -> ConfidentialDestination {
    let secp = Secp256k1::new();
    let spend_secret = SecretKey::from_slice(&[spend_marker; 32]).expect("spend key");
    let spend_keypair = Keypair::from_secret_key(&secp, &spend_secret);
    let (internal_key, _) = spend_keypair.x_only_public_key();
    let blinding_secret = SecretKey::from_slice(&[blind_marker; 32]).expect("blinding key");
    let blinding_public_key = PublicKey::from_secret_key(&secp, &blinding_secret);
    ConfidentialDestination::new(
        Script::new_v1_p2tr(&secp, internal_key, None),
        blinding_public_key,
        internal_key,
        WalletKeyLocator::new([locator_marker; 32]).expect("destination locator"),
    )
    .expect("confidential destination")
}

fn indexed_secret(namespace: u8, index: u32) -> SecretKey {
    let mut bytes = [0_u8; 32];
    bytes[27] = namespace;
    bytes[28..].copy_from_slice(
        &index
            .checked_add(1)
            .expect("secret index overflow")
            .to_be_bytes(),
    );
    SecretKey::from_slice(&bytes).expect("indexed secret key")
}

fn indexed_destination(index: u32) -> ConfidentialDestination {
    let secp = Secp256k1::new();
    let spend_keypair = Keypair::from_secret_key(&secp, &indexed_secret(1, index));
    let (internal_key, _) = spend_keypair.x_only_public_key();
    let blinding_public_key = PublicKey::from_secret_key(&secp, &indexed_secret(2, index));
    ConfidentialDestination::new(
        Script::new_v1_p2tr(&secp, internal_key, None),
        blinding_public_key,
        internal_key,
        WalletKeyLocator::new(indexed_bytes(3, index)).expect("indexed destination locator"),
    )
    .expect("indexed confidential destination")
}

fn recipient(marker: u8) -> QuoteRecipient {
    let destination = destination(marker, marker.wrapping_add(1), marker.wrapping_add(2));
    QuoteRecipient::new(
        destination.script_pubkey().clone(),
        destination.blinding_public_key(),
    )
    .expect("quote recipient")
}

fn fee_policy(identity: ProviderIdentity) -> FeePolicy {
    FeePolicy::new(
        identity.policy_asset(),
        2_000,
        50,
        100_000,
        FeeSizeMetric::DiscountVbytes,
    )
    .expect("fee policy")
}

fn broad_limits(maximum_provider_inputs: usize) -> PairLimits {
    PairLimits::new(
        AmountRange::new(1, u64::MAX).expect("input range"),
        AmountRange::new(1, u64::MAX).expect("output range"),
        maximum_provider_inputs,
        0,
    )
    .expect("pair limits")
}

fn market_config(identity: ProviderIdentity, limits: PairLimits) -> MarketQuoteConfig {
    directed_market_config(
        identity,
        asset(COLLATERAL_MARKER),
        asset(YES_MARKER),
        limits,
    )
}

fn directed_market_config(
    identity: ProviderIdentity,
    input_asset: AssetId,
    output_asset: AssetId,
    limits: PairLimits,
) -> MarketQuoteConfig {
    let context = quote_context(identity);
    MarketQuoteConfig::new(
        context,
        BinaryMarketAssets::new(
            asset(COLLATERAL_MARKER),
            asset(YES_MARKER),
            asset(NO_MARKER),
        )
        .expect("market assets"),
        vec![PairRule::new(input_asset, output_asset, limits)],
    )
    .expect("market config")
}

fn static_pricing(identity: ProviderIdentity) -> StaticRationalPricing {
    directed_static_pricing(
        identity,
        asset(COLLATERAL_MARKER),
        asset(YES_MARKER),
        RationalRate::new(1, 1).expect("rate"),
    )
}

fn directed_static_pricing(
    identity: ProviderIdentity,
    input_asset: AssetId,
    output_asset: AssetId,
    rate: RationalRate,
) -> StaticRationalPricing {
    let context = quote_context(identity);
    StaticRationalPricing::new(
        vec![StaticRateRule::new(
            context.market(),
            input_asset,
            output_asset,
            rate,
        )],
        PricingRevision::new(1),
    )
    .expect("static pricing")
}

fn open_engine(
    directory: &TempDir,
    identity: ProviderIdentity,
    source: MockSource,
    destinations: MockDestinations,
    pricing: CountingPricing,
) -> QuoteEngine<MockSource, MockDestinations, CountingPricing> {
    open_engine_with_policy(
        directory,
        identity,
        source,
        destinations,
        pricing,
        100,
        QuoteEnginePolicy::new(1_000, 2, 8, fee_policy(identity)).expect("engine policy"),
    )
}

fn open_engine_with_market(
    directory: &TempDir,
    identity: ProviderIdentity,
    source: MockSource,
    destinations: MockDestinations,
    pricing: CountingPricing,
    market: MarketQuoteConfig,
) -> QuoteEngine<MockSource, MockDestinations, CountingPricing> {
    let book = ReservationBook::open(directory.path().join("provider.redb"), identity)
        .expect("reservation book");
    let coordinator = InventoryCoordinator::new(
        book,
        source,
        InventoryFreshnessPolicy::new(10_000, 100).expect("freshness policy"),
    );
    QuoteEngine::new(
        coordinator,
        destinations,
        pricing,
        vec![market],
        QuoteEnginePolicy::new(1_000, 2, 8, fee_policy(identity)).expect("engine policy"),
    )
    .expect("quote engine")
}

#[allow(clippy::too_many_arguments)]
fn open_engine_with_policy(
    directory: &TempDir,
    identity: ProviderIdentity,
    source: MockSource,
    destinations: MockDestinations,
    pricing: CountingPricing,
    maximum_inventory_outputs: usize,
    policy: QuoteEnginePolicy,
) -> QuoteEngine<MockSource, MockDestinations, CountingPricing> {
    let book = ReservationBook::open(directory.path().join("provider.redb"), identity)
        .expect("reservation book");
    let coordinator = InventoryCoordinator::new(
        book,
        source,
        InventoryFreshnessPolicy::new(10_000, maximum_inventory_outputs).expect("freshness policy"),
    );
    QuoteEngine::new(
        coordinator,
        destinations,
        pricing,
        vec![market_config(identity, broad_limits(8))],
        policy,
    )
    .expect("quote engine")
}

fn exact_in_request(identity: ProviderIdentity, recipient: QuoteRecipient) -> FirmQuoteRequest {
    FirmQuoteRequest::new(
        quote_context(identity),
        QuoteKind::ExactIn {
            input: AssetAmount::new(asset(COLLATERAL_MARKER), 50).expect("input"),
            output_asset: asset(YES_MARKER),
            minimum_output: 50,
        },
        recipient,
        0,
    )
    .expect("firm quote request")
}

fn price_decision(rate: RationalRate, fee: u64) -> PricingDecision {
    PricingDecision::new(
        rate,
        fee,
        PricingPolicyId::new([42; 32]),
        PricingRevision::new(7),
    )
}

#[test]
fn persisted_quote_contribution_round_trips_through_the_store_codec() {
    let recipient = recipient(19);
    let encoded = postcard::to_allocvec(&recipient).expect("encode quote recipient");
    let decoded: QuoteRecipient = postcard::from_bytes(&encoded).expect("decode quote recipient");
    assert_eq!(decoded, recipient);

    let wallet = WalletFixture::new(17, 18);
    let owned = wallet.owned_output(19, asset(YES_MARKER), 65);
    let quoted_input = QuotedProviderInput {
        id: QuoteInputId::new(1),
        outpoint: owned.outpoint(),
        witness_utxo: owned.txout().clone(),
        inventory_binding: owned.binding(),
    };
    let encoded = postcard::to_allocvec(&quoted_input).expect("encode quoted input");
    let decoded: QuotedProviderInput = postcard::from_bytes(&encoded).expect("decode quoted input");
    assert_eq!(decoded, quoted_input);
    let quoted_output = QuotedOutput {
        id: QuoteOutputId::new(1),
        role: QuoteOutputRole::ProviderPayment,
        asset: asset(COLLATERAL_MARKER),
        amount: 50,
        destination: recipient,
        blinder: QuoteBlinderRole::TakerPaymentInput,
    };
    let encoded = postcard::to_allocvec(&quoted_output).expect("encode quoted output");
    let decoded: QuotedOutput = postcard::from_bytes(&encoded).expect("decode quoted output");
    assert_eq!(decoded, quoted_output);
    let contribution = QuoteContribution {
        inputs: vec![quoted_input],
        outputs: vec![quoted_output],
    };
    let encoded = postcard::to_allocvec(&contribution).expect("encode quote contribution");
    let decoded: QuoteContribution =
        postcard::from_bytes(&encoded).expect("decode quote contribution");
    assert_eq!(decoded, contribution);
}

#[test]
fn pricing_uses_checked_floor_and_ceiling_with_fee_in_gross_input() {
    let identity = identity(10);
    let context = quote_context(identity);
    let rate = RationalRate::new(6, 9).expect("normalized rate");
    assert_eq!((rate.numerator(), rate.denominator()), (2, 3));
    let limits = broad_limits(8);

    let exact_in = FirmQuoteRequest::new(
        context,
        QuoteKind::ExactIn {
            input: AssetAmount::new(asset(COLLATERAL_MARKER), 10).expect("input"),
            output_asset: asset(YES_MARKER),
            minimum_output: 6,
        },
        recipient(20),
        1,
    )
    .expect("exact-in request");
    let exact_in_execution = calculate_execution(&exact_in, price_decision(rate, 1), limits)
        .expect("exact-in execution");
    assert_eq!(exact_in_execution.input().amount(), 10);
    assert_eq!(exact_in_execution.output().amount(), 6);
    assert_eq!(exact_in_execution.input_asset_venue_fee(), 1);

    let exact_out = FirmQuoteRequest::new(
        context,
        QuoteKind::ExactOut {
            input_asset: asset(COLLATERAL_MARKER),
            maximum_input: 12,
            output: AssetAmount::new(asset(YES_MARKER), 7).expect("output"),
        },
        recipient(21),
        1,
    )
    .expect("exact-out request");
    let exact_out_execution = calculate_execution(&exact_out, price_decision(rate, 1), limits)
        .expect("exact-out execution");
    assert_eq!(exact_out_execution.input().amount(), 12);
    assert_eq!(exact_out_execution.output().amount(), 7);
    assert_eq!(exact_out_execution.input_asset_venue_fee(), 1);
}

#[test]
fn pricing_fails_closed_on_zero_rounding_overflow_and_user_guards() {
    let identity = identity(11);
    let context = quote_context(identity);
    let limits = broad_limits(8);
    let rounded_zero = FirmQuoteRequest::new(
        context,
        QuoteKind::ExactIn {
            input: AssetAmount::new(asset(COLLATERAL_MARKER), 1).expect("input"),
            output_asset: asset(YES_MARKER),
            minimum_output: 1,
        },
        recipient(22),
        0,
    )
    .expect("rounded-zero request");
    assert_eq!(
        calculate_execution(
            &rounded_zero,
            price_decision(RationalRate::new(1, 2).expect("rate"), 0),
            limits,
        ),
        Err(QuoteAdmissionError::RoundedAmountIsZero)
    );

    let overflow = FirmQuoteRequest::new(
        context,
        QuoteKind::ExactOut {
            input_asset: asset(COLLATERAL_MARKER),
            maximum_input: u64::MAX,
            output: AssetAmount::new(asset(YES_MARKER), u64::MAX).expect("output"),
        },
        recipient(23),
        0,
    )
    .expect("overflow request");
    assert_eq!(
        calculate_execution(
            &overflow,
            price_decision(RationalRate::new(1, u64::MAX).expect("rate"), 0),
            limits,
        ),
        Err(QuoteAdmissionError::AmountOverflow)
    );

    let fee_bound = FirmQuoteRequest::new(
        context,
        QuoteKind::ExactIn {
            input: AssetAmount::new(asset(COLLATERAL_MARKER), 10).expect("input"),
            output_asset: asset(YES_MARKER),
            minimum_output: 1,
        },
        recipient(24),
        1,
    )
    .expect("fee-bound request");
    assert_eq!(
        calculate_execution(
            &fee_bound,
            price_decision(RationalRate::new(1, 1).expect("rate"), 2),
            limits,
        ),
        Err(QuoteAdmissionError::VenueFeeLimitExceeded)
    );
}

#[test]
fn firm_quote_request_revalidates_an_invalid_recipient() {
    let identity = identity(17);
    let invalid_recipient = QuoteRecipient {
        script_pubkey: Script::new(),
        blinding_public_key: recipient(18).blinding_public_key(),
    };

    assert_eq!(
        FirmQuoteRequest::new(
            quote_context(identity),
            QuoteKind::ExactIn {
                input: AssetAmount::new(asset(COLLATERAL_MARKER), 50).expect("input"),
                output_asset: asset(YES_MARKER),
                minimum_output: 50,
            },
            invalid_recipient,
            0,
        ),
        Err(QuoteModelError::InvalidRecipientScript)
    );
}

#[test]
fn provider_destination_reuse_includes_the_opaque_wallet_locator() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(20);
    let wallet = WalletFixture::new(114, 115);
    let inventory = wallet.owned_output(116, asset(YES_MARKER), 65);
    let receive = destination(117, 118, 119);
    let secp = Secp256k1::new();
    let change_spend = SecretKey::from_slice(&[120; 32]).expect("change spend key");
    let change_keypair = Keypair::from_secret_key(&secp, &change_spend);
    let (change_internal_key, _) = change_keypair.x_only_public_key();
    let change_blind = SecretKey::from_slice(&[121; 32]).expect("change blinding key");
    let change = ConfidentialDestination::new(
        Script::new_v1_p2tr(&secp, change_internal_key, None),
        PublicKey::from_secret_key(&secp, &change_blind),
        change_internal_key,
        receive.wallet_locator(),
    )
    .expect("change destination");
    let engine = open_engine(
        &directory,
        identity,
        MockSource::new([snapshot(identity, 122, vec![inventory])]),
        MockDestinations::new([receive, change]),
        CountingPricing::new(static_pricing(identity), Arc::new(AtomicUsize::new(0))),
    );
    engine
        .inventory()
        .refresh(&UnixMillis::new(100))
        .expect("inventory refresh");

    assert!(matches!(
        engine.firm_quote(
            OwnerId::new([123; 32]),
            IdempotencyKey::new([124; 32]),
            exact_in_request(identity, recipient(125)),
            &UnixMillis::new(101),
        ),
        Err(QuoteEngineError::Admission(
            QuoteAdmissionError::ReusedProviderDestination
        ))
    ));
}

#[test]
fn firm_quote_ignores_superseded_historical_inventory_rows() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(21);
    let wallet = WalletFixture::new(126, 127);
    let superseded = wallet.owned_output(128, asset(YES_MARKER), 50);
    let current = wallet.owned_output(129, asset(YES_MARKER), 65);
    let engine = open_engine(
        &directory,
        identity,
        MockSource::new([
            snapshot(identity, 130, vec![superseded.clone(), current.clone()]),
            snapshot(identity, 131, vec![current.clone()]),
        ]),
        MockDestinations::new([destination(132, 133, 134), destination(135, 136, 137)]),
        CountingPricing::new(static_pricing(identity), Arc::new(AtomicUsize::new(0))),
    );
    engine
        .inventory()
        .refresh(&UnixMillis::new(100))
        .expect("initial inventory refresh");
    engine
        .inventory()
        .refresh(&UnixMillis::new(101))
        .expect("replacement inventory refresh");
    engine
        .inventory()
        .reservation_book()
        .poison_inventory_record_for_test(superseded.outpoint())
        .expect("poison superseded durable row");

    let outcome = engine
        .firm_quote(
            OwnerId::new([138; 32]),
            IdempotencyKey::new([139; 32]),
            exact_in_request(identity, recipient(140)),
            &UnixMillis::new(102),
        )
        .expect("quote from current bounded snapshot");
    assert!(outcome.created());
    assert_eq!(
        outcome.quote().contribution().inputs()[0].outpoint(),
        current.outpoint()
    );
}

#[test]
fn selection_prefers_exact_then_smallest_singleton_then_bounded_largest_first() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(12);
    let wallet = WalletFixture::new(30, 31);
    let yes = asset(YES_MARKER);
    let outputs = vec![
        wallet.owned_output(34, yes, 15),
        wallet.owned_output(31, yes, 4),
        wallet.owned_output(35, asset(NO_MARKER), 100),
        wallet.owned_output(33, yes, 10),
        wallet.owned_output(32, yes, 8),
    ];
    let book = ReservationBook::open(directory.path().join("provider.redb"), identity)
        .expect("reservation book");
    let coordinator = InventoryCoordinator::new(
        book,
        MockSource::new([snapshot(identity, 40, outputs)]),
        InventoryFreshnessPolicy::new(1_000, 10).expect("freshness policy"),
    );
    let eligible = coordinator
        .refresh(&UnixMillis::new(100))
        .expect("eligible inventory");
    let limits = broad_limits(2);

    let exact = select_inventory(&eligible, yes, 10, limits).expect("exact selection");
    assert_eq!(
        exact
            .iter()
            .map(|output| output.outpoint())
            .collect::<Vec<_>>(),
        vec![outpoint(33)]
    );

    let singleton = select_inventory(&eligible, yes, 9, limits).expect("singleton selection");
    assert_eq!(
        singleton
            .iter()
            .map(|output| output.outpoint())
            .collect::<Vec<_>>(),
        vec![outpoint(33)]
    );

    let accumulated = select_inventory(&eligible, yes, 17, limits).expect("accumulated selection");
    assert_eq!(
        accumulated
            .iter()
            .map(|output| output.outpoint())
            .collect::<Vec<_>>(),
        vec![outpoint(33), outpoint(34)]
    );

    assert_eq!(
        select_inventory(&eligible, yes, 26, limits),
        Err(QuoteAdmissionError::InventoryTooFragmented)
    );
}

#[test]
fn selection_finds_a_valid_bounded_subset_when_largest_first_has_dust_change() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(15);
    let wallet = WalletFixture::new(91, 92);
    let yes = asset(YES_MARKER);
    let eight = wallet.owned_output(93, yes, 8);
    let seven = wallet.owned_output(94, yes, 7);
    let six = wallet.owned_output(95, yes, 6);
    let book = ReservationBook::open(directory.path().join("provider.redb"), identity)
        .expect("reservation book");
    let coordinator = InventoryCoordinator::new(
        book,
        MockSource::new([snapshot(
            identity,
            96,
            vec![eight, seven.clone(), six.clone()],
        )]),
        InventoryFreshnessPolicy::new(1_000, 3).expect("freshness policy"),
    );
    let eligible = coordinator
        .refresh(&UnixMillis::new(100))
        .expect("eligible inventory");
    let limits = PairLimits::new(
        AmountRange::new(1, u64::MAX).expect("input range"),
        AmountRange::new(1, u64::MAX).expect("output range"),
        2,
        3,
    )
    .expect("pair limits");

    let selected = select_inventory(&eligible, yes, 13, limits)
        .expect("the exact 7 + 6 subset is a valid two-input selection");
    assert_eq!(
        selected
            .iter()
            .map(|output| output.outpoint())
            .collect::<Vec<_>>(),
        vec![seven.outpoint(), six.outpoint()]
    );
}

#[test]
fn firm_quote_is_exactly_replayed_before_inventory_pricing_or_destination_work() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(13);
    let context = quote_context(identity);
    let wallet = WalletFixture::new(40, 41);
    let inventory = wallet.owned_output(42, asset(YES_MARKER), 65);
    let source = MockSource::new([snapshot(identity, 50, vec![inventory.clone()])]);
    let destinations = MockDestinations::new([destination(51, 52, 53), destination(54, 55, 56)]);
    let destination_probe = destinations.clone();
    let pricing_calls = Arc::new(AtomicUsize::new(0));
    let pricing = CountingPricing::new(static_pricing(identity), Arc::clone(&pricing_calls));
    let engine = open_engine(&directory, identity, source, destinations.clone(), pricing);
    engine
        .inventory()
        .refresh(&UnixMillis::new(100))
        .expect("inventory refresh");
    let request = exact_in_request(identity, recipient(60));
    let owner = OwnerId::new([61; 32]);
    let key = IdempotencyKey::new([62; 32]);

    let created = engine
        .firm_quote(owner, key, request.clone(), &UnixMillis::new(101))
        .expect("firm quote");
    assert!(created.created());
    assert_eq!(created.quote().request().context(), context);
    assert_eq!(created.quote().execution().input().amount(), 50);
    assert_eq!(created.quote().execution().output().amount(), 50);
    assert_eq!(created.quote().accept_before(), UnixMillis::new(1_101));
    assert_eq!(
        created.quote().commitment(),
        created.reservation().quote_commitment()
    );
    assert_eq!(created.reservation().outpoints(), &[inventory.outpoint()]);
    let outputs = created.quote().contribution().outputs();
    assert_eq!(outputs.len(), 3);
    assert_eq!(outputs[0].role(), QuoteOutputRole::ProviderPayment);
    assert_eq!(outputs[0].amount(), 50);
    assert_eq!(outputs[0].blinder(), QuoteBlinderRole::TakerPaymentInput);
    assert_eq!(outputs[1].role(), QuoteOutputRole::TakerReceive);
    assert_eq!(outputs[1].amount(), 50);
    assert_eq!(
        outputs[1].blinder(),
        QuoteBlinderRole::ProviderInput(QuoteInputId::new(1))
    );
    assert_eq!(outputs[2].role(), QuoteOutputRole::ProviderChange);
    assert_eq!(outputs[2].amount(), 15);
    assert_eq!(pricing_calls.load(Ordering::SeqCst), 1);
    assert_eq!(destination_probe.calls(), 2);

    let replay = engine
        .firm_quote(owner, key, request.clone(), &UnixMillis::new(102))
        .expect("in-process replay");
    assert!(!replay.created());
    assert_eq!(replay.quote(), created.quote());
    assert_eq!(replay.reservation(), created.reservation());
    assert_eq!(pricing_calls.load(Ordering::SeqCst), 1);
    assert_eq!(destination_probe.calls(), 2);

    let changed = FirmQuoteRequest::new(
        context,
        QuoteKind::ExactIn {
            input: AssetAmount::new(asset(COLLATERAL_MARKER), 50).expect("input"),
            output_asset: asset(YES_MARKER),
            minimum_output: 49,
        },
        request.recipient().clone(),
        0,
    )
    .expect("changed request");
    assert!(matches!(
        engine.firm_quote(owner, key, changed, &UnixMillis::new(103)),
        Err(QuoteEngineError::Provider(
            ProviderError::IdempotencyConflict { .. }
        ))
    ));
    assert_eq!(pricing_calls.load(Ordering::SeqCst), 1);
    assert_eq!(destination_probe.calls(), 2);

    let expected_quote = created.quote().clone();
    let expected_reservation = created.reservation().clone();
    drop(engine);

    let reopened_pricing =
        CountingPricing::new(static_pricing(identity), Arc::clone(&pricing_calls));
    let reopened = open_engine(
        &directory,
        identity,
        MockSource::new([]),
        destinations,
        reopened_pricing,
    );
    let replayed_after_restart = reopened
        .firm_quote(owner, key, request, &UnixMillis::new(104))
        .expect("restart replay without inventory refresh");
    assert!(!replayed_after_restart.created());
    assert_eq!(replayed_after_restart.quote(), &expected_quote);
    assert_eq!(replayed_after_restart.reservation(), &expected_reservation);
    assert_eq!(pricing_calls.load(Ordering::SeqCst), 1);
    assert_eq!(destination_probe.calls(), 2);
}

#[test]
fn exact_out_quote_includes_input_asset_fee_and_omits_zero_change_output() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(31);
    let wallet = WalletFixture::new(131, 132);
    let inventory = wallet.owned_output(133, asset(YES_MARKER), 7);
    let provider_receive = destination(134, 135, 136);
    let destinations = MockDestinations::new([provider_receive.clone()]);
    let destination_probe = destinations.clone();
    let pricing_calls = Arc::new(AtomicUsize::new(0));
    let rate = RationalRate::new(2, 3).expect("rate");
    let pricing = CountingPricing::new(
        directed_static_pricing(identity, asset(COLLATERAL_MARKER), asset(YES_MARKER), rate),
        Arc::clone(&pricing_calls),
    )
    .with_input_asset_venue_fee(1);
    let engine = open_engine_with_market(
        &directory,
        identity,
        MockSource::new([snapshot(identity, 137, vec![inventory.clone()])]),
        destinations,
        pricing,
        directed_market_config(
            identity,
            asset(COLLATERAL_MARKER),
            asset(YES_MARKER),
            broad_limits(8),
        ),
    );
    engine
        .inventory()
        .refresh(&UnixMillis::new(100))
        .expect("inventory refresh");
    let taker_recipient = recipient(138);
    let request = FirmQuoteRequest::new(
        quote_context(identity),
        QuoteKind::ExactOut {
            input_asset: asset(COLLATERAL_MARKER),
            maximum_input: 12,
            output: AssetAmount::new(asset(YES_MARKER), 7).expect("output"),
        },
        taker_recipient.clone(),
        1,
    )
    .expect("exact-out request");

    let outcome = engine
        .firm_quote(
            OwnerId::new([139; 32]),
            IdempotencyKey::new([140; 32]),
            request,
            &UnixMillis::new(101),
        )
        .expect("firm quote");
    let quote = outcome.quote();
    assert_eq!(quote.pricing().rate(), rate);
    assert_eq!(quote.execution().input().asset(), asset(COLLATERAL_MARKER));
    assert_eq!(quote.execution().input().amount(), 12);
    assert_eq!(quote.execution().output().asset(), asset(YES_MARKER));
    assert_eq!(quote.execution().output().amount(), 7);
    assert_eq!(quote.execution().input_asset_venue_fee(), 1);

    let contribution = quote.contribution();
    assert_eq!(contribution.inputs().len(), 1);
    assert_eq!(contribution.inputs()[0].id(), QuoteInputId::new(1));
    assert_eq!(contribution.inputs()[0].outpoint(), inventory.outpoint());
    assert_eq!(contribution.outputs().len(), 2);
    let payment = &contribution.outputs()[0];
    assert_eq!(payment.role(), QuoteOutputRole::ProviderPayment);
    assert_eq!(payment.asset(), asset(COLLATERAL_MARKER));
    assert_eq!(payment.amount(), 12);
    assert_eq!(
        payment.destination(),
        &QuoteRecipient::from(&provider_receive)
    );
    assert_eq!(payment.blinder(), QuoteBlinderRole::TakerPaymentInput);
    let receive = &contribution.outputs()[1];
    assert_eq!(receive.role(), QuoteOutputRole::TakerReceive);
    assert_eq!(receive.asset(), asset(YES_MARKER));
    assert_eq!(receive.amount(), 7);
    assert_eq!(receive.destination(), &taker_recipient);
    assert_eq!(
        receive.blinder(),
        QuoteBlinderRole::ProviderInput(QuoteInputId::new(1))
    );
    assert_eq!(outcome.reservation().outpoints(), &[inventory.outpoint()]);
    assert_eq!(pricing_calls.load(Ordering::SeqCst), 1);
    assert_eq!(destination_probe.calls(), 1);
}

#[test]
fn reverse_no_to_collateral_quote_preserves_direction_and_change_economics() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(32);
    let wallet = WalletFixture::new(141, 142);
    let inventory = wallet.owned_output(143, asset(COLLATERAL_MARKER), 20);
    let provider_receive = destination(144, 145, 146);
    let provider_change = destination(147, 148, 149);
    let destinations = MockDestinations::new([provider_receive.clone(), provider_change.clone()]);
    let pricing_calls = Arc::new(AtomicUsize::new(0));
    let rate = RationalRate::new(3, 2).expect("rate");
    let pricing = CountingPricing::new(
        directed_static_pricing(identity, asset(NO_MARKER), asset(COLLATERAL_MARKER), rate),
        Arc::clone(&pricing_calls),
    );
    let engine = open_engine_with_market(
        &directory,
        identity,
        MockSource::new([snapshot(identity, 150, vec![inventory.clone()])]),
        destinations,
        pricing,
        directed_market_config(
            identity,
            asset(NO_MARKER),
            asset(COLLATERAL_MARKER),
            broad_limits(8),
        ),
    );
    engine
        .inventory()
        .refresh(&UnixMillis::new(100))
        .expect("inventory refresh");
    let taker_recipient = recipient(151);
    let request = FirmQuoteRequest::new(
        quote_context(identity),
        QuoteKind::ExactIn {
            input: AssetAmount::new(asset(NO_MARKER), 10).expect("input"),
            output_asset: asset(COLLATERAL_MARKER),
            minimum_output: 15,
        },
        taker_recipient.clone(),
        0,
    )
    .expect("reverse exact-in request");

    let outcome = engine
        .firm_quote(
            OwnerId::new([152; 32]),
            IdempotencyKey::new([153; 32]),
            request,
            &UnixMillis::new(101),
        )
        .expect("reverse firm quote");
    let quote = outcome.quote();
    assert_eq!(quote.pricing().rate(), rate);
    assert_eq!(quote.execution().input().asset(), asset(NO_MARKER));
    assert_eq!(quote.execution().input().amount(), 10);
    assert_eq!(quote.execution().output().asset(), asset(COLLATERAL_MARKER));
    assert_eq!(quote.execution().output().amount(), 15);
    assert_eq!(quote.execution().input_asset_venue_fee(), 0);

    let contribution = quote.contribution();
    assert_eq!(contribution.inputs().len(), 1);
    assert_eq!(contribution.inputs()[0].outpoint(), inventory.outpoint());
    assert_eq!(contribution.outputs().len(), 3);
    let payment = &contribution.outputs()[0];
    assert_eq!(payment.role(), QuoteOutputRole::ProviderPayment);
    assert_eq!(payment.asset(), asset(NO_MARKER));
    assert_eq!(payment.amount(), 10);
    assert_eq!(
        payment.destination(),
        &QuoteRecipient::from(&provider_receive)
    );
    assert_eq!(payment.blinder(), QuoteBlinderRole::TakerPaymentInput);
    let receive = &contribution.outputs()[1];
    assert_eq!(receive.role(), QuoteOutputRole::TakerReceive);
    assert_eq!(receive.asset(), asset(COLLATERAL_MARKER));
    assert_eq!(receive.amount(), 15);
    assert_eq!(receive.destination(), &taker_recipient);
    assert_eq!(
        receive.blinder(),
        QuoteBlinderRole::ProviderInput(QuoteInputId::new(1))
    );
    let change = &contribution.outputs()[2];
    assert_eq!(change.role(), QuoteOutputRole::ProviderChange);
    assert_eq!(change.asset(), asset(COLLATERAL_MARKER));
    assert_eq!(change.amount(), 5);
    assert_eq!(
        change.destination(),
        &QuoteRecipient::from(&provider_change)
    );
    assert_eq!(
        change.blinder(),
        QuoteBlinderRole::ProviderInput(QuoteInputId::new(1))
    );
    assert_eq!(pricing_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn multi_input_quote_uses_stable_ids_and_first_provider_input_for_output_blinding() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(33);
    let wallet = WalletFixture::new(154, 155);
    let first = wallet.owned_output(156, asset(YES_MARKER), 30);
    let second = wallet.owned_output(157, asset(YES_MARKER), 25);
    let destinations =
        MockDestinations::new([destination(158, 159, 160), destination(161, 162, 163)]);
    let pricing_calls = Arc::new(AtomicUsize::new(0));
    let engine = open_engine(
        &directory,
        identity,
        MockSource::new([snapshot(identity, 164, vec![second.clone(), first.clone()])]),
        destinations,
        CountingPricing::new(static_pricing(identity), Arc::clone(&pricing_calls)),
    );
    engine
        .inventory()
        .refresh(&UnixMillis::new(100))
        .expect("inventory refresh");

    let outcome = engine
        .firm_quote(
            OwnerId::new([165; 32]),
            IdempotencyKey::new([166; 32]),
            exact_in_request(identity, recipient(167)),
            &UnixMillis::new(101),
        )
        .expect("multi-input firm quote");
    let contribution = outcome.quote().contribution();
    assert_eq!(contribution.inputs().len(), 2);
    assert_eq!(contribution.inputs()[0].id(), QuoteInputId::new(1));
    assert_eq!(contribution.inputs()[0].outpoint(), first.outpoint());
    assert_eq!(contribution.inputs()[1].id(), QuoteInputId::new(2));
    assert_eq!(contribution.inputs()[1].outpoint(), second.outpoint());
    assert_eq!(
        outcome.reservation().outpoints(),
        &[first.outpoint(), second.outpoint()]
    );

    let outputs = contribution.outputs();
    assert_eq!(outputs.len(), 3);
    assert_eq!(outputs[0].role(), QuoteOutputRole::ProviderPayment);
    assert_eq!(outputs[0].asset(), asset(COLLATERAL_MARKER));
    assert_eq!(outputs[0].amount(), 50);
    assert_eq!(outputs[0].blinder(), QuoteBlinderRole::TakerPaymentInput);
    assert_eq!(outputs[1].role(), QuoteOutputRole::TakerReceive);
    assert_eq!(outputs[1].asset(), asset(YES_MARKER));
    assert_eq!(outputs[1].amount(), 50);
    assert_eq!(
        outputs[1].blinder(),
        QuoteBlinderRole::ProviderInput(QuoteInputId::new(1))
    );
    assert_eq!(outputs[2].role(), QuoteOutputRole::ProviderChange);
    assert_eq!(outputs[2].asset(), asset(YES_MARKER));
    assert_eq!(outputs[2].amount(), 5);
    assert_eq!(
        outputs[2].blinder(),
        QuoteBlinderRole::ProviderInput(QuoteInputId::new(1))
    );
    assert_eq!(pricing_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn expired_firm_quote_replay_is_exact_and_remains_terminal() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(18);
    let wallet = WalletFixture::new(85, 86);
    let inventory = wallet.owned_output(87, asset(YES_MARKER), 50);
    let destinations = MockDestinations::new([destination(88, 89, 90)]);
    let destination_probe = destinations.clone();
    let pricing_calls = Arc::new(AtomicUsize::new(0));
    let engine = open_engine_with_policy(
        &directory,
        identity,
        MockSource::new([snapshot(identity, 91, vec![inventory])]),
        destinations.clone(),
        CountingPricing::new(static_pricing(identity), Arc::clone(&pricing_calls)),
        10,
        QuoteEnginePolicy::new(1, 2, 8, fee_policy(identity)).expect("engine policy"),
    );
    engine
        .inventory()
        .refresh(&UnixMillis::new(100))
        .expect("inventory refresh");
    let owner = OwnerId::new([92; 32]);
    let key = IdempotencyKey::new([93; 32]);
    let request = exact_in_request(identity, recipient(94));

    let created = engine
        .firm_quote(owner, key, request.clone(), &UnixMillis::new(100))
        .expect("firm quote");
    assert!(created.created());
    assert_eq!(created.quote().accept_before(), UnixMillis::new(101));

    let expired = engine
        .firm_quote(owner, key, request.clone(), &UnixMillis::new(101))
        .expect("expired idempotent replay");
    assert!(!expired.created());
    assert_eq!(expired.quote(), created.quote());
    assert_eq!(
        expired.reservation().state(),
        ReservationState::Released {
            reason: ReleaseReason::Expired,
            at: UnixMillis::new(101),
        }
    );
    assert_eq!(pricing_calls.load(Ordering::SeqCst), 1);
    assert_eq!(destination_probe.calls(), 1);

    let expected = expired;
    drop(engine);
    let reopened = open_engine_with_policy(
        &directory,
        identity,
        MockSource::new([]),
        destinations,
        CountingPricing::new(static_pricing(identity), Arc::clone(&pricing_calls)),
        10,
        QuoteEnginePolicy::new(1, 2, 8, fee_policy(identity)).expect("engine policy"),
    );
    let replayed_after_restart = reopened
        .firm_quote(owner, key, request, &UnixMillis::new(102))
        .expect("terminal replay after restart");
    assert_eq!(replayed_after_restart, expected);
    assert_eq!(pricing_calls.load(Ordering::SeqCst), 1);
    assert_eq!(destination_probe.calls(), 1);
}

#[test]
fn authoritative_firm_quote_reserve_rejects_a_stale_allocation_revision() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(19);
    let wallet = WalletFixture::new(101, 102);
    let outputs = vec![
        wallet.owned_output(103, asset(YES_MARKER), 50),
        wallet.owned_output(104, asset(YES_MARKER), 50),
    ];
    let book = ReservationBook::open(directory.path().join("provider.redb"), identity)
        .expect("reservation book");
    let coordinator = InventoryCoordinator::new(
        book,
        MockSource::new([snapshot(identity, 105, outputs)]),
        InventoryFreshnessPolicy::new(1_000, 10).expect("freshness policy"),
    );
    let eligible = coordinator
        .refresh(&UnixMillis::new(100))
        .expect("eligible inventory");
    let selected = eligible.outputs().first().expect("selected output");
    let disjoint = eligible.outputs().get(1).expect("disjoint output");
    let request = exact_in_request(identity, recipient(106));
    let pricing = price_decision(RationalRate::new(1, 1).expect("rate"), 0);
    let execution =
        calculate_execution(&request, pricing, broad_limits(8)).expect("quote execution");
    let provider_receive = destination(107, 108, 109);
    let contribution = quote_contribution(
        &[selected],
        execution,
        request.recipient().clone(),
        &provider_receive,
        None,
        0,
    )
    .expect("quote contribution");
    let draft = FirmQuoteDraft {
        request: request.clone(),
        execution,
        pricing,
        snapshot: QuoteSnapshotEvidence {
            anchor: eligible.anchor(),
            commitment: eligible.token().snapshot(),
            allocation_revision: eligible.allocation_revision(),
            eligible_commitment: eligible.eligible_commitment(),
        },
        contribution,
        provider_receive_recovery: DestinationRecovery::from(&provider_receive),
        provider_change_recovery: None,
        selected_asset: asset(YES_MARKER),
        selected_amount: 50,
    };
    let owner = OwnerId::new([110; 32]);
    let key = IdempotencyKey::new([111; 32]);
    let request_digest =
        quote_request_digest(identity, owner, key, &request).expect("semantic request digest");

    let disjoint_plan = ReservationPlan::new(
        OwnerId::new([112; 32]),
        IdempotencyKey::new([113; 32]),
        QuoteCommitment::new([114; 32]),
        vec![disjoint.outpoint()],
        UnixMillis::new(1_000),
        fee_policy(identity),
    )
    .expect("disjoint reservation plan");
    coordinator
        .reserve(&eligible, &disjoint_plan, &UnixMillis::new(101))
        .expect("disjoint allocation");

    assert!(matches!(
        coordinator.reserve_firm_quote(
            &eligible,
            owner,
            key,
            request_digest,
            &draft,
            QuoteEnginePolicy::new(1_000, 2, 8, fee_policy(identity)).expect("engine policy"),
            &UnixMillis::new(102),
        ),
        Err(crate::inventory::InventoryCoordinatorError::Provider(
            ProviderError::EligibleInventoryChanged
        ))
    ));

    let current = coordinator
        .eligible(&UnixMillis::new(102))
        .expect("current eligible inventory");
    assert!(
        current
            .outputs()
            .iter()
            .any(|output| output.outpoint() == selected.outpoint())
    );
    assert!(
        current
            .outputs()
            .iter()
            .all(|output| output.outpoint() != disjoint.outpoint())
    );
}

#[test]
fn quote_admission_reclaims_more_than_one_expiration_batch_without_a_worker() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(16);
    let expired_count = MAX_EXPIRATION_BATCH
        .checked_add(1)
        .expect("expiration fixture size");
    let total_outputs = expired_count
        .checked_add(1)
        .expect("inventory fixture size");
    let wallet = WalletFixture::new(97, 98);
    // Reuse one valid confidential proof body across distinct outpoints. The
    // wallet boundary authenticates each outpoint independently, while this
    // keeps a >256-reservation regression test reasonably fast.
    let outputs = wallet.indexed_owned_outputs(99, total_outputs, asset(YES_MARKER), 50);
    let pricing_calls = Arc::new(AtomicUsize::new(0));
    let initial_destinations = MockDestinations::new(
        (0..expired_count)
            .map(|index| indexed_destination(u32::try_from(index).expect("destination index"))),
    );
    let initial_engine = open_engine_with_policy(
        &directory,
        identity,
        MockSource::new([snapshot(identity, 100, outputs.clone())]),
        initial_destinations,
        CountingPricing::new(static_pricing(identity), Arc::clone(&pricing_calls)),
        total_outputs,
        QuoteEnginePolicy::new(1, 1, expired_count, fee_policy(identity))
            .expect("initial engine policy"),
    );
    initial_engine
        .inventory()
        .refresh(&UnixMillis::new(100))
        .expect("initial inventory refresh");
    let request = exact_in_request(identity, recipient(101));
    for index in 0..expired_count {
        let index = u32::try_from(index).expect("quote index");
        initial_engine
            .firm_quote(
                OwnerId::new(indexed_bytes(10, index)),
                IdempotencyKey::new(indexed_bytes(11, index)),
                request.clone(),
                &UnixMillis::new(100),
            )
            .expect("initial live quote");
    }
    assert_eq!(pricing_calls.load(Ordering::SeqCst), expired_count);
    drop(initial_engine);

    // Simulate a valid restart-time policy reduction. Every old quote is now
    // expired, so none of their quota entries should count against a fresh
    // authenticated owner even though there are more than one sweep batch.
    let reopened = open_engine_with_policy(
        &directory,
        identity,
        MockSource::new([snapshot(identity, 102, outputs)]),
        MockDestinations::new([indexed_destination(
            u32::try_from(expired_count).expect("fresh destination index"),
        )]),
        CountingPricing::new(static_pricing(identity), pricing_calls),
        total_outputs,
        QuoteEnginePolicy::new(1_000, 1, 1, fee_policy(identity)).expect("reopened engine policy"),
    );
    reopened
        .inventory()
        .refresh(&UnixMillis::new(101))
        .expect("reopened inventory refresh");
    let fresh_index = u32::try_from(total_outputs).expect("fresh quote index");
    let admitted = reopened
        .firm_quote(
            OwnerId::new(indexed_bytes(12, fresh_index)),
            IdempotencyKey::new(indexed_bytes(13, fresh_index)),
            request,
            &UnixMillis::new(102),
        )
        .expect("expired quota entries must not require an external worker");
    assert!(admitted.created());
}

fn map_to_client_proposal(request: &LegPreparationRequest, quote: &FirmQuote) -> ProposedLeg {
    let inputs = quote
        .contribution()
        .inputs()
        .iter()
        .map(|input| {
            InputSpec::new(
                InputId::new(u64::from(input.id().value())),
                input.outpoint(),
                input.witness_utxo().clone(),
                InputSequence::Final,
            )
        })
        .collect::<Vec<_>>();
    let outputs = quote
        .contribution()
        .outputs()
        .iter()
        .map(|output| {
            let blinder = match output.blinder() {
                QuoteBlinderRole::TakerPaymentInput => {
                    BlinderRef::External(request.payer_blinder())
                }
                QuoteBlinderRole::ProviderInput(id) => {
                    BlinderRef::Local(InputId::new(u64::from(id.value())))
                }
            };
            OutputSpec::confidential(
                OutputId::new(u64::from(output.id().value())),
                output.asset(),
                output.amount(),
                output.destination().script_pubkey().clone(),
                BitcoinPublicKey::new(output.destination().blinding_public_key()),
                blinder,
            )
        })
        .collect::<Vec<_>>();
    let execution = quote.execution();
    let mut fees = BTreeMap::new();
    if execution.input_asset_venue_fee() != 0 {
        fees.insert(execution.input().asset(), execution.input_asset_venue_fee());
    }
    let payment = quote
        .contribution()
        .outputs()
        .iter()
        .find(|output| output.role() == QuoteOutputRole::ProviderPayment)
        .expect("payment output");
    let receive = quote
        .contribution()
        .outputs()
        .iter()
        .find(|output| output.role() == QuoteOutputRole::TakerReceive)
        .expect("receive output");
    ProposedLeg::new(
        ClientExactExecution::new(
            ClientAssetAmount::new(execution.input().asset(), execution.input().amount())
                .expect("client input"),
            ClientAssetAmount::new(execution.output().asset(), execution.output().amount())
                .expect("client output"),
        )
        .expect("client execution"),
        fees,
        TransactionContribution::new(inputs, outputs, LockTimeConstraint::Unconstrained),
        OutputId::new(u64::from(payment.id().value())),
        OutputId::new(u64::from(receive.id().value())),
    )
    .expect("client proposal")
}

#[test]
fn symbolic_firm_quote_maps_to_a_client_authorized_leg_without_provider_coupling() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(14);
    let wallet = WalletFixture::new(70, 71);
    let source = MockSource::new([snapshot(
        identity,
        72,
        vec![wallet.owned_output(73, asset(YES_MARKER), 65)],
    )]);
    let destinations = MockDestinations::new([destination(74, 75, 76), destination(77, 78, 79)]);
    let pricing_calls = Arc::new(AtomicUsize::new(0));
    let engine = open_engine(
        &directory,
        identity,
        source,
        destinations,
        CountingPricing::new(static_pricing(identity), pricing_calls),
    );
    engine
        .inventory()
        .refresh(&UnixMillis::new(100))
        .expect("inventory refresh");
    let request = exact_in_request(identity, recipient(80));
    let outcome = engine
        .firm_quote(
            OwnerId::new([81; 32]),
            IdempotencyKey::new([82; 32]),
            request.clone(),
            &UnixMillis::new(101),
        )
        .expect("firm quote");
    let quote = outcome.quote();
    let client_recipient = ClientRecipient::new(
        request.recipient().script_pubkey().clone(),
        BitcoinPublicKey::new(request.recipient().blinding_public_key()),
    )
    .expect("client recipient");
    let context = quote_context(identity);
    let client_request = ClientExecutionRequest::exact_in(
        VenueContext {
            chain: context.chain(),
            market: context.market(),
            policy_asset: context.policy_asset(),
        },
        ClientAssetAmount::new(asset(COLLATERAL_MARKER), 50).expect("client input"),
        asset(YES_MARKER),
        50,
        client_recipient,
        BTreeMap::new(),
        1_000,
    )
    .expect("client execution request");
    let payer_blinder = outpoint(83);
    let leg_request = client_request
        .exact_in_leg(LegId::new(1), 50, payer_blinder)
        .expect("leg request");
    let proposal = map_to_client_proposal(&leg_request, quote);
    let prepared = leg_request
        .authorize(proposal)
        .expect("client-authorized firm quote");
    assert_eq!(prepared.execution().input().amount(), 50);
    assert_eq!(prepared.execution().output().amount(), 50);
    assert!(prepared.venue_fees().is_empty());
    let payment = prepared
        .contribution()
        .outputs()
        .iter()
        .find(|output| output.id() == prepared.payment_output())
        .expect("prepared payment");
    assert_eq!(payment.blinder(), Some(BlinderRef::External(payer_blinder)));

    let wrong_recipient = ClientRecipient::new(
        recipient(84).script_pubkey().clone(),
        BitcoinPublicKey::new(recipient(84).blinding_public_key()),
    )
    .expect("wrong client recipient");
    let mismatched_request = ClientExecutionRequest::exact_in(
        VenueContext {
            chain: context.chain(),
            market: context.market(),
            policy_asset: context.policy_asset(),
        },
        ClientAssetAmount::new(asset(COLLATERAL_MARKER), 50).expect("client input"),
        asset(YES_MARKER),
        50,
        wrong_recipient,
        BTreeMap::new(),
        1_000,
    )
    .expect("mismatched execution request")
    .exact_in_leg(LegId::new(2), 50, payer_blinder)
    .expect("mismatched leg request");
    let mismatched_proposal = map_to_client_proposal(&mismatched_request, quote);
    assert_eq!(
        mismatched_request.authorize(mismatched_proposal),
        Err(ClientExecutionError::RecipientMismatch)
    );
}

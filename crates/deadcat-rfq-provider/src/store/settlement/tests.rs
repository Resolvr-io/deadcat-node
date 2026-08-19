//! Reusable confidential-settlement fixtures for provider-side validation.
//!
//! This module intentionally builds quotes through the real quote engine and
//! transactions through the real client composition seam. Individual validator
//! tests should start from [`SettlementFixture::new`] and mutate either the
//! submitted PSET, its symbolic-to-physical layout, or the authoritative chain
//! view. Keeping those three inputs separate makes it difficult for a negative
//! test to accidentally update both the untrusted claim and its authority.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use deadcat_client::composition::{
    BlinderRef, CompositionLimits, InputId, InputSequence, InputSpec, LockTimeConstraint,
    NetworkFee, OutputId, OutputSpec, TransactionContribution, UnblindedStructureManifest,
};
use deadcat_client::venue::{
    AssetAmount as ClientAssetAmount, ConfidentialRecipient as ClientRecipient,
    ExactExecution as ClientExactExecution, ExecutionRequest as ClientExecutionRequest, LegId,
    LegPreparationRequest, ProposedLeg, RouteAuthorization, VenueContext,
};
use deadcat_types::{ChainIdentity, ContractId, LiquidNetwork};
use elements::bitcoin::PublicKey as BitcoinPublicKey;
use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::encode::{deserialize, serialize};
use elements::hashes::Hash as _;
use elements::pset::{Input as PsetInput, Output as PsetOutput, PartiallySignedTransaction};
use elements::schnorr::TapTweak as _;
use elements::secp256k1_zkp::rand::thread_rng;
use elements::secp256k1_zkp::{Keypair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use elements::sighash::{Prevouts, SighashCache};
use elements::{
    AssetId, BlindAssetProofs as _, BlindValueProofs as _, BlockHash, LockTime, OutPoint,
    SchnorrSig, SchnorrSighashType, Script, Sequence, Transaction, TxOut, TxOutSecrets,
    TxOutWitness, Txid,
};
use tempfile::TempDir;
use thiserror::Error;

use crate::inventory::{InventoryCoordinator, InventoryFreshnessPolicy};
use crate::model::{
    FeePolicy, FeeSizeMetric, IdempotencyKey, InventoryState, OwnerId, ProviderId,
    ProviderIdentity, ReleaseReason, ReservationAccess, ReservationState, ReservationView,
    UnixMillis, WalletKeyLocator,
};
use crate::quote::{
    AmountRange, AssetAmount, BinaryMarketAssets, FirmQuote, FirmQuoteRequest, MarketQuoteConfig,
    PairLimits, PairRule, PricingRevision, QuoteBlinderRole, QuoteContext, QuoteEngine,
    QuoteEnginePolicy, QuoteInputId, QuoteKind, QuoteOutputId, QuoteOutputRole, QuoteRecipient,
    RationalRate, StaticRateRule, StaticRationalPricing,
};
use crate::store::ReservationBook;
use crate::wallet::{
    ConfidentialDestination, DestinationPurpose, DestinationSource, InventorySnapshot,
    InventorySource, ProviderOutputRecovery, WalletOwnedOutput, WalletScanAnchor,
};

use super::{
    AuthoritativePrevout, CommitOutcome, ProviderSettlementValidator, SettlementChainSource,
    SettlementInputPlacement, SettlementLayout, SettlementLayoutError, SettlementOutputPlacement,
    SettlementValidationError, project_finalized_pset,
};

pub(super) const QUOTE_TIME: UnixMillis = UnixMillis::new(101);
pub(super) const VALIDATION_TIME: UnixMillis = UnixMillis::new(102);
pub(super) const NETWORK_FEE: u64 = 1_000;
pub(super) const TAKER_FEE_INPUT_VALUE: u64 = 5_000;
pub(super) const TAKER_PAYMENT_INPUT_VALUE: u64 = 100;
pub(super) const QUOTED_PAYMENT_VALUE: u64 = 50;
pub(super) const QUOTED_RECEIVE_VALUE: u64 = 50;
pub(super) const PROVIDER_INVENTORY_VALUE: u64 = 65;

const POLICY_MARKER: u8 = 1;
const YES_MARKER: u8 = 2;
const NO_MARKER: u8 = 3;
const WALLET_FEE_INPUT_ID: InputId = InputId::new(1);
const WALLET_PAYMENT_INPUT_ID: InputId = InputId::new(2);
const WALLET_FEE_CHANGE_ID: OutputId = OutputId::new(1);
const WALLET_PAYMENT_CHANGE_ID: OutputId = OutputId::new(2);

type FixtureQuoteEngine =
    QuoteEngine<FixtureInventorySource, FixtureDestinationSource, StaticRationalPricing>;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(super) enum FixtureBackendError {
    #[error("fixture backend exhausted")]
    Exhausted,
    #[error("fixture wallet does not recognize the destination locator")]
    UnknownDestination,
    #[error("fixture wallet cannot recover the confidential output")]
    OutputRecovery,
    #[error("fixture chain view is missing an unspent prevout")]
    MissingOrSpentPrevout,
}

#[derive(Clone)]
pub(super) struct FixtureWallet {
    keypair: Keypair,
    internal_key: XOnlyPublicKey,
    blinding_secret: SecretKey,
    blinding_public_key: PublicKey,
    script_pubkey: Script,
}

impl FixtureWallet {
    pub(super) fn deterministic(spend_marker: u8, blind_marker: u8) -> Self {
        let secp = Secp256k1::new();
        let spend_secret = SecretKey::from_slice(&[spend_marker; 32]).expect("spend key");
        let keypair = Keypair::from_secret_key(&secp, &spend_secret);
        let (internal_key, _) = keypair.x_only_public_key();
        let blinding_secret = SecretKey::from_slice(&[blind_marker; 32]).expect("blinding key");
        let blinding_public_key = PublicKey::from_secret_key(&secp, &blinding_secret);
        let script_pubkey = Script::new_v1_p2tr(&secp, internal_key, None);
        Self {
            keypair,
            internal_key,
            blinding_secret,
            blinding_public_key,
            script_pubkey,
        }
    }

    pub(super) fn recipient(&self) -> QuoteRecipient {
        QuoteRecipient::new(self.script_pubkey.clone(), self.blinding_public_key)
            .expect("fixture recipient")
    }

    pub(super) fn confidential_output_spec(
        &self,
        id: OutputId,
        asset: AssetId,
        amount: u64,
        blinder: BlinderRef,
    ) -> OutputSpec {
        OutputSpec::confidential(
            id,
            asset,
            amount,
            self.script_pubkey.clone(),
            BitcoinPublicKey::new(self.blinding_public_key),
            blinder,
        )
    }

    pub(super) fn owned_utxo(&self, marker: u8, asset: AssetId, amount: u64) -> FixtureUtxo {
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
                &[explicit_secrets(asset, amount)],
            )
            .expect("synthetic confidential UTXO");
        FixtureUtxo {
            outpoint: outpoint(marker),
            txout,
            secrets: TxOutSecrets::new(asset, asset_bf, amount, value_bf),
        }
    }

    pub(super) fn configure_input(&self, input: &mut PsetInput) {
        input.sighash_type = Some(SchnorrSighashType::All.into());
        input.tap_internal_key = Some(self.internal_key);
    }

    pub(super) fn sign_input(
        &self,
        pset: &mut PartiallySignedTransaction,
        input_index: usize,
        genesis_hash: BlockHash,
    ) -> SchnorrSig {
        let digest = pset_sighash(pset, input_index, genesis_hash);
        let message = Message::from_digest(digest);
        let tweaked = self.keypair.tap_tweak(&Secp256k1::new(), None);
        let signature = SchnorrSig {
            sig: Secp256k1::new().sign_schnorr(&message, &tweaked.to_inner()),
            hash_ty: SchnorrSighashType::All,
        };
        let input = &mut pset.inputs_mut()[input_index];
        input.tap_key_sig = Some(signature);
        input.final_script_witness = Some(vec![signature.to_vec()]);
        signature
    }

    pub(super) fn unblind(&self, output: &TxOut) -> TxOutSecrets {
        output
            .unblind(&Secp256k1::new(), self.blinding_secret)
            .expect("fixture wallet can unblind output")
    }
}

#[derive(Clone)]
pub(super) struct FixtureDestination {
    pub(super) destination: ConfidentialDestination,
    blinding_secret: SecretKey,
}

impl FixtureDestination {
    pub(super) fn deterministic(spend_marker: u8, blind_marker: u8, locator_marker: u8) -> Self {
        let secp = Secp256k1::new();
        let spend_secret = SecretKey::from_slice(&[spend_marker; 32]).expect("spend key");
        let spend_keypair = Keypair::from_secret_key(&secp, &spend_secret);
        let (internal_key, _) = spend_keypair.x_only_public_key();
        let blinding_secret = SecretKey::from_slice(&[blind_marker; 32]).expect("blinding key");
        let blinding_public_key = PublicKey::from_secret_key(&secp, &blinding_secret);
        let destination = ConfidentialDestination::new(
            Script::new_v1_p2tr(&secp, internal_key, None),
            blinding_public_key,
            internal_key,
            WalletKeyLocator::new([locator_marker; 32]).expect("wallet locator"),
        )
        .expect("fixture destination");
        Self {
            destination,
            blinding_secret,
        }
    }

    pub(super) fn unblind(&self, output: &TxOut) -> TxOutSecrets {
        output
            .unblind(&Secp256k1::new(), self.blinding_secret)
            .expect("fixture destination can unblind output")
    }
}

pub(super) struct FixtureOutputRecovery {
    wallet_keys: BTreeMap<[u8; 32], (XOnlyPublicKey, SecretKey)>,
}

impl FixtureOutputRecovery {
    fn new(destinations: &[&FixtureDestination]) -> Self {
        let wallet_keys = destinations
            .iter()
            .map(|destination| {
                (
                    destination.destination.wallet_locator().to_bytes(),
                    (
                        destination.destination.internal_key(),
                        destination.blinding_secret,
                    ),
                )
            })
            .collect();
        Self { wallet_keys }
    }
}

impl ProviderOutputRecovery for FixtureOutputRecovery {
    type Error = FixtureBackendError;

    fn validate_confidential_output(
        &self,
        wallet_locator: WalletKeyLocator,
        expected_internal_key: XOnlyPublicKey,
        txout: &TxOut,
        expected_asset: AssetId,
        expected_amount: u64,
    ) -> Result<(), Self::Error> {
        let (wallet_internal_key, secret) = self
            .wallet_keys
            .get(&wallet_locator.to_bytes())
            .ok_or(FixtureBackendError::UnknownDestination)?;
        if *wallet_internal_key != expected_internal_key
            || txout.script_pubkey
                != Script::new_v1_p2tr(&Secp256k1::new(), expected_internal_key, None)
        {
            return Err(FixtureBackendError::OutputRecovery);
        }
        let opening = txout
            .unblind(&Secp256k1::new(), *secret)
            .map_err(|_| FixtureBackendError::OutputRecovery)?;
        if opening.asset != expected_asset || opening.value != expected_amount {
            return Err(FixtureBackendError::OutputRecovery);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct FixtureUtxo {
    pub(super) outpoint: OutPoint,
    pub(super) txout: TxOut,
    pub(super) secrets: TxOutSecrets,
}

impl FixtureUtxo {
    fn as_wallet_owned(&self, wallet: &FixtureWallet, locator_marker: u8) -> WalletOwnedOutput {
        WalletOwnedOutput::new(
            self.outpoint,
            self.txout.clone(),
            self.secrets,
            wallet.internal_key,
            WalletKeyLocator::new([locator_marker; 32]).expect("inventory locator"),
        )
        .expect("wallet-owned inventory")
    }
}

#[derive(Clone)]
pub(super) struct FixtureInventorySource {
    snapshots: Arc<Mutex<VecDeque<InventorySnapshot>>>,
}

impl FixtureInventorySource {
    fn new(snapshot: InventorySnapshot) -> Self {
        Self {
            snapshots: Arc::new(Mutex::new(VecDeque::from([snapshot]))),
        }
    }

    pub(super) fn push(&self, snapshot: InventorySnapshot) {
        self.snapshots
            .lock()
            .expect("inventory fixture lock")
            .push_back(snapshot);
    }
}

impl InventorySource for FixtureInventorySource {
    type Error = FixtureBackendError;

    fn inventory_snapshot(&self) -> Result<InventorySnapshot, Self::Error> {
        self.snapshots
            .lock()
            .expect("inventory fixture lock")
            .pop_front()
            .ok_or(FixtureBackendError::Exhausted)
    }
}

pub(super) struct FixtureDestinationSource {
    destinations: Mutex<VecDeque<ConfidentialDestination>>,
}

impl FixtureDestinationSource {
    fn new(destinations: impl IntoIterator<Item = ConfidentialDestination>) -> Self {
        Self {
            destinations: Mutex::new(destinations.into_iter().collect()),
        }
    }
}

impl DestinationSource for FixtureDestinationSource {
    type Error = FixtureBackendError;

    fn fresh_confidential_destination(
        &self,
        _purpose: DestinationPurpose,
    ) -> Result<ConfidentialDestination, Self::Error> {
        self.destinations
            .lock()
            .expect("destination fixture lock")
            .pop_front()
            .ok_or(FixtureBackendError::Exhausted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FixtureLayout {
    pub(super) provider_inputs: BTreeMap<QuoteInputId, usize>,
    pub(super) quote_outputs: BTreeMap<QuoteOutputId, usize>,
    pub(super) taker_fee_input: usize,
    pub(super) taker_payment_input: usize,
    pub(super) taker_fee_change: usize,
    pub(super) taker_payment_change: usize,
    pub(super) fee_output: usize,
}

impl FixtureLayout {
    pub(super) fn provider_input(&self, id: QuoteInputId) -> usize {
        self.provider_inputs[&id]
    }

    pub(super) fn quote_output(&self, id: QuoteOutputId) -> usize {
        self.quote_outputs[&id]
    }

    pub(super) fn output_for_role(&self, quote: &FirmQuote, role: QuoteOutputRole) -> usize {
        let id = quote
            .contribution()
            .outputs()
            .iter()
            .find(|output| output.role() == role)
            .expect("quoted output role")
            .id();
        self.quote_output(id)
    }

    pub(super) fn settlement_layout(&self) -> Result<SettlementLayout, SettlementLayoutError> {
        SettlementLayout::new(
            self.taker_payment_input,
            self.provider_inputs
                .iter()
                .map(|(&quote_input, &transaction_index)| {
                    SettlementInputPlacement::new(quote_input, transaction_index)
                })
                .collect(),
            self.quote_outputs
                .iter()
                .map(|(&quote_output, &transaction_index)| {
                    SettlementOutputPlacement::new(quote_output, transaction_index)
                })
                .collect(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FixtureChainEntry {
    pub(super) txout: TxOut,
    pub(super) unspent: bool,
}

/// Test representation of a coherent authoritative prevout lookup.
///
/// The production settlement module is expected to define its own trait and can
/// implement it for this type inside `cfg(test)` once that trait's exact method
/// names are fixed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FixtureChainView {
    pub(super) genesis_hash: BlockHash,
    pub(super) entries: BTreeMap<OutPoint, FixtureChainEntry>,
}

impl FixtureChainView {
    pub(super) fn entry(&self, outpoint: OutPoint) -> Option<&FixtureChainEntry> {
        self.entries.get(&outpoint)
    }

    pub(super) fn ordered_prevouts(&self, pset: &PartiallySignedTransaction) -> Option<Vec<TxOut>> {
        pset.inputs()
            .iter()
            .map(|input| {
                self.entries
                    .get(&input_outpoint(input))
                    .filter(|entry| entry.unspent)
                    .map(|entry| entry.txout.clone())
            })
            .collect()
    }
}

impl SettlementChainSource for FixtureChainView {
    type Error = FixtureBackendError;

    fn genesis_hash(&self) -> BlockHash {
        self.genesis_hash
    }

    fn unspent_prevouts(
        &self,
        outpoints: &[OutPoint],
    ) -> Result<Vec<AuthoritativePrevout>, Self::Error> {
        outpoints
            .iter()
            .map(|outpoint| {
                let entry = self
                    .entries
                    .get(outpoint)
                    .filter(|entry| entry.unspent)
                    .ok_or(FixtureBackendError::MissingOrSpentPrevout)?;
                Ok(AuthoritativePrevout::new(*outpoint, entry.txout.clone()))
            })
            .collect()
    }
}

#[derive(Clone)]
pub(super) struct FixtureSubmission {
    pub(super) pset: PartiallySignedTransaction,
    pub(super) layout: FixtureLayout,
    pub(super) chain: FixtureChainView,
}

impl FixtureSubmission {
    pub(super) fn canonical_pset_bytes(&self) -> Vec<u8> {
        serialize(&self.pset)
    }

    pub(super) fn transaction(&self) -> Transaction {
        self.pset.extract_tx().expect("fixture transaction")
    }
}

pub(super) struct SettlementFixture {
    _directory: TempDir,
    pub(super) engine: FixtureQuoteEngine,
    pub(super) identity: ProviderIdentity,
    pub(super) owner: OwnerId,
    pub(super) access: ReservationAccess,
    pub(super) quote: FirmQuote,
    pub(super) reservation: ReservationView,
    pub(super) manifest: UnblindedStructureManifest,
    pub(super) route_authorization: RouteAuthorization,
    pub(super) unblinded_pset: PartiallySignedTransaction,
    pub(super) baseline: FixtureSubmission,
    pub(super) inventory_source: FixtureInventorySource,
    pub(super) provider_inventory_wallet: FixtureWallet,
    pub(super) provider_receive: FixtureDestination,
    pub(super) provider_change: FixtureDestination,
    pub(super) output_recovery: FixtureOutputRecovery,
    pub(super) taker_wallet: FixtureWallet,
    pub(super) fee_input: FixtureUtxo,
    pub(super) payment_input: FixtureUtxo,
    pub(super) inventory_inputs: Vec<FixtureUtxo>,
}

impl SettlementFixture {
    pub(super) fn new() -> Self {
        Self::with_fee_policy(1, 1_000_000)
    }

    pub(super) fn with_multiple_provider_inputs() -> Self {
        Self::with_fee_policy_and_inventory(1, 1_000_000, &[(63, 64, 30), (66, 67, 35)])
    }

    fn with_fee_policy(minimum_absolute_fee: u64, maximum_transaction_weight: u64) -> Self {
        Self::with_fee_policy_and_inventory(
            minimum_absolute_fee,
            maximum_transaction_weight,
            &[(63, 64, PROVIDER_INVENTORY_VALUE)],
        )
    }

    fn with_fee_policy_and_inventory(
        minimum_absolute_fee: u64,
        maximum_transaction_weight: u64,
        inventory_specs: &[(u8, u8, u64)],
    ) -> Self {
        let directory = TempDir::new().expect("fixture directory");
        let identity = identity(20);
        let owner = OwnerId::new([21; 32]);
        let taker_wallet = FixtureWallet::deterministic(31, 32);
        let provider_inventory_wallet = FixtureWallet::deterministic(41, 42);
        let provider_receive = FixtureDestination::deterministic(51, 52, 53);
        let provider_change = FixtureDestination::deterministic(54, 55, 56);
        let output_recovery = FixtureOutputRecovery::new(&[&provider_receive, &provider_change]);

        let fee_input = taker_wallet.owned_utxo(61, identity.policy_asset(), TAKER_FEE_INPUT_VALUE);
        let payment_input =
            taker_wallet.owned_utxo(62, identity.policy_asset(), TAKER_PAYMENT_INPUT_VALUE);
        let inventory_inputs = inventory_specs
            .iter()
            .map(|(outpoint_marker, _, amount)| {
                provider_inventory_wallet.owned_utxo(*outpoint_marker, asset(YES_MARKER), *amount)
            })
            .collect::<Vec<_>>();
        let wallet_owned_inventory = inventory_specs
            .iter()
            .zip(&inventory_inputs)
            .map(|((_, locator_marker, _), input)| {
                input.as_wallet_owned(&provider_inventory_wallet, *locator_marker)
            })
            .collect();
        let snapshot = InventorySnapshot::new(
            identity,
            WalletScanAnchor::new(BlockHash::from_byte_array([65; 32]), 65),
            wallet_owned_inventory,
        )
        .expect("inventory snapshot");
        let book = ReservationBook::open(directory.path().join("provider.redb"), identity)
            .expect("reservation book");
        let inventory_source = FixtureInventorySource::new(snapshot);
        let inventory = InventoryCoordinator::new(
            book,
            inventory_source.clone(),
            InventoryFreshnessPolicy::new(10_000, 32).expect("inventory policy"),
        );
        let destinations = FixtureDestinationSource::new([
            provider_receive.destination.clone(),
            provider_change.destination.clone(),
        ]);
        let context = quote_context(identity);
        let pricing = StaticRationalPricing::new(
            vec![StaticRateRule::new(
                context.market(),
                identity.policy_asset(),
                asset(YES_MARKER),
                RationalRate::new(1, 1).expect("rate"),
            )],
            PricingRevision::new(1),
        )
        .expect("pricing");
        let limits = PairLimits::new(
            AmountRange::new(1, 10_000).expect("input range"),
            AmountRange::new(1, 10_000).expect("output range"),
            8,
            0,
        )
        .expect("pair limits");
        let market = MarketQuoteConfig::new(
            context,
            BinaryMarketAssets::new(identity.policy_asset(), asset(YES_MARKER), asset(NO_MARKER))
                .expect("market assets"),
            vec![PairRule::new(
                identity.policy_asset(),
                asset(YES_MARKER),
                limits,
            )],
        )
        .expect("market configuration");
        let engine = QuoteEngine::new(
            inventory,
            destinations,
            pricing,
            vec![market],
            QuoteEnginePolicy::new(
                30_000,
                4,
                32,
                fee_policy(identity, minimum_absolute_fee, maximum_transaction_weight),
            )
            .expect("quote policy"),
        )
        .expect("quote engine");
        engine
            .inventory()
            .refresh(&UnixMillis::new(100))
            .expect("inventory refresh");
        let request = FirmQuoteRequest::new(
            context,
            QuoteKind::ExactIn {
                input: AssetAmount::new(identity.policy_asset(), QUOTED_PAYMENT_VALUE)
                    .expect("quote input"),
                output_asset: asset(YES_MARKER),
                minimum_output: QUOTED_RECEIVE_VALUE,
            },
            taker_wallet.recipient(),
            0,
        )
        .expect("quote request");
        let outcome = engine
            .firm_quote(
                owner,
                IdempotencyKey::new([22; 32]),
                request.clone(),
                &QUOTE_TIME,
            )
            .expect("firm quote");
        let quote = outcome.quote().clone();
        let reservation = outcome.reservation().clone();
        let access = ReservationAccess::new(reservation.id(), owner);

        let client_recipient = ClientRecipient::new(
            request.recipient().script_pubkey().clone(),
            BitcoinPublicKey::new(request.recipient().blinding_public_key()),
        )
        .expect("client recipient");
        let client_request = ClientExecutionRequest::exact_in(
            VenueContext {
                chain: context.chain(),
                market: context.market(),
                policy_asset: identity.policy_asset(),
            },
            ClientAssetAmount::new(identity.policy_asset(), QUOTED_PAYMENT_VALUE)
                .expect("client input"),
            asset(YES_MARKER),
            QUOTED_RECEIVE_VALUE,
            client_recipient,
            BTreeMap::new(),
            NETWORK_FEE,
        )
        .expect("client request");
        let leg_request = client_request
            .exact_in_leg(LegId::new(1), QUOTED_PAYMENT_VALUE, payment_input.outpoint)
            .expect("leg allocation");
        let proposal = client_proposal(&leg_request, &quote);
        let leg = leg_request
            .authorize(proposal)
            .expect("client-authorized quote");
        let route = client_request
            .validate_route(
                vec![leg],
                NetworkFee::new(identity.policy_asset(), NETWORK_FEE).expect("network fee"),
            )
            .expect("validated route");
        let wallet_contribution = TransactionContribution::new(
            vec![
                InputSpec::new(
                    WALLET_FEE_INPUT_ID,
                    fee_input.outpoint,
                    fee_input.txout.clone(),
                    InputSequence::Final,
                ),
                InputSpec::new(
                    WALLET_PAYMENT_INPUT_ID,
                    payment_input.outpoint,
                    payment_input.txout.clone(),
                    InputSequence::Final,
                ),
            ],
            vec![
                taker_wallet.confidential_output_spec(
                    WALLET_FEE_CHANGE_ID,
                    identity.policy_asset(),
                    TAKER_FEE_INPUT_VALUE - NETWORK_FEE,
                    BlinderRef::Local(WALLET_FEE_INPUT_ID),
                ),
                taker_wallet.confidential_output_spec(
                    WALLET_PAYMENT_CHANGE_ID,
                    identity.policy_asset(),
                    TAKER_PAYMENT_INPUT_VALUE - QUOTED_PAYMENT_VALUE,
                    BlinderRef::Local(WALLET_PAYMENT_INPUT_ID),
                ),
            ],
            LockTimeConstraint::Unconstrained,
        );
        let composed_route = route
            .compose(CompositionLimits::default(), wallet_contribution)
            .expect("route composition");
        let wallet_handle = composed_route.layout().wallet();
        let venue_handle = composed_route
            .layout()
            .leg(LegId::new(1))
            .expect("venue handle");
        let (composed, route_authorization) = composed_route.into_parts();
        let layout = FixtureLayout {
            provider_inputs: quote
                .contribution()
                .inputs()
                .iter()
                .map(|input| {
                    let index = composed
                        .layout()
                        .input_index(venue_handle, InputId::new(u64::from(input.id().value())))
                        .expect("provider input placement");
                    (input.id(), index)
                })
                .collect(),
            quote_outputs: quote
                .contribution()
                .outputs()
                .iter()
                .map(|output| {
                    let index = composed
                        .layout()
                        .output_index(venue_handle, OutputId::new(u64::from(output.id().value())))
                        .expect("quote output placement");
                    (output.id(), index)
                })
                .collect(),
            taker_fee_input: composed
                .layout()
                .input_index(wallet_handle, WALLET_FEE_INPUT_ID)
                .expect("fee input placement"),
            taker_payment_input: composed
                .layout()
                .input_index(wallet_handle, WALLET_PAYMENT_INPUT_ID)
                .expect("payment input placement"),
            taker_fee_change: composed
                .layout()
                .output_index(wallet_handle, WALLET_FEE_CHANGE_ID)
                .expect("fee change placement"),
            taker_payment_change: composed
                .layout()
                .output_index(wallet_handle, WALLET_PAYMENT_CHANGE_ID)
                .expect("payment change placement"),
            fee_output: composed.layout().fee_output_index(),
        };
        let (mut pset, _, manifest) = composed.into_parts();
        taker_wallet.configure_input(&mut pset.inputs_mut()[layout.taker_fee_input]);
        taker_wallet.configure_input(&mut pset.inputs_mut()[layout.taker_payment_input]);
        for input in quote.contribution().inputs() {
            let index = layout.provider_input(input.id());
            provider_inventory_wallet.configure_input(&mut pset.inputs_mut()[index]);
        }
        manifest
            .validate(&pset)
            .expect("configured PSET preserves manifest");
        let unblinded_pset = pset.clone();

        let mut provider_secrets = HashMap::new();
        for input in quote.contribution().inputs() {
            let inventory = inventory_inputs
                .iter()
                .find(|inventory| inventory.outpoint == input.outpoint())
                .expect("quoted input belongs to fixture inventory");
            provider_secrets.insert(layout.provider_input(input.id()), inventory.secrets);
        }
        pset.blind_non_last(&mut thread_rng(), &Secp256k1::new(), &provider_secrets)
            .expect("provider non-last blinding");
        pset = deserialize(&serialize(&pset)).expect("provider PSET handoff");
        let mut taker_secrets = HashMap::new();
        taker_secrets.insert(layout.taker_fee_input, fee_input.secrets);
        taker_secrets.insert(layout.taker_payment_input, payment_input.secrets);
        pset.blind_last(&mut thread_rng(), &Secp256k1::new(), &taker_secrets)
            .expect("taker final blinding");
        taker_wallet.sign_input(&mut pset, layout.taker_fee_input, identity.genesis_hash());
        taker_wallet.sign_input(
            &mut pset,
            layout.taker_payment_input,
            identity.genesis_hash(),
        );
        pset = deserialize(&serialize(&pset)).expect("taker-signed PSET handoff");

        // Build authority from the wallet-discovered outputs, not from the
        // submitter-controlled PSET. In particular, these copies retain the
        // original input witnesses that PSET serializes into separate fields.
        let entries = [&fee_input, &payment_input]
            .into_iter()
            .chain(inventory_inputs.iter())
            .map(|input| {
                (
                    input.outpoint,
                    FixtureChainEntry {
                        txout: input.txout.clone(),
                        unspent: true,
                    },
                )
            })
            .collect();
        let baseline = FixtureSubmission {
            pset,
            layout,
            chain: FixtureChainView {
                genesis_hash: identity.genesis_hash(),
                entries,
            },
        };
        let fixture = Self {
            _directory: directory,
            engine,
            identity,
            owner,
            access,
            quote,
            reservation,
            manifest,
            route_authorization,
            unblinded_pset,
            baseline,
            inventory_source,
            provider_inventory_wallet,
            provider_receive,
            provider_change,
            output_recovery,
            taker_wallet,
            fee_input,
            payment_input,
            inventory_inputs,
        };
        fixture.assert_baseline();
        fixture
    }

    pub(super) fn book(&self) -> &ReservationBook {
        self.engine.inventory().reservation_book()
    }

    fn inventory_input(&self) -> &FixtureUtxo {
        self.inventory_inputs
            .first()
            .expect("fixture has provider inventory")
    }

    pub(super) fn close_book(self) -> (TempDir, ProviderIdentity) {
        let Self {
            _directory,
            engine,
            identity,
            ..
        } = self;
        drop(engine);
        (_directory, identity)
    }

    pub(super) fn submission(&self) -> FixtureSubmission {
        self.baseline.clone()
    }

    pub(super) fn mutated(&self, mutation: FixtureMutation) -> FixtureSubmission {
        let mut submission = self.submission();
        mutation.apply(&mut submission, self);
        if mutation.resign_taker_after_mutation() {
            self.resign_taker_inputs(&mut submission.pset, self.identity.genesis_hash());
        }
        submission
    }

    fn resign_taker_inputs(&self, pset: &mut PartiallySignedTransaction, genesis_hash: BlockHash) {
        for index in [
            self.baseline.layout.taker_fee_input,
            self.baseline.layout.taker_payment_input,
        ] {
            let input = &mut pset.inputs_mut()[index];
            input.tap_key_sig = None;
            input.final_script_witness = None;
        }
        self.taker_wallet
            .sign_input(pset, self.baseline.layout.taker_fee_input, genesis_hash);
        self.taker_wallet
            .sign_input(pset, self.baseline.layout.taker_payment_input, genesis_hash);
    }

    fn assert_baseline(&self) {
        self.manifest
            .validate(&self.baseline.pset)
            .expect("signed baseline preserves manifest");
        let prevouts = self
            .baseline
            .chain
            .ordered_prevouts(&self.baseline.pset)
            .expect("authoritative baseline prevouts");
        let transaction = self.baseline.transaction();
        transaction
            .verify_tx_amt_proofs(&Secp256k1::new(), &prevouts)
            .expect("baseline confidential proofs and balance");

        for output in self.baseline.pset.outputs() {
            if output.blinding_key.is_some() {
                assert_output_disclosure(output);
            }
        }
        let provider_payment = self
            .baseline
            .layout
            .output_for_role(&self.quote, QuoteOutputRole::ProviderPayment);
        let provider_change = self
            .baseline
            .layout
            .output_for_role(&self.quote, QuoteOutputRole::ProviderChange);
        let taker_receive = self
            .baseline
            .layout
            .output_for_role(&self.quote, QuoteOutputRole::TakerReceive);
        let payment_opening = self
            .provider_receive
            .unblind(&transaction.output[provider_payment]);
        assert_eq!(payment_opening.asset, self.identity.policy_asset());
        assert_eq!(payment_opening.value, QUOTED_PAYMENT_VALUE);
        let change_opening = self
            .provider_change
            .unblind(&transaction.output[provider_change]);
        assert_eq!(change_opening.asset, asset(YES_MARKER));
        assert_eq!(
            change_opening.value,
            self.inventory_inputs
                .iter()
                .map(|input| input.secrets.value)
                .sum::<u64>()
                - QUOTED_RECEIVE_VALUE
        );
        let taker_opening = self
            .taker_wallet
            .unblind(&transaction.output[taker_receive]);
        assert_eq!(taker_opening.asset, asset(YES_MARKER));
        assert_eq!(taker_opening.value, QUOTED_RECEIVE_VALUE);
        assert_eq!(
            transaction.fee_in(self.identity.policy_asset()),
            NETWORK_FEE
        );
    }
}

/// Independent one-field mutations used by fail-closed validator tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FixtureMutation {
    WrongPsetVersion,
    WrongTransactionVersion,
    TransactionModifiable,
    NonzeroLocktime,
    ProviderInputMappingOutOfRange,
    AliasProviderInputMapping,
    AliasProviderPaymentAndReceive,
    RemoveProviderInput,
    DuplicateProviderOutpoint,
    WrongProviderWitnessUtxo,
    UnexpectedInputDisclosure,
    NonFinalProviderSequence,
    ProviderAlreadySigned,
    MissingTakerWitness,
    WrongTakerSighash,
    IssuanceMetadata,
    PeginMetadata,
    RemoveQuotedOutput,
    SwapProviderPaymentAndReceive,
    WrongProviderPaymentScript,
    WrongProviderPaymentDisclosure,
    MissingBlindValueProof,
    MissingRangeproof,
    MissingSurjectionProof,
    MissingProviderNonce,
    WrongProviderNonce,
    WrongFeeAmount,
    WrongFeeAsset,
    ExtraFeeOutput,
    MissingAuthoritativePrevout,
    SpentProviderPrevout,
    WrongAuthoritativePrevout,
    WrongGenesis,
}

impl FixtureMutation {
    fn resign_taker_after_mutation(self) -> bool {
        matches!(
            self,
            Self::WrongTransactionVersion
                | Self::NonzeroLocktime
                | Self::DuplicateProviderOutpoint
                | Self::WrongProviderWitnessUtxo
                | Self::NonFinalProviderSequence
                | Self::RemoveQuotedOutput
                | Self::SwapProviderPaymentAndReceive
                | Self::WrongProviderPaymentScript
                | Self::MissingRangeproof
                | Self::MissingSurjectionProof
                | Self::MissingProviderNonce
                | Self::WrongProviderNonce
                | Self::WrongFeeAmount
                | Self::WrongFeeAsset
                | Self::ExtraFeeOutput
        )
    }

    fn apply(self, submission: &mut FixtureSubmission, fixture: &SettlementFixture) {
        let first_provider_id = fixture.quote.contribution().inputs()[0].id();
        let provider_input = submission.layout.provider_input(first_provider_id);
        let provider_payment = submission
            .layout
            .output_for_role(&fixture.quote, QuoteOutputRole::ProviderPayment);
        let taker_receive = submission
            .layout
            .output_for_role(&fixture.quote, QuoteOutputRole::TakerReceive);
        let provider_change = submission
            .layout
            .output_for_role(&fixture.quote, QuoteOutputRole::ProviderChange);
        match self {
            Self::WrongPsetVersion => submission.pset.global.version = 0,
            Self::WrongTransactionVersion => submission.pset.global.tx_data.version = 3,
            Self::TransactionModifiable => submission.pset.global.tx_data.tx_modifiable = Some(1),
            Self::NonzeroLocktime => {
                submission.pset.global.tx_data.fallback_locktime =
                    Some(LockTime::from_consensus(1));
            }
            Self::ProviderInputMappingOutOfRange => {
                submission
                    .layout
                    .provider_inputs
                    .insert(first_provider_id, submission.pset.inputs().len());
            }
            Self::AliasProviderInputMapping => {
                submission
                    .layout
                    .provider_inputs
                    .insert(first_provider_id, submission.layout.taker_payment_input);
            }
            Self::AliasProviderPaymentAndReceive => {
                let receive_id = fixture
                    .quote
                    .contribution()
                    .outputs()
                    .iter()
                    .find(|output| output.role() == QuoteOutputRole::TakerReceive)
                    .expect("receive output")
                    .id();
                submission
                    .layout
                    .quote_outputs
                    .insert(receive_id, provider_payment);
            }
            Self::RemoveProviderInput => {
                submission.pset.remove_input(provider_input);
            }
            Self::DuplicateProviderOutpoint => {
                let duplicate = input_outpoint(
                    &submission.pset.inputs()[submission.layout.taker_payment_input],
                );
                let input = &mut submission.pset.inputs_mut()[provider_input];
                input.previous_txid = duplicate.txid;
                input.previous_output_index = duplicate.vout;
            }
            Self::WrongProviderWitnessUtxo => {
                let wrong_prevout = submission.pset.inputs()[submission.layout.taker_payment_input]
                    .witness_utxo
                    .clone()
                    .expect("payment prevout");
                submission.pset.inputs_mut()[provider_input].witness_utxo = Some(wrong_prevout);
            }
            Self::UnexpectedInputDisclosure => {
                submission.pset.inputs_mut()[provider_input].amount =
                    Some(PROVIDER_INVENTORY_VALUE);
            }
            Self::NonFinalProviderSequence => {
                submission.pset.inputs_mut()[provider_input].sequence = Some(Sequence::ZERO);
            }
            Self::ProviderAlreadySigned => {
                fixture.provider_inventory_wallet.sign_input(
                    &mut submission.pset,
                    provider_input,
                    fixture.identity.genesis_hash(),
                );
            }
            Self::MissingTakerWitness => {
                let input =
                    &mut submission.pset.inputs_mut()[submission.layout.taker_payment_input];
                input.tap_key_sig = None;
                input.final_script_witness = None;
            }
            Self::WrongTakerSighash => {
                let input =
                    &mut submission.pset.inputs_mut()[submission.layout.taker_payment_input];
                let mut signature = input.tap_key_sig.expect("taker signature");
                signature.hash_ty = SchnorrSighashType::Single;
                input.tap_key_sig = Some(signature);
                input.final_script_witness = Some(vec![signature.to_vec()]);
            }
            Self::IssuanceMetadata => {
                submission.pset.inputs_mut()[provider_input].issuance_value_amount = Some(1);
            }
            Self::PeginMetadata => {
                submission.pset.inputs_mut()[provider_input].pegin_value = Some(1);
            }
            Self::RemoveQuotedOutput => {
                submission.pset.remove_output(provider_payment);
            }
            Self::SwapProviderPaymentAndReceive => {
                let payment = submission.pset.outputs()[provider_payment].clone();
                let receive = submission.pset.outputs()[taker_receive].clone();
                submission.pset.outputs_mut()[provider_payment] = receive;
                submission.pset.outputs_mut()[taker_receive] = payment;
            }
            Self::WrongProviderPaymentScript => {
                submission.pset.outputs_mut()[provider_payment].script_pubkey = Script::new();
            }
            Self::WrongProviderPaymentDisclosure => {
                submission.pset.outputs_mut()[provider_payment].amount =
                    Some(QUOTED_PAYMENT_VALUE + 1);
            }
            Self::MissingBlindValueProof => {
                submission.pset.outputs_mut()[provider_payment].blind_value_proof = None;
            }
            Self::MissingRangeproof => {
                submission.pset.outputs_mut()[taker_receive].value_rangeproof = None;
            }
            Self::MissingSurjectionProof => {
                submission.pset.outputs_mut()[taker_receive].asset_surjection_proof = None;
            }
            Self::MissingProviderNonce => {
                submission.pset.outputs_mut()[provider_change].ecdh_pubkey = None;
            }
            Self::WrongProviderNonce => {
                let wrong_nonce = submission.pset.outputs()[taker_receive]
                    .ecdh_pubkey
                    .expect("taker receive nonce");
                submission.pset.outputs_mut()[provider_change].ecdh_pubkey = Some(wrong_nonce);
            }
            Self::WrongFeeAmount => {
                submission.pset.outputs_mut()[submission.layout.fee_output].amount =
                    Some(NETWORK_FEE - 1);
            }
            Self::WrongFeeAsset => {
                submission.pset.outputs_mut()[submission.layout.fee_output].asset =
                    Some(asset(YES_MARKER));
            }
            Self::ExtraFeeOutput => {
                submission
                    .pset
                    .add_output(PsetOutput::from_txout(TxOut::new_fee(
                        1,
                        fixture.identity.policy_asset(),
                    )))
            }
            Self::MissingAuthoritativePrevout => {
                let outpoint = input_outpoint(&submission.pset.inputs()[provider_input]);
                submission.chain.entries.remove(&outpoint);
            }
            Self::SpentProviderPrevout => {
                let outpoint = input_outpoint(&submission.pset.inputs()[provider_input]);
                submission
                    .chain
                    .entries
                    .get_mut(&outpoint)
                    .expect("provider chain entry")
                    .unspent = false;
            }
            Self::WrongAuthoritativePrevout => {
                let outpoint = input_outpoint(&submission.pset.inputs()[provider_input]);
                submission
                    .chain
                    .entries
                    .get_mut(&outpoint)
                    .expect("provider chain entry")
                    .txout
                    .script_pubkey = Script::from(vec![0x51]);
            }
            Self::WrongGenesis => {
                let wrong_genesis = BlockHash::from_byte_array([99; 32]);
                fixture.resign_taker_inputs(&mut submission.pset, wrong_genesis);
                submission.chain.genesis_hash = wrong_genesis;
            }
        }
    }
}

fn client_proposal(request: &LegPreparationRequest, quote: &FirmQuote) -> ProposedLeg {
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
        .collect();
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
        .collect();
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

fn fee_policy(
    identity: ProviderIdentity,
    minimum_absolute_fee: u64,
    maximum_transaction_weight: u64,
) -> FeePolicy {
    FeePolicy::new(
        identity.policy_asset(),
        1,
        minimum_absolute_fee,
        maximum_transaction_weight,
        FeeSizeMetric::DiscountVbytes,
    )
    .expect("fee policy")
}

fn identity(marker: u8) -> ProviderIdentity {
    ProviderIdentity::new(
        ProviderId::new([marker; 32]),
        BlockHash::from_byte_array([marker.wrapping_add(1); 32]),
        asset(POLICY_MARKER),
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

fn asset(marker: u8) -> AssetId {
    AssetId::from_byte_array([marker; 32])
}

fn outpoint(marker: u8) -> OutPoint {
    OutPoint::new(Txid::from_byte_array([marker; 32]), u32::from(marker))
}

fn explicit_secrets(asset: AssetId, value: u64) -> TxOutSecrets {
    TxOutSecrets::new(
        asset,
        AssetBlindingFactor::zero(),
        value,
        ValueBlindingFactor::zero(),
    )
}

fn input_outpoint(input: &PsetInput) -> OutPoint {
    OutPoint::new(input.previous_txid, input.previous_output_index)
}

fn pset_sighash(
    pset: &PartiallySignedTransaction,
    input_index: usize,
    genesis_hash: BlockHash,
) -> [u8; 32] {
    let transaction = pset.extract_tx().expect("transaction for sighash");
    let prevouts = pset
        .inputs()
        .iter()
        .map(|input| input.witness_utxo.clone().expect("PSET prevout"))
        .collect::<Vec<_>>();
    SighashCache::new(&transaction)
        .taproot_key_spend_signature_hash(
            input_index,
            &Prevouts::All(&prevouts),
            SchnorrSighashType::All,
            genesis_hash,
        )
        .expect("Taproot sighash")
        .to_byte_array()
}

fn assert_output_disclosure(output: &PsetOutput) {
    let secp = Secp256k1::new();
    let asset = output.asset.expect("disclosed asset");
    let amount = output.amount.expect("disclosed amount");
    let asset_commitment = output.asset_comm.expect("asset commitment");
    let value_commitment = output.amount_comm.expect("value commitment");
    assert!(
        output
            .blind_asset_proof
            .as_deref()
            .expect("asset disclosure proof")
            .blind_asset_proof_verify(&secp, asset, asset_commitment)
    );
    assert!(
        output
            .blind_value_proof
            .as_deref()
            .expect("value disclosure proof")
            .blind_value_proof_verify(&secp, amount, asset_commitment, value_commitment,)
    );
}

#[test]
fn baseline_final_pset_validates_and_commits_the_exact_canonical_payload() {
    let fixture = SettlementFixture::new();
    let submission = fixture.submission();
    assert_eq!(fixture.reservation.owner(), fixture.owner);
    assert_eq!(fixture.route_authorization.legs().len(), 1);
    for utxo in [&fixture.fee_input, &fixture.payment_input]
        .into_iter()
        .chain(&fixture.inventory_inputs)
    {
        let authority = submission
            .chain
            .entry(utxo.outpoint)
            .expect("fixture authority contains every composed input");
        assert!(authority.unspent);
        assert_eq!(authority.txout, utxo.txout);
    }
    let layout = submission
        .layout
        .settlement_layout()
        .expect("settlement layout");
    let canonical = submission.canonical_pset_bytes();
    let validator = ProviderSettlementValidator::new(
        fixture.book(),
        &submission.chain,
        &fixture.output_recovery,
    );
    let intent = validator
        .validate(fixture.access, &layout, &canonical)
        .expect("valid final PSET");
    assert_eq!(intent.reservation_id(), fixture.reservation.id());
    assert_eq!(intent.canonical_pset(), canonical);
    assert_eq!(intent.fee().policy_asset(), fixture.identity.policy_asset());
    assert_eq!(intent.fee().amount(), NETWORK_FEE);
    assert!(intent.fee().weight() > 0);
    assert!(intent.fee().regular_vsize() >= intent.fee().discount_vsize());
    let mut projected = submission.transaction();
    for index in submission.layout.provider_inputs.values().copied() {
        projected.input[index].witness.script_witness = vec![vec![0_u8; 65]];
    }
    assert_eq!(
        intent.fee().weight(),
        u64::try_from(projected.weight()).expect("fixture weight")
    );
    assert_eq!(
        intent.fee().regular_vsize(),
        u64::try_from(projected.vsize()).expect("fixture vsize")
    );
    assert_eq!(
        intent.fee().discount_vsize(),
        u64::try_from(projected.discount_vsize()).expect("fixture discount vsize")
    );

    let committed = intent
        .commit(fixture.book(), &VALIDATION_TIME)
        .expect("durable signing commit");
    let CommitOutcome::NewlyCommitted(job) = committed else {
        panic!("first commit must create a durable signing job");
    };
    assert_eq!(job.pre_sign_payload(), canonical);
    assert_eq!(job.fee().amount(), NETWORK_FEE);
    assert_eq!(
        job.targets().len(),
        fixture.quote.contribution().inputs().len()
    );
}

#[test]
fn cancellation_after_validation_wins_before_the_point_of_no_return() {
    let fixture = SettlementFixture::new();
    let submission = fixture.submission();
    let layout = submission
        .layout
        .settlement_layout()
        .expect("settlement layout");
    let intent = ProviderSettlementValidator::new(
        fixture.book(),
        &submission.chain,
        &fixture.output_recovery,
    )
    .validate(fixture.access, &layout, &submission.canonical_pset_bytes())
    .expect("valid final PSET");
    assert!(
        fixture
            .book()
            .cancel(fixture.access, &VALIDATION_TIME)
            .expect("uncommitted reservation remains cancellable")
    );
    assert!(matches!(
        intent.commit(fixture.book(), &UnixMillis::new(103)),
        Err(crate::store::ProviderError::ReservationAlreadyReleased(_))
    ));
    assert!(matches!(
        fixture
            .book()
            .reservation(fixture.reservation.id())
            .expect("reservation lookup")
            .expect("reservation")
            .state(),
        ReservationState::Released {
            reason: ReleaseReason::ClientCancelled,
            ..
        }
    ));
    assert!(matches!(
        fixture
            .book()
            .inventory(fixture.inventory_input().outpoint)
            .expect("inventory lookup")
            .expect("inventory")
            .state(),
        InventoryState::Available
    ));
}

#[test]
fn validated_intent_is_bound_to_its_provider_book() {
    let fixture = SettlementFixture::new();
    let submission = fixture.submission();
    let layout = submission
        .layout
        .settlement_layout()
        .expect("settlement layout");
    let intent = ProviderSettlementValidator::new(
        fixture.book(),
        &submission.chain,
        &fixture.output_recovery,
    )
    .validate(fixture.access, &layout, &submission.canonical_pset_bytes())
    .expect("valid final PSET");
    let other_directory = TempDir::new().expect("other provider directory");
    let other_book =
        ReservationBook::open(other_directory.path().join("provider.redb"), identity(70))
            .expect("other provider book");

    assert!(matches!(
        intent.commit(&other_book, &VALIDATION_TIME),
        Err(crate::store::ProviderError::ValidatedIntentBindingMismatch(
            _
        ))
    ));
    assert!(matches!(
        fixture
            .book()
            .inventory(fixture.inventory_input().outpoint)
            .expect("inventory lookup")
            .expect("inventory")
            .state(),
        InventoryState::Reserved { .. }
    ));
}

#[test]
fn durable_commit_rechecks_the_exclusive_quote_deadline() {
    let fixture = SettlementFixture::new();
    let submission = fixture.submission();
    let layout = submission
        .layout
        .settlement_layout()
        .expect("settlement layout");
    let intent = ProviderSettlementValidator::new(
        fixture.book(),
        &submission.chain,
        &fixture.output_recovery,
    )
    .validate(fixture.access, &layout, &submission.canonical_pset_bytes())
    .expect("valid before deadline");

    let error = intent
        .commit(fixture.book(), &fixture.reservation.accept_before())
        .expect_err("commit at the exclusive deadline must expire");
    assert!(matches!(
        error,
        crate::store::ProviderError::ReservationDeadlineElapsed { .. }
    ));
    assert!(matches!(
        fixture
            .book()
            .inventory(fixture.inventory_input().outpoint)
            .expect("inventory lookup")
            .expect("inventory")
            .state(),
        InventoryState::Available
    ));
}

#[test]
fn malformed_unbounded_and_unauthorized_submissions_fail_before_commitment() {
    let fixture = SettlementFixture::new();
    let submission = fixture.submission();
    let layout = submission
        .layout
        .settlement_layout()
        .expect("settlement layout");
    let validator = ProviderSettlementValidator::new(
        fixture.book(),
        &submission.chain,
        &fixture.output_recovery,
    );
    assert!(matches!(
        validator.validate(fixture.access, &layout, &[]),
        Err(SettlementValidationError::EmptyPayload)
    ));
    assert!(matches!(
        validator.validate(fixture.access, &layout, &[0_u8]),
        Err(SettlementValidationError::InvalidPset(_))
    ));
    assert!(matches!(
        validator.validate(
            fixture.access,
            &layout,
            &vec![0_u8; crate::model::MAX_SETTLEMENT_BYTES + 1],
        ),
        Err(SettlementValidationError::PayloadTooLarge { .. })
    ));
    let wrong_owner = ReservationAccess::new(fixture.reservation.id(), OwnerId::new([0x99; 32]));
    assert!(matches!(
        validator.validate(wrong_owner, &layout, &submission.canonical_pset_bytes(),),
        Err(SettlementValidationError::Provider(
            crate::store::ProviderError::ReservationOwnerMismatch(_)
        ))
    ));
    assert!(matches!(
        fixture
            .book()
            .inventory(fixture.inventory_input().outpoint)
            .expect("inventory lookup")
            .expect("inventory")
            .state(),
        InventoryState::Reserved { .. }
    ));
}

#[test]
fn validation_reserves_space_for_the_provider_pset_signature_fields() {
    let fixture = SettlementFixture::new();
    let submission = fixture.submission();
    let provider_indexes = submission
        .layout
        .provider_inputs
        .values()
        .copied()
        .collect::<BTreeSet<_>>();
    let placeholder = submission.pset.inputs()[submission.layout.taker_payment_input]
        .tap_key_sig
        .expect("finalized taker signature");
    let pre_sign_bytes = submission.canonical_pset_bytes().len();

    let error = project_finalized_pset(
        &submission.pset,
        &provider_indexes,
        placeholder,
        pre_sign_bytes,
    )
    .expect_err("provider signature fields must increase the persisted PSET size");
    assert!(matches!(
        error,
        SettlementValidationError::FinalizedPayloadTooLarge { maximum, actual }
            if maximum == pre_sign_bytes && actual > maximum
    ));
    project_finalized_pset(
        &submission.pset,
        &provider_indexes,
        placeholder,
        crate::model::MAX_SETTLEMENT_BYTES,
    )
    .expect("ordinary settlement has enough final artifact capacity");
}

#[test]
fn validator_enforces_fee_policy_on_an_otherwise_balanced_transaction() {
    let underfee = SettlementFixture::with_fee_policy(NETWORK_FEE + 1, 1_000_000);
    let submission = underfee.submission();
    let layout = submission
        .layout
        .settlement_layout()
        .expect("settlement layout");
    let error = ProviderSettlementValidator::new(
        underfee.book(),
        &submission.chain,
        &underfee.output_recovery,
    )
    .validate(underfee.access, &layout, &submission.canonical_pset_bytes())
    .expect_err("absolute fee floor must be enforced");
    assert!(matches!(
        error,
        SettlementValidationError::FeePolicy(
            crate::model::FeePolicyViolation::FeeBelowMinimum {
                required,
                actual: NETWORK_FEE,
            }
        ) if required == NETWORK_FEE + 1
    ));

    let overweight = SettlementFixture::with_fee_policy(1, 1);
    let submission = overweight.submission();
    let layout = submission
        .layout
        .settlement_layout()
        .expect("settlement layout");
    let error = ProviderSettlementValidator::new(
        overweight.book(),
        &submission.chain,
        &overweight.output_recovery,
    )
    .validate(
        overweight.access,
        &layout,
        &submission.canonical_pset_bytes(),
    )
    .expect_err("weight ceiling must be enforced");
    assert!(matches!(
        error,
        SettlementValidationError::FeePolicy(
            crate::model::FeePolicyViolation::TransactionOverweight {
                maximum: 1,
                actual,
            }
        ) if actual > 1
    ));
}

#[test]
fn provider_output_recovery_must_resolve_the_durable_spend_key() {
    let fixture = SettlementFixture::new();
    let submission = fixture.submission();
    let layout = submission
        .layout
        .settlement_layout()
        .expect("settlement layout");
    let mut wrong_recovery =
        FixtureOutputRecovery::new(&[&fixture.provider_receive, &fixture.provider_change]);
    let receive_locator = fixture
        .provider_receive
        .destination
        .wallet_locator()
        .to_bytes();
    wrong_recovery
        .wallet_keys
        .get_mut(&receive_locator)
        .expect("provider receive recovery")
        .0 = fixture.provider_change.destination.internal_key();

    assert!(matches!(
        ProviderSettlementValidator::new(fixture.book(), &submission.chain, &wrong_recovery)
            .validate(fixture.access, &layout, &submission.canonical_pset_bytes(),),
        Err(SettlementValidationError::OutputRecovery {
            role: QuoteOutputRole::ProviderPayment,
            ..
        })
    ));
}

#[test]
fn exact_committed_retry_uses_durable_state_before_live_chain_revalidation() {
    let fixture = SettlementFixture::new();
    let submission = fixture.submission();
    let layout = submission
        .layout
        .settlement_layout()
        .expect("settlement layout");
    let canonical = submission.canonical_pset_bytes();
    let validator = ProviderSettlementValidator::new(
        fixture.book(),
        &submission.chain,
        &fixture.output_recovery,
    );
    validator
        .validate(fixture.access, &layout, &canonical)
        .expect("initial validation")
        .commit(fixture.book(), &VALIDATION_TIME)
        .expect("initial commit");

    let spent = fixture.mutated(FixtureMutation::SpentProviderPrevout);
    let retry_validator =
        ProviderSettlementValidator::new(fixture.book(), &spent.chain, &fixture.output_recovery);
    let retry = retry_validator
        .validate(fixture.access, &layout, &canonical)
        .expect("exact committed replay");
    let committed = retry
        .commit(fixture.book(), &UnixMillis::new(103))
        .expect("idempotent commit replay");
    assert!(matches!(committed, CommitOutcome::AlreadyCommitted(_)));
}

#[test]
fn exact_signed_retry_uses_durable_state_before_live_chain_revalidation() {
    let fixture = SettlementFixture::new();
    let submission = fixture.submission();
    let layout = submission
        .layout
        .settlement_layout()
        .expect("settlement layout");
    let canonical = submission.canonical_pset_bytes();
    let committed = ProviderSettlementValidator::new(
        fixture.book(),
        &submission.chain,
        &fixture.output_recovery,
    )
    .validate(fixture.access, &layout, &canonical)
    .expect("initial validation")
    .commit(fixture.book(), &VALIDATION_TIME)
    .expect("initial commit");
    let job = committed.signing_job().expect("committed signing job");
    let signed_bytes = vec![0x51_u8, 0x21, 0x02];
    fixture
        .book()
        .record_signed(
            fixture.reservation.id(),
            job.commitment(),
            signed_bytes.clone(),
            &UnixMillis::new(103),
        )
        .expect("persist signed artifact");

    let spent = fixture.mutated(FixtureMutation::SpentProviderPrevout);
    let replay =
        ProviderSettlementValidator::new(fixture.book(), &spent.chain, &fixture.output_recovery)
            .validate(fixture.access, &layout, &canonical)
            .expect("exact signed replay")
            .commit(fixture.book(), &UnixMillis::new(104))
            .expect("signed replay commit");
    let CommitOutcome::AlreadySigned(artifact) = replay else {
        panic!("signed replay must return the durable artifact");
    };
    assert_eq!(artifact.bytes(), signed_bytes);
}

#[test]
fn a_different_payload_is_rejected_after_the_point_of_no_return() {
    let fixture = SettlementFixture::new();
    let baseline = fixture.submission();
    let layout = baseline
        .layout
        .settlement_layout()
        .expect("settlement layout");
    let validator =
        ProviderSettlementValidator::new(fixture.book(), &baseline.chain, &fixture.output_recovery);
    validator
        .validate(fixture.access, &layout, &baseline.canonical_pset_bytes())
        .expect("initial validation")
        .commit(fixture.book(), &VALIDATION_TIME)
        .expect("initial commit");

    let different = fixture.mutated(FixtureMutation::WrongFeeAmount);
    let retry_validator = ProviderSettlementValidator::new(
        fixture.book(),
        &different.chain,
        &fixture.output_recovery,
    );
    assert!(
        retry_validator
            .validate(fixture.access, &layout, &different.canonical_pset_bytes(),)
            .is_err()
    );
}

#[test]
fn settlement_layout_rejects_input_and_output_aliasing_before_validation() {
    let fixture = SettlementFixture::new();
    let aliased_input = fixture.mutated(FixtureMutation::AliasProviderInputMapping);
    assert!(matches!(
        aliased_input.layout.settlement_layout(),
        Err(SettlementLayoutError::AliasedInput(_))
    ));
    let aliased_output = fixture.mutated(FixtureMutation::AliasProviderPaymentAndReceive);
    assert!(matches!(
        aliased_output.layout.settlement_layout(),
        Err(SettlementLayoutError::AliasedOutput(_))
    ));
}

#[test]
fn submitted_pset_and_authority_mutations_fail_closed() {
    let fixture = SettlementFixture::new();
    let mutations = [
        FixtureMutation::WrongPsetVersion,
        FixtureMutation::WrongTransactionVersion,
        FixtureMutation::TransactionModifiable,
        FixtureMutation::NonzeroLocktime,
        FixtureMutation::ProviderInputMappingOutOfRange,
        FixtureMutation::RemoveProviderInput,
        FixtureMutation::DuplicateProviderOutpoint,
        FixtureMutation::WrongProviderWitnessUtxo,
        FixtureMutation::UnexpectedInputDisclosure,
        FixtureMutation::NonFinalProviderSequence,
        FixtureMutation::ProviderAlreadySigned,
        FixtureMutation::MissingTakerWitness,
        FixtureMutation::WrongTakerSighash,
        FixtureMutation::IssuanceMetadata,
        FixtureMutation::PeginMetadata,
        FixtureMutation::RemoveQuotedOutput,
        FixtureMutation::SwapProviderPaymentAndReceive,
        FixtureMutation::WrongProviderPaymentScript,
        FixtureMutation::WrongProviderPaymentDisclosure,
        FixtureMutation::MissingBlindValueProof,
        FixtureMutation::MissingRangeproof,
        FixtureMutation::MissingSurjectionProof,
        FixtureMutation::MissingProviderNonce,
        FixtureMutation::WrongProviderNonce,
        FixtureMutation::WrongFeeAmount,
        FixtureMutation::WrongFeeAsset,
        FixtureMutation::ExtraFeeOutput,
        FixtureMutation::MissingAuthoritativePrevout,
        FixtureMutation::SpentProviderPrevout,
        FixtureMutation::WrongAuthoritativePrevout,
        FixtureMutation::WrongGenesis,
    ];

    for mutation in mutations {
        let submitted = fixture.mutated(mutation);
        let layout = submitted
            .layout
            .settlement_layout()
            .expect("non-alias mutation keeps a constructible layout");
        let validator = ProviderSettlementValidator::new(
            fixture.book(),
            &submitted.chain,
            &fixture.output_recovery,
        );
        let result = validator.validate(fixture.access, &layout, &submitted.canonical_pset_bytes());
        assert!(
            result.is_err(),
            "mutation unexpectedly validated: {mutation:?}"
        );
    }
}

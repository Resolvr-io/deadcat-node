//! Offline whole-PSET authorization tests.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use deadcat_client::composition::{
    BlinderRef, CompositionLimits, InputId, InputSequence, InputSpec, LockTimeConstraint,
    NetworkFee, OutputId, OutputSpec, TransactionContribution,
};
use deadcat_client::validation::validate_contract_view;
use deadcat_client::venue::{
    AssetAmount, ConfidentialRecipient, ExactExecution, ExecutionRequest, LegId, ProposedLeg,
    VenueContext,
};
use deadcat_contracts::binary_market::BinaryMarketSlot;
use deadcat_rfq_rpc::{
    AssetAmountDto, BlinderRoleDto, FeePolicyDto, FeeSizeMetricDto, FirmQuoteDto,
    FirmQuoteRequestDto, FixedBytes32, FixedBytes33, IdempotencyKeyDto, InputPlacementDto,
    OutputPlacementDto, PricingDecisionDto, QuoteContextDto, QuoteExecutionDto, QuoteInputDto,
    QuoteKindDto, QuoteOutputDto, QuoteOutputRoleDto, QuoteRecipientDto, SignedFirmQuote,
    SnapshotEvidenceDto, TxOutDto,
};
use deadcat_rpc::{ContractParametersView, ContractStateView, ContractView, LiveOutpoint};
use deadcat_types::{
    BinaryMarketParams, BinaryMarketState, ChainPosition, ContractKind, ContractSyncState,
    LiquidNetwork,
};
use elements::bitcoin::PublicKey as BitcoinPublicKey;
use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::hashes::Hash as _;
use elements::schnorr::TapTweak as _;
use elements::secp256k1_zkp::rand::thread_rng;
use elements::secp256k1_zkp::{Keypair, Message, PublicKey, SecretKey};
use elements::sighash::{Prevouts, SighashCache};
use elements::{
    Address, AddressParams, AssetId, BlockHash, SchnorrSig, TxOutSecrets, TxOutWitness, Txid,
};
use iroh::SecretKey as IrohSecretKey;
use serde::Serialize;

use super::*;

const FEE: u64 = 1_000;
const PAYMENT: u64 = 20_000;
const RECEIVE: u64 = 2;

fn asset(marker: u8) -> AssetId {
    AssetId::from_slice(&[marker; 32]).expect("test asset")
}

#[derive(Clone)]
struct TestWalletKey {
    keypair: Keypair,
    internal_key: XOnlyPublicKey,
    blinding_secret: SecretKey,
    address: Address,
}

impl TestWalletKey {
    fn new(spend: u8, blind: u8) -> Self {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[spend; 32]).expect("spend key");
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (internal_key, _) = keypair.x_only_public_key();
        let blinding_secret = SecretKey::from_slice(&[blind; 32]).expect("blinding key");
        let blinding_public = PublicKey::from_secret_key(&secp, &blinding_secret);
        let address = Address::p2tr(
            &secp,
            internal_key,
            None,
            Some(blinding_public),
            &AddressParams::ELEMENTS,
        );
        Self {
            keypair,
            internal_key,
            blinding_secret,
            address,
        }
    }

    fn recipient(&self) -> ConfidentialRecipient {
        ConfidentialRecipient::new(
            self.address.script_pubkey(),
            BitcoinPublicKey::new(self.address.blinding_pubkey.expect("blinding public key")),
        )
        .expect("recipient")
    }

    fn recipient_dto(&self) -> QuoteRecipientDto {
        QuoteRecipientDto {
            script_pubkey: self.address.script_pubkey().into_bytes(),
            blinding_public_key: FixedBytes33::new(
                self.address
                    .blinding_pubkey
                    .expect("blinding public key")
                    .serialize(),
            ),
        }
    }

    fn input_spec(&self, id: InputId, utxo: &OwnedUtxo) -> InputSpec {
        InputSpec::tree_less_p2tr_sighash_all(
            id,
            utxo.outpoint,
            utxo.txout.clone(),
            InputSequence::Final,
            self.internal_key,
        )
    }

    fn output_spec(
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
            self.address.script_pubkey(),
            BitcoinPublicKey::new(self.address.blinding_pubkey.expect("blinding public key")),
            blinder,
        )
    }
}

#[derive(Clone)]
struct OwnedUtxo {
    outpoint: OutPoint,
    txout: TxOut,
    secrets: TxOutSecrets,
}

fn explicit_secrets(asset: AssetId, value: u64) -> TxOutSecrets {
    TxOutSecrets::new(
        asset,
        AssetBlindingFactor::zero(),
        value,
        ValueBlindingFactor::zero(),
    )
}

fn confidential_utxo(wallet: &TestWalletKey, marker: u8, asset: AssetId, value: u64) -> OwnedUtxo {
    let explicit = TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey: wallet.address.script_pubkey(),
        witness: TxOutWitness::default(),
    };
    let (txout, asset_bf, value_bf, _) = explicit
        .to_non_last_confidential(
            &mut thread_rng(),
            &Secp256k1::new(),
            wallet.address.blinding_pubkey.expect("blinding public key"),
            &[explicit_secrets(asset, value)],
        )
        .expect("confidential UTXO");
    OwnedUtxo {
        outpoint: OutPoint::new(Txid::from_byte_array([marker; 32]), 0),
        txout,
        secrets: TxOutSecrets::new(asset, asset_bf, value, value_bf),
    }
}

fn chain() -> ChainIdentity {
    ChainIdentity {
        network: LiquidNetwork::ElementsRegtest,
        genesis_hash: BlockHash::from_byte_array([0x10; 32]),
    }
}

fn market(policy: AssetId, payment: AssetId, outcome: AssetId) -> TradingMarket {
    let secp = Secp256k1::new();
    let oracle = Keypair::from_secret_key(
        &secp,
        &SecretKey::from_slice(&[0x11; 32]).expect("oracle key"),
    );
    let creation = Txid::from_byte_array([0x12; 32]);
    let params = BinaryMarketParams {
        oracle_public_key: oracle.x_only_public_key().0.serialize(),
        collateral_asset_id: payment,
        yes_token_asset_id: outcome,
        no_token_asset_id: asset(4),
        yes_reissuance_token_id: asset(5),
        no_reissuance_token_id: asset(6),
        base_payout: 100,
        expiry_height: 500,
    };
    let view = ContractView {
        contract_id: ContractId::new(OutPoint::new(creation, 0)),
        kind: ContractKind::BinaryMarketV1,
        sync_state: ContractSyncState::Ready {
            synced_through: ChainAnchor {
                height: 10,
                hash: BlockHash::from_byte_array([0x13; 32]),
            },
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
                outpoint: OutPoint::new(creation, 0),
            },
            LiveOutpoint {
                role: BinaryMarketSlot::DormantNoRt as u8,
                outpoint: OutPoint::new(creation, 1),
            },
        ],
    };
    let validated = validate_contract_view(&view).expect("valid market");
    TradingMarket::from_validated(&validated, chain(), policy).expect("trading market")
}

#[derive(Serialize)]
struct BindingWire {
    provider_endpoint: FixedBytes32,
    client_endpoint: FixedBytes32,
    chain: ChainIdentity,
    policy_asset: AssetId,
    reservation_id: FixedBytes32,
    quote_commitment: FixedBytes32,
    created_at_millis: String,
    accept_before_millis: String,
}

fn binding_from_wire(wire: &BindingWire) -> ExecutionBinding {
    let bytes = postcard::to_allocvec(&wire).expect("serialize binding wire");
    postcard::from_bytes(&bytes).expect("deserialize private binding")
}

struct Fixture {
    plan: TakerSettlementPlan,
    binding: ExecutionBinding,
    layout: SettlementLayoutDto,
    provider_blinded: SettlementPset,
    source: TestSource,
    wallet: TestWallet,
}

fn fixture(wallet_mode: WalletMode, minimum_absolute_fee: u64) -> Fixture {
    let policy = asset(1);
    let payment = asset(2);
    let outcome = asset(3);
    let market = market(policy, payment, outcome);
    let user = TestWalletKey::new(0x21, 0x22);
    let provider = TestWalletKey::new(0x31, 0x32);
    let fee_input = confidential_utxo(&user, 0x41, policy, 5_000);
    let payment_input = confidential_utxo(&user, 0x42, payment, 30_000);
    let inventory_input = confidential_utxo(&provider, 0x43, outcome, 5);

    let context = VenueContext {
        chain: chain(),
        market: market.contract_id(),
        policy_asset: policy,
    };
    let request = ExecutionRequest::exact_in(
        context,
        AssetAmount::new(payment, PAYMENT).expect("input"),
        outcome,
        RECEIVE,
        user.recipient(),
        BTreeMap::new(),
        FEE,
    )
    .expect("execution request");
    let leg_request = request
        .exact_in_leg(LegId::new(1), PAYMENT, payment_input.outpoint)
        .expect("leg request");
    let proposal = ProposedLeg::new(
        ExactExecution::new(
            AssetAmount::new(payment, PAYMENT).expect("payment"),
            AssetAmount::new(outcome, RECEIVE).expect("receive"),
        )
        .expect("execution"),
        BTreeMap::new(),
        TransactionContribution::new(
            vec![provider.input_spec(InputId::new(1), &inventory_input)],
            vec![
                provider.output_spec(
                    OutputId::new(1),
                    payment,
                    PAYMENT,
                    BlinderRef::External(payment_input.outpoint),
                ),
                provider.output_spec(
                    OutputId::new(2),
                    outcome,
                    3,
                    BlinderRef::Local(InputId::new(1)),
                ),
                user.output_spec(
                    OutputId::new(3),
                    outcome,
                    RECEIVE,
                    BlinderRef::Local(InputId::new(1)),
                ),
            ],
            LockTimeConstraint::Unconstrained,
        ),
        OutputId::new(1),
        OutputId::new(3),
    )
    .expect("proposal");
    let leg = leg_request.authorize(proposal).expect("authorized leg");
    let route = request
        .validate_route(
            vec![leg],
            NetworkFee::new(policy, FEE).expect("network fee"),
        )
        .expect("route")
        .compose(
            CompositionLimits::default(),
            TransactionContribution::new(
                vec![
                    user.input_spec(InputId::new(1), &fee_input),
                    user.input_spec(InputId::new(2), &payment_input),
                ],
                vec![
                    user.output_spec(
                        OutputId::new(1),
                        policy,
                        4_000,
                        BlinderRef::Local(InputId::new(1)),
                    ),
                    user.output_spec(
                        OutputId::new(2),
                        payment,
                        10_000,
                        BlinderRef::Local(InputId::new(2)),
                    ),
                ],
                LockTimeConstraint::Unconstrained,
            ),
        )
        .expect("composed route");

    let composition = route.transaction().layout();
    let venue = route.layout().leg(LegId::new(1)).expect("venue handle");
    let provider_input_index = composition
        .input_index(venue, InputId::new(1))
        .expect("provider input");
    let output_indices = [OutputId::new(1), OutputId::new(2), OutputId::new(3)]
        .map(|id| composition.output_index(venue, id).expect("quote output"));
    let layout = SettlementLayoutDto {
        taker_payment_input: u16::try_from(
            composition
                .outpoint_index(payment_input.outpoint)
                .expect("payment input"),
        )
        .expect("u16"),
        provider_inputs: vec![InputPlacementDto {
            quote_input_id: 1,
            transaction_index: u16::try_from(provider_input_index).expect("u16"),
        }],
        quote_outputs: output_indices
            .iter()
            .enumerate()
            .map(|(position, index)| OutputPlacementDto {
                quote_output_id: u16::try_from(position + 1).expect("u16"),
                transaction_index: u16::try_from(*index).expect("u16"),
            })
            .collect(),
    };

    let provider_identity = IrohSecretKey::generate();
    let client_identity = IrohSecretKey::generate();
    let idempotency_key = IdempotencyKeyDto::new([0x51; 32]);
    let request_dto = FirmQuoteRequestDto {
        context: QuoteContextDto {
            network: chain().network,
            genesis_hash: chain().genesis_hash,
            market: market.contract_id(),
            policy_asset: policy,
        },
        kind: QuoteKindDto::ExactIn {
            input: AssetAmountDto {
                asset: payment,
                amount: PAYMENT,
            },
            output_asset: outcome,
            minimum_output: RECEIVE,
        },
        recipient: user.recipient_dto(),
        maximum_input_asset_venue_fee: 0,
    };
    let reservation_id = FixedBytes32::new([0x52; 32]);
    let quote_commitment = FixedBytes32::new([0x53; 32]);
    let quote = FirmQuoteDto {
        reservation_id,
        provider_endpoint: FixedBytes32::new(*provider_identity.public().as_bytes()),
        network: chain().network,
        genesis_hash: chain().genesis_hash,
        policy_asset: policy,
        request: request_dto.clone(),
        execution: QuoteExecutionDto {
            input: AssetAmountDto {
                asset: payment,
                amount: PAYMENT,
            },
            output: AssetAmountDto {
                asset: outcome,
                amount: RECEIVE,
            },
            input_asset_venue_fee: 0,
        },
        pricing: PricingDecisionDto {
            rate: deadcat_rfq_rpc::RationalRateDto {
                numerator: 1,
                denominator: 10_000,
            },
            input_asset_venue_fee: 0,
            policy_id: FixedBytes32::new([0x54; 32]),
            revision: 1,
        },
        snapshot: SnapshotEvidenceDto {
            block_hash: market.observed_at().hash,
            block_height: market.observed_at().height,
            snapshot_commitment: FixedBytes32::new([0x55; 32]),
            allocation_revision: 1,
            eligible_commitment: FixedBytes32::new([0x56; 32]),
        },
        inputs: vec![QuoteInputDto {
            id: 1,
            outpoint: inventory_input.outpoint,
            witness_utxo: TxOutDto::from_txout(&inventory_input.txout),
            internal_key: FixedBytes32::new(provider.internal_key.serialize()),
            inventory_binding: FixedBytes32::new([0x57; 32]),
        }],
        outputs: vec![
            QuoteOutputDto {
                id: 1,
                role: QuoteOutputRoleDto::ProviderPayment,
                asset: payment,
                amount: PAYMENT,
                destination: provider.recipient_dto(),
                blinder: BlinderRoleDto::TakerPaymentInput,
            },
            QuoteOutputDto {
                id: 2,
                role: QuoteOutputRoleDto::ProviderChange,
                asset: outcome,
                amount: 3,
                destination: provider.recipient_dto(),
                blinder: BlinderRoleDto::ProviderInput { quote_input_id: 1 },
            },
            QuoteOutputDto {
                id: 3,
                role: QuoteOutputRoleDto::TakerReceive,
                asset: outcome,
                amount: RECEIVE,
                destination: user.recipient_dto(),
                blinder: BlinderRoleDto::ProviderInput { quote_input_id: 1 },
            },
        ],
        created_at_millis: 1_000,
        accept_before_millis: 30_000,
        fee_policy: FeePolicyDto {
            policy_asset: policy,
            minimum_sats_per_kvb: 1,
            minimum_absolute_fee,
            maximum_transaction_weight: 1_000_000,
            size_metric: FeeSizeMetricDto::RegularVbytes,
        },
        recovery_metadata_commitment: FixedBytes32::new([0x58; 32]),
        quote_commitment,
    };
    let verified = SignedFirmQuote::sign(
        quote,
        &provider_identity,
        client_identity.public(),
        idempotency_key,
    )
    .expect("signed quote")
    .verify(
        provider_identity.public(),
        client_identity.public(),
        idempotency_key,
        &request_dto,
    )
    .expect("verified quote");
    let binding = binding_from_wire(&BindingWire {
        provider_endpoint: FixedBytes32::new(*provider_identity.public().as_bytes()),
        client_endpoint: FixedBytes32::new(*client_identity.public().as_bytes()),
        chain: chain(),
        policy_asset: policy,
        reservation_id,
        quote_commitment,
        created_at_millis: "1000".to_owned(),
        accept_before_millis: "30000".to_owned(),
    });
    let plan = TakerSettlementPlan::build(
        &route,
        binding,
        layout.clone(),
        verified,
        &market,
        LegId::new(1),
    )
    .expect("settlement plan");

    let mut provider_pset = plan.original_pset().clone();
    provider_pset
        .blind_non_last(
            &mut thread_rng(),
            &Secp256k1::new(),
            &HashMap::from([(provider_input_index, inventory_input.secrets)]),
        )
        .expect("provider blinding");
    let provider_blinded = SettlementPset::from_pset(&provider_pset).expect("provider PSET");
    let authoritative = vec![fee_input.clone(), payment_input.clone(), inventory_input]
        .into_iter()
        .map(|utxo| AuthoritativeTakerPrevout::new(utxo.outpoint, utxo.txout))
        .collect();
    let source = TestSource {
        now: 2_000,
        market,
        prevouts: authoritative,
        calls: AtomicUsize::new(0),
    };
    let wallet = TestWallet {
        user,
        openings: HashMap::from([(0, fee_input.secrets), (1, payment_input.secrets)]),
        mode: wallet_mode,
    };
    Fixture {
        plan,
        binding,
        layout,
        provider_blinded,
        source,
        wallet,
    }
}

#[derive(Debug, Error)]
#[error("test source failure")]
struct TestFailure;

struct TestSource {
    now: u64,
    market: TradingMarket,
    prevouts: Vec<AuthoritativeTakerPrevout>,
    calls: AtomicUsize,
}

#[async_trait]
impl TakerSettlementSource for TestSource {
    type Error = TestFailure;

    async fn settlement_snapshot(
        &self,
        _: TakerSettlementSnapshotRequest,
    ) -> Result<TakerSettlementSnapshot, Self::Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(TakerSettlementSnapshot::new(
            self.now,
            self.market.clone(),
            self.prevouts.clone(),
        ))
    }
}

#[derive(Clone, Copy)]
enum WalletMode {
    Valid,
    MutateDuringBlinding,
    MutateDuringSigning,
    InvalidSignature,
}

struct TestWallet {
    user: TestWalletKey,
    openings: HashMap<usize, TxOutSecrets>,
    mode: WalletMode,
}

impl TakerWalletFinalizer for TestWallet {
    type Error = TestFailure;

    fn blind_last(
        &self,
        job: TakerWalletBlindingJob,
    ) -> Result<PartiallySignedTransaction, Self::Error> {
        let mut pset = job.into_pset();
        pset.blind_last(&mut thread_rng(), &Secp256k1::new(), &self.openings)
            .map_err(|_| TestFailure)?;
        if matches!(self.mode, WalletMode::MutateDuringBlinding) {
            pset.inputs_mut()[2].final_script_witness = Some(vec![vec![0x01]]);
        }
        Ok(pset)
    }

    fn sign(&self, job: TakerWalletSigningJob) -> Result<PartiallySignedTransaction, Self::Error> {
        let genesis = job.chain().genesis_hash;
        let prevouts = job
            .prevouts()
            .iter()
            .map(|prevout| prevout.txout().clone())
            .collect::<Vec<_>>();
        let indices = job.wallet_input_indices().to_vec();
        let mut pset = job.into_pset();
        let transaction = pset.extract_tx().map_err(|_| TestFailure)?;
        for index in &indices {
            let sighash = SighashCache::new(&transaction)
                .taproot_key_spend_signature_hash(
                    *index,
                    &Prevouts::All(&prevouts),
                    SchnorrSighashType::All,
                    genesis,
                )
                .map_err(|_| TestFailure)?;
            let signature = SchnorrSig {
                sig: Secp256k1::new().sign_schnorr(
                    &Message::from_digest(sighash.to_byte_array()),
                    &self
                        .user
                        .keypair
                        .tap_tweak(&Secp256k1::new(), None)
                        .to_inner(),
                ),
                hash_ty: SchnorrSighashType::All,
            };
            pset.inputs_mut()[*index].tap_key_sig = Some(signature);
            pset.inputs_mut()[*index].final_script_witness = Some(vec![signature.to_vec()]);
        }
        if matches!(self.mode, WalletMode::MutateDuringSigning) {
            pset.inputs_mut()[2].final_script_witness = Some(vec![vec![0x02]]);
        }
        if matches!(self.mode, WalletMode::InvalidSignature) {
            let signature = SchnorrSig {
                sig: Secp256k1::new().sign_schnorr(
                    &Message::from_digest([0x99; 32]),
                    &self
                        .user
                        .keypair
                        .tap_tweak(&Secp256k1::new(), None)
                        .to_inner(),
                ),
                hash_ty: SchnorrSighashType::All,
            };
            pset.inputs_mut()[0].tap_key_sig = Some(signature);
            pset.inputs_mut()[0].final_script_witness = Some(vec![signature.to_vec()]);
        }
        Ok(pset)
    }

    fn validate_owned_output(&self, output: OwnedOutputValidation<'_>) -> Result<(), Self::Error> {
        let secrets = output
            .txout()
            .unblind(&Secp256k1::new(), self.user.blinding_secret)
            .map_err(|_| TestFailure)?;
        let expected = output.expectation();
        if secrets.asset != expected.asset()
            || secrets.value != expected.amount()
            || output.txout().script_pubkey != *expected.script_pubkey()
        {
            return Err(TestFailure);
        }
        Ok(())
    }
}

async fn authorize(fixture: &Fixture) -> Result<SettlementPset, TakerAuthorizationError> {
    let response = ProviderBlindedPset::from_test_parts(
        fixture.binding,
        fixture.layout.clone(),
        fixture.provider_blinded.clone(),
    );
    let preflight = response.preflight_with(fixture.plan.clone())?;
    let observed = preflight.observe(&fixture.source).await?;
    Ok(observed.authorize(&fixture.wallet)?.pset().clone())
}

#[tokio::test]
async fn authorizes_valid_confidential_settlement() {
    let fixture = fixture(WalletMode::Valid, 1);
    let signed = authorize(&fixture).await.expect("valid settlement");
    let pset = signed.to_pset().expect("signed PSET");
    assert!(pset.inputs()[0].tap_key_sig.is_some());
    assert!(pset.inputs()[1].tap_key_sig.is_some());
    assert!(pset.inputs()[2].tap_key_sig.is_none());
}

#[tokio::test]
async fn rejects_expired_quote_before_wallet_work() {
    let mut fixture = fixture(WalletMode::Valid, 1);
    fixture.source.now = 30_000;
    assert!(matches!(
        authorize(&fixture).await,
        Err(TakerAuthorizationError::QuoteNotLive { .. })
    ));
}

#[tokio::test]
async fn rejects_authoritative_prevout_mismatch() {
    let mut fixture = fixture(WalletMode::Valid, 1);
    fixture.source.prevouts[0].txout.value = Value::Explicit(123);
    assert!(matches!(
        authorize(&fixture).await,
        Err(TakerAuthorizationError::InvalidInput { index: 0, .. })
    ));
}

#[tokio::test]
async fn rejects_authoritative_provider_proof_mismatch() {
    let mut fixture = fixture(WalletMode::Valid, 1);
    fixture.source.prevouts[2].txout.witness.surjection_proof = None;
    assert!(matches!(
        authorize(&fixture).await,
        Err(TakerAuthorizationError::InvalidInput { index: 2, .. })
    ));
}

#[tokio::test]
async fn rejects_provider_mutation_outside_blinding_scope() {
    let mut fixture = fixture(WalletMode::Valid, 1);
    let mut provider = fixture.provider_blinded.to_pset().expect("provider PSET");
    provider.inputs_mut()[0].final_script_witness = Some(vec![vec![0x01]]);
    fixture.provider_blinded = SettlementPset::from_pset(&provider).expect("mutated PSET");
    assert!(matches!(
        authorize(&fixture).await,
        Err(TakerAuthorizationError::ProviderMutation(_))
    ));
    assert_eq!(
        fixture.source.calls.load(Ordering::Relaxed),
        0,
        "local preflight must reject before authoritative source I/O"
    );
}

#[tokio::test]
async fn rejects_provider_poisoned_owned_output_nonce() {
    let mut fixture = fixture(WalletMode::Valid, 1);
    let mut provider = fixture.provider_blinded.to_pset().expect("provider PSET");
    let receive_index = usize::from(
        fixture
            .layout
            .quote_outputs
            .iter()
            .find(|placement| placement.quote_output_id == 3)
            .expect("receive placement")
            .transaction_index,
    );
    provider.outputs_mut()[receive_index].ecdh_pubkey =
        Some(BitcoinPublicKey::new(PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[0x77; 32]).expect("replacement nonce key"),
        )));
    fixture.provider_blinded = SettlementPset::from_pset(&provider).expect("mutated PSET");
    assert!(matches!(
        authorize(&fixture).await,
        Err(TakerAuthorizationError::Wallet(_))
    ));
}

#[tokio::test]
async fn rejects_wallet_mutation_during_blinding() {
    let fixture = fixture(WalletMode::MutateDuringBlinding, 1);
    assert!(matches!(
        authorize(&fixture).await,
        Err(TakerAuthorizationError::WalletMutation(_))
    ));
}

#[tokio::test]
async fn rejects_wallet_mutation_during_signing() {
    let fixture = fixture(WalletMode::MutateDuringSigning, 1);
    assert!(matches!(
        authorize(&fixture).await,
        Err(TakerAuthorizationError::WalletMutation(_))
    ));
}

#[tokio::test]
async fn rejects_invalid_wallet_signature() {
    let fixture = fixture(WalletMode::InvalidSignature, 1);
    assert!(matches!(
        authorize(&fixture).await,
        Err(TakerAuthorizationError::InvalidSignature { index: 0, .. })
    ));
}

#[tokio::test]
async fn rejects_fee_policy_before_wallet_blinding() {
    let fixture = fixture(WalletMode::Valid, FEE + 1);
    assert!(matches!(
        authorize(&fixture).await,
        Err(TakerAuthorizationError::FeePolicy(_))
    ));
    assert_eq!(
        fixture.source.calls.load(Ordering::Relaxed),
        0,
        "fee policy is part of local preflight"
    );
}

#[test]
fn rejects_protocol_shape_above_input_bound() {
    let mut pset = PartiallySignedTransaction::new_v2();
    for marker in 0..=MAX_SETTLEMENT_INPUTS {
        pset.add_input(PsetInput::from_prevout(OutPoint::new(
            Txid::from_byte_array([u8::try_from(marker).expect("small bound"); 32]),
            0,
        )));
    }
    assert!(matches!(
        validate_settlement_shape(&pset),
        Err(TakerSettlementPlanError::LaunchProfile(_))
    ));
}

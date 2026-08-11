//! Confidential two-wallet RFQ settlement assurance.
//!
//! The ordinary tests exercise the complete collaborative PSET protocol with
//! synthetic UTXOs. The ignored live test repeats it against liquidregtest,
//! broadcasts the settlement, and spends both parties' received outputs.
//!
//! The wallet and collaborative-signing harness remains test-local, while the
//! settlement body is built through Deadcat's provisional production venue and
//! composition seam. No remote RFQ protocol or stable wire API is frozen here.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr as _;

use bitcoincore_rpc::{Client, RpcApi};
use deadcat_client::composition::{
    BlinderRef, CompositionLayout, CompositionLimits, ContributionHandle, InputId, InputSequence,
    InputSpec, LockTimeConstraint, NetworkFee, OutputId, OutputSpec, TransactionContribution,
    UnblindedStructureManifest,
};
use deadcat_client::venue::{
    AssetAmount, ConfidentialRecipient, ExactExecution, ExecutionError, ExecutionRequest, LegId,
    LegPreparationRequest, ProposedLeg, RouteAuthorization, VenueAdapter, VenueContext,
};
use deadcat_contracts::SimplicityNetwork;
use deadcat_types::{ChainIdentity, ContractId, LiquidNetwork};
use elements::bitcoin::PublicKey as BitcoinPublicKey;
use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::encode::{deserialize, serialize};
use elements::hashes::Hash as _;
use elements::hex::FromHex as _;
use elements::pset::{Input as PsetInput, Output as PsetOutput, PartiallySignedTransaction};
use elements::schnorr::TapTweak as _;
use elements::secp256k1_zkp::rand::thread_rng;
use elements::secp256k1_zkp::{Keypair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use elements::sighash::{Prevouts, SighashCache};
use elements::{
    Address, AddressParams, AssetId, BlindAssetProofs as _, BlindValueProofs as _, BlockHash,
    LockTime, OutPoint, SchnorrSig, SchnorrSighashType, Script, Sequence, Transaction, TxOut,
    TxOutSecrets, TxOutWitness, Txid, UnblindError,
};
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};
use simplex::provider::ElementsRpc;
use smplx_regtest::{Regtest, RegtestConfig};

const NETWORK_FEE: u64 = 1_000;
const USER_FEE_INPUT_VALUE: u64 = 5_000;
const USER_PAYMENT_INPUT_VALUE: u64 = 30_000;
const PROVIDER_INVENTORY_VALUE: u64 = 5;
const PROVIDER_PAYMENT_VALUE: u64 = 20_000;
const USER_RECEIVE_VALUE: u64 = 2;

const FEE_INPUT_ID: InputId = InputId::new(1);
const PAYMENT_INPUT_ID: InputId = InputId::new(2);
const INVENTORY_INPUT_ID: InputId = InputId::new(1);
const FEE_CHANGE_OUTPUT_ID: OutputId = OutputId::new(1);
const USER_PAYMENT_CHANGE_OUTPUT_ID: OutputId = OutputId::new(2);
const PROVIDER_PAYMENT_OUTPUT_ID: OutputId = OutputId::new(1);
const PROVIDER_INVENTORY_CHANGE_OUTPUT_ID: OutputId = OutputId::new(2);
const USER_RECEIVE_OUTPUT_ID: OutputId = OutputId::new(3);

#[derive(Clone, Copy)]
struct SettlementAssets {
    policy: AssetId,
    payment: AssetId,
    outcome: AssetId,
}

#[derive(Clone)]
struct P2trWallet {
    keypair: Keypair,
    internal_key: XOnlyPublicKey,
    blinding_secret: SecretKey,
    address: Address,
}

impl P2trWallet {
    fn deterministic(spend_byte: u8, blinding_byte: u8) -> Self {
        let secp = Secp256k1::new();
        let spend_secret = SecretKey::from_slice(&[spend_byte; 32]).expect("spend key");
        let keypair = Keypair::from_secret_key(&secp, &spend_secret);
        let (internal_key, _) = keypair.x_only_public_key();
        let blinding_secret = SecretKey::from_slice(&[blinding_byte; 32]).expect("blinding key");
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

    fn input(&self, utxo: &OwnedUtxo) -> PsetInput {
        let mut input = PsetInput::from_prevout(utxo.outpoint);
        input.witness_utxo = Some(utxo.txout.clone());
        self.configure_input(&mut input);
        input
    }

    fn configure_input(&self, input: &mut PsetInput) {
        input.sighash_type = Some(SchnorrSighashType::All.into());
        input.tap_internal_key = Some(self.internal_key);
    }

    fn confidential_output(
        &self,
        amount: u64,
        asset: AssetId,
        blinder_input_index: usize,
    ) -> PsetOutput {
        let mut output = PsetOutput::new_explicit(
            self.address.script_pubkey(),
            amount,
            asset,
            self.address.blinding_pubkey.map(BitcoinPublicKey::new),
        );
        output.blinder_index =
            Some(u32::try_from(blinder_input_index).expect("test input index fits in a PSET u32"));
        output
    }

    fn confidential_output_spec(
        &self,
        id: OutputId,
        amount: u64,
        asset: AssetId,
        blinder: BlinderRef,
    ) -> OutputSpec {
        OutputSpec::confidential(
            id,
            asset,
            amount,
            self.address.script_pubkey(),
            self.address
                .blinding_pubkey
                .map(BitcoinPublicKey::new)
                .expect("confidential address"),
            blinder,
        )
    }

    fn unblind(&self, txout: &TxOut) -> TxOutSecrets {
        self.try_unblind(txout)
            .expect("wallet can unblind its output")
    }

    fn try_unblind(&self, txout: &TxOut) -> Result<TxOutSecrets, UnblindError> {
        txout.unblind(&Secp256k1::new(), self.blinding_secret)
    }

    fn sign_input(
        &self,
        pset: &mut PartiallySignedTransaction,
        input_index: usize,
        genesis_hash: BlockHash,
    ) -> SchnorrSig {
        let sighash = pset_sighash(pset, input_index, genesis_hash);
        let message = Message::from_digest(sighash);
        let tweaked_keypair = self.keypair.tap_tweak(&Secp256k1::new(), None);
        let signature = SchnorrSig {
            sig: Secp256k1::new().sign_schnorr(&message, &tweaked_keypair.to_inner()),
            hash_ty: SchnorrSighashType::All,
        };
        let input = &mut pset.inputs_mut()[input_index];
        input.tap_key_sig = Some(signature);
        input.final_script_witness = Some(vec![signature.to_vec()]);
        signature
    }

    fn verifies(
        &self,
        transaction: &Transaction,
        prevouts: &[TxOut],
        input_index: usize,
        signature: SchnorrSig,
        genesis_hash: BlockHash,
    ) -> bool {
        let sighash = transaction_sighash(transaction, prevouts, input_index, genesis_hash);
        let message = Message::from_digest(sighash);
        let (output_key, _) = self.internal_key.tap_tweak(&Secp256k1::new(), None);
        Secp256k1::new()
            .verify_schnorr(&signature.sig, &message, output_key.as_inner())
            .is_ok()
    }
}

#[derive(Clone)]
struct OwnedUtxo {
    outpoint: OutPoint,
    txout: TxOut,
    secrets: TxOutSecrets,
}

#[derive(Clone, Copy)]
struct SettlementLayout {
    fee_input: usize,
    payment_input: usize,
    inventory_input: usize,
    fee_change: usize,
    provider_payment: usize,
    provider_inventory_change: usize,
    user_payment_change: usize,
    user_receive: usize,
    fee: usize,
}

impl SettlementLayout {
    fn from_composition(
        layout: &CompositionLayout,
        wallet: ContributionHandle,
        venue: ContributionHandle,
    ) -> Self {
        Self {
            fee_input: layout
                .input_index(wallet, FEE_INPUT_ID)
                .expect("fee input placement"),
            payment_input: layout
                .input_index(wallet, PAYMENT_INPUT_ID)
                .expect("payment input placement"),
            inventory_input: layout
                .input_index(venue, INVENTORY_INPUT_ID)
                .expect("inventory input placement"),
            fee_change: layout
                .output_index(wallet, FEE_CHANGE_OUTPUT_ID)
                .expect("fee change placement"),
            provider_payment: layout
                .output_index(venue, PROVIDER_PAYMENT_OUTPUT_ID)
                .expect("provider payment placement"),
            provider_inventory_change: layout
                .output_index(venue, PROVIDER_INVENTORY_CHANGE_OUTPUT_ID)
                .expect("provider inventory change placement"),
            user_payment_change: layout
                .output_index(wallet, USER_PAYMENT_CHANGE_OUTPUT_ID)
                .expect("user payment change placement"),
            user_receive: layout
                .output_index(venue, USER_RECEIVE_OUTPUT_ID)
                .expect("user receive placement"),
            fee: layout.fee_output_index(),
        }
    }
}

#[derive(Clone)]
struct SettlementFixture {
    pset: PartiallySignedTransaction,
    manifest: UnblindedStructureManifest,
    route_authorization: RouteAuthorization,
    layout: SettlementLayout,
    prevouts: Vec<TxOut>,
    user: P2trWallet,
    provider: P2trWallet,
    fee_input: OwnedUtxo,
    payment_input: OwnedUtxo,
    inventory_input: OwnedUtxo,
    assets: SettlementAssets,
}

fn explicit_secrets(asset: AssetId, value: u64) -> TxOutSecrets {
    TxOutSecrets::new(
        asset,
        AssetBlindingFactor::zero(),
        value,
        ValueBlindingFactor::zero(),
    )
}

fn fake_confidential_utxo(
    wallet: &P2trWallet,
    outpoint_byte: u8,
    asset: AssetId,
    value: u64,
) -> OwnedUtxo {
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
            wallet
                .address
                .blinding_pubkey
                .expect("confidential address"),
            &[explicit_secrets(asset, value)],
        )
        .expect("synthetic confidential UTXO");
    OwnedUtxo {
        outpoint: OutPoint::new(Txid::from_byte_array([outpoint_byte; 32]), 0),
        txout,
        secrets: TxOutSecrets::new(asset, asset_bf, value, value_bf),
    }
}

fn add_fee_output(pset: &mut PartiallySignedTransaction, amount: u64, policy_asset: AssetId) {
    pset.add_output(PsetOutput::from_txout(TxOut::new_fee(amount, policy_asset)));
}

#[derive(Clone)]
struct TestRfqEvidence {
    context: VenueContext,
    provider: P2trWallet,
    inventory_input: OwnedUtxo,
    assets: SettlementAssets,
}

struct TestRfqAdapter;

impl VenueAdapter for TestRfqAdapter {
    type Evidence = TestRfqEvidence;
    type Error = ExecutionError;

    fn prepare(
        &self,
        request: &LegPreparationRequest,
        evidence: &Self::Evidence,
    ) -> Result<ProposedLeg, Self::Error> {
        if request.context() != evidence.context {
            return Err(ExecutionError::ContextMismatch);
        }
        let execution = ExactExecution::new(
            AssetAmount::new(evidence.assets.payment, PROVIDER_PAYMENT_VALUE)?,
            AssetAmount::new(evidence.assets.outcome, USER_RECEIVE_VALUE)?,
        )?;
        let contribution = TransactionContribution::new(
            vec![InputSpec::new(
                INVENTORY_INPUT_ID,
                evidence.inventory_input.outpoint,
                evidence.inventory_input.txout.clone(),
                InputSequence::Final,
            )],
            vec![
                evidence.provider.confidential_output_spec(
                    PROVIDER_PAYMENT_OUTPUT_ID,
                    PROVIDER_PAYMENT_VALUE,
                    evidence.assets.payment,
                    BlinderRef::External(request.payer_blinder()),
                ),
                evidence.provider.confidential_output_spec(
                    PROVIDER_INVENTORY_CHANGE_OUTPUT_ID,
                    PROVIDER_INVENTORY_VALUE - USER_RECEIVE_VALUE,
                    evidence.assets.outcome,
                    BlinderRef::Local(INVENTORY_INPUT_ID),
                ),
                OutputSpec::confidential(
                    USER_RECEIVE_OUTPUT_ID,
                    evidence.assets.outcome,
                    USER_RECEIVE_VALUE,
                    request.recipient().script_pubkey().clone(),
                    request.recipient().blinding_key(),
                    BlinderRef::Local(INVENTORY_INPUT_ID),
                ),
            ],
            LockTimeConstraint::Unconstrained,
        );
        ProposedLeg::new(
            execution,
            BTreeMap::new(),
            contribution,
            PROVIDER_PAYMENT_OUTPUT_ID,
            USER_RECEIVE_OUTPUT_ID,
        )
    }
}

fn build_settlement(
    user: P2trWallet,
    provider: P2trWallet,
    fee_input: OwnedUtxo,
    payment_input: OwnedUtxo,
    inventory_input: OwnedUtxo,
    assets: SettlementAssets,
    genesis_hash: BlockHash,
) -> SettlementFixture {
    let context = VenueContext {
        chain: ChainIdentity {
            network: LiquidNetwork::ElementsRegtest,
            genesis_hash,
        },
        market: ContractId::new(inventory_input.outpoint),
        policy_asset: assets.policy,
    };
    let network_fee = NetworkFee::new(assets.policy, NETWORK_FEE).expect("network fee");
    let recipient = ConfidentialRecipient::new(
        user.address.script_pubkey(),
        user.address
            .blinding_pubkey
            .map(BitcoinPublicKey::new)
            .expect("confidential user address"),
    )
    .expect("user recipient");
    let request = ExecutionRequest::exact_in(
        context,
        AssetAmount::new(assets.payment, PROVIDER_PAYMENT_VALUE).expect("exact input"),
        assets.outcome,
        USER_RECEIVE_VALUE,
        recipient,
        BTreeMap::new(),
        NETWORK_FEE,
    )
    .expect("exact-in request");
    let evidence = TestRfqEvidence {
        context,
        provider: provider.clone(),
        inventory_input: inventory_input.clone(),
        assets,
    };
    let leg_request = request
        .exact_in_leg(
            LegId::new(1),
            PROVIDER_PAYMENT_VALUE,
            payment_input.outpoint,
        )
        .expect("single-leg allocation");
    let proposal = TestRfqAdapter
        .prepare(&leg_request, &evidence)
        .expect("client-local RFQ adapter");
    let leg = leg_request
        .authorize(proposal)
        .expect("proposal matches exact allocation and recipient");
    let route = request
        .validate_route(vec![leg], network_fee)
        .expect("prepared leg satisfies exact-in intent");

    let wallet = TransactionContribution::new(
        vec![
            InputSpec::new(
                FEE_INPUT_ID,
                fee_input.outpoint,
                fee_input.txout.clone(),
                InputSequence::Final,
            ),
            InputSpec::new(
                PAYMENT_INPUT_ID,
                payment_input.outpoint,
                payment_input.txout.clone(),
                InputSequence::Final,
            ),
        ],
        vec![
            user.confidential_output_spec(
                FEE_CHANGE_OUTPUT_ID,
                USER_FEE_INPUT_VALUE - NETWORK_FEE,
                assets.policy,
                BlinderRef::Local(FEE_INPUT_ID),
            ),
            user.confidential_output_spec(
                USER_PAYMENT_CHANGE_OUTPUT_ID,
                USER_PAYMENT_INPUT_VALUE - PROVIDER_PAYMENT_VALUE,
                assets.payment,
                BlinderRef::Local(PAYMENT_INPUT_ID),
            ),
        ],
        LockTimeConstraint::Unconstrained,
    );
    let composed_route = route
        .compose(CompositionLimits::default(), wallet)
        .expect("complete route composition");
    let wallet_handle = composed_route.layout().wallet();
    let venue_handle = composed_route
        .layout()
        .leg(LegId::new(1))
        .expect("RFQ placement");
    let (composed, route_authorization) = composed_route.into_parts();
    assert_eq!(
        composed
            .layout()
            .placement(wallet_handle)
            .expect("wallet placement")
            .input_base(),
        0
    );
    assert!(
        composed
            .layout()
            .placement(venue_handle)
            .expect("venue placement")
            .input_base()
            > 0,
        "the venue contribution must not rely on global input zero"
    );
    let layout = SettlementLayout::from_composition(composed.layout(), wallet_handle, venue_handle);
    let (mut pset, _, manifest) = composed.into_parts();
    user.configure_input(&mut pset.inputs_mut()[layout.fee_input]);
    user.configure_input(&mut pset.inputs_mut()[layout.payment_input]);
    provider.configure_input(&mut pset.inputs_mut()[layout.inventory_input]);
    manifest
        .validate(&pset)
        .expect("signing metadata preserves the frozen manifest");
    let prevouts = pset
        .inputs()
        .iter()
        .map(|input| input.witness_utxo.clone().expect("composed prevout"))
        .collect();

    SettlementFixture {
        pset,
        manifest,
        route_authorization,
        layout,
        prevouts,
        user,
        provider,
        fee_input,
        payment_input,
        inventory_input,
        assets,
    }
}

fn blind_settlement(fixture: &mut SettlementFixture) {
    let mut provider_secrets = HashMap::new();
    provider_secrets.insert(
        fixture.layout.inventory_input,
        fixture.inventory_input.secrets,
    );
    fixture
        .pset
        .blind_non_last(&mut thread_rng(), &Secp256k1::new(), &provider_secrets)
        .expect("provider non-last blinding");

    // Exercise the PSET handoff and scalar-offset serialization. The final
    // blinding call receives only the user's openings; process/key-domain
    // isolation remains a later remote-protocol acceptance gate.
    fixture.pset = deserialize(&serialize(&fixture.pset)).expect("PSET handoff round trip");
    validate_settlement_intent(fixture).expect("provider preserved the frozen transaction intent");
    for index in [
        fixture.layout.provider_inventory_change,
        fixture.layout.user_receive,
    ] {
        validate_output_disclosure(&fixture.pset.outputs()[index], index)
            .expect("provider disclosure matches its blinded output commitment");
    }
    let provider_blinded = fixture
        .pset
        .extract_tx()
        .expect("provider-blinded partial transaction");
    assert_opening(
        fixture
            .user
            .unblind(&provider_blinded.output[fixture.layout.user_receive]),
        fixture.assets.outcome,
        USER_RECEIVE_VALUE,
    );

    let mut user_secrets = HashMap::new();
    user_secrets.insert(fixture.layout.fee_input, fixture.fee_input.secrets);
    user_secrets.insert(fixture.layout.payment_input, fixture.payment_input.secrets);
    fixture
        .pset
        .blind_last(&mut thread_rng(), &Secp256k1::new(), &user_secrets)
        .expect("user final balancing blinding");
}

fn input_outpoint(input: &PsetInput) -> OutPoint {
    OutPoint::new(input.previous_txid, input.previous_output_index)
}

fn same_prevout_body(actual: &TxOut, expected: &TxOut) -> bool {
    // PSET serializes an input UTXO's rangeproof separately from its TxOut, so
    // compare the consensus prevout body that Taproot and Elements spend.
    actual.asset == expected.asset
        && actual.value == expected.value
        && actual.nonce == expected.nonce
        && actual.script_pubkey == expected.script_pubkey
}

fn expect_output(
    pset: &PartiallySignedTransaction,
    index: usize,
    recipient: &P2trWallet,
    asset: AssetId,
    amount: u64,
    blinder_input_index: usize,
) -> Result<(), String> {
    let output = pset
        .outputs()
        .get(index)
        .ok_or_else(|| format!("missing output {index}"))?;
    if output.script_pubkey != recipient.address.script_pubkey() {
        return Err(format!("wrong script at output {index}"));
    }
    if output.blinding_key != recipient.address.blinding_pubkey.map(BitcoinPublicKey::new) {
        return Err(format!("wrong receiver blinding key at output {index}"));
    }
    if output.blinder_index
        != Some(
            u32::try_from(blinder_input_index)
                .map_err(|_| format!("invalid blinder input index for output {index}"))?,
        )
    {
        return Err(format!("wrong blinding role at output {index}"));
    }
    if output.asset != Some(asset) {
        return Err(format!("wrong asset at output {index}"));
    }
    if output.amount != Some(amount) {
        return Err(format!("wrong amount at output {index}"));
    }
    if output.redeem_script.is_some()
        || output.witness_script.is_some()
        || !output.bip32_derivation.is_empty()
        || output.tap_internal_key.is_some()
        || output.tap_tree.is_some()
        || !output.tap_key_origins.is_empty()
        || !output.proprietary.is_empty()
        || !output.unknown.is_empty()
    {
        return Err(format!("unexpected wallet metadata at output {index}"));
    }
    Ok(())
}

fn validate_settlement_intent(fixture: &SettlementFixture) -> Result<(), String> {
    let pset = &fixture.pset;
    let layout = fixture.layout;
    let route_summary = fixture.route_authorization.summary();
    fixture
        .manifest
        .validate(pset)
        .map_err(|error| error.to_string())?;
    if route_summary.execution().input()
        != AssetAmount::new(fixture.assets.payment, PROVIDER_PAYMENT_VALUE)
            .map_err(|error| error.to_string())?
        || route_summary.execution().output()
            != AssetAmount::new(fixture.assets.outcome, USER_RECEIVE_VALUE)
                .map_err(|error| error.to_string())?
        || !route_summary.venue_fees().is_empty()
        || route_summary.network_fee().policy_asset() != fixture.assets.policy
        || route_summary.network_fee().amount() != NETWORK_FEE
    {
        return Err("normalized route summary no longer matches settlement intent".into());
    }
    if pset.inputs().len() != 3 || pset.outputs().len() != 6 {
        return Err("unexpected input or output count".into());
    }
    if pset.global.version != 2 || pset.global.tx_data.version != 2 {
        return Err("unexpected PSET or transaction version".into());
    }
    if !pset.global.xpub.is_empty()
        || !pset.global.proprietary.is_empty()
        || !pset.global.unknown.is_empty()
    {
        return Err("unexpected global wallet metadata".into());
    }
    let expected_inputs = [
        (layout.fee_input, &fixture.fee_input, &fixture.user),
        (layout.payment_input, &fixture.payment_input, &fixture.user),
        (
            layout.inventory_input,
            &fixture.inventory_input,
            &fixture.provider,
        ),
    ];
    for (index, expected, owner) in expected_inputs {
        let input = pset
            .inputs()
            .get(index)
            .ok_or_else(|| format!("missing input {index}"))?;
        if input_outpoint(input) != expected.outpoint {
            return Err(format!("wrong outpoint at input {index}"));
        }
        if !input
            .witness_utxo
            .as_ref()
            .is_some_and(|actual| same_prevout_body(actual, &expected.txout))
            || input.in_utxo_rangeproof != expected.txout.witness.rangeproof
        {
            return Err(format!("wrong witness UTXO at input {index}"));
        }
        if input.sighash_type != Some(SchnorrSighashType::All.into())
            || input.tap_internal_key != Some(owner.internal_key)
            || input.tap_merkle_root.is_some()
            || !input.tap_script_sigs.is_empty()
            || !input.tap_scripts.is_empty()
            || !input.tap_key_origins.is_empty()
            || input.non_witness_utxo.is_some()
            || !input.partial_sigs.is_empty()
            || !input.bip32_derivation.is_empty()
            || !input.ripemd160_preimages.is_empty()
            || !input.sha256_preimages.is_empty()
            || !input.hash160_preimages.is_empty()
            || !input.hash256_preimages.is_empty()
            || input.final_script_sig.is_some()
            || input.redeem_script.is_some()
            || input.witness_script.is_some()
            || !input.proprietary.is_empty()
            || !input.unknown.is_empty()
        {
            return Err(format!("wrong Taproot signing policy at input {index}"));
        }
        if input
            .sequence
            .is_some_and(|sequence| sequence != Sequence::MAX)
            || input.required_time_locktime.is_some()
            || input.required_height_locktime.is_some()
        {
            return Err(format!(
                "unexpected sequence or input locktime at input {index}"
            ));
        }
        if input.issuance_value_amount.is_some()
            || input.issuance_value_comm.is_some()
            || input.issuance_inflation_keys.is_some()
            || input.issuance_inflation_keys_comm.is_some()
            || input.issuance_value_rangeproof.is_some()
            || input.issuance_keys_rangeproof.is_some()
            || input.issuance_blinding_nonce.is_some()
            || input.issuance_asset_entropy.is_some()
            || input.in_issuance_blind_value_proof.is_some()
            || input.in_issuance_blind_inflation_keys_proof.is_some()
            || input.blinded_issuance.is_some()
            || input.pegin_tx.is_some()
            || input.pegin_txout_proof.is_some()
            || input.pegin_genesis_hash.is_some()
            || input.pegin_claim_script.is_some()
            || input.pegin_value.is_some()
            || input.pegin_witness.is_some()
        {
            return Err(format!("issuance or pegin at wallet input {index}"));
        }
    }
    let unique = pset
        .inputs()
        .iter()
        .map(input_outpoint)
        .collect::<HashSet<_>>();
    if unique.len() != pset.inputs().len() {
        return Err("duplicate input dependency".into());
    }
    if pset
        .global
        .tx_data
        .fallback_locktime
        .is_some_and(|lock| lock != LockTime::ZERO)
    {
        return Err("unexpected locktime".into());
    }
    if pset.global.tx_data.tx_modifiable.unwrap_or(0) != 0
        || pset.global.elements_tx_modifiable_flag.unwrap_or(0) != 0
    {
        return Err("transaction remains modifiable".into());
    }

    expect_output(
        pset,
        layout.fee_change,
        &fixture.user,
        fixture.assets.policy,
        USER_FEE_INPUT_VALUE - NETWORK_FEE,
        layout.fee_input,
    )?;
    expect_output(
        pset,
        layout.provider_payment,
        &fixture.provider,
        fixture.assets.payment,
        PROVIDER_PAYMENT_VALUE,
        layout.payment_input,
    )?;
    expect_output(
        pset,
        layout.provider_inventory_change,
        &fixture.provider,
        fixture.assets.outcome,
        PROVIDER_INVENTORY_VALUE - USER_RECEIVE_VALUE,
        layout.inventory_input,
    )?;
    expect_output(
        pset,
        layout.user_payment_change,
        &fixture.user,
        fixture.assets.payment,
        USER_PAYMENT_INPUT_VALUE - PROVIDER_PAYMENT_VALUE,
        layout.payment_input,
    )?;
    expect_output(
        pset,
        layout.user_receive,
        &fixture.user,
        fixture.assets.outcome,
        USER_RECEIVE_VALUE,
        layout.inventory_input,
    )?;
    let fee = &pset.outputs()[layout.fee];
    if fee.script_pubkey != Script::new()
        || fee.asset != Some(fixture.assets.policy)
        || fee.amount != Some(NETWORK_FEE)
        || fee.asset_comm.is_some()
        || fee.amount_comm.is_some()
        || fee.blinding_key.is_some()
        || fee.ecdh_pubkey.is_some()
        || fee.blinder_index.is_some()
        || fee.value_rangeproof.is_some()
        || fee.asset_surjection_proof.is_some()
        || fee.redeem_script.is_some()
        || fee.witness_script.is_some()
        || !fee.bip32_derivation.is_empty()
        || fee.tap_internal_key.is_some()
        || fee.tap_tree.is_some()
        || !fee.tap_key_origins.is_empty()
        || !fee.proprietary.is_empty()
        || !fee.unknown.is_empty()
    {
        return Err("fee output is not exact and explicit".into());
    }
    Ok(())
}

fn validate_output_disclosure(output: &PsetOutput, index: usize) -> Result<(), String> {
    let secp = Secp256k1::new();
    let asset = output
        .asset
        .ok_or_else(|| format!("output {index} lacks disclosed asset"))?;
    let amount = output
        .amount
        .ok_or_else(|| format!("output {index} lacks disclosed amount"))?;
    let asset_commitment = output
        .asset_comm
        .ok_or_else(|| format!("output {index} lacks asset commitment"))?;
    let value_commitment = output
        .amount_comm
        .ok_or_else(|| format!("output {index} lacks value commitment"))?;
    let asset_proof = output
        .blind_asset_proof
        .as_deref()
        .ok_or_else(|| format!("output {index} lacks blind asset proof"))?;
    let value_proof = output
        .blind_value_proof
        .as_deref()
        .ok_or_else(|| format!("output {index} lacks blind value proof"))?;
    if !asset_proof.blind_asset_proof_verify(&secp, asset, asset_commitment) {
        return Err(format!(
            "output {index} asset disclosure does not match commitment"
        ));
    }
    if !value_proof.blind_value_proof_verify(&secp, amount, asset_commitment, value_commitment) {
        return Err(format!(
            "output {index} value disclosure does not match commitment"
        ));
    }
    Ok(())
}

fn validate_blinded_outputs(pset: &PartiallySignedTransaction) -> Result<(), String> {
    for (index, output) in pset.outputs().iter().enumerate() {
        if output.blinding_key.is_none() {
            continue;
        }
        validate_output_disclosure(output, index)?;
    }
    Ok(())
}

fn validate_consensus_proofs(
    pset: &PartiallySignedTransaction,
    prevouts: &[TxOut],
) -> Result<(), String> {
    pset.extract_tx()
        .map_err(|error| error.to_string())?
        .verify_tx_amt_proofs(&Secp256k1::new(), prevouts)
        .map_err(|error| error.to_string())
}

fn assert_opening(opening: TxOutSecrets, asset: AssetId, value: u64) {
    assert_eq!(opening.asset, asset);
    assert_eq!(opening.value, value);
}

fn validate_recipient_opening(
    transaction: &Transaction,
    wallet: &P2trWallet,
    output_index: usize,
    asset: AssetId,
    value: u64,
) -> Result<(), String> {
    let opening = wallet
        .try_unblind(
            transaction
                .output
                .get(output_index)
                .ok_or_else(|| format!("missing recipient output {output_index}"))?,
        )
        .map_err(|error| format!("cannot unblind recipient output {output_index}: {error}"))?;
    if opening.asset != asset || opening.value != value {
        return Err(format!("wrong opening at recipient output {output_index}"));
    }
    Ok(())
}

fn validate_user_recipient_outputs(fixture: &SettlementFixture) -> Result<(), String> {
    let transaction = fixture
        .pset
        .extract_tx()
        .map_err(|error| error.to_string())?;
    for (index, asset, value) in [
        (
            fixture.layout.fee_change,
            fixture.assets.policy,
            USER_FEE_INPUT_VALUE - NETWORK_FEE,
        ),
        (
            fixture.layout.user_payment_change,
            fixture.assets.payment,
            USER_PAYMENT_INPUT_VALUE - PROVIDER_PAYMENT_VALUE,
        ),
        (
            fixture.layout.user_receive,
            fixture.assets.outcome,
            USER_RECEIVE_VALUE,
        ),
    ] {
        validate_recipient_opening(&transaction, &fixture.user, index, asset, value)?;
    }
    Ok(())
}

fn validate_provider_recipient_outputs(fixture: &SettlementFixture) -> Result<(), String> {
    let transaction = fixture
        .pset
        .extract_tx()
        .map_err(|error| error.to_string())?;
    for (index, asset, value) in [
        (
            fixture.layout.provider_payment,
            fixture.assets.payment,
            PROVIDER_PAYMENT_VALUE,
        ),
        (
            fixture.layout.provider_inventory_change,
            fixture.assets.outcome,
            PROVIDER_INVENTORY_VALUE - USER_RECEIVE_VALUE,
        ),
    ] {
        validate_recipient_opening(&transaction, &fixture.provider, index, asset, value)?;
    }
    Ok(())
}

fn pset_sighash(
    pset: &PartiallySignedTransaction,
    input_index: usize,
    genesis_hash: BlockHash,
) -> [u8; 32] {
    let transaction = pset.extract_tx().expect("extract transaction for sighash");
    let prevouts = pset
        .inputs()
        .iter()
        .map(|input| input.witness_utxo.clone().expect("all prevouts disclosed"))
        .collect::<Vec<_>>();
    transaction_sighash(&transaction, &prevouts, input_index, genesis_hash)
}

fn transaction_sighash(
    transaction: &Transaction,
    prevouts: &[TxOut],
    input_index: usize,
    genesis_hash: BlockHash,
) -> [u8; 32] {
    SighashCache::new(transaction)
        .taproot_key_spend_signature_hash(
            input_index,
            &Prevouts::All(prevouts),
            SchnorrSighashType::All,
            genesis_hash,
        )
        .expect("Taproot key-spend sighash")
        .to_byte_array()
}

fn validate_wallet_signature(
    pset: &PartiallySignedTransaction,
    prevouts: &[TxOut],
    wallet: &P2trWallet,
    input_index: usize,
    genesis_hash: BlockHash,
) -> Result<(), String> {
    let input = pset
        .inputs()
        .get(input_index)
        .ok_or_else(|| format!("missing signed input {input_index}"))?;
    let signature = input
        .tap_key_sig
        .ok_or_else(|| format!("missing Taproot signature at input {input_index}"))?;
    if signature.hash_ty != SchnorrSighashType::All
        || input.final_script_witness.as_ref() != Some(&vec![signature.to_vec()])
    {
        return Err(format!(
            "wrong final key-path witness at input {input_index}"
        ));
    }
    let transaction = pset.extract_tx().map_err(|error| error.to_string())?;
    if !wallet.verifies(&transaction, prevouts, input_index, signature, genesis_hash) {
        return Err(format!("invalid Taproot signature at input {input_index}"));
    }
    Ok(())
}

fn offline_fixture() -> SettlementFixture {
    let user = P2trWallet::deterministic(0x41, 0x42);
    let provider = P2trWallet::deterministic(0x51, 0x52);
    let policy_asset = AssetId::from_byte_array([0x11; 32]);
    let payment_asset = AssetId::from_byte_array([0x33; 32]);
    let outcome_asset = AssetId::from_byte_array([0x22; 32]);
    let fee_input = fake_confidential_utxo(&user, 0x61, policy_asset, USER_FEE_INPUT_VALUE);
    let payment_input =
        fake_confidential_utxo(&user, 0x62, payment_asset, USER_PAYMENT_INPUT_VALUE);
    let inventory_input =
        fake_confidential_utxo(&provider, 0x63, outcome_asset, PROVIDER_INVENTORY_VALUE);
    build_settlement(
        user,
        provider,
        fee_input,
        payment_input,
        inventory_input,
        SettlementAssets {
            policy: policy_asset,
            payment: payment_asset,
            outcome: outcome_asset,
        },
        BlockHash::from_byte_array([0x71; 32]),
    )
}

fn assert_mutation_breaks_signature(
    wallet: &P2trWallet,
    original: &Transaction,
    mutated: &Transaction,
    prevouts: &[TxOut],
    input_index: usize,
    signature: SchnorrSig,
    genesis_hash: BlockHash,
) {
    let original_hash = transaction_sighash(original, prevouts, input_index, genesis_hash);
    let mutated_hash = transaction_sighash(mutated, prevouts, input_index, genesis_hash);
    assert_ne!(
        original_hash, mutated_hash,
        "mutation must alter the sighash"
    );
    assert!(!wallet.verifies(mutated, prevouts, input_index, signature, genesis_hash,));
}

#[test]
fn collaborative_blinding_and_p2tr_signing_bind_the_complete_settlement() {
    let mut fixture = offline_fixture();
    validate_settlement_intent(&fixture).expect("unblinded intent is exact");
    blind_settlement(&mut fixture);
    validate_settlement_intent(&fixture).expect("blinded intent metadata is exact");
    validate_blinded_outputs(&fixture.pset).expect("disclosures match commitments");
    validate_consensus_proofs(&fixture.pset, &fixture.prevouts)
        .expect("rangeproofs, surjection proofs, and balance verify");
    validate_user_recipient_outputs(&fixture).expect("user can recover every owned output");
    validate_provider_recipient_outputs(&fixture).expect("provider can recover every owned output");

    let unsigned = fixture.pset.extract_tx().expect("blinded transaction");
    assert!(
        unsigned.output[fixture.layout.user_receive]
            .unblind(&Secp256k1::new(), fixture.provider.blinding_secret)
            .is_err(),
        "the other participant cannot rewind the receive output"
    );

    let genesis_hash = BlockHash::from_byte_array([0x71; 32]);
    let user_fee_sig =
        fixture
            .user
            .sign_input(&mut fixture.pset, fixture.layout.fee_input, genesis_hash);
    let user_payment_sig = fixture.user.sign_input(
        &mut fixture.pset,
        fixture.layout.payment_input,
        genesis_hash,
    );
    fixture.pset =
        deserialize(&serialize(&fixture.pset)).expect("user-signed PSET return handoff round trip");
    validate_wallet_signature(
        &fixture.pset,
        &fixture.prevouts,
        &fixture.user,
        fixture.layout.fee_input,
        genesis_hash,
    )
    .expect("provider verifies user fee signature");
    validate_wallet_signature(
        &fixture.pset,
        &fixture.prevouts,
        &fixture.user,
        fixture.layout.payment_input,
        genesis_hash,
    )
    .expect("provider verifies user payment signature");
    for signature in [user_fee_sig, user_payment_sig] {
        let bytes = signature.to_vec();
        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes.last(), Some(&(SchnorrSighashType::All as u8)));
    }
    let before_provider_signature = fixture.pset.extract_tx().expect("user-signed transaction");
    assert!(fixture.user.verifies(
        &before_provider_signature,
        &fixture.prevouts,
        fixture.layout.payment_input,
        user_payment_sig,
        genesis_hash,
    ));
    assert!(fixture.user.verifies(
        &before_provider_signature,
        &fixture.prevouts,
        fixture.layout.fee_input,
        user_fee_sig,
        genesis_hash,
    ));

    // The provider independently revalidates the frozen whole transaction
    // after the user's signatures arrive, then signs last.
    validate_settlement_intent(&fixture).expect("provider sees the exact frozen intent");
    validate_blinded_outputs(&fixture.pset).expect("provider sees valid disclosure proofs");
    validate_consensus_proofs(&fixture.pset, &fixture.prevouts)
        .expect("provider sees a balanced confidential transaction");
    validate_provider_recipient_outputs(&fixture)
        .expect("provider can recover payment and inventory change");
    let provider_signature = fixture.provider.sign_input(
        &mut fixture.pset,
        fixture.layout.inventory_input,
        genesis_hash,
    );
    validate_wallet_signature(
        &fixture.pset,
        &fixture.prevouts,
        &fixture.provider,
        fixture.layout.inventory_input,
        genesis_hash,
    )
    .expect("provider signature finalizes its inventory input");
    let signed = fixture.pset.extract_tx().expect("fully signed transaction");
    assert!(fixture.user.verifies(
        &signed,
        &fixture.prevouts,
        fixture.layout.payment_input,
        user_payment_sig,
        genesis_hash,
    ));
    assert!(fixture.provider.verifies(
        &signed,
        &fixture.prevouts,
        fixture.layout.inventory_input,
        provider_signature,
        genesis_hash,
    ));
    assert_eq!(
        transaction_sighash(
            &before_provider_signature,
            &fixture.prevouts,
            fixture.layout.payment_input,
            genesis_hash,
        ),
        transaction_sighash(
            &signed,
            &fixture.prevouts,
            fixture.layout.payment_input,
            genesis_hash,
        ),
        "another input's spending witness is intentionally outside Taproot ALL"
    );

    let mut no_rangeproof = signed.clone();
    no_rangeproof.output[fixture.layout.user_receive]
        .witness
        .rangeproof = None;
    assert_mutation_breaks_signature(
        &fixture.user,
        &signed,
        &no_rangeproof,
        &fixture.prevouts,
        fixture.layout.payment_input,
        user_payment_sig,
        genesis_hash,
    );

    let mut no_surjection_proof = signed.clone();
    no_surjection_proof.output[fixture.layout.user_receive]
        .witness
        .surjection_proof = None;
    assert_mutation_breaks_signature(
        &fixture.user,
        &signed,
        &no_surjection_proof,
        &fixture.prevouts,
        fixture.layout.payment_input,
        user_payment_sig,
        genesis_hash,
    );

    let mut wrong_script = signed.clone();
    wrong_script.output[fixture.layout.provider_payment].script_pubkey = Script::from(vec![0x51]);
    assert_mutation_breaks_signature(
        &fixture.user,
        &signed,
        &wrong_script,
        &fixture.prevouts,
        fixture.layout.payment_input,
        user_payment_sig,
        genesis_hash,
    );

    let mut wrong_nonce = signed.clone();
    wrong_nonce.output[fixture.layout.user_receive].nonce = Nonce::Null;
    assert_mutation_breaks_signature(
        &fixture.user,
        &signed,
        &wrong_nonce,
        &fixture.prevouts,
        fixture.layout.payment_input,
        user_payment_sig,
        genesis_hash,
    );

    let mut wrong_commitment = signed.clone();
    wrong_commitment.output[fixture.layout.user_receive].value =
        signed.output[fixture.layout.provider_inventory_change].value;
    assert_mutation_breaks_signature(
        &fixture.user,
        &signed,
        &wrong_commitment,
        &fixture.prevouts,
        fixture.layout.payment_input,
        user_payment_sig,
        genesis_hash,
    );

    let mut reordered_outputs = signed.clone();
    reordered_outputs
        .output
        .swap(fixture.layout.provider_payment, fixture.layout.user_receive);
    assert_mutation_breaks_signature(
        &fixture.user,
        &signed,
        &reordered_outputs,
        &fixture.prevouts,
        fixture.layout.payment_input,
        user_payment_sig,
        genesis_hash,
    );

    let mut wrong_fee = signed.clone();
    wrong_fee.output[fixture.layout.fee].value = Value::Explicit(NETWORK_FEE + 1);
    assert_mutation_breaks_signature(
        &fixture.user,
        &signed,
        &wrong_fee,
        &fixture.prevouts,
        fixture.layout.payment_input,
        user_payment_sig,
        genesis_hash,
    );

    let mut extra_output = signed.clone();
    extra_output
        .output
        .push(TxOut::new_fee(1, fixture.assets.policy));
    assert_mutation_breaks_signature(
        &fixture.user,
        &signed,
        &extra_output,
        &fixture.prevouts,
        fixture.layout.payment_input,
        user_payment_sig,
        genesis_hash,
    );

    let mut different_outpoint = signed.clone();
    different_outpoint.input[fixture.layout.inventory_input]
        .previous_output
        .vout += 1;
    assert_mutation_breaks_signature(
        &fixture.user,
        &signed,
        &different_outpoint,
        &fixture.prevouts,
        fixture.layout.payment_input,
        user_payment_sig,
        genesis_hash,
    );

    let mut different_sequence = signed.clone();
    different_sequence.input[fixture.layout.inventory_input].sequence = Sequence::ZERO;
    assert_mutation_breaks_signature(
        &fixture.user,
        &signed,
        &different_sequence,
        &fixture.prevouts,
        fixture.layout.payment_input,
        user_payment_sig,
        genesis_hash,
    );

    let mut different_locktime = signed.clone();
    different_locktime.lock_time = LockTime::from_consensus(1);
    assert_mutation_breaks_signature(
        &fixture.user,
        &signed,
        &different_locktime,
        &fixture.prevouts,
        fixture.layout.payment_input,
        user_payment_sig,
        genesis_hash,
    );

    let wrong_genesis = BlockHash::from_byte_array([0x72; 32]);
    assert!(!fixture.user.verifies(
        &signed,
        &fixture.prevouts,
        fixture.layout.payment_input,
        user_payment_sig,
        wrong_genesis,
    ));
}

#[test]
fn settlement_intent_and_disclosure_validation_fail_closed() {
    let fixture = offline_fixture();
    validate_settlement_intent(&fixture).expect("baseline intent");

    let round_trip: PartiallySignedTransaction =
        deserialize(&serialize(&fixture.pset)).expect("PSET round trip");
    assert_eq!(
        round_trip.inputs()[fixture.layout.payment_input].in_utxo_rangeproof,
        fixture.payment_input.txout.witness.rangeproof,
        "a confidential input rangeproof must survive a PSET handoff"
    );
    fixture
        .manifest
        .validate(&round_trip)
        .expect("round-tripped input proof remains authorized");

    let mut mutated = fixture.clone();
    mutated.pset.global.tx_data.version = 3;
    assert!(validate_settlement_intent(&mutated).is_err());

    mutated = fixture.clone();
    mutated.pset.inputs_mut()[mutated.layout.payment_input].final_script_sig = Some(Script::new());
    assert!(validate_settlement_intent(&mutated).is_err());

    mutated = fixture.clone();
    mutated.pset.outputs_mut()[fixture.layout.user_receive].asset = Some(fixture.assets.policy);
    assert!(validate_settlement_intent(&mutated).is_err());

    mutated = fixture.clone();
    mutated.pset.outputs_mut()[mutated.layout.user_receive].amount = Some(USER_RECEIVE_VALUE + 1);
    assert!(validate_settlement_intent(&mutated).is_err());

    mutated = fixture.clone();
    mutated.pset.outputs_mut()[mutated.layout.provider_payment].script_pubkey = Script::new();
    assert!(validate_settlement_intent(&mutated).is_err());

    mutated = fixture.clone();
    mutated.pset.outputs_mut()[mutated.layout.user_receive].blinding_key = mutated
        .provider
        .address
        .blinding_pubkey
        .map(BitcoinPublicKey::new);
    assert!(validate_settlement_intent(&mutated).is_err());

    mutated = fixture.clone();
    mutated.pset.outputs_mut()[mutated.layout.user_receive].blinder_index =
        Some(u32::try_from(mutated.layout.payment_input).expect("input index"));
    assert!(validate_settlement_intent(&mutated).is_err());

    mutated = fixture.clone();
    mutated.pset.outputs_mut()[mutated.layout.fee].amount = Some(NETWORK_FEE + 1);
    assert!(validate_settlement_intent(&mutated).is_err());

    mutated = fixture.clone();
    mutated.pset.outputs_mut()[mutated.layout.fee].asset = Some(mutated.assets.payment);
    assert!(validate_settlement_intent(&mutated).is_err());

    mutated = fixture.clone();
    mutated.pset.inputs_mut()[mutated.layout.payment_input].witness_utxo =
        Some(mutated.inventory_input.txout.clone());
    assert!(validate_settlement_intent(&mutated).is_err());

    mutated = fixture.clone();
    mutated.pset.inputs_mut()[mutated.layout.payment_input].in_utxo_rangeproof = None;
    assert!(validate_settlement_intent(&mutated).is_err());

    mutated = fixture.clone();
    mutated.pset.inputs_mut()[mutated.layout.payment_input].sighash_type = None;
    assert!(validate_settlement_intent(&mutated).is_err());

    mutated = fixture.clone();
    let duplicate = input_outpoint(&mutated.pset.inputs()[mutated.layout.payment_input]);
    mutated.pset.inputs_mut()[mutated.layout.inventory_input].previous_txid = duplicate.txid;
    mutated.pset.inputs_mut()[mutated.layout.inventory_input].previous_output_index =
        duplicate.vout;
    assert!(validate_settlement_intent(&mutated).is_err());

    mutated = fixture;
    mutated
        .pset
        .add_output(PsetOutput::from_txout(TxOut::new_fee(
            1,
            mutated.assets.policy,
        )));
    assert!(validate_settlement_intent(&mutated).is_err());

    let mut blinded = offline_fixture();
    blind_settlement(&mut blinded);
    validate_blinded_outputs(&blinded.pset).expect("baseline disclosure proofs");
    let mut wrong_nonce = blinded.clone();
    wrong_nonce.pset.outputs_mut()[wrong_nonce.layout.provider_payment].ecdh_pubkey = wrong_nonce
        .user
        .address
        .blinding_pubkey
        .map(BitcoinPublicKey::new);
    validate_settlement_intent(&wrong_nonce)
        .expect("non-consensus blinding metadata still looks correct");
    validate_blinded_outputs(&wrong_nonce.pset)
        .expect("public disclosure proofs do not authenticate the ECDH nonce");
    validate_consensus_proofs(&wrong_nonce.pset, &wrong_nonce.prevouts)
        .expect("consensus proofs do not require a rewindable nonce");
    assert!(validate_provider_recipient_outputs(&wrong_nonce).is_err());

    blinded.pset.outputs_mut()[blinded.layout.provider_payment].amount =
        Some(PROVIDER_PAYMENT_VALUE + 1);
    assert!(validate_blinded_outputs(&blinded.pset).is_err());
}

#[derive(Debug, Deserialize)]
struct MempoolAcceptance {
    allowed: Option<bool>,
    #[serde(rename = "reject-reason")]
    reject_reason: Option<String>,
}

fn test_mempool_accept(rpc: &Client, transaction: &Transaction) -> MempoolAcceptance {
    let response: Vec<MempoolAcceptance> = rpc
        .call(
            "testmempoolaccept",
            &[
                json!([elements::encode::serialize_hex(transaction)]),
                json!(0),
            ],
        )
        .expect("testmempoolaccept RPC");
    response.into_iter().next().expect("one acceptance result")
}

fn assert_unspent(rpc: &Client, outpoint: OutPoint) {
    let utxo: Option<JsonValue> = rpc
        .call(
            "gettxout",
            &[
                json!(outpoint.txid.to_string()),
                json!(outpoint.vout),
                json!(true),
            ],
        )
        .expect("gettxout RPC");
    assert!(utxo.is_some(), "{outpoint} must remain unspent");
}

fn accept_broadcast_mine(rpc: &Client, miner: &ElementsRpc, transaction: &Transaction) {
    let acceptance = test_mempool_accept(rpc, transaction);
    assert_eq!(
        acceptance.allowed,
        Some(true),
        "elementsd rejected transaction: {:?}",
        acceptance.reject_reason
    );
    let txid: String = rpc
        .call(
            "sendrawtransaction",
            &[
                json!(elements::encode::serialize_hex(transaction)),
                json!(0),
            ],
        )
        .expect("sendrawtransaction RPC");
    assert_eq!(txid, transaction.txid().to_string());
    miner.generate_blocks(1).expect("mine accepted transaction");
}

fn raw_transaction(rpc: &Client, txid: Txid) -> Transaction {
    let raw: String = rpc
        .call(
            "getrawtransaction",
            &[json!(txid.to_string()), json!(false)],
        )
        .expect("getrawtransaction RPC");
    deserialize(&Vec::<u8>::from_hex(&raw).expect("raw transaction hex"))
        .expect("Elements transaction")
}

fn wallet_output(rpc: &Client, txid: Txid, wallet: &P2trWallet) -> OwnedUtxo {
    let transaction = raw_transaction(rpc, txid);
    let (index, txout) = transaction
        .output
        .iter()
        .enumerate()
        .find(|(_, output)| output.script_pubkey == wallet.address.script_pubkey())
        .expect("wallet output in funding transaction");
    OwnedUtxo {
        outpoint: OutPoint::new(txid, u32::try_from(index).expect("output index fits")),
        secrets: wallet.unblind(txout),
        txout: txout.clone(),
    }
}

fn issue_fixture_asset(rpc: &Client, miner: &ElementsRpc) -> AssetId {
    // Opaque issued assets stand in for market collateral/payment and
    // pre-issued YES inventory. Market issuance itself remains covered by
    // `market_regtest.rs`; this test keeps both distinct from the policy fee.
    let issued: JsonValue = rpc
        .call("issueasset", &[json!(1.0), json!(0), json!(false)])
        .expect("issue RFQ outcome fixture asset");
    let asset = AssetId::from_str(
        issued["asset"]
            .as_str()
            .expect("issueasset returns asset id"),
    )
    .expect("issued asset id");
    miner.generate_blocks(1).expect("mine fixture issuance");
    asset
}

fn build_wallet_sweep(
    wallet: &P2trWallet,
    inputs: &[OwnedUtxo],
    policy_asset: AssetId,
    genesis_hash: BlockHash,
) -> Transaction {
    let mut totals = HashMap::<AssetId, u64>::new();
    let mut first_input_by_asset = HashMap::<AssetId, usize>::new();
    let mut pset = PartiallySignedTransaction::new_v2();
    for (index, input) in inputs.iter().enumerate() {
        *totals.entry(input.secrets.asset).or_default() += input.secrets.value;
        first_input_by_asset
            .entry(input.secrets.asset)
            .or_insert(index);
        pset.add_input(wallet.input(input));
    }
    *totals
        .get_mut(&policy_asset)
        .expect("sweep includes policy asset for fee") -= NETWORK_FEE;
    for (asset, value) in totals {
        pset.add_output(wallet.confidential_output(value, asset, first_input_by_asset[&asset]));
    }
    add_fee_output(&mut pset, NETWORK_FEE, policy_asset);
    let input_secrets = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| (index, input.secrets))
        .collect::<HashMap<_, _>>();
    pset.blind_last(&mut thread_rng(), &Secp256k1::new(), &input_secrets)
        .expect("one-wallet sweep blinding");
    validate_blinded_outputs(&pset).expect("sweep disclosure proofs");
    let prevouts = inputs
        .iter()
        .map(|input| input.txout.clone())
        .collect::<Vec<_>>();
    validate_consensus_proofs(&pset, &prevouts).expect("sweep consensus proofs");
    for index in 0..inputs.len() {
        wallet.sign_input(&mut pset, index, genesis_hash);
    }
    pset.extract_tx().expect("signed wallet sweep")
}

#[test]
#[ignore = "starts elementsd and liquid-enabled Electrs from the Nix development shell"]
fn two_wallet_confidential_p2tr_rfq_settlement_is_accepted_and_spendable() {
    let (client, _) = Regtest::from_config(&RegtestConfig::default()).expect("regtest environment");
    let miner = ElementsRpc::new(client.rpc_url(), client.auth()).expect("Elements RPC");
    let rpc = Client::new(&client.rpc_url(), client.auth()).expect("raw Elements RPC");
    let policy_asset = SimplicityNetwork::default_regtest().policy_asset();
    let genesis_hash = BlockHash::from_str(
        &rpc.get_block_hash(0)
            .expect("regtest genesis block")
            .to_string(),
    )
    .expect("Elements genesis hash");
    let payment_asset = issue_fixture_asset(&rpc, &miner);
    let outcome_asset = issue_fixture_asset(&rpc, &miner);
    let user = P2trWallet::deterministic(0x41, 0x42);
    let provider = P2trWallet::deterministic(0x51, 0x52);

    let fee_txid = miner
        .send_to_address(&user.address, USER_FEE_INPUT_VALUE, None)
        .expect("fund user fee input");
    let payment_txid = miner
        .send_to_address(&user.address, USER_PAYMENT_INPUT_VALUE, Some(payment_asset))
        .expect("fund user payment input");
    let inventory_txid = miner
        .send_to_address(
            &provider.address,
            PROVIDER_INVENTORY_VALUE,
            Some(outcome_asset),
        )
        .expect("fund provider outcome inventory");
    let provider_fee_txid = miner
        .send_to_address(&provider.address, USER_FEE_INPUT_VALUE, None)
        .expect("fund provider child-spend fee input");
    miner.generate_blocks(1).expect("mine P2TR funding");

    let fee_input = wallet_output(&rpc, fee_txid, &user);
    let payment_input = wallet_output(&rpc, payment_txid, &user);
    let inventory_input = wallet_output(&rpc, inventory_txid, &provider);
    let provider_fee_input = wallet_output(&rpc, provider_fee_txid, &provider);
    assert_opening(fee_input.secrets, policy_asset, USER_FEE_INPUT_VALUE);
    assert_opening(
        payment_input.secrets,
        payment_asset,
        USER_PAYMENT_INPUT_VALUE,
    );
    assert_opening(
        inventory_input.secrets,
        outcome_asset,
        PROVIDER_INVENTORY_VALUE,
    );
    assert_opening(
        provider_fee_input.secrets,
        policy_asset,
        USER_FEE_INPUT_VALUE,
    );

    let mut fixture = build_settlement(
        user,
        provider,
        fee_input,
        payment_input,
        inventory_input,
        SettlementAssets {
            policy: policy_asset,
            payment: payment_asset,
            outcome: outcome_asset,
        },
        genesis_hash,
    );
    validate_settlement_intent(&fixture).expect("exact RFQ intent before blinding");
    blind_settlement(&mut fixture);
    validate_settlement_intent(&fixture).expect("exact RFQ intent after blinding");
    validate_blinded_outputs(&fixture.pset).expect("public commitment disclosures");
    validate_consensus_proofs(&fixture.pset, &fixture.prevouts)
        .expect("complete confidential transaction proofs");
    validate_user_recipient_outputs(&fixture)
        .expect("user can recover receive and change before signing");

    fixture
        .user
        .sign_input(&mut fixture.pset, fixture.layout.fee_input, genesis_hash);
    fixture.user.sign_input(
        &mut fixture.pset,
        fixture.layout.payment_input,
        genesis_hash,
    );
    fixture.pset =
        deserialize(&serialize(&fixture.pset)).expect("user-signed PSET return handoff round trip");
    for input_index in [fixture.layout.fee_input, fixture.layout.payment_input] {
        validate_wallet_signature(
            &fixture.pset,
            &fixture.prevouts,
            &fixture.user,
            input_index,
            genesis_hash,
        )
        .expect("provider verifies a user signature before signing");
    }
    let user_signed = fixture.pset.extract_tx().expect("user-signed RFQ");
    assert_eq!(test_mempool_accept(&rpc, &user_signed).allowed, Some(false));
    for input in [
        fixture.fee_input.outpoint,
        fixture.payment_input.outpoint,
        fixture.inventory_input.outpoint,
    ] {
        assert_unspent(&rpc, input);
    }
    validate_settlement_intent(&fixture).expect("provider revalidates exact intent");
    validate_blinded_outputs(&fixture.pset).expect("provider revalidates disclosures");
    validate_consensus_proofs(&fixture.pset, &fixture.prevouts)
        .expect("provider revalidates complete CT proofs");
    validate_provider_recipient_outputs(&fixture)
        .expect("provider can recover payment and change before signing");
    fixture.provider.sign_input(
        &mut fixture.pset,
        fixture.layout.inventory_input,
        genesis_hash,
    );
    validate_wallet_signature(
        &fixture.pset,
        &fixture.prevouts,
        &fixture.provider,
        fixture.layout.inventory_input,
        genesis_hash,
    )
    .expect("provider final signature verifies before relay");
    let settlement = fixture.pset.extract_tx().expect("fully signed RFQ");
    accept_broadcast_mine(&rpc, &miner, &settlement);
    assert_eq!(raw_transaction(&rpc, settlement.txid()), settlement);

    let user_receive = OwnedUtxo {
        outpoint: OutPoint::new(
            settlement.txid(),
            u32::try_from(fixture.layout.user_receive).expect("output index"),
        ),
        secrets: fixture
            .user
            .unblind(&settlement.output[fixture.layout.user_receive]),
        txout: settlement.output[fixture.layout.user_receive].clone(),
    };
    let user_change = OwnedUtxo {
        outpoint: OutPoint::new(
            settlement.txid(),
            u32::try_from(fixture.layout.user_payment_change).expect("output index"),
        ),
        secrets: fixture
            .user
            .unblind(&settlement.output[fixture.layout.user_payment_change]),
        txout: settlement.output[fixture.layout.user_payment_change].clone(),
    };
    let user_fee_change = OwnedUtxo {
        outpoint: OutPoint::new(
            settlement.txid(),
            u32::try_from(fixture.layout.fee_change).expect("output index"),
        ),
        secrets: fixture
            .user
            .unblind(&settlement.output[fixture.layout.fee_change]),
        txout: settlement.output[fixture.layout.fee_change].clone(),
    };
    let provider_payment = OwnedUtxo {
        outpoint: OutPoint::new(
            settlement.txid(),
            u32::try_from(fixture.layout.provider_payment).expect("output index"),
        ),
        secrets: fixture
            .provider
            .unblind(&settlement.output[fixture.layout.provider_payment]),
        txout: settlement.output[fixture.layout.provider_payment].clone(),
    };
    let provider_change = OwnedUtxo {
        outpoint: OutPoint::new(
            settlement.txid(),
            u32::try_from(fixture.layout.provider_inventory_change).expect("output index"),
        ),
        secrets: fixture
            .provider
            .unblind(&settlement.output[fixture.layout.provider_inventory_change]),
        txout: settlement.output[fixture.layout.provider_inventory_change].clone(),
    };
    assert_opening(user_receive.secrets, outcome_asset, USER_RECEIVE_VALUE);
    assert_opening(
        provider_payment.secrets,
        payment_asset,
        PROVIDER_PAYMENT_VALUE,
    );

    let user_sweep = build_wallet_sweep(
        &fixture.user,
        &[user_receive, user_change, user_fee_change],
        policy_asset,
        genesis_hash,
    );
    accept_broadcast_mine(&rpc, &miner, &user_sweep);
    let provider_sweep = build_wallet_sweep(
        &fixture.provider,
        &[provider_payment, provider_change, provider_fee_input],
        policy_asset,
        genesis_hash,
    );
    accept_broadcast_mine(&rpc, &miner, &provider_sweep);
}

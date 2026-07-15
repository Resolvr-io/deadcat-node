//! Serial, production-shaped Deadcat protocol lifecycles on liquidregtest.
//!
//! This test is ignored by ordinary `cargo test` because it starts an isolated
//! `elementsd` + Electrs pair. It is required by `just ci` through the explicit
//! `just regtest` suite. Its focused recipes are `just regtest-market-ab` and
//! `just regtest-maker-orders`.

use std::collections::HashMap;
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use bitcoincore_rpc::{Auth, Client, RpcApi};
use deadcat_client::keys::{DeadcatKeychain, DerivedOwnedOrder, MakerOrderTerms};
use deadcat_client::maker_builder::{MakerFillPlan, maker_order_creation_outputs};
use deadcat_client::market_builder::{
    BinaryMarketCreationPlan, BinaryMarketLiveInputs, BinaryMarketTransitionPlan,
    MarketCreationContext, MarketIssuanceEntropies, MarketRtInput, OracleAttestation,
};
use deadcat_client::recover_order_candidate_index;
use deadcat_client::validation::replay_contract_history;
use deadcat_contracts::SimplicityNetwork;
use deadcat_contracts::binary_market::{BinaryMarketAction, BinaryMarketEconomics, BinaryOutcome};
use deadcat_contracts::maker_order::CompiledMakerOrder;
use deadcat_contracts::market_crypto::{
    BinaryOutcome as OracleOutcome, derive_issuance_assets, oracle_message,
};
use deadcat_contracts::recovery::{
    MarketCollateral, MarketRecoveryHint, OrderRecoveryHint, validate_recovery_txout,
};
use deadcat_contracts::rt::{RtLeg, RtSide, add_mod_order, cbf, factors, infer_side};
use deadcat_iroh::RequestHandler as _;
use deadcat_node::chain::ChainSource as _;
use deadcat_node::chain::elements_rpc::{
    ElementsRpcAuth, ElementsRpcChainSource, ElementsRpcConfig,
};
use deadcat_node::interpreter::{
    DeadcatInterpreter, TRANSITION_V1_MAKER_CANCELLED, TRANSITION_V1_MAKER_FILLED,
};
use deadcat_node::registration::RegistrationVerifier;
use deadcat_node::rpc_handler::{NodeRpcHandler, RpcHandlerConfig};
use deadcat_node::store::{
    ChainIdentity as StoreChainIdentity, ContractParameters, ContractState, Store,
};
use deadcat_node::sync::{SyncCoordinator, SyncOutcome};
use deadcat_rpc::{
    BackendKind, ContractHistoryPage, ContractStateView, ContractView, PageRequest, RecoveryFamily,
    Request, Response, RpcErrorCode, TransactionEvidence,
};
use deadcat_types::{
    BinaryMarketParams, BinaryMarketState, CONTRACT_PACKAGE_FORMAT_VERSION, ChainAnchor,
    ChainIdentity, ChainPosition, ContractDeclaration, ContractDescriptor, ContractId,
    ContractPackage, ContractSyncState, DiscoveryCoverage, DiscoveryMode, LiquidNetwork,
    MakerOrderParams, MakerOrderState, OrderDirection, OrderSide,
};
use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::hashes::Hash as _;
use elements::pset::{Input as PsetInput, Output as PsetOutput, PartiallySignedTransaction};
use elements::schnorr::TapTweak as _;
use elements::secp256k1_zkp::rand::thread_rng;
use elements::secp256k1_zkp::{Keypair, Message, Secp256k1, SecretKey, SurjectionProof, Tweak};
use elements::sighash::{Prevouts, SchnorrSighashType, SighashCache};
use elements::taproot::{TapLeafHash, TapNodeHash};
use elements::{
    AssetId, BlockHash, OutPoint, Script, Transaction, TxOut, TxOutSecrets, TxOutWitness,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use simplex::provider::ElementsRpc;
use simplex::signer::{Signer, SignerTrait as _};
use simplex::transaction::{FinalTransaction, PartialOutput};
use smplx_regtest::{Regtest, RegtestConfig};

const FUNDING_VALUE: u64 = 100_000;
const FEE: u64 = 1_000;
const BASE_PAYOUT: u64 = 100;
const INITIAL_PAIRS: u64 = 2;
const SUBSEQUENT_PAIRS: u64 = 1;
const FUNDING_OUTPUTS: usize = 20;

#[derive(Clone)]
struct Funding {
    outpoint: OutPoint,
    txout: TxOut,
    secrets: TxOutSecrets,
}

#[derive(Clone, Debug)]
struct AcceptedTx {
    mempool_vsize: usize,
    block_height: u64,
    block_hash: String,
}

#[derive(Debug, Deserialize)]
struct MempoolAcceptance {
    allowed: Option<bool>,
    vsize: Option<usize>,
    #[serde(rename = "reject-reason")]
    reject_reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct TxMetrics {
    chain: &'static str,
    stage: &'static str,
    txid: String,
    inputs: usize,
    outputs: usize,
    bytes: usize,
    weight: usize,
    vsize: usize,
    discount_weight: usize,
    discount_vsize: usize,
    mempool_vsize: usize,
    block_height: u64,
    block_hash: String,
    covenant_stack_bytes: usize,
    surjection_proof_bytes: usize,
    rangeproof_bytes: usize,
    side_before: Option<&'static str>,
    side_after: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct NegativeTest {
    case: &'static str,
    reject_reason: String,
}

fn side_name(side: RtSide) -> &'static str {
    match side {
        RtSide::A => "a",
        RtSide::B => "b",
    }
}

fn explicit_txout(asset: AssetId, value: u64, script_pubkey: Script) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey,
        witness: TxOutWitness::default(),
    }
}

fn explicit_secrets(asset: AssetId, value: u64) -> TxOutSecrets {
    TxOutSecrets::new(
        asset,
        AssetBlindingFactor::zero(),
        value,
        ValueBlindingFactor::zero(),
    )
}

fn pset_input(outpoint: OutPoint, witness_utxo: TxOut) -> PsetInput {
    let mut input = PsetInput::from_prevout(outpoint);
    input.witness_utxo = Some(witness_utxo);
    input
}

fn sign_input(signer: &Signer, pset: &mut PartiallySignedTransaction, index: usize) {
    let (public_key, signature) = signer.sign_input(pset, index).expect("P2WPKH signature");
    let mut raw_signature = signature.serialize_der().to_vec();
    raw_signature.push(0x01);
    pset.inputs_mut()[index].final_script_witness =
        Some(vec![raw_signature, public_key.to_bytes()]);
}

fn rt_secrets(asset: AssetId, leg: RtLeg, side: RtSide) -> TxOutSecrets {
    let rt = factors(leg, side);
    TxOutSecrets::new(
        asset,
        AssetBlindingFactor::from_slice(&rt.abf).expect("RT ABF"),
        1,
        ValueBlindingFactor::from_slice(&rt.vbf).expect("RT VBF"),
    )
}

fn balanced_change(
    signer: &Signer,
    value: u64,
    policy_asset: AssetId,
    spent: &[TxOutSecrets],
    other_outputs: &[TxOutSecrets],
) -> TxOut {
    let secp = Secp256k1::new();
    let mut rng = thread_rng();
    let output_refs = other_outputs.iter().collect::<Vec<_>>();
    let output_abf = AssetBlindingFactor::new(&mut rng);
    let ephemeral = SecretKey::new(&mut rng);
    TxOut::with_secrets_last(
        &mut rng,
        &secp,
        value,
        signer.get_address().script_pubkey(),
        signer.get_blinding_public_key().inner,
        policy_asset,
        ephemeral,
        output_abf,
        spent,
        &output_refs,
    )
    .expect("balanced confidential wallet change")
    .0
}

fn prepare_funding(
    signer: &Signer,
    rpc: &Client,
    miner: &ElementsRpc,
    policy_asset: AssetId,
) -> (Transaction, AcceptedTx, Vec<Funding>) {
    let mut funding = FinalTransaction::new();
    for index in 0..FUNDING_OUTPUTS {
        let output = PartialOutput::new(
            signer.get_address().script_pubkey(),
            FUNDING_VALUE,
            policy_asset,
        );
        funding.add_output(if index == 3 {
            output.with_blinding_key(signer.get_blinding_public_key())
        } else {
            output
        });
    }
    let (transaction, _) = signer.finalize(&funding).expect("fund market test inputs");
    let accepted = accept_broadcast_mine(rpc, miner, &transaction);
    let blinding_key = signer.get_blinding_private_key().inner;
    let outputs = transaction
        .output
        .iter()
        .take(FUNDING_OUTPUTS)
        .cloned()
        .enumerate()
        .map(|(index, txout)| {
            let secrets = if index == 3 {
                txout
                    .unblind(&Secp256k1::new(), blinding_key)
                    .expect("unblind confidential funding output")
            } else {
                explicit_secrets(policy_asset, FUNDING_VALUE)
            };
            Funding {
                outpoint: OutPoint::new(transaction.txid(), index as u32),
                txout,
                secrets,
            }
        })
        .collect();
    (transaction, accepted, outputs)
}

fn oracle_keypair() -> Keypair {
    Keypair::from_seckey_slice(&Secp256k1::new(), &[0x31; 32]).expect("oracle key")
}

fn attestation(params: BinaryMarketParams, outcome: BinaryOutcome) -> OracleAttestation {
    let oracle_outcome = match outcome {
        BinaryOutcome::Yes => OracleOutcome::Yes,
        BinaryOutcome::No => OracleOutcome::No,
    };
    let digest = oracle_message(
        params.yes_token_asset_id,
        params.no_token_asset_id,
        oracle_outcome,
    );
    let signature =
        Secp256k1::new().sign_schnorr_no_aux_rand(&Message::from_digest(digest), &oracle_keypair());
    OracleAttestation {
        outcome,
        signature: signature.serialize(),
    }
}

fn params_for(
    policy_asset: AssetId,
    yes_defining_outpoint: OutPoint,
    no_defining_outpoint: OutPoint,
    expiry_height: u32,
) -> BinaryMarketParams {
    let assets = derive_issuance_assets(yes_defining_outpoint, no_defining_outpoint);
    BinaryMarketParams {
        oracle_public_key: oracle_keypair().x_only_public_key().0.serialize(),
        collateral_asset_id: policy_asset,
        yes_token_asset_id: assets.yes_token,
        no_token_asset_id: assets.no_token,
        yes_reissuance_token_id: assets.yes_reissuance_token,
        no_reissuance_token_id: assets.no_reissuance_token,
        base_payout: BASE_PAYOUT,
        expiry_height,
    }
}

fn market_hint(params: BinaryMarketParams) -> MarketRecoveryHint {
    MarketRecoveryHint {
        oracle_public_key: params.oracle_public_key,
        collateral: MarketCollateral::PolicyAsset,
        base_payout: params.base_payout,
        expiry_height: params.expiry_height,
    }
}

fn add_plan_outputs(pset: &mut PartiallySignedTransaction, plan: &BinaryMarketTransitionPlan) {
    for (_, output) in plan.mandatory_outputs(0).expect("mandatory outputs") {
        pset.add_output(PsetOutput::from_txout(output));
    }
}

struct CreatedMarket {
    params: BinaryMarketParams,
    entropies: MarketIssuanceEntropies,
    transaction: Transaction,
    accepted: AcceptedTx,
}

fn create_market(
    signer: &Signer,
    rpc: &Client,
    miner: &ElementsRpc,
    policy_asset: AssetId,
    yes_funding: &Funding,
    no_funding: &Funding,
    expiry_height: u32,
) -> CreatedMarket {
    let params = params_for(
        policy_asset,
        yes_funding.outpoint,
        no_funding.outpoint,
        expiry_height,
    );
    let plan = BinaryMarketCreationPlan::new(
        MarketCreationContext {
            policy_asset,
            liquid_mainnet_usdt: None,
        },
        params,
        market_hint(params),
        yes_funding.outpoint,
        no_funding.outpoint,
    )
    .expect("canonical market creation plan");
    let mut pset = plan
        .build_pset(
            pset_input(yes_funding.outpoint, yes_funding.txout.clone()),
            pset_input(no_funding.outpoint, no_funding.txout.clone()),
        )
        .expect("creation PSET");
    pset.add_output(PsetOutput::from_txout(explicit_txout(
        policy_asset,
        FUNDING_VALUE * 2 - FEE,
        signer.get_address().script_pubkey(),
    )));
    pset.add_output(PsetOutput::from_txout(TxOut::new_fee(FEE, policy_asset)));
    plan.finalize_rt_proofs(&mut pset)
        .expect("creation RT proofs");
    sign_input(signer, &mut pset, 0);
    sign_input(signer, &mut pset, 1);
    let transaction = pset.extract_tx().expect("creation transaction");
    assert_eq!(transaction.output[3].asset, Asset::Explicit(policy_asset));
    assert_eq!(
        transaction.output[3].value,
        Value::Explicit(FUNDING_VALUE * 2 - FEE)
    );
    assert_rt_pair(&transaction, params, RtSide::A, false);
    let accepted = accept_broadcast_mine(rpc, miner, &transaction);
    CreatedMarket {
        params,
        entropies: plan.entropies(),
        transaction,
        accepted,
    }
}

fn assert_live_elements_package_ingestion(
    rpc_url: &str,
    auth: &Auth,
    rpc: &Client,
    policy_asset: AssetId,
    market: &CreatedMarket,
) {
    let source_auth = match auth {
        Auth::None => ElementsRpcAuth::None,
        Auth::UserPass(username, password) => ElementsRpcAuth::Basic {
            username: username.clone(),
            password: password.clone(),
        },
        Auth::CookieFile(path) => ElementsRpcAuth::CookieFile(path.clone()),
    };
    let source = ElementsRpcChainSource::new(ElementsRpcConfig::new(rpc_url, source_auth))
        .expect("node Elements RPC source");
    let genesis_hash = BlockHash::from_str(
        &rpc.get_block_hash(0)
            .expect("regtest genesis block")
            .to_string(),
    )
    .expect("Elements genesis hash");
    let creation_anchor = ChainAnchor {
        height: u32::try_from(market.accepted.block_height).expect("creation height"),
        hash: BlockHash::from_str(&market.accepted.block_hash).expect("creation block hash"),
    };
    let chain = ChainIdentity {
        network: LiquidNetwork::ElementsRegtest,
        genesis_hash,
    };
    let contract_id = ContractId::new(OutPoint::new(market.transaction.txid(), 0));
    let package = ContractPackage {
        format_version: CONTRACT_PACKAGE_FORMAT_VERSION,
        chain,
        roots: vec![contract_id],
        declarations: vec![ContractDeclaration {
            contract_id,
            descriptor: ContractDescriptor::BinaryMarketV1 {
                params: market.params,
            },
        }],
    };

    let directory = tempfile::tempdir().expect("package-ingestion database directory");
    let store = Store::open(directory.path().join("deadcat.redb")).expect("open store");
    store
        .bind_chain(StoreChainIdentity {
            network: chain.network,
            genesis_hash: chain.genesis_hash,
            policy_asset,
        })
        .expect("bind store chain");
    store
        .initialize_tip(creation_anchor)
        .expect("initialize indexed tip");
    let verifier = RegistrationVerifier::new(
        &source,
        &store,
        LiquidNetwork::ElementsRegtest,
        genesis_hash,
        policy_asset,
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("registration runtime");

    let registered = runtime
        .block_on(verifier.verify_and_register_package(&package))
        .expect("verify live creation through the Elements backend");
    assert_eq!(registered.len(), 1);
    assert!(registered[0].1);
    assert_eq!(registered[0].0.record.contract_id, contract_id);
    assert_eq!(
        registered[0].0.record.params,
        ContractParameters::BinaryMarket(market.params)
    );
    let persisted = store
        .contract(contract_id)
        .expect("read registered contract")
        .expect("registered market");
    assert_eq!(persisted, registered[0].0.record);
    let evidence = store
        .transaction(persisted.creation_position)
        .expect("read creation evidence")
        .expect("persisted creation evidence");
    assert_eq!(
        elements::encode::deserialize::<Transaction>(&evidence.raw_tx)
            .expect("decode creation evidence"),
        market.transaction
    );

    let repeated = runtime
        .block_on(verifier.verify_and_register_package(&package))
        .expect("idempotent live registration retry");
    assert_eq!(repeated.len(), 1);
    assert!(!repeated[0].1);
}

fn dormant_live(transaction: &Transaction) -> BinaryMarketLiveInputs {
    BinaryMarketLiveInputs {
        yes_rt: Some(MarketRtInput {
            outpoint: OutPoint::new(transaction.txid(), 0),
            txout: transaction.output[0].clone(),
        }),
        no_rt: Some(MarketRtInput {
            outpoint: OutPoint::new(transaction.txid(), 1),
            txout: transaction.output[1].clone(),
        }),
        collateral: None,
    }
}

fn active_live(transaction: &Transaction) -> BinaryMarketLiveInputs {
    BinaryMarketLiveInputs {
        yes_rt: Some(MarketRtInput {
            outpoint: OutPoint::new(transaction.txid(), 0),
            txout: transaction.output[0].clone(),
        }),
        no_rt: Some(MarketRtInput {
            outpoint: OutPoint::new(transaction.txid(), 1),
            txout: transaction.output[1].clone(),
        }),
        collateral: Some(OutPoint::new(transaction.txid(), 2)),
    }
}

fn assert_rt_pair(
    transaction: &Transaction,
    params: BinaryMarketParams,
    side: RtSide,
    terminal: bool,
) {
    let yes = &transaction.output[0];
    let no = &transaction.output[1];
    assert_eq!(
        infer_side(
            RtLeg::Yes,
            params.yes_reissuance_token_id,
            yes.asset,
            yes.value,
        ),
        Ok(side)
    );
    assert_eq!(
        infer_side(RtLeg::No, params.no_reissuance_token_id, no.asset, no.value,),
        Ok(side)
    );
    assert!(yes.witness.rangeproof.is_some());
    assert!(no.witness.rangeproof.is_some());
    assert!(yes.witness.surjection_proof.is_some());
    assert!(no.witness.surjection_proof.is_some());
    if terminal {
        assert_eq!(yes.script_pubkey.as_bytes(), &[0x6a]);
        assert_eq!(no.script_pubkey.as_bytes(), &[0x6a]);
    }
}

fn assert_reissuances(
    transaction: &Transaction,
    entropies: MarketIssuanceEntropies,
    side: RtSide,
    pairs: u64,
) {
    for (input, entropy) in transaction.input[..2]
        .iter()
        .zip([entropies.yes, entropies.no])
    {
        assert_eq!(
            input.asset_issuance.asset_blinding_nonce,
            Tweak::from_inner(side.abf()).expect("side ABF")
        );
        assert_eq!(input.asset_issuance.asset_entropy, entropy);
        assert_eq!(input.asset_issuance.amount, Value::Explicit(pairs));
        assert_eq!(input.asset_issuance.inflation_keys, Value::Null);
    }
}

#[allow(clippy::too_many_arguments)]
fn build_issuance(
    signer: &Signer,
    network: &SimplicityNetwork,
    params: BinaryMarketParams,
    entropies: MarketIssuanceEntropies,
    before: BinaryMarketState,
    live: &BinaryMarketLiveInputs,
    collateral_txout: Option<&TxOut>,
    funding: &Funding,
    pairs: u64,
    input_side: RtSide,
    confidential_change: bool,
) -> (Transaction, BinaryMarketState) {
    let plan = BinaryMarketTransitionPlan::new(
        params,
        before,
        BinaryMarketAction::Issue { pairs },
        live.clone(),
        None,
    )
    .expect("issuance plan");
    let yes = live.yes_rt.as_ref().expect("YES RT");
    let no = live.no_rt.as_ref().expect("NO RT");
    let mut pset = PartiallySignedTransaction::new_v2();
    pset.add_input(pset_input(yes.outpoint, yes.txout.clone()));
    pset.add_input(pset_input(no.outpoint, no.txout.clone()));
    if let (Some(outpoint), Some(txout)) = (live.collateral, collateral_txout) {
        pset.add_input(pset_input(outpoint, txout.clone()));
    }
    let wallet_input_index = pset.inputs().len();
    pset.add_input(pset_input(funding.outpoint, funding.txout.clone()));
    add_plan_outputs(&mut pset, &plan);
    pset.add_output(PsetOutput::from_txout(explicit_txout(
        params.yes_token_asset_id,
        pairs,
        signer.get_address().script_pubkey(),
    )));
    pset.add_output(PsetOutput::from_txout(explicit_txout(
        params.no_token_asset_id,
        pairs,
        signer.get_address().script_pubkey(),
    )));

    let economics = BinaryMarketEconomics::new(params.base_payout).expect("economics");
    let old_collateral = match before {
        BinaryMarketState::Trading { outstanding_pairs } => economics
            .collateral_for_pairs(outstanding_pairs)
            .expect("old collateral"),
        _ => panic!("issuance starts in trading state"),
    };
    let new_collateral = match plan.after() {
        BinaryMarketState::Trading { outstanding_pairs } => economics
            .collateral_for_pairs(outstanding_pairs)
            .expect("new collateral"),
        _ => panic!("issuance ends in trading state"),
    };
    let change_value = FUNDING_VALUE + old_collateral - new_collateral - FEE;
    if confidential_change {
        let output_side = input_side.flip();
        let mut spent = vec![
            rt_secrets(params.yes_reissuance_token_id, RtLeg::Yes, input_side),
            explicit_secrets(params.yes_token_asset_id, pairs),
            rt_secrets(params.no_reissuance_token_id, RtLeg::No, input_side),
            explicit_secrets(params.no_token_asset_id, pairs),
        ];
        if old_collateral > 0 {
            spent.push(explicit_secrets(params.collateral_asset_id, old_collateral));
        }
        spent.push(funding.secrets);
        let other_outputs = vec![
            rt_secrets(params.yes_reissuance_token_id, RtLeg::Yes, output_side),
            rt_secrets(params.no_reissuance_token_id, RtLeg::No, output_side),
            explicit_secrets(params.collateral_asset_id, new_collateral),
            explicit_secrets(params.yes_token_asset_id, pairs),
            explicit_secrets(params.no_token_asset_id, pairs),
        ];
        pset.add_output(PsetOutput::from_txout(balanced_change(
            signer,
            change_value,
            params.collateral_asset_id,
            &spent,
            &other_outputs,
        )));
    } else {
        pset.add_output(PsetOutput::from_txout(explicit_txout(
            params.collateral_asset_id,
            change_value,
            signer.get_address().script_pubkey(),
        )));
    }
    pset.add_output(PsetOutput::from_txout(TxOut::new_fee(
        FEE,
        params.collateral_asset_id,
    )));
    plan.configure_reissuance_inputs(&mut pset, 0, entropies)
        .expect("configure exact reissuances");
    plan.finalize(&mut pset, 0, 0, network)
        .expect("finalize issuance covenants");
    sign_input(signer, &mut pset, wallet_input_index);
    let transaction = pset.extract_tx().expect("issuance transaction");
    assert_reissuances(&transaction, entropies, input_side, pairs);
    assert_rt_pair(&transaction, params, input_side.flip(), false);
    if confidential_change {
        assert!(transaction.output[5].value.is_confidential());
    } else {
        assert_eq!(transaction.output[5].value, Value::Explicit(change_value));
    }
    (transaction, plan.after())
}

#[derive(Clone)]
struct WalletUtxo {
    outpoint: OutPoint,
    txout: TxOut,
}

const MAKER_MNEMONIC: &str =
    "exist carry drive collect lend cereal occur much tiger just involve mean";
const MAKER_PRICE: u32 = 7;
const MAKER_MINIMUM: u32 = 3;
const MAKER_CAPACITY: u64 = 10;

struct LiveMakerOrder {
    order_index: u16,
    side: OrderSide,
    owned: DerivedOwnedOrder,
    contract_id: ContractId,
    output: WalletUtxo,
    hint_vout: u32,
}

fn explicit_value(txout: &TxOut) -> u64 {
    let Value::Explicit(value) = txout.value else {
        panic!("test wallet output value must be explicit")
    };
    value
}

fn maker_terms(
    market: BinaryMarketParams,
    side: OrderSide,
    direction: OrderDirection,
) -> MakerOrderTerms {
    MakerOrderTerms {
        base_asset_id: match side {
            OrderSide::Yes => market.yes_token_asset_id,
            OrderSide::No => market.no_token_asset_id,
        },
        quote_asset_id: market.collateral_asset_id,
        price: MAKER_PRICE,
        min_active_base: MAKER_MINIMUM,
        direction,
    }
}

#[allow(clippy::too_many_arguments)]
fn create_maker_orders(
    signer: &Signer,
    rpc: &Client,
    miner: &ElementsRpc,
    keychain: &DeadcatKeychain,
    market: &CreatedMarket,
    yes_tokens: &WalletUtxo,
    no_tokens: &WalletUtxo,
    funding: &Funding,
) -> (
    Transaction,
    AcceptedTx,
    Vec<LiveMakerOrder>,
    WalletUtxo,
    WalletUtxo,
) {
    let definitions = [
        (0_u16, OrderSide::Yes, OrderDirection::SellBase),
        (1, OrderSide::No, OrderDirection::SellQuote),
        (2, OrderSide::No, OrderDirection::SellBase),
        (3, OrderSide::Yes, OrderDirection::SellBase),
    ];
    let owned = definitions
        .into_iter()
        .map(|(index, side, direction)| {
            let terms = maker_terms(market.params, side, direction);
            let owned = keychain
                .derive_owned_order(index, market.transaction.txid(), side, terms)
                .expect("derive mnemonic-owned maker order");
            (index, side, owned)
        })
        .collect::<Vec<_>>();

    let mut pset = PartiallySignedTransaction::new_v2();
    pset.add_input(pset_input(yes_tokens.outpoint, yes_tokens.txout.clone()));
    pset.add_input(pset_input(no_tokens.outpoint, no_tokens.txout.clone()));
    pset.add_input(pset_input(funding.outpoint, funding.txout.clone()));

    let mut positions = Vec::with_capacity(owned.len());
    for (index, side, owned) in owned {
        let creation = maker_order_creation_outputs(
            market.params.collateral_asset_id,
            owned.params,
            MAKER_CAPACITY,
            &owned.keys.maker_receive_spk,
            owned.recovery_hint,
        )
        .expect("canonical maker-order outputs");
        let order_vout = u32::try_from(pset.outputs().len()).expect("order vout");
        pset.add_output(PsetOutput::from_txout(creation.order));
        let hint_vout = u32::try_from(pset.outputs().len()).expect("hint vout");
        pset.add_output(PsetOutput::from_txout(creation.recovery_hint));
        positions.push((index, side, owned, order_vout, hint_vout));
    }

    pset.add_output(PsetOutput::from_txout(explicit_txout(
        market.params.yes_token_asset_id,
        explicit_value(&yes_tokens.txout) - MAKER_CAPACITY * 2,
        signer.get_address().script_pubkey(),
    )));
    pset.add_output(PsetOutput::from_txout(explicit_txout(
        market.params.no_token_asset_id,
        explicit_value(&no_tokens.txout) - MAKER_CAPACITY,
        signer.get_address().script_pubkey(),
    )));
    pset.add_output(PsetOutput::from_txout(explicit_txout(
        market.params.collateral_asset_id,
        FUNDING_VALUE - MAKER_CAPACITY * u64::from(MAKER_PRICE) - FEE,
        signer.get_address().script_pubkey(),
    )));
    pset.add_output(PsetOutput::from_txout(TxOut::new_fee(
        FEE,
        market.params.collateral_asset_id,
    )));
    sign_input(signer, &mut pset, 0);
    sign_input(signer, &mut pset, 1);
    sign_input(signer, &mut pset, 2);
    let transaction = pset.extract_tx().expect("maker creation transaction");

    for (_, _, owned, order_vout, hint_vout) in &positions {
        let capacity = MAKER_CAPACITY;
        let expected = maker_order_creation_outputs(
            market.params.collateral_asset_id,
            owned.params,
            capacity,
            &owned.keys.maker_receive_spk,
            owned.recovery_hint,
        )
        .expect("rebuild canonical maker outputs");
        assert_eq!(transaction.output[*order_vout as usize], expected.order);
        assert_eq!(
            transaction.output[*hint_vout as usize],
            expected.recovery_hint
        );
    }

    let accepted = accept_broadcast_mine(rpc, miner, &transaction);
    let orders = positions
        .into_iter()
        .map(
            |(order_index, side, owned, order_vout, hint_vout)| LiveMakerOrder {
                order_index,
                side,
                owned,
                contract_id: ContractId::new(OutPoint::new(transaction.txid(), order_vout)),
                output: wallet_utxo(&transaction, order_vout as usize),
                hint_vout,
            },
        )
        .collect();
    (
        transaction.clone(),
        accepted,
        orders,
        wallet_utxo(&transaction, 8),
        wallet_utxo(&transaction, 9),
    )
}

#[allow(clippy::too_many_arguments)]
fn build_sell_base_fill(
    signer: &Signer,
    network: &SimplicityNetwork,
    params: MakerOrderParams,
    maker_receive_spk: &Script,
    order: &WalletUtxo,
    funding: &Funding,
    fill_base: u64,
    prior_total_filled_base: u64,
) -> (PartiallySignedTransaction, MakerFillPlan) {
    let input_locked = explicit_value(&order.txout);
    let plan = MakerFillPlan::new(
        params,
        maker_receive_spk.clone(),
        input_locked,
        fill_base,
        prior_total_filled_base,
    )
    .expect("SellBase fill plan");
    let remainder_index = plan.remainder_locked().map(|_| 1);
    let mut pset = PartiallySignedTransaction::new_v2();
    pset.add_input(pset_input(order.outpoint, order.txout.clone()));
    pset.add_input(pset_input(funding.outpoint, funding.txout.clone()));
    for (_, output) in plan
        .mandatory_outputs(0, remainder_index)
        .expect("SellBase mandatory outputs")
    {
        pset.add_output(PsetOutput::from_txout(output));
    }
    pset.add_output(PsetOutput::from_txout(explicit_txout(
        params.base_asset_id,
        fill_base,
        signer.get_address().script_pubkey(),
    )));
    pset.add_output(PsetOutput::from_txout(explicit_txout(
        params.quote_asset_id,
        FUNDING_VALUE - plan.maker_payment() - FEE,
        signer.get_address().script_pubkey(),
    )));
    pset.add_output(PsetOutput::from_txout(TxOut::new_fee(
        FEE,
        params.quote_asset_id,
    )));
    plan.finalize(&mut pset, 0, remainder_index, network)
        .expect("finalize SellBase covenant");
    (pset, plan)
}

#[allow(clippy::too_many_arguments)]
fn build_sell_quote_fill(
    signer: &Signer,
    network: &SimplicityNetwork,
    params: MakerOrderParams,
    maker_receive_spk: &Script,
    order: &WalletUtxo,
    taker_base: &WalletUtxo,
    funding: &Funding,
    fill_base: u64,
    prior_total_filled_base: u64,
) -> (PartiallySignedTransaction, MakerFillPlan) {
    let input_locked = explicit_value(&order.txout);
    let taker_base_value = explicit_value(&taker_base.txout);
    assert!(taker_base_value >= fill_base);
    let plan = MakerFillPlan::new(
        params,
        maker_receive_spk.clone(),
        input_locked,
        fill_base,
        prior_total_filled_base,
    )
    .expect("SellQuote fill plan");
    let remainder_index = plan.remainder_locked().map(|_| 1);
    let mut pset = PartiallySignedTransaction::new_v2();
    pset.add_input(pset_input(order.outpoint, order.txout.clone()));
    pset.add_input(pset_input(taker_base.outpoint, taker_base.txout.clone()));
    pset.add_input(pset_input(funding.outpoint, funding.txout.clone()));
    for (_, output) in plan
        .mandatory_outputs(0, remainder_index)
        .expect("SellQuote mandatory outputs")
    {
        pset.add_output(PsetOutput::from_txout(output));
    }
    pset.add_output(PsetOutput::from_txout(explicit_txout(
        params.quote_asset_id,
        fill_base * u64::from(params.price),
        signer.get_address().script_pubkey(),
    )));
    if taker_base_value > fill_base {
        pset.add_output(PsetOutput::from_txout(explicit_txout(
            params.base_asset_id,
            taker_base_value - fill_base,
            signer.get_address().script_pubkey(),
        )));
    }
    pset.add_output(PsetOutput::from_txout(explicit_txout(
        params.quote_asset_id,
        FUNDING_VALUE - FEE,
        signer.get_address().script_pubkey(),
    )));
    pset.add_output(PsetOutput::from_txout(TxOut::new_fee(
        FEE,
        params.quote_asset_id,
    )));
    plan.finalize(&mut pset, 0, remainder_index, network)
        .expect("finalize SellQuote covenant");
    (pset, plan)
}

fn build_maker_cancellation(
    signer: &Signer,
    params: MakerOrderParams,
    order: &WalletUtxo,
    funding: &Funding,
) -> PartiallySignedTransaction {
    let mut pset = PartiallySignedTransaction::new_v2();
    pset.add_input(pset_input(order.outpoint, order.txout.clone()));
    pset.add_input(pset_input(funding.outpoint, funding.txout.clone()));
    pset.add_output(PsetOutput::from_txout(explicit_txout(
        params.base_asset_id,
        explicit_value(&order.txout),
        signer.get_address().script_pubkey(),
    )));
    pset.add_output(PsetOutput::from_txout(explicit_txout(
        params.quote_asset_id,
        FUNDING_VALUE - FEE,
        signer.get_address().script_pubkey(),
    )));
    pset.add_output(PsetOutput::from_txout(TxOut::new_fee(
        FEE,
        params.quote_asset_id,
    )));
    pset
}

fn sign_maker_cancellation(
    pset: &mut PartiallySignedTransaction,
    order_input_index: usize,
    owned: &DerivedOwnedOrder,
    genesis_hash: BlockHash,
    apply_tap_tweak: bool,
) {
    let compiled = CompiledMakerOrder::new(owned.params).expect("compile cancellation order");
    assert!(compiled.control_block().merkle_branch.as_inner().is_empty());
    let leaf = TapLeafHash::from_script(
        &Script::from(compiled.cmr().to_vec()),
        compiled.control_block().leaf_version,
    );
    let root = TapNodeHash::from_byte_array(leaf.to_byte_array());
    let secp = Secp256k1::new();
    let maker_keypair = Keypair::from_seckey_slice(&secp, owned.keys.maker_secret_key())
        .expect("mnemonic-derived maker keypair");
    assert_eq!(
        maker_keypair.x_only_public_key().0.serialize(),
        owned.params.maker_pubkey
    );

    let signing_keypair = if apply_tap_tweak {
        let tweaked = maker_keypair.tap_tweak(&secp, Some(root));
        assert_eq!(
            Script::new_v1_p2tr_tweaked(tweaked.public_parts().0),
            *compiled.script_pubkey()
        );
        tweaked.to_inner()
    } else {
        maker_keypair
    };
    let unsigned = pset
        .extract_tx()
        .expect("cancellation unsigned transaction");
    let prevouts = pset
        .inputs()
        .iter()
        .map(|input| input.witness_utxo.clone().expect("cancellation prevout"))
        .collect::<Vec<_>>();
    let sighash = SighashCache::new(&unsigned)
        .taproot_key_spend_signature_hash(
            order_input_index,
            &Prevouts::All(&prevouts),
            SchnorrSighashType::Default,
            genesis_hash,
        )
        .expect("Elements Taproot key-spend sighash");
    let signature = secp.sign_schnorr_no_aux_rand(
        &Message::from_digest(sighash.to_byte_array()),
        &signing_keypair,
    );
    pset.inputs_mut()[order_input_index].final_script_witness =
        Some(vec![signature.as_ref().to_vec()]);
}

fn assert_mnemonic_order_recovery(
    keychain: &DeadcatKeychain,
    market: &CreatedMarket,
    creation: &Transaction,
    order: &LiveMakerOrder,
) {
    let payload = validate_recovery_txout(
        &creation.output[order.hint_vout as usize],
        market.params.collateral_asset_id,
    )
    .expect("canonical order recovery envelope");
    let hint = OrderRecoveryHint::decode(payload).expect("decode order recovery hint");
    assert_eq!(hint, order.owned.recovery_hint);
    assert_eq!(hint.market_creation_txid, market.transaction.txid());
    let deadcat_secret = keychain.deadcat_secret_key().expect("Deadcat secret");
    let candidate = recover_order_candidate_index(payload, &deadcat_secret)
        .expect("recover candidate order index");
    assert_eq!(candidate, order.order_index);
    let terms = maker_terms(market.params, hint.side, hint.direction);
    let recovered = keychain
        .derive_owned_order(candidate, hint.market_creation_txid, hint.side, terms)
        .expect("rederive recovered order");
    let compiled = CompiledMakerOrder::new(recovered.params).expect("compile recovered order");
    let held_asset = match recovered.params.direction {
        OrderDirection::SellBase => recovered.params.base_asset_id,
        OrderDirection::SellQuote => recovered.params.quote_asset_id,
    };
    let matches = creation
        .output
        .iter()
        .enumerate()
        .filter_map(|(index, output)| {
            if output.script_pubkey != *compiled.script_pubkey()
                || output.asset != Asset::Explicit(held_asset)
                || output.nonce != Nonce::Null
                || output.witness != TxOutWitness::default()
            {
                return None;
            }
            let Value::Explicit(locked) = output.value else {
                return None;
            };
            let capacity = match recovered.params.direction {
                OrderDirection::SellBase => locked,
                OrderDirection::SellQuote => {
                    let price = u64::from(recovered.params.price);
                    if !locked.is_multiple_of(price) {
                        return None;
                    }
                    locked / price
                }
            };
            if capacity < u64::from(recovered.params.min_active_base) {
                return None;
            }
            let expected = maker_order_creation_outputs(
                market.params.collateral_asset_id,
                recovered.params,
                capacity,
                &recovered.keys.maker_receive_spk,
                hint,
            )
            .ok()?;
            (output == &expected.order).then_some((index, capacity, expected))
        })
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1);
    let (matched_vout, recovered_capacity, expected) = &matches[0];
    assert_eq!(*matched_vout, order.contract_id.vout() as usize);
    assert_eq!(*recovered_capacity, MAKER_CAPACITY);
    assert_eq!(
        creation.output[order.hint_vout as usize],
        expected.recovery_hint
    );

    let foreign = DeadcatKeychain::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "",
    )
    .expect("foreign mnemonic");
    let foreign_secret = foreign.deadcat_secret_key().expect("foreign secret");
    let foreign_candidate = recover_order_candidate_index(payload, &foreign_secret)
        .expect("foreign hint still unmasks to a candidate");
    let foreign_order = foreign
        .derive_owned_order(
            foreign_candidate,
            hint.market_creation_txid,
            hint.side,
            terms,
        )
        .expect("derive foreign candidate");
    let foreign_compiled =
        CompiledMakerOrder::new(foreign_order.params).expect("compile foreign candidate");
    assert!(
        creation
            .output
            .iter()
            .all(|output| output.script_pubkey != *foreign_compiled.script_pubkey())
    );
}

fn node_elements_auth(auth: &Auth) -> ElementsRpcAuth {
    match auth {
        Auth::None => ElementsRpcAuth::None,
        Auth::UserPass(username, password) => ElementsRpcAuth::Basic {
            username: username.clone(),
            password: password.clone(),
        },
        Auth::CookieFile(path) => ElementsRpcAuth::CookieFile(path.clone()),
    }
}

fn maker_rpc_config(
    genesis_hash: BlockHash,
    policy_asset: AssetId,
    baseline: ChainAnchor,
    tip: ChainAnchor,
) -> RpcHandlerConfig {
    RpcHandlerConfig {
        network: LiquidNetwork::ElementsRegtest,
        genesis_hash,
        policy_asset,
        backend: BackendKind::ElementsRpc,
        discovery: DiscoveryCoverage {
            mode: DiscoveryMode::FullHintScan,
            from: baseline,
            scanned_through: tip,
            target_tip: tip,
            canonical_market_complete: true,
        },
        registration_bearer_token: None,
        max_concurrent_registrations: 1,
        max_concurrent_broadcasts: 1,
        subscription_buffer: 16,
        subscription_poll_interval: Duration::from_millis(1),
    }
}

async fn node_response(
    handler: &NodeRpcHandler<ElementsRpcChainSource>,
    request: Request,
) -> Response {
    handler
        .handle([0x55; 32], request)
        .await
        .expect("node RPC response")
}

async fn rpc_contract_view(
    handler: &NodeRpcHandler<ElementsRpcChainSource>,
    contract_id: ContractId,
) -> ContractView {
    let Response::Contract {
        contract: Some(contract),
    } = node_response(handler, Request::GetContract { contract_id }).await
    else {
        panic!("GetContract returned the wrong response")
    };
    contract
}

async fn rpc_contract_history(
    handler: &NodeRpcHandler<ElementsRpcChainSource>,
    contract_id: ContractId,
) -> ContractHistoryPage {
    let Response::ContractHistory { page } = node_response(
        handler,
        Request::GetContractHistory {
            contract_id,
            after: None,
            limit: 1_000,
        },
    )
    .await
    else {
        panic!("GetContractHistory returned the wrong response")
    };
    assert!(page.next.is_none());
    page
}

async fn rpc_transaction_evidence(
    handler: &NodeRpcHandler<ElementsRpcChainSource>,
    position: ChainPosition,
) -> TransactionEvidence {
    let Response::Transaction {
        evidence: Some(evidence),
    } = node_response(handler, Request::GetTransaction { position }).await
    else {
        panic!("GetTransaction returned the wrong response")
    };
    evidence
}

async fn assert_rpc_contract_replay(
    handler: &NodeRpcHandler<ElementsRpcChainSource>,
    source: &ElementsRpcChainSource,
    contract_id: ContractId,
    parent_market: Option<&ContractView>,
) -> (ContractView, ContractHistoryPage) {
    let view = rpc_contract_view(handler, contract_id).await;
    let history = rpc_contract_history(handler, contract_id).await;
    let creation = rpc_transaction_evidence(handler, view.creation_position).await;
    let mut transitions = Vec::with_capacity(history.entries.len());
    for entry in &history.entries {
        transitions.push(rpc_transaction_evidence(handler, entry.position).await);
    }
    let mut canonical = HashMap::new();
    for evidence in std::iter::once(&creation).chain(transitions.iter()) {
        let canonical_hash = source
            .block_hash(evidence.position.block_height)
            .await
            .expect("independent canonical block hash");
        assert_eq!(canonical_hash, evidence.block_hash);
        let block = source
            .block(evidence.block_hash)
            .await
            .expect("independent canonical block");
        let transaction = block
            .txdata
            .get(evidence.position.tx_index as usize)
            .expect("evidence transaction index");
        assert_eq!(transaction, &evidence.transaction);
        canonical.insert(
            (evidence.position, evidence.block_hash),
            transaction.clone(),
        );
    }
    let trusted_tip = source.tip().await.expect("independent canonical tip");
    let replay = replay_contract_history(
        &view,
        parent_market,
        &history,
        &creation,
        &transitions,
        trusted_tip,
        |position, block_hash, transaction| {
            canonical
                .get(&(position, block_hash))
                .is_some_and(|expected| expected == transaction)
        },
    )
    .expect("independent client history replay");
    assert_eq!(replay.contract().contract_id(), contract_id);
    assert_eq!(replay.transition_count(), history.entries.len());
    (view, history)
}

fn stored_maker_state(store: &Store, contract_id: ContractId) -> MakerOrderState {
    let record = store
        .contract(contract_id)
        .expect("read maker contract")
        .expect("registered maker contract");
    assert!(matches!(record.sync_state, ContractSyncState::Ready { .. }));
    let ContractState::MakerOrder(state) = record.state else {
        panic!("maker ContractId resolved to non-maker state")
    };
    state
}

struct TokenPair {
    yes: WalletUtxo,
    no: WalletUtxo,
}

fn wallet_utxo(transaction: &Transaction, index: usize) -> WalletUtxo {
    WalletUtxo {
        outpoint: OutPoint::new(transaction.txid(), index as u32),
        txout: transaction.output[index].clone(),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_partial_cancellation(
    signer: &Signer,
    network: &SimplicityNetwork,
    params: BinaryMarketParams,
    before: BinaryMarketState,
    live: &BinaryMarketLiveInputs,
    collateral_txout: &TxOut,
    tokens: &TokenPair,
    funding: &Funding,
    pairs: u64,
    input_side: RtSide,
) -> (Transaction, BinaryMarketState, TokenPair) {
    let plan = BinaryMarketTransitionPlan::new(
        params,
        before,
        BinaryMarketAction::Cancel { pairs },
        live.clone(),
        None,
    )
    .expect("partial cancellation plan");
    let yes_rt = live.yes_rt.as_ref().expect("YES RT");
    let no_rt = live.no_rt.as_ref().expect("NO RT");
    let mut pset = PartiallySignedTransaction::new_v2();
    pset.add_input(pset_input(yes_rt.outpoint, yes_rt.txout.clone()));
    pset.add_input(pset_input(no_rt.outpoint, no_rt.txout.clone()));
    pset.add_input(pset_input(
        live.collateral.expect("collateral outpoint"),
        collateral_txout.clone(),
    ));
    pset.add_input(pset_input(tokens.yes.outpoint, tokens.yes.txout.clone()));
    pset.add_input(pset_input(tokens.no.outpoint, tokens.no.txout.clone()));
    pset.add_input(pset_input(funding.outpoint, funding.txout.clone()));
    add_plan_outputs(&mut pset, &plan);

    let outstanding = match before {
        BinaryMarketState::Trading { outstanding_pairs } => outstanding_pairs,
        _ => panic!("cancellation starts in trading state"),
    };
    let remaining_tokens = outstanding - pairs;
    pset.add_output(PsetOutput::from_txout(explicit_txout(
        params.yes_token_asset_id,
        remaining_tokens,
        signer.get_address().script_pubkey(),
    )));
    pset.add_output(PsetOutput::from_txout(explicit_txout(
        params.no_token_asset_id,
        remaining_tokens,
        signer.get_address().script_pubkey(),
    )));
    let collateral_released = BinaryMarketEconomics::new(params.base_payout)
        .expect("economics")
        .collateral_for_pairs(pairs)
        .expect("released collateral");
    pset.add_output(PsetOutput::from_txout(explicit_txout(
        params.collateral_asset_id,
        collateral_released,
        signer.get_address().script_pubkey(),
    )));
    pset.add_output(PsetOutput::from_txout(explicit_txout(
        params.collateral_asset_id,
        FUNDING_VALUE - FEE,
        signer.get_address().script_pubkey(),
    )));
    pset.add_output(PsetOutput::from_txout(TxOut::new_fee(
        FEE,
        params.collateral_asset_id,
    )));
    plan.finalize(&mut pset, 0, 0, network)
        .expect("finalize partial cancellation");
    sign_input(signer, &mut pset, 3);
    sign_input(signer, &mut pset, 4);
    sign_input(signer, &mut pset, 5);
    let transaction = pset.extract_tx().expect("partial cancellation transaction");
    assert!(
        transaction
            .input
            .iter()
            .all(|input| input.asset_issuance.is_null())
    );
    assert_rt_pair(&transaction, params, input_side.flip(), false);
    let token_changes = TokenPair {
        yes: wallet_utxo(&transaction, 5),
        no: wallet_utxo(&transaction, 6),
    };
    (transaction, plan.after(), token_changes)
}

#[allow(clippy::too_many_arguments)]
fn build_full_cancellation(
    signer: &Signer,
    network: &SimplicityNetwork,
    params: BinaryMarketParams,
    before: BinaryMarketState,
    live: &BinaryMarketLiveInputs,
    collateral_txout: &TxOut,
    tokens: &TokenPair,
    funding: &Funding,
    pairs: u64,
    input_side: RtSide,
) -> (Transaction, BinaryMarketState) {
    let plan = BinaryMarketTransitionPlan::new(
        params,
        before,
        BinaryMarketAction::Cancel { pairs },
        live.clone(),
        None,
    )
    .expect("full cancellation plan");
    let yes_rt = live.yes_rt.as_ref().expect("YES RT");
    let no_rt = live.no_rt.as_ref().expect("NO RT");
    let mut pset = PartiallySignedTransaction::new_v2();
    pset.add_input(pset_input(yes_rt.outpoint, yes_rt.txout.clone()));
    pset.add_input(pset_input(no_rt.outpoint, no_rt.txout.clone()));
    pset.add_input(pset_input(
        live.collateral.expect("collateral outpoint"),
        collateral_txout.clone(),
    ));
    pset.add_input(pset_input(tokens.yes.outpoint, tokens.yes.txout.clone()));
    pset.add_input(pset_input(tokens.no.outpoint, tokens.no.txout.clone()));
    pset.add_input(pset_input(funding.outpoint, funding.txout.clone()));
    add_plan_outputs(&mut pset, &plan);
    let collateral_released = BinaryMarketEconomics::new(params.base_payout)
        .expect("economics")
        .collateral_for_pairs(pairs)
        .expect("released collateral");
    pset.add_output(PsetOutput::from_txout(explicit_txout(
        params.collateral_asset_id,
        collateral_released,
        signer.get_address().script_pubkey(),
    )));
    pset.add_output(PsetOutput::from_txout(explicit_txout(
        params.collateral_asset_id,
        FUNDING_VALUE - FEE,
        signer.get_address().script_pubkey(),
    )));
    pset.add_output(PsetOutput::from_txout(TxOut::new_fee(
        FEE,
        params.collateral_asset_id,
    )));
    plan.finalize(&mut pset, 0, 0, network)
        .expect("finalize full cancellation");
    sign_input(signer, &mut pset, 3);
    sign_input(signer, &mut pset, 4);
    sign_input(signer, &mut pset, 5);
    let transaction = pset.extract_tx().expect("full cancellation transaction");
    assert!(
        transaction
            .input
            .iter()
            .all(|input| input.asset_issuance.is_null())
    );
    assert_eq!(
        plan.after(),
        BinaryMarketState::Trading {
            outstanding_pairs: 0
        }
    );
    assert_rt_pair(&transaction, params, input_side.flip(), false);
    (transaction, plan.after())
}

#[allow(clippy::too_many_arguments)]
fn build_active_resolution(
    signer: &Signer,
    network: &SimplicityNetwork,
    params: BinaryMarketParams,
    before: BinaryMarketState,
    live: &BinaryMarketLiveInputs,
    collateral_txout: &TxOut,
    funding: &Funding,
    outcome: BinaryOutcome,
    input_side: RtSide,
) -> (Transaction, BinaryMarketState) {
    let plan = BinaryMarketTransitionPlan::new(
        params,
        before,
        BinaryMarketAction::Resolve { outcome },
        live.clone(),
        Some(attestation(params, outcome)),
    )
    .expect("active resolution plan");
    let yes_rt = live.yes_rt.as_ref().expect("YES RT");
    let no_rt = live.no_rt.as_ref().expect("NO RT");
    let mut pset = PartiallySignedTransaction::new_v2();
    pset.add_input(pset_input(yes_rt.outpoint, yes_rt.txout.clone()));
    pset.add_input(pset_input(no_rt.outpoint, no_rt.txout.clone()));
    pset.add_input(pset_input(
        live.collateral.expect("collateral outpoint"),
        collateral_txout.clone(),
    ));
    pset.add_input(pset_input(funding.outpoint, funding.txout.clone()));
    add_plan_outputs(&mut pset, &plan);
    pset.add_output(PsetOutput::from_txout(explicit_txout(
        params.collateral_asset_id,
        FUNDING_VALUE - FEE,
        signer.get_address().script_pubkey(),
    )));
    pset.add_output(PsetOutput::from_txout(TxOut::new_fee(
        FEE,
        params.collateral_asset_id,
    )));
    plan.finalize(&mut pset, 0, 0, network)
        .expect("finalize active resolution");
    sign_input(signer, &mut pset, 3);
    let transaction = pset.extract_tx().expect("active resolution transaction");
    assert!(
        transaction
            .input
            .iter()
            .all(|input| input.asset_issuance.is_null())
    );
    assert_rt_pair(&transaction, params, input_side.flip(), true);
    (transaction, plan.after())
}

#[allow(clippy::too_many_arguments)]
fn build_active_expiry(
    signer: &Signer,
    network: &SimplicityNetwork,
    params: BinaryMarketParams,
    before: BinaryMarketState,
    live: &BinaryMarketLiveInputs,
    collateral_txout: &TxOut,
    funding: &Funding,
    input_side: RtSide,
) -> (Transaction, BinaryMarketState) {
    let plan = BinaryMarketTransitionPlan::new(
        params,
        before,
        BinaryMarketAction::Expire,
        live.clone(),
        None,
    )
    .expect("active expiry plan");
    let yes_rt = live.yes_rt.as_ref().expect("YES RT");
    let no_rt = live.no_rt.as_ref().expect("NO RT");
    let mut pset = PartiallySignedTransaction::new_v2();
    pset.add_input(pset_input(yes_rt.outpoint, yes_rt.txout.clone()));
    pset.add_input(pset_input(no_rt.outpoint, no_rt.txout.clone()));
    pset.add_input(pset_input(
        live.collateral.expect("collateral outpoint"),
        collateral_txout.clone(),
    ));
    pset.add_input(pset_input(funding.outpoint, funding.txout.clone()));
    add_plan_outputs(&mut pset, &plan);
    pset.add_output(PsetOutput::from_txout(explicit_txout(
        params.collateral_asset_id,
        FUNDING_VALUE - FEE,
        signer.get_address().script_pubkey(),
    )));
    pset.add_output(PsetOutput::from_txout(TxOut::new_fee(
        FEE,
        params.collateral_asset_id,
    )));
    plan.prepare_expiry(&mut pset, 0)
        .expect("expiry locktime and sequences");
    plan.finalize(&mut pset, 0, 0, network)
        .expect("finalize active expiry");
    sign_input(signer, &mut pset, 3);
    let transaction = pset.extract_tx().expect("active expiry transaction");
    assert!(
        transaction
            .input
            .iter()
            .all(|input| input.asset_issuance.is_null())
    );
    assert_eq!(
        transaction.lock_time.to_consensus_u32(),
        params.expiry_height
    );
    assert!(
        transaction.input[..3]
            .iter()
            .all(|input| input.sequence.0 == 0xffff_fffe)
    );
    assert_rt_pair(&transaction, params, input_side.flip(), true);
    (transaction, plan.after())
}

fn corrupted_surjection(original: &SurjectionProof) -> SurjectionProof {
    let bytes = original.serialize();
    for index in (0..bytes.len()).rev() {
        for mask in [1_u8, 2, 4, 8, 16, 32, 64, 128] {
            let mut candidate = bytes.clone();
            candidate[index] ^= mask;
            if let Ok(proof) = SurjectionProof::from_slice(&candidate)
                && proof != *original
            {
                return proof;
            }
        }
    }
    panic!("could not produce a parseable corrupted surjection proof")
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

fn assert_mempool_rejects(
    rpc: &Client,
    transaction: &Transaction,
    case: &'static str,
) -> NegativeTest {
    let acceptance = test_mempool_accept(rpc, transaction);
    assert_eq!(
        acceptance.allowed,
        Some(false),
        "elementsd unexpectedly accepted {case}"
    );
    NegativeTest {
        case,
        reject_reason: acceptance
            .reject_reason
            .expect("rejected transaction has a reason"),
    }
}

fn accept_broadcast_mine(
    rpc: &Client,
    miner: &ElementsRpc,
    transaction: &Transaction,
) -> AcceptedTx {
    let acceptance = test_mempool_accept(rpc, transaction);
    assert_eq!(
        acceptance.allowed,
        Some(true),
        "elementsd rejected transaction: {:?}",
        acceptance.reject_reason
    );
    let mempool_vsize = acceptance.vsize.expect("accepted transaction vsize");
    assert!(
        mempool_vsize == transaction.vsize() || mempool_vsize == transaction.discount_vsize(),
        "unexpected policy vsize {mempool_vsize}; regular={}, discounted={}",
        transaction.vsize(),
        transaction.discount_vsize()
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
    let verbose: JsonValue = rpc
        .call(
            "getrawtransaction",
            &[json!(transaction.txid().to_string()), json!(true)],
        )
        .expect("getrawtransaction RPC");
    assert!(
        verbose["confirmations"]
            .as_u64()
            .is_some_and(|count| count >= 1),
        "transaction was not confirmed: {verbose}"
    );
    let block_height: u64 = rpc.call("getblockcount", &[]).expect("getblockcount RPC");
    let block_hash: String = rpc
        .call("getblockhash", &[json!(block_height)])
        .expect("getblockhash RPC");
    assert_eq!(
        verbose["blockhash"].as_str(),
        Some(block_hash.as_str()),
        "transaction confirmed in an unexpected block"
    );
    AcceptedTx {
        mempool_vsize,
        block_height,
        block_hash,
    }
}

fn metrics(
    chain: &'static str,
    stage: &'static str,
    transaction: &Transaction,
    accepted: &AcceptedTx,
    covenant_inputs: &[usize],
    sides: Option<(RtSide, RtSide)>,
) -> TxMetrics {
    assert_eq!(
        transaction.size(),
        elements::encode::serialize(transaction).len()
    );
    let covenant_stack_bytes = covenant_inputs
        .iter()
        .map(|index| {
            elements::encode::serialize(&transaction.input[*index].witness.script_witness).len()
        })
        .sum();
    let surjection_proof_bytes = transaction
        .output
        .iter()
        .filter_map(|output| output.witness.surjection_proof.as_deref())
        .map(SurjectionProof::len)
        .sum();
    let rangeproof_bytes = transaction
        .output
        .iter()
        .filter_map(|output| output.witness.rangeproof.as_deref())
        .map(|proof| proof.serialize().len())
        .sum();
    TxMetrics {
        chain,
        stage,
        txid: transaction.txid().to_string(),
        inputs: transaction.input.len(),
        outputs: transaction.output.len(),
        bytes: transaction.size(),
        weight: transaction.weight(),
        vsize: transaction.vsize(),
        discount_weight: transaction.discount_weight(),
        discount_vsize: transaction.discount_vsize(),
        mempool_vsize: accepted.mempool_vsize,
        block_height: accepted.block_height,
        block_hash: accepted.block_hash.clone(),
        covenant_stack_bytes,
        surjection_proof_bytes,
        rangeproof_bytes,
        side_before: sides.map(|(before, _)| side_name(before)),
        side_after: sides.map(|(_, after)| side_name(after)),
    }
}

#[test]
#[ignore = "starts elementsd and liquid-enabled Electrs from the Nix development shell"]
fn binary_market_ab_lifecycle_is_accepted_by_elementsd() {
    assert_eq!(add_mod_order(cbf(RtLeg::Yes), cbf(RtLeg::No)), [0; 32]);

    let (client, signer) =
        Regtest::from_config(&RegtestConfig::default()).expect("regtest environment");
    let network = SimplicityNetwork::default_regtest();
    let policy_asset = network.policy_asset();
    let miner = ElementsRpc::new(client.rpc_url(), client.auth()).expect("Elements RPC");
    let rpc = Client::new(&client.rpc_url(), client.auth()).expect("raw Elements RPC");
    let (funding_tx, funding_accepted, funding) =
        prepare_funding(&signer, &rpc, &miner, policy_asset);
    let expiry_height = u32::try_from(funding_accepted.block_height)
        .expect("regtest height fits in a v1 expiry height");
    let mut transactions = vec![metrics(
        "fixture",
        "funding",
        &funding_tx,
        &funding_accepted,
        &[],
        None,
    )];

    // Chain one keeps the confidential-wallet composition check and proves
    // active YES resolution followed by both partial and complete redemption.
    let market_one = create_market(
        &signer,
        &rpc,
        &miner,
        policy_asset,
        &funding[0],
        &funding[1],
        expiry_height,
    );
    assert_live_elements_package_ingestion(
        &client.rpc_url(),
        &client.auth(),
        &rpc,
        policy_asset,
        &market_one,
    );
    let params = market_one.params;
    transactions.push(metrics(
        "yes_resolution",
        "creation",
        &market_one.transaction,
        &market_one.accepted,
        &[],
        None,
    ));
    let (initial, trading_two) = build_issuance(
        &signer,
        &network,
        params,
        market_one.entropies,
        BinaryMarketState::Trading {
            outstanding_pairs: 0,
        },
        &dormant_live(&market_one.transaction),
        None,
        &funding[2],
        INITIAL_PAIRS,
        RtSide::A,
        false,
    );

    let mut missing_proof = initial.clone();
    missing_proof.output[0].witness.surjection_proof = None;
    let missing = assert_mempool_rejects(&rpc, &missing_proof, "missing_rt_surjection_proof");
    let mut malformed_proof = initial.clone();
    let original = malformed_proof.output[0]
        .witness
        .surjection_proof
        .as_deref()
        .expect("YES RT surjection proof");
    malformed_proof.output[0].witness.surjection_proof =
        Some(Box::new(corrupted_surjection(original)));
    let malformed = assert_mempool_rejects(&rpc, &malformed_proof, "malformed_rt_surjection_proof");
    let initial_accepted = accept_broadcast_mine(&rpc, &miner, &initial);
    transactions.push(metrics(
        "yes_resolution",
        "initial_issuance",
        &initial,
        &initial_accepted,
        &[0, 1],
        Some((RtSide::A, RtSide::B)),
    ));
    let (subsequent, trading_three) = build_issuance(
        &signer,
        &network,
        params,
        market_one.entropies,
        trading_two,
        &active_live(&initial),
        Some(&initial.output[2]),
        &funding[3],
        SUBSEQUENT_PAIRS,
        RtSide::B,
        true,
    );
    let subsequent_accepted = accept_broadcast_mine(&rpc, &miner, &subsequent);
    transactions.push(metrics(
        "yes_resolution",
        "subsequent_issuance_confidential_wallet",
        &subsequent,
        &subsequent_accepted,
        &[0, 1, 2],
        Some((RtSide::B, RtSide::A)),
    ));
    let (resolution, resolved_state) = build_active_resolution(
        &signer,
        &network,
        params,
        trading_three,
        &active_live(&subsequent),
        &subsequent.output[2],
        &funding[4],
        BinaryOutcome::Yes,
        RtSide::A,
    );
    let resolution_accepted = accept_broadcast_mine(&rpc, &miner, &resolution);
    transactions.push(metrics(
        "yes_resolution",
        "active_yes_resolution",
        &resolution,
        &resolution_accepted,
        &[0, 1, 2],
        Some((RtSide::A, RtSide::B)),
    ));

    let partial_redemption_plan = BinaryMarketTransitionPlan::new(
        params,
        resolved_state,
        BinaryMarketAction::Redeem {
            outcome: BinaryOutcome::Yes,
            tokens: 1,
        },
        BinaryMarketLiveInputs {
            collateral: Some(OutPoint::new(resolution.txid(), 2)),
            ..BinaryMarketLiveInputs::default()
        },
        None,
    )
    .expect("partial resolved redemption plan");
    let mut redemption_pset = PartiallySignedTransaction::new_v2();
    redemption_pset.add_input(pset_input(
        OutPoint::new(resolution.txid(), 2),
        resolution.output[2].clone(),
    ));
    redemption_pset.add_input(pset_input(
        OutPoint::new(initial.txid(), 3),
        initial.output[3].clone(),
    ));
    redemption_pset.add_input(pset_input(funding[5].outpoint, funding[5].txout.clone()));
    add_plan_outputs(&mut redemption_pset, &partial_redemption_plan);
    redemption_pset.add_output(PsetOutput::from_txout(explicit_txout(
        policy_asset,
        BASE_PAYOUT * 2,
        signer.get_address().script_pubkey(),
    )));
    redemption_pset.add_output(PsetOutput::from_txout(explicit_txout(
        params.yes_token_asset_id,
        INITIAL_PAIRS - 1,
        signer.get_address().script_pubkey(),
    )));
    redemption_pset.add_output(PsetOutput::from_txout(explicit_txout(
        policy_asset,
        FUNDING_VALUE - FEE,
        signer.get_address().script_pubkey(),
    )));
    redemption_pset.add_output(PsetOutput::from_txout(TxOut::new_fee(FEE, policy_asset)));
    partial_redemption_plan
        .finalize(&mut redemption_pset, 0, 0, &network)
        .expect("finalize partial redemption");
    sign_input(&signer, &mut redemption_pset, 1);
    sign_input(&signer, &mut redemption_pset, 2);
    let partial_redemption = redemption_pset
        .extract_tx()
        .expect("partial redemption transaction");
    let partial_redemption_accepted = accept_broadcast_mine(&rpc, &miner, &partial_redemption);
    transactions.push(metrics(
        "yes_resolution",
        "partial_resolved_redemption",
        &partial_redemption,
        &partial_redemption_accepted,
        &[0],
        None,
    ));

    let full_redemption_plan = BinaryMarketTransitionPlan::new(
        params,
        partial_redemption_plan.after(),
        BinaryMarketAction::Redeem {
            outcome: BinaryOutcome::Yes,
            tokens: 2,
        },
        BinaryMarketLiveInputs {
            collateral: Some(OutPoint::new(partial_redemption.txid(), 0)),
            ..BinaryMarketLiveInputs::default()
        },
        None,
    )
    .expect("full resolved redemption plan");
    let mut full_redemption_pset = PartiallySignedTransaction::new_v2();
    full_redemption_pset.add_input(pset_input(
        OutPoint::new(partial_redemption.txid(), 0),
        partial_redemption.output[0].clone(),
    ));
    full_redemption_pset.add_input(pset_input(
        OutPoint::new(partial_redemption.txid(), 3),
        partial_redemption.output[3].clone(),
    ));
    full_redemption_pset.add_input(pset_input(
        OutPoint::new(subsequent.txid(), 3),
        subsequent.output[3].clone(),
    ));
    full_redemption_pset.add_input(pset_input(funding[6].outpoint, funding[6].txout.clone()));
    add_plan_outputs(&mut full_redemption_pset, &full_redemption_plan);
    full_redemption_pset.add_output(PsetOutput::from_txout(explicit_txout(
        policy_asset,
        BASE_PAYOUT * 4,
        signer.get_address().script_pubkey(),
    )));
    full_redemption_pset.add_output(PsetOutput::from_txout(explicit_txout(
        policy_asset,
        FUNDING_VALUE - FEE,
        signer.get_address().script_pubkey(),
    )));
    full_redemption_pset.add_output(PsetOutput::from_txout(TxOut::new_fee(FEE, policy_asset)));
    full_redemption_plan
        .finalize(&mut full_redemption_pset, 0, 0, &network)
        .expect("finalize full redemption");
    sign_input(&signer, &mut full_redemption_pset, 1);
    sign_input(&signer, &mut full_redemption_pset, 2);
    sign_input(&signer, &mut full_redemption_pset, 3);
    let full_redemption = full_redemption_pset
        .extract_tx()
        .expect("full redemption transaction");
    assert_eq!(
        full_redemption_plan.after(),
        BinaryMarketState::ResolvedYes {
            collateral_unredeemed: 0
        }
    );
    assert_eq!(full_redemption.output[0].value, Value::Explicit(2));
    assert_eq!(full_redemption.output[0].script_pubkey.as_bytes(), &[0x6a]);
    let full_redemption_accepted = accept_broadcast_mine(&rpc, &miner, &full_redemption);
    transactions.push(metrics(
        "yes_resolution",
        "full_resolved_redemption",
        &full_redemption,
        &full_redemption_accepted,
        &[0],
        None,
    ));

    // Chain two covers both cancellation paths, restoration of Dormant, a
    // B-side dormant reissuance, and an oracle-authorized NO resolution.
    let market_two = create_market(
        &signer,
        &rpc,
        &miner,
        policy_asset,
        &funding[7],
        &funding[8],
        expiry_height,
    );
    let cancel_params = market_two.params;
    transactions.push(metrics(
        "cancel_reissue_no",
        "creation",
        &market_two.transaction,
        &market_two.accepted,
        &[],
        None,
    ));
    let (cancel_initial, trading_three) = build_issuance(
        &signer,
        &network,
        cancel_params,
        market_two.entropies,
        BinaryMarketState::Trading {
            outstanding_pairs: 0,
        },
        &dormant_live(&market_two.transaction),
        None,
        &funding[9],
        3,
        RtSide::A,
        false,
    );
    let cancel_initial_accepted = accept_broadcast_mine(&rpc, &miner, &cancel_initial);
    transactions.push(metrics(
        "cancel_reissue_no",
        "initial_issuance",
        &cancel_initial,
        &cancel_initial_accepted,
        &[0, 1],
        Some((RtSide::A, RtSide::B)),
    ));
    let initial_tokens = TokenPair {
        yes: wallet_utxo(&cancel_initial, 3),
        no: wallet_utxo(&cancel_initial, 4),
    };
    let (partial_cancel, trading_two, cancel_token_changes) = build_partial_cancellation(
        &signer,
        &network,
        cancel_params,
        trading_three,
        &active_live(&cancel_initial),
        &cancel_initial.output[2],
        &initial_tokens,
        &funding[10],
        1,
        RtSide::B,
    );
    let partial_cancel_accepted = accept_broadcast_mine(&rpc, &miner, &partial_cancel);
    transactions.push(metrics(
        "cancel_reissue_no",
        "partial_cancellation",
        &partial_cancel,
        &partial_cancel_accepted,
        &[0, 1, 2],
        Some((RtSide::B, RtSide::A)),
    ));
    let (full_cancel, dormant_state) = build_full_cancellation(
        &signer,
        &network,
        cancel_params,
        trading_two,
        &active_live(&partial_cancel),
        &partial_cancel.output[2],
        &cancel_token_changes,
        &funding[11],
        2,
        RtSide::A,
    );
    let full_cancel_accepted = accept_broadcast_mine(&rpc, &miner, &full_cancel);
    transactions.push(metrics(
        "cancel_reissue_no",
        "full_cancellation_to_dormant",
        &full_cancel,
        &full_cancel_accepted,
        &[0, 1, 2],
        Some((RtSide::A, RtSide::B)),
    ));
    let (dormant_reissue, trading_one) = build_issuance(
        &signer,
        &network,
        cancel_params,
        market_two.entropies,
        dormant_state,
        &dormant_live(&full_cancel),
        None,
        &funding[12],
        1,
        RtSide::B,
        false,
    );
    let dormant_reissue_accepted = accept_broadcast_mine(&rpc, &miner, &dormant_reissue);
    transactions.push(metrics(
        "cancel_reissue_no",
        "dormant_reissuance",
        &dormant_reissue,
        &dormant_reissue_accepted,
        &[0, 1],
        Some((RtSide::B, RtSide::A)),
    ));
    let (no_resolution, _) = build_active_resolution(
        &signer,
        &network,
        cancel_params,
        trading_one,
        &active_live(&dormant_reissue),
        &dormant_reissue.output[2],
        &funding[13],
        BinaryOutcome::No,
        RtSide::A,
    );
    let no_resolution_accepted = accept_broadcast_mine(&rpc, &miner, &no_resolution);
    transactions.push(metrics(
        "cancel_reissue_no",
        "active_no_resolution",
        &no_resolution,
        &no_resolution_accepted,
        &[0, 1, 2],
        Some((RtSide::A, RtSide::B)),
    ));

    // Chain three expires an active B-side market. This supplies a real CLTV
    // locktime/sequence spend and the corpus's B -> A terminal burn.
    let market_three = create_market(
        &signer,
        &rpc,
        &miner,
        policy_asset,
        &funding[14],
        &funding[15],
        expiry_height,
    );
    let expiry_params = market_three.params;
    transactions.push(metrics(
        "active_expiry",
        "creation",
        &market_three.transaction,
        &market_three.accepted,
        &[],
        None,
    ));
    let (expiry_initial, expiry_trading) = build_issuance(
        &signer,
        &network,
        expiry_params,
        market_three.entropies,
        BinaryMarketState::Trading {
            outstanding_pairs: 0,
        },
        &dormant_live(&market_three.transaction),
        None,
        &funding[16],
        1,
        RtSide::A,
        false,
    );
    let expiry_initial_accepted = accept_broadcast_mine(&rpc, &miner, &expiry_initial);
    transactions.push(metrics(
        "active_expiry",
        "initial_issuance",
        &expiry_initial,
        &expiry_initial_accepted,
        &[0, 1],
        Some((RtSide::A, RtSide::B)),
    ));
    let current_height: u64 = rpc.call("getblockcount", &[]).expect("getblockcount RPC");
    assert!(current_height >= u64::from(expiry_params.expiry_height));
    let (expiry, _) = build_active_expiry(
        &signer,
        &network,
        expiry_params,
        expiry_trading,
        &active_live(&expiry_initial),
        &expiry_initial.output[2],
        &funding[17],
        RtSide::B,
    );
    let expiry_accepted = accept_broadcast_mine(&rpc, &miner, &expiry);
    transactions.push(metrics(
        "active_expiry",
        "active_expiry",
        &expiry,
        &expiry_accepted,
        &[0, 1, 2],
        Some((RtSide::B, RtSide::A)),
    ));

    let report = json!({
        "schema": "deadcat.market-ab-regtest.v1",
        "policy_asset": policy_asset.to_string(),
        "markets": [
            {
                "chain": "yes_resolution",
                "yes_token_asset": params.yes_token_asset_id.to_string(),
                "no_token_asset": params.no_token_asset_id.to_string(),
            },
            {
                "chain": "cancel_reissue_no",
                "yes_token_asset": cancel_params.yes_token_asset_id.to_string(),
                "no_token_asset": cancel_params.no_token_asset_id.to_string(),
            },
            {
                "chain": "active_expiry",
                "yes_token_asset": expiry_params.yes_token_asset_id.to_string(),
                "no_token_asset": expiry_params.no_token_asset_id.to_string(),
                "expiry_height": expiry_params.expiry_height,
            },
        ],
        "transactions": transactions,
        "negative_tests": [missing, malformed],
    });
    eprintln!(
        "DEADCAT_MARKET_AB_METRICS={}",
        serde_json::to_string(&report).expect("serialize market metrics")
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "starts elementsd and liquid-enabled Electrs from the Nix development shell"]
async fn maker_order_lifecycle_is_accepted_by_elementsd() {
    let (client, signer) =
        Regtest::from_config(&RegtestConfig::default()).expect("regtest environment");
    let network = SimplicityNetwork::default_regtest();
    let policy_asset = network.policy_asset();
    let miner = ElementsRpc::new(client.rpc_url(), client.auth()).expect("Elements RPC");
    let rpc = Client::new(&client.rpc_url(), client.auth()).expect("raw Elements RPC");
    let genesis_hash = BlockHash::from_str(
        &rpc.get_block_hash(0)
            .expect("regtest genesis block")
            .to_string(),
    )
    .expect("Elements genesis hash");
    let (_funding_tx, funding_accepted, funding) =
        prepare_funding(&signer, &rpc, &miner, policy_asset);
    let baseline = ChainAnchor {
        height: u32::try_from(funding_accepted.block_height).expect("baseline height"),
        hash: BlockHash::from_str(&funding_accepted.block_hash).expect("baseline hash"),
    };
    let expiry_height = baseline.height.checked_add(1_000).expect("future expiry");
    let market = create_market(
        &signer,
        &rpc,
        &miner,
        policy_asset,
        &funding[0],
        &funding[1],
        expiry_height,
    );
    let (issuance, trading) = build_issuance(
        &signer,
        &network,
        market.params,
        market.entropies,
        BinaryMarketState::Trading {
            outstanding_pairs: 0,
        },
        &dormant_live(&market.transaction),
        None,
        &funding[2],
        30,
        RtSide::A,
        false,
    );
    assert_eq!(
        trading,
        BinaryMarketState::Trading {
            outstanding_pairs: 30
        }
    );
    accept_broadcast_mine(&rpc, &miner, &issuance);

    let keychain =
        DeadcatKeychain::from_mnemonic(MAKER_MNEMONIC, "").expect("test Deadcat keychain");
    let (order_creation, _, orders, _yes_change, no_change) = create_maker_orders(
        &signer,
        &rpc,
        &miner,
        &keychain,
        &market,
        &wallet_utxo(&issuance, 3),
        &wallet_utxo(&issuance, 4),
        &funding[3],
    );
    assert_eq!(
        orders
            .iter()
            .map(|order| order.contract_id.vout())
            .collect::<Vec<_>>(),
        vec![0, 2, 4, 6]
    );
    for order in &orders {
        assert_mnemonic_order_recovery(&keychain, &market, &order_creation, order);
    }

    let sell_base = &orders[0];
    let (sell_base_partial_pset, sell_base_partial_plan) = build_sell_base_fill(
        &signer,
        &network,
        sell_base.owned.params,
        &sell_base.owned.keys.maker_receive_spk,
        &sell_base.output,
        &funding[4],
        3,
        0,
    );
    assert_eq!(
        sell_base_partial_plan.next_state(),
        MakerOrderState::Active {
            remaining_base: 7,
            total_filled_base: 3,
        }
    );
    let mut wrong_payment = sell_base_partial_pset.clone();
    wrong_payment.outputs_mut()[0].amount = Some(22);
    wrong_payment.outputs_mut()[3].amount = Some(FUNDING_VALUE - 22 - FEE);
    sign_input(&signer, &mut wrong_payment, 1);
    let wrong_payment = wrong_payment
        .extract_tx()
        .expect("wrong-payment transaction");
    let wrong_payment_rejection =
        assert_mempool_rejects(&rpc, &wrong_payment, "maker_wrong_payment_amount");

    let mut wrong_receive_script = sell_base_partial_pset.clone();
    wrong_receive_script.outputs_mut()[0].script_pubkey = signer.get_address().script_pubkey();
    sign_input(&signer, &mut wrong_receive_script, 1);
    let wrong_receive_script = wrong_receive_script
        .extract_tx()
        .expect("wrong receive-script transaction");
    let wrong_receive_rejection =
        assert_mempool_rejects(&rpc, &wrong_receive_script, "maker_wrong_receive_script");

    let mut below_minimum = sell_base_partial_pset.clone();
    below_minimum.outputs_mut()[0].amount = Some(14);
    below_minimum.outputs_mut()[1].amount = Some(8);
    below_minimum.outputs_mut()[2].amount = Some(2);
    below_minimum.outputs_mut()[3].amount = Some(FUNDING_VALUE - 14 - FEE);
    sign_input(&signer, &mut below_minimum, 1);
    let below_minimum = below_minimum
        .extract_tx()
        .expect("below-minimum transaction");
    let below_minimum_rejection =
        assert_mempool_rejects(&rpc, &below_minimum, "maker_fill_below_minimum");

    let mut sell_base_partial_pset = sell_base_partial_pset;
    sign_input(&signer, &mut sell_base_partial_pset, 1);
    let sell_base_partial = sell_base_partial_pset
        .extract_tx()
        .expect("SellBase partial transaction");
    accept_broadcast_mine(&rpc, &miner, &sell_base_partial);
    let (mut sell_base_full_pset, sell_base_full_plan) = build_sell_base_fill(
        &signer,
        &network,
        sell_base.owned.params,
        &sell_base.owned.keys.maker_receive_spk,
        &wallet_utxo(&sell_base_partial, 1),
        &funding[5],
        7,
        3,
    );
    assert_eq!(sell_base_full_plan.next_state(), MakerOrderState::Consumed);
    sign_input(&signer, &mut sell_base_full_pset, 1);
    let sell_base_full = sell_base_full_pset
        .extract_tx()
        .expect("SellBase full transaction");
    accept_broadcast_mine(&rpc, &miner, &sell_base_full);

    let sell_quote = &orders[1];
    let (sell_quote_partial_pset, sell_quote_partial_plan) = build_sell_quote_fill(
        &signer,
        &network,
        sell_quote.owned.params,
        &sell_quote.owned.keys.maker_receive_spk,
        &sell_quote.output,
        &no_change,
        &funding[6],
        3,
        0,
    );
    assert_eq!(
        sell_quote_partial_plan.next_state(),
        MakerOrderState::Active {
            remaining_base: 7,
            total_filled_base: 3,
        }
    );
    let mut wrong_remainder = sell_quote_partial_pset.clone();
    wrong_remainder.outputs_mut()[1].amount = Some(48);
    wrong_remainder.outputs_mut()[2].amount = Some(22);
    sign_input(&signer, &mut wrong_remainder, 1);
    sign_input(&signer, &mut wrong_remainder, 2);
    let wrong_remainder = wrong_remainder
        .extract_tx()
        .expect("wrong-remainder transaction");
    let wrong_remainder_rejection =
        assert_mempool_rejects(&rpc, &wrong_remainder, "maker_wrong_remainder_amount");

    let mut wrong_remainder_script = sell_quote_partial_pset.clone();
    wrong_remainder_script.outputs_mut()[1].script_pubkey = signer.get_address().script_pubkey();
    sign_input(&signer, &mut wrong_remainder_script, 1);
    sign_input(&signer, &mut wrong_remainder_script, 2);
    let wrong_remainder_script = wrong_remainder_script
        .extract_tx()
        .expect("wrong-remainder-script transaction");
    let wrong_remainder_script_rejection = assert_mempool_rejects(
        &rpc,
        &wrong_remainder_script,
        "maker_wrong_remainder_script",
    );

    let mut sell_quote_partial_pset = sell_quote_partial_pset;
    sign_input(&signer, &mut sell_quote_partial_pset, 1);
    sign_input(&signer, &mut sell_quote_partial_pset, 2);
    let sell_quote_partial = sell_quote_partial_pset
        .extract_tx()
        .expect("SellQuote partial transaction");
    accept_broadcast_mine(&rpc, &miner, &sell_quote_partial);
    let (mut sell_quote_full_pset, sell_quote_full_plan) = build_sell_quote_fill(
        &signer,
        &network,
        sell_quote.owned.params,
        &sell_quote.owned.keys.maker_receive_spk,
        &wallet_utxo(&sell_quote_partial, 1),
        &wallet_utxo(&sell_quote_partial, 3),
        &funding[7],
        7,
        3,
    );
    assert_eq!(sell_quote_full_plan.next_state(), MakerOrderState::Consumed);
    sign_input(&signer, &mut sell_quote_full_pset, 1);
    sign_input(&signer, &mut sell_quote_full_pset, 2);
    let sell_quote_full = sell_quote_full_pset
        .extract_tx()
        .expect("SellQuote full transaction");
    accept_broadcast_mine(&rpc, &miner, &sell_quote_full);

    let cancelled = &orders[2];
    let cancellation_pset = build_maker_cancellation(
        &signer,
        cancelled.owned.params,
        &cancelled.output,
        &funding[8],
    );
    let mut untweaked_cancel = cancellation_pset.clone();
    sign_input(&signer, &mut untweaked_cancel, 1);
    sign_maker_cancellation(
        &mut untweaked_cancel,
        0,
        &cancelled.owned,
        genesis_hash,
        false,
    );
    let untweaked_cancel = untweaked_cancel
        .extract_tx()
        .expect("untweaked cancellation transaction");
    let untweaked_cancel_rejection =
        assert_mempool_rejects(&rpc, &untweaked_cancel, "maker_untweaked_cancellation_key");
    let mut cancellation_pset = cancellation_pset;
    sign_input(&signer, &mut cancellation_pset, 1);
    sign_maker_cancellation(
        &mut cancellation_pset,
        0,
        &cancelled.owned,
        genesis_hash,
        true,
    );
    let cancellation = cancellation_pset
        .extract_tx()
        .expect("maker cancellation transaction");
    accept_broadcast_mine(&rpc, &miner, &cancellation);

    let (resolution, resolved_state) = build_active_resolution(
        &signer,
        &network,
        market.params,
        trading,
        &active_live(&issuance),
        &issuance.output[2],
        &funding[9],
        BinaryOutcome::Yes,
        RtSide::B,
    );
    assert!(matches!(
        resolved_state,
        BinaryMarketState::ResolvedYes { .. }
    ));
    let resolution_accepted = accept_broadcast_mine(&rpc, &miner, &resolution);

    // Feed the exact same chain through the production node path. The store
    // starts before market creation, scans the parent from its public hint,
    // then accepts all four maker declarations late and backfills their full
    // histories before any order becomes routable.
    let source = Arc::new(
        ElementsRpcChainSource::new(ElementsRpcConfig::new(
            client.rpc_url(),
            node_elements_auth(&client.auth()),
        ))
        .expect("production Elements chain source"),
    );
    let database_directory = tempfile::tempdir().expect("maker node database directory");
    let database_path = database_directory.path().join("deadcat.redb");
    let store = Arc::new(Store::open(&database_path).expect("open maker node store"));
    store
        .bind_chain(StoreChainIdentity {
            network: LiquidNetwork::ElementsRegtest,
            genesis_hash,
            policy_asset,
        })
        .expect("bind maker node chain");
    store.initialize_tip(baseline).expect("initialize baseline");
    let interpreter = DeadcatInterpreter::new(LiquidNetwork::ElementsRegtest, policy_asset);
    eprintln!("DEADCAT_MAKER_REGTEST_PHASE=initial_sync");
    let SyncOutcome::Ready(initial_sync) =
        SyncCoordinator::new(source.as_ref(), store.as_ref(), &interpreter)
            .sync_to_tip()
            .await
            .expect("initial production node sync")
    else {
        panic!("live maker chain unexpectedly required a rescan")
    };
    assert!(initial_sync.blocks_applied >= 9);
    let resolution_tip = source.tip().await.expect("resolution tip");
    let market_id = ContractId::new(OutPoint::new(market.transaction.txid(), 0));
    let discovered_market = store
        .contract(market_id)
        .expect("read discovered market")
        .expect("market auto-discovered from its canonical hint");
    assert_eq!(
        discovered_market.state,
        ContractState::BinaryMarket(resolved_state)
    );
    assert!(orders.iter().all(|order| {
        store
            .contract(order.contract_id)
            .expect("order lookup")
            .is_none()
    }));

    let package = ContractPackage {
        format_version: CONTRACT_PACKAGE_FORMAT_VERSION,
        chain: ChainIdentity {
            network: LiquidNetwork::ElementsRegtest,
            genesis_hash,
        },
        roots: orders.iter().map(|order| order.contract_id).collect(),
        declarations: orders
            .iter()
            .map(|order| ContractDeclaration {
                contract_id: order.contract_id,
                descriptor: ContractDescriptor::MakerOrderV1 {
                    parent_market: market_id,
                    side: order.side,
                    params: order.owned.params,
                },
            })
            .chain(std::iter::once(ContractDeclaration {
                contract_id: market_id,
                descriptor: ContractDescriptor::BinaryMarketV1 {
                    params: market.params,
                },
            }))
            .collect(),
    };
    let handler = NodeRpcHandler::new(
        Arc::clone(&source),
        Arc::clone(&store),
        maker_rpc_config(genesis_hash, policy_asset, baseline, resolution_tip),
    )
    .expect("production node RPC handler");
    eprintln!("DEADCAT_MAKER_REGTEST_PHASE=package_registration");
    let Response::RegistrationAccepted { registration } = node_response(
        &handler,
        Request::RegisterContractPackage {
            package: package.clone(),
            bearer_token: None,
        },
    )
    .await
    else {
        panic!("registration returned the wrong response")
    };
    assert_eq!(registration.roots, package.roots);
    assert_eq!(registration.contracts.len(), 5);
    for receipt in &registration.contracts {
        assert_eq!(
            receipt.already_registered,
            receipt.contract_id == market_id,
            "only the hint-discovered market should predate package registration"
        );
    }
    eprintln!("DEADCAT_MAKER_REGTEST_PHASE=late_backfill");
    let SyncOutcome::Ready(backfill) =
        SyncCoordinator::new(source.as_ref(), store.as_ref(), &interpreter)
            .sync_to_tip()
            .await
            .expect("maker late-registration backfill")
    else {
        panic!("maker backfill unexpectedly required a rescan")
    };
    assert!(backfill.backfill_blocks_applied > 0);
    assert_eq!(
        stored_maker_state(&store, orders[0].contract_id),
        MakerOrderState::Consumed
    );
    assert_eq!(
        stored_maker_state(&store, orders[1].contract_id),
        MakerOrderState::Consumed
    );
    assert_eq!(
        stored_maker_state(&store, orders[2].contract_id),
        MakerOrderState::Cancelled
    );
    assert_eq!(
        stored_maker_state(&store, orders[3].contract_id),
        MakerOrderState::Active {
            remaining_base: MAKER_CAPACITY,
            total_filled_base: 0,
        }
    );
    for (order, expected_kinds) in orders.iter().zip([
        vec![TRANSITION_V1_MAKER_FILLED, TRANSITION_V1_MAKER_FILLED],
        vec![TRANSITION_V1_MAKER_FILLED, TRANSITION_V1_MAKER_FILLED],
        vec![TRANSITION_V1_MAKER_CANCELLED],
        vec![],
    ]) {
        let history = store
            .contract_history(order.contract_id)
            .expect("maker history after backfill");
        assert_eq!(
            history
                .iter()
                .map(|entry| entry.transition.kind)
                .collect::<Vec<_>>(),
            expected_kinds
        );
    }
    let active_orders = store
        .ready_orders(market_id, None, None, None, 10)
        .expect("ready maker orders");
    assert_eq!(active_orders.items.len(), 1);
    assert_eq!(
        active_orders.items[0].contract.contract_id,
        orders[3].contract_id
    );

    let Response::RecoveryHints { page: hints } = node_response(
        &handler,
        Request::ListRecoveryHints {
            family: Some(RecoveryFamily::MakerOrderV1),
            page: PageRequest {
                cursor: None,
                limit: 100,
            },
        },
    )
    .await
    else {
        panic!("recovery-hint query returned the wrong response")
    };
    let creation_hints = hints
        .hints
        .iter()
        .filter(|hint| hint.creation_txid == order_creation.txid())
        .collect::<Vec<_>>();
    assert_eq!(creation_hints.len(), 4);
    assert!(
        creation_hints
            .iter()
            .all(|hint| hint.associated_contract.is_none())
    );
    assert_eq!(
        creation_hints
            .iter()
            .map(|hint| hint.location.output_index)
            .collect::<Vec<_>>(),
        vec![1, 3, 5, 7]
    );
    for order in &orders {
        let record = creation_hints
            .iter()
            .find(|record| record.location.output_index == order.hint_vout)
            .expect("RPC recovery record for every created order");
        let on_chain_payload = validate_recovery_txout(
            &order_creation.output[order.hint_vout as usize],
            policy_asset,
        )
        .expect("on-chain recovery hint payload");
        assert_eq!(record.payload, on_chain_payload);
        assert_eq!(record.payload, order.owned.recovery_hint.encode());
    }

    let route_error = handler
        .handle(
            [0x55; 32],
            Request::SuggestRoute {
                market_id,
                side: orders[3].side,
                direction: orders[3].owned.params.direction,
                base_amount: MAKER_CAPACITY,
                max_orders: 1,
            },
        )
        .await
        .expect_err("official routing must stop after parent resolution");
    assert_eq!(route_error.code, RpcErrorCode::CovenantInvariantViolation);

    let post_resolution = &orders[3];
    let (mut post_resolution_fill_pset, post_resolution_plan) = build_sell_base_fill(
        &signer,
        &network,
        post_resolution.owned.params,
        &post_resolution.owned.keys.maker_receive_spk,
        &post_resolution.output,
        &funding[10],
        MAKER_CAPACITY,
        0,
    );
    assert_eq!(post_resolution_plan.next_state(), MakerOrderState::Consumed);
    sign_input(&signer, &mut post_resolution_fill_pset, 1);
    let post_resolution_fill = post_resolution_fill_pset
        .extract_tx()
        .expect("post-resolution maker fill");
    assert_eq!(
        test_mempool_accept(&rpc, &post_resolution_fill).allowed,
        Some(true),
        "maker covenant intentionally remains consensus-fillable after parent resolution"
    );
    let post_resolution_accepted = accept_broadcast_mine(&rpc, &miner, &post_resolution_fill);

    eprintln!("DEADCAT_MAKER_REGTEST_PHASE=post_fill_sync");
    let SyncOutcome::Ready(post_fill_sync) =
        SyncCoordinator::new(source.as_ref(), store.as_ref(), &interpreter)
            .sync_to_tip()
            .await
            .expect("index post-resolution custom fill")
    else {
        panic!("post-resolution fill unexpectedly required a rescan")
    };
    assert_eq!(post_fill_sync.blocks_applied, 1);
    assert_eq!(
        stored_maker_state(&store, post_resolution.contract_id),
        MakerOrderState::Consumed
    );
    assert_eq!(
        store
            .contract_history(post_resolution.contract_id)
            .expect("post-resolution order history")
            .iter()
            .map(|entry| entry.transition.kind)
            .collect::<Vec<_>>(),
        vec![TRANSITION_V1_MAKER_FILLED]
    );
    assert!(
        store
            .ready_orders(market_id, None, None, None, 10)
            .expect("empty terminal order book")
            .items
            .is_empty()
    );

    // Replace the final two blocks with a different canonical branch while
    // explicitly controlling which mempool transactions enter each block.
    // This exercises the production coordinator's full two-block rollback and
    // replay boundary with the same semantic state on different block hashes.
    let mining_address = signer.get_address().to_unconfidential().to_string();
    let mine_exact = |txids: Vec<String>| -> String {
        let result: JsonValue = rpc
            .call(
                "generateblock",
                &[json!(mining_address.clone()), json!(txids)],
            )
            .expect("mine exact regtest block");
        result["hash"]
            .as_str()
            .expect("generateblock hash")
            .to_owned()
    };
    let invalidated: JsonValue = rpc
        .call(
            "invalidateblock",
            &[json!(resolution_accepted.block_hash.clone())],
        )
        .expect("invalidate resolution block");
    assert!(invalidated.is_null());
    let replacement_resolution_hash = mine_exact(vec![resolution.txid().to_string()]);
    let replacement_post_fill_hash = mine_exact(vec![post_resolution_fill.txid().to_string()]);
    assert_ne!(replacement_resolution_hash, resolution_accepted.block_hash);
    assert_ne!(
        replacement_post_fill_hash,
        post_resolution_accepted.block_hash
    );
    eprintln!("DEADCAT_MAKER_REGTEST_PHASE=two_block_reorg");
    let SyncOutcome::Ready(two_block_reorg) =
        SyncCoordinator::new(source.as_ref(), store.as_ref(), &interpreter)
            .sync_to_tip()
            .await
            .expect("two-block live reorg")
    else {
        panic!("two-block live reorg exceeded retention")
    };
    assert_eq!(two_block_reorg.blocks_rolled_back, 2);
    assert_eq!(two_block_reorg.blocks_applied, 2);
    assert_eq!(
        stored_maker_state(&store, post_resolution.contract_id),
        MakerOrderState::Consumed
    );

    // Replace only the post-resolution fill block with an empty block. The
    // parent remains resolved while the maker order returns to Active, proving
    // that official routing still refuses it. Mine the still-valid custom fill
    // one block later and index it again.
    let invalidated: JsonValue = rpc
        .call(
            "invalidateblock",
            &[json!(replacement_post_fill_hash.clone())],
        )
        .expect("invalidate post-resolution fill block");
    assert!(invalidated.is_null());
    let empty_replacement_hash = mine_exact(vec![]);
    assert_ne!(empty_replacement_hash, replacement_post_fill_hash);
    eprintln!("DEADCAT_MAKER_REGTEST_PHASE=one_block_reorg");
    let SyncOutcome::Ready(one_block_reorg) =
        SyncCoordinator::new(source.as_ref(), store.as_ref(), &interpreter)
            .sync_to_tip()
            .await
            .expect("one-block live reorg")
    else {
        panic!("one-block live reorg exceeded retention")
    };
    assert_eq!(one_block_reorg.blocks_rolled_back, 1);
    assert_eq!(one_block_reorg.blocks_applied, 1);
    assert_eq!(
        store
            .contract(market_id)
            .expect("resolved market after one-block reorg")
            .expect("resolved market after one-block reorg")
            .state,
        ContractState::BinaryMarket(resolved_state)
    );
    assert_eq!(
        stored_maker_state(&store, post_resolution.contract_id),
        MakerOrderState::Active {
            remaining_base: MAKER_CAPACITY,
            total_filled_base: 0,
        }
    );
    let restored_record = store
        .contract(post_resolution.contract_id)
        .expect("restored order lookup")
        .expect("restored active order");
    assert_eq!(restored_record.outpoints.len(), 1);
    assert_eq!(
        restored_record.outpoints[0].outpoint,
        post_resolution.output.outpoint
    );
    assert!(
        store
            .contract_history(post_resolution.contract_id)
            .expect("rolled-back order history")
            .is_empty()
    );
    let restored_book = store
        .ready_orders(market_id, None, None, None, 10)
        .expect("restored active order index");
    assert_eq!(restored_book.items.len(), 1);
    assert_eq!(
        restored_book.items[0].contract.contract_id,
        post_resolution.contract_id
    );
    assert_eq!(restored_book.items[0].entry.remaining_base, MAKER_CAPACITY);
    let route_error = handler
        .handle(
            [0x55; 32],
            Request::SuggestRoute {
                market_id,
                side: post_resolution.side,
                direction: post_resolution.owned.params.direction,
                base_amount: MAKER_CAPACITY,
                max_orders: 1,
            },
        )
        .await
        .expect_err("routing stays disabled while the custom fill is rolled back");
    assert_eq!(route_error.code, RpcErrorCode::CovenantInvariantViolation);

    let final_post_fill_hash = mine_exact(vec![post_resolution_fill.txid().to_string()]);
    assert_ne!(final_post_fill_hash, post_resolution_accepted.block_hash);
    eprintln!("DEADCAT_MAKER_REGTEST_PHASE=post_reorg_fill_replay");
    let SyncOutcome::Ready(post_reorg_fill_replay) =
        SyncCoordinator::new(source.as_ref(), store.as_ref(), &interpreter)
            .sync_to_tip()
            .await
            .expect("index post-reorg custom fill")
    else {
        panic!("post-reorg fill unexpectedly required a rescan")
    };
    assert_eq!(post_reorg_fill_replay.blocks_applied, 1);
    assert_eq!(
        stored_maker_state(&store, post_resolution.contract_id),
        MakerOrderState::Consumed
    );

    // Close every redb handle, reopen the database, retry the package and sync,
    // then independently replay RPC history/evidence through client logic.
    drop(handler);
    drop(store);
    eprintln!("DEADCAT_MAKER_REGTEST_PHASE=restart");
    let reopened = Arc::new(Store::open(&database_path).expect("reopen maker node store"));
    let SyncOutcome::Ready(restart_sync) =
        SyncCoordinator::new(source.as_ref(), reopened.as_ref(), &interpreter)
            .sync_to_tip()
            .await
            .expect("idempotent sync after restart")
    else {
        panic!("restarted live maker node unexpectedly required a rescan")
    };
    assert_eq!(restart_sync.blocks_applied, 0);
    assert_eq!(restart_sync.blocks_rolled_back, 0);
    assert_eq!(restart_sync.backfill_blocks_applied, 0);
    let final_tip = source.tip().await.expect("final canonical tip");
    let reopened_handler = NodeRpcHandler::new(
        Arc::clone(&source),
        Arc::clone(&reopened),
        maker_rpc_config(genesis_hash, policy_asset, baseline, final_tip),
    )
    .expect("reopened production node RPC handler");
    let Response::RegistrationAccepted {
        registration: repeated,
    } = node_response(
        &reopened_handler,
        Request::RegisterContractPackage {
            package: package.clone(),
            bearer_token: None,
        },
    )
    .await
    else {
        panic!("idempotent registration returned the wrong response")
    };
    assert_eq!(repeated.roots, package.roots);
    assert_eq!(repeated.contracts.len(), package.declarations.len());
    for declaration in &package.declarations {
        let receipt = repeated
            .contracts
            .iter()
            .find(|receipt| receipt.contract_id == declaration.contract_id)
            .expect("idempotent receipt for every declared contract");
        assert!(receipt.already_registered);
    }

    eprintln!("DEADCAT_MAKER_REGTEST_PHASE=client_replay");
    let (parent_view, parent_history) =
        assert_rpc_contract_replay(&reopened_handler, source.as_ref(), market_id, None).await;
    assert!(matches!(
        parent_view.state,
        ContractStateView::BinaryMarket {
            state: BinaryMarketState::ResolvedYes { .. }
        }
    ));
    assert!(
        parent_history
            .entries
            .iter()
            .any(|entry| entry.txid == resolution.txid())
    );
    for (index, order) in orders.iter().enumerate() {
        let (view, history) = assert_rpc_contract_replay(
            &reopened_handler,
            source.as_ref(),
            order.contract_id,
            Some(&parent_view),
        )
        .await;
        let expected_state = match index {
            0 | 1 | 3 => MakerOrderState::Consumed,
            2 => MakerOrderState::Cancelled,
            _ => unreachable!(),
        };
        assert_eq!(
            view.state,
            ContractStateView::MakerOrder {
                state: expected_state,
            }
        );
        let expected_kinds = match index {
            0 | 1 => vec![TRANSITION_V1_MAKER_FILLED, TRANSITION_V1_MAKER_FILLED],
            2 => vec![TRANSITION_V1_MAKER_CANCELLED],
            3 => vec![TRANSITION_V1_MAKER_FILLED],
            _ => unreachable!(),
        };
        assert_eq!(
            history
                .entries
                .iter()
                .map(|entry| entry.transition_kind)
                .collect::<Vec<_>>(),
            expected_kinds
        );
    }

    let report = json!({
        "schema": "deadcat.maker-regtest.v1",
        "market_id": ContractId::new(OutPoint::new(market.transaction.txid(), 0)).to_string(),
        "order_ids": orders.iter().map(|order| order.contract_id.to_string()).collect::<Vec<_>>(),
        "canonical_resolution_block": replacement_resolution_hash,
        "canonical_post_resolution_fill_block": final_post_fill_hash,
        "negative_tests": [
            wrong_payment_rejection,
            wrong_receive_rejection,
            below_minimum_rejection,
            wrong_remainder_rejection,
            wrong_remainder_script_rejection,
            untweaked_cancel_rejection,
        ],
    });
    eprintln!(
        "DEADCAT_MAKER_REGTEST_METRICS={}",
        serde_json::to_string(&report).expect("serialize maker metrics")
    );
}

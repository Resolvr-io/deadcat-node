//! Serial, production-shaped Deadcat protocol lifecycles on liquidregtest.
//!
//! This test is ignored by ordinary `cargo test` because it starts an isolated
//! `elementsd` + Electrs pair. It is required by `just ci` through the explicit
//! `just regtest` suite. Its focused recipes are `just regtest-market-ab` and
//! `just regtest-multi-market`,
//! `just regtest-backend-equivalence`, and `just regtest-process-boundary`.

#[path = "support/process.rs"]
mod process_support;

use std::collections::HashMap;
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use bitcoincore_rpc::{Auth, Client, RpcApi};
use deadcat_client::market_builder::{
    BinaryMarketCreationPlan, BinaryMarketLiveInputs, BinaryMarketTransitionPlan,
    MarketCreationContext, MarketIssuanceEntropies, MarketRtInput, OracleAttestation,
};
use deadcat_client::validation::replay_contract_history;
use deadcat_contracts::SimplicityNetwork;
use deadcat_contracts::binary_market::{
    BinaryMarketAction, BinaryMarketEconomics, BinaryMarketSlot, BinaryMarketTransition,
    BinaryOutcome, CompiledBinaryMarket, derived_binary_market,
};
use deadcat_contracts::market_crypto::{
    BinaryOutcome as OracleOutcome, derive_issuance_assets, oracle_message,
};
use deadcat_contracts::recovery::{MarketCollateral, MarketRecoveryHint};
use deadcat_contracts::rt::{RtLeg, RtSide, add_mod_order, cbf, factors, infer_side};
use deadcat_iroh::RequestHandler as _;
use deadcat_node::chain::elements_rpc::{
    ElementsRpcAuth, ElementsRpcChainSource, ElementsRpcConfig,
};
use deadcat_node::chain::esplora::{EsploraChainSource, EsploraConfig};
use deadcat_node::chain::{ChainSource as _, ChainSourceError, TransactionStatus};
use deadcat_node::interpreter::{DeadcatInterpreter, TRANSITION_V1_MARKET_ISSUED};
use deadcat_node::registration::RegistrationVerifier;
use deadcat_node::rpc_handler::{NodeRpcHandler, RpcHandlerConfig};
use deadcat_node::store::{
    BlockDelta, ChainIdentity as StoreChainIdentity, ContractParameters, ContractState, Store,
    StoreError, StoredEvent,
};
use deadcat_node::sync::{SyncCoordinator, SyncOutcome};
use deadcat_rpc::{
    BackendKind, ContractHistoryPage, ContractStateView, ContractView, Event, EventEnvelope,
    Request, Response, RpcErrorCode, SyncStatus, TransactionEvidence,
};
use deadcat_types::{
    BinaryMarketParams, BinaryMarketState, CONTRACT_PACKAGE_FORMAT_VERSION, ChainAnchor,
    ChainIdentity, ChainPosition, ContractDeclaration, ContractDescriptor, ContractId,
    ContractPackage, ContractSyncState, LiquidNetwork,
};
use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::pset::{Input as PsetInput, Output as PsetOutput, PartiallySignedTransaction};
use elements::secp256k1_zkp::rand::thread_rng;
use elements::secp256k1_zkp::{Keypair, Message, Secp256k1, SecretKey, SurjectionProof, Tweak};
use elements::{
    AssetId, BlockHash, OutPoint, Script, Transaction, TxOut, TxOutSecrets, TxOutWitness,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use simplex::program::{ProgramTrait as _, WitnessTrait as _};
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
    let has_confidential_funding =
        yes_funding.txout.value.is_confidential() || no_funding.txout.value.is_confidential();
    let change_value = FUNDING_VALUE * 2 - FEE;
    let change = if has_confidential_funding {
        balanced_change(
            signer,
            change_value,
            policy_asset,
            &[
                yes_funding.secrets,
                explicit_secrets(params.yes_reissuance_token_id, 1),
                no_funding.secrets,
                explicit_secrets(params.no_reissuance_token_id, 1),
            ],
            &[
                rt_secrets(params.yes_reissuance_token_id, RtLeg::Yes, RtSide::A),
                rt_secrets(params.no_reissuance_token_id, RtLeg::No, RtSide::A),
                explicit_secrets(policy_asset, 0),
            ],
        )
    } else {
        explicit_txout(
            policy_asset,
            change_value,
            signer.get_address().script_pubkey(),
        )
    };
    pset.add_output(PsetOutput::from_txout(change));
    pset.add_output(PsetOutput::from_txout(TxOut::new_fee(FEE, policy_asset)));
    plan.finalize_rt_proofs(&mut pset)
        .expect("creation RT proofs");
    sign_input(signer, &mut pset, 0);
    sign_input(signer, &mut pset, 1);
    let transaction = pset.extract_tx().expect("creation transaction");
    if has_confidential_funding {
        assert!(transaction.output[3].value.is_confidential());
    } else {
        assert_eq!(transaction.output[3].asset, Asset::Explicit(policy_asset));
        assert_eq!(transaction.output[3].value, Value::Explicit(change_value));
    }
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
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("registration runtime");
    let activation_height = creation_anchor
        .height
        .checked_sub(1)
        .expect("live creation is after regtest genesis");
    let activation = ChainAnchor {
        height: activation_height,
        hash: runtime
            .block_on(source.block_hash(activation_height))
            .expect("pre-creation activation hash"),
    };
    let creation_block = runtime
        .block_on(source.block(creation_anchor.hash))
        .expect("canonical creation block");
    assert_eq!(creation_block.header.prev_blockhash, activation.hash);
    store
        .initialize_chain(
            StoreChainIdentity {
                network: chain.network,
                genesis_hash: chain.genesis_hash,
                policy_asset,
            },
            activation,
        )
        .expect("bind store chain and activation");
    store
        .apply_block(&BlockDelta {
            anchor: creation_anchor,
            prev_block_hash: activation.hash,
            ordered_txids: creation_block
                .txdata
                .iter()
                .map(Transaction::txid)
                .collect(),
            relevant_transactions: Vec::new(),
            recovery_hints: Vec::new(),
        })
        .expect("index canonical creation block");
    let verifier = RegistrationVerifier::new(
        &source,
        &store,
        LiquidNetwork::ElementsRegtest,
        genesis_hash,
        policy_asset,
    );
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

fn assert_rt_pair_at(
    transaction: &Transaction,
    output_base: usize,
    params: BinaryMarketParams,
    side: RtSide,
) {
    let yes = &transaction.output[output_base];
    let no = &transaction.output[output_base + 1];
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

fn assert_reissuances_at(
    transaction: &Transaction,
    input_base: usize,
    entropies: MarketIssuanceEntropies,
    side: RtSide,
    pairs: u64,
) {
    for (input, entropy) in transaction.input[input_base..input_base + 2]
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

#[derive(Clone)]
struct ComposedMarketPlans {
    first: BinaryMarketTransitionPlan,
    second: BinaryMarketTransitionPlan,
}

fn explicit_value(txout: &TxOut) -> u64 {
    let Value::Explicit(value) = txout.value else {
        panic!("test wallet output value must be explicit")
    };
    value
}

#[allow(clippy::too_many_arguments)]
fn build_composed_mixed_market_issuances(
    signer: &Signer,
    network: &SimplicityNetwork,
    first: &CreatedMarket,
    first_before: BinaryMarketState,
    first_live: &BinaryMarketLiveInputs,
    first_collateral_txout: &TxOut,
    first_pairs: u64,
    second: &CreatedMarket,
    second_before: BinaryMarketState,
    second_live: &BinaryMarketLiveInputs,
    second_pairs: u64,
    funding: &Funding,
) -> (PartiallySignedTransaction, ComposedMarketPlans) {
    let first_plan = BinaryMarketTransitionPlan::new(
        first.params,
        first_before,
        BinaryMarketAction::Issue { pairs: first_pairs },
        first_live.clone(),
        None,
    )
    .expect("first composed market issuance plan");
    let second_plan = BinaryMarketTransitionPlan::new(
        second.params,
        second_before,
        BinaryMarketAction::Issue {
            pairs: second_pairs,
        },
        second_live.clone(),
        None,
    )
    .expect("second composed market issuance plan");

    let first_yes = first_live.yes_rt.as_ref().expect("first live YES RT");
    let first_no = first_live.no_rt.as_ref().expect("first live NO RT");
    let second_yes = second_live.yes_rt.as_ref().expect("second live YES RT");
    let second_no = second_live.no_rt.as_ref().expect("second live NO RT");
    let mut pset = PartiallySignedTransaction::new_v2();
    pset.add_input(pset_input(first_yes.outpoint, first_yes.txout.clone()));
    pset.add_input(pset_input(first_no.outpoint, first_no.txout.clone()));
    pset.add_input(pset_input(
        first_live.collateral.expect("first live market collateral"),
        first_collateral_txout.clone(),
    ));
    pset.add_input(pset_input(second_yes.outpoint, second_yes.txout.clone()));
    pset.add_input(pset_input(second_no.outpoint, second_no.txout.clone()));
    assert!(
        second_live.collateral.is_none(),
        "second market must use the two-input initial-issuance path"
    );
    pset.add_input(pset_input(funding.outpoint, funding.txout.clone()));

    // The three-input subsequent issuance and two-input initial issuance own
    // disjoint three-output windows. Neither plan assumes that its window
    // begins at zero or that it owns the complete transaction.
    for (_, output) in first_plan
        .mandatory_outputs(0)
        .expect("first composed market outputs")
    {
        pset.add_output(PsetOutput::from_txout(output));
    }
    for (_, output) in second_plan
        .mandatory_outputs(3)
        .expect("second composed market outputs")
    {
        pset.add_output(PsetOutput::from_txout(output));
    }
    for (asset, value) in [
        (first.params.yes_token_asset_id, first_pairs),
        (first.params.no_token_asset_id, first_pairs),
        (second.params.yes_token_asset_id, second_pairs),
        (second.params.no_token_asset_id, second_pairs),
    ] {
        pset.add_output(PsetOutput::from_txout(explicit_txout(
            asset,
            value,
            signer.get_address().script_pubkey(),
        )));
    }

    let first_economics =
        BinaryMarketEconomics::new(first.params.base_payout).expect("first economics");
    let second_economics =
        BinaryMarketEconomics::new(second.params.base_payout).expect("second economics");
    let BinaryMarketState::Trading {
        outstanding_pairs: first_old_pairs,
    } = first_before
    else {
        panic!("first composed issuance must start in Trading")
    };
    let BinaryMarketState::Trading {
        outstanding_pairs: first_new_pairs,
    } = first_plan.after()
    else {
        panic!("first composed issuance must end in Trading")
    };
    let BinaryMarketState::Trading {
        outstanding_pairs: second_old_pairs,
    } = second_before
    else {
        panic!("second composed issuance must start in Trading")
    };
    let BinaryMarketState::Trading {
        outstanding_pairs: second_new_pairs,
    } = second_plan.after()
    else {
        panic!("second composed issuance must end in Trading")
    };
    let first_old_collateral = first_economics
        .collateral_for_pairs(first_old_pairs)
        .expect("first old collateral");
    let first_new_collateral = first_economics
        .collateral_for_pairs(first_new_pairs)
        .expect("first new collateral");
    let second_old_collateral = second_economics
        .collateral_for_pairs(second_old_pairs)
        .expect("second old collateral");
    let second_new_collateral = second_economics
        .collateral_for_pairs(second_new_pairs)
        .expect("second new collateral");
    assert_eq!(explicit_value(first_collateral_txout), first_old_collateral);
    assert_eq!(second_old_collateral, 0);
    let funding_change = FUNDING_VALUE
        .checked_add(first_old_collateral)
        .and_then(|value| value.checked_add(second_old_collateral))
        .and_then(|value| value.checked_sub(first_new_collateral))
        .and_then(|value| value.checked_sub(second_new_collateral))
        .and_then(|value| value.checked_sub(FEE))
        .expect("two-market funding change");
    pset.add_output(PsetOutput::from_txout(explicit_txout(
        first.params.collateral_asset_id,
        funding_change,
        signer.get_address().script_pubkey(),
    )));
    pset.add_output(PsetOutput::from_txout(TxOut::new_fee(
        FEE,
        first.params.collateral_asset_id,
    )));
    assert_eq!(
        first.params.collateral_asset_id,
        second.params.collateral_asset_id
    );
    assert_eq!(pset.inputs().len(), 6);
    assert_eq!(pset.outputs().len(), 12);

    first_plan
        .configure_reissuance_inputs(&mut pset, 0, first.entropies)
        .expect("configure first composed reissuances");
    second_plan
        .configure_reissuance_inputs(&mut pset, 3, second.entropies)
        .expect("configure second composed reissuances");
    first_plan
        .finalize(&mut pset, 0, 0, network)
        .expect("finalize first composed market covenants");
    second_plan
        .finalize(&mut pset, 3, 3, network)
        .expect("finalize second composed market covenants");

    (
        pset,
        ComposedMarketPlans {
            first: first_plan,
            second: second_plan,
        },
    )
}

#[allow(clippy::too_many_arguments)]
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

fn node_rpc_config(
    _genesis_hash: BlockHash,
    _policy_asset: AssetId,
    _baseline: ChainAnchor,
    _tip: ChainAnchor,
) -> RpcHandlerConfig {
    RpcHandlerConfig {
        backend: BackendKind::ElementsRpc,
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

fn stored_market_state(store: &Store, contract_id: ContractId) -> BinaryMarketState {
    let record = store
        .contract(contract_id)
        .expect("read market contract")
        .expect("registered market contract");
    assert!(matches!(record.sync_state, ContractSyncState::Ready { .. }));
    let ContractState::BinaryMarket(state) = record.state;
    state
}

fn stored_contract_outpoints(store: &Store, contract_id: ContractId) -> Vec<(u8, OutPoint)> {
    let mut outpoints = store
        .contract(contract_id)
        .expect("read contract outpoints")
        .expect("registered contract")
        .outpoints
        .into_iter()
        .map(|tracked| (tracked.role, tracked.outpoint))
        .collect::<Vec<_>>();
    outpoints.sort();
    outpoints
}

fn assert_tracked_outpoints(
    store: &Store,
    contract_id: ContractId,
    mut expected: Vec<(u8, OutPoint)>,
) {
    expected.sort();
    assert_eq!(stored_contract_outpoints(store, contract_id), expected);
    for (role, outpoint) in expected {
        let owner = store
            .outpoint_owner(outpoint)
            .expect("read outpoint owner")
            .expect("tracked outpoint owner");
        assert_eq!(owner.contract_id, contract_id);
        assert_eq!(owner.role, role);
    }
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

fn rebuild_pruned_market_followers_from_divergent_witnesses(
    pset: &mut PartiallySignedTransaction,
    plan: &BinaryMarketTransitionPlan,
    params: BinaryMarketParams,
    network: &SimplicityNetwork,
) {
    let compiled = CompiledBinaryMarket::new(params).expect("compile canonical market");
    for (input_index, slot, path, output_base, signature, tokens_burned, redeem_yes) in [
        (
            1,
            BinaryMarketSlot::UnresolvedNoRt,
            u8::MAX,
            u32::MAX,
            [0xa5; 64],
            u64::MAX,
            true,
        ),
        (
            2,
            BinaryMarketSlot::UnresolvedCollateral,
            9,
            u32::MAX - 1,
            [0x5a; 64],
            u64::MAX - 1,
            false,
        ),
    ] {
        let canonical = pset.inputs()[input_index]
            .final_script_witness
            .as_ref()
            .expect("canonical follower witness")
            .clone();
        let witness = derived_binary_market::BinaryMarketWitness {
            path,
            slot: slot as u8,
            output_base,
            oracle_outcome_yes: input_index == 1,
            oracle_signature: signature,
            tokens_burned,
            redeem_yes,
        };
        compiled
            .program(slot)
            .as_ref()
            .execute(pset, &witness.build_witness(), input_index, network)
            .unwrap_or_else(|error| panic!("divergent {slot:?} follower: {error}"));
        let mut rebuilt = compiled
            .program(slot)
            .as_ref()
            .finalize(pset, &witness.build_witness(), input_index, network)
            .expect("finalize divergent follower witness");
        match canonical.len() {
            4 => {}
            5 => rebuilt.push(canonical[4].clone()),
            length => panic!("unexpected canonical follower stack length {length}"),
        }
        pset.inputs_mut()[input_index].final_script_witness = Some(rebuilt);
    }
    assert_eq!(
        plan.path(),
        deadcat_contracts::interpret::BinaryMarketPath::PartialCancellation
    );
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
    rebuild_pruned_market_followers_from_divergent_witnesses(&mut pset, &plan, params, network);
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

const ELECTRS_SYNC_TIMEOUT: Duration = Duration::from_secs(20);

async fn wait_for_esplora_tip(source: &EsploraChainSource, expected: ChainAnchor) {
    let deadline = tokio::time::Instant::now() + ELECTRS_SYNC_TIMEOUT;
    loop {
        let latest = source.tip().await;
        if latest.as_ref().is_ok_and(|actual| *actual == expected) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "Electrs did not reach {expected:?} within {ELECTRS_SYNC_TIMEOUT:?}; latest={latest:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_esplora_status(
    source: &EsploraChainSource,
    txid: elements::Txid,
    expected: TransactionStatus,
) {
    let deadline = tokio::time::Instant::now() + ELECTRS_SYNC_TIMEOUT;
    loop {
        let latest = source.transaction_status(txid).await;
        if latest.as_ref().is_ok_and(|actual| *actual == expected) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "Electrs did not report {txid} as {expected:?} within {ELECTRS_SYNC_TIMEOUT:?}; latest={latest:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_esplora_issuance(
    source: &EsploraChainSource,
    asset_id: AssetId,
    expected: elements::Txid,
) {
    let deadline = tokio::time::Instant::now() + ELECTRS_SYNC_TIMEOUT;
    loop {
        let latest = source.issuance_transaction(asset_id).await;
        if latest
            .as_ref()
            .is_ok_and(|actual| *actual == Some(expected))
        {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "Electrs did not index asset {asset_id} from {expected} within {ELECTRS_SYNC_TIMEOUT:?}; latest={latest:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_esplora_history(
    source: &EsploraChainSource,
    script: &Script,
    expected: &[elements::Txid],
) -> Vec<elements::Txid> {
    let deadline = tokio::time::Instant::now() + ELECTRS_SYNC_TIMEOUT;
    loop {
        let latest = source.script_history(script).await;
        if let Ok(history) = &latest
            && expected.iter().all(|txid| history.contains(txid))
        {
            return history.clone();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "Electrs did not index expected script history within {ELECTRS_SYNC_TIMEOUT:?}; expected={expected:?}; latest={latest:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn assert_live_chain_equivalence(
    elements: &ElementsRpcChainSource,
    esplora: &EsploraChainSource,
    first_height: u32,
) -> ChainAnchor {
    let expected_tip = elements.tip().await.expect("Elements canonical tip");
    wait_for_esplora_tip(esplora, expected_tip).await;
    assert_eq!(
        esplora.tip().await.expect("Esplora canonical tip"),
        expected_tip
    );

    let mut heights = vec![0];
    heights.extend(first_height..=expected_tip.height);
    heights.sort_unstable();
    heights.dedup();
    for height in heights {
        let elements_hash = elements
            .block_hash(height)
            .await
            .expect("Elements block hash");
        let esplora_hash = esplora
            .block_hash(height)
            .await
            .expect("Esplora block hash");
        assert_eq!(esplora_hash, elements_hash, "block hash at height {height}");

        let elements_block = elements
            .block(elements_hash)
            .await
            .expect("Elements raw block");
        let esplora_block = esplora
            .block(esplora_hash)
            .await
            .expect("Esplora raw block");
        assert_eq!(
            elements::encode::serialize(&esplora_block),
            elements::encode::serialize(&elements_block),
            "raw block at height {height}"
        );
    }
    expected_tip
}

async fn assert_live_fee_path(label: &str, source: &impl deadcat_node::chain::ChainSource) {
    match source.estimate_fee_rate(2).await {
        Ok(rate) => assert!(
            rate.is_finite() && rate > 0.0,
            "{label} returned invalid fee rate {rate}"
        ),
        Err(ChainSourceError::Unavailable(_)) => {
            // A fresh deterministic regtest does not necessarily have enough
            // fee history. Reaching this typed result still exercises the
            // production endpoint and its no-estimate semantics.
        }
        Err(error) => panic!("{label} fee path failed unexpectedly: {error}"),
    }
}

fn assert_market_store_equivalence(
    elements_store: &Store,
    esplora_store: &Store,
    market_id: ContractId,
) {
    assert_eq!(
        esplora_store.tip().expect("Esplora-backed store tip"),
        elements_store.tip().expect("Elements-backed store tip")
    );
    assert_eq!(
        esplora_store
            .sync_status()
            .expect("Esplora-backed sync status"),
        elements_store
            .sync_status()
            .expect("Elements-backed sync status")
    );

    let elements_record = elements_store
        .contract(market_id)
        .expect("Elements-backed market lookup")
        .expect("Elements-backed market");
    let esplora_record = esplora_store
        .contract(market_id)
        .expect("Esplora-backed market lookup")
        .expect("Esplora-backed market");
    assert_eq!(esplora_record, elements_record);

    let elements_history = elements_store
        .contract_history(market_id)
        .expect("Elements-backed market history");
    let esplora_history = esplora_store
        .contract_history(market_id)
        .expect("Esplora-backed market history");
    assert_eq!(esplora_history, elements_history);

    let positions = std::iter::once(elements_record.creation_position)
        .chain(elements_history.iter().map(|entry| entry.position));
    for position in positions {
        assert_eq!(
            esplora_store
                .transaction(position)
                .expect("Esplora-backed transaction evidence"),
            elements_store
                .transaction(position)
                .expect("Elements-backed transaction evidence"),
            "transaction evidence at {position:?}"
        );
    }
    for tracked in elements_record.outpoints {
        assert_eq!(
            esplora_store
                .output(tracked.outpoint)
                .expect("Esplora-backed output evidence"),
            elements_store
                .output(tracked.outpoint)
                .expect("Elements-backed output evidence"),
            "output evidence for {:?}",
            tracked.outpoint
        );
        assert_eq!(
            esplora_store
                .outpoint_owner(tracked.outpoint)
                .expect("Esplora-backed outpoint owner"),
            elements_store
                .outpoint_owner(tracked.outpoint)
                .expect("Elements-backed outpoint owner"),
            "outpoint owner for {:?}",
            tracked.outpoint
        );
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
    let mut transplanted_follower_stack = partial_cancel.clone();
    transplanted_follower_stack.input[0].witness.script_witness = transplanted_follower_stack.input
        [1]
    .witness
    .script_witness
    .clone();
    let transplanted_follower = assert_mempool_rejects(
        &rpc,
        &transplanted_follower_stack,
        "market_follower_stack_as_coordinator",
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
        "negative_tests": [missing, malformed, transplanted_follower],
    });
    eprintln!(
        "DEADCAT_MARKET_AB_METRICS={}",
        serde_json::to_string(&report).expect("serialize market metrics")
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "starts elementsd and liquid-enabled Electrs from the Nix development shell"]
async fn elements_and_esplora_backends_index_the_same_live_chain() {
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
    let elements_source = ElementsRpcChainSource::new(ElementsRpcConfig::new(
        client.rpc_url(),
        node_elements_auth(&client.auth()),
    ))
    .expect("production Elements chain source");
    let esplora_source = EsploraChainSource::new(EsploraConfig::new(client.esplora_url()))
        .expect("production Esplora chain source");

    let (funding_tx, funding_accepted, funding) =
        prepare_funding(&signer, &rpc, &miner, policy_asset);
    let baseline = ChainAnchor {
        height: u32::try_from(funding_accepted.block_height).expect("baseline height"),
        hash: BlockHash::from_str(&funding_accepted.block_hash).expect("baseline hash"),
    };
    assert_eq!(
        assert_live_chain_equivalence(&elements_source, &esplora_source, baseline.height).await,
        baseline
    );

    let market = create_market(
        &signer,
        &rpc,
        &miner,
        policy_asset,
        &funding[0],
        &funding[1],
        baseline.height.checked_add(1_000).expect("future expiry"),
    );
    let market_id = ContractId::new(OutPoint::new(market.transaction.txid(), 0));
    let (issuance, trading_state) = build_issuance(
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
        INITIAL_PAIRS,
        RtSide::A,
        false,
    );
    assert_eq!(
        trading_state,
        BinaryMarketState::Trading {
            outstanding_pairs: INITIAL_PAIRS,
        }
    );

    let acceptance = test_mempool_accept(&rpc, &issuance);
    assert_eq!(
        acceptance.allowed,
        Some(true),
        "elementsd rejected Esplora broadcast fixture: {:?}",
        acceptance.reject_reason
    );
    assert_eq!(
        esplora_source
            .broadcast(&issuance)
            .await
            .expect("broadcast issuance through production Esplora source"),
        issuance.txid()
    );
    wait_for_esplora_status(
        &esplora_source,
        issuance.txid(),
        TransactionStatus::Unconfirmed,
    )
    .await;
    assert_eq!(
        elements_source
            .transaction_status(issuance.txid())
            .await
            .expect("Elements unconfirmed issuance status"),
        TransactionStatus::Unconfirmed
    );
    assert_eq!(
        esplora_source
            .transaction(issuance.txid())
            .await
            .expect("Esplora unconfirmed issuance transaction"),
        elements_source
            .transaction(issuance.txid())
            .await
            .expect("Elements unconfirmed issuance transaction")
    );

    let mining_address = signer.get_address().to_unconfidential().to_string();
    let mine_exact = |txids: Vec<String>| -> String {
        let result: JsonValue = rpc
            .call(
                "generateblock",
                &[json!(mining_address.clone()), json!(txids)],
            )
            .expect("mine exact backend-equivalence block");
        result["hash"]
            .as_str()
            .expect("generateblock hash")
            .to_owned()
    };
    let original_issuance_hash = mine_exact(vec![issuance.txid().to_string()]);
    let initial_tip =
        assert_live_chain_equivalence(&elements_source, &esplora_source, baseline.height).await;
    assert_eq!(initial_tip.hash.to_string(), original_issuance_hash);

    for transaction in [&market.transaction, &issuance] {
        let txid = transaction.txid();
        assert_eq!(
            elements_source
                .transaction(txid)
                .await
                .expect("Elements canonical transaction"),
            *transaction
        );
        assert_eq!(
            esplora_source
                .transaction(txid)
                .await
                .expect("Esplora canonical transaction"),
            *transaction
        );
        let elements_status = elements_source
            .transaction_status(txid)
            .await
            .expect("Elements canonical transaction status");
        wait_for_esplora_status(&esplora_source, txid, elements_status).await;
        assert_eq!(
            esplora_source
                .transaction_status(txid)
                .await
                .expect("Esplora canonical transaction status"),
            elements_status
        );
    }

    let spent_market_outpoint = OutPoint::new(market.transaction.txid(), 0);
    let esplora_outspend = esplora_source
        .outspend(spent_market_outpoint)
        .await
        .expect("Esplora confirmed outspend")
        .expect("spent market RT");
    assert_eq!(esplora_outspend.spending_txid, issuance.txid());
    assert!(matches!(
        esplora_outspend.status,
        TransactionStatus::Confirmed { .. }
    ));
    assert!(matches!(
        elements_source.outspend(spent_market_outpoint).await,
        Err(ChainSourceError::Unsupported(_))
    ));
    let unspent_issuance_outpoint = OutPoint::new(issuance.txid(), 0);
    assert_eq!(
        esplora_source
            .outspend(unspent_issuance_outpoint)
            .await
            .expect("Esplora unspent output"),
        elements_source
            .outspend(unspent_issuance_outpoint)
            .await
            .expect("Elements unspent output")
    );

    for asset_id in [
        market.params.yes_token_asset_id,
        market.params.no_token_asset_id,
    ] {
        wait_for_esplora_issuance(&esplora_source, asset_id, market.transaction.txid()).await;
    }
    let expected_wallet_history = [
        funding_tx.txid(),
        market.transaction.txid(),
        issuance.txid(),
    ];
    let wallet_history = wait_for_esplora_history(
        &esplora_source,
        &signer.get_address().script_pubkey(),
        &expected_wallet_history,
    )
    .await;
    let wallet_positions = expected_wallet_history.map(|txid| {
        wallet_history
            .iter()
            .position(|candidate| *candidate == txid)
            .expect("expected wallet transaction in Esplora history")
    });
    assert!(wallet_positions.windows(2).all(|pair| pair[0] < pair[1]));
    assert_live_fee_path("Elements RPC", &elements_source).await;
    assert_live_fee_path("Esplora", &esplora_source).await;

    let elements_directory = tempfile::tempdir().expect("Elements-backed database directory");
    let esplora_directory = tempfile::tempdir().expect("Esplora-backed database directory");
    let elements_store = Store::open(elements_directory.path().join("deadcat.redb"))
        .expect("open Elements-backed store");
    let esplora_store = Store::open(esplora_directory.path().join("deadcat.redb"))
        .expect("open Esplora-backed store");
    let identity = StoreChainIdentity {
        network: LiquidNetwork::ElementsRegtest,
        genesis_hash,
        policy_asset,
    };
    elements_store
        .initialize_chain(identity, baseline)
        .expect("initialize Elements-backed store");
    esplora_store
        .initialize_chain(identity, baseline)
        .expect("initialize Esplora-backed store");
    let interpreter = DeadcatInterpreter::new(LiquidNetwork::ElementsRegtest, policy_asset);

    let SyncOutcome::Ready(elements_initial) =
        SyncCoordinator::new(&elements_source, &elements_store, &interpreter)
            .sync_to_tip()
            .await
            .expect("initial Elements-backed sync")
    else {
        panic!("initial Elements-backed sync unexpectedly required a rescan")
    };
    let SyncOutcome::Ready(esplora_initial) =
        SyncCoordinator::new(&esplora_source, &esplora_store, &interpreter)
            .sync_to_tip()
            .await
            .expect("initial Esplora-backed sync")
    else {
        panic!("initial Esplora-backed sync unexpectedly required a rescan")
    };
    assert_eq!(esplora_initial, elements_initial);
    assert_eq!(elements_initial.blocks_applied, 2);
    assert_eq!(
        stored_market_state(&elements_store, market_id),
        trading_state
    );
    assert_market_store_equivalence(&elements_store, &esplora_store, market_id);
    let original_history = elements_store
        .contract_history(market_id)
        .expect("original market history");
    assert_eq!(original_history.len(), 1);
    let original_position = original_history[0].position;

    let invalidated: JsonValue = rpc
        .call("invalidateblock", &[json!(original_issuance_hash.clone())])
        .expect("invalidate original issuance block");
    assert!(invalidated.is_null());
    let empty_replacement_hash = mine_exact(vec![]);
    assert_ne!(empty_replacement_hash, original_issuance_hash);
    let replacement_tip =
        assert_live_chain_equivalence(&elements_source, &esplora_source, baseline.height).await;
    assert_eq!(replacement_tip.height, initial_tip.height);
    assert_eq!(replacement_tip.hash.to_string(), empty_replacement_hash);

    let SyncOutcome::Ready(elements_reorg) =
        SyncCoordinator::new(&elements_source, &elements_store, &interpreter)
            .sync_to_tip()
            .await
            .expect("Elements-backed one-block reorg")
    else {
        panic!("Elements-backed one-block reorg unexpectedly required a rescan")
    };
    let SyncOutcome::Ready(esplora_reorg) =
        SyncCoordinator::new(&esplora_source, &esplora_store, &interpreter)
            .sync_to_tip()
            .await
            .expect("Esplora-backed one-block reorg")
    else {
        panic!("Esplora-backed one-block reorg unexpectedly required a rescan")
    };
    assert_eq!(esplora_reorg, elements_reorg);
    assert_eq!(elements_reorg.blocks_rolled_back, 1);
    assert_eq!(elements_reorg.blocks_applied, 1);
    assert_eq!(
        stored_market_state(&elements_store, market_id),
        BinaryMarketState::Trading {
            outstanding_pairs: 0,
        }
    );
    assert!(
        elements_store
            .contract_history(market_id)
            .expect("rolled-back market history")
            .is_empty()
    );
    assert!(
        elements_store
            .transaction(original_position)
            .expect("rolled-back original evidence")
            .is_none()
    );
    assert_market_store_equivalence(&elements_store, &esplora_store, market_id);

    let moved_issuance_hash = mine_exact(vec![issuance.txid().to_string()]);
    let moved_tip =
        assert_live_chain_equivalence(&elements_source, &esplora_source, baseline.height).await;
    assert_eq!(moved_tip.hash.to_string(), moved_issuance_hash);
    assert_eq!(moved_tip.height, initial_tip.height + 1);
    let moved_status = elements_source
        .transaction_status(issuance.txid())
        .await
        .expect("moved Elements issuance status");
    wait_for_esplora_status(&esplora_source, issuance.txid(), moved_status).await;

    let SyncOutcome::Ready(elements_remine) =
        SyncCoordinator::new(&elements_source, &elements_store, &interpreter)
            .sync_to_tip()
            .await
            .expect("Elements-backed issuance remine")
    else {
        panic!("Elements-backed issuance remine unexpectedly required a rescan")
    };
    let SyncOutcome::Ready(esplora_remine) =
        SyncCoordinator::new(&esplora_source, &esplora_store, &interpreter)
            .sync_to_tip()
            .await
            .expect("Esplora-backed issuance remine")
    else {
        panic!("Esplora-backed issuance remine unexpectedly required a rescan")
    };
    assert_eq!(esplora_remine, elements_remine);
    assert_eq!(elements_remine.blocks_applied, 1);
    assert_eq!(elements_remine.blocks_rolled_back, 0);
    assert_eq!(
        stored_market_state(&elements_store, market_id),
        trading_state
    );
    assert_market_store_equivalence(&elements_store, &esplora_store, market_id);

    let moved_history = elements_store
        .contract_history(market_id)
        .expect("moved market history");
    assert_eq!(moved_history.len(), 1);
    let moved_position = moved_history[0].position;
    assert_eq!(
        moved_position.block_height,
        original_position.block_height + 1
    );
    assert_ne!(moved_position, original_position);
    assert!(
        elements_store
            .transaction(original_position)
            .expect("stale original evidence")
            .is_none()
    );
    let moved_evidence = elements_store
        .transaction(moved_position)
        .expect("moved transaction evidence")
        .expect("canonical moved issuance evidence");
    assert_eq!(
        elements::encode::deserialize::<Transaction>(&moved_evidence.raw_tx)
            .expect("decode moved issuance evidence"),
        issuance
    );
    let moved_outspend = esplora_source
        .outspend(spent_market_outpoint)
        .await
        .expect("Esplora moved outspend")
        .expect("moved issuance spends the market RT");
    assert_eq!(moved_outspend.spending_txid, issuance.txid());
    assert_eq!(moved_outspend.status, moved_status);
    assert!(matches!(
        elements_source.outspend(spent_market_outpoint).await,
        Err(ChainSourceError::Unsupported(_))
    ));
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "starts elementsd and liquid-enabled Electrs from the Nix development shell"]
async fn multi_market_transaction_is_accepted_and_indexed_by_elementsd() {
    const FIRST_INITIAL_PAIRS: u64 = 30;
    const FIRST_COMPOSED_PAIRS: u64 = 10;
    const SECOND_COMPOSED_PAIRS: u64 = 7;

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
    let first_market = create_market(
        &signer,
        &rpc,
        &miner,
        policy_asset,
        &funding[0],
        &funding[1],
        expiry_height,
    );
    let second_market = create_market(
        &signer,
        &rpc,
        &miner,
        policy_asset,
        &funding[2],
        &funding[3],
        expiry_height,
    );
    let initial_state = BinaryMarketState::Trading {
        outstanding_pairs: 0,
    };
    let (first_issuance, first_pre_state) = build_issuance(
        &signer,
        &network,
        first_market.params,
        first_market.entropies,
        initial_state,
        &dormant_live(&first_market.transaction),
        None,
        &funding[4],
        FIRST_INITIAL_PAIRS,
        RtSide::A,
        false,
    );
    accept_broadcast_mine(&rpc, &miner, &first_issuance);
    let second_pre_state = initial_state;
    assert_eq!(
        first_pre_state,
        BinaryMarketState::Trading {
            outstanding_pairs: FIRST_INITIAL_PAIRS,
        }
    );
    assert_eq!(
        second_pre_state,
        BinaryMarketState::Trading {
            outstanding_pairs: 0,
        }
    );

    let source = Arc::new(
        ElementsRpcChainSource::new(ElementsRpcConfig::new(
            client.rpc_url(),
            node_elements_auth(&client.auth()),
        ))
        .expect("production Elements chain source"),
    );
    let database_directory = tempfile::tempdir().expect("multi-market database directory");
    let database_path = database_directory.path().join("deadcat.redb");
    let store = Arc::new(Store::open(&database_path).expect("open multi-market store"));
    store
        .initialize_chain(
            StoreChainIdentity {
                network: LiquidNetwork::ElementsRegtest,
                genesis_hash,
                policy_asset,
            },
            baseline,
        )
        .expect("initialize multi-market chain");
    let interpreter = DeadcatInterpreter::new(LiquidNetwork::ElementsRegtest, policy_asset);
    eprintln!("DEADCAT_MULTI_MARKET_REGTEST_PHASE=initial_sync");
    let SyncOutcome::Ready(initial_sync) =
        SyncCoordinator::new(source.as_ref(), store.as_ref(), &interpreter)
            .sync_to_tip()
            .await
            .expect("initial multi-market sync")
    else {
        panic!("initial multi-market sync unexpectedly required a rescan")
    };
    assert_eq!(initial_sync.blocks_applied, 3);

    let first_id = ContractId::new(OutPoint::new(first_market.transaction.txid(), 0));
    let second_id = ContractId::new(OutPoint::new(second_market.transaction.txid(), 0));
    assert_ne!(first_id, second_id);
    assert_eq!(stored_market_state(&store, first_id), first_pre_state);
    assert_eq!(stored_market_state(&store, second_id), second_pre_state);
    assert_tracked_outpoints(
        &store,
        first_id,
        vec![
            (
                BinaryMarketSlot::UnresolvedYesRt as u8,
                OutPoint::new(first_issuance.txid(), 0),
            ),
            (
                BinaryMarketSlot::UnresolvedNoRt as u8,
                OutPoint::new(first_issuance.txid(), 1),
            ),
            (
                BinaryMarketSlot::UnresolvedCollateral as u8,
                OutPoint::new(first_issuance.txid(), 2),
            ),
        ],
    );
    assert_tracked_outpoints(
        &store,
        second_id,
        vec![
            (
                BinaryMarketSlot::DormantYesRt as u8,
                OutPoint::new(second_market.transaction.txid(), 0),
            ),
            (
                BinaryMarketSlot::DormantNoRt as u8,
                OutPoint::new(second_market.transaction.txid(), 1),
            ),
        ],
    );

    let package = ContractPackage {
        format_version: CONTRACT_PACKAGE_FORMAT_VERSION,
        chain: ChainIdentity {
            network: LiquidNetwork::ElementsRegtest,
            genesis_hash,
        },
        roots: vec![first_id, second_id],
        declarations: vec![
            ContractDeclaration {
                contract_id: first_id,
                descriptor: ContractDescriptor::BinaryMarketV1 {
                    params: first_market.params,
                },
            },
            ContractDeclaration {
                contract_id: second_id,
                descriptor: ContractDescriptor::BinaryMarketV1 {
                    params: second_market.params,
                },
            },
        ],
    };
    let registration_tip = source.tip().await.expect("registration tip");
    let handler = NodeRpcHandler::new(
        Arc::clone(&source),
        Arc::clone(&store),
        node_rpc_config(genesis_hash, policy_asset, baseline, registration_tip),
    )
    .expect("multi-market RPC handler");
    eprintln!("DEADCAT_MULTI_MARKET_REGTEST_PHASE=package_registration");
    let Response::RegistrationAccepted { registration } = node_response(
        &handler,
        Request::RegisterContractPackage {
            package: package.clone(),
            bearer_token: None,
        },
    )
    .await
    else {
        panic!("multi-market registration returned the wrong response")
    };
    assert_eq!(registration.roots, package.roots);
    assert_eq!(registration.contracts.len(), 2);
    assert!(
        registration
            .contracts
            .iter()
            .all(|receipt| receipt.already_registered)
    );
    let first_pre_history = store
        .contract_history(first_id)
        .expect("first pre-composition market history");
    let second_pre_history = store
        .contract_history(second_id)
        .expect("second pre-composition market history");
    assert_eq!(first_pre_history.len(), 1);
    assert!(second_pre_history.is_empty());
    assert_eq!(first_pre_history[0].txid, first_issuance.txid());

    let (base_pset, plans) = build_composed_mixed_market_issuances(
        &signer,
        &network,
        &first_market,
        first_pre_state,
        &active_live(&first_issuance),
        &first_issuance.output[2],
        FIRST_COMPOSED_PAIRS,
        &second_market,
        second_pre_state,
        &dormant_live(&second_market.transaction),
        SECOND_COMPOSED_PAIRS,
        &funding[5],
    );
    let first_post_state = BinaryMarketState::Trading {
        outstanding_pairs: FIRST_INITIAL_PAIRS + FIRST_COMPOSED_PAIRS,
    };
    let second_post_state = BinaryMarketState::Trading {
        outstanding_pairs: SECOND_COMPOSED_PAIRS,
    };
    assert_eq!(plans.first.after(), first_post_state);
    assert_eq!(plans.second.after(), second_post_state);
    assert_eq!(plans.first.path() as u8, 1);
    assert_eq!(plans.second.path() as u8, 0);

    // Keep the first market leg and all asset/value balances valid while
    // redirecting only the second market's collateral continuation. The
    // second covenant must reject, making the complete transaction invalid.
    let mut wrong_second_continuation = base_pset.clone();
    assert_ne!(
        wrong_second_continuation.outputs()[5].script_pubkey,
        signer.get_address().script_pubkey()
    );
    wrong_second_continuation.outputs_mut()[5].script_pubkey = signer.get_address().script_pubkey();
    sign_input(&signer, &mut wrong_second_continuation, 5);
    let wrong_second_continuation = wrong_second_continuation
        .extract_tx()
        .expect("balanced wrong-second-market transaction");
    let wrong_second_rejection = assert_mempool_rejects(
        &rpc,
        &wrong_second_continuation,
        "multi_market_wrong_second_collateral_continuation",
    );

    let mut valid_pset = base_pset;
    sign_input(&signer, &mut valid_pset, 5);
    let composed = valid_pset
        .extract_tx()
        .expect("composed two-market transaction");
    assert_eq!(composed.input.len(), 6);
    assert_eq!(composed.output.len(), 12);
    assert_reissuances_at(
        &composed,
        0,
        first_market.entropies,
        RtSide::B,
        FIRST_COMPOSED_PAIRS,
    );
    assert_reissuances_at(
        &composed,
        3,
        second_market.entropies,
        RtSide::A,
        SECOND_COMPOSED_PAIRS,
    );
    assert_rt_pair_at(&composed, 0, first_market.params, RtSide::A);
    assert_rt_pair_at(&composed, 3, second_market.params, RtSide::B);
    assert_eq!(composed.output[2].value, Value::Explicit(8_000));
    assert_eq!(composed.output[5].value, Value::Explicit(1_400));
    assert_eq!(
        composed.output[10].value,
        Value::Explicit(
            FUNDING_VALUE - (FIRST_COMPOSED_PAIRS + SECOND_COMPOSED_PAIRS) * BASE_PAYOUT * 2 - FEE
        )
    );
    assert_eq!(composed.output[11].value, Value::Explicit(FEE));
    eprintln!("DEADCAT_MULTI_MARKET_REGTEST_PHASE=consensus_acceptance");
    let composed_accepted = accept_broadcast_mine(&rpc, &miner, &composed);
    let original_block_hash =
        BlockHash::from_str(&composed_accepted.block_hash).expect("original composed block hash");
    let before_composed_cursor = store
        .event_high_watermark()
        .expect("event cursor before composed indexing");

    eprintln!("DEADCAT_MULTI_MARKET_REGTEST_PHASE=atomic_indexing");
    let SyncOutcome::Ready(applied) =
        SyncCoordinator::new(source.as_ref(), store.as_ref(), &interpreter)
            .sync_to_tip()
            .await
            .expect("index composed two-market transaction")
    else {
        panic!("composed two-market sync unexpectedly required a rescan")
    };
    assert_eq!(applied.blocks_applied, 1);
    assert_eq!(applied.blocks_rolled_back, 0);
    assert_eq!(stored_market_state(&store, first_id), first_post_state);
    assert_eq!(stored_market_state(&store, second_id), second_post_state);
    assert_tracked_outpoints(
        &store,
        first_id,
        vec![
            (
                BinaryMarketSlot::UnresolvedYesRt as u8,
                OutPoint::new(composed.txid(), 0),
            ),
            (
                BinaryMarketSlot::UnresolvedNoRt as u8,
                OutPoint::new(composed.txid(), 1),
            ),
            (
                BinaryMarketSlot::UnresolvedCollateral as u8,
                OutPoint::new(composed.txid(), 2),
            ),
        ],
    );
    assert_tracked_outpoints(
        &store,
        second_id,
        vec![
            (
                BinaryMarketSlot::UnresolvedYesRt as u8,
                OutPoint::new(composed.txid(), 3),
            ),
            (
                BinaryMarketSlot::UnresolvedNoRt as u8,
                OutPoint::new(composed.txid(), 4),
            ),
            (
                BinaryMarketSlot::UnresolvedCollateral as u8,
                OutPoint::new(composed.txid(), 5),
            ),
        ],
    );
    for spent in [
        OutPoint::new(first_issuance.txid(), 0),
        OutPoint::new(first_issuance.txid(), 1),
        OutPoint::new(first_issuance.txid(), 2),
        OutPoint::new(second_market.transaction.txid(), 0),
        OutPoint::new(second_market.transaction.txid(), 1),
    ] {
        assert!(
            store
                .outpoint_owner(spent)
                .expect("read spent owner")
                .is_none()
        );
    }

    let first_post_history = store
        .contract_history(first_id)
        .expect("first post-composition market history");
    let second_post_history = store
        .contract_history(second_id)
        .expect("second post-composition market history");
    assert_eq!(first_post_history.len(), 2);
    assert_eq!(second_post_history.len(), 1);
    let first_entry = first_post_history
        .iter()
        .find(|entry| entry.txid == composed.txid())
        .expect("first composed market transition");
    let second_entry = second_post_history
        .iter()
        .find(|entry| entry.txid == composed.txid())
        .expect("second composed market transition");
    let original_position = first_entry.position;
    assert_eq!(second_entry.position, original_position);
    assert_eq!(
        original_position.block_height,
        u32::try_from(composed_accepted.block_height).expect("composed height")
    );
    for (entry, before, after, plan) in [
        (first_entry, first_pre_state, first_post_state, &plans.first),
        (
            second_entry,
            second_pre_state,
            second_post_state,
            &plans.second,
        ),
    ] {
        assert_eq!(entry.old_state, ContractState::BinaryMarket(before));
        assert_eq!(entry.new_state, ContractState::BinaryMarket(after));
        assert_eq!(entry.transition.kind, TRANSITION_V1_MARKET_ISSUED);
        let BinaryMarketTransition::Issued {
            pairs,
            collateral_locked,
        } = plan.transition()
        else {
            panic!("composed market plan was not an issuance")
        };
        let mut expected_payload = vec![plan.path() as u8];
        expected_payload.extend_from_slice(&pairs.to_be_bytes());
        expected_payload.extend_from_slice(&collateral_locked.to_be_bytes());
        assert_eq!(entry.transition.payload, expected_payload);
    }

    let mut expected_affected = vec![first_id, second_id];
    expected_affected.sort();
    let composed_events = store
        .events_after(Some(before_composed_cursor), 100)
        .expect("events from composed indexing");
    let applied_events = composed_events
        .iter()
        .filter(|event| {
            matches!(
                &event.event,
                StoredEvent::TransactionApplied { txid, .. } if *txid == composed.txid()
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(applied_events.len(), 1);
    let StoredEvent::TransactionApplied {
        anchor,
        txid,
        position,
        affected_contract_ids,
    } = &applied_events[0].event
    else {
        unreachable!("filtered to the composed TransactionApplied event")
    };
    assert_eq!(
        *anchor,
        ChainAnchor {
            height: original_position.block_height,
            hash: original_block_hash,
        }
    );
    assert_eq!(*txid, composed.txid());
    assert_eq!(*position, original_position);
    assert_eq!(affected_contract_ids, &expected_affected);
    let post_apply_cursor = store
        .event_high_watermark()
        .expect("event cursor after composed indexing");
    let original_evidence = store
        .transaction(original_position)
        .expect("read composed evidence")
        .expect("one shared composed evidence row");
    assert_eq!(original_evidence.block_hash, original_block_hash);
    assert_eq!(original_evidence.txid, composed.txid());
    assert_eq!(
        original_evidence.raw_tx,
        elements::encode::serialize(&composed)
    );
    assert_eq!(original_evidence.affected_contract_ids, expected_affected);
    for (vout, expected_output) in composed.output.iter().enumerate() {
        let stored = store
            .output(OutPoint::new(composed.txid(), vout as u32))
            .expect("read composed output evidence")
            .expect("composed output reference");
        assert_eq!(stored.position, original_position);
        assert_eq!(&stored.output, expected_output);
    }

    drop(handler);
    drop(store);
    eprintln!("DEADCAT_MULTI_MARKET_REGTEST_PHASE=restart");
    let reopened = Arc::new(Store::open(&database_path).expect("reopen multi-market store"));
    let SyncOutcome::Ready(restart_sync) =
        SyncCoordinator::new(source.as_ref(), reopened.as_ref(), &interpreter)
            .sync_to_tip()
            .await
            .expect("idempotent multi-market restart sync")
    else {
        panic!("restarted multi-market node unexpectedly required a rescan")
    };
    assert_eq!(restart_sync.blocks_applied, 0);
    assert_eq!(restart_sync.blocks_rolled_back, 0);
    assert_eq!(restart_sync.backfill_blocks_applied, 0);
    assert_eq!(
        reopened
            .event_high_watermark()
            .expect("restarted event cursor"),
        post_apply_cursor
    );
    assert_eq!(
        reopened
            .contract_history(first_id)
            .expect("restarted first history"),
        first_post_history
    );
    assert_eq!(
        reopened
            .contract_history(second_id)
            .expect("restarted second history"),
        second_post_history
    );
    assert_eq!(
        reopened
            .transaction(original_position)
            .expect("restarted composed evidence"),
        Some(original_evidence.clone())
    );

    let mining_address = signer.get_address().to_unconfidential().to_string();
    let mine_exact = |txids: Vec<String>| -> String {
        let result: JsonValue = rpc
            .call(
                "generateblock",
                &[json!(mining_address.clone()), json!(txids)],
            )
            .expect("mine exact multi-market regtest block");
        result["hash"]
            .as_str()
            .expect("generateblock hash")
            .to_owned()
    };

    // Move the shared transaction one block later on a two-block fork. Both
    // histories and the one evidence row must move together.
    let _original_successor_hash = mine_exact(vec![]);
    let SyncOutcome::Ready(successor_sync) =
        SyncCoordinator::new(source.as_ref(), reopened.as_ref(), &interpreter)
            .sync_to_tip()
            .await
            .expect("index original empty successor")
    else {
        panic!("empty successor unexpectedly required a rescan")
    };
    assert_eq!(successor_sync.blocks_applied, 1);
    let original_branch_tip = source.tip().await.expect("original branch tip");
    let before_two_block_cursor = reopened
        .event_high_watermark()
        .expect("event cursor before two-block reorg");
    let invalidated: JsonValue = rpc
        .call(
            "invalidateblock",
            &[json!(composed_accepted.block_hash.clone())],
        )
        .expect("invalidate original composed block");
    assert!(invalidated.is_null());
    let two_block_ancestor = source.tip().await.expect("two-block reorg ancestor");
    let empty_at_original_height = mine_exact(vec![]);
    let moved_block_hash_string = mine_exact(vec![composed.txid().to_string()]);
    assert_ne!(empty_at_original_height, composed_accepted.block_hash);
    let moved_block_hash =
        BlockHash::from_str(&moved_block_hash_string).expect("moved composed block hash");
    eprintln!("DEADCAT_MULTI_MARKET_REGTEST_PHASE=two_block_reorg");
    let SyncOutcome::Ready(two_block_reorg) =
        SyncCoordinator::new(source.as_ref(), reopened.as_ref(), &interpreter)
            .sync_to_tip()
            .await
            .expect("two-block composed reorg")
    else {
        panic!("two-block composed reorg exceeded retention")
    };
    assert_eq!(two_block_reorg.blocks_rolled_back, 2);
    assert_eq!(two_block_reorg.blocks_applied, 2);
    assert_eq!(stored_market_state(&reopened, first_id), first_post_state);
    assert_eq!(stored_market_state(&reopened, second_id), second_post_state);
    let moved_first_history = reopened
        .contract_history(first_id)
        .expect("moved first history");
    let moved_second_history = reopened
        .contract_history(second_id)
        .expect("moved second history");
    let moved_position = moved_first_history
        .iter()
        .find(|entry| entry.txid == composed.txid())
        .expect("moved first market transition")
        .position;
    assert_eq!(
        moved_position.block_height,
        original_position.block_height + 1
    );
    assert_eq!(
        moved_second_history
            .iter()
            .find(|entry| entry.txid == composed.txid())
            .expect("moved second market transition")
            .position,
        moved_position
    );
    let two_block_events = reopened
        .events_after(Some(before_two_block_cursor), 100)
        .expect("events from two-block reorg");
    let rollback_events = two_block_events
        .iter()
        .filter(|event| matches!(&event.event, StoredEvent::ChainRolledBack { .. }))
        .collect::<Vec<_>>();
    assert_eq!(rollback_events.len(), 1);
    let StoredEvent::ChainRolledBack {
        old_tip,
        new_tip,
        orphaned_positions,
        affected_contract_ids,
    } = &rollback_events[0].event
    else {
        unreachable!("filtered to a ChainRolledBack event")
    };
    assert_eq!(*old_tip, original_branch_tip);
    assert_eq!(*new_tip, two_block_ancestor);
    assert_eq!(orphaned_positions, &[original_position]);
    assert_eq!(affected_contract_ids, &expected_affected);
    let moved_applied_events = two_block_events
        .iter()
        .filter(|event| {
            matches!(
                &event.event,
                StoredEvent::TransactionApplied { txid, .. } if *txid == composed.txid()
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(moved_applied_events.len(), 1);
    assert!(
        rollback_events[0].cursor.sequence < moved_applied_events[0].cursor.sequence,
        "subscription consumers must observe rollback before replacement apply"
    );
    let moved_evidence = reopened
        .transaction(moved_position)
        .expect("moved evidence lookup")
        .expect("moved shared evidence row");
    assert_eq!(moved_evidence.block_hash, moved_block_hash);
    assert_eq!(moved_evidence.raw_tx, original_evidence.raw_tx);
    assert_eq!(moved_evidence.affected_contract_ids, expected_affected);
    assert!(
        reopened
            .transaction(original_position)
            .expect("orphaned original evidence lookup")
            .is_none()
    );

    // Replace the moved transaction with an empty block. Both markets must
    // return to their exact pre-transaction state in one coordinator update.
    let moved_branch_tip = source.tip().await.expect("moved branch tip");
    let before_one_block_cursor = reopened
        .event_high_watermark()
        .expect("event cursor before one-block rollback");
    let invalidated: JsonValue = rpc
        .call("invalidateblock", &[json!(moved_block_hash_string.clone())])
        .expect("invalidate moved composed block");
    assert!(invalidated.is_null());
    let one_block_ancestor = source.tip().await.expect("one-block reorg ancestor");
    let empty_replacement_hash = mine_exact(vec![]);
    assert_ne!(empty_replacement_hash, moved_block_hash_string);
    eprintln!("DEADCAT_MULTI_MARKET_REGTEST_PHASE=one_block_atomic_rollback");
    let SyncOutcome::Ready(one_block_reorg) =
        SyncCoordinator::new(source.as_ref(), reopened.as_ref(), &interpreter)
            .sync_to_tip()
            .await
            .expect("one-block composed rollback")
    else {
        panic!("one-block composed rollback exceeded retention")
    };
    assert_eq!(one_block_reorg.blocks_rolled_back, 1);
    assert_eq!(one_block_reorg.blocks_applied, 1);
    assert_eq!(stored_market_state(&reopened, first_id), first_pre_state);
    assert_eq!(stored_market_state(&reopened, second_id), second_pre_state);
    assert_eq!(
        reopened
            .contract_history(first_id)
            .expect("rolled-back first history"),
        first_pre_history
    );
    assert_eq!(
        reopened
            .contract_history(second_id)
            .expect("rolled-back second history"),
        second_pre_history
    );
    assert!(
        reopened
            .transaction(moved_position)
            .expect("rolled-back moved evidence")
            .is_none()
    );
    for vout in 0..composed.output.len() {
        assert!(
            reopened
                .output(OutPoint::new(composed.txid(), vout as u32))
                .expect("rolled-back output lookup")
                .is_none()
        );
    }
    let one_block_events = reopened
        .events_after(Some(before_one_block_cursor), 100)
        .expect("events from one-block rollback");
    let rollback_events = one_block_events
        .iter()
        .filter(|event| matches!(&event.event, StoredEvent::ChainRolledBack { .. }))
        .collect::<Vec<_>>();
    assert_eq!(rollback_events.len(), 1);
    let StoredEvent::ChainRolledBack {
        old_tip,
        new_tip,
        orphaned_positions,
        affected_contract_ids,
    } = &rollback_events[0].event
    else {
        unreachable!("filtered to a one-block ChainRolledBack event")
    };
    assert_eq!(*old_tip, moved_branch_tip);
    assert_eq!(*new_tip, one_block_ancestor);
    assert_eq!(orphaned_positions, &[moved_position]);
    assert_eq!(affected_contract_ids, &expected_affected);
    assert!(one_block_events.iter().all(|event| {
        !matches!(
            &event.event,
            StoredEvent::TransactionApplied { txid, .. } if *txid == composed.txid()
        )
    }));

    // Mine the same transaction once more and independently replay both market
    // histories through only the public RPC evidence surface.
    let before_final_cursor = reopened
        .event_high_watermark()
        .expect("event cursor before final remine");
    let final_block_hash_string = mine_exact(vec![composed.txid().to_string()]);
    let final_block_hash =
        BlockHash::from_str(&final_block_hash_string).expect("final composed block hash");
    eprintln!("DEADCAT_MULTI_MARKET_REGTEST_PHASE=canonical_remine");
    let SyncOutcome::Ready(final_sync) =
        SyncCoordinator::new(source.as_ref(), reopened.as_ref(), &interpreter)
            .sync_to_tip()
            .await
            .expect("index final composed remine")
    else {
        panic!("final composed remine unexpectedly required a rescan")
    };
    assert_eq!(final_sync.blocks_applied, 1);
    assert_eq!(final_sync.blocks_rolled_back, 0);
    assert_eq!(stored_market_state(&reopened, first_id), first_post_state);
    assert_eq!(stored_market_state(&reopened, second_id), second_post_state);
    let final_first_history = reopened
        .contract_history(first_id)
        .expect("final first history");
    let final_second_history = reopened
        .contract_history(second_id)
        .expect("final second history");
    let final_position = final_first_history
        .iter()
        .find(|entry| entry.txid == composed.txid())
        .expect("final first transition")
        .position;
    assert_eq!(
        final_second_history
            .iter()
            .find(|entry| entry.txid == composed.txid())
            .expect("final second transition")
            .position,
        final_position
    );
    assert_eq!(
        final_position.block_height,
        original_position.block_height + 2
    );
    let final_evidence = reopened
        .transaction(final_position)
        .expect("final evidence lookup")
        .expect("final shared evidence row");
    assert_eq!(final_evidence.block_hash, final_block_hash);
    assert_eq!(final_evidence.raw_tx, original_evidence.raw_tx);
    assert_eq!(final_evidence.affected_contract_ids, expected_affected);
    let final_events = reopened
        .events_after(Some(before_final_cursor), 100)
        .expect("events from final remine");
    assert_eq!(
        final_events
            .iter()
            .filter(|event| {
                matches!(
                    &event.event,
                    StoredEvent::TransactionApplied { txid, .. } if *txid == composed.txid()
                )
            })
            .count(),
        1
    );

    let final_tip = source.tip().await.expect("final multi-market tip");
    let reopened_handler = NodeRpcHandler::new(
        Arc::clone(&source),
        Arc::clone(&reopened),
        node_rpc_config(genesis_hash, policy_asset, baseline, final_tip),
    )
    .expect("final multi-market RPC handler");
    eprintln!("DEADCAT_MULTI_MARKET_REGTEST_PHASE=client_replay");
    for (market_id, expected_state, expected_history_len) in [
        (first_id, first_post_state, 2),
        (second_id, second_post_state, 1),
    ] {
        let (view, history) =
            assert_rpc_contract_replay(&reopened_handler, source.as_ref(), market_id).await;
        assert_eq!(
            view.state,
            ContractStateView::BinaryMarket {
                state: expected_state,
            }
        );
        assert_eq!(history.entries.len(), expected_history_len);
        assert_eq!(
            history
                .entries
                .iter()
                .find(|entry| entry.txid == composed.txid())
                .expect("RPC composed transition")
                .position,
            final_position
        );
    }
    let rpc_evidence = rpc_transaction_evidence(&reopened_handler, final_position).await;
    assert_eq!(rpc_evidence.block_hash, final_block_hash);
    assert_eq!(rpc_evidence.transaction, composed);
    assert_eq!(rpc_evidence.affected_contract_ids, expected_affected);

    // Push the shared transition outside the two-block undo window, replace
    // the complete suffix, and prove an activation-based rebuild preserves
    // both retained market declarations and rematerializes them atomically.
    eprintln!("DEADCAT_MULTI_MARKET_REGTEST_PHASE=deep_reorg_invalidation");
    let _stale_successor_one = mine_exact(vec![]);
    let _stale_successor_two = mine_exact(vec![]);
    let SyncOutcome::Ready(stale_successor_sync) =
        SyncCoordinator::new(source.as_ref(), reopened.as_ref(), &interpreter)
            .sync_to_tip()
            .await
            .expect("index successors beyond undo retention")
    else {
        panic!("successor indexing unexpectedly required a rescan")
    };
    assert_eq!(stale_successor_sync.blocks_applied, 2);
    let stale_branch_tip = source.tip().await.expect("stale branch tip");
    let before_deep_reorg_cursor = reopened
        .event_high_watermark()
        .expect("cursor before deep reorg");
    let retained_before_rebuild = [first_id, second_id]
        .into_iter()
        .map(|contract_id| {
            (
                contract_id,
                reopened
                    .retained_declaration(contract_id)
                    .expect("retained declaration lookup")
                    .expect("market declaration retained"),
            )
        })
        .collect::<Vec<_>>();

    let invalidated: JsonValue = rpc
        .call("invalidateblock", &[json!(final_block_hash_string.clone())])
        .expect("invalidate composed block beyond undo retention");
    assert!(invalidated.is_null());
    let deep_empty_hash_string = mine_exact(vec![]);
    let deep_composed_hash_string = mine_exact(vec![composed.txid().to_string()]);
    let _deep_successor_hash_string = mine_exact(vec![]);
    let deep_composed_hash =
        BlockHash::from_str(&deep_composed_hash_string).expect("deep replacement block hash");
    assert_ne!(deep_empty_hash_string, final_block_hash_string);
    assert_ne!(deep_composed_hash_string, final_block_hash_string);
    let deep_source_tip = source.tip().await.expect("deep replacement tip");
    assert_eq!(deep_source_tip.height, stale_branch_tip.height);

    let SyncOutcome::RescanRequired {
        indexed_tip,
        source_tip,
    } = SyncCoordinator::new(source.as_ref(), reopened.as_ref(), &interpreter)
        .sync_to_tip()
        .await
        .expect("detect real three-block fork")
    else {
        panic!("three-block fork did not enter RescanRequired")
    };
    assert_eq!(indexed_tip, stale_branch_tip);
    assert_eq!(source_tip, deep_source_tip);
    assert_eq!(
        reopened.sync_status().expect("invalidated status"),
        deadcat_rpc::SyncStatus::RescanRequired
    );
    let invalidated_cursor = reopened
        .event_high_watermark()
        .expect("invalidated event cursor");
    assert_ne!(invalidated_cursor.epoch, before_deep_reorg_cursor.epoch);
    assert_eq!(invalidated_cursor.sequence, 1);
    assert_eq!(stored_market_state(&reopened, first_id), first_post_state);
    assert_eq!(stored_market_state(&reopened, second_id), second_post_state);
    assert!(matches!(
        reopened.events_after(Some(before_deep_reorg_cursor), 1),
        Err(StoreError::StaleCursor { .. })
    ));
    let stale_read = reopened_handler
        .handle(
            [0x92; 32],
            Request::GetContract {
                contract_id: first_id,
            },
        )
        .await
        .expect_err("known-stale RPC state must fail closed");
    assert_eq!(stale_read.code, RpcErrorCode::RescanRequired);
    drop(reopened_handler);
    drop(reopened);

    eprintln!("DEADCAT_MULTI_MARKET_REGTEST_PHASE=deep_rebuild_reset");
    let invalidated_store = Store::open(&database_path).expect("reopen invalidated store");
    assert_eq!(
        invalidated_store
            .sync_status()
            .expect("reopened invalidated status"),
        deadcat_rpc::SyncStatus::RescanRequired
    );
    for (contract_id, declaration) in &retained_before_rebuild {
        assert_eq!(
            invalidated_store
                .retained_declaration(*contract_id)
                .expect("reopened retained declaration"),
            Some(*declaration)
        );
    }
    let reset_cursor = invalidated_store
        .reset_for_rebuild()
        .expect("explicit activation reset");
    assert_eq!(reset_cursor.epoch, invalidated_cursor.epoch);
    assert_eq!(invalidated_store.tip().expect("reset tip"), Some(baseline));
    assert_eq!(
        invalidated_store.sync_status().expect("reset status"),
        deadcat_rpc::SyncStatus::Syncing
    );
    for (contract_id, declaration) in &retained_before_rebuild {
        assert!(
            invalidated_store
                .contract(*contract_id)
                .expect("cleared contract lookup")
                .is_none()
        );
        assert_eq!(
            invalidated_store
                .retained_declaration(*contract_id)
                .expect("retained declaration after reset"),
            Some(*declaration)
        );
    }
    drop(invalidated_store);

    eprintln!("DEADCAT_MULTI_MARKET_REGTEST_PHASE=deep_rebuild_replay");
    let rebuilt = Arc::new(Store::open(&database_path).expect("reopen reset store"));
    let SyncOutcome::Ready(deep_rebuild) =
        SyncCoordinator::new(source.as_ref(), rebuilt.as_ref(), &interpreter)
            .rebuild_to_tip()
            .await
            .expect("resume explicit rebuild after reopen")
    else {
        panic!("replacement branch changed deeply during rebuild")
    };
    assert!(deep_rebuild.blocks_applied > 0);
    assert_eq!(deep_rebuild.indexed_tip, deep_source_tip);
    assert_eq!(
        rebuilt.sync_status().expect("rebuilt status"),
        deadcat_rpc::SyncStatus::Ready
    );
    assert_eq!(
        rebuilt
            .event_high_watermark()
            .expect("rebuilt cursor")
            .epoch,
        invalidated_cursor.epoch
    );
    assert_eq!(stored_market_state(&rebuilt, first_id), first_post_state);
    assert_eq!(stored_market_state(&rebuilt, second_id), second_post_state);
    assert_tracked_outpoints(
        &rebuilt,
        first_id,
        vec![
            (
                BinaryMarketSlot::UnresolvedYesRt as u8,
                OutPoint::new(composed.txid(), 0),
            ),
            (
                BinaryMarketSlot::UnresolvedNoRt as u8,
                OutPoint::new(composed.txid(), 1),
            ),
            (
                BinaryMarketSlot::UnresolvedCollateral as u8,
                OutPoint::new(composed.txid(), 2),
            ),
        ],
    );
    assert_tracked_outpoints(
        &rebuilt,
        second_id,
        vec![
            (
                BinaryMarketSlot::UnresolvedYesRt as u8,
                OutPoint::new(composed.txid(), 3),
            ),
            (
                BinaryMarketSlot::UnresolvedNoRt as u8,
                OutPoint::new(composed.txid(), 4),
            ),
            (
                BinaryMarketSlot::UnresolvedCollateral as u8,
                OutPoint::new(composed.txid(), 5),
            ),
        ],
    );
    for (contract_id, declaration) in &retained_before_rebuild {
        assert_eq!(
            rebuilt
                .retained_declaration(*contract_id)
                .expect("retained declaration after replay"),
            Some(*declaration)
        );
    }
    let deep_first_history = rebuilt
        .contract_history(first_id)
        .expect("deep rebuilt first history");
    let deep_second_history = rebuilt
        .contract_history(second_id)
        .expect("deep rebuilt second history");
    let deep_position = deep_first_history
        .iter()
        .find(|entry| entry.txid == composed.txid())
        .expect("deep rebuilt first transition")
        .position;
    assert_eq!(
        deep_second_history
            .iter()
            .find(|entry| entry.txid == composed.txid())
            .expect("deep rebuilt second transition")
            .position,
        deep_position
    );
    assert_eq!(deep_position.block_height, final_position.block_height + 1);
    let deep_evidence = rebuilt
        .transaction(deep_position)
        .expect("deep rebuilt evidence lookup")
        .expect("deep rebuilt shared evidence");
    assert_eq!(deep_evidence.block_hash, deep_composed_hash);
    assert_eq!(deep_evidence.txid, composed.txid());
    assert_eq!(deep_evidence.raw_tx, elements::encode::serialize(&composed));
    assert_eq!(deep_evidence.affected_contract_ids, expected_affected);
    assert!(matches!(
        rebuilt.events_after(Some(before_deep_reorg_cursor), 1),
        Err(StoreError::StaleCursor { .. })
    ));

    let deep_handler = NodeRpcHandler::new(
        Arc::clone(&source),
        Arc::clone(&rebuilt),
        node_rpc_config(genesis_hash, policy_asset, baseline, deep_source_tip),
    )
    .expect("deep rebuilt RPC handler");
    for (market_id, expected_state, expected_history_len) in [
        (first_id, first_post_state, 2),
        (second_id, second_post_state, 1),
    ] {
        let (view, history) =
            assert_rpc_contract_replay(&deep_handler, source.as_ref(), market_id).await;
        assert_eq!(
            view.state,
            ContractStateView::BinaryMarket {
                state: expected_state,
            }
        );
        assert_eq!(history.entries.len(), expected_history_len);
        assert_eq!(
            history
                .entries
                .iter()
                .find(|entry| entry.txid == composed.txid())
                .expect("deep RPC composed transition")
                .position,
            deep_position
        );
    }

    let report = json!({
        "schema": "deadcat.multi-market-regtest.v1",
        "market_ids": [first_id.to_string(), second_id.to_string()],
        "txid": composed.txid().to_string(),
        "inputs": composed.input.len(),
        "outputs": composed.output.len(),
        "mempool_vsize": composed_accepted.mempool_vsize,
        "original_position": original_position,
        "original_block_hash": composed_accepted.block_hash,
        "moved_position": moved_position,
        "moved_block_hash": moved_block_hash_string,
        "final_position": final_position,
        "final_block_hash": final_block_hash_string,
        "deep_rebuild_position": deep_position,
        "deep_rebuild_block_hash": deep_composed_hash_string,
        "negative_test": wrong_second_rejection,
    });
    eprintln!(
        "DEADCAT_MULTI_MARKET_REGTEST_METRICS={}",
        serde_json::to_string(&report).expect("serialize multi-market metrics")
    );
}

fn process_chain_tip(rpc: &Client) -> ChainAnchor {
    let height = u32::try_from(rpc.get_block_count().expect("process-test block count"))
        .expect("liquidregtest height fits in u32");
    let hash = BlockHash::from_str(
        &rpc.get_block_hash(u64::from(height))
            .expect("process-test tip hash")
            .to_string(),
    )
    .expect("Elements tip hash");
    ChainAnchor { height, hash }
}

fn build_process_relay(signer: &Signer, policy_asset: AssetId, funding: &Funding) -> Transaction {
    let mut pset = PartiallySignedTransaction::new_v2();
    pset.add_input(pset_input(funding.outpoint, funding.txout.clone()));
    pset.add_output(PsetOutput::from_txout(explicit_txout(
        policy_asset,
        FUNDING_VALUE - FEE,
        signer.get_address().script_pubkey(),
    )));
    pset.add_output(PsetOutput::from_txout(TxOut::new_fee(FEE, policy_asset)));
    sign_input(signer, &mut pset, 0);
    pset.extract_tx().expect("extract process-test relay")
}

#[test]
#[ignore = "starts elementsd, the deadcat-node daemon, and real Iroh/CLI processes"]
fn daemon_iroh_cli_restart_and_rebuild_boundary_is_live() {
    let node_binary = process_support::required_binary("DEADCAT_NODE_BIN", "deadcat-node");
    let cli_binary = process_support::required_binary("DEADCAT_CLI_BIN", "deadcat");
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

    let directory = tempfile::tempdir().expect("process-boundary directory");
    let database = directory.path().join("deadcat.redb");
    let iroh_secret = directory.path().join("iroh-secret");
    let mut node = process_support::NodeProcess::spawn(
        &node_binary,
        &database,
        &iroh_secret,
        LiquidNetwork::ElementsRegtest,
        policy_asset,
        Some(baseline.height),
        &client.rpc_url(),
        &client.auth(),
    );
    let initial_info = process_support::wait_for_info(&cli_binary, node.endpoint(), |info| {
        info.sync_status == SyncStatus::Ready
            && info.source_tip == Some(baseline)
            && info.indexed_tip == baseline
    });
    assert_eq!(initial_info.network, LiquidNetwork::ElementsRegtest);
    assert_eq!(initial_info.genesis_hash, genesis_hash);
    assert_eq!(initial_info.policy_asset, policy_asset);
    let before_market_cursor = initial_info.event_high_watermark;

    // Create a real market after the daemon is already serving. This drives
    // background Elements synchronization and leaves a durable event for a
    // separately spawned CLI subscription to resume from its old cursor.
    let market = create_market(
        &signer,
        &rpc,
        &miner,
        policy_asset,
        &funding[0],
        &funding[1],
        baseline.height.checked_add(1_000).expect("future expiry"),
    );
    let market_tip = ChainAnchor {
        height: u32::try_from(market.accepted.block_height).expect("market height"),
        hash: BlockHash::from_str(&market.accepted.block_hash).expect("market block hash"),
    };
    let market_id = ContractId::new(OutPoint::new(market.transaction.txid(), 0));
    let caught_up = process_support::wait_for_info(&cli_binary, node.endpoint(), |info| {
        info.sync_status == SyncStatus::Ready
            && info.source_tip == Some(market_tip)
            && info.indexed_tip == market_tip
    });
    assert!(caught_up.discovery.canonical_market_complete);

    let subscribe_args = vec![
        "subscribe".to_owned(),
        "--after-json".to_owned(),
        serde_json::to_string(&before_market_cursor).expect("serialize old event cursor"),
    ];
    let subscription = process_support::subscription_until(
        &cli_binary,
        node.endpoint(),
        &subscribe_args,
        move |value| {
            serde_json::from_value::<EventEnvelope>(value.clone()).is_ok_and(|envelope| {
                match envelope.event {
                    Event::ContractRegistered { contract_id }
                    | Event::ContractReady { contract_id, .. }
                    | Event::BackfillApplied { contract_id, .. } => contract_id == market_id,
                    Event::TransactionApplied {
                        affected_contract_ids,
                        ..
                    }
                    | Event::ChainRolledBack {
                        affected_contract_ids,
                        ..
                    } => affected_contract_ids.contains(&market_id),
                    Event::SyncStatusChanged { .. } | Event::CaughtUp { .. } => false,
                }
            })
        },
    );
    assert!(subscription[0].get("subscription_opened").is_some());
    let event: EventEnvelope = serde_json::from_value(
        subscription
            .last()
            .expect("matched market subscription event")
            .clone(),
    )
    .expect("subscription event envelope");
    assert_eq!(event.cursor.epoch, before_market_cursor.epoch);
    assert!(event.cursor.sequence > before_market_cursor.sequence);
    assert!(match event.event {
        Event::ContractRegistered { contract_id }
        | Event::ContractReady { contract_id, .. }
        | Event::BackfillApplied { contract_id, .. } => contract_id == market_id,
        Event::TransactionApplied {
            affected_contract_ids,
            ..
        }
        | Event::ChainRolledBack {
            affected_contract_ids,
            ..
        } => affected_contract_ids.contains(&market_id),
        Event::SyncStatusChanged { .. } | Event::CaughtUp { .. } => false,
    });

    let package = ContractPackage {
        format_version: CONTRACT_PACKAGE_FORMAT_VERSION,
        chain: ChainIdentity {
            network: LiquidNetwork::ElementsRegtest,
            genesis_hash,
        },
        roots: vec![market_id],
        declarations: vec![ContractDeclaration {
            contract_id: market_id,
            descriptor: ContractDescriptor::BinaryMarketV1 {
                params: market.params,
            },
        }],
    };
    let registration = process_support::cli_response(
        &cli_binary,
        node.endpoint(),
        &[
            "register".to_owned(),
            "--json".to_owned(),
            serde_json::to_string(&package).expect("serialize contract package"),
        ],
    );
    let Response::RegistrationAccepted { registration } = registration else {
        panic!("real CLI returned the wrong registration response")
    };
    assert_eq!(registration.roots, vec![market_id]);
    assert_eq!(registration.contracts.len(), 1);
    assert_eq!(registration.contracts[0].contract_id, market_id);
    assert!(registration.contracts[0].already_registered);
    assert!(matches!(
        registration.contracts[0].sync_state,
        ContractSyncState::Ready { synced_through } if synced_through == market_tip
    ));

    let contract = process_support::cli_response(
        &cli_binary,
        node.endpoint(),
        &["get-contract".to_owned(), market_id.to_string()],
    );
    let Response::Contract {
        contract: Some(contract),
    } = contract
    else {
        panic!("real CLI did not return the discovered market")
    };
    assert_eq!(contract.contract_id, market_id);
    assert_eq!(contract.creation_position.block_height, market_tip.height);

    let markets =
        process_support::cli_response(&cli_binary, node.endpoint(), &["list-markets".to_owned()]);
    let Response::Markets { page } = markets else {
        panic!("real CLI returned the wrong markets response")
    };
    assert_eq!(page.contracts.len(), 1);
    assert_eq!(page.contracts[0].contract_id, market_id);

    let history = process_support::cli_response(
        &cli_binary,
        node.endpoint(),
        &["history".to_owned(), market_id.to_string()],
    );
    let Response::ContractHistory { page } = history else {
        panic!("real CLI returned the wrong history response")
    };
    assert_eq!(page.contract_id, market_id);
    assert!(page.entries.is_empty());

    let creation_position = contract.creation_position;
    let evidence = process_support::cli_response(
        &cli_binary,
        node.endpoint(),
        &[
            "transaction".to_owned(),
            format!(
                "{}:{}",
                creation_position.block_height, creation_position.tx_index
            ),
        ],
    );
    let Response::Transaction {
        evidence: Some(evidence),
    } = evidence
    else {
        panic!("real CLI did not return creation evidence")
    };
    assert_eq!(evidence.transaction, market.transaction);

    // Relay a separately signed wallet transaction through the actual CLI and
    // Iroh server, then require the daemon to index its confirmed block.
    let relay = build_process_relay(&signer, policy_asset, &funding[5]);
    let broadcast = process_support::cli_response(
        &cli_binary,
        node.endpoint(),
        &[
            "broadcast".to_owned(),
            "--hex".to_owned(),
            elements::encode::serialize_hex(&relay),
        ],
    );
    assert_eq!(
        broadcast,
        Response::BroadcastAccepted { txid: relay.txid() }
    );
    miner.generate_blocks(1).expect("mine relayed transaction");
    let relay_tip = process_chain_tip(&rpc);
    let relay_status: JsonValue = rpc
        .call(
            "getrawtransaction",
            &[json!(relay.txid().to_string()), json!(true)],
        )
        .expect("read confirmed relayed transaction");
    assert!(
        relay_status["confirmations"]
            .as_u64()
            .is_some_and(|confirmations| confirmations >= 1)
    );
    assert_eq!(
        relay_status["blockhash"].as_str(),
        Some(relay_tip.hash.to_string().as_str())
    );
    let before_restart = process_support::wait_for_info(&cli_binary, node.endpoint(), |info| {
        info.sync_status == SyncStatus::Ready
            && info.source_tip == Some(relay_tip)
            && info.indexed_tip == relay_tip
    });
    let pre_rebuild_cursor = before_restart.event_high_watermark;
    let endpoint_id = node.endpoint().id;
    node.stop_gracefully();

    // A fresh daemon process must reuse its Iroh identity and redb state.
    let mut restarted = process_support::NodeProcess::spawn(
        &node_binary,
        &database,
        &iroh_secret,
        LiquidNetwork::ElementsRegtest,
        policy_asset,
        Some(baseline.height),
        &client.rpc_url(),
        &client.auth(),
    );
    assert_eq!(restarted.endpoint().id, endpoint_id);
    process_support::wait_for_info(&cli_binary, restarted.endpoint(), |info| {
        info.sync_status == SyncStatus::Ready && info.indexed_tip == relay_tip
    });
    let persisted = process_support::cli_response(
        &cli_binary,
        restarted.endpoint(),
        &["get-contract".to_owned(), market_id.to_string()],
    );
    assert!(matches!(
        persisted,
        Response::Contract {
            contract: Some(ref value)
        } if value.contract_id == market_id
    ));

    // Replace a three-block suffix. The daemon can retain only two undo
    // deltas, so it must fail closed and require the explicit rebuild command.
    let stale_height = relay_tip.height.checked_add(1).expect("stale height");
    miner
        .generate_blocks(3)
        .expect("mine stale three-block suffix");
    let stale_tip = process_chain_tip(&rpc);
    process_support::wait_for_info(&cli_binary, restarted.endpoint(), |info| {
        info.sync_status == SyncStatus::Ready && info.indexed_tip == stale_tip
    });
    let stale_root_hash = rpc
        .get_block_hash(u64::from(stale_height))
        .expect("stale suffix root")
        .to_string();
    let invalidated: JsonValue = rpc
        .call("invalidateblock", &[json!(stale_root_hash)])
        .expect("invalidate deep suffix");
    assert!(invalidated.is_null());
    let replacement_marker = build_process_relay(&signer, policy_asset, &funding[6]);
    let replacement_marker_txid: String = rpc
        .call(
            "sendrawtransaction",
            &[
                json!(elements::encode::serialize_hex(&replacement_marker)),
                json!(0),
            ],
        )
        .expect("broadcast replacement-branch marker");
    assert_eq!(
        replacement_marker_txid,
        replacement_marker.txid().to_string()
    );
    let mining_address = signer.get_address().to_unconfidential().to_string();
    for index in 0..3 {
        let txids = if index == 0 {
            vec![replacement_marker_txid.clone()]
        } else {
            Vec::new()
        };
        let generated: JsonValue = rpc
            .call(
                "generateblock",
                &[json!(mining_address.clone()), json!(txids)],
            )
            .expect("mine exact replacement block");
        assert!(generated["hash"].is_string());
    }
    let replacement_tip = process_chain_tip(&rpc);
    assert_eq!(replacement_tip.height, stale_tip.height);
    assert_ne!(replacement_tip.hash, stale_tip.hash);
    let invalidated_info =
        process_support::wait_for_info(&cli_binary, restarted.endpoint(), |info| {
            info.sync_status == SyncStatus::RescanRequired
        });
    assert_eq!(invalidated_info.indexed_tip, stale_tip);
    assert_eq!(invalidated_info.source_tip, Some(replacement_tip));
    assert_ne!(
        invalidated_info.event_high_watermark.epoch,
        pre_rebuild_cursor.epoch
    );
    let invalidated_epoch = invalidated_info.event_high_watermark.epoch;
    let stale_contract = process_support::cli_output(
        &cli_binary,
        restarted.endpoint(),
        &["get-contract".to_owned(), market_id.to_string()],
    );
    assert!(!stale_contract.status.success());
    let stale_contract_error = String::from_utf8_lossy(&stale_contract.stderr).to_lowercase();
    assert!(
        stale_contract_error.contains("rescan"),
        "chain-derived RPC did not fail explicitly during invalidation: {stale_contract_error}"
    );
    restarted.stop_gracefully();

    let rebuild_output =
        process_support::run_rebuild(&node_binary, &database, &client.rpc_url(), &client.auth());
    assert!(rebuild_output.contains("rebuild complete"));

    let mut rebuilt = process_support::NodeProcess::spawn(
        &node_binary,
        &database,
        &iroh_secret,
        LiquidNetwork::ElementsRegtest,
        policy_asset,
        Some(baseline.height),
        &client.rpc_url(),
        &client.auth(),
    );
    assert_eq!(rebuilt.endpoint().id, endpoint_id);
    let rebuilt_info = process_support::wait_for_info(&cli_binary, rebuilt.endpoint(), |info| {
        info.sync_status == SyncStatus::Ready
            && info.source_tip == Some(replacement_tip)
            && info.indexed_tip == replacement_tip
    });
    assert_eq!(rebuilt_info.event_high_watermark.epoch, invalidated_epoch);
    let rebuilt_contract = process_support::cli_response(
        &cli_binary,
        rebuilt.endpoint(),
        &["get-contract".to_owned(), market_id.to_string()],
    );
    assert!(matches!(
        rebuilt_contract,
        Response::Contract {
            contract: Some(ref value)
        } if value.contract_id == market_id && value.creation_position == creation_position
    ));
    let rebuilt_evidence = process_support::cli_response(
        &cli_binary,
        rebuilt.endpoint(),
        &[
            "transaction".to_owned(),
            format!(
                "{}:{}",
                creation_position.block_height, creation_position.tx_index
            ),
        ],
    );
    assert!(matches!(
        rebuilt_evidence,
        Response::Transaction {
            evidence: Some(ref value)
        } if value.transaction == market.transaction
            && value.position == creation_position
    ));

    let stale_subscription = process_support::cli_output(
        &cli_binary,
        rebuilt.endpoint(),
        &[
            "subscribe".to_owned(),
            "--after-json".to_owned(),
            serde_json::to_string(&pre_rebuild_cursor).expect("serialize stale cursor"),
        ],
    );
    assert!(!stale_subscription.status.success());
    let stale_error = String::from_utf8_lossy(&stale_subscription.stderr).to_lowercase();
    assert!(
        stale_error.contains("stale"),
        "stale cursor rejection was not explicit: {stale_error}"
    );
    rebuilt.stop_gracefully();

    eprintln!(
        "DEADCAT_PROCESS_BOUNDARY_REGTEST_METRICS={}",
        serde_json::to_string(&json!({
            "schema": "deadcat.process-boundary-regtest.v1",
            "market_id": market_id.to_string(),
            "endpoint_id": endpoint_id.to_string(),
            "baseline": baseline,
            "stale_tip": stale_tip,
            "replacement_tip": replacement_tip,
            "rescan_cursor_epoch_rotated_once": true,
        }))
        .expect("serialize process-boundary metrics")
    );
}

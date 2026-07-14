//! Serial, production-shaped A/B binary-market lifecycle on liquidregtest.
//!
//! This test is ignored by the normal workspace suite because it starts an
//! isolated `elementsd` + Electrs pair. Run it through `just regtest-market-ab`.

use bitcoincore_rpc::{Client, RpcApi};
use deadcat_client::market_builder::{
    BinaryMarketCreationPlan, BinaryMarketLiveInputs, BinaryMarketTransitionPlan,
    MarketCreationContext, MarketIssuanceEntropies, MarketRtInput, OracleAttestation,
};
use deadcat_contracts::SimplicityNetwork;
use deadcat_contracts::binary_market::{BinaryMarketAction, BinaryMarketEconomics, BinaryOutcome};
use deadcat_contracts::market_crypto::{
    BinaryOutcome as OracleOutcome, derive_issuance_assets, oracle_message,
};
use deadcat_contracts::recovery::{MarketCollateral, MarketRecoveryHint};
use deadcat_contracts::rt::{RtLeg, RtSide, add_mod_order, cbf, factors, infer_side};
use deadcat_types::{BinaryMarketParams, BinaryMarketState};
use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::pset::{Input as PsetInput, Output as PsetOutput, PartiallySignedTransaction};
use elements::secp256k1_zkp::rand::thread_rng;
use elements::secp256k1_zkp::{Keypair, Message, Secp256k1, SecretKey, SurjectionProof, Tweak};
use elements::{AssetId, OutPoint, Script, Transaction, TxOut, TxOutSecrets, TxOutWitness};
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

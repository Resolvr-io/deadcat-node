//! Focused, serial `elementsd` acceptance harness for the two RT schedules.
//!
//! This deliberately isolates confidential RT transport from market
//! economics, but its two nonterminal transitions carry real Elements asset
//! reissuances. It proves the RT nonce, entropy, proof, wallet-composition,
//! and terminal-burn mechanics without claiming full-market covenant coverage.

use std::collections::HashMap;

use bitcoincore_rpc::{Client, RpcApi};
use deadcat_contracts::rt::{
    RtFactors, add_mod_order, commitments, continuation_factors, creation_factors,
};
use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::hashes::Hash as _;
use elements::pset::{Input as PsetInput, Output as PsetOutput, PartiallySignedTransaction};
use elements::secp256k1_zkp::rand::{SeedableRng as _, thread_rng};
use elements::secp256k1_zkp::{
    Generator, Secp256k1, SecretKey, SurjectionProof, Tweak, ZERO_TWEAK,
};
use elements::{
    AssetId, ContractHash, OutPoint, RangeProofMessage, Script, Transaction, TxOut, TxOutSecrets,
    TxOutWitness,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use simplex::program::{ProgramTrait as _, WitnessTrait as _};
use simplex::provider::{ElementsRpc, SimplicityNetwork};
use simplex::signer::{Signer, SignerTrait as _};
use simplex::transaction::{FinalTransaction, PartialOutput};
use smplx_regtest::{Regtest, RegtestConfig};

use crate::artifacts::rt_ab::{RtAbProgram, derived_rt_ab};
use crate::artifacts::rt_rolling::{RtRollingProgram, derived_rt_rolling};
use crate::schedule::{RtLeg, RtSide, cbf, factors, infer_side};

const FUNDING_VALUE: u64 = 100_000;
const FEE: u64 = 1_000;
const REISSUANCE_AMOUNT: u64 = 7;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum Scheme {
    Rolling,
    Ab,
}

#[derive(Clone)]
struct Funding {
    outpoint: OutPoint,
    txout: TxOut,
    secrets: TxOutSecrets,
}

#[derive(Clone)]
struct LiveRt {
    asset_id: AssetId,
    entropy: [u8; 32],
    outpoint: OutPoint,
    txout: TxOut,
    factors: RtFactors,
}

#[derive(Clone)]
struct LivePair {
    yes: LiveRt,
    no: LiveRt,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
struct CovenantMetrics {
    cost_milliweight: u64,
    program_bytes: usize,
    witness_bytes: usize,
    stack_bytes: usize,
}

impl CovenantMetrics {
    fn add(self, other: Self) -> Self {
        Self {
            cost_milliweight: self.cost_milliweight + other.cost_milliweight,
            program_bytes: self.program_bytes + other.program_bytes,
            witness_bytes: self.witness_bytes + other.witness_bytes,
            stack_bytes: self.stack_bytes + other.stack_bytes,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct TxMetrics {
    stage: &'static str,
    bytes: usize,
    weight: usize,
    vsize: usize,
    discount_weight: usize,
    discount_vsize: usize,
    mempool_vsize: usize,
    covenant: CovenantMetrics,
}

#[derive(Clone, Debug, Serialize)]
struct SchemeMetrics {
    scheme: Scheme,
    transactions: Vec<TxMetrics>,
}

#[derive(Debug, Deserialize)]
struct MempoolAcceptance {
    allowed: Option<bool>,
    vsize: Option<usize>,
    #[serde(rename = "reject-reason")]
    reject_reason: Option<String>,
}

fn parts(serialized: [u8; 33]) -> (bool, [u8; 32]) {
    let mut x = [0; 32];
    x.copy_from_slice(&serialized[1..]);
    (serialized[0] & 1 != 0, x)
}

fn ab_program(asset_id: AssetId, leg: RtLeg) -> RtAbProgram {
    let (asset_a, value_a) = commitments(asset_id, factors(leg, RtSide::A)).expect("A");
    let (asset_b, value_b) = commitments(asset_id, factors(leg, RtSide::B)).expect("B");
    assert_eq!(value_a, value_b);
    let (asset_a_parity, asset_a_x) = parts(asset_a.commitment().expect("A generator").serialize());
    let (asset_b_parity, asset_b_x) = parts(asset_b.commitment().expect("B generator").serialize());
    let (value_parity, value_x) =
        parts(value_a.commitment().expect("value commitment").serialize());
    RtAbProgram::new(derived_rt_ab::RtAbArguments {
        asset_a_parity,
        asset_a_x,
        asset_b_parity,
        asset_b_x,
        value_parity,
        value_x,
    })
}

fn rolling_program(asset_id: AssetId) -> RtRollingProgram {
    RtRollingProgram::new(derived_rt_rolling::RtRollingArguments {
        rt_asset_id: asset_id.into_inner().to_byte_array(),
    })
}

fn script_for(
    scheme: Scheme,
    asset_id: AssetId,
    leg: RtLeg,
    network: &SimplicityNetwork,
) -> Script {
    match scheme {
        Scheme::Rolling => rolling_program(asset_id).get_script_pubkey(network),
        Scheme::Ab => ab_program(asset_id, leg).get_script_pubkey(network),
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

fn pset_input(outpoint: OutPoint, witness_utxo: TxOut) -> PsetInput {
    let mut input = PsetInput::from_prevout(outpoint);
    input.witness_utxo = Some(witness_utxo);
    input
}

fn configure_new_rt_issuance(input: &mut PsetInput) {
    input.issuance_value_amount = None;
    input.issuance_value_comm = None;
    input.issuance_inflation_keys = Some(1);
    input.issuance_inflation_keys_comm = None;
    input.issuance_blinding_nonce = Some(ZERO_TWEAK);
    input.issuance_asset_entropy = Some([0; 32]);
    input.blinded_issuance = Some(0);
}

fn issued_rt(outpoint: OutPoint) -> (AssetId, [u8; 32]) {
    let entropy = AssetId::generate_asset_entropy(outpoint, ContractHash::from_byte_array([0; 32]));
    (
        AssetId::reissuance_token_from_entropy(entropy, false),
        entropy.to_byte_array(),
    )
}

fn reissued_asset(entropy: [u8; 32]) -> AssetId {
    AssetId::from_entropy(elements::hashes::sha256::Midstate::from_byte_array(entropy))
}

fn configure_reissuance(input: &mut PsetInput, live: &LiveRt) {
    input.issuance_value_amount = Some(REISSUANCE_AMOUNT);
    input.issuance_value_comm = None;
    input.issuance_inflation_keys = None;
    input.issuance_inflation_keys_comm = None;
    input.issuance_blinding_nonce =
        Some(Tweak::from_inner(live.factors.abf).expect("current RT ABF"));
    input.issuance_asset_entropy = Some(live.entropy);
    input.blinded_issuance = Some(0);
}

fn rt_secrets(asset_id: AssetId, factors: RtFactors) -> TxOutSecrets {
    TxOutSecrets::new(
        asset_id,
        AssetBlindingFactor::from_slice(&factors.abf).expect("RT ABF"),
        1,
        ValueBlindingFactor::from_slice(&factors.vbf).expect("RT VBF"),
    )
}

fn confidential_rt(asset_id: AssetId, factors: RtFactors, script_pubkey: Script) -> TxOut {
    let secp = Secp256k1::new();
    let (asset, expected_value) = commitments(asset_id, factors).expect("RT commitments");
    let output_abf = AssetBlindingFactor::from_slice(&factors.abf).expect("RT ABF");
    let output_vbf = ValueBlindingFactor::from_slice(&factors.vbf).expect("RT VBF");
    let message = RangeProofMessage {
        asset: asset_id,
        bf: output_abf,
    };
    let rewind = deterministic_secret(asset_id, factors, &script_pubkey);
    let (value, rangeproof) = Value::Explicit(1)
        .blind_with_shared_secret(&secp, output_vbf, rewind, &script_pubkey, &message)
        .expect("RT rangeproof");
    assert_eq!(value, expected_value);
    TxOut {
        asset,
        value,
        nonce: Nonce::Null,
        script_pubkey,
        witness: TxOutWitness {
            surjection_proof: None,
            rangeproof: Some(Box::new(rangeproof)),
        },
    }
}

fn deterministic_secret(asset_id: AssetId, factors: RtFactors, script: &Script) -> SecretKey {
    use elements::hashes::{HashEngine as _, sha256};

    for counter in 0_u32..=u32::MAX {
        let mut engine = sha256::Hash::engine();
        engine.input(asset_id.into_inner().as_ref());
        engine.input(&factors.abf);
        engine.input(&factors.vbf);
        engine.input(script.as_bytes());
        engine.input(&counter.to_be_bytes());
        if let Ok(secret) =
            SecretKey::from_slice(&sha256::Hash::from_engine(engine).to_byte_array())
        {
            return secret;
        }
    }
    panic!("SHA256 could not derive a valid rangeproof secret")
}

fn install_surjection(
    pset: &mut PartiallySignedTransaction,
    output_index: usize,
    asset_id: AssetId,
    output_factors: RtFactors,
    known_inputs: &HashMap<usize, TxOutSecrets>,
) {
    let secp = Secp256k1::new();
    let domain = pset
        .surjection_inputs(known_inputs)
        .expect("surjection domain")
        .into_iter()
        .map(|input| input.surjection_target(&secp).expect("surjection target"))
        .collect::<Vec<_>>();
    let mut seed = [0_u8; 32];
    seed[..8].copy_from_slice(&(output_index as u64).to_be_bytes());
    seed[8..].copy_from_slice(&output_factors.abf[..24]);
    let mut rng = elements::secp256k1_zkp::rand::rngs::StdRng::from_seed(seed);
    let proof = SurjectionProof::new(
        &secp,
        &mut rng,
        asset_id.into_tag(),
        Tweak::from_inner(output_factors.abf).expect("output ABF"),
        &domain,
    )
    .expect("RT surjection proof");
    let output_generator = pset.outputs()[output_index]
        .to_txout()
        .asset
        .commitment()
        .expect("output generator");
    let input_generators = domain
        .iter()
        .map(|entry| entry.0)
        .collect::<Vec<Generator>>();
    assert!(proof.verify(&secp, output_generator, &input_generators));
    pset.outputs_mut()[output_index].asset_surjection_proof = Some(Box::new(proof));
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
    .expect("balanced confidential change")
    .0
}

fn sign_input(signer: &Signer, pset: &mut PartiallySignedTransaction, index: usize) {
    let (public_key, signature) = signer.sign_input(pset, index).expect("P2WPKH signature");
    let mut raw_signature = signature.serialize_der().to_vec();
    raw_signature.push(0x01);
    pset.inputs_mut()[index].final_script_witness =
        Some(vec![raw_signature, public_key.to_bytes()]);
}

#[allow(clippy::too_many_arguments)]
fn finalize_covenant(
    scheme: Scheme,
    leg: RtLeg,
    asset_id: AssetId,
    input_factors: RtFactors,
    output_index: u32,
    terminal: bool,
    input_index: usize,
    pset: &PartiallySignedTransaction,
    network: &SimplicityNetwork,
) -> (Vec<Vec<u8>>, CovenantMetrics) {
    match scheme {
        Scheme::Rolling => {
            let program = rolling_program(asset_id);
            let witness = derived_rt_rolling::RtRollingWitness {
                output_index,
                input_abf: input_factors.abf,
                input_cbf: input_factors.cbf,
                terminal,
            };
            let values = witness.build_witness();
            let (node, _) = program
                .as_ref()
                .execute(pset, &values, input_index, network)
                .expect("rolling covenant execution");
            let stack = program
                .as_ref()
                .finalize(pset, &values, input_index, network)
                .expect("rolling covenant finalization");
            let bounds = node.bounds();
            assert!(bounds.cost.is_budget_valid(&stack));
            let (program_bytes, witness_bytes) = node.to_vec_with_witness();
            let stack_bytes = elements::encode::serialize(&stack).len();
            (
                stack,
                CovenantMetrics {
                    cost_milliweight: bounds
                        .cost
                        .to_string()
                        .parse()
                        .expect("numeric Simplicity cost"),
                    program_bytes: program_bytes.len(),
                    witness_bytes: witness_bytes.len(),
                    stack_bytes,
                },
            )
        }
        Scheme::Ab => {
            let program = ab_program(asset_id, leg);
            let witness = derived_rt_ab::RtAbWitness {
                output_index,
                terminal,
            };
            let values = witness.build_witness();
            let (node, _) = program
                .as_ref()
                .execute(pset, &values, input_index, network)
                .expect("A/B covenant execution");
            let stack = program
                .as_ref()
                .finalize(pset, &values, input_index, network)
                .expect("A/B covenant finalization");
            let bounds = node.bounds();
            assert!(bounds.cost.is_budget_valid(&stack));
            let (program_bytes, witness_bytes) = node.to_vec_with_witness();
            let stack_bytes = elements::encode::serialize(&stack).len();
            (
                stack,
                CovenantMetrics {
                    cost_milliweight: bounds
                        .cost
                        .to_string()
                        .parse()
                        .expect("numeric Simplicity cost"),
                    program_bytes: program_bytes.len(),
                    witness_bytes: witness_bytes.len(),
                    stack_bytes,
                },
            )
        }
    }
}

fn prepare_funding(
    signer: &Signer,
    rpc: &Client,
    miner: &ElementsRpc,
    policy_asset: AssetId,
) -> Vec<Funding> {
    let mut funding = FinalTransaction::new();
    for index in 0..10 {
        let output = PartialOutput::new(
            signer.get_address().script_pubkey(),
            FUNDING_VALUE,
            policy_asset,
        );
        funding.add_output(if index % 5 == 3 {
            output.with_blinding_key(signer.get_blinding_public_key())
        } else {
            output
        });
    }
    let (transaction, _) = signer.finalize(&funding).expect("fund study inputs");
    accept_broadcast_mine(rpc, miner, &transaction);
    let blinding_key = signer.get_blinding_private_key().inner;
    transaction
        .output
        .iter()
        .take(10)
        .cloned()
        .enumerate()
        .map(|(index, txout)| {
            let secrets = if index % 5 == 3 {
                txout
                    .unblind(&Secp256k1::new(), blinding_key)
                    .expect("unblind reserved confidential funding")
            } else {
                TxOutSecrets::new(
                    policy_asset,
                    AssetBlindingFactor::zero(),
                    FUNDING_VALUE,
                    ValueBlindingFactor::zero(),
                )
            };
            Funding {
                outpoint: OutPoint::new(transaction.txid(), index as u32),
                txout,
                secrets,
            }
        })
        .collect()
}

fn create_pair(
    scheme: Scheme,
    signer: &Signer,
    network: &SimplicityNetwork,
    policy_asset: AssetId,
    yes_funding: &Funding,
    no_funding: &Funding,
) -> (Transaction, LivePair) {
    let (yes_asset, yes_entropy) = issued_rt(yes_funding.outpoint);
    let (no_asset, no_entropy) = issued_rt(no_funding.outpoint);
    let yes_factors = match scheme {
        Scheme::Rolling => creation_factors(yes_funding.outpoint),
        Scheme::Ab => factors(RtLeg::Yes, RtSide::A),
    };
    let no_factors = match scheme {
        Scheme::Rolling => creation_factors(no_funding.outpoint),
        Scheme::Ab => factors(RtLeg::No, RtSide::A),
    };
    let yes_script = script_for(scheme, yes_asset, RtLeg::Yes, network);
    let no_script = script_for(scheme, no_asset, RtLeg::No, network);
    let yes_output = confidential_rt(yes_asset, yes_factors, yes_script);
    let no_output = confidential_rt(no_asset, no_factors, no_script);

    let mut yes_input = pset_input(yes_funding.outpoint, yes_funding.txout.clone());
    let mut no_input = pset_input(no_funding.outpoint, no_funding.txout.clone());
    configure_new_rt_issuance(&mut yes_input);
    configure_new_rt_issuance(&mut no_input);
    let mut pset = PartiallySignedTransaction::new_v2();
    pset.add_input(yes_input);
    pset.add_input(no_input);
    pset.add_output(PsetOutput::from_txout(yes_output));
    pset.add_output(PsetOutput::from_txout(no_output));

    let known = HashMap::new();
    install_surjection(&mut pset, 0, yes_asset, yes_factors, &known);
    install_surjection(&mut pset, 1, no_asset, no_factors, &known);

    let issuance_yes = TxOutSecrets::new(
        yes_asset,
        AssetBlindingFactor::zero(),
        1,
        ValueBlindingFactor::zero(),
    );
    let issuance_no = TxOutSecrets::new(
        no_asset,
        AssetBlindingFactor::zero(),
        1,
        ValueBlindingFactor::zero(),
    );
    match scheme {
        Scheme::Rolling => {
            let spent = [
                yes_funding.secrets,
                issuance_yes,
                no_funding.secrets,
                issuance_no,
            ];
            let rt_outputs = [
                rt_secrets(yes_asset, yes_factors),
                rt_secrets(no_asset, no_factors),
            ];
            pset.add_output(PsetOutput::from_txout(balanced_change(
                signer,
                FUNDING_VALUE * 2 - FEE,
                policy_asset,
                &spent,
                &rt_outputs,
            )));
        }
        Scheme::Ab => pset.add_output(PsetOutput::from_txout(explicit_txout(
            policy_asset,
            FUNDING_VALUE * 2 - FEE,
            signer.get_address().script_pubkey(),
        ))),
    }
    pset.add_output(PsetOutput::from_txout(TxOut::new_fee(FEE, policy_asset)));
    sign_input(signer, &mut pset, 0);
    sign_input(signer, &mut pset, 1);
    let transaction = pset.extract_tx().expect("creation transaction");
    match scheme {
        Scheme::Rolling => assert!(transaction.output[2].value.is_confidential()),
        Scheme::Ab => {
            assert_eq!(transaction.output[2].asset, Asset::Explicit(policy_asset));
            assert_eq!(
                transaction.output[2].value,
                Value::Explicit(FUNDING_VALUE * 2 - FEE)
            );
        }
    }
    let txid = transaction.txid();
    let pair = LivePair {
        yes: LiveRt {
            asset_id: yes_asset,
            entropy: yes_entropy,
            outpoint: OutPoint::new(txid, 0),
            txout: transaction.output[0].clone(),
            factors: yes_factors,
        },
        no: LiveRt {
            asset_id: no_asset,
            entropy: no_entropy,
            outpoint: OutPoint::new(txid, 1),
            txout: transaction.output[1].clone(),
            factors: no_factors,
        },
    };
    (transaction, pair)
}

fn next_factors(scheme: Scheme, leg: RtLeg, asset_id: AssetId, input: &LiveRt) -> RtFactors {
    match scheme {
        Scheme::Rolling => continuation_factors(input.outpoint, input.factors.cbf),
        Scheme::Ab => {
            let side = infer_side(leg, asset_id, input.txout.asset, input.txout.value)
                .expect("infer A/B side");
            factors(leg, side.flip())
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn transition(
    scheme: Scheme,
    signer: &Signer,
    network: &SimplicityNetwork,
    policy_asset: AssetId,
    live: &LivePair,
    funding: &Funding,
    confidential_change: bool,
    terminal: bool,
) -> (Transaction, LivePair, CovenantMetrics) {
    let yes_asset = rt_secrets_asset(&live.yes);
    let no_asset = rt_secrets_asset(&live.no);
    let yes_output_factors = next_factors(scheme, RtLeg::Yes, yes_asset, &live.yes);
    let no_output_factors = next_factors(scheme, RtLeg::No, no_asset, &live.no);
    assert_eq!(yes_output_factors.cbf, live.yes.factors.cbf);
    assert_eq!(no_output_factors.cbf, live.no.factors.cbf);
    assert_ne!(yes_output_factors.abf, live.yes.factors.abf);
    assert_ne!(no_output_factors.abf, live.no.factors.abf);

    let yes_script = if terminal {
        Script::from(vec![0x6a])
    } else {
        live.yes.txout.script_pubkey.clone()
    };
    let no_script = if terminal {
        Script::from(vec![0x6a])
    } else {
        live.no.txout.script_pubkey.clone()
    };
    let yes_output = confidential_rt(yes_asset, yes_output_factors, yes_script);
    let no_output = confidential_rt(no_asset, no_output_factors, no_script);
    let mut yes_input = pset_input(live.yes.outpoint, live.yes.txout.clone());
    let mut no_input = pset_input(live.no.outpoint, live.no.txout.clone());
    if !terminal {
        configure_reissuance(&mut yes_input, &live.yes);
        configure_reissuance(&mut no_input, &live.no);
    }
    let mut pset = PartiallySignedTransaction::new_v2();
    pset.add_input(yes_input);
    pset.add_input(no_input);
    pset.add_input(pset_input(funding.outpoint, funding.txout.clone()));
    pset.add_output(PsetOutput::from_txout(yes_output));
    pset.add_output(PsetOutput::from_txout(no_output));
    if !terminal {
        pset.add_output(PsetOutput::from_txout(explicit_txout(
            reissued_asset(live.yes.entropy),
            REISSUANCE_AMOUNT,
            signer.get_address().script_pubkey(),
        )));
        pset.add_output(PsetOutput::from_txout(explicit_txout(
            reissued_asset(live.no.entropy),
            REISSUANCE_AMOUNT,
            signer.get_address().script_pubkey(),
        )));
    }

    let known = HashMap::from([
        (0, rt_secrets(yes_asset, live.yes.factors)),
        (1, rt_secrets(no_asset, live.no.factors)),
        (2, funding.secrets),
    ]);
    install_surjection(&mut pset, 0, yes_asset, yes_output_factors, &known);
    install_surjection(&mut pset, 1, no_asset, no_output_factors, &known);

    let change_amount = FUNDING_VALUE - FEE;
    if confidential_change {
        let yes_reissuance = TxOutSecrets::new(
            reissued_asset(live.yes.entropy),
            AssetBlindingFactor::zero(),
            REISSUANCE_AMOUNT,
            ValueBlindingFactor::zero(),
        );
        let no_reissuance = TxOutSecrets::new(
            reissued_asset(live.no.entropy),
            AssetBlindingFactor::zero(),
            REISSUANCE_AMOUNT,
            ValueBlindingFactor::zero(),
        );
        let spent = if terminal {
            vec![
                rt_secrets(yes_asset, live.yes.factors),
                rt_secrets(no_asset, live.no.factors),
                funding.secrets,
            ]
        } else {
            vec![
                rt_secrets(yes_asset, live.yes.factors),
                yes_reissuance,
                rt_secrets(no_asset, live.no.factors),
                no_reissuance,
                funding.secrets,
            ]
        };
        let outputs = [
            rt_secrets(yes_asset, yes_output_factors),
            rt_secrets(no_asset, no_output_factors),
        ];
        pset.add_output(PsetOutput::from_txout(balanced_change(
            signer,
            change_amount,
            policy_asset,
            spent.as_slice(),
            &outputs,
        )));
    } else {
        pset.add_output(PsetOutput::from_txout(explicit_txout(
            policy_asset,
            change_amount,
            signer.get_address().script_pubkey(),
        )));
    }
    pset.add_output(PsetOutput::from_txout(TxOut::new_fee(FEE, policy_asset)));

    let (yes_stack, yes_metrics) = finalize_covenant(
        scheme,
        RtLeg::Yes,
        yes_asset,
        live.yes.factors,
        0,
        terminal,
        0,
        &pset,
        network,
    );
    let (no_stack, no_metrics) = finalize_covenant(
        scheme,
        RtLeg::No,
        no_asset,
        live.no.factors,
        1,
        terminal,
        1,
        &pset,
        network,
    );
    pset.inputs_mut()[0].final_script_witness = Some(yes_stack);
    pset.inputs_mut()[1].final_script_witness = Some(no_stack);
    sign_input(signer, &mut pset, 2);
    let transaction = pset.extract_tx().expect("RT transition transaction");
    if terminal {
        assert!(transaction.input[0].asset_issuance.is_null());
        assert!(transaction.input[1].asset_issuance.is_null());
    } else {
        for (input, live_rt) in transaction.input[..2].iter().zip([&live.yes, &live.no]) {
            assert_eq!(
                input.asset_issuance.asset_blinding_nonce,
                Tweak::from_inner(live_rt.factors.abf).expect("current RT ABF")
            );
            assert_eq!(input.asset_issuance.asset_entropy, live_rt.entropy);
            assert_eq!(
                input.asset_issuance.amount,
                Value::Explicit(REISSUANCE_AMOUNT)
            );
            assert_eq!(input.asset_issuance.inflation_keys, Value::Null);
        }
        assert_eq!(
            transaction.output[2].asset,
            Asset::Explicit(reissued_asset(live.yes.entropy))
        );
        assert_eq!(
            transaction.output[3].asset,
            Asset::Explicit(reissued_asset(live.no.entropy))
        );
        assert_eq!(
            transaction.output[2].value,
            Value::Explicit(REISSUANCE_AMOUNT)
        );
        assert_eq!(
            transaction.output[3].value,
            Value::Explicit(REISSUANCE_AMOUNT)
        );
    }
    let txid = transaction.txid();
    let next = LivePair {
        yes: LiveRt {
            asset_id: yes_asset,
            entropy: live.yes.entropy,
            outpoint: OutPoint::new(txid, 0),
            txout: transaction.output[0].clone(),
            factors: yes_output_factors,
        },
        no: LiveRt {
            asset_id: no_asset,
            entropy: live.no.entropy,
            outpoint: OutPoint::new(txid, 1),
            txout: transaction.output[1].clone(),
            factors: no_output_factors,
        },
    };
    (transaction, next, yes_metrics.add(no_metrics))
}

fn rt_secrets_asset(live: &LiveRt) -> AssetId {
    live.asset_id
}

fn accept_broadcast_mine(rpc: &Client, miner: &ElementsRpc, transaction: &Transaction) -> usize {
    let hex = elements::encode::serialize_hex(transaction);
    let response: Vec<MempoolAcceptance> = rpc
        .call("testmempoolaccept", &[json!([hex]), json!(0)])
        .expect("testmempoolaccept RPC");
    let acceptance = response.first().expect("one acceptance result");
    assert_eq!(
        acceptance.allowed,
        Some(true),
        "elementsd rejected transaction: {:?}",
        acceptance.reject_reason
    );
    let mempool_vsize = acceptance.vsize.expect("accepted transaction vsize");
    assert!(
        mempool_vsize == transaction.vsize() || mempool_vsize == transaction.discount_vsize(),
        "unexpected elementsd policy vsize {mempool_vsize} (regular {}, discounted {})",
        transaction.vsize(),
        transaction.discount_vsize(),
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
    mempool_vsize
}

fn assert_mempool_rejects(rpc: &Client, transaction: &Transaction, what: &str) {
    let response: Vec<MempoolAcceptance> = rpc
        .call(
            "testmempoolaccept",
            &[
                json!([elements::encode::serialize_hex(transaction)]),
                json!(0),
            ],
        )
        .expect("negative testmempoolaccept RPC");
    let acceptance = response.first().expect("one rejection result");
    assert_eq!(
        acceptance.allowed,
        Some(false),
        "elementsd unexpectedly accepted {what}"
    );
    assert!(
        acceptance.reject_reason.is_some(),
        "elementsd rejected {what} without a reason"
    );
}

fn measure(
    stage: &'static str,
    transaction: &Transaction,
    mempool_vsize: usize,
    covenant: CovenantMetrics,
) -> TxMetrics {
    assert_eq!(
        transaction.size(),
        elements::encode::serialize(transaction).len()
    );
    TxMetrics {
        stage,
        bytes: transaction.size(),
        weight: transaction.weight(),
        vsize: transaction.vsize(),
        discount_weight: transaction.discount_weight(),
        discount_vsize: transaction.discount_vsize(),
        mempool_vsize,
        covenant,
    }
}

fn run_scheme(
    scheme: Scheme,
    signer: &Signer,
    rpc: &Client,
    miner: &ElementsRpc,
    network: &SimplicityNetwork,
    policy_asset: AssetId,
    funding: &[Funding],
) -> SchemeMetrics {
    let (creation, created) = create_pair(
        scheme,
        signer,
        network,
        policy_asset,
        &funding[0],
        &funding[1],
    );
    let creation_vsize = accept_broadcast_mine(rpc, miner, &creation);
    let (first, first_live, first_covenant) = transition(
        scheme,
        signer,
        network,
        policy_asset,
        &created,
        &funding[2],
        false,
        false,
    );
    let mut missing_proof = first.clone();
    missing_proof.output[0].witness.surjection_proof = None;
    assert_mempool_rejects(
        rpc,
        &missing_proof,
        "an RT continuation with its surjection proof removed",
    );
    let first_vsize = accept_broadcast_mine(rpc, miner, &first);
    let (second, second_live, second_covenant) = transition(
        scheme,
        signer,
        network,
        policy_asset,
        &first_live,
        &funding[3],
        true,
        false,
    );
    let second_vsize = accept_broadcast_mine(rpc, miner, &second);

    let (terminal, terminal_outputs, terminal_covenant) = transition(
        scheme,
        signer,
        network,
        policy_asset,
        &second_live,
        &funding[4],
        false,
        true,
    );
    let terminal_vsize = accept_broadcast_mine(rpc, miner, &terminal);
    assert_eq!(terminal_outputs.yes.txout.script_pubkey.as_bytes(), &[0x6a]);
    assert_eq!(terminal_outputs.no.txout.script_pubkey.as_bytes(), &[0x6a]);

    assert_eq!(second_live.yes.factors.cbf, created.yes.factors.cbf);
    assert_eq!(second_live.no.factors.cbf, created.no.factors.cbf);
    if matches!(scheme, Scheme::Ab) {
        assert_eq!(second_live.yes.factors, factors(RtLeg::Yes, RtSide::A));
        assert_eq!(second_live.no.factors, factors(RtLeg::No, RtSide::A));
    }

    SchemeMetrics {
        scheme,
        transactions: vec![
            measure(
                "creation",
                &creation,
                creation_vsize,
                CovenantMetrics::default(),
            ),
            measure("explicit_transition", &first, first_vsize, first_covenant),
            measure(
                "confidential_transition",
                &second,
                second_vsize,
                second_covenant,
            ),
            measure(
                "terminal_burn",
                &terminal,
                terminal_vsize,
                terminal_covenant,
            ),
        ],
    }
}

#[test]
#[ignore = "starts elementsd and liquid-enabled Electrs from the Nix development shell"]
fn rolling_and_ab_chains_are_accepted_by_elementsd() {
    assert_eq!(add_mod_order(cbf(RtLeg::Yes), cbf(RtLeg::No)), [0; 32]);

    let (client, signer) =
        Regtest::from_config(&RegtestConfig::default()).expect("regtest environment");
    let network = SimplicityNetwork::default_regtest();
    let policy_asset = network.policy_asset();
    let miner = ElementsRpc::new(client.rpc_url(), client.auth()).expect("Elements RPC");
    let rpc = Client::new(&client.rpc_url(), client.auth()).expect("raw Elements RPC");
    let funding = prepare_funding(&signer, &rpc, &miner, policy_asset);

    let rolling = run_scheme(
        Scheme::Rolling,
        &signer,
        &rpc,
        &miner,
        &network,
        policy_asset,
        &funding[..5],
    );
    let ab = run_scheme(
        Scheme::Ab,
        &signer,
        &rpc,
        &miner,
        &network,
        policy_asset,
        &funding[5..],
    );

    assert!(ab.transactions[0].weight < rolling.transactions[0].weight);
    for index in 1..=3 {
        assert!(
            ab.transactions[index].covenant.cost_milliweight
                < rolling.transactions[index].covenant.cost_milliweight
        );
        assert!(
            ab.transactions[index].covenant.witness_bytes
                < rolling.transactions[index].covenant.witness_bytes
        );
        assert!(ab.transactions[index].weight < rolling.transactions[index].weight);
        assert!(ab.transactions[index].vsize < rolling.transactions[index].vsize);
        assert!(ab.transactions[index].discount_vsize < rolling.transactions[index].discount_vsize);
    }

    eprintln!(
        "{}",
        serde_json::to_string_pretty(&[rolling, ab]).expect("serialize metrics")
    );
}

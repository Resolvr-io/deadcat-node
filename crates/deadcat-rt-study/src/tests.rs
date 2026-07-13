use std::collections::HashMap;
use std::sync::Arc;

use deadcat_contracts::rt::{RtFactors, add_mod_order, commitments, continuation_factors};
use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::hashes::Hash as _;
use elements::pset::{Input as PsetInput, Output as PsetOutput, PartiallySignedTransaction};
use elements::secp256k1_zkp::rand::{SeedableRng as _, rngs::StdRng};
use elements::secp256k1_zkp::{Secp256k1, SecretKey, SurjectionProof, Tweak};
use elements::{AssetId, OutPoint, RangeProofMessage, TxOut, TxOutSecrets, TxOutWitness, Txid};
use simplex::program::{ProgramTrait as _, WitnessTrait as _};
use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::simplicity::RedeemNode;
use simplex::simplicityhl::simplicity::jet::Elements;

use crate::artifacts::rt_ab::{RtAbProgram, derived_rt_ab};
use crate::artifacts::rt_rolling::{RtRollingProgram, derived_rt_rolling};
use crate::schedule::{RtLeg, RtSide, cbf, factors, infer_side};

fn asset(byte: u8) -> AssetId {
    AssetId::from_slice(&[byte; 32]).expect("asset")
}

fn parts(serialized: [u8; 33]) -> (bool, [u8; 32]) {
    let mut x = [0; 32];
    x.copy_from_slice(&serialized[1..]);
    (serialized[0] & 1 != 0, x)
}

fn ab_program(asset_id: AssetId, leg: RtLeg) -> RtAbProgram {
    let (asset_a, value_a) = commitments(asset_id, factors(leg, RtSide::A)).expect("A");
    let (asset_b, value_b) = commitments(asset_id, factors(leg, RtSide::B)).expect("B");
    assert_eq!(
        value_a, value_b,
        "constant CBF keeps value commitment fixed"
    );
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

fn txout(asset_id: AssetId, factors: RtFactors, script_pubkey: elements::Script) -> TxOut {
    let (asset, value) = commitments(asset_id, factors).expect("commitments");
    TxOut {
        asset,
        value,
        nonce: Nonce::Null,
        script_pubkey,
        witness: TxOutWitness::default(),
    }
}

fn rangeproof_txout(
    asset_id: AssetId,
    output_factors: RtFactors,
    script_pubkey: elements::Script,
) -> TxOut {
    let secp = Secp256k1::new();
    let (asset, expected_value) = commitments(asset_id, output_factors).expect("commitments");
    let output_abf = AssetBlindingFactor::from_slice(&output_factors.abf).expect("output ABF");
    let output_vbf = ValueBlindingFactor::from_slice(&output_factors.vbf).expect("output VBF");
    let message = RangeProofMessage {
        asset: asset_id,
        bf: output_abf,
    };
    let rewind = SecretKey::from_slice(&[9; 32]).expect("rewind key");
    let (value, rangeproof) = Value::Explicit(1)
        .blind_with_shared_secret(&secp, output_vbf, rewind, &script_pubkey, &message)
        .expect("rangeproof");
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

fn install_surjection(
    pset: &mut PartiallySignedTransaction,
    asset_id: AssetId,
    output_factors: RtFactors,
    input_factors: RtFactors,
) {
    let input_abf = AssetBlindingFactor::from_slice(&input_factors.abf).expect("input ABF");
    let input_vbf = ValueBlindingFactor::from_slice(&input_factors.vbf).expect("input VBF");
    let mut secrets = HashMap::new();
    secrets.insert(0, TxOutSecrets::new(asset_id, input_abf, 1, input_vbf));
    let secp = Secp256k1::new();
    let domain = pset
        .surjection_inputs(&secrets)
        .expect("surjection inputs")
        .into_iter()
        .map(|input| input.surjection_target(&secp).expect("target"))
        .collect::<Vec<_>>();
    let mut rng = StdRng::from_seed([0x51; 32]);
    let proof = SurjectionProof::new(
        &secp,
        &mut rng,
        asset_id.into_tag(),
        Tweak::from_inner(output_factors.abf).expect("output ABF"),
        &domain,
    )
    .expect("surjection proof");
    let generators = domain.iter().map(|entry| entry.0).collect::<Vec<_>>();
    let output_generator = pset.outputs()[0]
        .to_txout()
        .asset
        .commitment()
        .expect("output generator");
    assert!(proof.verify(&secp, output_generator, &generators));
    pset.outputs_mut()[0].asset_surjection_proof = Some(Box::new(proof));
}

fn pset(outpoint: OutPoint, input: TxOut, output: TxOut) -> PartiallySignedTransaction {
    let mut pset = PartiallySignedTransaction::new_v2();
    let mut input_record = PsetInput::from_prevout(outpoint);
    input_record.witness_utxo = Some(input);
    pset.add_input(input_record);
    pset.add_output(PsetOutput::from_txout(output));
    pset
}

fn add_explicit_decoy_input(pset: &mut PartiallySignedTransaction) {
    let mut input = PsetInput::from_prevout(OutPoint::new(Txid::from_byte_array([0xdd; 32]), 1));
    input.witness_utxo = Some(TxOut {
        asset: Asset::Explicit(asset(0x99)),
        value: Value::Explicit(1),
        nonce: Nonce::Null,
        script_pubkey: elements::Script::from(vec![0x51]),
        witness: TxOutWitness::default(),
    });
    pset.add_input(input);
}

#[derive(Debug)]
struct Metrics {
    cost_milliweight: u32,
    program_bytes: usize,
    witness_bytes: usize,
    stack_bytes: usize,
    padding_bytes: usize,
    tx_bytes: usize,
    tx_weight: usize,
    tx_vsize: usize,
    tx_discount_weight: usize,
    tx_discount_vsize: usize,
}

fn metrics(
    node: &Arc<RedeemNode<Elements>>,
    mut stack: Vec<Vec<u8>>,
    mut pset: PartiallySignedTransaction,
) -> Metrics {
    let bounds = node.bounds();
    let cost_milliweight = bounds.cost.to_string().parse().expect("numeric cost");
    let (program, witness) = node.to_vec_with_witness();
    let stack_bytes = elements::encode::serialize(&stack).len();
    let padding_bytes = bounds.cost.get_padding(&stack).map_or(0, |padding| {
        let len = padding.len();
        stack.push(padding);
        len
    });
    assert!(bounds.cost.is_budget_valid(&stack));
    pset.inputs_mut()[0].final_script_witness = Some(stack);
    let transaction = pset.extract_tx().expect("final transaction");
    Metrics {
        cost_milliweight,
        program_bytes: program.len(),
        witness_bytes: witness.len(),
        stack_bytes,
        padding_bytes,
        tx_bytes: transaction.size(),
        tx_weight: transaction.weight(),
        tx_vsize: transaction.vsize(),
        tx_discount_weight: transaction.discount_weight(),
        tx_discount_vsize: transaction.discount_vsize(),
    }
}

#[test]
fn complementary_cbfs_balance_creation_and_sides_round_trip() {
    assert_eq!(add_mod_order(cbf(RtLeg::Yes), cbf(RtLeg::No)), [0; 32]);
    for (leg, asset_id) in [(RtLeg::Yes, asset(0x11)), (RtLeg::No, asset(0x22))] {
        for side in [RtSide::A, RtSide::B] {
            let (asset_commitment, value_commitment) =
                commitments(asset_id, factors(leg, side)).expect("commitments");
            assert_eq!(
                infer_side(leg, asset_id, asset_commitment, value_commitment),
                Ok(side)
            );
        }
        assert_eq!(factors(leg, RtSide::A).cbf, factors(leg, RtSide::B).cbf);
        assert_ne!(factors(leg, RtSide::A).abf, factors(leg, RtSide::B).abf);
    }
}

#[test]
fn equal_input_and_output_generators_cannot_produce_a_surjection_proof() {
    let asset_id = asset(0x23);
    let factors = factors(RtLeg::Yes, RtSide::A);
    let generator = commitments(asset_id, factors)
        .expect("commitments")
        .0
        .commitment()
        .expect("generator");
    let domain = [(
        generator,
        asset_id.into_tag(),
        Tweak::from_inner(factors.abf).expect("ABF"),
    )];
    assert!(
        SurjectionProof::new(
            &Secp256k1::new(),
            &mut StdRng::from_seed([0x23; 32]),
            asset_id.into_tag(),
            Tweak::from_inner(factors.abf).expect("ABF"),
            &domain,
        )
        .is_err()
    );
}

#[test]
fn current_rolling_creation_cbfs_are_not_locally_balanced() {
    let yes = deadcat_contracts::rt::creation_factors(OutPoint::new(
        Txid::from_byte_array([0x24; 32]),
        0,
    ));
    let no = deadcat_contracts::rt::creation_factors(OutPoint::new(
        Txid::from_byte_array([0x25; 32]),
        1,
    ));
    assert_ne!(add_mod_order(yes.cbf, no.cbf), [0; 32]);
    assert_eq!(add_mod_order(cbf(RtLeg::Yes), cbf(RtLeg::No)), [0; 32]);
}

#[test]
fn public_ab_schedule_has_stable_scalar_vectors() {
    assert_eq!(hex::encode(crate::schedule::ABF_A), "01".repeat(32));
    assert_eq!(hex::encode(crate::schedule::ABF_B), "02".repeat(32));
    assert_eq!(hex::encode(crate::schedule::YES_CBF), "03".repeat(32));
    assert_eq!(
        hex::encode(crate::schedule::no_cbf()),
        "fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfbb7abd9e3ac459d38bccf5b89cd333e3e"
    );
    assert_eq!(
        hex::encode(factors(RtLeg::No, RtSide::A).vbf),
        "fbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfab6aad8e2ab449c37bbce5a88cc323d3d"
    );
    assert_eq!(
        hex::encode(factors(RtLeg::No, RtSide::B).vbf),
        "fafafafafafafafafafafafafafafaf9b5a9d7e1aa439b36bacd5987cb313c3c"
    );
}

#[test]
fn ab_contract_accepts_both_flips_and_rejects_same_side() {
    let asset_id = asset(0x31);
    let network = SimplicityNetwork::ElementsRegtest {
        policy_asset: asset_id,
    };
    for input_side in [RtSide::A, RtSide::B] {
        let program = ab_program(asset_id, RtLeg::Yes);
        let script = program.get_script_pubkey(&network);
        let outpoint = OutPoint::new(Txid::from_byte_array([input_side as u8 + 1; 32]), 7);
        let valid = pset(
            outpoint,
            txout(asset_id, factors(RtLeg::Yes, input_side), script.clone()),
            txout(
                asset_id,
                factors(RtLeg::Yes, input_side.flip()),
                script.clone(),
            ),
        );
        let witness = derived_rt_ab::RtAbWitness {
            output_index: 0,
            terminal: false,
        };
        program
            .as_ref()
            .execute(&valid, &witness.build_witness(), 0, &network)
            .expect("opposite-side continuation");

        let invalid = pset(
            outpoint,
            txout(asset_id, factors(RtLeg::Yes, input_side), script.clone()),
            txout(asset_id, factors(RtLeg::Yes, input_side), script),
        );
        assert!(
            program
                .as_ref()
                .execute(&invalid, &witness.build_witness(), 0, &network)
                .is_err()
        );
    }
}

#[test]
fn ab_rejects_wrong_leg_value_commitment() {
    let asset_id = asset(0x32);
    let network = SimplicityNetwork::ElementsRegtest {
        policy_asset: asset_id,
    };
    let program = ab_program(asset_id, RtLeg::Yes);
    let script = program.get_script_pubkey(&network);
    let invalid = pset(
        OutPoint::new(Txid::from_byte_array([3; 32]), 9),
        txout(asset_id, factors(RtLeg::Yes, RtSide::A), script.clone()),
        txout(asset_id, factors(RtLeg::No, RtSide::B), script),
    );
    assert!(
        program
            .as_ref()
            .execute(
                &invalid,
                &derived_rt_ab::RtAbWitness {
                    output_index: 0,
                    terminal: false,
                }
                .build_witness(),
                0,
                &network,
            )
            .is_err()
    );
}

#[test]
fn rolling_contract_rejects_wrong_outpoint_wrong_cbf_and_wrong_witness() {
    let asset_id = asset(0x33);
    let network = SimplicityNetwork::ElementsRegtest {
        policy_asset: asset_id,
    };
    let program = rolling_program(asset_id);
    let script = program.get_script_pubkey(&network);
    let outpoint = OutPoint::new(Txid::from_byte_array([0x33; 32]), 4);
    let input = deadcat_contracts::rt::creation_factors(OutPoint::new(
        Txid::from_byte_array([0x34; 32]),
        5,
    ));
    let witness = derived_rt_rolling::RtRollingWitness {
        output_index: 0,
        input_abf: input.abf,
        input_cbf: input.cbf,
        terminal: false,
    };
    let valid = pset(
        outpoint,
        txout(asset_id, input, script.clone()),
        txout(
            asset_id,
            continuation_factors(outpoint, input.cbf),
            script.clone(),
        ),
    );
    program
        .as_ref()
        .execute(&valid, &witness.build_witness(), 0, &network)
        .expect("rolling continuation");

    let wrong_outpoint = pset(
        outpoint,
        txout(asset_id, input, script.clone()),
        txout(
            asset_id,
            continuation_factors(
                OutPoint::new(Txid::from_byte_array([0x35; 32]), 4),
                input.cbf,
            ),
            script.clone(),
        ),
    );
    assert!(
        program
            .as_ref()
            .execute(&wrong_outpoint, &witness.build_witness(), 0, &network)
            .is_err()
    );

    let wrong_cbf = pset(
        outpoint,
        txout(asset_id, input, script.clone()),
        txout(asset_id, continuation_factors(outpoint, [0x36; 32]), script),
    );
    assert!(
        program
            .as_ref()
            .execute(&wrong_cbf, &witness.build_witness(), 0, &network)
            .is_err()
    );

    let wrong_witness = derived_rt_rolling::RtRollingWitness {
        input_abf: [0x37; 32],
        ..witness
    };
    assert!(
        program
            .as_ref()
            .execute(&valid, &wrong_witness.build_witness(), 0, &network)
            .is_err()
    );
}

#[test]
fn isolated_contract_metrics_show_the_factor_witness_and_hashing_delta() {
    let asset_id = asset(0x41);
    let network = SimplicityNetwork::ElementsRegtest {
        policy_asset: asset_id,
    };
    let outpoint = OutPoint::new(Txid::from_byte_array([4; 32]), 11);

    let rolling = rolling_program(asset_id);
    let rolling_script = rolling.get_script_pubkey(&network);
    let rolling_input = deadcat_contracts::rt::creation_factors(OutPoint::new(
        Txid::from_byte_array([0x44; 32]),
        3,
    ));
    let rolling_output = continuation_factors(outpoint, rolling_input.cbf);
    let mut rolling_pset = pset(
        outpoint,
        txout(asset_id, rolling_input, rolling_script.clone()),
        rangeproof_txout(asset_id, rolling_output, rolling_script),
    );
    add_explicit_decoy_input(&mut rolling_pset);
    install_surjection(&mut rolling_pset, asset_id, rolling_output, rolling_input);
    let rolling_witness = derived_rt_rolling::RtRollingWitness {
        output_index: 0,
        input_abf: rolling_input.abf,
        input_cbf: rolling_input.cbf,
        terminal: false,
    };
    let (rolling_node, _) = rolling
        .as_ref()
        .execute(&rolling_pset, &rolling_witness.build_witness(), 0, &network)
        .expect("rolling execution");
    let rolling_stack = rolling
        .as_ref()
        .finalize(&rolling_pset, &rolling_witness.build_witness(), 0, &network)
        .expect("rolling stack");

    let ab = ab_program(asset_id, RtLeg::Yes);
    let ab_script = ab.get_script_pubkey(&network);
    let ab_input = factors(RtLeg::Yes, RtSide::A);
    let ab_output = factors(RtLeg::Yes, RtSide::B);
    let mut ab_pset = pset(
        outpoint,
        txout(asset_id, ab_input, ab_script.clone()),
        rangeproof_txout(asset_id, ab_output, ab_script),
    );
    add_explicit_decoy_input(&mut ab_pset);
    install_surjection(&mut ab_pset, asset_id, ab_output, ab_input);
    let ab_witness = derived_rt_ab::RtAbWitness {
        output_index: 0,
        terminal: false,
    };
    let (ab_node, _) = ab
        .as_ref()
        .execute(&ab_pset, &ab_witness.build_witness(), 0, &network)
        .expect("A/B execution");
    let ab_stack = ab
        .as_ref()
        .finalize(&ab_pset, &ab_witness.build_witness(), 0, &network)
        .expect("A/B stack");

    let rolling_metrics = metrics(&rolling_node, rolling_stack, rolling_pset);
    let ab_metrics = metrics(&ab_node, ab_stack, ab_pset);
    eprintln!("rolling={rolling_metrics:?} A/B={ab_metrics:?}");
    assert!(ab_metrics.witness_bytes < rolling_metrics.witness_bytes);
    assert!(ab_metrics.cost_milliweight < rolling_metrics.cost_milliweight);
    assert!(ab_metrics.program_bytes < rolling_metrics.program_bytes);
    assert!(ab_metrics.stack_bytes < rolling_metrics.stack_bytes);
    assert!(ab_metrics.padding_bytes <= rolling_metrics.padding_bytes);
    assert!(ab_metrics.tx_bytes < rolling_metrics.tx_bytes);
    assert!(ab_metrics.tx_weight < rolling_metrics.tx_weight);
    assert!(ab_metrics.tx_vsize < rolling_metrics.tx_vsize);
    assert!(ab_metrics.tx_discount_weight < rolling_metrics.tx_discount_weight);
    assert!(ab_metrics.tx_discount_vsize < rolling_metrics.tx_discount_vsize);
}

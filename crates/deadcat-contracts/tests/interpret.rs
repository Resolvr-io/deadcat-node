//! Confirmed-transaction interpreter tests using extracted, finalized spends.

mod support;

use deadcat_contracts::binary_market::{
    BinaryMarketAction, BinaryMarketSlot, CompiledBinaryMarket, derived_binary_market,
};
use deadcat_contracts::interpret::{
    BinaryMarketLiveOutputs, BinaryMarketPath, InterpretError, MakerOrderSpendKind,
    TrackedContractOutput, interpret_binary_market_spend, interpret_maker_order_spend,
};
use deadcat_contracts::maker_order::{CompiledMakerOrder, derived_maker_order};
use deadcat_contracts::rt::{RtFactors, RtLeg, RtSide, factors};
use deadcat_types::{
    BinaryMarketParams, BinaryMarketState, MakerOrderParams, MakerOrderState, OrderDirection,
};
use elements::confidential::{Asset, Nonce, Value};
use elements::hashes::{Hash as _, HashEngine as _, sha256};
use elements::pset::PartiallySignedTransaction;
use elements::secp256k1_zkp::{Generator, Keypair, PedersenCommitment, Secp256k1, Tweak};
use elements::{LockTime, OutPoint, Script, Sequence, Transaction, TxOut, TxOutWitness};
use simplex::program::{ProgramTrait as _, WitnessTrait as _};

use support::{asset, bare_op_return, explicit_txout, network, pset_input, pset_output, script};

fn key(seed: u8) -> [u8; 32] {
    Keypair::from_seckey_slice(&Secp256k1::new(), &[seed; 32])
        .expect("valid key")
        .x_only_public_key()
        .0
        .serialize()
}

fn script_hash(script: &Script) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    engine.input(script.as_bytes());
    sha256::Hash::from_engine(engine).to_byte_array()
}

fn maker_params(direction: OrderDirection) -> MakerOrderParams {
    MakerOrderParams {
        base_asset_id: asset(0x11),
        quote_asset_id: asset(0x22),
        price: 7,
        min_active_base: 3,
        direction,
        maker_receive_spk_hash: script_hash(&script(0x42)),
        maker_pubkey: key(0x31),
    }
}

struct MakerScenario {
    params: MakerOrderParams,
    before: MakerOrderState,
    live: TrackedContractOutput,
    transaction: Transaction,
}

fn maker_fill_scenario(
    direction: OrderDirection,
    partial: bool,
    decoy_remainder: bool,
    annex: bool,
) -> MakerScenario {
    let params = maker_params(direction);
    let compiled = CompiledMakerOrder::new(params).expect("compile order");
    let input_amount = match direction {
        OrderDirection::SellBase => 10,
        OrderDirection::SellQuote => 70,
    };
    let payment = match (direction, partial) {
        (OrderDirection::SellBase, false) => 70,
        (OrderDirection::SellBase, true) => 28,
        (OrderDirection::SellQuote, false) => 10,
        (OrderDirection::SellQuote, true) => 4,
    };
    let input_asset = match direction {
        OrderDirection::SellBase => params.base_asset_id,
        OrderDirection::SellQuote => params.quote_asset_id,
    };
    let payment_asset = match direction {
        OrderDirection::SellBase => params.quote_asset_id,
        OrderDirection::SellQuote => params.base_asset_id,
    };
    let previous = OutPoint::new(elements::Txid::from_byte_array([0xa1; 32]), 0);
    let live_txout = explicit_txout(input_asset, input_amount, compiled.script_pubkey().clone());
    let mut pset = PartiallySignedTransaction::new_v2();
    let mut input = pset_input(0xa1, 0, live_txout.clone());
    input.previous_txid = previous.txid;
    pset.add_input(input);
    pset.add_output(pset_output(explicit_txout(
        payment_asset,
        payment,
        script(0x42),
    )));

    let remainder_index = if partial {
        if decoy_remainder {
            pset.add_output(pset_output(explicit_txout(
                input_asset,
                5,
                compiled.script_pubkey().clone(),
            )));
            2
        } else {
            1
        }
    } else {
        // A full fill must not adopt a same-script decoy.
        pset.add_output(pset_output(explicit_txout(
            input_asset,
            6,
            compiled.script_pubkey().clone(),
        )));
        1
    };
    if partial {
        let remainder = match direction {
            OrderDirection::SellBase => 6,
            OrderDirection::SellQuote => 42,
        };
        pset.add_output(pset_output(explicit_txout(
            input_asset,
            remainder,
            compiled.script_pubkey().clone(),
        )));
    }

    let witness = derived_maker_order::MakerOrderWitness { remainder_index };
    let net = network(params.quote_asset_id);
    let mut stack = compiled
        .program()
        .as_ref()
        .finalize(&pset, &witness.build_witness(), 0, &net)
        .expect("finalize maker fill");
    if annex {
        stack.push(vec![0x50, 0x01]);
    }
    let mut transaction = pset.extract_tx().expect("extract maker tx");
    transaction.input[0].witness.script_witness = stack;
    MakerScenario {
        params,
        before: MakerOrderState::Active {
            remaining_base: 10,
            total_filled_base: 0,
        },
        live: TrackedContractOutput {
            outpoint: previous,
            txout: live_txout,
        },
        transaction,
    }
}

#[test]
fn interprets_all_maker_fill_transitions_from_finalized_transactions() {
    for direction in [OrderDirection::SellBase, OrderDirection::SellQuote] {
        let full = maker_fill_scenario(direction, false, false, false);
        let interpreted =
            interpret_maker_order_spend(full.params, full.before, &full.live, &full.transaction)
                .expect("interpret full fill");
        assert!(matches!(interpreted.kind, MakerOrderSpendKind::Fill(_)));
        assert_eq!(interpreted.after, MakerOrderState::Consumed);
        assert!(interpreted.continuation.is_none());

        let partial = maker_fill_scenario(direction, true, false, false);
        let interpreted = interpret_maker_order_spend(
            partial.params,
            partial.before,
            &partial.live,
            &partial.transaction,
        )
        .expect("interpret partial fill");
        assert_eq!(
            interpreted.after,
            MakerOrderState::Active {
                remaining_base: 6,
                total_filled_base: 4,
            }
        );
        assert_eq!(interpreted.remainder_index, Some(1));
    }
}

#[test]
fn maker_interpreter_uses_designated_remainder_and_handles_annex() {
    let scenario = maker_fill_scenario(OrderDirection::SellBase, true, true, true);
    let interpreted = interpret_maker_order_spend(
        scenario.params,
        scenario.before,
        &scenario.live,
        &scenario.transaction,
    )
    .expect("interpret designated remainder");
    assert_eq!(interpreted.remainder_index, Some(2));
    assert_eq!(
        interpreted
            .continuation
            .expect("continuation")
            .outpoint
            .vout,
        2
    );
    assert!(interpreted.annex_present);
}

#[test]
fn maker_key_spend_is_cancellation_after_annex_stripping() {
    let params = maker_params(OrderDirection::SellBase);
    let compiled = CompiledMakerOrder::new(params).expect("compile order");
    let previous = OutPoint::new(elements::Txid::from_byte_array([0xb1; 32]), 0);
    let live_txout = explicit_txout(params.base_asset_id, 10, compiled.script_pubkey().clone());
    let mut pset = PartiallySignedTransaction::new_v2();
    let mut input = pset_input(0xb1, 0, live_txout.clone());
    input.previous_txid = previous.txid;
    pset.add_input(input);
    pset.add_output(pset_output(explicit_txout(
        params.base_asset_id,
        10,
        script(0x77),
    )));
    let mut transaction = pset.extract_tx().expect("extract cancellation");
    transaction.input[0].witness.script_witness = vec![vec![1; 64], vec![0x50, 0x99]];
    let before = MakerOrderState::Active {
        remaining_base: 10,
        total_filled_base: 0,
    };
    let interpreted = interpret_maker_order_spend(
        params,
        before,
        &TrackedContractOutput {
            outpoint: previous,
            txout: live_txout,
        },
        &transaction,
    )
    .expect("interpret cancellation");
    assert_eq!(interpreted.kind, MakerOrderSpendKind::Cancel);
    assert_eq!(interpreted.after, MakerOrderState::Cancelled);
    assert!(interpreted.annex_present);
}

fn binary_params() -> BinaryMarketParams {
    BinaryMarketParams {
        oracle_public_key: key(0x41),
        collateral_asset_id: asset(0x61),
        yes_token_asset_id: asset(0x62),
        no_token_asset_id: asset(0x63),
        yes_reissuance_token_id: asset(0x64),
        no_reissuance_token_id: asset(0x65),
        base_payout: 100,
        expiry_height: 500,
    }
}

struct BinaryScenario {
    params: BinaryMarketParams,
    before: BinaryMarketState,
    live: BinaryMarketLiveOutputs,
    transaction: Transaction,
}

fn resolved_redemption_scenario(full: bool, decoy: bool, annex: bool) -> BinaryScenario {
    let params = binary_params();
    let compiled = CompiledBinaryMarket::new(params).expect("compile market");
    let before = BinaryMarketState::ResolvedYes {
        collateral_unredeemed: 600,
    };
    let previous = OutPoint::new(elements::Txid::from_byte_array([0xc1; 32]), 0);
    let live_txout = explicit_txout(
        params.collateral_asset_id,
        600,
        compiled
            .slot(BinaryMarketSlot::ResolvedYesCollateral)
            .script_pubkey()
            .clone(),
    );
    let mut pset = PartiallySignedTransaction::new_v2();
    let mut input = pset_input(0xc1, 0, live_txout.clone());
    input.previous_txid = previous.txid;
    pset.add_input(input);

    let (tokens, output_base) = if full {
        pset.add_output(pset_output(explicit_txout(
            params.yes_token_asset_id,
            3,
            bare_op_return(),
        )));
        (3, 0)
    } else if decoy {
        pset.add_output(pset_output(explicit_txout(
            params.collateral_asset_id,
            399,
            compiled
                .slot(BinaryMarketSlot::ResolvedYesCollateral)
                .script_pubkey()
                .clone(),
        )));
        pset.add_output(pset_output(explicit_txout(
            params.collateral_asset_id,
            1,
            script(0x88),
        )));
        pset.add_output(pset_output(explicit_txout(
            params.collateral_asset_id,
            400,
            compiled
                .slot(BinaryMarketSlot::ResolvedYesCollateral)
                .script_pubkey()
                .clone(),
        )));
        pset.add_output(pset_output(explicit_txout(
            params.yes_token_asset_id,
            1,
            bare_op_return(),
        )));
        (1, 2)
    } else {
        pset.add_output(pset_output(explicit_txout(
            params.collateral_asset_id,
            400,
            compiled
                .slot(BinaryMarketSlot::ResolvedYesCollateral)
                .script_pubkey()
                .clone(),
        )));
        pset.add_output(pset_output(explicit_txout(
            params.yes_token_asset_id,
            1,
            bare_op_return(),
        )));
        (1, 0)
    };
    // Unconstrained wallet payout; present only to make the economic shape clear.
    pset.add_output(pset_output(explicit_txout(
        params.collateral_asset_id,
        tokens * 200,
        script(0x90),
    )));

    let witness = derived_binary_market::BinaryMarketWitness {
        path: 8,
        slot: BinaryMarketSlot::ResolvedYesCollateral as u8,
        output_base,
        oracle_outcome_yes: false,
        oracle_signature: [0; 64],
        tokens_burned: tokens,
        redeem_yes: false,
    };
    let net = network(params.collateral_asset_id);
    let mut stack = compiled
        .program(BinaryMarketSlot::ResolvedYesCollateral)
        .as_ref()
        .finalize(&pset, &witness.build_witness(), 0, &net)
        .expect("finalize redemption");
    if annex {
        stack.push(vec![0x50, 0x01]);
    }
    let mut transaction = pset.extract_tx().expect("extract market tx");
    transaction.input[0].witness.script_witness = stack;
    BinaryScenario {
        params,
        before,
        live: BinaryMarketLiveOutputs {
            yes_rt: None,
            no_rt: None,
            collateral: Some(TrackedContractOutput {
                outpoint: previous,
                txout: live_txout,
            }),
        },
        transaction,
    }
}

#[test]
fn interprets_partial_and_full_market_redemptions() {
    let partial = resolved_redemption_scenario(false, false, true);
    let interpreted = interpret_binary_market_spend(
        partial.params,
        partial.before,
        &partial.live,
        &partial.transaction,
    )
    .expect("interpret partial redemption");
    assert_eq!(interpreted.path, BinaryMarketPath::ResolvedRedemption);
    assert_eq!(
        interpreted.action,
        BinaryMarketAction::Redeem {
            outcome: deadcat_contracts::binary_market::BinaryOutcome::Yes,
            tokens: 1,
        }
    );
    assert_eq!(
        interpreted.after,
        BinaryMarketState::ResolvedYes {
            collateral_unredeemed: 400,
        }
    );
    assert_eq!(interpreted.continuations[0].output.outpoint.vout, 0);

    let full = resolved_redemption_scenario(true, false, false);
    let interpreted =
        interpret_binary_market_spend(full.params, full.before, &full.live, &full.transaction)
            .expect("interpret full redemption");
    assert_eq!(
        interpreted.after,
        BinaryMarketState::ResolvedYes {
            collateral_unredeemed: 0,
        }
    );
    assert!(interpreted.continuations.is_empty());
}

#[test]
fn market_interpreter_uses_witness_output_base_not_first_matching_script() {
    let scenario = resolved_redemption_scenario(false, true, false);
    let interpreted = interpret_binary_market_spend(
        scenario.params,
        scenario.before,
        &scenario.live,
        &scenario.transaction,
    )
    .expect("interpret witness-designated continuation");
    assert_eq!(interpreted.output_base, 2);
    assert_eq!(interpreted.continuations[0].output.outpoint.vout, 2);
}

#[test]
fn interpreters_reject_tampered_designated_outputs_and_control_blocks() {
    let mut maker = maker_fill_scenario(OrderDirection::SellBase, true, false, false);
    maker.transaction.output[1].value = elements::confidential::Value::Explicit(5);
    assert!(
        interpret_maker_order_spend(maker.params, maker.before, &maker.live, &maker.transaction,)
            .is_err()
    );

    let mut market = resolved_redemption_scenario(false, false, false);
    let compiled = CompiledBinaryMarket::new(market.params).expect("compile market");
    market.transaction.input[0].witness.script_witness[3] = compiled
        .slot(BinaryMarketSlot::ResolvedNoCollateral)
        .control_block()
        .serialize();
    let error = interpret_binary_market_spend(
        market.params,
        market.before,
        &market.live,
        &market.transaction,
    )
    .expect_err("wrong slot control block");
    assert!(matches!(error, InterpretError::Inconsistent(_)));
}

fn confidential_rt_txout(
    asset_id: elements::AssetId,
    factors: RtFactors,
    script_pubkey: Script,
) -> TxOut {
    let secp = Secp256k1::new();
    let generator = Generator::new_blinded(
        &secp,
        asset_id.into_tag(),
        Tweak::from_inner(factors.abf).expect("ABF"),
    );
    let commitment = PedersenCommitment::new(
        &secp,
        1,
        Tweak::from_inner(factors.vbf).expect("VBF"),
        generator,
    );
    TxOut {
        asset: Asset::Confidential(generator),
        value: Value::Confidential(commitment),
        nonce: Nonce::Null,
        script_pubkey,
        witness: TxOutWitness::default(),
    }
}

fn finalized_active_expiry(side: RtSide) -> BinaryScenario {
    let params = binary_params();
    let compiled = CompiledBinaryMarket::new(params).expect("compile market");
    let before = BinaryMarketState::Trading {
        outstanding_pairs: 3,
    };
    let yes_input = factors(RtLeg::Yes, side);
    let no_input = factors(RtLeg::No, side);
    let yes_burn = factors(RtLeg::Yes, side.flip());
    let no_burn = factors(RtLeg::No, side.flip());
    let common_txid = elements::Txid::from_byte_array([0xd1; 32]);
    let yes_outpoint = OutPoint::new(common_txid, 10);
    let no_outpoint = OutPoint::new(common_txid, 11);
    let collateral_outpoint = OutPoint::new(common_txid, 12);
    let yes_txout = confidential_rt_txout(
        params.yes_reissuance_token_id,
        yes_input,
        compiled
            .slot(BinaryMarketSlot::UnresolvedYesRt)
            .script_pubkey()
            .clone(),
    );
    let no_txout = confidential_rt_txout(
        params.no_reissuance_token_id,
        no_input,
        compiled
            .slot(BinaryMarketSlot::UnresolvedNoRt)
            .script_pubkey()
            .clone(),
    );
    let collateral_txout = explicit_txout(
        params.collateral_asset_id,
        600,
        compiled
            .slot(BinaryMarketSlot::UnresolvedCollateral)
            .script_pubkey()
            .clone(),
    );
    let mut pset = PartiallySignedTransaction::new_v2();
    pset.global.tx_data.fallback_locktime =
        Some(LockTime::from_height(params.expiry_height).expect("height"));
    for (outpoint, txout) in [
        (yes_outpoint, yes_txout.clone()),
        (no_outpoint, no_txout.clone()),
        (collateral_outpoint, collateral_txout.clone()),
    ] {
        let mut input = pset_input(0xd1, outpoint.vout, txout);
        input.previous_txid = common_txid;
        input.sequence = Some(Sequence(0xffff_fffe));
        pset.add_input(input);
    }
    // Same-script decoy at vout 0; the decoded OUTPUT_BASE is 2.
    pset.add_output(pset_output(explicit_txout(
        params.collateral_asset_id,
        599,
        compiled
            .slot(BinaryMarketSlot::ExpiredCollateral)
            .script_pubkey()
            .clone(),
    )));
    pset.add_output(pset_output(explicit_txout(
        params.collateral_asset_id,
        1,
        script(0x91),
    )));
    pset.add_output(pset_output(confidential_rt_txout(
        params.yes_reissuance_token_id,
        yes_burn,
        bare_op_return(),
    )));
    pset.add_output(pset_output(confidential_rt_txout(
        params.no_reissuance_token_id,
        no_burn,
        bare_op_return(),
    )));
    pset.add_output(pset_output(explicit_txout(
        params.collateral_asset_id,
        600,
        compiled
            .slot(BinaryMarketSlot::ExpiredCollateral)
            .script_pubkey()
            .clone(),
    )));

    let witness = derived_binary_market::BinaryMarketWitness {
        path: 6,
        slot: BinaryMarketSlot::UnresolvedYesRt as u8,
        output_base: 2,
        oracle_outcome_yes: false,
        oracle_signature: [0; 64],
        tokens_burned: 0,
        redeem_yes: false,
    };
    let net = network(params.collateral_asset_id);
    let stack = compiled
        .program(BinaryMarketSlot::UnresolvedYesRt)
        .as_ref()
        .finalize(&pset, &witness.build_witness(), 0, &net)
        .expect("finalize active expiry");
    let mut transaction = pset.extract_tx().expect("extract expiry");
    transaction.input[0].witness.script_witness = stack;
    BinaryScenario {
        params,
        before,
        live: BinaryMarketLiveOutputs {
            yes_rt: Some(TrackedContractOutput {
                outpoint: yes_outpoint,
                txout: yes_txout,
            }),
            no_rt: Some(TrackedContractOutput {
                outpoint: no_outpoint,
                txout: no_txout,
            }),
            collateral: Some(TrackedContractOutput {
                outpoint: collateral_outpoint,
                txout: collateral_txout,
            }),
        },
        transaction,
    }
}

#[test]
fn interprets_active_expiry_and_rejects_nonconsecutive_sibling_decoy() {
    for side in [RtSide::A, RtSide::B] {
        let scenario = finalized_active_expiry(side);
        let interpreted = interpret_binary_market_spend(
            scenario.params,
            scenario.before,
            &scenario.live,
            &scenario.transaction,
        )
        .unwrap_or_else(|error| panic!("interpret {side:?} expiry: {error}"));
        assert_eq!(interpreted.path, BinaryMarketPath::ActiveExpiry);
        assert_eq!(interpreted.output_base, 2);
        assert_eq!(
            interpreted.after,
            BinaryMarketState::Expired {
                collateral_unredeemed: 600,
            }
        );
        assert_eq!(interpreted.continuations[0].output.outpoint.vout, 4);
    }

    let scenario = finalized_active_expiry(RtSide::A);

    let mut decoy = scenario.transaction.clone();
    decoy.input[2].previous_output.vout = 13;
    assert!(
        interpret_binary_market_spend(scenario.params, scenario.before, &scenario.live, &decoy,)
            .is_err()
    );

    let mut wrong_burn = scenario.transaction.clone();
    wrong_burn.output[2] = confidential_rt_txout(
        scenario.params.yes_reissuance_token_id,
        factors(RtLeg::Yes, RtSide::A),
        bare_op_return(),
    );
    assert!(
        interpret_binary_market_spend(
            scenario.params,
            scenario.before,
            &scenario.live,
            &wrong_burn,
        )
        .is_err()
    );
}

#[test]
fn interprets_partial_cancellation_when_path_equals_slot_and_bases_are_shared() {
    let params = binary_params();
    let compiled = CompiledBinaryMarket::new(params).expect("compile market");
    let before = BinaryMarketState::Trading {
        outstanding_pairs: 3,
    };
    let yes_input = factors(RtLeg::Yes, RtSide::A);
    let no_input = factors(RtLeg::No, RtSide::A);
    let common_txid = elements::Txid::from_byte_array([0xe1; 32]);
    let yes_outpoint = OutPoint::new(common_txid, 10);
    let no_outpoint = OutPoint::new(common_txid, 11);
    let collateral_outpoint = OutPoint::new(common_txid, 12);
    let yes_txout = confidential_rt_txout(
        params.yes_reissuance_token_id,
        yes_input,
        compiled
            .slot(BinaryMarketSlot::UnresolvedYesRt)
            .script_pubkey()
            .clone(),
    );
    let no_txout = confidential_rt_txout(
        params.no_reissuance_token_id,
        no_input,
        compiled
            .slot(BinaryMarketSlot::UnresolvedNoRt)
            .script_pubkey()
            .clone(),
    );
    let collateral_txout = explicit_txout(
        params.collateral_asset_id,
        600,
        compiled
            .slot(BinaryMarketSlot::UnresolvedCollateral)
            .script_pubkey()
            .clone(),
    );
    let mut pset = PartiallySignedTransaction::new_v2();
    for (outpoint, txout) in [
        (yes_outpoint, yes_txout.clone()),
        (no_outpoint, no_txout.clone()),
        (collateral_outpoint, collateral_txout.clone()),
    ] {
        let mut input = pset_input(0xe1, outpoint.vout, txout);
        input.previous_txid = common_txid;
        pset.add_input(input);
    }
    pset.add_output(pset_output(confidential_rt_txout(
        params.yes_reissuance_token_id,
        factors(RtLeg::Yes, RtSide::B),
        compiled
            .slot(BinaryMarketSlot::UnresolvedYesRt)
            .script_pubkey()
            .clone(),
    )));
    pset.add_output(pset_output(confidential_rt_txout(
        params.no_reissuance_token_id,
        factors(RtLeg::No, RtSide::B),
        compiled
            .slot(BinaryMarketSlot::UnresolvedNoRt)
            .script_pubkey()
            .clone(),
    )));
    pset.add_output(pset_output(explicit_txout(
        params.collateral_asset_id,
        400,
        compiled
            .slot(BinaryMarketSlot::UnresolvedCollateral)
            .script_pubkey()
            .clone(),
    )));
    pset.add_output(pset_output(explicit_txout(
        params.yes_token_asset_id,
        1,
        bare_op_return(),
    )));
    pset.add_output(pset_output(explicit_txout(
        params.no_token_asset_id,
        1,
        bare_op_return(),
    )));
    pset.add_output(pset_output(explicit_txout(
        params.collateral_asset_id,
        200,
        script(0x92),
    )));
    let witness = derived_binary_market::BinaryMarketWitness {
        path: 2,
        slot: 2,
        output_base: 0,
        oracle_outcome_yes: false,
        oracle_signature: [0; 64],
        tokens_burned: 0,
        redeem_yes: false,
    };
    let net = network(params.collateral_asset_id);
    let stack = compiled
        .program(BinaryMarketSlot::UnresolvedYesRt)
        .as_ref()
        .finalize(&pset, &witness.build_witness(), 0, &net)
        .expect("finalize partial cancellation");
    let mut transaction = pset.extract_tx().expect("extract cancellation");
    transaction.input[0].witness.script_witness = stack;
    let live = BinaryMarketLiveOutputs {
        yes_rt: Some(TrackedContractOutput {
            outpoint: yes_outpoint,
            txout: yes_txout,
        }),
        no_rt: Some(TrackedContractOutput {
            outpoint: no_outpoint,
            txout: no_txout,
        }),
        collateral: Some(TrackedContractOutput {
            outpoint: collateral_outpoint,
            txout: collateral_txout,
        }),
    };
    let interpreted = interpret_binary_market_spend(params, before, &live, &transaction)
        .expect("interpret cancellation");
    assert_eq!(interpreted.path, BinaryMarketPath::PartialCancellation);
    assert_eq!(interpreted.input_base, 0);
    assert_eq!(interpreted.output_base, 0);
    assert_eq!(
        interpreted.after,
        BinaryMarketState::Trading {
            outstanding_pairs: 2,
        }
    );

    let mut wrong_continuation = transaction.clone();
    wrong_continuation.output[0] = confidential_rt_txout(
        params.yes_reissuance_token_id,
        factors(RtLeg::Yes, RtSide::A),
        compiled
            .slot(BinaryMarketSlot::UnresolvedYesRt)
            .script_pubkey()
            .clone(),
    );
    assert!(interpret_binary_market_spend(params, before, &live, &wrong_continuation).is_err());

    let mut mismatched_sides = live.clone();
    mismatched_sides.no_rt.as_mut().expect("NO RT").txout = confidential_rt_txout(
        params.no_reissuance_token_id,
        factors(RtLeg::No, RtSide::B),
        compiled
            .slot(BinaryMarketSlot::UnresolvedNoRt)
            .script_pubkey()
            .clone(),
    );
    assert!(
        interpret_binary_market_spend(params, before, &mismatched_sides, &transaction).is_err()
    );

    let mut wrong_live = live;
    wrong_live.yes_rt.as_mut().expect("YES RT").txout = confidential_rt_txout(
        params.yes_reissuance_token_id,
        factors(RtLeg::No, RtSide::A),
        compiled
            .slot(BinaryMarketSlot::UnresolvedYesRt)
            .script_pubkey()
            .clone(),
    );
    assert!(interpret_binary_market_spend(params, before, &wrong_live, &transaction).is_err());
}

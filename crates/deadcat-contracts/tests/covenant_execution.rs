//! Daemon-free execution tests for generated Deadcat covenants.
//!
//! Each case constructs an Elements PSET and executes a real generated witness
//! through smplx's BitMachine transaction environment.

mod support;

use deadcat_contracts::binary_market::{
    BinaryMarketSlot, CompiledBinaryMarket, derived_binary_market,
};
use deadcat_contracts::maker_order::{CompiledMakerOrder, derived_maker_order};
use deadcat_contracts::market_crypto::derive_issuance_assets;
use deadcat_contracts::rt::{RtFactors, RtLeg, RtSide, factors};
use deadcat_types::{BinaryMarketParams, MakerOrderParams, OrderDirection};
use elements::confidential::{Asset, Nonce, Value};
use elements::hashes::{Hash as _, HashEngine as _, sha256};
use elements::pset::PartiallySignedTransaction;
use elements::secp256k1_zkp::{Generator, Keypair, PedersenCommitment, Secp256k1, Tweak};
use elements::{
    AssetId, ContractHash, LockTime, OutPoint, Script, Sequence, TxOut, TxOutWitness, Txid,
};
use simplex::program::{ProgramTrait as _, WitnessTrait as _};

use support::{asset, bare_op_return, explicit_txout, network, pset_input, pset_output, script};

fn maker_receive_script() -> Script {
    script(0x42)
}

fn script_hash(script: &Script) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    engine.input(script.as_bytes());
    sha256::Hash::from_engine(engine).to_byte_array()
}

fn maker_key() -> [u8; 32] {
    Keypair::from_seckey_slice(&Secp256k1::new(), &[0x31; 32])
        .expect("valid maker key")
        .x_only_public_key()
        .0
        .serialize()
}

fn maker_params(direction: OrderDirection) -> MakerOrderParams {
    MakerOrderParams {
        base_asset_id: asset(0x11),
        quote_asset_id: asset(0x22),
        price: 7,
        min_active_base: 3,
        direction,
        maker_receive_spk_hash: script_hash(&maker_receive_script()),
        maker_pubkey: maker_key(),
    }
}

#[derive(Clone)]
struct RemainderOutput {
    amount: u64,
    output_index: usize,
    asset: AssetId,
    script_pubkey: Script,
}

#[derive(Clone)]
struct MakerFillCase {
    direction: OrderDirection,
    input_index: usize,
    input_amount: u64,
    payment_amount: u64,
    payment_index: usize,
    remainder: Option<RemainderOutput>,
    remainder_witness_index: u32,
    attach_issuance: bool,
}

impl MakerFillCase {
    fn full(direction: OrderDirection, input_amount: u64, payment_amount: u64) -> Self {
        Self {
            direction,
            input_index: 0,
            input_amount,
            payment_amount,
            payment_index: 0,
            remainder: None,
            remainder_witness_index: 1,
            attach_issuance: false,
        }
    }

    fn partial(
        direction: OrderDirection,
        input_amount: u64,
        payment_amount: u64,
        remainder_amount: u64,
    ) -> Self {
        let params = maker_params(direction);
        Self {
            direction,
            input_index: 0,
            input_amount,
            payment_amount,
            payment_index: 0,
            remainder: Some(RemainderOutput {
                amount: remainder_amount,
                output_index: 1,
                asset: match direction {
                    OrderDirection::SellBase => params.base_asset_id,
                    OrderDirection::SellQuote => params.quote_asset_id,
                },
                // Empty means "use the order continuation script" in the builder.
                script_pubkey: Script::new(),
            }),
            remainder_witness_index: 1,
            attach_issuance: false,
        }
    }
}

fn execute_maker_fill(case: MakerFillCase) -> Result<(), Box<dyn std::error::Error>> {
    let params = maker_params(case.direction);
    let compiled = CompiledMakerOrder::new(params)?;
    let order_script = compiled.script_pubkey().clone();
    let input_asset = match case.direction {
        OrderDirection::SellBase => params.base_asset_id,
        OrderDirection::SellQuote => params.quote_asset_id,
    };
    let payment_asset = match case.direction {
        OrderDirection::SellBase => params.quote_asset_id,
        OrderDirection::SellQuote => params.base_asset_id,
    };

    let mut pset = PartiallySignedTransaction::new_v2();
    for index in 0..=case.input_index {
        let mut input = if index == case.input_index {
            pset_input(
                0xa0 + u8::try_from(index)?,
                u32::try_from(index)?,
                explicit_txout(input_asset, case.input_amount, order_script.clone()),
            )
        } else {
            pset_input(
                0x90 + u8::try_from(index)?,
                u32::try_from(index)?,
                explicit_txout(params.quote_asset_id, 1, script(0x90)),
            )
        };
        if index == case.input_index && case.attach_issuance {
            input.issuance_value_amount = Some(1);
            input.issuance_asset_entropy = Some([0x88; 32]);
        }
        pset.add_input(input);
    }

    let remainder_output_index = case
        .remainder
        .as_ref()
        .map_or(0, |remainder| remainder.output_index);
    let last_output = case
        .payment_index
        .max(remainder_output_index)
        .max(case.input_index);
    let mut outputs = vec![explicit_txout(params.quote_asset_id, 1, script(0x99)); last_output + 1];
    outputs[case.payment_index] =
        explicit_txout(payment_asset, case.payment_amount, maker_receive_script());
    if let Some(mut remainder) = case.remainder {
        if remainder.script_pubkey.is_empty() {
            remainder.script_pubkey = order_script;
        }
        outputs[remainder.output_index] =
            explicit_txout(remainder.asset, remainder.amount, remainder.script_pubkey);
    }
    for output in outputs {
        pset.add_output(pset_output(output));
    }

    let witness = derived_maker_order::MakerOrderWitness {
        remainder_index: case.remainder_witness_index,
    };
    let net = network(params.quote_asset_id);
    compiled
        .program()
        .as_ref()
        .execute(&pset, &witness.build_witness(), case.input_index, &net)?;
    Ok(())
}

#[test]
fn maker_sell_base_full_and_partial_execute() {
    execute_maker_fill(MakerFillCase::full(OrderDirection::SellBase, 10, 70))
        .expect("full SellBase fill");
    execute_maker_fill(MakerFillCase::partial(OrderDirection::SellBase, 10, 28, 6))
        .expect("partial SellBase fill");
}

#[test]
fn maker_sell_quote_full_and_partial_execute() {
    execute_maker_fill(MakerFillCase::full(OrderDirection::SellQuote, 70, 10))
        .expect("full SellQuote fill");
    execute_maker_fill(MakerFillCase::partial(OrderDirection::SellQuote, 70, 4, 42))
        .expect("partial SellQuote fill");
}

#[test]
fn maker_rejects_inexact_payments_and_dust_remainders() {
    assert!(
        execute_maker_fill(MakerFillCase::partial(OrderDirection::SellBase, 10, 29, 6,)).is_err()
    );
    assert!(
        execute_maker_fill(MakerFillCase::partial(OrderDirection::SellQuote, 70, 4, 41,)).is_err()
    );
    assert!(
        execute_maker_fill(MakerFillCase::partial(OrderDirection::SellBase, 10, 56, 2,)).is_err()
    );
    assert!(
        execute_maker_fill(MakerFillCase::partial(OrderDirection::SellQuote, 70, 8, 14,)).is_err()
    );
}

#[test]
fn maker_rejects_wrong_remainder_script_and_alias() {
    let mut wrong_script = MakerFillCase::partial(OrderDirection::SellBase, 10, 28, 6);
    wrong_script
        .remainder
        .as_mut()
        .expect("remainder")
        .script_pubkey = script(0x55);
    assert!(execute_maker_fill(wrong_script).is_err());

    let mut alias = MakerFillCase::partial(OrderDirection::SellBase, 10, 28, 6);
    alias.remainder_witness_index = 0;
    assert!(execute_maker_fill(alias).is_err());
}

#[test]
fn maker_rejects_attached_issuance() {
    let mut case = MakerFillCase::full(OrderDirection::SellBase, 10, 70);
    case.attach_issuance = true;
    assert!(execute_maker_fill(case).is_err());
}

#[test]
fn maker_payment_is_anchored_to_current_input_position() {
    let mut valid = MakerFillCase::full(OrderDirection::SellBase, 10, 70);
    valid.input_index = 1;
    valid.payment_index = 1;
    execute_maker_fill(valid).expect("payment at current input index");

    let mut misplaced = MakerFillCase::full(OrderDirection::SellBase, 10, 70);
    misplaced.input_index = 1;
    misplaced.payment_index = 0;
    assert!(execute_maker_fill(misplaced).is_err());
}

fn confidential_rt_txout(asset_id: AssetId, factors: RtFactors, script_pubkey: Script) -> TxOut {
    let secp = Secp256k1::new();
    let asset_blinder = Tweak::from_inner(factors.abf).expect("valid test ABF");
    let value_blinder = Tweak::from_inner(factors.vbf).expect("valid test VBF");
    let generator = Generator::new_blinded(&secp, asset_id.into_tag(), asset_blinder);
    let commitment = PedersenCommitment::new(&secp, 1, value_blinder, generator);
    TxOut {
        asset: Asset::Confidential(generator),
        value: Value::Confidential(commitment),
        nonce: Nonce::Null,
        script_pubkey,
        witness: TxOutWitness::default(),
    }
}

fn binary_params() -> BinaryMarketParams {
    BinaryMarketParams {
        oracle_public_key: maker_key(),
        collateral_asset_id: asset(0x61),
        yes_token_asset_id: asset(0x62),
        no_token_asset_id: asset(0x63),
        yes_reissuance_token_id: asset(0x64),
        no_reissuance_token_id: asset(0x65),
        base_payout: 100,
        expiry_height: 500,
    }
}

/// Execute the unresolved -> expired transition for all three covenant inputs.
/// `previous_vouts` models the sibling outputs of their shared prior tx.
fn execute_active_expiry(
    previous_vouts: [u32; 3],
    yes_input: RtFactors,
    no_input: RtFactors,
    yes_burn: RtFactors,
    no_burn: RtFactors,
) -> Result<(), Box<dyn std::error::Error>> {
    let params = binary_params();
    let compiled = CompiledBinaryMarket::new(params)?;
    let collateral = 600;

    let mut pset = PartiallySignedTransaction::new_v2();
    pset.global.tx_data.fallback_locktime = Some(LockTime::from_height(params.expiry_height)?);
    let input_utxos = [
        confidential_rt_txout(
            params.yes_reissuance_token_id,
            yes_input,
            compiled
                .slot(BinaryMarketSlot::UnresolvedYesRt)
                .script_pubkey()
                .clone(),
        ),
        confidential_rt_txout(
            params.no_reissuance_token_id,
            no_input,
            compiled
                .slot(BinaryMarketSlot::UnresolvedNoRt)
                .script_pubkey()
                .clone(),
        ),
        explicit_txout(
            params.collateral_asset_id,
            collateral,
            compiled
                .slot(BinaryMarketSlot::UnresolvedCollateral)
                .script_pubkey()
                .clone(),
        ),
    ];
    for (vout, utxo) in previous_vouts.into_iter().zip(input_utxos) {
        let mut input = pset_input(0xb0, vout, utxo);
        input.sequence = Some(Sequence(0xffff_fffe));
        pset.add_input(input);
    }

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
        collateral,
        compiled
            .slot(BinaryMarketSlot::ExpiredCollateral)
            .script_pubkey()
            .clone(),
    )));

    let slots = [
        BinaryMarketSlot::UnresolvedYesRt,
        BinaryMarketSlot::UnresolvedNoRt,
        BinaryMarketSlot::UnresolvedCollateral,
    ];
    let net = network(params.collateral_asset_id);
    for (input_index, slot) in slots.into_iter().enumerate() {
        let witness = derived_binary_market::BinaryMarketWitness {
            path: 6,
            slot: slot as u8,
            input_base: 0,
            output_base: 0,
            oracle_outcome_yes: false,
            oracle_signature: [0; 64],
            tokens_burned: 0,
            redeem_yes: false,
        };
        compiled.program(slot).as_ref().execute(
            &pset,
            &witness.build_witness(),
            input_index,
            &net,
        )?;
    }
    Ok(())
}

fn valid_active_expiry(side: RtSide) -> Result<(), Box<dyn std::error::Error>> {
    execute_active_expiry(
        [10, 11, 12],
        factors(RtLeg::Yes, side),
        factors(RtLeg::No, side),
        factors(RtLeg::Yes, side.flip()),
        factors(RtLeg::No, side.flip()),
    )
}

fn execute_initial_issuance(
    input_side: RtSide,
    yes_nonce_side: RtSide,
    no_nonce_side: RtSide,
) -> Result<(), Box<dyn std::error::Error>> {
    let yes_outpoint = OutPoint::new(Txid::from_byte_array([0xc0; 32]), 10);
    let no_outpoint = OutPoint::new(Txid::from_byte_array([0xc0; 32]), 11);
    let issued = derive_issuance_assets(yes_outpoint, no_outpoint);
    let params = BinaryMarketParams {
        yes_token_asset_id: issued.yes_token,
        no_token_asset_id: issued.no_token,
        yes_reissuance_token_id: issued.yes_reissuance_token,
        no_reissuance_token_id: issued.no_reissuance_token,
        ..binary_params()
    };
    let compiled = CompiledBinaryMarket::new(params)?;
    let mut pset = PartiallySignedTransaction::new_v2();
    let input_specs = [
        (
            yes_outpoint,
            RtLeg::Yes,
            params.yes_reissuance_token_id,
            BinaryMarketSlot::DormantYesRt,
            yes_nonce_side,
        ),
        (
            no_outpoint,
            RtLeg::No,
            params.no_reissuance_token_id,
            BinaryMarketSlot::DormantNoRt,
            no_nonce_side,
        ),
    ];
    for (outpoint, leg, rt_asset, slot, nonce_side) in input_specs {
        let mut input = pset_input(
            0xc0,
            outpoint.vout,
            confidential_rt_txout(
                rt_asset,
                factors(leg, input_side),
                compiled.slot(slot).script_pubkey().clone(),
            ),
        );
        input.previous_txid = outpoint.txid;
        input.issuance_value_amount = Some(2);
        input.issuance_value_comm = None;
        input.issuance_inflation_keys = None;
        input.issuance_inflation_keys_comm = None;
        input.issuance_blinding_nonce = Some(Tweak::from_inner(nonce_side.abf())?);
        input.issuance_asset_entropy = Some(
            AssetId::generate_asset_entropy(outpoint, ContractHash::from_byte_array([0; 32]))
                .to_byte_array(),
        );
        input.blinded_issuance = Some(0);
        pset.add_input(input);
    }

    pset.add_output(pset_output(confidential_rt_txout(
        params.yes_reissuance_token_id,
        factors(RtLeg::Yes, input_side.flip()),
        compiled
            .slot(BinaryMarketSlot::UnresolvedYesRt)
            .script_pubkey()
            .clone(),
    )));
    pset.add_output(pset_output(confidential_rt_txout(
        params.no_reissuance_token_id,
        factors(RtLeg::No, input_side.flip()),
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

    let network = network(params.collateral_asset_id);
    for (input_index, slot) in [
        BinaryMarketSlot::DormantYesRt,
        BinaryMarketSlot::DormantNoRt,
    ]
    .into_iter()
    .enumerate()
    {
        let witness = derived_binary_market::BinaryMarketWitness {
            path: 0,
            slot: slot as u8,
            input_base: 0,
            output_base: 0,
            oracle_outcome_yes: false,
            oracle_signature: [0; 64],
            tokens_burned: 0,
            redeem_yes: false,
        };
        compiled.program(slot).as_ref().execute(
            &pset,
            &witness.build_witness(),
            input_index,
            &network,
        )?;
    }
    Ok(())
}

#[test]
fn binary_active_expiry_executes_with_consecutive_siblings() {
    valid_active_expiry(RtSide::A).expect("valid A -> B unresolved sibling transition");
    valid_active_expiry(RtSide::B).expect("valid B -> A unresolved sibling transition");
}

#[test]
fn binary_issuance_binds_reissuance_nonce_to_the_input_side() {
    execute_initial_issuance(RtSide::A, RtSide::A, RtSide::A).expect("side-A issuance nonce");
    execute_initial_issuance(RtSide::B, RtSide::B, RtSide::B).expect("side-B issuance nonce");

    assert!(execute_initial_issuance(RtSide::A, RtSide::B, RtSide::A).is_err());
    assert!(execute_initial_issuance(RtSide::A, RtSide::A, RtSide::B).is_err());
}

#[test]
fn binary_rejects_same_txid_collateral_decoy_at_nonconsecutive_vout() {
    assert!(
        execute_active_expiry(
            [10, 11, 13],
            factors(RtLeg::Yes, RtSide::A),
            factors(RtLeg::No, RtSide::A),
            factors(RtLeg::Yes, RtSide::B),
            factors(RtLeg::No, RtSide::B),
        )
        .is_err()
    );
}

#[test]
fn binary_rejects_same_side_wrong_role_and_mixed_side_rt_shapes() {
    let valid_yes_in = factors(RtLeg::Yes, RtSide::A);
    let valid_no_in = factors(RtLeg::No, RtSide::A);
    let valid_yes_out = factors(RtLeg::Yes, RtSide::B);
    let valid_no_out = factors(RtLeg::No, RtSide::B);

    assert!(
        execute_active_expiry(
            [10, 11, 12],
            valid_yes_in,
            valid_no_in,
            // The generator and value remain on the input side.
            factors(RtLeg::Yes, RtSide::A),
            valid_no_out,
        )
        .is_err()
    );
    assert!(
        execute_active_expiry(
            [10, 11, 12],
            valid_yes_in,
            valid_no_in,
            // ABFs are global, so this specifically substitutes NO's CBF/value.
            factors(RtLeg::No, RtSide::B),
            valid_no_out,
        )
        .is_err()
    );
    assert!(
        execute_active_expiry(
            [10, 11, 12],
            valid_yes_in,
            // Canonical markets can never have A/B or B/A live legs.
            factors(RtLeg::No, RtSide::B),
            valid_yes_out,
            factors(RtLeg::No, RtSide::A),
        )
        .is_err()
    );
    assert!(
        execute_active_expiry(
            [10, 11, 12],
            // The YES asset generator with NO's CBF is not a recognized YES side.
            factors(RtLeg::No, RtSide::A),
            valid_no_in,
            valid_yes_out,
            valid_no_out,
        )
        .is_err()
    );
}

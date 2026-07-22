use deadcat_client::maker_builder::MakerFillPlan;
use deadcat_client::market_builder::{
    BinaryMarketLiveInputs, BinaryMarketTransitionPlan, MarketIssuanceEntropies, MarketRtInput,
    OracleAttestation,
};
use deadcat_contracts::SimplicityNetwork;
use deadcat_contracts::binary_market::{
    BinaryMarketAction, BinaryMarketEconomics, BinaryMarketSlot, BinaryOutcome,
    CompiledBinaryMarket, derived_binary_market,
};
use deadcat_contracts::interpret::strip_taproot_annex;
use deadcat_contracts::interpret::{
    BinaryMarketLiveOutputs, TrackedContractOutput, interpret_binary_market_spend,
};
use deadcat_contracts::maker_order::CompiledMakerOrder;
use deadcat_contracts::market_crypto::{
    BinaryOutcome as OracleOutcome, derive_issuance_assets, oracle_message,
};
use deadcat_contracts::rt::{RtLeg, RtSide, commitments, factors};
use deadcat_types::{BinaryMarketParams, BinaryMarketState, MakerOrderParams, OrderDirection};
use elements::confidential::{Asset, Nonce, Value};
use elements::hashes::Hash as _;
use elements::pset::{Input as PsetInput, Output as PsetOutput, PartiallySignedTransaction};
use elements::secp256k1_zkp::{Keypair, Message, Secp256k1, Tweak};
use elements::{AssetId, OutPoint, Script, TxOut, TxOutWitness, Txid};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use simplex::program::{ProgramTrait as _, WitnessTrait as _};
use simplex::simplicityhl::simplicity::jet::Elements;
use simplex::simplicityhl::simplicity::{BitIter, RedeemNode};

#[derive(Debug)]
struct Underbudget {
    label: String,
    milliweight: String,
    stack_bytes: usize,
    required_annex_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
struct CovenantMetrics {
    cost_milliweight: u64,
    program_bytes: usize,
    witness_bytes: usize,
    stack_bytes: usize,
    padding_bytes: usize,
}

impl CovenantMetrics {
    fn add_assign(&mut self, other: Self) {
        self.cost_milliweight += other.cost_milliweight;
        self.program_bytes += other.program_bytes;
        self.witness_bytes += other.witness_bytes;
        self.stack_bytes += other.stack_bytes;
        self.padding_bytes += other.padding_bytes;
    }
}

#[derive(Debug, Serialize)]
struct MarketMetrics<'a> {
    stage: &'a str,
    rt_input_side: &'a str,
    covenant: CovenantMetrics,
    tx_bytes: usize,
    tx_weight: usize,
    tx_vsize: usize,
    tx_discount_weight: usize,
    tx_discount_vsize: usize,
}

impl std::fmt::Display for Underbudget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}: cost={}mw stack={}B required_annex={}B",
            self.label, self.milliweight, self.stack_bytes, self.required_annex_bytes
        )
    }
}

fn failure_report(failures: &[Underbudget]) -> String {
    failures
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

fn record_budget(
    label: impl Into<String>,
    stack: &[Vec<u8>],
    failures: &mut Vec<Underbudget>,
) -> CovenantMetrics {
    let stack = stack.to_vec();
    let (core_stack, annex) = strip_taproot_annex(&stack);
    assert_eq!(
        core_stack.len(),
        4,
        "finalized Simplicity stack must have four core elements"
    );
    let redeem = RedeemNode::<Elements>::decode(
        BitIter::from(core_stack[1].iter().copied()),
        BitIter::from(core_stack[0].iter().copied()),
    )
    .expect("decode finalized Simplicity program");
    let cost = redeem.bounds().cost;
    if !cost.is_budget_valid(&stack) {
        failures.push(Underbudget {
            label: label.into(),
            milliweight: cost.to_string(),
            stack_bytes: elements::encode::serialize(&stack).len(),
            required_annex_bytes: cost.get_padding(&stack).map_or(0, |annex| annex.len()),
        });
    }
    CovenantMetrics {
        cost_milliweight: cost
            .to_string()
            .parse()
            .expect("Simplicity cost is an integer milliweight"),
        program_bytes: core_stack[1].len(),
        witness_bytes: core_stack[0].len(),
        stack_bytes: elements::encode::serialize(&stack).len(),
        padding_bytes: annex.map_or(0, <[u8]>::len),
    }
}

fn asset(byte: u8) -> AssetId {
    AssetId::from_slice(&[byte; 32]).expect("asset id")
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

fn confidential_rt_txout(
    leg: RtLeg,
    side: RtSide,
    asset_id: AssetId,
    script_pubkey: Script,
) -> TxOut {
    let (asset, value) = commitments(asset_id, factors(leg, side)).expect("RT commitments");
    TxOut {
        asset,
        value,
        nonce: Nonce::Null,
        script_pubkey,
        witness: TxOutWitness::default(),
    }
}

fn oracle_keypair() -> Keypair {
    Keypair::from_seckey_slice(&Secp256k1::new(), &[0x31; 32]).expect("oracle key")
}

fn defining_outpoints() -> (OutPoint, OutPoint) {
    (
        OutPoint::new(Txid::from_byte_array([0x11; 32]), 3),
        OutPoint::new(Txid::from_byte_array([0x22; 32]), 4),
    )
}

fn market_params() -> BinaryMarketParams {
    let (yes, no) = defining_outpoints();
    let ids = derive_issuance_assets(yes, no);
    BinaryMarketParams {
        oracle_public_key: oracle_keypair().x_only_public_key().0.serialize(),
        collateral_asset_id: asset(0x51),
        yes_token_asset_id: ids.yes_token,
        no_token_asset_id: ids.no_token,
        yes_reissuance_token_id: ids.yes_reissuance_token,
        no_reissuance_token_id: ids.no_reissuance_token,
        base_payout: 100,
        expiry_height: 500,
    }
}

fn sign_attestation(params: BinaryMarketParams, outcome: BinaryOutcome) -> OracleAttestation {
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

fn live_inputs(
    params: BinaryMarketParams,
    state: BinaryMarketState,
    side: RtSide,
) -> BinaryMarketLiveInputs {
    let compiled = CompiledBinaryMarket::new(params).expect("compile market");
    match state {
        BinaryMarketState::Trading {
            outstanding_pairs: 0,
        } => BinaryMarketLiveInputs {
            yes_rt: Some(MarketRtInput {
                outpoint: OutPoint::new(Txid::from_byte_array([0x70; 32]), 2),
                txout: confidential_rt_txout(
                    RtLeg::Yes,
                    side,
                    params.yes_reissuance_token_id,
                    compiled
                        .slot(BinaryMarketSlot::DormantYesRt)
                        .script_pubkey()
                        .clone(),
                ),
            }),
            no_rt: Some(MarketRtInput {
                outpoint: OutPoint::new(Txid::from_byte_array([0x70; 32]), 9),
                txout: confidential_rt_txout(
                    RtLeg::No,
                    side,
                    params.no_reissuance_token_id,
                    compiled
                        .slot(BinaryMarketSlot::DormantNoRt)
                        .script_pubkey()
                        .clone(),
                ),
            }),
            collateral: None,
        },
        BinaryMarketState::Trading { .. } => BinaryMarketLiveInputs {
            yes_rt: Some(MarketRtInput {
                outpoint: OutPoint::new(Txid::from_byte_array([0x71; 32]), 4),
                txout: confidential_rt_txout(
                    RtLeg::Yes,
                    side,
                    params.yes_reissuance_token_id,
                    compiled
                        .slot(BinaryMarketSlot::UnresolvedYesRt)
                        .script_pubkey()
                        .clone(),
                ),
            }),
            no_rt: Some(MarketRtInput {
                outpoint: OutPoint::new(Txid::from_byte_array([0x71; 32]), 5),
                txout: confidential_rt_txout(
                    RtLeg::No,
                    side,
                    params.no_reissuance_token_id,
                    compiled
                        .slot(BinaryMarketSlot::UnresolvedNoRt)
                        .script_pubkey()
                        .clone(),
                ),
            }),
            collateral: Some(OutPoint::new(Txid::from_byte_array([0x71; 32]), 6)),
        },
        BinaryMarketState::ResolvedYes { .. }
        | BinaryMarketState::ResolvedNo { .. }
        | BinaryMarketState::Expired { .. } => BinaryMarketLiveInputs {
            collateral: Some(OutPoint::new(Txid::from_byte_array([0x72; 32]), 8)),
            ..BinaryMarketLiveInputs::default()
        },
    }
}

fn market_input_slots(state: BinaryMarketState) -> Vec<BinaryMarketSlot> {
    match state {
        BinaryMarketState::Trading {
            outstanding_pairs: 0,
        } => vec![
            BinaryMarketSlot::DormantYesRt,
            BinaryMarketSlot::DormantNoRt,
        ],
        BinaryMarketState::Trading { .. } => vec![
            BinaryMarketSlot::UnresolvedYesRt,
            BinaryMarketSlot::UnresolvedNoRt,
            BinaryMarketSlot::UnresolvedCollateral,
        ],
        BinaryMarketState::ResolvedYes { .. } => {
            vec![BinaryMarketSlot::ResolvedYesCollateral]
        }
        BinaryMarketState::ResolvedNo { .. } => {
            vec![BinaryMarketSlot::ResolvedNoCollateral]
        }
        BinaryMarketState::Expired { .. } => vec![BinaryMarketSlot::ExpiredCollateral],
    }
}

fn collateral_amount(params: BinaryMarketParams, state: BinaryMarketState) -> u64 {
    match state {
        BinaryMarketState::Trading { outstanding_pairs } => {
            BinaryMarketEconomics::new(params.base_payout)
                .expect("economics")
                .collateral_for_pairs(outstanding_pairs)
                .expect("collateral")
        }
        BinaryMarketState::ResolvedYes {
            collateral_unredeemed,
        }
        | BinaryMarketState::ResolvedNo {
            collateral_unredeemed,
        }
        | BinaryMarketState::Expired {
            collateral_unredeemed,
        } => collateral_unredeemed,
    }
}

fn market_pset(
    params: BinaryMarketParams,
    state: BinaryMarketState,
    live: &BinaryMarketLiveInputs,
    plan: &BinaryMarketTransitionPlan,
    input_base: usize,
    output_base: usize,
) -> PartiallySignedTransaction {
    let compiled = CompiledBinaryMarket::new(params).expect("compile market");
    let mut pset = PartiallySignedTransaction::new_v2();
    for index in 0..input_base {
        pset.add_input(pset_input(
            OutPoint::new(Txid::from_byte_array([0x80; 32]), index as u32),
            explicit_txout(params.collateral_asset_id, 1, Script::from(vec![0x51])),
        ));
    }
    for slot in market_input_slots(state) {
        let (outpoint, txout) = match slot {
            BinaryMarketSlot::DormantYesRt | BinaryMarketSlot::UnresolvedYesRt => {
                let rt = live.yes_rt.as_ref().expect("YES RT");
                (rt.outpoint, rt.txout.clone())
            }
            BinaryMarketSlot::DormantNoRt | BinaryMarketSlot::UnresolvedNoRt => {
                let rt = live.no_rt.as_ref().expect("NO RT");
                (rt.outpoint, rt.txout.clone())
            }
            _ => (
                live.collateral.expect("collateral outpoint"),
                explicit_txout(
                    params.collateral_asset_id,
                    collateral_amount(params, state),
                    compiled.slot(slot).script_pubkey().clone(),
                ),
            ),
        };
        pset.add_input(pset_input(outpoint, txout));
    }
    while pset.outputs().len() < output_base {
        pset.add_output(PsetOutput::from_txout(explicit_txout(
            params.collateral_asset_id,
            1,
            Script::from(vec![0x51]),
        )));
    }
    for (_, output) in plan.mandatory_outputs(output_base).expect("market outputs") {
        pset.add_output(PsetOutput::from_txout(output));
    }
    pset
}

fn interpreter_live_outputs(
    params: BinaryMarketParams,
    state: BinaryMarketState,
    live: &BinaryMarketLiveInputs,
) -> BinaryMarketLiveOutputs {
    let compiled = CompiledBinaryMarket::new(params).expect("compile market");
    let collateral = live.collateral.map(|outpoint| {
        let slot = market_input_slots(state)
            .into_iter()
            .find(|slot| {
                !matches!(
                    slot,
                    BinaryMarketSlot::DormantYesRt
                        | BinaryMarketSlot::DormantNoRt
                        | BinaryMarketSlot::UnresolvedYesRt
                        | BinaryMarketSlot::UnresolvedNoRt
                )
            })
            .expect("collateral slot");
        TrackedContractOutput {
            outpoint,
            txout: explicit_txout(
                params.collateral_asset_id,
                collateral_amount(params, state),
                compiled.slot(slot).script_pubkey().clone(),
            ),
        }
    });
    BinaryMarketLiveOutputs {
        yes_rt: live.yes_rt.as_ref().map(|rt| TrackedContractOutput {
            outpoint: rt.outpoint,
            txout: rt.txout.clone(),
        }),
        no_rt: live.no_rt.as_ref().map(|rt| TrackedContractOutput {
            outpoint: rt.outpoint,
            txout: rt.txout.clone(),
        }),
        collateral,
    }
}

fn direct_market_witness(
    plan: &BinaryMarketTransitionPlan,
    action: BinaryMarketAction,
    attestation: Option<OracleAttestation>,
    slot: BinaryMarketSlot,
    output_base: usize,
) -> derived_binary_market::BinaryMarketWitness {
    let (tokens_burned, redeem_yes) = match action {
        BinaryMarketAction::Redeem { outcome, tokens } => (tokens, outcome == BinaryOutcome::Yes),
        _ => (0, false),
    };
    let oracle_outcome_yes = redeem_yes
        || matches!(
            action,
            BinaryMarketAction::Resolve {
                outcome: BinaryOutcome::Yes
            }
        );
    derived_binary_market::BinaryMarketWitness {
        path: plan.path() as u8,
        slot: slot as u8,
        output_base: u32::try_from(output_base).expect("test output index fits u32"),
        oracle_outcome_yes,
        oracle_signature: attestation.map_or([0; 64], |value| value.signature),
        tokens_burned,
        redeem_yes,
    }
}

fn attach_dummy_issuance(input: &mut PsetInput) {
    input.issuance_value_amount = Some(1);
    input.issuance_value_comm = None;
    input.issuance_inflation_keys = Some(0);
    input.issuance_inflation_keys_comm = None;
    input.issuance_blinding_nonce = Some(Tweak::from_inner([0x21; 32]).expect("valid tweak"));
    input.issuance_asset_entropy = Some([0x31; 32]);
    input.blinded_issuance = Some(0);
}

fn replace_confidential_output_commitments(
    pset: &mut PartiallySignedTransaction,
    output_index: usize,
    asset: Asset,
    value: Value,
) {
    let Asset::Confidential(asset) = asset else {
        panic!("test RT asset must be confidential");
    };
    let Value::Confidential(value) = value else {
        panic!("test RT value must be confidential");
    };
    let output = &mut pset.outputs_mut()[output_index];
    output.asset = None;
    output.asset_comm = Some(asset);
    output.amount = None;
    output.amount_comm = Some(value);
}

#[test]
fn every_finalized_market_stack_has_sufficient_simplicity_budget() {
    let params = market_params();
    let collateral_per_pair = params.base_payout * 2;
    let cases = [
        (
            "initial-issuance",
            BinaryMarketState::Trading {
                outstanding_pairs: 0,
            },
            BinaryMarketAction::Issue { pairs: 2 },
            None,
        ),
        (
            "subsequent-issuance",
            BinaryMarketState::Trading {
                outstanding_pairs: 3,
            },
            BinaryMarketAction::Issue { pairs: 2 },
            None,
        ),
        (
            "partial-cancellation",
            BinaryMarketState::Trading {
                outstanding_pairs: 5,
            },
            BinaryMarketAction::Cancel { pairs: 2 },
            None,
        ),
        (
            "full-cancellation",
            BinaryMarketState::Trading {
                outstanding_pairs: 5,
            },
            BinaryMarketAction::Cancel { pairs: 5 },
            None,
        ),
        (
            "active-resolution-yes",
            BinaryMarketState::Trading {
                outstanding_pairs: 3,
            },
            BinaryMarketAction::Resolve {
                outcome: BinaryOutcome::Yes,
            },
            Some(sign_attestation(params, BinaryOutcome::Yes)),
        ),
        (
            "active-resolution-no",
            BinaryMarketState::Trading {
                outstanding_pairs: 3,
            },
            BinaryMarketAction::Resolve {
                outcome: BinaryOutcome::No,
            },
            Some(sign_attestation(params, BinaryOutcome::No)),
        ),
        (
            "dormant-resolution-yes",
            BinaryMarketState::Trading {
                outstanding_pairs: 0,
            },
            BinaryMarketAction::Resolve {
                outcome: BinaryOutcome::Yes,
            },
            Some(sign_attestation(params, BinaryOutcome::Yes)),
        ),
        (
            "dormant-resolution-no",
            BinaryMarketState::Trading {
                outstanding_pairs: 0,
            },
            BinaryMarketAction::Resolve {
                outcome: BinaryOutcome::No,
            },
            Some(sign_attestation(params, BinaryOutcome::No)),
        ),
        (
            "active-expiry",
            BinaryMarketState::Trading {
                outstanding_pairs: 3,
            },
            BinaryMarketAction::Expire,
            None,
        ),
        (
            "dormant-expiry",
            BinaryMarketState::Trading {
                outstanding_pairs: 0,
            },
            BinaryMarketAction::Expire,
            None,
        ),
        (
            "resolved-yes-partial-redemption",
            BinaryMarketState::ResolvedYes {
                collateral_unredeemed: 3 * collateral_per_pair,
            },
            BinaryMarketAction::Redeem {
                outcome: BinaryOutcome::Yes,
                tokens: 1,
            },
            None,
        ),
        (
            "resolved-yes-full-redemption",
            BinaryMarketState::ResolvedYes {
                collateral_unredeemed: collateral_per_pair,
            },
            BinaryMarketAction::Redeem {
                outcome: BinaryOutcome::Yes,
                tokens: 1,
            },
            None,
        ),
        (
            "resolved-no-partial-redemption",
            BinaryMarketState::ResolvedNo {
                collateral_unredeemed: 3 * collateral_per_pair,
            },
            BinaryMarketAction::Redeem {
                outcome: BinaryOutcome::No,
                tokens: 1,
            },
            None,
        ),
        (
            "resolved-no-full-redemption",
            BinaryMarketState::ResolvedNo {
                collateral_unredeemed: collateral_per_pair,
            },
            BinaryMarketAction::Redeem {
                outcome: BinaryOutcome::No,
                tokens: 1,
            },
            None,
        ),
        (
            "expiry-yes-partial-redemption",
            BinaryMarketState::Expired {
                collateral_unredeemed: 3 * params.base_payout,
            },
            BinaryMarketAction::Redeem {
                outcome: BinaryOutcome::Yes,
                tokens: 1,
            },
            None,
        ),
        (
            "expiry-yes-full-redemption",
            BinaryMarketState::Expired {
                collateral_unredeemed: params.base_payout,
            },
            BinaryMarketAction::Redeem {
                outcome: BinaryOutcome::Yes,
                tokens: 1,
            },
            None,
        ),
        (
            "expiry-no-partial-redemption",
            BinaryMarketState::Expired {
                collateral_unredeemed: 3 * params.base_payout,
            },
            BinaryMarketAction::Redeem {
                outcome: BinaryOutcome::No,
                tokens: 1,
            },
            None,
        ),
        (
            "expiry-no-full-redemption",
            BinaryMarketState::Expired {
                collateral_unredeemed: params.base_payout,
            },
            BinaryMarketAction::Redeem {
                outcome: BinaryOutcome::No,
                tokens: 1,
            },
            None,
        ),
    ];
    let entropies = MarketIssuanceEntropies::from_defining_outpoints(
        params,
        defining_outpoints().0,
        defining_outpoints().1,
    )
    .expect("issuance entropies");
    let network = SimplicityNetwork::ElementsRegtest {
        policy_asset: params.collateral_asset_id,
    };
    let mut failures = Vec::new();
    let mut measurements = Vec::new();
    let compiled = CompiledBinaryMarket::new(params).expect("compile canonical market");
    for side in [RtSide::A, RtSide::B] {
        for &(label, before, action, attestation) in &cases {
            let live = live_inputs(params, before, side);
            let plan =
                BinaryMarketTransitionPlan::new(params, before, action, live.clone(), attestation)
                    .unwrap_or_else(|error| panic!("{label}/{side:?}: plan: {error}"));
            let input_base = 1;
            let output_base = 1;
            let mut pset = market_pset(params, before, &live, &plan, input_base, output_base);
            if matches!(action, BinaryMarketAction::Issue { .. }) {
                plan.configure_reissuance_inputs(&mut pset, input_base, entropies)
                    .unwrap_or_else(|error| panic!("{label}/{side:?}: reissuance: {error}"));
            }
            if matches!(action, BinaryMarketAction::Expire) {
                plan.prepare_expiry(&mut pset, input_base)
                    .unwrap_or_else(|error| panic!("{label}/{side:?}: expiry: {error}"));
            }
            plan.finalize(&mut pset, input_base, output_base, &network)
                .unwrap_or_else(|error| panic!("{label}/{side:?}: finalize: {error}"));
            let slots = market_input_slots(before);
            for (offset, slot) in slots.iter().copied().enumerate() {
                let witness = direct_market_witness(&plan, action, attestation, slot, output_base);
                compiled
                    .program(slot)
                    .as_ref()
                    .execute(
                        &pset,
                        &witness.build_witness(),
                        input_base + offset,
                        &network,
                    )
                    .unwrap_or_else(|error| {
                        panic!("{label}/{side:?}/{slot:?}: direct execution: {error}")
                    });
            }

            let mut unrelated_issuance = pset.clone();
            attach_dummy_issuance(&mut unrelated_issuance.inputs_mut()[0]);
            for (offset, slot) in slots.iter().copied().enumerate() {
                let witness = direct_market_witness(&plan, action, attestation, slot, output_base);
                compiled
                    .program(slot)
                    .as_ref()
                    .execute(
                        &unrelated_issuance,
                        &witness.build_witness(),
                        input_base + offset,
                        &network,
                    )
                    .unwrap_or_else(|error| {
                        panic!("{label}/{side:?}/{slot:?}: unrelated issuance: {error}")
                    });
            }

            if !matches!(action, BinaryMarketAction::Issue { .. }) {
                let coordinator = slots[0];
                let witness =
                    direct_market_witness(&plan, action, attestation, coordinator, output_base);
                for issuance_offset in 0..slots.len() {
                    let mut malicious = pset.clone();
                    attach_dummy_issuance(
                        &mut malicious.inputs_mut()[input_base + issuance_offset],
                    );
                    assert!(
                        compiled
                            .program(coordinator)
                            .as_ref()
                            .execute(&malicious, &witness.build_witness(), input_base, &network,)
                            .is_err(),
                        "{label}/{side:?}: coordinator accepted issuance on market input offset {issuance_offset}"
                    );
                }
            }
            let mut covenant = CovenantMetrics::default();
            for (offset, _) in market_input_slots(before).iter().enumerate() {
                let input_index = input_base + offset;
                let stack = pset.inputs()[input_index]
                    .final_script_witness
                    .as_ref()
                    .expect("final market witness");
                covenant.add_assign(record_budget(
                    format!("{label}/{side:?}/input-{input_index}"),
                    stack,
                    &mut failures,
                ));
            }

            let transaction = pset.extract_tx().expect("extract finalized market tx");
            measurements.push(MarketMetrics {
                stage: label,
                rt_input_side: match side {
                    RtSide::A => "a",
                    RtSide::B => "b",
                },
                covenant,
                tx_bytes: transaction.size(),
                tx_weight: transaction.weight(),
                tx_vsize: transaction.vsize(),
                tx_discount_weight: transaction.discount_weight(),
                tx_discount_vsize: transaction.discount_vsize(),
            });
            let interpreted = interpret_binary_market_spend(
                params,
                before,
                &interpreter_live_outputs(params, before, &live),
                &transaction,
            )
            .unwrap_or_else(|error| panic!("{label}/{side:?}: interpret: {error}"));
            assert_eq!(interpreted.action, action, "{label}/{side:?}: action");
            assert_eq!(
                interpreted.after,
                plan.after(),
                "{label}/{side:?}: resulting state"
            );

            if matches!(before, BinaryMarketState::Trading { .. }) {
                let coordinator = slots[0];
                let witness =
                    direct_market_witness(&plan, action, attestation, coordinator, output_base);
                let mut same_side_pset = pset.clone();
                let (asset, value) =
                    commitments(params.yes_reissuance_token_id, factors(RtLeg::Yes, side))
                        .expect("same-side commitments");
                replace_confidential_output_commitments(
                    &mut same_side_pset,
                    output_base,
                    asset,
                    value,
                );
                assert!(
                    compiled
                        .program(coordinator)
                        .as_ref()
                        .execute(
                            &same_side_pset,
                            &witness.build_witness(),
                            input_base,
                            &network,
                        )
                        .is_err(),
                    "{label}/{side:?}: covenant accepted same-side RT output"
                );

                let mut same_side_output = transaction.clone();
                same_side_output.output[output_base].asset = asset;
                same_side_output.output[output_base].value = value;
                assert!(
                    interpret_binary_market_spend(
                        params,
                        before,
                        &interpreter_live_outputs(params, before, &live),
                        &same_side_output,
                    )
                    .is_err(),
                    "{label}/{side:?}: same-side RT output"
                );
            }

            if matches!(action, BinaryMarketAction::Issue { .. }) {
                let coordinator = slots[0];
                let witness =
                    direct_market_witness(&plan, action, attestation, coordinator, output_base);
                for offset in 0..2 {
                    let mut wrong_nonce_pset = pset.clone();
                    wrong_nonce_pset.inputs_mut()[input_base + offset].issuance_blinding_nonce =
                        Some(Tweak::from_inner(side.flip().abf()).expect("opposite public ABF"));
                    assert!(
                        compiled
                            .program(coordinator)
                            .as_ref()
                            .execute(
                                &wrong_nonce_pset,
                                &witness.build_witness(),
                                input_base,
                                &network,
                            )
                            .is_err(),
                        "{label}/{side:?}: covenant accepted wrong nonce at sibling {offset}"
                    );

                    let mut wrong_nonce = transaction.clone();
                    wrong_nonce.input[input_base + offset]
                        .asset_issuance
                        .asset_blinding_nonce =
                        Tweak::from_inner(side.flip().abf()).expect("opposite public ABF");
                    assert!(
                        interpret_binary_market_spend(
                            params,
                            before,
                            &interpreter_live_outputs(params, before, &live),
                            &wrong_nonce,
                        )
                        .is_err(),
                        "{label}/{side:?}: wrong reissuance nonce at sibling {offset}"
                    );
                }
            }
        }
    }
    let report = failure_report(&failures);
    assert!(
        failures.is_empty(),
        "underbudget finalized market stacks:\n{report}"
    );
    eprintln!(
        "DEADCAT_AB_MARKET_METRICS={}",
        serde_json::to_string(&measurements).expect("serialize market measurements")
    );
}

#[test]
fn market_followers_ignore_transition_witnesses_but_require_the_exact_coordinator_group() {
    let params = market_params();
    let network = SimplicityNetwork::ElementsRegtest {
        policy_asset: params.collateral_asset_id,
    };
    let compiled = CompiledBinaryMarket::new(params).expect("compile canonical market");
    let input_base = 1;
    let output_base = 1;

    let active_before = BinaryMarketState::Trading {
        outstanding_pairs: 5,
    };
    let active_action = BinaryMarketAction::Cancel { pairs: 2 };
    let active_live = live_inputs(params, active_before, RtSide::A);
    let active_plan = BinaryMarketTransitionPlan::new(
        params,
        active_before,
        active_action,
        active_live.clone(),
        None,
    )
    .expect("partial cancellation plan");
    let active_pset = market_pset(
        params,
        active_before,
        &active_live,
        &active_plan,
        input_base,
        output_base,
    );
    let active_slots = [
        BinaryMarketSlot::UnresolvedYesRt,
        BinaryMarketSlot::UnresolvedNoRt,
        BinaryMarketSlot::UnresolvedCollateral,
    ];

    for (offset, slot) in active_slots.into_iter().enumerate() {
        let witness = direct_market_witness(&active_plan, active_action, None, slot, output_base);
        compiled
            .program(slot)
            .as_ref()
            .execute(
                &active_pset,
                &witness.build_witness(),
                input_base + offset,
                &network,
            )
            .unwrap_or_else(|error| panic!("valid {slot:?} spend: {error}"));
    }

    for (offset, slot) in [
        BinaryMarketSlot::UnresolvedNoRt,
        BinaryMarketSlot::UnresolvedCollateral,
    ]
    .into_iter()
    .enumerate()
    {
        for path in (0_u8..=9).chain([u8::MAX]) {
            let mut witness =
                direct_market_witness(&active_plan, active_action, None, slot, output_base);
            witness.path = path;
            witness.output_base = u32::MAX;
            compiled
                .program(slot)
                .as_ref()
                .execute(
                    &active_pset,
                    &witness.build_witness(),
                    input_base + offset + 1,
                    &network,
                )
                .unwrap_or_else(|error| {
                    panic!("path-independent follower {slot:?} rejected path {path}: {error}")
                });
        }
    }

    for wrong_path in (0_u8..=9).filter(|path| *path != 2).chain([u8::MAX]) {
        let mut witness = direct_market_witness(
            &active_plan,
            active_action,
            None,
            BinaryMarketSlot::UnresolvedYesRt,
            output_base,
        );
        witness.path = wrong_path;
        assert!(
            compiled
                .program(BinaryMarketSlot::UnresolvedYesRt)
                .as_ref()
                .execute(&active_pset, &witness.build_witness(), input_base, &network,)
                .is_err(),
            "coordinator accepted partial cancellation under path {wrong_path}"
        );
    }

    let mut wrong_active_group = active_pset;
    wrong_active_group.inputs_mut()[input_base + 1].previous_txid =
        Txid::from_byte_array([0xf1; 32]);
    for (offset, slot) in active_slots.into_iter().enumerate() {
        let witness = direct_market_witness(&active_plan, active_action, None, slot, output_base);
        assert!(
            compiled
                .program(slot)
                .as_ref()
                .execute(
                    &wrong_active_group,
                    &witness.build_witness(),
                    input_base + offset,
                    &network,
                )
                .is_err(),
            "{slot:?} accepted a sibling from another contract group"
        );
    }

    let dormant_before = BinaryMarketState::Trading {
        outstanding_pairs: 0,
    };
    let dormant_action = BinaryMarketAction::Expire;
    let dormant_live = live_inputs(params, dormant_before, RtSide::A);
    let dormant_plan = BinaryMarketTransitionPlan::new(
        params,
        dormant_before,
        dormant_action,
        dormant_live.clone(),
        None,
    )
    .expect("dormant expiry plan");
    let mut dormant_pset = market_pset(
        params,
        dormant_before,
        &dormant_live,
        &dormant_plan,
        input_base,
        output_base,
    );
    dormant_plan
        .prepare_expiry(&mut dormant_pset, input_base)
        .expect("prepare dormant expiry");
    let dormant_follower = BinaryMarketSlot::DormantNoRt;
    for path in (0_u8..=9).chain([u8::MAX]) {
        let mut witness = direct_market_witness(
            &dormant_plan,
            dormant_action,
            None,
            dormant_follower,
            output_base,
        );
        witness.path = path;
        witness.output_base = u32::MAX;
        compiled
            .program(dormant_follower)
            .as_ref()
            .execute(
                &dormant_pset,
                &witness.build_witness(),
                input_base + 1,
                &network,
            )
            .unwrap_or_else(|error| {
                panic!("dormant path-independent follower rejected path {path}: {error}")
            });
    }

    let mut wrong_dormant_group = dormant_pset;
    wrong_dormant_group.inputs_mut()[input_base].previous_txid = Txid::from_byte_array([0xf2; 32]);
    let witness = direct_market_witness(
        &dormant_plan,
        dormant_action,
        None,
        dormant_follower,
        output_base,
    );
    assert!(
        compiled
            .program(dormant_follower)
            .as_ref()
            .execute(
                &wrong_dormant_group,
                &witness.build_witness(),
                input_base + 1,
                &network,
            )
            .is_err(),
        "dormant follower accepted a coordinator from another group"
    );
}

fn maker_receive_script() -> Script {
    Script::from(
        vec![0x51, 0x20]
            .into_iter()
            .chain([0x44; 32])
            .collect::<Vec<_>>(),
    )
}

fn maker_params(direction: OrderDirection) -> MakerOrderParams {
    let receive = maker_receive_script();
    MakerOrderParams {
        base_asset_id: asset(0x91),
        quote_asset_id: asset(0x92),
        price: 7,
        min_active_base: 3,
        direction,
        maker_receive_spk_hash: Sha256::digest(receive.as_bytes()).into(),
        maker_pubkey: Keypair::from_seckey_slice(&Secp256k1::new(), &[0x41; 32])
            .expect("maker key")
            .x_only_public_key()
            .0
            .serialize(),
    }
}

fn finalized_maker_stack(direction: OrderDirection, partial: bool) -> Vec<Vec<u8>> {
    let params = maker_params(direction);
    let input_locked = match direction {
        OrderDirection::SellBase => 10,
        OrderDirection::SellQuote => 70,
    };
    let fill_base = if partial { 4 } else { 10 };
    let remainder_index = partial.then_some(1);
    let plan = MakerFillPlan::new(params, maker_receive_script(), input_locked, fill_base, 0)
        .expect("maker fill plan");
    let compiled = CompiledMakerOrder::new(params).expect("compile maker order");
    let held_asset = match direction {
        OrderDirection::SellBase => params.base_asset_id,
        OrderDirection::SellQuote => params.quote_asset_id,
    };
    let mut pset = PartiallySignedTransaction::new_v2();
    pset.add_input(pset_input(
        OutPoint::new(Txid::from_byte_array([0xa1; 32]), 0),
        explicit_txout(held_asset, input_locked, compiled.script_pubkey().clone()),
    ));
    for (_, output) in plan
        .mandatory_outputs(0, remainder_index)
        .expect("maker outputs")
    {
        pset.add_output(PsetOutput::from_txout(output));
    }
    let network = SimplicityNetwork::ElementsRegtest {
        policy_asset: params.quote_asset_id,
    };
    plan.finalize(&mut pset, 0, remainder_index, &network)
        .expect("finalize maker order");
    pset.inputs()[0]
        .final_script_witness
        .clone()
        .expect("final maker witness")
}

#[test]
fn every_finalized_maker_fill_stack_has_sufficient_simplicity_budget() {
    let mut failures = Vec::new();
    for direction in [OrderDirection::SellBase, OrderDirection::SellQuote] {
        for partial in [false, true] {
            let shape = if partial { "partial" } else { "full" };
            let stack = finalized_maker_stack(direction, partial);
            let _ = record_budget(
                format!("maker-{direction:?}-{shape}"),
                &stack,
                &mut failures,
            );
        }
    }
    let report = failure_report(&failures);
    assert!(
        failures.is_empty(),
        "underbudget finalized maker stacks:\n{report}"
    );
}

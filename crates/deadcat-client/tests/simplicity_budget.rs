use deadcat_client::market_builder::{
    BinaryMarketLiveInputs, BinaryMarketTransitionPlan, MarketIssuanceEntropies, MarketRtInput,
    OracleAttestation,
};
use deadcat_contracts::SimplicityNetwork;
use deadcat_contracts::binary_market::{
    BinaryMarketAction, BinaryMarketCoordinatorAction, BinaryMarketCoordinatorRole,
    BinaryMarketEconomics, BinaryMarketLayout, BinaryMarketOperation, BinaryMarketResolution,
    BinaryMarketSlot, BinaryMarketWitness, BinaryOutcome, CompiledBinaryMarket,
};
use deadcat_contracts::finalized_spend::FinalizedSimplicitySpend;
use deadcat_contracts::interpret::{
    BinaryMarketLiveOutputs, TrackedContractOutput, interpret_binary_market_spend_with_compiled,
};
use deadcat_contracts::market_crypto::{
    BinaryOutcome as OracleOutcome, derive_issuance_assets, oracle_message,
};
use deadcat_contracts::rt::{RtLeg, RtSide, commitments, factors};
use deadcat_types::{BinaryMarketParams, BinaryMarketState};
use elements::confidential::{Asset, Nonce, Value};
use elements::hashes::Hash as _;
use elements::pset::{Input as PsetInput, Output as PsetOutput, PartiallySignedTransaction};
use elements::secp256k1_zkp::{Keypair, Message, Secp256k1, Tweak};
use elements::{AssetId, LockTime, OutPoint, Script, Sequence, TxOut, TxOutWitness, Txid};
use serde::Serialize;
use simplex::simplicityhl::simplicity::Cost;

// Rounded CI ceilings with headroom above the oracle-precomputed maxima of 3,633,302
// mw, 72,462 cells, 62 frames, 4,339 stack bytes, 13,624 transaction bytes,
// 15,574 WU, and 3,894 vB. The exact measurements are emitted by the test.
const MAX_MARKET_COVENANT_COST_MILLIWEIGHT: u64 = 4_000_000;
const MAX_MARKET_INPUT_EXTRA_CELLS: usize = 80_000;
const MAX_MARKET_INPUT_EXTRA_FRAMES: usize = 70;
const MAX_MARKET_COVENANT_STACK_BYTES: usize = 5_000;
const MAX_MARKET_TX_BYTES: usize = 15_000;
const MAX_MARKET_TX_WEIGHT: usize = 17_000;
const MAX_MARKET_TX_VSIZE: usize = 4_500;

#[derive(Clone, Copy, Debug, Default, Serialize)]
struct CovenantMetrics {
    cost_milliweight: u64,
    max_extra_cells: usize,
    max_extra_frames: usize,
    program_bytes: usize,
    witness_bytes: usize,
    stack_bytes: usize,
    padding_bytes: usize,
}

impl CovenantMetrics {
    fn add_assign(&mut self, other: Self) {
        self.cost_milliweight = self
            .cost_milliweight
            .checked_add(other.cost_milliweight)
            .expect("aggregate Simplicity cost fits u64");
        self.max_extra_cells = self.max_extra_cells.max(other.max_extra_cells);
        self.max_extra_frames = self.max_extra_frames.max(other.max_extra_frames);
        self.program_bytes += other.program_bytes;
        self.witness_bytes += other.witness_bytes;
        self.stack_bytes += other.stack_bytes;
        self.padding_bytes += other.padding_bytes;
    }
}

fn cost_milliweight(cost: Cost) -> u64 {
    serde_json::to_value(cost)
        .expect("serialize typed Simplicity cost")
        .as_u64()
        .expect("Simplicity cost serializes as integer milliweight")
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

fn assert_at_most<T>(label: &str, metric: &str, actual: T, ceiling: T)
where
    T: Copy + PartialOrd + std::fmt::Display,
{
    assert!(
        actual <= ceiling,
        "{label}: {metric} {actual} exceeds CI ceiling {ceiling}"
    );
}

fn assert_market_resource_ceilings(metrics: &MarketMetrics<'_>) {
    let label = format!("{}/{}", metrics.stage, metrics.rt_input_side);
    assert_at_most(
        &label,
        "aggregate covenant cost (milliweight)",
        metrics.covenant.cost_milliweight,
        MAX_MARKET_COVENANT_COST_MILLIWEIGHT,
    );
    assert_at_most(
        &label,
        "maximum per-input extra cells",
        metrics.covenant.max_extra_cells,
        MAX_MARKET_INPUT_EXTRA_CELLS,
    );
    assert_at_most(
        &label,
        "maximum per-input extra frames",
        metrics.covenant.max_extra_frames,
        MAX_MARKET_INPUT_EXTRA_FRAMES,
    );
    assert_at_most(
        &label,
        "aggregate covenant stack bytes",
        metrics.covenant.stack_bytes,
        MAX_MARKET_COVENANT_STACK_BYTES,
    );
    assert_at_most(
        &label,
        "transaction bytes",
        metrics.tx_bytes,
        MAX_MARKET_TX_BYTES,
    );
    assert_at_most(
        &label,
        "transaction weight",
        metrics.tx_weight,
        MAX_MARKET_TX_WEIGHT,
    );
    assert_at_most(
        &label,
        "transaction vsize",
        metrics.tx_vsize,
        MAX_MARKET_TX_VSIZE,
    );
}

fn assert_canonical_padding(label: &str, annex: &[u8]) {
    assert_eq!(annex.first(), Some(&0x50), "{label}: annex tag");
    assert!(
        annex[1..].iter().all(|byte| *byte == 0),
        "{label}: annex must contain only the 0x50 tag followed by zero padding"
    );
}

fn record_budget(label: impl Into<String>, stack: &[Vec<u8>]) -> CovenantMetrics {
    let label = label.into();
    let stack = stack.to_vec();
    let finalized = FinalizedSimplicitySpend::from_witness_stack(stack.clone())
        .unwrap_or_else(|error| panic!("{label}: {error}"));
    let bounds = finalized.bounds();
    let cost = bounds.cost;
    let annex = finalized.annex();
    if let Some(annex) = annex {
        assert_canonical_padding(&label, annex);
        if annex.len() > 1 {
            let mut shortened = stack;
            assert_eq!(
                shortened.last_mut().expect("annex").pop(),
                Some(0),
                "{label}: last annex byte must be zero padding"
            );
            assert!(
                !cost.is_budget_valid(&shortened),
                "{label}: finalized annex contains unnecessary zero padding"
            );
        }
    }

    let sizes = finalized.encoded_sizes();
    CovenantMetrics {
        cost_milliweight: cost_milliweight(cost),
        max_extra_cells: bounds.extra_cells,
        max_extra_frames: bounds.extra_frames,
        program_bytes: sizes.program_bytes,
        witness_bytes: sizes.witness_bytes,
        stack_bytes: sizes.stack_bytes,
        padding_bytes: sizes.annex_bytes,
    }
}

#[test]
fn simplicity_budget_padding_is_minimal_at_compact_size_boundaries() {
    // Keep the four-item shape of a finalized Simplicity stack. The contents do
    // not matter for budget accounting, which uses consensus-encoded length.
    let stack = vec![Vec::new(); 4];
    let base_budget = elements::encode::serialize(&stack).len() + 50;
    let cases = [
        ("tag-only-annex", 1_usize, 1_usize),
        ("annex-252/deficit-253", 253, 252),
        ("annex-253/deficit-254", 254, 253),
        ("annex-253/deficit-255", 255, 253),
        ("annex-253/deficit-256", 256, 253),
        ("annex-254/deficit-257", 257, 254),
        ("annex-65535/deficit-65538", 65_538, 65_535),
        ("annex-65536/deficit-65539", 65_539, 65_536),
        ("annex-65536/deficit-65540", 65_540, 65_536),
        ("annex-65536/deficit-65541", 65_541, 65_536),
        ("annex-65537/deficit-65542", 65_542, 65_537),
    ];

    for (label, deficit, expected_annex_len) in cases {
        let milliweight =
            u32::try_from((base_budget + deficit) * 1_000).expect("boundary test cost fits u32");
        let cost = Cost::from_milliweight(milliweight);
        assert!(
            !cost.is_budget_valid(&stack),
            "{label}: unpadded stack unexpectedly has sufficient budget"
        );

        let annex = cost
            .get_padding(&stack)
            .unwrap_or_else(|| panic!("{label}: expected padding"));
        assert_eq!(annex.len(), expected_annex_len, "{label}: annex length");
        assert_canonical_padding(label, &annex);

        let mut padded = stack.clone();
        padded.push(annex);
        assert!(
            cost.is_budget_valid(&padded),
            "{label}: generated padding must satisfy the budget"
        );
        if expected_annex_len == 1 {
            let removed = padded.pop().expect("tag-only annex");
            assert_eq!(removed.as_slice(), &[0x50], "{label}: removed annex");
            assert!(
                !cost.is_budget_valid(&padded),
                "{label}: removing the tag-only annex must leave the core stack underbudget"
            );
        } else {
            assert_eq!(
                padded.last_mut().expect("annex").pop(),
                Some(0),
                "{label}: boundary annex must end in zero padding"
            );
            assert!(
                !cost.is_budget_valid(&padded),
                "{label}: removing one zero must make the padding insufficient"
            );
        }
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
    compiled: &CompiledBinaryMarket,
    state: BinaryMarketState,
    side: RtSide,
) -> BinaryMarketLiveInputs {
    let params = compiled.params();
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
    compiled: &CompiledBinaryMarket,
    state: BinaryMarketState,
    live: &BinaryMarketLiveInputs,
    plan: &BinaryMarketTransitionPlan,
    input_base: usize,
    output_base: usize,
) -> PartiallySignedTransaction {
    let params = compiled.params();
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
    compiled: &CompiledBinaryMarket,
    state: BinaryMarketState,
    live: &BinaryMarketLiveInputs,
) -> BinaryMarketLiveOutputs {
    let params = compiled.params();
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
) -> BinaryMarketWitness {
    let resolution = match (action, attestation) {
        (BinaryMarketAction::Resolve { outcome }, Some(attestation)) => {
            Some(BinaryMarketResolution::new(outcome, attestation.signature))
        }
        _ => None,
    };
    let layout = plan.layout();
    let coordinator_action = BinaryMarketCoordinatorAction::for_layout(
        layout,
        u32::try_from(output_base).expect("test output index fits u32"),
        resolution,
    )
    .expect("action matches transition layout");
    BinaryMarketWitness::for_slot(layout, slot, coordinator_action)
        .expect("slot belongs to transition layout")
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

fn finalized_market_fixture(
    compiled: &CompiledBinaryMarket,
    before: BinaryMarketState,
    action: BinaryMarketAction,
    side: RtSide,
    input_base: usize,
    output_base: usize,
) -> (
    BinaryMarketTransitionPlan,
    Option<OracleAttestation>,
    PartiallySignedTransaction,
) {
    let params = compiled.params();
    let attestation = match action {
        BinaryMarketAction::Resolve { outcome } => Some(sign_attestation(params, outcome)),
        _ => None,
    };
    let live = live_inputs(compiled, before, side);
    let plan = BinaryMarketTransitionPlan::new_with_compiled(
        compiled,
        before,
        action,
        live.clone(),
        attestation,
    )
    .expect("market transition plan");
    let mut pset = market_pset(compiled, before, &live, &plan, input_base, output_base);
    if matches!(action, BinaryMarketAction::Issue { .. }) {
        let entropies = MarketIssuanceEntropies::from_defining_outpoints(
            params,
            defining_outpoints().0,
            defining_outpoints().1,
        )
        .expect("issuance entropies");
        plan.configure_reissuance_inputs(&mut pset, input_base, entropies)
            .expect("configure reissuance");
    }
    if matches!(action, BinaryMarketAction::Expire) {
        plan.prepare_expiry(&mut pset, input_base)
            .expect("prepare expiry");
    }
    let network = SimplicityNetwork::ElementsRegtest {
        policy_asset: params.collateral_asset_id,
    };
    plan.finalize_with_compiled(compiled, &mut pset, input_base, output_base, &network)
        .expect("finalize market fixture");
    (plan, attestation, pset)
}

#[test]
fn typed_finalized_spend_round_trips_and_reexecutes_from_the_installed_stack() {
    let params = market_params();
    let compiled = CompiledBinaryMarket::new(params).expect("compile canonical market");
    let before = BinaryMarketState::Trading {
        outstanding_pairs: 0,
    };
    let action = BinaryMarketAction::Issue { pairs: 2 };
    let input_base = 1;
    let output_base = 1;
    let (plan, attestation, pset) = finalized_market_fixture(
        &compiled,
        before,
        action,
        RtSide::A,
        input_base,
        output_base,
    );
    let slot = BinaryMarketSlot::DormantYesRt;
    let witness = direct_market_witness(&plan, action, attestation, slot, output_base);
    let network = SimplicityNetwork::ElementsRegtest {
        policy_asset: params.collateral_asset_id,
    };
    let installed = pset.inputs()[input_base]
        .final_script_witness
        .as_ref()
        .expect("installed finalized witness");

    let finalized = compiled
        .finalize(slot, &pset, &witness.build_witness(), input_base, &network)
        .expect("build typed finalized spend");
    assert_eq!(finalized.witness_stack(), installed);
    assert_eq!(finalized.cmr(), compiled.cmr());
    assert_eq!(
        finalized.control_block(),
        compiled.slot(slot).control_block()
    );
    assert_eq!(
        finalized.encoded_sizes().stack_bytes,
        elements::encode::serialize(installed).len()
    );
    assert_eq!(finalized.into_witness_stack(), *installed);

    compiled
        .execute_finalized(slot, &pset, input_base, &network)
        .expect("re-execute installed finalized witness");
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
    let mut measurements = Vec::new();
    let compiled = CompiledBinaryMarket::new(params).expect("compile canonical market");
    for side in [RtSide::A, RtSide::B] {
        for &(label, before, action, attestation) in &cases {
            let live = live_inputs(&compiled, before, side);
            let plan = BinaryMarketTransitionPlan::new_with_compiled(
                &compiled,
                before,
                action,
                live.clone(),
                attestation,
            )
            .unwrap_or_else(|error| panic!("{label}/{side:?}: plan: {error}"));
            let input_base = 1;
            let output_base = 1;
            let mut pset = market_pset(&compiled, before, &live, &plan, input_base, output_base);
            if matches!(action, BinaryMarketAction::Issue { .. }) {
                plan.configure_reissuance_inputs(&mut pset, input_base, entropies)
                    .unwrap_or_else(|error| panic!("{label}/{side:?}: reissuance: {error}"));
            }
            if matches!(action, BinaryMarketAction::Expire) {
                plan.prepare_expiry(&mut pset, input_base)
                    .unwrap_or_else(|error| panic!("{label}/{side:?}: expiry: {error}"));
            }
            plan.finalize_with_compiled(&compiled, &mut pset, input_base, output_base, &network)
                .unwrap_or_else(|error| panic!("{label}/{side:?}: finalize: {error}"));
            let slots = market_input_slots(before);
            for (offset, slot) in slots.iter().copied().enumerate() {
                let witness = direct_market_witness(&plan, action, attestation, slot, output_base);
                compiled
                    .execute(
                        slot,
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
                    .execute(
                        slot,
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
                            .execute(
                                coordinator,
                                &malicious,
                                &witness.build_witness(),
                                input_base,
                                &network,
                            )
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
                ));
            }

            let transaction = pset.extract_tx().expect("extract finalized market tx");
            let metrics = MarketMetrics {
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
            };
            assert_market_resource_ceilings(&metrics);
            measurements.push(metrics);
            let interpreted = interpret_binary_market_spend_with_compiled(
                &compiled,
                before,
                &interpreter_live_outputs(&compiled, before, &live),
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
                        .execute(
                            coordinator,
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
                    interpret_binary_market_spend_with_compiled(
                        &compiled,
                        before,
                        &interpreter_live_outputs(&compiled, before, &live),
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
                            .execute(
                                coordinator,
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
                        interpret_binary_market_spend_with_compiled(
                            &compiled,
                            before,
                            &interpreter_live_outputs(&compiled, before, &live),
                            &wrong_nonce,
                        )
                        .is_err(),
                        "{label}/{side:?}: wrong reissuance nonce at sibling {offset}"
                    );
                }
            }
        }
    }
    eprintln!(
        "DEADCAT_AB_MARKET_METRICS={}",
        serde_json::to_string(&measurements).expect("serialize market measurements")
    );
}

#[test]
fn market_coordinator_rejects_adversarial_solvency_and_authorization_mutations() {
    let params = market_params();
    let compiled = CompiledBinaryMarket::new(params).expect("compile canonical market");
    let network = SimplicityNetwork::ElementsRegtest {
        policy_asset: params.collateral_asset_id,
    };
    let input_base = 1;
    let output_base = 1;
    let assert_rejected = |before: BinaryMarketState,
                           action: BinaryMarketAction,
                           attestation: Option<OracleAttestation>,
                           plan: &BinaryMarketTransitionPlan,
                           candidate: &PartiallySignedTransaction,
                           label: &str| {
        let coordinator = market_input_slots(before)[0];
        let witness = direct_market_witness(plan, action, attestation, coordinator, output_base);
        assert!(
            compiled
                .execute(
                    coordinator,
                    candidate,
                    &witness.build_witness(),
                    input_base,
                    &network,
                )
                .is_err(),
            "coordinator accepted {label}"
        );
    };

    let dormant = BinaryMarketState::Trading {
        outstanding_pairs: 0,
    };
    let issue_two = BinaryMarketAction::Issue { pairs: 2 };
    let (initial_plan, initial_attestation, initial) = finalized_market_fixture(
        &compiled,
        dormant,
        issue_two,
        RtSide::A,
        input_base,
        output_base,
    );

    let mut unequal_issuance = initial.clone();
    unequal_issuance.inputs_mut()[input_base + 1].issuance_value_amount = Some(3);
    assert_rejected(
        dormant,
        issue_two,
        initial_attestation,
        &initial_plan,
        &unequal_issuance,
        "unequal YES/NO issuance",
    );

    let mut zero_issuance = initial.clone();
    for offset in 0..2 {
        zero_issuance.inputs_mut()[input_base + offset].issuance_value_amount = Some(0);
    }
    zero_issuance.outputs_mut()[output_base + 2].amount = Some(0);
    assert_rejected(
        dormant,
        issue_two,
        initial_attestation,
        &initial_plan,
        &zero_issuance,
        "equal zero issuance with zero collateral",
    );

    let Value::Confidential(confidential_amount) = initial.inputs()[input_base]
        .witness_utxo
        .as_ref()
        .expect("YES RT witness UTXO")
        .value
    else {
        panic!("YES RT value must be confidential");
    };
    let mut confidential_issuance = initial.clone();
    confidential_issuance.inputs_mut()[input_base].issuance_value_amount = None;
    confidential_issuance.inputs_mut()[input_base].issuance_value_comm = Some(confidential_amount);
    assert_rejected(
        dormant,
        issue_two,
        initial_attestation,
        &initial_plan,
        &confidential_issuance,
        "confidential issuance amount",
    );

    let mut token_issuance_builder = initial.clone();
    token_issuance_builder.inputs_mut()[input_base].issuance_inflation_keys = Some(1);
    assert!(
        initial_plan
            .finalize_with_compiled(
                &compiled,
                &mut token_issuance_builder,
                input_base,
                output_base,
                &network
            )
            .is_err(),
        "builder accepted raw non-null reissuance-token field",
    );
    let mut token_issuance_interpreter = initial.clone();
    token_issuance_interpreter.inputs_mut()[input_base].issuance_inflation_keys = Some(1);
    let token_issuance_tx = token_issuance_interpreter
        .extract_tx()
        .expect("extract raw token-issuance transaction");
    let live = live_inputs(&compiled, dormant, RtSide::A);
    assert!(
        interpret_binary_market_spend_with_compiled(
            &compiled,
            dormant,
            &interpreter_live_outputs(&compiled, dormant, &live),
            &token_issuance_tx,
        )
        .is_err(),
        "interpreter accepted raw non-null reissuance-token field",
    );

    let mut wrong_issuance_identity = initial.clone();
    wrong_issuance_identity.inputs_mut()[input_base].issuance_asset_entropy = Some([0x91; 32]);
    assert_rejected(
        dormant,
        issue_two,
        initial_attestation,
        &initial_plan,
        &wrong_issuance_identity,
        "wrong issued asset and token identity",
    );

    let mut wrong_initial_collateral = initial;
    wrong_initial_collateral.outputs_mut()[output_base + 2].amount = Some(401);
    assert_rejected(
        dormant,
        issue_two,
        initial_attestation,
        &initial_plan,
        &wrong_initial_collateral,
        "initial issuance collateral off by one",
    );

    let active = BinaryMarketState::Trading {
        outstanding_pairs: 3,
    };
    let (subsequent_plan, subsequent_attestation, subsequent) = finalized_market_fixture(
        &compiled,
        active,
        issue_two,
        RtSide::B,
        input_base,
        output_base,
    );
    let mut issuance_on_collateral = subsequent.clone();
    attach_dummy_issuance(&mut issuance_on_collateral.inputs_mut()[input_base + 2]);
    assert_rejected(
        active,
        issue_two,
        subsequent_attestation,
        &subsequent_plan,
        &issuance_on_collateral,
        "issuance on the subsequent-issuance collateral input",
    );

    let mut wrong_subsequent_collateral = subsequent;
    wrong_subsequent_collateral.outputs_mut()[output_base + 2].amount = Some(1_001);
    assert_rejected(
        active,
        issue_two,
        subsequent_attestation,
        &subsequent_plan,
        &wrong_subsequent_collateral,
        "subsequent issuance collateral off by one",
    );

    let cancel_one = BinaryMarketAction::Cancel { pairs: 1 };
    let (partial_plan, partial_attestation, partial) = finalized_market_fixture(
        &compiled,
        active,
        cancel_one,
        RtSide::A,
        input_base,
        output_base,
    );
    let mut unequal_burn = partial.clone();
    unequal_burn.outputs_mut()[output_base + 4].amount = Some(2);
    assert_rejected(
        active,
        cancel_one,
        partial_attestation,
        &partial_plan,
        &unequal_burn,
        "unequal cancellation burns",
    );

    let mut wrong_burn_script = partial.clone();
    wrong_burn_script.outputs_mut()[output_base + 3].script_pubkey = Script::from(vec![0x51]);
    assert_rejected(
        active,
        cancel_one,
        partial_attestation,
        &partial_plan,
        &wrong_burn_script,
        "cancellation burn sent to a spendable script",
    );

    let mut wrong_partial_collateral = partial.clone();
    wrong_partial_collateral.outputs_mut()[output_base + 2].amount = Some(401);
    assert_rejected(
        active,
        cancel_one,
        partial_attestation,
        &partial_plan,
        &wrong_partial_collateral,
        "partial cancellation collateral off by one",
    );

    let mut drained_partial = partial;
    drained_partial.inputs_mut()[input_base + 2]
        .witness_utxo
        .as_mut()
        .expect("collateral witness UTXO")
        .value = Value::Explicit(200);
    drained_partial.outputs_mut()[output_base + 2].amount = Some(0);
    assert_rejected(
        active,
        cancel_one,
        partial_attestation,
        &partial_plan,
        &drained_partial,
        "partial cancellation that drains the state to zero",
    );

    let cancel_all = BinaryMarketAction::Cancel { pairs: 3 };
    let (full_plan, full_attestation, mut wrong_full_collateral) = finalized_market_fixture(
        &compiled,
        active,
        cancel_all,
        RtSide::B,
        input_base,
        output_base,
    );
    wrong_full_collateral.inputs_mut()[input_base + 2]
        .witness_utxo
        .as_mut()
        .expect("collateral witness UTXO")
        .value = Value::Explicit(601);
    assert_rejected(
        active,
        cancel_all,
        full_attestation,
        &full_plan,
        &wrong_full_collateral,
        "full cancellation with excess collateral",
    );

    let resolve_yes = BinaryMarketAction::Resolve {
        outcome: BinaryOutcome::Yes,
    };
    let (resolution_plan, resolution_attestation, resolution) = finalized_market_fixture(
        &compiled,
        active,
        resolve_yes,
        RtSide::A,
        input_base,
        output_base,
    );
    let coordinator = BinaryMarketSlot::UnresolvedYesRt;
    let mut signature = resolution_attestation
        .expect("resolution attestation")
        .signature;
    signature[0] ^= 1;
    let bad_action = BinaryMarketCoordinatorAction::for_layout(
        resolution_plan.layout(),
        u32::try_from(output_base).expect("test output index fits u32"),
        Some(BinaryMarketResolution::new(BinaryOutcome::Yes, signature)),
    )
    .expect("resolution action");
    let bad_signature =
        BinaryMarketWitness::for_slot(resolution_plan.layout(), coordinator, bad_action)
            .expect("coordinator witness");
    assert!(
        compiled
            .execute(
                coordinator,
                &resolution,
                &bad_signature.build_witness(),
                input_base,
                &network,
            )
            .is_err(),
        "coordinator accepted a bad oracle signature"
    );

    let resolve_no = BinaryMarketAction::Resolve {
        outcome: BinaryOutcome::No,
    };
    let no_attestation = Some(sign_attestation(params, BinaryOutcome::No));
    let wrong_outcome = direct_market_witness(
        &resolution_plan,
        resolve_no,
        no_attestation,
        coordinator,
        output_base,
    );
    assert!(
        compiled
            .execute(
                coordinator,
                &resolution,
                &wrong_outcome.build_witness(),
                input_base,
                &network,
            )
            .is_err(),
        "coordinator accepted a valid NO attestation with a YES continuation"
    );

    let (no_resolution_plan, _, no_resolution) = finalized_market_fixture(
        &compiled,
        active,
        resolve_no,
        RtSide::A,
        input_base,
        output_base,
    );
    let yes_signature_for_no = direct_market_witness(
        &no_resolution_plan,
        resolve_no,
        resolution_attestation,
        coordinator,
        output_base,
    );
    assert!(
        compiled
            .execute(
                coordinator,
                &no_resolution,
                &yes_signature_for_no.build_witness(),
                input_base,
                &network,
            )
            .is_err(),
        "coordinator accepted a valid YES signature for the NO message"
    );

    let mut wrong_resolution_collateral = resolution.clone();
    wrong_resolution_collateral.outputs_mut()[output_base + 2].amount = Some(601);
    assert_rejected(
        active,
        resolve_yes,
        resolution_attestation,
        &resolution_plan,
        &wrong_resolution_collateral,
        "resolution collateral off by one",
    );

    let mut spendable_rt_burn = resolution;
    spendable_rt_burn.outputs_mut()[output_base].script_pubkey = Script::from(vec![0x51]);
    assert_rejected(
        active,
        resolve_yes,
        resolution_attestation,
        &resolution_plan,
        &spendable_rt_burn,
        "terminal RT sent to a spendable script",
    );

    let expire = BinaryMarketAction::Expire;
    let (expiry_plan, expiry_attestation, expiry) = finalized_market_fixture(
        &compiled,
        active,
        expire,
        RtSide::B,
        input_base,
        output_base,
    );
    let mut early_expiry = expiry.clone();
    early_expiry.global.tx_data.fallback_locktime =
        Some(LockTime::from_height(params.expiry_height - 1).expect("prior height"));
    assert_rejected(
        active,
        expire,
        expiry_attestation,
        &expiry_plan,
        &early_expiry,
        "expiry below the committed height",
    );

    let mut final_sequence_expiry = expiry;
    for offset in 0..3 {
        final_sequence_expiry.inputs_mut()[input_base + offset].sequence = Some(Sequence::MAX);
    }
    assert_rejected(
        active,
        expire,
        expiry_attestation,
        &expiry_plan,
        &final_sequence_expiry,
        "expiry whose transaction has only final sequences",
    );

    let resolved = BinaryMarketState::ResolvedYes {
        collateral_unredeemed: 600,
    };
    let redeem_yes = BinaryMarketAction::Redeem {
        outcome: BinaryOutcome::Yes,
        tokens: 1,
    };
    let (redemption_plan, redemption_attestation, redemption) = finalized_market_fixture(
        &compiled,
        resolved,
        redeem_yes,
        RtSide::A,
        input_base,
        output_base,
    );
    for tokens in [0, 4] {
        let mut wrong_burn = redemption.clone();
        wrong_burn.outputs_mut()[output_base + 1].amount = Some(tokens);
        assert_rejected(
            resolved,
            redeem_yes,
            redemption_attestation,
            &redemption_plan,
            &wrong_burn,
            "resolved redemption with an invalid derived burn amount",
        );
    }

    let mut wrong_resolved_formula = redemption.clone();
    wrong_resolved_formula.outputs_mut()[output_base].amount = Some(500);
    assert_rejected(
        resolved,
        redeem_yes,
        redemption_attestation,
        &redemption_plan,
        &wrong_resolved_formula,
        "resolved redemption using the one-sided expiry payout",
    );

    let mut wrong_winner = redemption.clone();
    wrong_winner.outputs_mut()[output_base + 1].asset = Some(params.no_token_asset_id);
    assert_rejected(
        resolved,
        redeem_yes,
        redemption_attestation,
        &redemption_plan,
        &wrong_winner,
        "resolved redemption burning the losing token",
    );

    let mut wrong_redemption_slot = redemption;
    wrong_redemption_slot.outputs_mut()[output_base].script_pubkey = compiled
        .slot(BinaryMarketSlot::ResolvedNoCollateral)
        .script_pubkey()
        .clone();
    assert_rejected(
        resolved,
        redeem_yes,
        redemption_attestation,
        &redemption_plan,
        &wrong_redemption_slot,
        "resolved redemption continuing in the wrong slot",
    );

    let expired = BinaryMarketState::Expired {
        collateral_unredeemed: 300,
    };
    let redeem_expired_no = BinaryMarketAction::Redeem {
        outcome: BinaryOutcome::No,
        tokens: 1,
    };
    let (expired_plan, expired_attestation, expired_redemption) = finalized_market_fixture(
        &compiled,
        expired,
        redeem_expired_no,
        RtSide::A,
        input_base,
        output_base,
    );
    let mut wrong_expiry_formula = expired_redemption.clone();
    wrong_expiry_formula.outputs_mut()[output_base].amount = Some(100);
    assert_rejected(
        expired,
        redeem_expired_no,
        expired_attestation,
        &expired_plan,
        &wrong_expiry_formula,
        "expiry redemption using the resolved-market payout",
    );

    let mut alternate_expiry_token = expired_redemption;
    alternate_expiry_token.outputs_mut()[output_base + 1].asset = Some(params.yes_token_asset_id);
    let slot = BinaryMarketSlot::ExpiredCollateral;
    let witness = direct_market_witness(
        &expired_plan,
        redeem_expired_no,
        expired_attestation,
        slot,
        output_base,
    );
    compiled
        .execute(
            slot,
            &alternate_expiry_token,
            &witness.build_witness(),
            input_base,
            &network,
        )
        .expect("expiry redemption derives and accepts either token side");
    let transaction = alternate_expiry_token
        .extract_tx()
        .expect("extract alternate expiry redemption");
    let expired_live = live_inputs(&compiled, expired, RtSide::A);
    let interpreted = interpret_binary_market_spend_with_compiled(
        &compiled,
        expired,
        &interpreter_live_outputs(&compiled, expired, &expired_live),
        &transaction,
    )
    .expect("interpret alternate expiry token side");
    assert_eq!(
        interpreted.action,
        BinaryMarketAction::Redeem {
            outcome: BinaryOutcome::Yes,
            tokens: 1,
        }
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
    let active_live = live_inputs(&compiled, active_before, RtSide::A);
    let active_plan = BinaryMarketTransitionPlan::new_with_compiled(
        &compiled,
        active_before,
        active_action,
        active_live.clone(),
        None,
    )
    .expect("partial cancellation plan");
    let active_pset = market_pset(
        &compiled,
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
            .execute(
                slot,
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
        for divergent_output_base in [0, u32::MAX - 1, u32::MAX] {
            let action = BinaryMarketCoordinatorAction::Cancel {
                output_base: divergent_output_base,
            };
            let witness = BinaryMarketWitness::for_slot(active_plan.layout(), slot, action)
                .expect("follower witness");
            compiled
                .execute(
                    slot,
                    &active_pset,
                    &witness.build_witness(),
                    input_base + offset + 1,
                    &network,
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "action-independent follower {slot:?} rejected output base \
                         {divergent_output_base}: {error}"
                    )
                });
        }
    }

    let output_base_u32 = u32::try_from(output_base).expect("test output index fits u32");
    let wrong_layouts = [
        (
            BinaryMarketLayout::for_operation(
                BinaryMarketCoordinatorRole::UnresolvedYesRt,
                BinaryMarketOperation::Issue,
                None,
            )
            .expect("issuance layout"),
            BinaryMarketCoordinatorAction::Issue {
                output_base: output_base_u32,
            },
            "issue",
        ),
        (
            BinaryMarketLayout::for_operation(
                BinaryMarketCoordinatorRole::UnresolvedYesRt,
                BinaryMarketOperation::Resolve,
                None,
            )
            .expect("resolution layout"),
            BinaryMarketCoordinatorAction::Resolve {
                output_base: output_base_u32,
                resolution: BinaryMarketResolution::new(
                    BinaryOutcome::Yes,
                    sign_attestation(params, BinaryOutcome::Yes).signature,
                ),
            },
            "resolve",
        ),
        (
            BinaryMarketLayout::for_operation(
                BinaryMarketCoordinatorRole::UnresolvedYesRt,
                BinaryMarketOperation::Expire,
                None,
            )
            .expect("expiry layout"),
            BinaryMarketCoordinatorAction::Expire {
                output_base: output_base_u32,
            },
            "expire",
        ),
    ];
    for (wrong_layout, wrong_action, label) in wrong_layouts {
        let witness = BinaryMarketWitness::for_slot(
            wrong_layout,
            BinaryMarketSlot::UnresolvedYesRt,
            wrong_action,
        )
        .expect("wrong semantic coordinator witness");
        assert!(
            compiled
                .execute(
                    BinaryMarketSlot::UnresolvedYesRt,
                    &active_pset,
                    &witness.build_witness(),
                    input_base,
                    &network,
                )
                .is_err(),
            "coordinator accepted cancellation transaction under {label} action"
        );
    }

    for (offset, slot) in active_slots.into_iter().enumerate() {
        let wrong_slot = active_slots[(offset + 1) % active_slots.len()];
        let action = BinaryMarketCoordinatorAction::Cancel {
            output_base: output_base_u32,
        };
        let witness = BinaryMarketWitness::for_slot(active_plan.layout(), wrong_slot, action)
            .expect("wrong role still belongs to active layout");
        assert!(
            compiled
                .execute(
                    slot,
                    &active_pset,
                    &witness.build_witness(),
                    input_base + offset,
                    &network,
                )
                .is_err(),
            "{slot:?} accepted the wrong committed SLOT"
        );
    }

    let mut wrong_active_group = active_pset.clone();
    wrong_active_group.inputs_mut()[input_base + 1].previous_txid =
        Txid::from_byte_array([0xf1; 32]);
    for (offset, slot) in active_slots.into_iter().enumerate() {
        let witness = direct_market_witness(&active_plan, active_action, None, slot, output_base);
        assert!(
            compiled
                .execute(
                    slot,
                    &wrong_active_group,
                    &witness.build_witness(),
                    input_base + offset,
                    &network,
                )
                .is_err(),
            "{slot:?} accepted a sibling from another contract group"
        );
    }

    let mut wrong_no_vout = active_pset.clone();
    wrong_no_vout.inputs_mut()[input_base + 1].previous_output_index += 1;
    for (offset, slot) in active_slots.into_iter().enumerate() {
        let witness = direct_market_witness(&active_plan, active_action, None, slot, output_base);
        assert!(
            compiled
                .execute(
                    slot,
                    &wrong_no_vout,
                    &witness.build_witness(),
                    input_base + offset,
                    &network,
                )
                .is_err(),
            "{slot:?} accepted a nonconsecutive NO sibling"
        );
    }

    let mut wrong_collateral_vout = active_pset.clone();
    wrong_collateral_vout.inputs_mut()[input_base + 2].previous_output_index += 1;
    for (offset, slot) in active_slots.into_iter().enumerate() {
        let witness = direct_market_witness(&active_plan, active_action, None, slot, output_base);
        assert!(
            compiled
                .execute(
                    slot,
                    &wrong_collateral_vout,
                    &witness.build_witness(),
                    input_base + offset,
                    &network,
                )
                .is_err(),
            "{slot:?} accepted a nonconsecutive collateral sibling"
        );
    }

    let mut wrong_no_script = active_pset.clone();
    wrong_no_script.inputs_mut()[input_base + 1]
        .witness_utxo
        .as_mut()
        .expect("NO witness UTXO")
        .script_pubkey = Script::from(vec![0x51]);
    for (offset, slot) in active_slots.into_iter().enumerate() {
        let witness = direct_market_witness(&active_plan, active_action, None, slot, output_base);
        assert!(
            compiled
                .execute(
                    slot,
                    &wrong_no_script,
                    &witness.build_witness(),
                    input_base + offset,
                    &network,
                )
                .is_err(),
            "{slot:?} accepted a sibling with the wrong role script"
        );
    }

    let mut mixed_witness_pset = active_pset;
    active_plan
        .finalize_with_compiled(
            &compiled,
            &mut mixed_witness_pset,
            input_base,
            output_base,
            &network,
        )
        .expect("finalize canonical coordinator and followers");
    for (offset, slot, divergent_output_base) in [
        (1, BinaryMarketSlot::UnresolvedNoRt, u32::MAX - 1),
        (2, BinaryMarketSlot::UnresolvedCollateral, u32::MAX),
    ] {
        let input_index = input_base + offset;
        let witness = BinaryMarketWitness::for_slot(
            active_plan.layout(),
            slot,
            BinaryMarketCoordinatorAction::Cancel {
                output_base: divergent_output_base,
            },
        )
        .expect("follower witness with divergent action payload");
        compiled
            .execute(
                slot,
                &mixed_witness_pset,
                &witness.build_witness(),
                input_index,
                &network,
            )
            .unwrap_or_else(|error| panic!("mixed follower {slot:?}: {error}"));
        let canonical_stack = mixed_witness_pset.inputs()[input_index]
            .final_script_witness
            .as_ref()
            .expect("canonical follower stack")
            .clone();
        let mixed_stack = compiled
            .finalize(
                slot,
                &mixed_witness_pset,
                &witness.build_witness(),
                input_index,
                &network,
            )
            .expect("finalize mixed follower")
            .into_witness_stack();
        assert!((4..=5).contains(&canonical_stack.len()));
        assert_eq!(
            mixed_stack, canonical_stack,
            "follower {slot:?} must prune ACTION from its witness program"
        );
        record_budget(format!("mixed-follower-{slot:?}"), &mixed_stack);
        mixed_witness_pset.inputs_mut()[input_index].final_script_witness = Some(mixed_stack);
    }
    let mixed_transaction = mixed_witness_pset
        .extract_tx()
        .expect("extract mixed-witness transaction");
    let interpreted = interpret_binary_market_spend_with_compiled(
        &compiled,
        active_before,
        &interpreter_live_outputs(&compiled, active_before, &active_live),
        &mixed_transaction,
    )
    .expect("interpret mixed-witness transaction from its coordinator");
    assert_eq!(interpreted.action, active_action);
    assert_eq!(interpreted.after, active_plan.after());

    let dormant_before = BinaryMarketState::Trading {
        outstanding_pairs: 0,
    };
    let dormant_action = BinaryMarketAction::Expire;
    let dormant_live = live_inputs(&compiled, dormant_before, RtSide::A);
    let dormant_plan = BinaryMarketTransitionPlan::new_with_compiled(
        &compiled,
        dormant_before,
        dormant_action,
        dormant_live.clone(),
        None,
    )
    .expect("dormant expiry plan");
    let mut dormant_pset = market_pset(
        &compiled,
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
    for divergent_output_base in [0, u32::MAX - 1, u32::MAX] {
        let witness = BinaryMarketWitness::for_slot(
            dormant_plan.layout(),
            dormant_follower,
            BinaryMarketCoordinatorAction::Expire {
                output_base: divergent_output_base,
            },
        )
        .expect("dormant follower witness with divergent action payload");
        compiled
            .execute(
                dormant_follower,
                &dormant_pset,
                &witness.build_witness(),
                input_base + 1,
                &network,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "ACTION-independent dormant follower rejected output base \
                     {divergent_output_base}: {error}"
                )
            });
    }

    // Dormant RTs may originate at nonconsecutive outputs of one composed
    // creation transaction. Only unresolved continuation groups are required
    // to occupy consecutive prior vouts.
    let mut composed_dormant_pset = dormant_pset.clone();
    composed_dormant_pset.inputs_mut()[input_base + 1].previous_output_index += 7;
    for (offset, slot) in [
        BinaryMarketSlot::DormantYesRt,
        BinaryMarketSlot::DormantNoRt,
    ]
    .into_iter()
    .enumerate()
    {
        let witness = direct_market_witness(&dormant_plan, dormant_action, None, slot, output_base);
        compiled
            .execute(
                slot,
                &composed_dormant_pset,
                &witness.build_witness(),
                input_base + offset,
                &network,
            )
            .unwrap_or_else(|error| {
                panic!("{slot:?} rejected a valid nonconsecutive dormant sibling: {error}")
            });
    }

    for (offset, slot) in [
        BinaryMarketSlot::DormantYesRt,
        BinaryMarketSlot::DormantNoRt,
    ]
    .into_iter()
    .enumerate()
    {
        let dormant_slots = [
            BinaryMarketSlot::DormantYesRt,
            BinaryMarketSlot::DormantNoRt,
        ];
        let wrong_slot = dormant_slots[(offset + 1) % dormant_slots.len()];
        let witness = BinaryMarketWitness::for_slot(
            dormant_plan.layout(),
            wrong_slot,
            BinaryMarketCoordinatorAction::Expire {
                output_base: u32::try_from(output_base).expect("output index fits u32"),
            },
        )
        .expect("wrong role still belongs to dormant layout");
        assert!(
            compiled
                .execute(
                    slot,
                    &dormant_pset,
                    &witness.build_witness(),
                    input_base + offset,
                    &network,
                )
                .is_err(),
            "{slot:?} accepted the wrong committed SLOT"
        );
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
            .execute(
                dormant_follower,
                &wrong_dormant_group,
                &witness.build_witness(),
                input_base + 1,
                &network,
            )
            .is_err(),
        "dormant follower accepted a coordinator from another group"
    );
}

#[test]
fn every_terminal_market_slot_rejects_a_false_slot_witness() {
    let params = market_params();
    let compiled = CompiledBinaryMarket::new(params).expect("compile canonical market");
    let network = SimplicityNetwork::ElementsRegtest {
        policy_asset: params.collateral_asset_id,
    };
    let input_base = 1;
    let output_base = 1;
    let cases = [
        (
            BinaryMarketState::ResolvedYes {
                collateral_unredeemed: 600,
            },
            BinaryMarketAction::Redeem {
                outcome: BinaryOutcome::Yes,
                tokens: 1,
            },
            BinaryMarketSlot::ResolvedYesCollateral,
            BinaryMarketCoordinatorRole::ResolvedNoCollateral,
        ),
        (
            BinaryMarketState::ResolvedNo {
                collateral_unredeemed: 600,
            },
            BinaryMarketAction::Redeem {
                outcome: BinaryOutcome::No,
                tokens: 1,
            },
            BinaryMarketSlot::ResolvedNoCollateral,
            BinaryMarketCoordinatorRole::ResolvedYesCollateral,
        ),
        (
            BinaryMarketState::Expired {
                collateral_unredeemed: 300,
            },
            BinaryMarketAction::Redeem {
                outcome: BinaryOutcome::Yes,
                tokens: 1,
            },
            BinaryMarketSlot::ExpiredCollateral,
            BinaryMarketCoordinatorRole::ResolvedYesCollateral,
        ),
    ];
    for (before, action, slot, wrong_coordinator) in cases {
        let (_plan, _attestation, pset) = finalized_market_fixture(
            &compiled,
            before,
            action,
            RtSide::A,
            input_base,
            output_base,
        );
        let wrong_layout = BinaryMarketLayout::for_operation(
            wrong_coordinator,
            BinaryMarketOperation::Redeem,
            None,
        )
        .expect("alternate terminal redemption layout");
        let witness = BinaryMarketWitness::for_slot(
            wrong_layout,
            wrong_coordinator.slot(),
            BinaryMarketCoordinatorAction::Redeem {
                output_base: u32::try_from(output_base).expect("output index fits u32"),
            },
        )
        .expect("alternate terminal coordinator witness");
        assert!(
            compiled
                .execute(slot, &pset, &witness.build_witness(), input_base, &network,)
                .is_err(),
            "{slot:?} accepted a false SLOT witness"
        );
    }
}

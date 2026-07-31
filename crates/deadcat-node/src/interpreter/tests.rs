use deadcat_client::market_builder::{
    BinaryMarketLiveInputs, BinaryMarketTransitionPlan, MarketIssuanceEntropies, MarketRtInput,
};
use deadcat_contracts::SimplicityNetwork;
use deadcat_contracts::binary_market::{
    BinaryMarketAction, BinaryMarketSlot, CompiledBinaryMarket,
};
use deadcat_contracts::market_crypto::derive_issuance_assets;
use deadcat_contracts::recovery::{MarketCollateral, MarketRecoveryHint, recovery_txout};
use deadcat_contracts::rt::{RtLeg, RtSide, commitments, factors};
use deadcat_types::{
    BinaryMarketParams, BinaryMarketState, ChainAnchor, ChainPosition, ContractSyncState,
};
use elements::confidential::{Nonce, Value};
use elements::hashes::Hash as _;
use elements::pset::{Input as PsetInput, Output as PsetOutput, PartiallySignedTransaction};
use elements::secp256k1_zkp::ZERO_TWEAK;
use elements::{
    AssetIssuance, BlockHash, LockTime, OutPoint, Transaction, TxIn, TxOut, TxOutWitness, Txid,
};
use tempfile::TempDir;

use super::*;
use crate::registration::verify_binary_market_creation;
use crate::store::{
    BlockDelta, ChainTxDelta, ContractRecord, ContractState, RegistrationEvidence, Store,
};

const VALID_XONLY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

fn asset(byte: u8) -> AssetId {
    AssetId::from_slice(&[byte; 32]).expect("asset")
}

fn anchor(height: u32, byte: u8) -> ChainAnchor {
    ChainAnchor {
        height,
        hash: BlockHash::from_byte_array([byte; 32]),
    }
}

fn empty_store() -> (TempDir, Store) {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = Store::open(directory.path().join("deadcat.redb")).expect("store");
    store.initialize_tip(anchor(0, 0x01)).expect("baseline tip");
    (directory, store)
}

fn prior_creation(
    transaction: Transaction,
    records: Vec<ContractRecord>,
    position: ChainPosition,
    block_hash: BlockHash,
) -> ChainTxDelta {
    ChainTxDelta {
        position,
        block_hash,
        txid: transaction.txid(),
        raw_tx: transaction,
        created_contracts: records,
        state_updates: Vec::new(),
    }
}

fn cancellation(outpoints: impl IntoIterator<Item = OutPoint>) -> Transaction {
    Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: outpoints
            .into_iter()
            .map(|outpoint| TxIn {
                previous_output: outpoint,
                ..TxIn::default()
            })
            .collect(),
        output: Vec::new(),
    }
}

fn issuance_input(byte: u8, vout: u32) -> TxIn {
    TxIn {
        previous_output: OutPoint::new(Txid::from_byte_array([byte; 32]), vout),
        asset_issuance: AssetIssuance {
            asset_blinding_nonce: ZERO_TWEAK,
            asset_entropy: [0; 32],
            amount: Value::Null,
            inflation_keys: Value::Explicit(1),
        },
        ..TxIn::default()
    }
}

fn standalone_market_with_seeds(
    policy_asset: AssetId,
    yes_seed: u8,
    no_seed: u8,
) -> (Transaction, BinaryMarketParams) {
    let yes_input = issuance_input(yes_seed, 3);
    let no_input = issuance_input(no_seed, 4);
    let ids = derive_issuance_assets(yes_input.previous_output, no_input.previous_output);
    let params = BinaryMarketParams {
        oracle_public_key: VALID_XONLY,
        collateral_asset_id: policy_asset,
        yes_token_asset_id: ids.yes_token,
        no_token_asset_id: ids.no_token,
        yes_reissuance_token_id: ids.yes_reissuance_token,
        no_reissuance_token_id: ids.no_reissuance_token,
        base_payout: 1_000,
        expiry_height: 50_000,
    };
    let compiled = CompiledBinaryMarket::new(params).expect("compile market");
    let yes_commitments = commitments(
        params.yes_reissuance_token_id,
        factors(RtLeg::Yes, RtSide::A),
    )
    .expect("YES commitments");
    let no_commitments = commitments(params.no_reissuance_token_id, factors(RtLeg::No, RtSide::A))
        .expect("NO commitments");
    let hint = MarketRecoveryHint {
        oracle_public_key: params.oracle_public_key,
        collateral: MarketCollateral::PolicyAsset,
        base_payout: params.base_payout,
        expiry_height: params.expiry_height,
    }
    .encode()
    .expect("hint");
    let transaction = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![yes_input, no_input],
        output: vec![
            TxOut {
                asset: yes_commitments.0,
                value: yes_commitments.1,
                nonce: Nonce::Null,
                script_pubkey: compiled
                    .slot(BinaryMarketSlot::DormantYesRt)
                    .script_pubkey()
                    .clone(),
                witness: TxOutWitness::default(),
            },
            TxOut {
                asset: no_commitments.0,
                value: no_commitments.1,
                nonce: Nonce::Null,
                script_pubkey: compiled
                    .slot(BinaryMarketSlot::DormantNoRt)
                    .script_pubkey()
                    .clone(),
                witness: TxOutWitness::default(),
            },
            recovery_txout(policy_asset, &hint).expect("hint output"),
        ],
    };
    (transaction, params)
}

fn standalone_market_with_params(policy_asset: AssetId) -> (Transaction, BinaryMarketParams) {
    standalone_market_with_seeds(policy_asset, 0x41, 0x42)
}

fn standalone_market(policy_asset: AssetId) -> Transaction {
    standalone_market_with_params(policy_asset).0
}

#[derive(Clone)]
struct MarketFixture {
    creation: Transaction,
    params: BinaryMarketParams,
    record: ContractRecord,
    entropies: MarketIssuanceEntropies,
}

fn market_fixture(
    policy_asset: AssetId,
    seed: u8,
    position: ChainPosition,
    synced_through: ChainAnchor,
) -> MarketFixture {
    let (creation, params) =
        standalone_market_with_seeds(policy_asset, seed, seed.checked_add(1).expect("seed"));
    let entropies = MarketIssuanceEntropies::from_defining_outpoints(
        params,
        creation.input[0].previous_output,
        creation.input[1].previous_output,
    )
    .expect("market entropies");
    let mut record = verify_binary_market_creation(
        &creation,
        position,
        synced_through,
        LiquidNetwork::ElementsRegtest,
        policy_asset,
        Some(params),
        None,
    )
    .expect("verify market fixture")
    .record;
    record.sync_state = ContractSyncState::Ready { synced_through };
    MarketFixture {
        creation,
        params,
        record,
        entropies,
    }
}

fn market_rt_input(
    record: &ContractRecord,
    transaction: &Transaction,
    roles: &[BinaryMarketSlot],
) -> Option<MarketRtInput> {
    record
        .outpoints
        .iter()
        .find(|tracked| roles.iter().any(|slot| tracked.role == *slot as u8))
        .map(|tracked| MarketRtInput {
            outpoint: tracked.outpoint,
            txout: transaction.output[tracked.outpoint.vout as usize].clone(),
        })
}

fn market_live_inputs(
    record: &ContractRecord,
    transaction: &Transaction,
) -> BinaryMarketLiveInputs {
    let yes_rt = market_rt_input(
        record,
        transaction,
        &[
            BinaryMarketSlot::DormantYesRt,
            BinaryMarketSlot::UnresolvedYesRt,
        ],
    );
    let no_rt = market_rt_input(
        record,
        transaction,
        &[
            BinaryMarketSlot::DormantNoRt,
            BinaryMarketSlot::UnresolvedNoRt,
        ],
    );
    let collateral = record
        .outpoints
        .iter()
        .find(|tracked| {
            [
                BinaryMarketSlot::UnresolvedCollateral,
                BinaryMarketSlot::ResolvedYesCollateral,
                BinaryMarketSlot::ResolvedNoCollateral,
                BinaryMarketSlot::ExpiredCollateral,
            ]
            .iter()
            .any(|slot| tracked.role == *slot as u8)
        })
        .map(|tracked| tracked.outpoint);
    BinaryMarketLiveInputs {
        yes_rt,
        no_rt,
        collateral,
    }
}

fn pset_input(outpoint: OutPoint, witness_utxo: TxOut) -> PsetInput {
    let mut input = PsetInput::from_prevout(outpoint);
    input.witness_utxo = Some(witness_utxo);
    input
}

struct MarketIssuance<'a> {
    record: &'a ContractRecord,
    source_transaction: &'a Transaction,
    params: BinaryMarketParams,
    entropies: MarketIssuanceEntropies,
    pairs: u64,
}

fn composed_market_issuance(
    policy_asset: AssetId,
    issuances: &[MarketIssuance<'_>],
) -> Transaction {
    struct PendingPlan {
        plan: BinaryMarketTransitionPlan,
        input_base: usize,
        output_base: usize,
        entropies: MarketIssuanceEntropies,
    }

    let mut pset = PartiallySignedTransaction::new_v2();
    let mut pending = Vec::with_capacity(issuances.len());
    for issuance in issuances {
        let ContractState::BinaryMarket(before) = issuance.record.state;
        let live = market_live_inputs(issuance.record, issuance.source_transaction);
        let plan = BinaryMarketTransitionPlan::new(
            issuance.params,
            before,
            BinaryMarketAction::Issue {
                pairs: issuance.pairs,
            },
            live.clone(),
            None,
        )
        .expect("market issuance plan");
        let input_base = pset.inputs().len();
        let yes = live.yes_rt.as_ref().expect("YES RT");
        let no = live.no_rt.as_ref().expect("NO RT");
        pset.add_input(pset_input(yes.outpoint, yes.txout.clone()));
        pset.add_input(pset_input(no.outpoint, no.txout.clone()));
        if let Some(collateral) = live.collateral {
            let tracked = issuance
                .record
                .outpoints
                .iter()
                .find(|tracked| tracked.outpoint == collateral)
                .expect("tracked collateral");
            pset.add_input(pset_input(
                collateral,
                issuance.source_transaction.output[tracked.outpoint.vout as usize].clone(),
            ));
        }
        let output_base = pset.outputs().len();
        for (_, output) in plan
            .mandatory_outputs(output_base)
            .expect("mandatory market outputs")
        {
            pset.add_output(PsetOutput::from_txout(output));
        }
        pending.push(PendingPlan {
            plan,
            input_base,
            output_base,
            entropies: issuance.entropies,
        });
    }

    for pending in &pending {
        pending
            .plan
            .configure_reissuance_inputs(&mut pset, pending.input_base, pending.entropies)
            .expect("configure market reissuance");
    }
    let network = SimplicityNetwork::ElementsRegtest { policy_asset };
    for pending in &pending {
        pending
            .plan
            .finalize(&mut pset, pending.input_base, pending.output_base, &network)
            .expect("finalize market issuance");
    }
    pset.extract_tx().expect("extract market issuance")
}

fn record_after_update(record: &ContractRecord, update: &StateUpdate) -> ContractRecord {
    assert_eq!(record.contract_id, update.contract_id);
    assert_eq!(record.state, update.old_state);
    let mut updated = record.clone();
    updated.state = update.new_state;
    updated.outpoints.clone_from(&update.new_outpoints);
    updated
}

#[test]
fn market_only_multi_contract_batch_is_atomic_and_fails_closed() {
    let (_directory, store) = empty_store();
    let policy = asset(0xaa);
    let block = anchor(8, 0x82);
    let first_position = ChainPosition {
        block_height: 8,
        tx_index: 0,
    };
    let second_position = ChainPosition {
        block_height: 8,
        tx_index: 1,
    };
    let first = market_fixture(policy, 0x51, first_position, block);
    let second = market_fixture(policy, 0x61, second_position, block);
    let prior = vec![
        prior_creation(
            first.creation.clone(),
            vec![first.record.clone()],
            first_position,
            block.hash,
        ),
        prior_creation(
            second.creation.clone(),
            vec![second.record.clone()],
            second_position,
            block.hash,
        ),
    ];
    let spend = composed_market_issuance(
        policy,
        &[
            MarketIssuance {
                record: &first.record,
                source_transaction: &first.creation,
                params: first.params,
                entropies: first.entropies,
                pairs: 2,
            },
            MarketIssuance {
                record: &second.record,
                source_transaction: &second.creation,
                params: second.params,
                entropies: second.entropies,
                pairs: 3,
            },
        ],
    );
    let interpreter = DeadcatInterpreter::new(LiquidNetwork::ElementsRegtest, policy);
    let context = InterpretationContext {
        store: &store,
        anchor: block,
        position: ChainPosition {
            block_height: 8,
            tx_index: 2,
        },
        prior_transactions: &prior,
        retained_declarations: &[],
        mode: InterpretationMode::Canonical,
    };

    let interpreted = interpreter
        .interpret_transaction(&context, &spend)
        .expect("both market issuances");
    assert_eq!(interpreted.state_updates.len(), 2);
    assert_eq!(
        interpreted.state_updates[0].new_state,
        ContractState::BinaryMarket(BinaryMarketState::Trading {
            outstanding_pairs: 2,
        })
    );
    assert_eq!(
        interpreted.state_updates[1].new_state,
        ContractState::BinaryMarket(BinaryMarketState::Trading {
            outstanding_pairs: 3,
        })
    );

    // The second market begins at input 2. Invalidating any one covenant
    // witness must reject the transaction instead of returning the valid first
    // market update as a partial batch.
    let mut invalid = spend;
    invalid.input[2].witness.script_witness.clear();
    assert!(
        interpreter
            .interpret_transaction(&context, &invalid)
            .is_err()
    );
}

#[test]
fn market_only_same_block_overlay_uses_latest_state_and_transaction_output() {
    let (_directory, store) = empty_store();
    let policy = asset(0xaa);
    let block = anchor(9, 0x92);
    let creation_position = ChainPosition {
        block_height: 9,
        tx_index: 0,
    };
    let fixture = market_fixture(policy, 0x71, creation_position, block);
    let creation_delta = prior_creation(
        fixture.creation.clone(),
        vec![fixture.record.clone()],
        creation_position,
        block.hash,
    );
    let first_spend = composed_market_issuance(
        policy,
        &[MarketIssuance {
            record: &fixture.record,
            source_transaction: &fixture.creation,
            params: fixture.params,
            entropies: fixture.entropies,
            pairs: 2,
        }],
    );
    let interpreter = DeadcatInterpreter::new(LiquidNetwork::ElementsRegtest, policy);
    let first_prior = [creation_delta.clone()];
    let first_context = InterpretationContext {
        store: &store,
        anchor: block,
        position: ChainPosition {
            block_height: 9,
            tx_index: 1,
        },
        prior_transactions: &first_prior,
        retained_declarations: &[],
        mode: InterpretationMode::Canonical,
    };
    let first_interpreted = interpreter
        .interpret_transaction(&first_context, &first_spend)
        .expect("initial market issuance");
    let first_update = first_interpreted.state_updates[0].clone();
    let updated_record = record_after_update(&fixture.record, &first_update);
    let second_spend = composed_market_issuance(
        policy,
        &[MarketIssuance {
            record: &updated_record,
            source_transaction: &first_spend,
            params: fixture.params,
            entropies: fixture.entropies,
            pairs: 1,
        }],
    );
    let prior = vec![
        creation_delta,
        ChainTxDelta {
            position: ChainPosition {
                block_height: 9,
                tx_index: 1,
            },
            block_hash: block.hash,
            txid: first_spend.txid(),
            raw_tx: first_spend,
            created_contracts: Vec::new(),
            state_updates: vec![first_update],
        },
    ];
    let context = InterpretationContext {
        store: &store,
        anchor: block,
        position: ChainPosition {
            block_height: 9,
            tx_index: 2,
        },
        prior_transactions: &prior,
        retained_declarations: &[],
        mode: InterpretationMode::Canonical,
    };

    let interpreted = interpreter
        .interpret_transaction(&context, &second_spend)
        .expect("same-block subsequent issuance");
    assert_eq!(interpreted.state_updates.len(), 1);
    assert_eq!(
        interpreted.state_updates[0].old_state,
        ContractState::BinaryMarket(BinaryMarketState::Trading {
            outstanding_pairs: 2,
        })
    );
    assert_eq!(
        interpreted.state_updates[0].new_state,
        ContractState::BinaryMarket(BinaryMarketState::Trading {
            outstanding_pairs: 3,
        })
    );
    assert!(
        interpreted.state_updates[0]
            .new_outpoints
            .iter()
            .all(|tracked| tracked.outpoint.txid == second_spend.txid())
    );
}

#[test]
fn market_only_backfill_filters_non_targets_and_materializes_stored_outputs() {
    let (directory, store) = empty_store();
    let policy = asset(0xaa);
    let baseline = anchor(0, 0x01);
    let current = anchor(1, 0x04);
    let first_position = ChainPosition {
        block_height: 1,
        tx_index: 0,
    };
    let second_position = ChainPosition {
        block_height: 1,
        tx_index: 1,
    };
    let first = market_fixture(policy, 0x81, first_position, current);
    let second = market_fixture(policy, 0x91, second_position, current);
    store
        .apply_block(&BlockDelta {
            anchor: current,
            prev_block_hash: baseline.hash,
            ordered_txids: vec![first.creation.txid(), second.creation.txid()],
            relevant_transactions: vec![
                prior_creation(
                    first.creation.clone(),
                    vec![first.record.clone()],
                    first_position,
                    current.hash,
                ),
                prior_creation(
                    second.creation.clone(),
                    vec![second.record.clone()],
                    second_position,
                    current.hash,
                ),
            ],
            recovery_hints: Vec::new(),
        })
        .expect("seed market creations");
    let spend = composed_market_issuance(
        policy,
        &[
            MarketIssuance {
                record: &first.record,
                source_transaction: &first.creation,
                params: first.params,
                entropies: first.entropies,
                pairs: 2,
            },
            MarketIssuance {
                record: &second.record,
                source_transaction: &second.creation,
                params: second.params,
                entropies: second.entropies,
                pairs: 3,
            },
        ],
    );
    let targets = [first.record.contract_id];
    let context = InterpretationContext {
        store: &store,
        anchor: anchor(2, 0x05),
        position: ChainPosition {
            block_height: 2,
            tx_index: 0,
        },
        prior_transactions: &[],
        retained_declarations: &[],
        mode: InterpretationMode::Backfill {
            contract_ids: &targets,
        },
    };

    let interpreted = DeadcatInterpreter::new(LiquidNetwork::ElementsRegtest, policy)
        .interpret_transaction(&context, &spend)
        .expect("targeted market backfill");
    assert_eq!(interpreted.state_updates.len(), 1);
    assert_eq!(
        interpreted.state_updates[0].contract_id,
        first.record.contract_id
    );
    assert_eq!(
        interpreted.state_updates[0].new_state,
        ContractState::BinaryMarket(BinaryMarketState::Trading {
            outstanding_pairs: 2,
        })
    );
    drop(store);
    drop(directory);
}

#[test]
fn market_only_prior_spends_and_invalid_witnesses_fail_closed() {
    let (_directory, store) = empty_store();
    let policy = asset(0xaa);
    let block = anchor(15, 0xd2);
    let creation_position = ChainPosition {
        block_height: 15,
        tx_index: 0,
    };
    let fixture = market_fixture(policy, 0xa1, creation_position, block);
    let creation_delta = prior_creation(
        fixture.creation.clone(),
        vec![fixture.record.clone()],
        creation_position,
        block.hash,
    );
    let first_spend = composed_market_issuance(
        policy,
        &[MarketIssuance {
            record: &fixture.record,
            source_transaction: &fixture.creation,
            params: fixture.params,
            entropies: fixture.entropies,
            pairs: 2,
        }],
    );
    let interpreter = DeadcatInterpreter::new(LiquidNetwork::ElementsRegtest, policy);
    let creation_prior = [creation_delta.clone()];
    let initial_context = InterpretationContext {
        store: &store,
        anchor: block,
        position: ChainPosition {
            block_height: 15,
            tx_index: 1,
        },
        prior_transactions: &creation_prior,
        retained_declarations: &[],
        mode: InterpretationMode::Canonical,
    };
    let first_update = interpreter
        .interpret_transaction(&initial_context, &first_spend)
        .expect("initial issuance")
        .state_updates
        .into_iter()
        .next()
        .expect("market update");
    let prior = vec![
        creation_delta,
        ChainTxDelta {
            position: ChainPosition {
                block_height: 15,
                tx_index: 1,
            },
            block_hash: block.hash,
            txid: first_spend.txid(),
            raw_tx: first_spend.clone(),
            created_contracts: Vec::new(),
            state_updates: vec![first_update],
        },
    ];
    let context = InterpretationContext {
        store: &store,
        anchor: block,
        position: ChainPosition {
            block_height: 15,
            tx_index: 2,
        },
        prior_transactions: &prior,
        retained_declarations: &[],
        mode: InterpretationMode::Canonical,
    };
    assert!(matches!(
        interpreter.interpret_transaction(&context, &first_spend),
        Err(NodeInterpretError::SameBlockDoubleSpend { .. })
    ));

    let fresh_prior = &prior[..1];
    let fresh_context = InterpretationContext {
        prior_transactions: fresh_prior,
        ..context
    };
    let mut invalid = first_spend;
    invalid.input[0].witness.script_witness.clear();
    assert!(
        interpreter
            .interpret_transaction(&fresh_context, &invalid)
            .is_err()
    );
}

#[test]
fn canonical_hint_creates_ready_market_but_composed_shape_is_registration_only() {
    let (_directory, store) = empty_store();
    let policy = asset(0xa1);
    let interpreter = DeadcatInterpreter::new(LiquidNetwork::ElementsRegtest, policy);
    let current = anchor(12, 0xc1);
    let context = InterpretationContext {
        store: &store,
        anchor: current,
        position: ChainPosition {
            block_height: 12,
            tx_index: 4,
        },
        prior_transactions: &[],
        retained_declarations: &[],
        mode: InterpretationMode::Canonical,
    };
    let transaction = standalone_market(policy);

    let interpreted = interpreter
        .interpret_transaction(&context, &transaction)
        .expect("discover market");
    assert_eq!(interpreted.created_contracts.len(), 1);
    assert_eq!(interpreted.recovery_hints.len(), 1);
    assert_eq!(
        interpreted.created_contracts[0].sync_state,
        ContractSyncState::Ready {
            synced_through: current
        }
    );
    assert_eq!(
        interpreted.recovery_hints[0].associated_contract,
        Some(interpreted.created_contracts[0].contract_id)
    );
    let discovered = interpreted.created_contracts[0].clone();
    let creation_delta = prior_creation(
        transaction.clone(),
        vec![discovered.clone()],
        context.position,
        current.hash,
    );
    let prior = [creation_delta];
    let spend_context = InterpretationContext {
        store: &store,
        anchor: current,
        position: ChainPosition {
            block_height: 12,
            tx_index: 5,
        },
        prior_transactions: &prior,
        retained_declarations: &[],
        mode: InterpretationMode::Canonical,
    };
    // Spending only the secondary RT leg still touches the market. The
    // interpreter must not overlook it merely because the primary leg is
    // absent from the transaction.
    assert!(
        interpreter
            .interpret_transaction(
                &spend_context,
                &cancellation([discovered.outpoints[1].outpoint])
            )
            .is_err()
    );

    let mut composed = transaction;
    composed.output.swap(0, 1);
    let interpreted = interpreter
        .interpret_transaction(&context, &composed)
        .expect("retain valid hint");
    assert!(interpreted.created_contracts.is_empty());
    assert_eq!(interpreted.recovery_hints.len(), 1);
    assert!(interpreted.recovery_hints[0].associated_contract.is_none());
}

#[test]
fn destructive_replay_revalidates_two_retained_markets() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = Store::open(directory.path().join("deadcat.redb")).expect("store");
    let genesis = anchor(0, 0x01);
    let policy = asset(0xa3);
    store
        .initialize_chain(
            crate::store::ChainIdentity {
                network: LiquidNetwork::ElementsRegtest,
                genesis_hash: genesis.hash,
                policy_asset: policy,
            },
            genesis,
        )
        .expect("initialize chain");

    let (mut creation, first_params) = standalone_market_with_seeds(policy, 0xb1, 0xb2);
    let (second_creation, second_params) = standalone_market_with_seeds(policy, 0xc1, 0xc2);
    creation.input.extend(second_creation.input);
    creation.output.extend(second_creation.output);
    // Two complete market declarations and their two hints share one
    // transaction. This is intentionally outside the fixed standalone
    // discovery shape, so retained parameters must recover both markets.
    let old_anchor = anchor(1, 0x03);
    let old_position = ChainPosition {
        block_height: 1,
        tx_index: 0,
    };
    store
        .apply_block(&BlockDelta {
            anchor: old_anchor,
            prev_block_hash: genesis.hash,
            ordered_txids: vec![creation.txid()],
            relevant_transactions: Vec::new(),
            recovery_hints: Vec::new(),
        })
        .expect("index original creation block");
    let first_market_id = ContractId::new(OutPoint::new(creation.txid(), 0));
    let second_market_id = ContractId::new(OutPoint::new(creation.txid(), 3));
    let first_market = verify_binary_market_creation(
        &creation,
        old_position,
        old_anchor,
        LiquidNetwork::ElementsRegtest,
        policy,
        Some(first_params),
        Some(first_market_id),
    )
    .expect("verify first composed market");
    let second_market = verify_binary_market_creation(
        &creation,
        old_position,
        old_anchor,
        LiquidNetwork::ElementsRegtest,
        policy,
        Some(second_params),
        Some(second_market_id),
    )
    .expect("verify second composed market");
    let shared_creation = Arc::new(creation.clone());
    store
        .register_contracts(&[
            (
                first_market.record,
                RegistrationEvidence {
                    anchor: old_anchor,
                    transaction: Arc::clone(&shared_creation),
                    associated_hint: None,
                },
            ),
            (
                second_market.record,
                RegistrationEvidence {
                    anchor: old_anchor,
                    transaction: shared_creation,
                    associated_hint: None,
                },
            ),
        ])
        .expect("retain composed market declarations");
    let retained = store
        .retained_declarations_for_txid(creation.txid())
        .expect("retained declarations");
    assert_eq!(
        retained
            .iter()
            .map(|declaration| declaration.contract_id)
            .collect::<Vec<_>>(),
        vec![first_market_id, second_market_id]
    );
    let assert_shared_evidence =
        |store: &Store, position: ChainPosition, expected_sync: ContractSyncState| {
            for contract_id in [first_market_id, second_market_id] {
                let record = store
                    .contract(contract_id)
                    .expect("market lookup")
                    .expect("replayed market");
                assert_eq!(record.creation_position, position);
                assert_eq!(record.sync_state, expected_sync);
            }
            let stored = store
                .transaction(position)
                .expect("creation transaction lookup")
                .expect("shared creation transaction");
            assert_eq!(stored.txid, creation.txid());
            assert_eq!(stored.raw_tx, elements::encode::serialize(&creation));
            assert_eq!(
                stored.affected_contract_ids,
                vec![first_market_id, second_market_id]
            );
            for vout in [0, 1, 3, 4] {
                assert_eq!(
                    store
                        .output(OutPoint::new(creation.txid(), vout))
                        .expect("creation output lookup")
                        .expect("shared creation output")
                        .output,
                    creation.output[vout as usize]
                );
            }
        };
    assert_shared_evidence(
        &store,
        old_position,
        ContractSyncState::CatchingUp {
            synced_through: old_anchor,
        },
    );

    store.invalidate_for_rebuild().expect("invalidate");
    store.reset_for_rebuild().expect("activation rebuild reset");
    let replacement_one = anchor(1, 0x13);
    let unrelated = Transaction {
        version: 2,
        lock_time: LockTime::from_consensus(0x13),
        input: Vec::new(),
        output: vec![TxOut::new_fee(1, policy)],
    };
    store
        .apply_block(&BlockDelta {
            anchor: replacement_one,
            prev_block_hash: genesis.hash,
            ordered_txids: vec![unrelated.txid()],
            relevant_transactions: Vec::new(),
            recovery_hints: Vec::new(),
        })
        .expect("replacement block one");

    let replacement_two = anchor(2, 0x23);
    let new_position = ChainPosition {
        block_height: 2,
        tx_index: 0,
    };
    let interpreter = DeadcatInterpreter::new(LiquidNetwork::ElementsRegtest, policy);
    let without_declaration = interpreter
        .interpret_transaction(
            &InterpretationContext {
                store: &store,
                anchor: replacement_two,
                position: new_position,
                prior_transactions: &[],
                retained_declarations: &[],
                mode: InterpretationMode::Canonical,
            },
            &creation,
        )
        .expect("composed shape remains registration-only");
    assert!(without_declaration.created_contracts.is_empty());

    let retained = store
        .retained_declarations_for_txid(creation.txid())
        .expect("retained declarations for replay");
    let interpreted = interpreter
        .interpret_transaction(
            &InterpretationContext {
                store: &store,
                anchor: replacement_two,
                position: new_position,
                prior_transactions: &[],
                retained_declarations: &retained,
                mode: InterpretationMode::Canonical,
            },
            &creation,
        )
        .expect("revalidate retained markets");
    assert_eq!(
        interpreted
            .created_contracts
            .iter()
            .map(|record| (record.contract_id, record.creation_position))
            .collect::<Vec<_>>(),
        vec![
            (first_market_id, new_position),
            (second_market_id, new_position),
        ]
    );

    store
        .apply_block(&BlockDelta {
            anchor: replacement_two,
            prev_block_hash: replacement_one.hash,
            ordered_txids: vec![creation.txid()],
            relevant_transactions: vec![prior_creation(
                creation.clone(),
                interpreted.created_contracts,
                new_position,
                replacement_two.hash,
            )],
            recovery_hints: Vec::new(),
        })
        .expect("materialize replayed markets");
    assert_shared_evidence(
        &store,
        new_position,
        ContractSyncState::Ready {
            synced_through: replacement_two,
        },
    );
    drop(store);
    let reopened = Store::open(directory.path().join("deadcat.redb")).expect("reopen store");
    assert_shared_evidence(
        &reopened,
        new_position,
        ContractSyncState::Ready {
            synced_through: replacement_two,
        },
    );
}

#[test]
fn transition_tags_and_payloads_are_byte_stable() {
    let issued = market_transition_record(
        BinaryMarketPath::SubsequentIssuance,
        BinaryMarketTransition::Issued {
            pairs: 2,
            collateral_locked: 400,
        },
    );
    let mut expected = vec![BinaryMarketPath::SubsequentIssuance as u8];
    expected.extend_from_slice(&2_u64.to_be_bytes());
    expected.extend_from_slice(&400_u64.to_be_bytes());
    assert_eq!(issued.kind, TRANSITION_V1_MARKET_ISSUED);
    assert_eq!(issued.payload, expected);
}

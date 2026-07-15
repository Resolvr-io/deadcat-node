use deadcat_client::market_builder::{
    BinaryMarketCreationPlan, BinaryMarketLiveInputs, BinaryMarketTransitionPlan,
    MarketCreationContext, MarketIssuanceEntropies, MarketRtInput,
};
use deadcat_contracts::SimplicityNetwork;
use deadcat_contracts::binary_market::BinaryMarketAction;
use deadcat_contracts::market_crypto::derive_issuance_assets;
use deadcat_contracts::recovery::{MarketCollateral, MarketRecoveryHint};
use deadcat_contracts::rt::{RtLeg, RtSide, infer_side};
use deadcat_node::interpreter::DeadcatInterpreter;
use deadcat_node::store::{
    BlockDelta, ChainTxDelta, ContractState, RecoveryHintDelta, RollbackResult, Store,
};
use deadcat_node::sync::{
    ChainInterpreter, InterpretationContext, InterpretationMode, TransactionInterpretation,
};
use deadcat_types::{
    BinaryMarketParams, BinaryMarketState, ChainAnchor, ChainPosition, ContractId,
    ContractSyncState, LiquidNetwork, RecoveryHintLocation,
};
use elements::confidential::{Asset, Nonce, Value};
use elements::hashes::Hash as _;
use elements::pset::{Input as PsetInput, Output as PsetOutput, PartiallySignedTransaction};
use elements::secp256k1_zkp::{Keypair, Secp256k1};
use elements::{AssetId, BlockHash, OutPoint, Script, Transaction, TxOut, TxOutWitness, Txid};

fn asset(byte: u8) -> AssetId {
    AssetId::from_slice(&[byte; 32]).expect("asset")
}

fn anchor(height: u32, byte: u8) -> ChainAnchor {
    ChainAnchor {
        height,
        hash: BlockHash::from_byte_array([byte; 32]),
    }
}

fn explicit_txout(asset_id: AssetId, value: u64) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset_id),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey: Script::from(vec![0x51]),
        witness: TxOutWitness::default(),
    }
}

fn pset_input(outpoint: OutPoint, witness_utxo: TxOut) -> PsetInput {
    let mut input = PsetInput::from_prevout(outpoint);
    input.witness_utxo = Some(witness_utxo);
    input
}

fn defining_outpoints(seed: u8) -> (OutPoint, OutPoint) {
    (
        OutPoint::new(Txid::from_byte_array([seed; 32]), 3),
        OutPoint::new(Txid::from_byte_array([seed.wrapping_add(1); 32]), 4),
    )
}

fn market_params(seed: u8, policy_asset: AssetId) -> BinaryMarketParams {
    let (yes, no) = defining_outpoints(seed);
    let ids = derive_issuance_assets(yes, no);
    let oracle = Keypair::from_seckey_slice(&Secp256k1::new(), &[seed.wrapping_add(16); 32])
        .expect("oracle key")
        .x_only_public_key()
        .0
        .serialize();
    BinaryMarketParams {
        oracle_public_key: oracle,
        collateral_asset_id: policy_asset,
        yes_token_asset_id: ids.yes_token,
        no_token_asset_id: ids.no_token,
        yes_reissuance_token_id: ids.yes_reissuance_token,
        no_reissuance_token_id: ids.no_reissuance_token,
        base_payout: 100,
        expiry_height: 50_000,
    }
}

fn recovery_hint(params: BinaryMarketParams) -> MarketRecoveryHint {
    MarketRecoveryHint {
        oracle_public_key: params.oracle_public_key,
        collateral: MarketCollateral::PolicyAsset,
        base_payout: params.base_payout,
        expiry_height: params.expiry_height,
    }
}

fn creation_transaction(
    params: BinaryMarketParams,
    policy_asset: AssetId,
    defining: (OutPoint, OutPoint),
) -> (Transaction, MarketIssuanceEntropies) {
    let plan = BinaryMarketCreationPlan::new(
        MarketCreationContext {
            policy_asset,
            liquid_mainnet_usdt: None,
        },
        params,
        recovery_hint(params),
        defining.0,
        defining.1,
    )
    .expect("creation plan");
    let funding = explicit_txout(policy_asset, 10_000);
    let mut pset = plan
        .build_pset(
            pset_input(defining.0, funding.clone()),
            pset_input(defining.1, funding),
        )
        .expect("creation PSET");
    plan.finalize_rt_proofs(&mut pset)
        .expect("creation RT proofs");
    (
        pset.extract_tx().expect("creation transaction"),
        plan.entropies(),
    )
}

fn live_creation_outputs(creation: &Transaction) -> BinaryMarketLiveInputs {
    BinaryMarketLiveInputs {
        yes_rt: Some(MarketRtInput {
            outpoint: OutPoint::new(creation.txid(), 0),
            txout: creation.output[0].clone(),
        }),
        no_rt: Some(MarketRtInput {
            outpoint: OutPoint::new(creation.txid(), 1),
            txout: creation.output[1].clone(),
        }),
        collateral: None,
    }
}

fn composed_initial_issuance(
    markets: &[(BinaryMarketParams, Transaction, MarketIssuanceEntropies)],
) -> Transaction {
    let network = SimplicityNetwork::ElementsRegtest {
        policy_asset: markets[0].0.collateral_asset_id,
    };
    let plans = markets
        .iter()
        .map(|(params, creation, _)| {
            BinaryMarketTransitionPlan::new(
                *params,
                BinaryMarketState::Trading {
                    outstanding_pairs: 0,
                },
                BinaryMarketAction::Issue { pairs: 2 },
                live_creation_outputs(creation),
                None,
            )
            .expect("initial issuance plan")
        })
        .collect::<Vec<_>>();

    let mut pset = PartiallySignedTransaction::new_v2();
    for (_, creation, _) in markets {
        pset.add_input(pset_input(
            OutPoint::new(creation.txid(), 0),
            creation.output[0].clone(),
        ));
        pset.add_input(pset_input(
            OutPoint::new(creation.txid(), 1),
            creation.output[1].clone(),
        ));
    }
    for plan in &plans {
        for (_, output) in plan
            .mandatory_outputs(pset.outputs().len())
            .expect("mandatory outputs")
        {
            pset.add_output(PsetOutput::from_txout(output));
        }
    }

    for (index, (plan, (_, _, entropies))) in plans.iter().zip(markets).enumerate() {
        plan.configure_reissuance_inputs(&mut pset, index * 2, *entropies)
            .expect("reissuance fields");
    }
    for (index, plan) in plans.iter().enumerate() {
        plan.finalize(&mut pset, index * 2, index * 3, &network)
            .expect("composed covenant finalization");
    }
    pset.extract_tx().expect("composed issuance transaction")
}

fn append_interpretation(
    anchor: ChainAnchor,
    position: ChainPosition,
    transaction: &Transaction,
    interpreted: TransactionInterpretation,
    relevant: &mut Vec<ChainTxDelta>,
    hints: &mut Vec<RecoveryHintDelta>,
) {
    for hint in interpreted.recovery_hints {
        hints.push(RecoveryHintDelta {
            location: RecoveryHintLocation {
                position,
                output_index: hint.output_index,
            },
            creation_txid: transaction.txid(),
            family: hint.family,
            payload: hint.payload,
            associated_contract: hint.associated_contract,
        });
    }
    if interpreted.created_contracts.is_empty() && interpreted.state_updates.is_empty() {
        return;
    }
    relevant.push(ChainTxDelta {
        position,
        block_hash: anchor.hash,
        txid: transaction.txid(),
        raw_tx: transaction.clone(),
        created_contracts: interpreted.created_contracts,
        state_updates: interpreted.state_updates,
    });
}

fn interpret_block(
    store: &Store,
    interpreter: &DeadcatInterpreter,
    anchor: ChainAnchor,
    prev_block_hash: BlockHash,
    transactions: &[Transaction],
) -> BlockDelta {
    let mut relevant = Vec::new();
    let mut hints = Vec::new();
    for (tx_index, transaction) in transactions.iter().enumerate() {
        let position = ChainPosition {
            block_height: anchor.height,
            tx_index: u32::try_from(tx_index).expect("transaction index"),
        };
        let context = InterpretationContext {
            store,
            anchor,
            position,
            prior_transactions: &relevant,
            retained_declarations: &[],
            mode: InterpretationMode::Canonical,
        };
        let interpreted = interpreter
            .interpret_transaction(&context, transaction)
            .expect("valid binary-market transaction");
        append_interpretation(
            anchor,
            position,
            transaction,
            interpreted,
            &mut relevant,
            &mut hints,
        );
    }
    BlockDelta {
        anchor,
        prev_block_hash,
        ordered_txids: transactions.iter().map(Transaction::txid).collect(),
        relevant_transactions: relevant,
        recovery_hints: hints,
    }
}

fn assert_markets_issued(
    store: &Store,
    ids: &[ContractId],
    issuance: &Transaction,
    expected_tip: ChainAnchor,
) {
    for (market_index, contract_id) in ids.iter().copied().enumerate() {
        let record = store
            .contract(contract_id)
            .expect("read market")
            .expect("stored market");
        assert_eq!(
            record.state,
            ContractState::BinaryMarket(BinaryMarketState::Trading {
                outstanding_pairs: 2,
            })
        );
        assert_eq!(
            record.sync_state,
            ContractSyncState::Ready {
                synced_through: expected_tip,
            }
        );
        assert_eq!(record.outpoints.len(), 3);
        let output_base = u32::try_from(market_index * 3).expect("output base");
        let yes = store
            .output(OutPoint::new(issuance.txid(), output_base))
            .expect("read YES output")
            .expect("stored YES output");
        let no = store
            .output(OutPoint::new(issuance.txid(), output_base + 1))
            .expect("read NO output")
            .expect("stored NO output");
        let deadcat_node::store::ContractParameters::BinaryMarket(params) = record.params else {
            unreachable!();
        };
        assert_eq!(
            infer_side(
                RtLeg::Yes,
                params.yes_reissuance_token_id,
                yes.output.asset,
                yes.output.value,
            )
            .expect("infer persisted RT side"),
            RtSide::B,
        );
        assert_eq!(
            infer_side(
                RtLeg::No,
                params.no_reissuance_token_id,
                no.output.asset,
                no.output.value,
            )
            .expect("infer persisted RT side"),
            RtSide::B,
        );
        assert_eq!(
            store
                .contract_history(contract_id)
                .expect("market history")
                .len(),
            1,
        );
    }
    let stored = store
        .transaction(ChainPosition {
            block_height: expected_tip.height,
            tx_index: 0,
        })
        .expect("read composed transaction")
        .expect("stored composed transaction");
    assert_eq!(stored.affected_contract_ids.len(), ids.len());
}

#[test]
fn ab_markets_survive_restart_and_two_block_reorg_then_reapply_atomically() {
    let directory = tempfile::tempdir().expect("tempdir");
    let database = directory.path().join("deadcat.redb");
    let policy_asset = asset(0xa1);
    let interpreter = DeadcatInterpreter::new(LiquidNetwork::ElementsRegtest, policy_asset);
    let genesis = anchor(0, 0x01);
    let original_creation_anchor = anchor(1, 0x11);
    let original_issuance_anchor = anchor(2, 0x12);
    let replacement_creation_anchor = anchor(1, 0x21);
    let replacement_issuance_anchor = anchor(2, 0x22);

    let market_specs = [0x31, 0x51]
        .map(|seed| {
            let params = market_params(seed, policy_asset);
            let (creation, entropies) =
                creation_transaction(params, policy_asset, defining_outpoints(seed));
            (params, creation, entropies)
        })
        .to_vec();
    let creations = market_specs
        .iter()
        .map(|(_, transaction, _)| transaction.clone())
        .collect::<Vec<_>>();
    let issuance = composed_initial_issuance(&market_specs);
    assert_eq!(issuance.input.len(), 4);
    assert_eq!(issuance.output.len(), 6);

    let store = Store::open(&database).expect("open store");
    store.initialize_tip(genesis).expect("initialize tip");
    let creation_block = interpret_block(
        &store,
        &interpreter,
        original_creation_anchor,
        genesis.hash,
        &creations,
    );
    let ids = creation_block.relevant_transactions[0]
        .created_contracts
        .iter()
        .chain(
            creation_block.relevant_transactions[1]
                .created_contracts
                .iter(),
        )
        .map(|record| record.contract_id)
        .collect::<Vec<_>>();
    assert_eq!(ids.len(), 2);
    store.apply_block(&creation_block).expect("creation block");
    let issuance_block = interpret_block(
        &store,
        &interpreter,
        original_issuance_anchor,
        original_creation_anchor.hash,
        std::slice::from_ref(&issuance),
    );
    assert_eq!(
        issuance_block.relevant_transactions[0].state_updates.len(),
        2,
    );
    store.apply_block(&issuance_block).expect("issuance block");
    assert_markets_issued(&store, &ids, &issuance, original_issuance_anchor);
    drop(store);

    let reopened = Store::open(&database).expect("reopen store");
    assert_eq!(
        reopened.tip().expect("reopened tip"),
        Some(original_issuance_anchor),
    );
    assert_markets_issued(&reopened, &ids, &issuance, original_issuance_anchor);

    let one_block = reopened
        .rollback_to(original_creation_anchor)
        .expect("one-block rollback");
    let RollbackResult::RolledBack {
        old_tip,
        new_tip,
        orphaned_positions,
        ..
    } = one_block
    else {
        panic!("expected retained one-block rollback");
    };
    assert_eq!(old_tip, original_issuance_anchor);
    assert_eq!(new_tip, original_creation_anchor);
    assert_eq!(orphaned_positions.len(), 1);
    for contract_id in &ids {
        let record = reopened
            .contract(*contract_id)
            .expect("read rolled-back market")
            .expect("creation remains after one-block rollback");
        assert_eq!(
            record.state,
            ContractState::BinaryMarket(BinaryMarketState::Trading {
                outstanding_pairs: 0,
            })
        );
        assert_eq!(
            reopened
                .contract_history(*contract_id)
                .expect("rolled-back market history")
                .len(),
            0,
        );
    }
    reopened
        .apply_block(&issuance_block)
        .expect("reapply original issuance block");
    assert_markets_issued(&reopened, &ids, &issuance, original_issuance_anchor);

    let rollback = reopened.rollback_to(genesis).expect("two-block rollback");
    let RollbackResult::RolledBack {
        old_tip,
        new_tip,
        orphaned_positions,
        ..
    } = rollback
    else {
        panic!("expected retained two-block rollback");
    };
    assert_eq!(old_tip, original_issuance_anchor);
    assert_eq!(new_tip, genesis);
    assert_eq!(orphaned_positions.len(), 3);
    assert_eq!(reopened.tip().expect("rolled-back tip"), Some(genesis));
    for contract_id in &ids {
        assert!(
            reopened
                .contract(*contract_id)
                .expect("rolled-back contract lookup")
                .is_none()
        );
    }

    let replacement_creation = interpret_block(
        &reopened,
        &interpreter,
        replacement_creation_anchor,
        genesis.hash,
        &creations,
    );
    reopened
        .apply_block(&replacement_creation)
        .expect("replacement creation block");
    let replacement_issuance = interpret_block(
        &reopened,
        &interpreter,
        replacement_issuance_anchor,
        replacement_creation_anchor.hash,
        std::slice::from_ref(&issuance),
    );
    assert_eq!(
        replacement_issuance.relevant_transactions[0]
            .state_updates
            .len(),
        2,
    );
    reopened
        .apply_block(&replacement_issuance)
        .expect("replacement issuance block");
    assert_markets_issued(&reopened, &ids, &issuance, replacement_issuance_anchor);
    assert_eq!(
        reopened.tip().expect("replacement tip"),
        Some(replacement_issuance_anchor),
    );
}

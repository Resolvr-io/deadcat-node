use deadcat_contracts::binary_market::{BinaryMarketSlot, CompiledBinaryMarket};
use deadcat_contracts::maker_order::CompiledMakerOrder;
use deadcat_contracts::market_crypto::derive_issuance_assets;
use deadcat_contracts::recovery::{MarketCollateral, MarketRecoveryHint, recovery_txout};
use deadcat_contracts::rt::{RtLeg, RtSide, commitments, factors};
use deadcat_types::{
    BinaryMarketParams, ChainAnchor, ChainPosition, ContractSyncState, MakerOrderParams,
    MakerOrderState, OrderDirection, OrderSide,
};
use elements::confidential::{Asset, Nonce, Value};
use elements::hashes::Hash as _;
use elements::secp256k1_zkp::{Keypair, Secp256k1, ZERO_TWEAK};
use elements::{
    AssetIssuance, BlockHash, LockTime, OutPoint, Script, Transaction, TxIn, TxOut, TxOutWitness,
    Txid,
};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

use super::*;
use crate::registration::{verify_binary_market_creation, verify_maker_order_creation};
use crate::store::{
    AssetBinding, AssetRelationKind, BlockDelta, ChainTxDelta, ContractParameters, ContractRecord,
    ContractState, OrderBookEntry, RegistrationEvidence, ScriptBinding, Store, TrackedOutpoint,
    TransitionRecord,
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

fn explicit_txout(asset_id: AssetId, value: u64, script_pubkey: Script) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset_id),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey,
        witness: TxOutWitness::default(),
    }
}

fn key(seed: u8) -> [u8; 32] {
    Keypair::from_seckey_slice(&Secp256k1::new(), &[seed; 32])
        .expect("key")
        .x_only_public_key()
        .0
        .serialize()
}

fn maker_params(seed: u8) -> MakerOrderParams {
    MakerOrderParams {
        base_asset_id: asset(0x11),
        quote_asset_id: asset(0x22),
        price: 7,
        min_active_base: 3,
        direction: OrderDirection::SellBase,
        maker_receive_spk_hash: Sha256::digest([seed]).into(),
        maker_pubkey: key(seed),
    }
}

fn maker_creation(
    params: &[MakerOrderParams],
    position: ChainPosition,
    synced_through: ChainAnchor,
) -> (Transaction, Vec<ContractRecord>) {
    let outputs = params
        .iter()
        .map(|params| {
            let compiled = CompiledMakerOrder::new(*params).expect("compile maker");
            explicit_txout(params.base_asset_id, 10, compiled.script_pubkey().clone())
        })
        .collect();
    let transaction = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: Vec::new(),
        output: outputs,
    };
    let records = params
        .iter()
        .enumerate()
        .map(|(index, params)| {
            let compiled = CompiledMakerOrder::new(*params).expect("compile maker");
            let output_index = u32::try_from(index).expect("vout");
            let contract_id = ContractId::new(OutPoint::new(transaction.txid(), output_index));
            let parent_market =
                ContractId::new(OutPoint::new(Txid::from_byte_array([0x78; 32]), 0));
            ContractRecord {
                contract_id,
                kind: ContractKind::MakerOrderV1,
                params: ContractParameters::MakerOrder(*params),
                creation_position: position,
                state: ContractState::MakerOrder(MakerOrderState::Active {
                    remaining_base: 10,
                    total_filled_base: 0,
                }),
                sync_state: ContractSyncState::Ready { synced_through },
                parent_market: Some(parent_market),
                outcome_side: Some(OrderSide::Yes),
                scripts: vec![ScriptBinding {
                    role: 0,
                    script_pubkey: compiled.script_pubkey().as_bytes().to_vec(),
                }],
                assets: vec![
                    AssetBinding {
                        asset_id: params.base_asset_id,
                        relation: AssetRelationKind::OrderBase,
                        role: 0,
                    },
                    AssetBinding {
                        asset_id: params.quote_asset_id,
                        relation: AssetRelationKind::OrderQuote,
                        role: 1,
                    },
                ],
                outpoints: vec![TrackedOutpoint {
                    role: 0,
                    outpoint: OutPoint::new(transaction.txid(), output_index),
                }],
                order_book: Some(OrderBookEntry {
                    market_id: parent_market,
                    side: OrderSide::Yes,
                    direction: params.direction,
                    price: params.price,
                    creation_position: position,
                    remaining_base: 10,
                }),
            }
        })
        .collect();
    (transaction, records)
}

fn cancellation(outpoints: impl IntoIterator<Item = OutPoint>) -> Transaction {
    let input = outpoints
        .into_iter()
        .map(|outpoint| {
            let mut input = TxIn {
                previous_output: outpoint,
                ..TxIn::default()
            };
            input.witness.script_witness = vec![vec![1; 64]];
            input
        })
        .collect();
    Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input,
        output: Vec::new(),
    }
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

#[test]
fn multi_contract_batch_is_atomic_and_fails_closed() {
    let (_directory, store) = empty_store();
    let block = anchor(8, 0x81);
    let position = ChainPosition {
        block_height: 8,
        tx_index: 0,
    };
    let (creation, records) =
        maker_creation(&[maker_params(0x31), maker_params(0x32)], position, block);
    let prior = vec![prior_creation(
        creation,
        records.clone(),
        position,
        block.hash,
    )];
    let interpreter = DeadcatInterpreter::new(LiquidNetwork::ElementsRegtest, asset(0xaa));
    let spend = cancellation(records.iter().map(|record| record.outpoints[0].outpoint));
    let context = InterpretationContext {
        store: &store,
        anchor: block,
        position: ChainPosition {
            block_height: 8,
            tx_index: 1,
        },
        prior_transactions: &prior,
        retained_declarations: &[],
        mode: InterpretationMode::Canonical,
    };

    let interpreted = interpreter
        .interpret_transaction(&context, &spend)
        .expect("both cancellations");
    assert_eq!(interpreted.state_updates.len(), 2);
    assert!(interpreted.state_updates.iter().all(|update| {
        update.new_state == ContractState::MakerOrder(MakerOrderState::Cancelled)
            && update.transition.kind == TRANSITION_V1_MAKER_CANCELLED
            && update.transition.payload.is_empty()
    }));

    let mut invalid = spend;
    invalid.input[1].witness.script_witness.clear();
    assert!(
        interpreter
            .interpret_transaction(&context, &invalid)
            .is_err()
    );
}

#[test]
fn same_block_overlay_uses_latest_state_and_transaction_output() {
    let (_directory, store) = empty_store();
    let block = anchor(9, 0x91);
    let creation_position = ChainPosition {
        block_height: 9,
        tx_index: 0,
    };
    let params = maker_params(0x33);
    let (creation, records) = maker_creation(&[params], creation_position, block);
    let record = records[0].clone();
    let compiled = CompiledMakerOrder::new(params).expect("compile maker");
    let move_tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: Vec::new(),
        output: vec![explicit_txout(
            params.base_asset_id,
            6,
            compiled.script_pubkey().clone(),
        )],
    };
    let moved = OutPoint::new(move_tx.txid(), 0);
    let prior = vec![
        prior_creation(
            creation,
            vec![record.clone()],
            creation_position,
            block.hash,
        ),
        ChainTxDelta {
            position: ChainPosition {
                block_height: 9,
                tx_index: 1,
            },
            block_hash: block.hash,
            txid: move_tx.txid(),
            raw_tx: move_tx,
            created_contracts: Vec::new(),
            state_updates: vec![StateUpdate {
                contract_id: record.contract_id,
                old_state: record.state,
                new_state: ContractState::MakerOrder(MakerOrderState::Active {
                    remaining_base: 6,
                    total_filled_base: 4,
                }),
                spent_outpoints: vec![record.outpoints[0].outpoint],
                new_outpoints: vec![TrackedOutpoint {
                    role: 0,
                    outpoint: moved,
                }],
                order_remaining_base: Some(6),
                transition: TransitionRecord {
                    kind: TRANSITION_V1_MAKER_FILLED,
                    payload: Vec::new(),
                },
            }],
        },
    ];
    let interpreter = DeadcatInterpreter::new(LiquidNetwork::ElementsRegtest, asset(0xaa));
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
        .interpret_transaction(&context, &cancellation([moved]))
        .expect("overlay cancellation");
    assert_eq!(interpreted.state_updates.len(), 1);
    assert_eq!(
        interpreted.state_updates[0].old_state,
        ContractState::MakerOrder(MakerOrderState::Active {
            remaining_base: 6,
            total_filled_base: 4,
        })
    );
}

fn seed_store_with_orders() -> (TempDir, Store, Vec<ContractRecord>) {
    let (directory, store) = empty_store();
    let baseline = anchor(0, 0x01);
    let current = anchor(1, 0x02);
    store.initialize_tip(baseline).expect("tip");
    let position = ChainPosition {
        block_height: 1,
        tx_index: 0,
    };
    let (creation, records) =
        maker_creation(&[maker_params(0x34), maker_params(0x35)], position, current);
    let creation_txid = creation.txid();
    store
        .apply_block(&BlockDelta {
            anchor: current,
            prev_block_hash: baseline.hash,
            ordered_txids: vec![creation_txid],
            relevant_transactions: vec![prior_creation(
                creation,
                records.clone(),
                position,
                current.hash,
            )],
            recovery_hints: Vec::new(),
        })
        .expect("seed block");
    (directory, store, records)
}

#[test]
fn backfill_filters_non_targets_and_materializes_stored_outputs() {
    let (_directory, store, records) = seed_store_with_orders();
    let target = records[0].contract_id;
    let targets = [target];
    let context = InterpretationContext {
        store: &store,
        anchor: anchor(2, 0x03),
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
    let spend = cancellation(records.iter().map(|record| record.outpoints[0].outpoint));
    let interpreter = DeadcatInterpreter::new(LiquidNetwork::ElementsRegtest, asset(0xaa));

    let interpreted = interpreter
        .interpret_transaction(&context, &spend)
        .expect("targeted backfill");
    assert!(interpreted.created_contracts.is_empty());
    assert!(interpreted.recovery_hints.is_empty());
    assert_eq!(interpreted.state_updates.len(), 1);
    assert_eq!(interpreted.state_updates[0].contract_id, target);
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

fn standalone_market_with_params(policy_asset: AssetId) -> (Transaction, BinaryMarketParams) {
    let yes_input = issuance_input(0x41, 3);
    let no_input = issuance_input(0x42, 4);
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

fn standalone_market(policy_asset: AssetId) -> Transaction {
    standalone_market_with_params(policy_asset).0
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
fn destructive_replay_revalidates_retained_market_and_identical_same_tx_makers() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = Store::open(directory.path().join("deadcat.redb")).expect("store");
    let genesis = anchor(0, 0x01);
    let policy = asset(0xa2);
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

    let (mut creation, market_params) = standalone_market_with_params(policy);
    let order_params = MakerOrderParams {
        base_asset_id: market_params.yes_token_asset_id,
        quote_asset_id: market_params.collateral_asset_id,
        price: 100,
        min_active_base: 10,
        direction: OrderDirection::SellQuote,
        maker_receive_spk_hash: [0x43; 32],
        maker_pubkey: VALID_XONLY,
    };
    let compiled_order = CompiledMakerOrder::new(order_params).expect("compile order");
    let order_output = explicit_txout(
        order_params.quote_asset_id,
        2_000,
        compiled_order.script_pubkey().clone(),
    );
    // Move the canonical YES RT away from vout 0. The complete declaration
    // remains verifiable, but fixed-shape hint discovery alone must not recover
    // this composed market during rebuild.
    creation.output.swap(0, 1);
    creation.output.push(order_output.clone());
    creation.output.push(order_output);

    let old_anchor = anchor(1, 0x02);
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
    let market_id = ContractId::new(OutPoint::new(creation.txid(), 1));
    let first_order_id = ContractId::new(OutPoint::new(creation.txid(), 3));
    let second_order_id = ContractId::new(OutPoint::new(creation.txid(), 4));
    let market = verify_binary_market_creation(
        &creation,
        old_position,
        old_anchor,
        LiquidNetwork::ElementsRegtest,
        policy,
        Some(market_params),
        Some(market_id),
    )
    .expect("verify market");
    let first_order = verify_maker_order_creation(
        &creation,
        old_position,
        old_anchor,
        first_order_id,
        &market.record,
        OrderSide::Yes,
        order_params,
    )
    .expect("verify first order");
    let second_order = verify_maker_order_creation(
        &creation,
        old_position,
        old_anchor,
        second_order_id,
        &market.record,
        OrderSide::Yes,
        order_params,
    )
    .expect("verify second order");
    let shared_creation = Arc::new(creation.clone());
    store
        .register_contracts(&[
            (
                market.record,
                RegistrationEvidence {
                    anchor: old_anchor,
                    transaction: Arc::clone(&shared_creation),
                    associated_hint: None,
                },
            ),
            (
                first_order.record,
                RegistrationEvidence {
                    anchor: old_anchor,
                    transaction: Arc::clone(&shared_creation),
                    associated_hint: None,
                },
            ),
            (
                second_order.record,
                RegistrationEvidence {
                    anchor: old_anchor,
                    transaction: shared_creation,
                    associated_hint: None,
                },
            ),
        ])
        .expect("retain composed declarations");
    assert_eq!(
        store
            .retained_declarations_for_txid(creation.txid())
            .expect("retained declarations")
            .iter()
            .map(|declaration| declaration.contract_id)
            .collect::<Vec<_>>(),
        vec![market_id, first_order_id, second_order_id]
    );

    store.invalidate_for_rebuild().expect("invalidate");
    store.reset_for_rebuild().expect("activation rebuild reset");
    let replacement_one = anchor(1, 0x12);
    let unrelated = Transaction {
        version: 2,
        lock_time: LockTime::from_consensus(0x12),
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

    let replacement_two = anchor(2, 0x22);
    let new_position = ChainPosition {
        block_height: 2,
        tx_index: 0,
    };
    let interpreter = DeadcatInterpreter::new(LiquidNetwork::ElementsRegtest, policy);
    let retained = store
        .retained_declarations_for_txid(creation.txid())
        .expect("retained declarations for replay");
    let maker_only = retained
        .iter()
        .copied()
        .filter(|declaration| {
            matches!(
                declaration.descriptor,
                deadcat_types::ContractDescriptor::MakerOrderV1 { .. }
            )
        })
        .collect::<Vec<_>>();
    let dormant = interpreter
        .interpret_transaction(
            &InterpretationContext {
                store: &store,
                anchor: replacement_two,
                position: new_position,
                prior_transactions: &[],
                retained_declarations: &maker_only,
                mode: InterpretationMode::Canonical,
            },
            &creation,
        )
        .expect("missing retained parent leaves maker declarations dormant");
    assert!(dormant.created_contracts.is_empty());

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
        .expect("revalidate retained declarations");
    assert_eq!(
        interpreted
            .created_contracts
            .iter()
            .map(|record| record.contract_id)
            .collect::<Vec<_>>(),
        vec![market_id, first_order_id, second_order_id]
    );
    assert!(
        interpreted
            .created_contracts
            .iter()
            .all(|record| record.creation_position == new_position)
    );

    store
        .apply_block(&BlockDelta {
            anchor: replacement_two,
            prev_block_hash: replacement_one.hash,
            ordered_txids: vec![creation.txid()],
            relevant_transactions: vec![prior_creation(
                creation,
                interpreted.created_contracts,
                new_position,
                replacement_two.hash,
            )],
            recovery_hints: Vec::new(),
        })
        .expect("materialize replayed declarations");
    for contract_id in [market_id, first_order_id, second_order_id] {
        let record = store
            .contract(contract_id)
            .expect("contract lookup")
            .expect("replayed contract");
        assert_eq!(record.creation_position, new_position);
        assert!(matches!(
            record.sync_state,
            ContractSyncState::Ready { synced_through } if synced_through == replacement_two
        ));
    }

    let assert_identical_orders_are_indexed = |store: &Store| {
        let mut actual = store
            .ready_orders(market_id, None, None, None, 10)
            .expect("ready orders")
            .items
            .into_iter()
            .map(|order| order.contract.contract_id)
            .collect::<Vec<_>>();
        actual.sort_unstable();
        let mut expected = vec![first_order_id, second_order_id];
        expected.sort_unstable();
        assert_eq!(actual, expected);
    };
    assert_identical_orders_are_indexed(&store);
    drop(store);
    let reopened = Store::open(directory.path().join("deadcat.redb")).expect("reopen store");
    assert_identical_orders_are_indexed(&reopened);
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

    let filled = maker_transition_record(MakerOrderSpendKind::Fill(
        deadcat_contracts::maker_order::MakerOrderFill {
            filled_base: 4,
            maker_payment: 28,
            remaining_locked: Some(6),
            next_state: MakerOrderState::Active {
                remaining_base: 6,
                total_filled_base: 4,
            },
        },
    ));
    let mut expected = Vec::new();
    expected.extend_from_slice(&4_u64.to_be_bytes());
    expected.extend_from_slice(&28_u64.to_be_bytes());
    expected.push(1);
    expected.extend_from_slice(&6_u64.to_be_bytes());
    assert_eq!(filled.kind, TRANSITION_V1_MAKER_FILLED);
    assert_eq!(filled.payload, expected);
}

#[test]
fn prior_spends_and_invalid_witnesses_fail_closed() {
    let (_directory, store) = empty_store();
    let block = anchor(15, 0xd1);
    let position = ChainPosition {
        block_height: 15,
        tx_index: 0,
    };
    let (creation, records) = maker_creation(&[maker_params(0x36)], position, block);
    let record = records[0].clone();
    let first_spend = cancellation([record.outpoints[0].outpoint]);
    let prior = vec![
        prior_creation(creation, vec![record.clone()], position, block.hash),
        ChainTxDelta {
            position: ChainPosition {
                block_height: 15,
                tx_index: 1,
            },
            block_hash: block.hash,
            txid: first_spend.txid(),
            raw_tx: first_spend,
            created_contracts: Vec::new(),
            state_updates: vec![StateUpdate {
                contract_id: record.contract_id,
                old_state: record.state,
                new_state: ContractState::MakerOrder(MakerOrderState::Cancelled),
                spent_outpoints: vec![record.outpoints[0].outpoint],
                new_outpoints: Vec::new(),
                order_remaining_base: None,
                transition: TransitionRecord {
                    kind: TRANSITION_V1_MAKER_CANCELLED,
                    payload: Vec::new(),
                },
            }],
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
    let interpreter = DeadcatInterpreter::new(LiquidNetwork::ElementsRegtest, asset(0xaa));
    assert!(matches!(
        interpreter.interpret_transaction(&context, &cancellation([record.outpoints[0].outpoint])),
        Err(NodeInterpretError::SameBlockDoubleSpend { .. })
    ));

    let fresh_prior = &prior[..1];
    let fresh_context = InterpretationContext {
        prior_transactions: fresh_prior,
        ..context
    };
    let mut invalid = cancellation([record.outpoints[0].outpoint]);
    invalid.input[0].witness.script_witness = vec![vec![1; 12]];
    assert!(
        interpreter
            .interpret_transaction(&fresh_context, &invalid)
            .is_err()
    );
}

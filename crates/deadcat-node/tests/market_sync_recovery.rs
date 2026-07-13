use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use deadcat_client::market_builder::{
    BinaryMarketCreationPlan, BinaryMarketLiveInputs, BinaryMarketTransitionPlan,
    MarketCreationContext, MarketIssuanceEntropies, MarketRtInput,
};
use deadcat_contracts::SimplicityNetwork;
use deadcat_contracts::binary_market::{BinaryMarketAction, CompiledBinaryMarket};
use deadcat_contracts::market_crypto::derive_issuance_assets;
use deadcat_contracts::recovery::{MarketCollateral, MarketRecoveryHint};
use deadcat_contracts::rt::{RtLeg, RtSide, infer_side};
use deadcat_node::chain::{ChainSource, ChainSourceError, Outspend, TransactionStatus};
use deadcat_node::interpreter::{DeadcatInterpreter, TRANSITION_V1_MARKET_ISSUED};
use deadcat_node::store::{ContractParameters, ContractState, Store};
use deadcat_node::sync::{SyncCoordinator, SyncOutcome};
use deadcat_rpc::RecoveryFamily;
use deadcat_types::{
    BinaryMarketParams, BinaryMarketState, ChainAnchor, ChainPosition, ContractId,
    ContractSyncState, DeadcatOutPoint, LiquidNetwork, RecoveryHintLocation,
};
use elements::confidential::{Asset, Nonce, Value};
use elements::hashes::{Hash as _, HashEngine as _, sha256d};
use elements::pset::{Input as PsetInput, Output as PsetOutput, PartiallySignedTransaction};
use elements::secp256k1_zkp::{Keypair, Secp256k1};
use elements::{
    AssetId, Block, BlockExtData, BlockHash, BlockHeader, LockTime, OutPoint, Script, Transaction,
    TxMerkleNode, TxOut, TxOutWitness, Txid,
};

#[derive(Clone)]
struct MutableChain {
    blocks: Arc<Mutex<BTreeMap<u32, Block>>>,
}

impl MutableChain {
    fn new(blocks: Vec<Block>) -> Self {
        Self {
            blocks: Arc::new(Mutex::new(block_map(blocks))),
        }
    }

    fn replace(&self, blocks: Vec<Block>) {
        *self.blocks.lock().expect("chain lock") = block_map(blocks);
    }
}

#[async_trait]
impl ChainSource for MutableChain {
    async fn tip(&self) -> Result<ChainAnchor, ChainSourceError> {
        let blocks = self.blocks.lock().expect("chain lock");
        let (&height, block) = blocks
            .last_key_value()
            .ok_or_else(|| ChainSourceError::NotFound("tip".to_owned()))?;
        Ok(block_anchor(height, block))
    }

    async fn block_hash(&self, height: u32) -> Result<BlockHash, ChainSourceError> {
        self.blocks
            .lock()
            .expect("chain lock")
            .get(&height)
            .map(Block::block_hash)
            .ok_or_else(|| ChainSourceError::NotFound(format!("block {height}")))
    }

    async fn block(&self, hash: BlockHash) -> Result<Block, ChainSourceError> {
        self.blocks
            .lock()
            .expect("chain lock")
            .values()
            .find(|block| block.block_hash() == hash)
            .cloned()
            .ok_or_else(|| ChainSourceError::NotFound(hash.to_string()))
    }

    async fn transaction(&self, txid: Txid) -> Result<Transaction, ChainSourceError> {
        self.blocks
            .lock()
            .expect("chain lock")
            .values()
            .flat_map(|block| block.txdata.iter())
            .find(|transaction| transaction.txid() == txid)
            .cloned()
            .ok_or_else(|| ChainSourceError::NotFound(txid.to_string()))
    }

    async fn transaction_status(&self, txid: Txid) -> Result<TransactionStatus, ChainSourceError> {
        let blocks = self.blocks.lock().expect("chain lock");
        for (&height, block) in &*blocks {
            if let Some(index) = block
                .txdata
                .iter()
                .position(|transaction| transaction.txid() == txid)
            {
                return Ok(TransactionStatus::Confirmed {
                    anchor: block_anchor(height, block),
                    tx_index: u32::try_from(index)
                        .map_err(|_| ChainSourceError::InvalidData("tx index".to_owned()))?,
                });
            }
        }
        Err(ChainSourceError::NotFound(txid.to_string()))
    }

    async fn outspend(
        &self,
        outpoint: DeadcatOutPoint,
    ) -> Result<Option<Outspend>, ChainSourceError> {
        let blocks = self.blocks.lock().expect("chain lock");
        for (&height, block) in &*blocks {
            for (tx_index, transaction) in block.txdata.iter().enumerate() {
                for (input_index, input) in transaction.input.iter().enumerate() {
                    if DeadcatOutPoint::from(input.previous_output) == outpoint {
                        return Ok(Some(Outspend {
                            spending_txid: transaction.txid(),
                            input_index: u32::try_from(input_index).map_err(|_| {
                                ChainSourceError::InvalidData("input index".to_owned())
                            })?,
                            status: TransactionStatus::Confirmed {
                                anchor: block_anchor(height, block),
                                tx_index: u32::try_from(tx_index).map_err(|_| {
                                    ChainSourceError::InvalidData("tx index".to_owned())
                                })?,
                            },
                        }));
                    }
                }
            }
        }
        Ok(None)
    }

    async fn script_history(&self, _script: &Script) -> Result<Vec<Txid>, ChainSourceError> {
        Ok(Vec::new())
    }

    async fn issuance_transaction(
        &self,
        _asset_id: AssetId,
    ) -> Result<Option<Txid>, ChainSourceError> {
        Ok(None)
    }

    async fn estimate_fee_rate(&self, _target_blocks: u16) -> Result<f64, ChainSourceError> {
        Ok(0.1)
    }

    async fn broadcast(&self, transaction: &Transaction) -> Result<Txid, ChainSourceError> {
        Ok(transaction.txid())
    }
}

#[derive(Clone)]
struct MarketFixture {
    params: BinaryMarketParams,
    creation: Transaction,
    issuance: Transaction,
    contract_id: ContractId,
    pairs: u64,
}

fn asset(byte: u8) -> AssetId {
    AssetId::from_slice(&[byte; 32]).expect("asset")
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
    let oracle_public_key =
        Keypair::from_seckey_slice(&Secp256k1::new(), &[seed.wrapping_add(16); 32])
            .expect("oracle key")
            .x_only_public_key()
            .0
            .serialize();
    BinaryMarketParams {
        oracle_public_key,
        collateral_asset_id: policy_asset,
        yes_token_asset_id: ids.yes_token,
        no_token_asset_id: ids.no_token,
        yes_reissuance_token_id: ids.yes_reissuance_token,
        no_reissuance_token_id: ids.no_reissuance_token,
        base_payout: 100,
        expiry_height: 50_000,
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
        market_hint(params),
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

fn initial_issuance(
    params: BinaryMarketParams,
    creation: &Transaction,
    entropies: MarketIssuanceEntropies,
    pairs: u64,
) -> Transaction {
    let live = BinaryMarketLiveInputs {
        yes_rt: Some(MarketRtInput {
            outpoint: OutPoint::new(creation.txid(), 0),
            txout: creation.output[0].clone(),
        }),
        no_rt: Some(MarketRtInput {
            outpoint: OutPoint::new(creation.txid(), 1),
            txout: creation.output[1].clone(),
        }),
        collateral: None,
    };
    let plan = BinaryMarketTransitionPlan::new(
        params,
        BinaryMarketState::Trading {
            outstanding_pairs: 0,
        },
        BinaryMarketAction::Issue { pairs },
        live,
        None,
    )
    .expect("initial issuance plan");
    let mut pset = PartiallySignedTransaction::new_v2();
    pset.add_input(pset_input(
        OutPoint::new(creation.txid(), 0),
        creation.output[0].clone(),
    ));
    pset.add_input(pset_input(
        OutPoint::new(creation.txid(), 1),
        creation.output[1].clone(),
    ));
    for (_, output) in plan.mandatory_outputs(0).expect("mandatory outputs") {
        pset.add_output(PsetOutput::from_txout(output));
    }
    plan.configure_reissuance_inputs(&mut pset, 0, entropies)
        .expect("reissuance fields");
    plan.finalize(
        &mut pset,
        0,
        0,
        &SimplicityNetwork::ElementsRegtest {
            policy_asset: params.collateral_asset_id,
        },
    )
    .expect("covenant finalization");
    pset.extract_tx().expect("initial issuance transaction")
}

fn market_fixture(seed: u8, policy_asset: AssetId, pairs: u64) -> MarketFixture {
    let params = market_params(seed, policy_asset);
    let (creation, entropies) =
        creation_transaction(params, policy_asset, defining_outpoints(seed));
    let issuance = initial_issuance(params, &creation, entropies, pairs);
    let contract_id = CompiledBinaryMarket::new(params)
        .expect("compile market")
        .contract_id(creation.txid());
    MarketFixture {
        params,
        creation,
        issuance,
        contract_id,
        pairs,
    }
}

fn marker_transaction(marker: u8, policy_asset: AssetId) -> Transaction {
    Transaction {
        version: 2,
        lock_time: LockTime::from_consensus(u32::from(marker)),
        input: Vec::new(),
        output: vec![TxOut::new_fee(u64::from(marker) + 1, policy_asset)],
    }
}

fn block_map(blocks: Vec<Block>) -> BTreeMap<u32, Block> {
    blocks
        .into_iter()
        .map(|block| (block.header.height, block))
        .collect()
}

fn block_anchor(height: u32, block: &Block) -> ChainAnchor {
    ChainAnchor {
        height,
        hash: block.block_hash(),
    }
}

fn merkle_root(transactions: &[Transaction]) -> TxMerkleNode {
    let mut layer = transactions
        .iter()
        .map(|transaction| transaction.txid().to_raw_hash())
        .collect::<Vec<sha256d::Hash>>();
    assert!(!layer.is_empty(), "test block must not be empty");
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            let mut engine = sha256d::Hash::engine();
            engine.input(left.as_byte_array());
            engine.input(right.as_byte_array());
            next.push(sha256d::Hash::from_engine(engine));
        }
        layer = next;
    }
    TxMerkleNode::from_raw_hash(layer[0])
}

fn test_block(
    height: u32,
    prev_blockhash: BlockHash,
    marker: u8,
    txdata: Vec<Transaction>,
) -> Block {
    Block {
        header: BlockHeader {
            version: 0x2000_0000,
            prev_blockhash,
            merkle_root: merkle_root(&txdata),
            time: u32::from(marker),
            height,
            ext: BlockExtData::Proof {
                challenge: Script::new(),
                solution: Script::new(),
            },
        },
        txdata,
    }
}

fn assert_indexed_market(store: &Store, fixture: &MarketFixture, expected_tip: ChainAnchor) {
    let record = store
        .contract(fixture.contract_id)
        .expect("read market")
        .expect("auto-discovered market");
    assert_eq!(
        record.params,
        ContractParameters::BinaryMarket(fixture.params)
    );
    assert_eq!(
        record.state,
        ContractState::BinaryMarket(BinaryMarketState::Trading {
            outstanding_pairs: fixture.pairs,
        })
    );
    assert_eq!(
        record.sync_state,
        ContractSyncState::Ready {
            synced_through: expected_tip,
        }
    );
    assert_eq!(
        record.creation_position,
        ChainPosition {
            block_height: 1,
            tx_index: 0,
        }
    );
    assert_eq!(record.outpoints.len(), 3);
    for vout in 0..3_u32 {
        let outpoint = DeadcatOutPoint::new(fixture.issuance.txid(), vout);
        assert!(
            record
                .outpoints
                .iter()
                .any(|tracked| tracked.outpoint == outpoint)
        );
        let stored = store
            .output(outpoint)
            .expect("read live output")
            .expect("persisted live output");
        assert_eq!(stored.position.block_height, 2);
        assert_eq!(
            stored.output,
            fixture.issuance.output[usize::try_from(vout).expect("vout")]
        );
    }

    let yes = store
        .output(DeadcatOutPoint::new(fixture.issuance.txid(), 0))
        .expect("read YES output")
        .expect("stored YES output");
    let no = store
        .output(DeadcatOutPoint::new(fixture.issuance.txid(), 1))
        .expect("read NO output")
        .expect("stored NO output");
    assert_eq!(
        infer_side(
            RtLeg::Yes,
            fixture.params.yes_reissuance_token_id,
            yes.output.asset,
            yes.output.value,
        )
        .expect("infer YES side"),
        RtSide::B
    );
    assert_eq!(
        infer_side(
            RtLeg::No,
            fixture.params.no_reissuance_token_id,
            no.output.asset,
            no.output.value,
        )
        .expect("infer NO side"),
        RtSide::B
    );

    let creation_evidence = store
        .transaction(ChainPosition {
            block_height: 1,
            tx_index: 0,
        })
        .expect("read creation evidence")
        .expect("stored creation evidence");
    assert_eq!(
        elements::encode::deserialize::<Transaction>(&creation_evidence.raw_tx)
            .expect("decode creation evidence"),
        fixture.creation
    );
    assert_eq!(
        creation_evidence.affected_contract_ids,
        [fixture.contract_id]
    );

    let issuance_evidence = store
        .transaction(ChainPosition {
            block_height: 2,
            tx_index: 0,
        })
        .expect("read issuance evidence")
        .expect("stored issuance evidence");
    assert_eq!(
        elements::encode::deserialize::<Transaction>(&issuance_evidence.raw_tx)
            .expect("decode issuance evidence"),
        fixture.issuance
    );
    assert_eq!(
        issuance_evidence.affected_contract_ids,
        [fixture.contract_id]
    );

    let history = store
        .contract_history(fixture.contract_id)
        .expect("market history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].position.block_height, 2);
    assert_eq!(history[0].txid, fixture.issuance.txid());
    assert_eq!(history[0].transition.kind, TRANSITION_V1_MARKET_ISSUED);
    assert_eq!(
        history[0].new_state,
        ContractState::BinaryMarket(BinaryMarketState::Trading {
            outstanding_pairs: fixture.pairs,
        })
    );

    let hint = store
        .recovery_hint(RecoveryHintLocation {
            position: ChainPosition {
                block_height: 1,
                tx_index: 0,
            },
            output_index: 2,
        })
        .expect("read recovery hint")
        .expect("stored recovery hint");
    assert_eq!(hint.family, RecoveryFamily::BinaryMarketV1);
    assert_eq!(hint.creation_txid, fixture.creation.txid());
    assert_eq!(hint.associated_contract, Some(fixture.contract_id));
}

#[tokio::test]
async fn full_chain_market_recovery_survives_restart_and_coordinator_reorgs() {
    let directory = tempfile::tempdir().expect("tempdir");
    let database = directory.path().join("deadcat.redb");
    let policy_asset = asset(0xa1);
    let original = market_fixture(0x31, policy_asset, 2);
    let alternate_issuance = MarketFixture {
        issuance: initial_issuance(
            original.params,
            &original.creation,
            BinaryMarketCreationPlan::new(
                MarketCreationContext {
                    policy_asset,
                    liquid_mainnet_usdt: None,
                },
                original.params,
                market_hint(original.params),
                defining_outpoints(0x31).0,
                defining_outpoints(0x31).1,
            )
            .expect("alternate creation plan")
            .entropies(),
            3,
        ),
        pairs: 3,
        ..original.clone()
    };
    let replacement = market_fixture(0x61, policy_asset, 4);

    let genesis = test_block(
        0,
        BlockHash::all_zeros(),
        0x01,
        vec![marker_transaction(0x01, policy_asset)],
    );
    let original_creation = test_block(
        1,
        genesis.block_hash(),
        0x11,
        vec![original.creation.clone()],
    );
    let original_issuance = test_block(
        2,
        original_creation.block_hash(),
        0x12,
        vec![original.issuance.clone()],
    );
    let source = MutableChain::new(vec![
        genesis.clone(),
        original_creation.clone(),
        original_issuance.clone(),
    ]);
    let interpreter = DeadcatInterpreter::new(LiquidNetwork::ElementsRegtest, policy_asset);
    let store = Store::open(&database).expect("open empty store");
    store
        .initialize_tip(block_anchor(0, &genesis))
        .expect("initialize activation anchor");
    assert!(
        store
            .contract(original.contract_id)
            .expect("empty contract lookup")
            .is_none()
    );

    let SyncOutcome::Ready(initial) = SyncCoordinator::new(&source, &store, &interpreter)
        .sync_to_tip()
        .await
        .expect("initial archival sync")
    else {
        panic!("expected ready initial sync");
    };
    assert_eq!(initial.blocks_applied, 2);
    assert_eq!(initial.blocks_rolled_back, 0);
    let original_tip = block_anchor(2, &original_issuance);
    assert_indexed_market(&store, &original, original_tip);
    let initial_cursor = store.event_high_watermark().expect("initial cursor");
    drop(store);

    let reopened = Store::open(&database).expect("reopen store");
    assert_indexed_market(&reopened, &original, original_tip);
    let SyncOutcome::Ready(idempotent) = SyncCoordinator::new(&source, &reopened, &interpreter)
        .sync_to_tip()
        .await
        .expect("idempotent restart sync")
    else {
        panic!("expected ready restart sync");
    };
    assert_eq!(idempotent.blocks_applied, 0);
    assert_eq!(idempotent.blocks_rolled_back, 0);
    assert_eq!(
        reopened.event_high_watermark().expect("restart cursor"),
        initial_cursor
    );

    let alternate_block = test_block(
        2,
        original_creation.block_hash(),
        0x22,
        vec![alternate_issuance.issuance.clone()],
    );
    source.replace(vec![
        genesis.clone(),
        original_creation.clone(),
        alternate_block.clone(),
    ]);
    let SyncOutcome::Ready(one_block) = SyncCoordinator::new(&source, &reopened, &interpreter)
        .sync_to_tip()
        .await
        .expect("one-block branch replacement")
    else {
        panic!("expected ready after one-block reorg");
    };
    assert_eq!(one_block.blocks_rolled_back, 1);
    assert_eq!(one_block.blocks_applied, 1);
    assert_indexed_market(
        &reopened,
        &alternate_issuance,
        block_anchor(2, &alternate_block),
    );
    assert!(
        reopened
            .output(DeadcatOutPoint::new(original.issuance.txid(), 0))
            .expect("orphan output lookup")
            .is_none()
    );

    let replacement_creation = test_block(
        1,
        genesis.block_hash(),
        0x31,
        vec![replacement.creation.clone()],
    );
    let replacement_issuance = test_block(
        2,
        replacement_creation.block_hash(),
        0x32,
        vec![replacement.issuance.clone()],
    );
    source.replace(vec![
        genesis,
        replacement_creation,
        replacement_issuance.clone(),
    ]);
    let SyncOutcome::Ready(two_block) = SyncCoordinator::new(&source, &reopened, &interpreter)
        .sync_to_tip()
        .await
        .expect("two-block branch replacement")
    else {
        panic!("expected ready after two-block reorg");
    };
    assert_eq!(two_block.blocks_rolled_back, 2);
    assert_eq!(two_block.blocks_applied, 2);
    assert!(
        reopened
            .contract(original.contract_id)
            .expect("orphan contract lookup")
            .is_none()
    );
    assert_indexed_market(
        &reopened,
        &replacement,
        block_anchor(2, &replacement_issuance),
    );
}

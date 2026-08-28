//! Validation-first compilation of the canonical binary-market covenant.

use std::collections::HashSet;
use std::sync::{Arc, LazyLock};

use elements::confidential::{Asset, Value};
use elements::hashes::{Hash as _, HashEngine as _, sha256};
use elements::pset::PartiallySignedTransaction;
use elements::secp256k1_zkp::{Secp256k1, XOnlyPublicKey};
use elements::taproot::{ControlBlock, TaprootBuilder, TaprootBuilderError};
use elements::{AssetId, Script, Transaction, TxOut};
use simplex::global::GlobalConfig;
use simplex::program::logger::ProgramLogger;
use simplex::program::{ArgumentsTrait as _, ProgramError};
use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::ast::ElementsJetHinter;
use simplex::simplicityhl::error::ErrorCollector;
use simplex::simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use simplex::simplicityhl::simplicity::{
    BitMachine, HasCmr as _, RedeemNode, Value as SimplicityValue, leaf_version,
};
use simplex::simplicityhl::{
    CompiledProgram, TemplateProgram, UnstableFeature, UnstableFeatures, WitnessValues,
};
use thiserror::Error;

use super::{BinaryMarketEconomics, BinaryMarketParams, BinaryMarketSlot};
use crate::artifacts::binary_market::{BinaryMarketProgram, derived_binary_market};
use crate::finalized_spend::{FinalizedSimplicitySpend, FinalizedSimplicitySpendError};
use crate::market_crypto::{BinaryOutcome as OracleOutcome, oracle_message};
use crate::rt::{RtCommitmentError, RtLeg, RtSide, commitments, factors};

const NUMS_INTERNAL_KEY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];
const TAPROOT_ANNEX_TAG: u8 = 0x50;

static BINARY_MARKET_TEMPLATE: LazyLock<Result<TemplateProgram, Arc<ErrorCollector>>> =
    LazyLock::new(analyze_binary_market_template);

#[cfg(test)]
static TEMPLATE_ANALYSIS_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn analyze_binary_market_template() -> Result<TemplateProgram, Arc<ErrorCollector>> {
    #[cfg(test)]
    TEMPLATE_ANALYSIS_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    TemplateProgram::new_with_unstable(
        BinaryMarketProgram::SOURCE,
        &UnstableFeatures::new([UnstableFeature::Imports]),
        Box::new(ElementsJetHinter),
    )
    .map_err(Arc::new)
}

fn binary_market_template() -> Result<&'static TemplateProgram, CompiledBinaryMarketError> {
    match &*BINARY_MARKET_TEMPLATE {
        Ok(template) => Ok(template),
        Err(error) => Err(CompiledBinaryMarketError::TemplateCompilation(Arc::clone(
            error,
        ))),
    }
}

/// One fully materialized static slot of a compiled binary market.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledBinaryMarketSlot {
    slot: BinaryMarketSlot,
    storage_word: [u8; 32],
    script_pubkey: Script,
    control_block: ControlBlock,
}

impl CompiledBinaryMarketSlot {
    #[must_use]
    pub const fn slot(&self) -> BinaryMarketSlot {
        self.slot
    }

    #[must_use]
    pub const fn storage_word(&self) -> [u8; 32] {
        self.storage_word
    }

    #[must_use]
    pub fn script_pubkey(&self) -> &Script {
        &self.script_pubkey
    }

    #[must_use]
    pub const fn control_block(&self) -> &ControlBlock {
        &self.control_block
    }
}

/// A validated binary-market program plus all eight static Taproot slots.
///
/// Construction compiles the parameterized SimplicityHL source through the
/// fallible compiler API, then constructs the two-leaf Taproot tree directly.
/// It deliberately does not call smplx's panic-based address/script helpers.
#[derive(Clone, Debug)]
pub struct CompiledBinaryMarket {
    params: BinaryMarketParams,
    #[cfg(test)]
    arguments: derived_binary_market::BinaryMarketArguments,
    compiled: CompiledProgram,
    cmr: [u8; 32],
    slots: [CompiledBinaryMarketSlot; 8],
}

impl CompiledBinaryMarket {
    /// Validate parameters and compile the canonical v1 covenant.
    pub fn new(params: BinaryMarketParams) -> Result<Self, CompiledBinaryMarketError> {
        validate_params(params)?;

        let arguments = contract_arguments(params)?;
        let compiled = binary_market_template()?
            .instantiate(arguments.build_arguments(), false)
            .map_err(CompiledBinaryMarketError::ArgumentInstantiation)?;
        let cmr_node = compiled.commit().cmr();
        let mut cmr = [0_u8; 32];
        cmr.copy_from_slice(cmr_node.as_ref());
        let program_leaf_script = Script::from(cmr.to_vec());

        let internal_key = XOnlyPublicKey::from_slice(&NUMS_INTERNAL_KEY)
            .map_err(|_| CompiledBinaryMarketError::InvalidNumsInternalKey)?;
        let secp = Secp256k1::verification_only();
        let mut materialized = Vec::with_capacity(BinaryMarketSlot::ALL.len());
        for slot in BinaryMarketSlot::ALL {
            materialized.push(compile_slot(
                slot,
                &program_leaf_script,
                internal_key,
                &secp,
            )?);
        }
        let slots = materialized
            .try_into()
            .map_err(|_| CompiledBinaryMarketError::SlotCountInvariant)?;

        Ok(Self {
            params,
            #[cfg(test)]
            arguments,
            compiled,
            cmr,
            slots,
        })
    }

    #[must_use]
    pub const fn params(&self) -> BinaryMarketParams {
        self.params
    }

    #[must_use]
    pub const fn cmr(&self) -> [u8; 32] {
        self.cmr
    }

    #[must_use]
    pub const fn slots(&self) -> &[CompiledBinaryMarketSlot; 8] {
        &self.slots
    }

    #[must_use]
    pub fn slot(&self, slot: BinaryMarketSlot) -> &CompiledBinaryMarketSlot {
        &self.slots[slot as usize]
    }

    /// Recreate the generated smplx program for the sole SDK parity regression.
    #[cfg(test)]
    #[must_use]
    #[allow(unused_must_use)]
    fn program(&self, slot: BinaryMarketSlot) -> BinaryMarketProgram {
        let mut program = BinaryMarketProgram::new(self.arguments.clone()).with_storage_capacity(1);
        program.set_storage_at(0, slot.storage_word());
        program
    }

    /// Execute one storage slot without recompiling the parameterized source.
    pub fn execute(
        &self,
        slot: BinaryMarketSlot,
        pset: &PartiallySignedTransaction,
        witness: &WitnessValues,
        input_index: usize,
        network: &SimplicityNetwork,
    ) -> Result<(Arc<RedeemNode>, SimplicityValue), CompiledBinaryMarketExecutionError> {
        let satisfied = self
            .compiled
            .satisfy(witness.clone())
            .map_err(ProgramError::WitnessSatisfaction)?;
        let mut tracker =
            ProgramLogger::make_tracker(satisfied.debug_symbols(), GlobalConfig::get_log_level());
        let environment = self.environment(slot, pset, input_index, network)?;
        let pruned = satisfied
            .redeem()
            .prune_with_tracker(&environment, &mut tracker)
            .map_err(ProgramError::Pruning)?;

        if GlobalConfig::is_max_verbose() {
            ProgramLogger::buffer_cost_log(&pruned);
        }

        let mut machine =
            BitMachine::for_program(&pruned).map_err(ProgramError::BitMachineCreation)?;
        let result = machine
            .exec(&pruned, &environment)
            .map_err(ProgramError::Execution)?;
        Ok((pruned, result))
    }

    /// Finalize one storage slot without recompiling the parameterized source.
    pub fn finalize(
        &self,
        slot: BinaryMarketSlot,
        pset: &PartiallySignedTransaction,
        witness: &WitnessValues,
        input_index: usize,
        network: &SimplicityNetwork,
    ) -> Result<FinalizedSimplicitySpend, CompiledBinaryMarketExecutionError> {
        let pruned = self.execute(slot, pset, witness, input_index, network)?.0;
        let (program_bytes, witness_bytes) = pruned.to_vec_with_witness();
        Ok(FinalizedSimplicitySpend::from_core_stack([
            witness_bytes,
            program_bytes,
            pruned.cmr().as_ref().to_vec(),
            self.slot(slot).control_block().serialize(),
        ])?)
    }

    /// Re-execute the finalized Simplicity witness installed on one PSET input.
    pub fn execute_finalized(
        &self,
        slot: BinaryMarketSlot,
        pset: &PartiallySignedTransaction,
        input_index: usize,
        network: &SimplicityNetwork,
    ) -> Result<SimplicityValue, CompiledBinaryMarketExecutionError> {
        let Some(input) = pset.inputs().get(input_index) else {
            return Err(ProgramError::UtxoIndexOutOfBounds {
                input_index,
                utxo_count: pset.inputs().len(),
            }
            .into());
        };
        let witness_stack = input
            .final_script_witness
            .as_ref()
            .ok_or(CompiledBinaryMarketExecutionError::MissingFinalScriptWitness { input_index })?;
        let finalized = FinalizedSimplicitySpend::parse_witness_stack(witness_stack)?;
        if finalized.cmr() != self.cmr {
            return Err(CompiledBinaryMarketExecutionError::CmrMismatch {
                expected: self.cmr,
                actual: finalized.cmr(),
            });
        }
        let expected_control_block = self.slot(slot).control_block();
        if finalized.control_block() != expected_control_block {
            return Err(CompiledBinaryMarketExecutionError::ControlBlockMismatch {
                expected: Box::new(expected_control_block.clone()),
                actual: Box::new(finalized.control_block().clone()),
            });
        }

        let environment = self.environment(slot, pset, input_index, network)?;
        let redeem_node = finalized.redeem_node();
        if GlobalConfig::is_max_verbose() {
            ProgramLogger::buffer_cost_log(redeem_node);
        }
        let mut machine =
            BitMachine::for_program(redeem_node).map_err(ProgramError::BitMachineCreation)?;
        machine
            .exec(redeem_node, &environment)
            .map_err(ProgramError::Execution)
            .map_err(Into::into)
    }

    fn environment(
        &self,
        slot: BinaryMarketSlot,
        pset: &PartiallySignedTransaction,
        input_index: usize,
        network: &SimplicityNetwork,
    ) -> Result<ElementsEnv<Arc<Transaction>>, CompiledBinaryMarketExecutionError> {
        let utxos = collect_witness_utxos(pset)?;
        let Some(target_utxo) = utxos.get(input_index) else {
            return Err(ProgramError::UtxoIndexOutOfBounds {
                input_index,
                utxo_count: utxos.len(),
            }
            .into());
        };
        let expected_script = self.slot(slot).script_pubkey();
        if target_utxo.script_pubkey != *expected_script {
            return Err(ProgramError::ScriptPubkeyMismatch {
                expected_hash: expected_script.script_hash().to_string(),
                actual_hash: target_utxo.script_pubkey.script_hash().to_string(),
            }
            .into());
        }

        let annex = current_input_annex(pset, input_index);

        Ok(ElementsEnv::new(
            Arc::new(pset.extract_tx().map_err(ProgramError::TxExtraction)?),
            utxos
                .iter()
                .map(|utxo| ElementsUtxo {
                    script_pubkey: utxo.script_pubkey.clone(),
                    asset: utxo.asset,
                    value: utxo.value,
                })
                .collect(),
            u32::try_from(input_index).map_err(ProgramError::InputIndexOverflow)?,
            self.compiled.commit().cmr(),
            self.slot(slot).control_block().clone(),
            annex,
            network.genesis_block_hash(),
        ))
    }
}

fn collect_witness_utxos(
    pset: &PartiallySignedTransaction,
) -> Result<Vec<TxOut>, CompiledBinaryMarketExecutionError> {
    pset.inputs()
        .iter()
        .enumerate()
        .map(|(input_index, input)| {
            input
                .witness_utxo
                .clone()
                .ok_or(CompiledBinaryMarketExecutionError::MissingWitnessUtxo { input_index })
        })
        .collect()
}

fn current_input_annex(pset: &PartiallySignedTransaction, input_index: usize) -> Option<Vec<u8>> {
    let witness_stack = pset
        .inputs()
        .get(input_index)?
        .final_script_witness
        .as_ref()?;
    if witness_stack.len() < 2 {
        return None;
    }
    witness_stack
        .last()
        .filter(|item| item.first() == Some(&TAPROOT_ANNEX_TAG))
        .cloned()
}

#[derive(Debug, Error)]
pub enum CompiledBinaryMarketError {
    #[error("{base_payout} is not a canonical v1 base payout")]
    InvalidBasePayout { base_payout: u64 },
    #[error("expiry height {expiry_height} is outside 1..500,000,000")]
    InvalidExpiryHeight { expiry_height: u32 },
    #[error("oracle public key is not a valid x-only secp256k1 key")]
    InvalidOraclePublicKey,
    #[error("binary-market collateral, outcome-token, and RT asset IDs must be distinct")]
    DuplicateAssetIds,
    #[error("failed to parse or analyze the canonical binary-market SimplicityHL template: {0}")]
    TemplateCompilation(#[source] Arc<ErrorCollector>),
    #[error("failed to instantiate binary-market SimplicityHL arguments: {0}")]
    ArgumentInstantiation(String),
    #[error("failed to build binary-market Taproot tree: {0}")]
    Taproot(#[from] TaprootBuilderError),
    #[error("compiled Taproot tree did not contain its program leaf")]
    MissingControlBlock,
    #[error("the fixed binary-market NUMS internal key is invalid")]
    InvalidNumsInternalKey,
    #[error("compiled binary-market slot count was not eight")]
    SlotCountInvariant,
    #[error("failed to derive public RT commitments: {0}")]
    RtCommitment(#[from] RtCommitmentError),
    #[error("derived RT commitment was unexpectedly explicit")]
    ExplicitRtCommitment,
    #[error("A/B sides produced different value commitments for one RT leg")]
    InconsistentRtValueCommitment,
}

/// Errors raised while preparing or executing a compiled binary-market spend.
#[derive(Debug, Error)]
pub enum CompiledBinaryMarketExecutionError {
    #[error("PSET input {input_index} is missing its witness_utxo")]
    MissingWitnessUtxo { input_index: usize },
    #[error("PSET input {input_index} is missing its final_script_witness")]
    MissingFinalScriptWitness { input_index: usize },
    #[error("finalized Simplicity CMR mismatch: expected {expected:?}, got {actual:?}")]
    CmrMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    #[error("finalized Simplicity control block mismatch: expected {expected:?}, got {actual:?}")]
    ControlBlockMismatch {
        expected: Box<ControlBlock>,
        actual: Box<ControlBlock>,
    },
    #[error(transparent)]
    FinalizedSpend(#[from] FinalizedSimplicitySpendError),
    #[error(transparent)]
    Program(#[from] ProgramError),
}

fn validate_params(params: BinaryMarketParams) -> Result<(), CompiledBinaryMarketError> {
    BinaryMarketEconomics::new(params.base_payout).map_err(|_| {
        CompiledBinaryMarketError::InvalidBasePayout {
            base_payout: params.base_payout,
        }
    })?;
    if !(1..500_000_000).contains(&params.expiry_height) {
        return Err(CompiledBinaryMarketError::InvalidExpiryHeight {
            expiry_height: params.expiry_height,
        });
    }
    XOnlyPublicKey::from_slice(&params.oracle_public_key)
        .map_err(|_| CompiledBinaryMarketError::InvalidOraclePublicKey)?;

    let assets = [
        params.collateral_asset_id,
        params.yes_token_asset_id,
        params.no_token_asset_id,
        params.yes_reissuance_token_id,
        params.no_reissuance_token_id,
    ];
    let distinct: HashSet<AssetId> = assets.into_iter().collect();
    if distinct.len() != assets.len() {
        return Err(CompiledBinaryMarketError::DuplicateAssetIds);
    }
    Ok(())
}

fn contract_arguments(
    params: BinaryMarketParams,
) -> Result<derived_binary_market::BinaryMarketArguments, CompiledBinaryMarketError> {
    let yes = rt_commitment_arguments(params.yes_reissuance_token_id, RtLeg::Yes)?;
    let no = rt_commitment_arguments(params.no_reissuance_token_id, RtLeg::No)?;
    let oracle_message_yes = oracle_message(
        params.yes_token_asset_id,
        params.no_token_asset_id,
        OracleOutcome::Yes,
    );
    let oracle_message_no = oracle_message(
        params.yes_token_asset_id,
        params.no_token_asset_id,
        OracleOutcome::No,
    );
    Ok(derived_binary_market::BinaryMarketArguments {
        oracle_public_key: params.oracle_public_key,
        oracle_message_yes,
        oracle_message_no,
        collateral_asset_id: params.collateral_asset_id.into_inner().to_byte_array(),
        yes_token_asset_id: params.yes_token_asset_id.into_inner().to_byte_array(),
        no_token_asset_id: params.no_token_asset_id.into_inner().to_byte_array(),
        yes_reissuance_token_id: params.yes_reissuance_token_id.into_inner().to_byte_array(),
        no_reissuance_token_id: params.no_reissuance_token_id.into_inner().to_byte_array(),
        base_payout: params.base_payout,
        expiry_height: params.expiry_height,
        yes_rt_asset_a_parity: yes.asset_a.parity,
        yes_rt_asset_a_x: yes.asset_a.x,
        yes_rt_asset_b_parity: yes.asset_b.parity,
        yes_rt_asset_b_x: yes.asset_b.x,
        yes_rt_value_parity: yes.value.parity,
        yes_rt_value_x: yes.value.x,
        no_rt_asset_a_parity: no.asset_a.parity,
        no_rt_asset_a_x: no.asset_a.x,
        no_rt_asset_b_parity: no.asset_b.parity,
        no_rt_asset_b_x: no.asset_b.x,
        no_rt_value_parity: no.value.parity,
        no_rt_value_x: no.value.x,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompressedCommitment {
    parity: bool,
    x: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RtCommitmentArguments {
    asset_a: CompressedCommitment,
    asset_b: CompressedCommitment,
    value: CompressedCommitment,
}

fn rt_commitment_arguments(
    asset_id: AssetId,
    leg: RtLeg,
) -> Result<RtCommitmentArguments, CompiledBinaryMarketError> {
    let (asset_a, value_a) = commitments(asset_id, factors(leg, RtSide::A))?;
    let (asset_b, value_b) = commitments(asset_id, factors(leg, RtSide::B))?;
    let asset_a = compress_asset(asset_a)?;
    let asset_b = compress_asset(asset_b)?;
    let value_a = compress_value(value_a)?;
    let value_b = compress_value(value_b)?;
    if value_a != value_b {
        return Err(CompiledBinaryMarketError::InconsistentRtValueCommitment);
    }
    Ok(RtCommitmentArguments {
        asset_a,
        asset_b,
        value: value_a,
    })
}

fn compress_asset(asset: Asset) -> Result<CompressedCommitment, CompiledBinaryMarketError> {
    let Asset::Confidential(commitment) = asset else {
        return Err(CompiledBinaryMarketError::ExplicitRtCommitment);
    };
    Ok(compress_serialized(commitment.serialize()))
}

fn compress_value(value: Value) -> Result<CompressedCommitment, CompiledBinaryMarketError> {
    let Value::Confidential(commitment) = value else {
        return Err(CompiledBinaryMarketError::ExplicitRtCommitment);
    };
    Ok(compress_serialized(commitment.serialize()))
}

fn compress_serialized(serialized: [u8; 33]) -> CompressedCommitment {
    let mut x = [0_u8; 32];
    x.copy_from_slice(&serialized[1..]);
    CompressedCommitment {
        parity: serialized[0] & 1 != 0,
        x,
    }
}

fn compile_slot(
    slot: BinaryMarketSlot,
    program_leaf_script: &Script,
    internal_key: XOnlyPublicKey,
    secp: &Secp256k1<elements::secp256k1_zkp::VerifyOnly>,
) -> Result<CompiledBinaryMarketSlot, CompiledBinaryMarketError> {
    let storage_word = slot.storage_word();
    let storage_leaf = tap_data_hash(&storage_word);
    let version = leaf_version();
    let builder =
        TaprootBuilder::new().add_leaf_with_ver(1, program_leaf_script.clone(), version)?;
    let builder = builder.add_hidden(1, storage_leaf)?;
    let spend_info = builder.finalize(secp, internal_key)?;
    let control_block = spend_info
        .control_block(&(program_leaf_script.clone(), version))
        .ok_or(CompiledBinaryMarketError::MissingControlBlock)?;
    let script_pubkey = Script::new_v1_p2tr_tweaked(spend_info.output_key());

    Ok(CompiledBinaryMarketSlot {
        slot,
        storage_word,
        script_pubkey,
        control_block,
    })
}

fn tap_data_hash(data: &[u8]) -> sha256::Hash {
    let tag = sha256::Hash::hash(b"TapData");
    let mut engine = sha256::Hash::engine();
    engine.input(tag.as_byte_array());
    engine.input(tag.as_byte_array());
    engine.input(data);
    sha256::Hash::from_engine(engine)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::atomic::Ordering;

    use elements::confidential::Nonce;
    use elements::hashes::Hash as _;
    use elements::pset::Input as PsetInput;
    use elements::schnorr::TweakedPublicKey;
    use elements::{AssetId, OutPoint, TxOutWitness, Txid};
    use simplex::provider::SimplicityNetwork;
    use simplex::simplicityhl::Arguments;

    use super::*;

    fn asset(byte: u8) -> AssetId {
        AssetId::from_slice(&[byte; 32]).expect("32-byte asset ID")
    }

    fn params() -> BinaryMarketParams {
        BinaryMarketParams {
            oracle_public_key: NUMS_INTERNAL_KEY,
            collateral_asset_id: asset(0x11),
            yes_token_asset_id: asset(0x22),
            no_token_asset_id: asset(0x33),
            yes_reissuance_token_id: asset(0x44),
            no_reissuance_token_id: asset(0x55),
            base_payout: 1_000,
            expiry_height: 250_000,
        }
    }

    fn txout(byte: u8, script_pubkey: Script) -> TxOut {
        TxOut {
            asset: Asset::Explicit(asset(byte)),
            value: Value::Explicit(u64::from(byte)),
            nonce: Nonce::Null,
            script_pubkey,
            witness: TxOutWitness::default(),
        }
    }

    fn pset_with_witness_utxos(
        witness_utxos: impl IntoIterator<Item = Option<TxOut>>,
    ) -> PartiallySignedTransaction {
        let mut pset = PartiallySignedTransaction::new_v2();
        for (input_index, witness_utxo) in witness_utxos.into_iter().enumerate() {
            let input_byte = u8::try_from(input_index + 1).expect("small test input index");
            let mut input = PsetInput::from_prevout(OutPoint::new(
                Txid::from_byte_array([input_byte; 32]),
                u32::try_from(input_index).expect("small test input index"),
            ));
            input.witness_utxo = witness_utxo;
            pset.add_input(input);
        }
        pset
    }

    fn simple_finalized_spend(control_block: &ControlBlock) -> FinalizedSimplicitySpend {
        let compiled = CompiledProgram::new(
            "fn main() { assert!(true); }",
            Arguments::default(),
            false,
            Box::new(ElementsJetHinter),
        )
        .expect("compile simple program");
        let satisfied = compiled
            .satisfy(WitnessValues::default())
            .expect("satisfy simple program");
        let redeem_node = satisfied.redeem();
        let (program_bytes, witness_bytes) = redeem_node.to_vec_with_witness();
        FinalizedSimplicitySpend::from_core_stack([
            witness_bytes,
            program_bytes,
            redeem_node.cmr().as_ref().to_vec(),
            control_block.serialize(),
        ])
        .expect("build simple finalized spend")
    }

    #[test]
    fn analyzed_template_is_reused_and_instantiation_remains_deterministic() {
        let first_template = binary_market_template().expect("analyze template");
        let second_template = binary_market_template().expect("reuse template");
        assert!(std::ptr::eq(first_template, second_template));
        assert_eq!(TEMPLATE_ANALYSIS_COUNT.load(Ordering::Relaxed), 1);

        let params = params();
        let first = CompiledBinaryMarket::new(params).expect("first instantiation");
        let repeated = CompiledBinaryMarket::new(params).expect("repeated instantiation");
        assert_eq!(first.cmr(), repeated.cmr());
        let mut changed = params;
        changed.expiry_height += 1;
        let second_market =
            CompiledBinaryMarket::new(changed).expect("distinct market instantiation");
        assert_ne!(first.cmr(), second_market.cmr());

        let error = first_template
            .instantiate(Arguments::default(), false)
            .map_err(CompiledBinaryMarketError::ArgumentInstantiation)
            .expect_err("missing arguments must fail during instantiation");
        assert!(matches!(
            error,
            CompiledBinaryMarketError::ArgumentInstantiation(_)
        ));
    }

    #[test]
    #[ignore = "manual compiler frontend benchmark"]
    fn benchmark_cached_template_instantiation_against_full_compilation() {
        use std::hint::black_box;
        use std::time::Instant;

        const SAMPLES: usize = 5;

        let arguments = contract_arguments(params()).expect("derive benchmark arguments");
        let template = binary_market_template().expect("analyze cached template");

        let cached_start = Instant::now();
        let mut cached_cmr = None;
        for _ in 0..SAMPLES {
            let compiled = template
                .instantiate(arguments.build_arguments(), false)
                .expect("instantiate cached template");
            cached_cmr = Some(black_box(compiled.commit().cmr()));
        }
        let cached_elapsed = cached_start.elapsed();

        let full_start = Instant::now();
        let mut full_cmr = None;
        for _ in 0..SAMPLES {
            let compiled = CompiledProgram::new_with_unstable(
                BinaryMarketProgram::SOURCE,
                &UnstableFeatures::new([UnstableFeature::Imports]),
                arguments.build_arguments(),
                false,
                Box::new(ElementsJetHinter),
            )
            .expect("compile source from scratch");
            full_cmr = Some(black_box(compiled.commit().cmr()));
        }
        let full_elapsed = full_start.elapsed();

        assert_eq!(cached_cmr, full_cmr);
        eprintln!(
            "samples={SAMPLES} cached_template_ns={} full_compilation_ns={}",
            cached_elapsed.as_nanos(),
            full_elapsed.as_nanos()
        );
    }

    #[test]
    fn witness_utxo_collection_preserves_pset_input_order() {
        let expected = vec![
            txout(0x61, Script::from(vec![0x51])),
            txout(0x62, Script::from(vec![0x52])),
            txout(0x63, Script::from(vec![0x53])),
        ];
        let pset = pset_with_witness_utxos(expected.iter().cloned().map(Some));

        assert_eq!(
            collect_witness_utxos(&pset).expect("complete witness UTXOs"),
            expected
        );
    }

    #[test]
    fn missing_witness_utxo_before_target_does_not_shift_indices() {
        let params = params();
        let compiled = CompiledBinaryMarket::new(params).expect("compile market");
        let slot = BinaryMarketSlot::UnresolvedCollateral;
        let target = txout(0x61, compiled.slot(slot).script_pubkey().clone());
        let pset = pset_with_witness_utxos([None, Some(target)]);
        let network = SimplicityNetwork::ElementsRegtest {
            policy_asset: params.collateral_asset_id,
        };

        assert!(matches!(
            compiled.environment(slot, &pset, 1, &network),
            Err(CompiledBinaryMarketExecutionError::MissingWitnessUtxo { input_index: 0 })
        ));
    }

    #[test]
    fn missing_witness_utxo_at_target_reports_target_index() {
        let params = params();
        let compiled = CompiledBinaryMarket::new(params).expect("compile market");
        let slot = BinaryMarketSlot::UnresolvedCollateral;
        let decoy = txout(0x61, Script::from(vec![0x51]));
        let pset = pset_with_witness_utxos([Some(decoy), None]);
        let network = SimplicityNetwork::ElementsRegtest {
            policy_asset: params.collateral_asset_id,
        };

        assert!(matches!(
            compiled.environment(slot, &pset, 1, &network),
            Err(CompiledBinaryMarketExecutionError::MissingWitnessUtxo { input_index: 1 })
        ));
    }

    #[test]
    fn missing_witness_utxo_after_target_is_also_rejected() {
        let params = params();
        let compiled = CompiledBinaryMarket::new(params).expect("compile market");
        let slot = BinaryMarketSlot::UnresolvedCollateral;
        let target = txout(0x61, compiled.slot(slot).script_pubkey().clone());
        let pset = pset_with_witness_utxos([Some(target), None]);
        let network = SimplicityNetwork::ElementsRegtest {
            policy_asset: params.collateral_asset_id,
        };

        assert!(matches!(
            compiled.environment(slot, &pset, 0, &network),
            Err(CompiledBinaryMarketExecutionError::MissingWitnessUtxo { input_index: 1 })
        ));
    }

    #[test]
    fn environment_uses_the_target_inputs_installed_annex() {
        let params = params();
        let compiled = CompiledBinaryMarket::new(params).expect("compile market");
        let slot = BinaryMarketSlot::UnresolvedCollateral;
        let target = txout(0x61, compiled.slot(slot).script_pubkey().clone());
        let mut pset = pset_with_witness_utxos([Some(target)]);
        let annex = vec![TAPROOT_ANNEX_TAG, 0xaa, 0xbb];
        pset.inputs_mut()[0].final_script_witness = Some(vec![
            vec![0x01],
            vec![0x02],
            vec![0x03],
            vec![0x04],
            annex.clone(),
        ]);
        let network = SimplicityNetwork::ElementsRegtest {
            policy_asset: params.collateral_asset_id,
        };

        let environment = compiled
            .environment(slot, &pset, 0, &network)
            .expect("build annex-bearing environment");
        assert_eq!(environment.annex(), Some(&annex));
        assert_eq!(
            environment.tx().input[0].witness.script_witness.last(),
            Some(&annex)
        );
    }

    #[test]
    fn nonfinal_annex_tag_is_not_treated_as_the_current_annex() {
        let mut pset = pset_with_witness_utxos([Some(txout(0x61, Script::new()))]);
        pset.inputs_mut()[0].final_script_witness =
            Some(vec![vec![TAPROOT_ANNEX_TAG, 0xaa], vec![0x04]]);

        assert_eq!(current_input_annex(&pset, 0), None);
    }

    #[test]
    fn one_item_key_path_witness_is_not_treated_as_an_annex() {
        let mut pset = pset_with_witness_utxos([Some(txout(0x61, Script::new()))]);
        pset.inputs_mut()[0].final_script_witness = Some(vec![vec![TAPROOT_ANNEX_TAG, 0xaa]]);

        assert_eq!(current_input_annex(&pset, 0), None);
    }

    #[test]
    fn execute_finalized_requires_an_installed_final_witness() {
        let params = params();
        let compiled = CompiledBinaryMarket::new(params).expect("compile market");
        let slot = BinaryMarketSlot::UnresolvedCollateral;
        let target = txout(0x61, compiled.slot(slot).script_pubkey().clone());
        let pset = pset_with_witness_utxos([Some(target)]);
        let network = SimplicityNetwork::ElementsRegtest {
            policy_asset: params.collateral_asset_id,
        };

        assert!(matches!(
            compiled.execute_finalized(slot, &pset, 0, &network),
            Err(CompiledBinaryMarketExecutionError::MissingFinalScriptWitness { input_index: 0 })
        ));
    }

    #[test]
    fn execute_finalized_rejects_a_different_program_cmr() {
        let params = params();
        let compiled = CompiledBinaryMarket::new(params).expect("compile market");
        let slot = BinaryMarketSlot::UnresolvedCollateral;
        let finalized = simple_finalized_spend(compiled.slot(slot).control_block());
        assert_ne!(finalized.cmr(), compiled.cmr());
        let actual = finalized.cmr();
        let mut pset = pset_with_witness_utxos([Some(txout(
            0x61,
            compiled.slot(slot).script_pubkey().clone(),
        ))]);
        pset.inputs_mut()[0].final_script_witness = Some(finalized.into_witness_stack());
        let network = SimplicityNetwork::ElementsRegtest {
            policy_asset: params.collateral_asset_id,
        };

        assert!(matches!(
            compiled.execute_finalized(slot, &pset, 0, &network),
            Err(CompiledBinaryMarketExecutionError::CmrMismatch {
                expected,
                actual: found,
            }) if expected == compiled.cmr() && found == actual
        ));
    }

    #[test]
    fn execute_finalized_rejects_a_different_typed_control_block() {
        let params = params();
        let mut compiled = CompiledBinaryMarket::new(params).expect("compile market");
        let slot = BinaryMarketSlot::UnresolvedCollateral;
        let other_slot = BinaryMarketSlot::ResolvedYesCollateral;
        let finalized = simple_finalized_spend(compiled.slot(other_slot).control_block());

        // Isolate control-block validation by making this test-only clone expect
        // the simple program's otherwise valid CMR.
        compiled.cmr = finalized.cmr();
        let expected = compiled.slot(slot).control_block().clone();
        let actual = finalized.control_block().clone();
        assert_ne!(expected, actual);
        let mut pset = pset_with_witness_utxos([Some(txout(
            0x61,
            compiled.slot(slot).script_pubkey().clone(),
        ))]);
        pset.inputs_mut()[0].final_script_witness = Some(finalized.into_witness_stack());
        let network = SimplicityNetwork::ElementsRegtest {
            policy_asset: params.collateral_asset_id,
        };

        assert!(matches!(
            compiled.execute_finalized(slot, &pset, 0, &network),
            Err(CompiledBinaryMarketExecutionError::ControlBlockMismatch {
                expected: found_expected,
                actual: found_actual,
            }) if *found_expected == expected && *found_actual == actual
        ));
    }

    #[test]
    fn generated_arguments_preserve_internal_asset_bytes_and_scalars() {
        let params = params();
        let compiled = CompiledBinaryMarket::new(params).expect("compile market");
        assert_eq!(
            compiled.arguments.oracle_public_key,
            params.oracle_public_key
        );
        assert_eq!(
            compiled.arguments.oracle_message_yes,
            oracle_message(
                params.yes_token_asset_id,
                params.no_token_asset_id,
                OracleOutcome::Yes,
            )
        );
        assert_eq!(
            compiled.arguments.oracle_message_no,
            oracle_message(
                params.yes_token_asset_id,
                params.no_token_asset_id,
                OracleOutcome::No,
            )
        );
        assert_eq!(
            compiled.arguments.collateral_asset_id,
            params.collateral_asset_id.into_inner().to_byte_array()
        );
        assert_eq!(
            compiled.arguments.yes_token_asset_id,
            params.yes_token_asset_id.into_inner().to_byte_array()
        );
        assert_eq!(
            compiled.arguments.no_token_asset_id,
            params.no_token_asset_id.into_inner().to_byte_array()
        );
        assert_eq!(
            compiled.arguments.yes_reissuance_token_id,
            params.yes_reissuance_token_id.into_inner().to_byte_array()
        );
        assert_eq!(
            compiled.arguments.no_reissuance_token_id,
            params.no_reissuance_token_id.into_inner().to_byte_array()
        );
        assert_eq!(compiled.arguments.base_payout, params.base_payout);
        assert_eq!(compiled.arguments.expiry_height, params.expiry_height);

        let yes = rt_commitment_arguments(params.yes_reissuance_token_id, RtLeg::Yes)
            .expect("YES RT commitments");
        assert_eq!(
            (
                compiled.arguments.yes_rt_asset_a_parity,
                compiled.arguments.yes_rt_asset_a_x
            ),
            (yes.asset_a.parity, yes.asset_a.x)
        );
        assert_eq!(
            (
                compiled.arguments.yes_rt_asset_b_parity,
                compiled.arguments.yes_rt_asset_b_x
            ),
            (yes.asset_b.parity, yes.asset_b.x)
        );
        assert_eq!(
            (
                compiled.arguments.yes_rt_value_parity,
                compiled.arguments.yes_rt_value_x
            ),
            (yes.value.parity, yes.value.x)
        );

        let no = rt_commitment_arguments(params.no_reissuance_token_id, RtLeg::No)
            .expect("NO RT commitments");
        assert_eq!(
            (
                compiled.arguments.no_rt_asset_a_parity,
                compiled.arguments.no_rt_asset_a_x
            ),
            (no.asset_a.parity, no.asset_a.x)
        );
        assert_eq!(
            (
                compiled.arguments.no_rt_asset_b_parity,
                compiled.arguments.no_rt_asset_b_x
            ),
            (no.asset_b.parity, no.asset_b.x)
        );
        assert_eq!(
            (
                compiled.arguments.no_rt_value_parity,
                compiled.arguments.no_rt_value_x
            ),
            (no.value.parity, no.value.x)
        );
    }

    #[test]
    fn every_slot_has_exact_storage_and_a_distinct_generated_parity_script() {
        let params = params();
        let compiled = CompiledBinaryMarket::new(params).expect("compile market");
        let network = SimplicityNetwork::ElementsRegtest {
            policy_asset: params.collateral_asset_id,
        };
        let secp = Secp256k1::verification_only();
        let program_leaf = Script::from(compiled.cmr().to_vec());
        let mut scripts = HashSet::new();

        for slot in BinaryMarketSlot::ALL {
            let materialized = compiled.slot(slot);
            assert_eq!(materialized.storage_word(), slot.storage_word());
            assert_eq!(materialized.control_block().size(), 65);
            assert_eq!(
                materialized.script_pubkey(),
                &compiled.program(slot).get_script_pubkey(&network),
                "direct fallible Taproot construction diverged for {slot:?}"
            );
            let output_key =
                XOnlyPublicKey::from_slice(&materialized.script_pubkey().as_bytes()[2..34])
                    .expect("P2TR output key");
            assert!(materialized.control_block().verify_taproot_commitment(
                &secp,
                &TweakedPublicKey::new(output_key),
                &program_leaf,
            ));
            assert!(scripts.insert(materialized.script_pubkey().as_bytes().to_vec()));
        }
        assert_eq!(scripts.len(), BinaryMarketSlot::ALL.len());
    }

    #[test]
    fn cmr_is_deterministic() {
        let params = params();
        let first = CompiledBinaryMarket::new(params).expect("first compile");
        let second = CompiledBinaryMarket::new(params).expect("second compile");
        assert_eq!(first.cmr(), second.cmr());
        assert_eq!(
            first.cmr(),
            [
                0x00, 0xe4, 0xba, 0xb6, 0x9c, 0xe3, 0xf9, 0xd6, 0x34, 0x6f, 0xe6, 0x7f, 0xe1, 0x86,
                0xd4, 0xef, 0x08, 0xd3, 0xc6, 0x08, 0xef, 0x31, 0xb4, 0xc4, 0xad, 0xe8, 0xa4, 0x74,
                0x59, 0x85, 0x24, 0x47,
            ]
        );

        let mut changed = params;
        changed.expiry_height += 1;
        assert_ne!(
            first.cmr(),
            CompiledBinaryMarket::new(changed)
                .expect("changed compile")
                .cmr()
        );
    }

    #[test]
    fn invalid_params_fail_before_program_materialization() {
        let mut invalid = params();
        invalid.base_payout = 999;
        assert!(matches!(
            CompiledBinaryMarket::new(invalid).expect_err("invalid payout"),
            CompiledBinaryMarketError::InvalidBasePayout { base_payout: 999 }
        ));

        invalid = params();
        invalid.expiry_height = 500_000_000;
        assert!(matches!(
            CompiledBinaryMarket::new(invalid).expect_err("invalid expiry"),
            CompiledBinaryMarketError::InvalidExpiryHeight {
                expiry_height: 500_000_000
            }
        ));

        invalid = params();
        invalid.no_token_asset_id = invalid.yes_token_asset_id;
        assert!(matches!(
            CompiledBinaryMarket::new(invalid).expect_err("duplicate assets"),
            CompiledBinaryMarketError::DuplicateAssetIds
        ));
    }
}

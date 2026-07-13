//! Validation-first compilation of the canonical binary-market covenant.

use std::collections::HashSet;

use deadcat_types::ContractId;
use elements::hashes::{Hash as _, HashEngine as _, sha256};
use elements::secp256k1_zkp::{Secp256k1, XOnlyPublicKey};
use elements::taproot::{ControlBlock, TaprootBuilder, TaprootBuilderError};
use elements::{AssetId, Script, Txid};
use simplex::program::ArgumentsTrait as _;
use simplex::simplicityhl::CompiledProgram;
use simplex::simplicityhl::simplicity::{HasCmr as _, leaf_version};
use thiserror::Error;

use super::{BinaryMarketEconomics, BinaryMarketParams, BinaryMarketSlot};
use crate::artifacts::binary_market::{BinaryMarketProgram, derived_binary_market};

const NUMS_INTERNAL_KEY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

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
    arguments: derived_binary_market::BinaryMarketArguments,
    cmr: [u8; 32],
    slots: [CompiledBinaryMarketSlot; 8],
}

impl CompiledBinaryMarket {
    /// Validate parameters and compile the canonical v1 covenant.
    pub fn new(params: BinaryMarketParams) -> Result<Self, CompiledBinaryMarketError> {
        validate_params(params)?;

        let arguments = contract_arguments(params);
        let compiled = CompiledProgram::new(
            BinaryMarketProgram::SOURCE,
            arguments.build_arguments(),
            false,
        )
        .map_err(CompiledBinaryMarketError::Compilation)?;
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
            arguments,
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
    pub const fn contract_id(&self, creation_txid: Txid) -> ContractId {
        ContractId {
            cmr: self.cmr,
            creation_txid,
        }
    }

    #[must_use]
    pub const fn slots(&self) -> &[CompiledBinaryMarketSlot; 8] {
        &self.slots
    }

    #[must_use]
    pub fn slot(&self, slot: BinaryMarketSlot) -> &CompiledBinaryMarketSlot {
        &self.slots[slot as usize]
    }

    /// Recreate the generated smplx program at one validated storage slot.
    ///
    /// This is intended for execution/finalization. Script discovery should use
    /// [`Self::slot`], whose value was constructed without panic-based helpers.
    #[must_use]
    #[allow(unused_must_use)]
    pub fn program(&self, slot: BinaryMarketSlot) -> BinaryMarketProgram {
        let mut program = BinaryMarketProgram::new(self.arguments.clone()).with_storage_capacity(1);
        program.set_storage_at(0, slot.storage_word());
        program
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CompiledBinaryMarketError {
    #[error("{base_payout} is not a canonical v1 base payout")]
    InvalidBasePayout { base_payout: u64 },
    #[error("expiry height {expiry_height} is outside 1..500,000,000")]
    InvalidExpiryHeight { expiry_height: u32 },
    #[error("oracle public key is not a valid x-only secp256k1 key")]
    InvalidOraclePublicKey,
    #[error("binary-market collateral, outcome-token, and RT asset IDs must be distinct")]
    DuplicateAssetIds,
    #[error("failed to compile binary-market SimplicityHL: {0}")]
    Compilation(String),
    #[error("failed to build binary-market Taproot tree: {0}")]
    Taproot(#[from] TaprootBuilderError),
    #[error("compiled Taproot tree did not contain its program leaf")]
    MissingControlBlock,
    #[error("the fixed binary-market NUMS internal key is invalid")]
    InvalidNumsInternalKey,
    #[error("compiled binary-market slot count was not eight")]
    SlotCountInvariant,
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

fn contract_arguments(params: BinaryMarketParams) -> derived_binary_market::BinaryMarketArguments {
    derived_binary_market::BinaryMarketArguments {
        oracle_public_key: params.oracle_public_key,
        collateral_asset_id: params.collateral_asset_id.into_inner().to_byte_array(),
        yes_token_asset_id: params.yes_token_asset_id.into_inner().to_byte_array(),
        no_token_asset_id: params.no_token_asset_id.into_inner().to_byte_array(),
        yes_reissuance_token_id: params.yes_reissuance_token_id.into_inner().to_byte_array(),
        no_reissuance_token_id: params.no_reissuance_token_id.into_inner().to_byte_array(),
        base_payout: params.base_payout,
        expiry_height: params.expiry_height,
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

    use elements::hashes::Hash as _;
    use elements::schnorr::TweakedPublicKey;
    use elements::{AssetId, Txid};
    use simplex::provider::SimplicityNetwork;

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

    #[test]
    fn generated_arguments_preserve_internal_asset_bytes_and_scalars() {
        let params = params();
        let compiled = CompiledBinaryMarket::new(params).expect("compile market");
        assert_eq!(
            compiled.arguments.oracle_public_key,
            params.oracle_public_key
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
    fn cmr_and_contract_identity_are_deterministic() {
        let params = params();
        let first = CompiledBinaryMarket::new(params).expect("first compile");
        let second = CompiledBinaryMarket::new(params).expect("second compile");
        assert_eq!(first.cmr(), second.cmr());
        assert_eq!(
            first.cmr(),
            [
                0xd7, 0xb0, 0xbf, 0x24, 0x7d, 0x66, 0xc9, 0xe7, 0xd3, 0xb6, 0x8b, 0xe5, 0x53, 0xb5,
                0x42, 0xc5, 0xc9, 0xbb, 0x5b, 0xf9, 0x2c, 0x10, 0x65, 0x6e, 0xe0, 0x83, 0xe3, 0x5e,
                0x82, 0x3b, 0x4f, 0xcc,
            ]
        );

        let creation_txid = Txid::from_byte_array([0x77; 32]);
        assert_eq!(
            first.contract_id(creation_txid),
            ContractId {
                cmr: first.cmr(),
                creation_txid,
            }
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
        assert_eq!(
            CompiledBinaryMarket::new(invalid).expect_err("invalid payout"),
            CompiledBinaryMarketError::InvalidBasePayout { base_payout: 999 }
        );

        invalid = params();
        invalid.expiry_height = 500_000_000;
        assert_eq!(
            CompiledBinaryMarket::new(invalid).expect_err("invalid expiry"),
            CompiledBinaryMarketError::InvalidExpiryHeight {
                expiry_height: 500_000_000,
            }
        );

        invalid = params();
        invalid.no_token_asset_id = invalid.yes_token_asset_id;
        assert_eq!(
            CompiledBinaryMarket::new(invalid).expect_err("duplicate assets"),
            CompiledBinaryMarketError::DuplicateAssetIds
        );
    }
}

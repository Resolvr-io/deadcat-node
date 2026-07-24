//! Validation-first compilation of the canonical maker-order covenant.

use elements::Script;
use elements::secp256k1_zkp::{Scalar, Secp256k1, XOnlyPublicKey};
use elements::taproot::{ControlBlock, TaprootBuilder, TaprootBuilderError};
use sha2::{Digest as _, Sha256};
use simplex::program::ArgumentsTrait as _;
use simplex::simplicityhl::CompiledProgram;
use simplex::simplicityhl::simplicity::{HasCmr as _, leaf_version};
use thiserror::Error;

use super::{
    MakerOrderParams, ORDER_CANCEL_TWEAK_DOMAIN, ORDER_RECEIVE_TWEAK_DOMAIN, validate_params,
};
use crate::artifacts::maker_order::{MakerOrderProgram, derived_maker_order};
use crate::rt::hash_to_scalar;

/// A validated order covenant and its maker-cancellable Taproot output.
#[derive(Clone, Debug)]
pub struct CompiledMakerOrder {
    params: MakerOrderParams,
    arguments: derived_maker_order::MakerOrderArguments,
    cmr: [u8; 32],
    internal_key: XOnlyPublicKey,
    maker_receive_spk: Script,
    script_pubkey: Script,
    control_block: ControlBlock,
}

impl CompiledMakerOrder {
    pub fn new(params: MakerOrderParams) -> Result<Self, CompiledMakerOrderError> {
        validate_params(params).map_err(CompiledMakerOrderError::InvalidEconomics)?;
        let maker_key = XOnlyPublicKey::from_slice(&params.maker_pubkey)
            .map_err(|_| CompiledMakerOrderError::InvalidMakerPublicKey)?;
        let secp = Secp256k1::verification_only();
        let internal_key = tweak_key(
            &secp,
            maker_key,
            ORDER_CANCEL_TWEAK_DOMAIN,
            params.instance_id,
        )?;
        let receive_key = tweak_key(
            &secp,
            maker_key,
            ORDER_RECEIVE_TWEAK_DOMAIN,
            params.instance_id,
        )?;
        let maker_receive_spk = p2tr_key_script(receive_key);
        let maker_receive_spk_hash = Sha256::digest(maker_receive_spk.as_bytes()).into();
        let arguments = contract_arguments(params, maker_receive_spk_hash);
        let compiled = CompiledProgram::new(
            MakerOrderProgram::SOURCE,
            arguments.build_arguments(),
            false,
        )
        .map_err(CompiledMakerOrderError::Compilation)?;
        let cmr_node = compiled.commit().cmr();
        let mut cmr = [0_u8; 32];
        cmr.copy_from_slice(cmr_node.as_ref());

        let version = leaf_version();
        let program_leaf_script = Script::from(cmr.to_vec());
        let spend_info = TaprootBuilder::new()
            .add_leaf_with_ver(0, program_leaf_script.clone(), version)?
            .finalize(&secp, internal_key)?;
        let control_block = spend_info
            .control_block(&(program_leaf_script, version))
            .ok_or(CompiledMakerOrderError::MissingControlBlock)?;
        let script_pubkey = Script::new_v1_p2tr_tweaked(spend_info.output_key());

        Ok(Self {
            params,
            arguments,
            cmr,
            internal_key,
            maker_receive_spk,
            script_pubkey,
            control_block,
        })
    }

    #[must_use]
    pub const fn params(&self) -> MakerOrderParams {
        self.params
    }

    #[must_use]
    pub const fn cmr(&self) -> [u8; 32] {
        self.cmr
    }

    #[must_use]
    pub const fn internal_key(&self) -> XOnlyPublicKey {
        self.internal_key
    }

    #[must_use]
    pub fn maker_receive_spk(&self) -> &Script {
        &self.maker_receive_spk
    }

    #[must_use]
    pub fn script_pubkey(&self) -> &Script {
        &self.script_pubkey
    }

    #[must_use]
    pub const fn control_block(&self) -> &ControlBlock {
        &self.control_block
    }

    /// Recreate the validated generated program for witness satisfaction.
    #[must_use]
    pub fn program(&self) -> MakerOrderProgram {
        MakerOrderProgram::new(self.arguments.clone()).with_taproot_pubkey(self.internal_key)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CompiledMakerOrderError {
    #[error("invalid maker-order economics: {0}")]
    InvalidEconomics(super::MakerOrderError),
    #[error("maker public key is not a valid x-only secp256k1 key")]
    InvalidMakerPublicKey,
    #[error("derived maker-order tweak is not a valid scalar")]
    InvalidTweakScalar,
    #[error("derived maker-order key is the point at infinity")]
    TweakedKeyAtInfinity,
    #[error("failed to compile maker-order SimplicityHL: {0}")]
    Compilation(String),
    #[error("failed to build maker-order Taproot tree: {0}")]
    Taproot(#[from] TaprootBuilderError),
    #[error("compiled Taproot tree did not contain its program leaf")]
    MissingControlBlock,
}

fn contract_arguments(
    params: MakerOrderParams,
    maker_receive_spk_hash: [u8; 32],
) -> derived_maker_order::MakerOrderArguments {
    derived_maker_order::MakerOrderArguments {
        base_asset_id: params.base_asset_id.into_inner().to_byte_array(),
        quote_asset_id: params.quote_asset_id.into_inner().to_byte_array(),
        price: params.price,
        min_active_base: params.min_active_base,
        maker_receive_spk_hash,
        direction_sell_quote: params.direction == deadcat_types::OrderDirection::SellQuote,
    }
}

fn tweak_key(
    secp: &Secp256k1<elements::secp256k1_zkp::VerifyOnly>,
    key: XOnlyPublicKey,
    domain: &str,
    instance_id: [u8; 32],
) -> Result<XOnlyPublicKey, CompiledMakerOrderError> {
    let tweak = Scalar::from_be_bytes(hash_to_scalar(domain, &instance_id))
        .map_err(|_| CompiledMakerOrderError::InvalidTweakScalar)?;
    key.add_tweak(secp, &tweak)
        .map(|(key, _)| key)
        .map_err(|_| CompiledMakerOrderError::TweakedKeyAtInfinity)
}

fn p2tr_key_script(key: XOnlyPublicKey) -> Script {
    let mut bytes = Vec::with_capacity(34);
    bytes.extend_from_slice(&[0x51, 0x20]);
    bytes.extend_from_slice(&key.serialize());
    Script::from(bytes)
}

#[cfg(test)]
mod tests {
    use elements::AssetId;
    use elements::schnorr::TweakedPublicKey;
    use simplex::provider::SimplicityNetwork;

    use super::*;

    const VALID_XONLY: [u8; 32] = [
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a,
        0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80,
        0x3a, 0xc0,
    ];

    fn asset(byte: u8) -> AssetId {
        AssetId::from_slice(&[byte; 32]).expect("asset")
    }

    fn params() -> MakerOrderParams {
        MakerOrderParams {
            base_asset_id: asset(0x11),
            quote_asset_id: asset(0x22),
            price: 12_345,
            min_active_base: 67,
            direction: deadcat_types::OrderDirection::SellQuote,
            instance_id: [0x33; 32],
            maker_pubkey: VALID_XONLY,
        }
    }

    #[test]
    fn direct_taproot_materialization_matches_generated_program() {
        let params = params();
        let compiled = CompiledMakerOrder::new(params).expect("compile");
        let network = SimplicityNetwork::ElementsRegtest {
            policy_asset: params.quote_asset_id,
        };
        assert_eq!(
            compiled.script_pubkey(),
            &compiled.program().get_script_pubkey(&network)
        );
        assert_eq!(compiled.control_block().size(), 33);

        let secp = Secp256k1::verification_only();
        let output_key = XOnlyPublicKey::from_slice(&compiled.script_pubkey().as_bytes()[2..34])
            .expect("output key");
        assert!(compiled.control_block().verify_taproot_commitment(
            &secp,
            &TweakedPublicKey::new(output_key),
            &Script::from(compiled.cmr().to_vec()),
        ));
    }

    #[test]
    fn params_map_exactly_and_compilation_is_deterministic() {
        let params = params();
        let first = CompiledMakerOrder::new(params).expect("compile");
        let second = CompiledMakerOrder::new(params).expect("compile");
        assert_eq!(first.cmr(), second.cmr());
        assert_eq!(
            first.cmr(),
            [
                0xd1, 0xde, 0x83, 0x2f, 0x42, 0x54, 0x7f, 0xd6, 0xb2, 0xe9, 0xd3, 0xdb, 0x51, 0x7f,
                0x9e, 0x3f, 0x8f, 0x8f, 0x87, 0xe0, 0xf4, 0xf3, 0xac, 0x3e, 0x4e, 0x7c, 0x99, 0xe1,
                0x17, 0xf9, 0xcb, 0x63,
            ]
        );
        assert_eq!(
            first.arguments.base_asset_id,
            params.base_asset_id.into_inner().to_byte_array()
        );
        assert_eq!(first.arguments.price, params.price);
        assert!(first.arguments.direction_sell_quote);
    }

    #[test]
    fn economics_instance_and_maker_key_change_commitments() {
        let params = params();
        let original = CompiledMakerOrder::new(params).expect("compile");
        let mut changed_direction = params;
        changed_direction.direction = deadcat_types::OrderDirection::SellBase;
        assert_ne!(
            original.cmr(),
            CompiledMakerOrder::new(changed_direction)
                .expect("compile")
                .cmr()
        );

        let mut changed_instance = params;
        changed_instance.instance_id = [0x44; 32];
        let changed_instance = CompiledMakerOrder::new(changed_instance).expect("compile");
        assert_ne!(original.cmr(), changed_instance.cmr());
        assert_ne!(original.script_pubkey(), changed_instance.script_pubkey());
        assert_ne!(
            original.maker_receive_spk(),
            changed_instance.maker_receive_spk()
        );

        let mut changed_maker = params;
        changed_maker.maker_pubkey = [2; 32];
        let changed_maker = CompiledMakerOrder::new(changed_maker).expect("compile");
        assert_ne!(original.cmr(), changed_maker.cmr());
        assert_ne!(original.script_pubkey(), changed_maker.script_pubkey());
        assert_ne!(
            original.maker_receive_spk(),
            changed_maker.maker_receive_spk()
        );
    }

    #[test]
    fn invalid_params_fail_before_materialization() {
        let mut invalid = params();
        invalid.price = 0;
        assert_eq!(
            CompiledMakerOrder::new(invalid).expect_err("zero price"),
            CompiledMakerOrderError::InvalidEconomics(super::super::MakerOrderError::ZeroPrice)
        );

        invalid = params();
        invalid.maker_pubkey = [0; 32];
        assert_eq!(
            CompiledMakerOrder::new(invalid).expect_err("invalid key"),
            CompiledMakerOrderError::InvalidMakerPublicKey
        );
    }
}

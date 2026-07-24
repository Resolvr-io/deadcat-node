//! Mnemonic-derived Deadcat order ownership and recovery keys.

use bip39::{Language, Mnemonic};
use deadcat_contracts::maker_order::{ORDER_CANCEL_TWEAK_DOMAIN, ORDER_RECEIVE_TWEAK_DOMAIN};
use deadcat_contracts::recovery::{OrderRecoveryHint, ParentMarketRef, order_mask};
use deadcat_contracts::rt::hash_to_scalar;
use deadcat_types::{MakerOrderParams, OrderDirection, OrderSide};
use elements::bitcoin::NetworkKind;
use elements::bitcoin::bip32::{ChildNumber, Xpriv};
use elements::bitcoin::secp256k1::{Parity, Scalar, Secp256k1};
use elements::{AssetId, Script};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const DEADCAT_PURPOSE: u32 = 86;
const DEADCAT_COIN_TYPE: u32 = 1_145_258_324;
const SECRET_CHILD: u32 = 0;
const ORDER_CHILD: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MakerOrderTerms {
    pub base_asset_id: AssetId,
    pub quote_asset_id: AssetId,
    pub price: u32,
    pub min_active_base: u32,
    pub direction: OrderDirection,
}

/// Secret material required to cancel an order and spend its private receive
/// output. This type intentionally does not implement `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct OrderKeyMaterial {
    cancel_secret_key: [u8; 32],
    receive_secret_key: [u8; 32],
    pub instance_id: [u8; 32],
    pub maker_public_key: [u8; 32],
    pub maker_was_odd: bool,
    pub cancel_tweak: [u8; 32],
    pub cancel_public_key: [u8; 32],
    pub cancel_was_odd: bool,
    pub receive_tweak: [u8; 32],
    pub receive_public_key: [u8; 32],
    pub receive_was_odd: bool,
    pub maker_receive_spk: Script,
    pub maker_receive_spk_hash: [u8; 32],
}

/// All deterministic owner data needed to create and later recover one order.
#[derive(Clone, PartialEq, Eq)]
pub struct DerivedOwnedOrder {
    pub params: MakerOrderParams,
    pub recovery_hint: OrderRecoveryHint,
    pub keys: OrderKeyMaterial,
}

impl OrderKeyMaterial {
    #[must_use]
    pub fn maker_secret_key(&self) -> &[u8; 32] {
        &self.cancel_secret_key
    }

    #[must_use]
    pub fn receive_secret_key(&self) -> &[u8; 32] {
        &self.receive_secret_key
    }

    #[must_use]
    pub fn params(&self, terms: MakerOrderTerms) -> MakerOrderParams {
        MakerOrderParams {
            base_asset_id: terms.base_asset_id,
            quote_asset_id: terms.quote_asset_id,
            price: terms.price,
            min_active_base: terms.min_active_base,
            direction: terms.direction,
            instance_id: self.instance_id,
            maker_pubkey: self.maker_public_key,
        }
    }
}

/// BIP-32 keychain rooted in a BIP-39 seed. The mnemonic and seed are not
/// retained after construction.
#[derive(Clone)]
pub struct DeadcatKeychain {
    master: Xpriv,
}

impl DeadcatKeychain {
    pub fn from_mnemonic(phrase: &str, passphrase: &str) -> Result<Self, KeyDerivationError> {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)?;
        Self::from_seed(&mnemonic.to_seed(passphrase))
    }

    pub fn from_seed(seed: &[u8]) -> Result<Self, KeyDerivationError> {
        Ok(Self {
            master: Xpriv::new_master(NetworkKind::Main, seed)?,
        })
    }

    pub fn deadcat_secret_key(&self) -> Result<[u8; 32], KeyDerivationError> {
        let key = self.derive(&[
            hardened(DEADCAT_PURPOSE)?,
            hardened(DEADCAT_COIN_TYPE)?,
            hardened(SECRET_CHILD)?,
        ])?;
        Ok(key.private_key.secret_bytes())
    }

    pub fn derive_order(
        &self,
        order_index: u16,
        instance_id: [u8; 32],
    ) -> Result<OrderKeyMaterial, KeyDerivationError> {
        let maker = self.derive(&[
            hardened(DEADCAT_PURPOSE)?,
            hardened(DEADCAT_COIN_TYPE)?,
            hardened(ORDER_CHILD)?,
            hardened(u32::from(order_index))?,
        ])?;
        let maker_secret = maker.private_key;
        let secp = Secp256k1::new();
        let (maker_public, maker_parity) = maker_secret.x_only_public_key(&secp);
        let maker_public_key = maker_public.serialize();

        let cancel_tweak = hash_to_scalar(ORDER_CANCEL_TWEAK_DOMAIN, &instance_id);
        let cancel_scalar = Scalar::from_be_bytes(cancel_tweak)
            .map_err(|_| KeyDerivationError::InvalidTweakScalar)?;
        let normalized_maker_secret = match maker_parity {
            Parity::Even => maker_secret,
            Parity::Odd => maker_secret.negate(),
        };
        let cancel_secret = normalized_maker_secret
            .add_tweak(&cancel_scalar)
            .map_err(|_| KeyDerivationError::TweakedKeyAtInfinity)?;
        let (cancel_public, cancel_parity) = cancel_secret.x_only_public_key(&secp);

        let receive_tweak = hash_to_scalar(ORDER_RECEIVE_TWEAK_DOMAIN, &instance_id);
        let receive_scalar = Scalar::from_be_bytes(receive_tweak)
            .map_err(|_| KeyDerivationError::InvalidTweakScalar)?;
        let receive_secret = normalized_maker_secret
            .add_tweak(&receive_scalar)
            .map_err(|_| KeyDerivationError::TweakedKeyAtInfinity)?;
        let (receive_public, receive_parity) = receive_secret.x_only_public_key(&secp);
        let receive_public_key = receive_public.serialize();

        let mut script_bytes = Vec::with_capacity(34);
        script_bytes.extend_from_slice(&[0x51, 0x20]);
        script_bytes.extend_from_slice(&receive_public_key);
        let maker_receive_spk = Script::from(script_bytes);
        let maker_receive_spk_hash = Sha256::digest(maker_receive_spk.as_bytes()).into();

        Ok(OrderKeyMaterial {
            cancel_secret_key: cancel_secret.secret_bytes(),
            receive_secret_key: receive_secret.secret_bytes(),
            instance_id,
            maker_public_key,
            maker_was_odd: maker_parity == Parity::Odd,
            cancel_tweak,
            cancel_public_key: cancel_public.serialize(),
            cancel_was_odd: cancel_parity == Parity::Odd,
            receive_tweak,
            receive_public_key,
            receive_was_odd: receive_parity == Parity::Odd,
            maker_receive_spk,
            maker_receive_spk_hash,
        })
    }

    /// Derive keys, public contract parameters, and the masked chain-recovery
    /// hint together so callers cannot accidentally mix order indices.
    pub fn derive_owned_order(
        &self,
        order_index: u16,
        parent_market: ParentMarketRef,
        side: OrderSide,
        terms: MakerOrderTerms,
        instance_id: [u8; 32],
    ) -> Result<DerivedOwnedOrder, KeyDerivationError> {
        let keys = self.derive_order(order_index, instance_id)?;
        let params = keys.params(terms);
        let mut recovery_hint = OrderRecoveryHint {
            side,
            direction: terms.direction,
            masked_order_index: 0,
            parent_market,
            price: terms.price,
            min_active_base: terms.min_active_base,
            maker_pubkey: keys.maker_public_key,
        };
        recovery_hint.masked_order_index =
            order_index ^ order_mask(recovery_hint, &self.deadcat_secret_key()?);
        Ok(DerivedOwnedOrder {
            params,
            recovery_hint,
            keys,
        })
    }

    fn derive(&self, path: &[ChildNumber]) -> Result<Xpriv, KeyDerivationError> {
        Ok(self.master.derive_priv(&Secp256k1::new(), &path)?)
    }
}

fn hardened(index: u32) -> Result<ChildNumber, KeyDerivationError> {
    Ok(ChildNumber::from_hardened_idx(index)?)
}

#[derive(Debug, Error)]
pub enum KeyDerivationError {
    #[error("invalid BIP-39 mnemonic: {0}")]
    Mnemonic(#[from] bip39::Error),
    #[error("BIP-32 derivation failed: {0}")]
    Bip32(#[from] elements::bitcoin::bip32::Error),
    #[error("order tweak was not a reduced secp256k1 scalar")]
    InvalidTweakScalar,
    #[error("order receive tweak produced the point at infinity")]
    TweakedKeyAtInfinity,
}

#[cfg(test)]
mod tests {
    use deadcat_contracts::maker_order::CompiledMakerOrder;
    use deadcat_types::ContractId;
    use elements::hashes::Hash as _;
    use elements::{OutPoint, Txid};

    use super::*;

    const MNEMONIC: &str =
        "exist carry drive collect lend cereal occur much tiger just involve mean";
    const INSTANCE_A: [u8; 32] = [0x77; 32];
    const INSTANCE_B: [u8; 32] = [0x88; 32];

    fn terms() -> MakerOrderTerms {
        MakerOrderTerms {
            base_asset_id: AssetId::from_slice(&[0x11; 32]).expect("base"),
            quote_asset_id: AssetId::from_slice(&[0x22; 32]).expect("quote"),
            price: 12_345,
            min_active_base: 67,
            direction: OrderDirection::SellQuote,
        }
    }

    #[test]
    fn mnemonic_derivation_is_deterministic_and_derived_keys_match_scripts() {
        let keychain = DeadcatKeychain::from_mnemonic(MNEMONIC, "").expect("keychain");
        let first = keychain.derive_order(17, INSTANCE_A).expect("derive");
        let repeated = keychain.derive_order(17, INSTANCE_A).expect("derive");
        assert_eq!(
            keychain.deadcat_secret_key().expect("secret"),
            [
                0x2b, 0x58, 0x9d, 0xde, 0xba, 0xf4, 0x86, 0xbf, 0x1a, 0x8b, 0x13, 0xbe, 0x98, 0x6d,
                0x6e, 0xf3, 0x35, 0xa0, 0xc2, 0xc7, 0x90, 0x00, 0x8a, 0xcf, 0x44, 0x4c, 0xc1, 0x58,
                0x65, 0x30, 0x18, 0xd2,
            ]
        );
        assert_eq!(
            first.maker_public_key,
            [
                0x52, 0x53, 0x14, 0x83, 0xce, 0x28, 0x08, 0xb9, 0xa0, 0xdb, 0x2e, 0x5f, 0xb5, 0x7d,
                0x12, 0x58, 0xcf, 0x82, 0x1f, 0xe0, 0x99, 0xf7, 0x83, 0xbe, 0x29, 0x6a, 0x38, 0xa3,
                0x71, 0x66, 0xab, 0xb8,
            ]
        );
        assert!(first == repeated);
        assert_eq!(first.instance_id, INSTANCE_A);
        assert_eq!(&first.maker_receive_spk.as_bytes()[..2], &[0x51, 0x20]);
        assert_eq!(
            &first.maker_receive_spk.as_bytes()[2..],
            &first.receive_public_key
        );
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(first.maker_receive_spk.as_bytes())),
            first.maker_receive_spk_hash
        );

        let compiled = CompiledMakerOrder::new(first.params(terms())).expect("compile");
        assert_eq!(compiled.internal_key().serialize(), first.cancel_public_key);
        assert_eq!(compiled.maker_receive_spk(), &first.maker_receive_spk);
    }

    #[test]
    fn instance_id_separates_keys_without_changing_the_base_maker_key() {
        let keychain = DeadcatKeychain::from_mnemonic(MNEMONIC, "").expect("keychain");
        let a = keychain.derive_order(17, INSTANCE_A).expect("derive");
        let b = keychain.derive_order(17, INSTANCE_B).expect("derive");
        assert_eq!(a.maker_public_key, b.maker_public_key);
        assert_ne!(a.cancel_public_key, b.cancel_public_key);
        assert_ne!(a.receive_public_key, b.receive_public_key);
        assert_ne!(a.maker_receive_spk_hash, b.maker_receive_spk_hash);
    }

    #[test]
    fn different_order_indices_separate_base_and_derived_keys() {
        let keychain = DeadcatKeychain::from_mnemonic(MNEMONIC, "").expect("keychain");
        let a = keychain.derive_order(17, INSTANCE_A).expect("derive");
        let b = keychain.derive_order(18, INSTANCE_A).expect("derive");
        assert_ne!(a.maker_public_key, b.maker_public_key);
        assert_ne!(a.cancel_public_key, b.cancel_public_key);
        assert_ne!(a.receive_public_key, b.receive_public_key);
    }

    #[test]
    fn owned_order_binds_one_index_to_params_and_masked_hint() {
        let keychain = DeadcatKeychain::from_mnemonic(MNEMONIC, "").expect("keychain");
        let parent = ContractId::new(OutPoint::new(Txid::from_byte_array([0x66; 32]), 4));
        let owned = keychain
            .derive_owned_order(513, parent.into(), OrderSide::No, terms(), INSTANCE_A)
            .expect("derive");
        assert_eq!(owned.params, owned.keys.params(terms()));
        assert_eq!(owned.params.instance_id, INSTANCE_A);
        assert_eq!(owned.recovery_hint.side, OrderSide::No);
        assert_eq!(owned.recovery_hint.parent_market, parent.into());
        assert_eq!(
            owned.recovery_hint.maker_pubkey,
            owned.keys.maker_public_key
        );
        assert_eq!(
            owned
                .recovery_hint
                .unmask_index(&keychain.deadcat_secret_key().expect("secret")),
            513
        );
    }
}

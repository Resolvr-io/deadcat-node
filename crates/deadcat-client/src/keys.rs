//! Mnemonic-derived Deadcat order ownership and recovery keys.

use bip39::{Language, Mnemonic};
use deadcat_contracts::recovery::{OrderRecoveryHint, order_mask};
use deadcat_contracts::rt::hash_to_scalar;
use deadcat_types::{MakerOrderParams, OrderDirection, OrderSide};
use elements::bitcoin::NetworkKind;
use elements::bitcoin::bip32::{ChildNumber, Xpriv};
use elements::bitcoin::secp256k1::{Parity, Scalar, Secp256k1};
use elements::{AssetId, Script, Txid};
use hmac::{Hmac, Mac as _};
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
    maker_secret_key: [u8; 32],
    receive_secret_key: [u8; 32],
    pub maker_public_key: [u8; 32],
    pub maker_was_odd: bool,
    pub order_nonce: [u8; 32],
    pub order_uid: [u8; 32],
    pub order_tweak: [u8; 32],
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
        &self.maker_secret_key
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
            maker_receive_spk_hash: self.maker_receive_spk_hash,
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
        terms: MakerOrderTerms,
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

        let deadcat_secret = self.deadcat_secret_key()?;
        let order_nonce = order_nonce(&deadcat_secret, order_index);
        let order_uid = order_uid(maker_public_key, order_nonce, terms);
        let order_tweak = hash_to_scalar("deadcat/order_tweak", &order_uid);
        let tweak = Scalar::from_be_bytes(order_tweak)
            .map_err(|_| KeyDerivationError::InvalidTweakScalar)?;

        // X-only tweak addition starts from the even-Y lift of the maker key.
        let normalized_maker_secret = match maker_parity {
            Parity::Even => maker_secret,
            Parity::Odd => maker_secret.negate(),
        };
        let receive_secret = normalized_maker_secret
            .add_tweak(&tweak)
            .map_err(|_| KeyDerivationError::TweakedKeyAtInfinity)?;
        let (receive_public, receive_parity) = receive_secret.x_only_public_key(&secp);
        let receive_public_key = receive_public.serialize();

        let mut script_bytes = Vec::with_capacity(34);
        script_bytes.extend_from_slice(&[0x51, 0x20]);
        script_bytes.extend_from_slice(&receive_public_key);
        let maker_receive_spk = Script::from(script_bytes);
        let maker_receive_spk_hash = Sha256::digest(maker_receive_spk.as_bytes()).into();

        Ok(OrderKeyMaterial {
            maker_secret_key: maker_secret.secret_bytes(),
            receive_secret_key: receive_secret.secret_bytes(),
            maker_public_key,
            maker_was_odd: maker_parity == Parity::Odd,
            order_nonce,
            order_uid,
            order_tweak,
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
        market_creation_txid: Txid,
        side: OrderSide,
        terms: MakerOrderTerms,
    ) -> Result<DerivedOwnedOrder, KeyDerivationError> {
        let keys = self.derive_order(order_index, terms)?;
        let params = keys.params(terms);
        let mut recovery_hint = OrderRecoveryHint {
            side,
            direction: terms.direction,
            masked_order_index: 0,
            market_creation_txid,
            price: terms.price,
            min_active_base: terms.min_active_base,
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

#[must_use]
pub fn order_nonce(deadcat_secret_key: &[u8; 32], order_index: u16) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(deadcat_secret_key).expect("HMAC accepts any key");
    mac.update(b"deadcat/order_nonce");
    mac.update(&order_index.to_be_bytes());
    mac.finalize().into_bytes().into()
}

#[must_use]
pub fn order_uid(maker_public_key: [u8; 32], nonce: [u8; 32], terms: MakerOrderTerms) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"deadcat/order_uid");
    hasher.update(maker_public_key);
    hasher.update(nonce);
    hasher.update(terms.base_asset_id.into_inner().to_byte_array());
    hasher.update(terms.quote_asset_id.into_inner().to_byte_array());
    hasher.update(terms.price.to_be_bytes());
    hasher.update(terms.min_active_base.to_be_bytes());
    hasher.update([terms.direction.protocol_byte()]);
    hasher.finalize().into()
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
    use elements::hashes::Hash as _;

    use super::*;

    const MNEMONIC: &str =
        "exist carry drive collect lend cereal occur much tiger just involve mean";

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
    fn mnemonic_derivation_is_deterministic_and_receive_key_matches_script() {
        let keychain = DeadcatKeychain::from_mnemonic(MNEMONIC, "").expect("keychain");
        let first = keychain.derive_order(17, terms()).expect("derive");
        let repeated = keychain.derive_order(17, terms()).expect("derive");
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
        assert_eq!(
            first.order_nonce,
            [
                0xa1, 0x32, 0x57, 0xe0, 0x3f, 0xee, 0xed, 0xbf, 0xf0, 0xef, 0xe9, 0xf2, 0x17, 0x39,
                0x1b, 0x56, 0x1c, 0x79, 0x55, 0x46, 0x5b, 0xc2, 0x11, 0xcc, 0xec, 0xf9, 0xbf, 0x48,
                0x7c, 0x06, 0x00, 0xdc,
            ]
        );
        assert_eq!(
            first.order_uid,
            [
                0x1d, 0x7d, 0xef, 0xff, 0x8c, 0xde, 0xfb, 0xe4, 0xcf, 0xfd, 0xea, 0xf0, 0xf0, 0x9c,
                0x07, 0x53, 0xba, 0x9e, 0xda, 0xd0, 0x55, 0x2a, 0x2e, 0xfb, 0xf9, 0x08, 0x9a, 0x5d,
                0x2f, 0x4a, 0xff, 0x5a,
            ]
        );
        assert_eq!(
            first.order_tweak,
            [
                0x54, 0xd3, 0x0a, 0x3e, 0x1e, 0xb8, 0x6f, 0x6e, 0x6c, 0x72, 0xbd, 0xee, 0x9f, 0x5a,
                0x6e, 0xb5, 0x27, 0x5d, 0x83, 0xf1, 0x88, 0xc2, 0x9f, 0x45, 0x7f, 0xdb, 0xcf, 0x4a,
                0x81, 0xbc, 0x94, 0x43,
            ]
        );
        assert_eq!(
            first.receive_public_key,
            [
                0xa1, 0xea, 0xd9, 0x2f, 0xf1, 0x30, 0xda, 0xea, 0x59, 0x7a, 0xa1, 0x4f, 0x85, 0x29,
                0x0b, 0xe2, 0xa3, 0xb2, 0xed, 0x5d, 0x7b, 0x72, 0x16, 0xcb, 0xa4, 0xbe, 0xe7, 0x66,
                0x3b, 0xaf, 0x30, 0x60,
            ]
        );
        assert_eq!(
            first.maker_receive_spk_hash,
            [
                0xb0, 0x9f, 0xad, 0x10, 0x9c, 0xcc, 0x53, 0xf1, 0x32, 0x74, 0x7f, 0x02, 0x8c, 0x08,
                0xfd, 0x2c, 0x81, 0xa2, 0x8c, 0xa4, 0xdd, 0x3d, 0x5c, 0xa0, 0xf4, 0xa6, 0x44, 0xca,
                0xdb, 0xda, 0xe9, 0x93,
            ]
        );
        assert!(!first.maker_was_odd);
        assert!(first.receive_was_odd);
        assert!(first == repeated);
        assert_eq!(&first.maker_receive_spk.as_bytes()[..2], &[0x51, 0x20]);
        assert_eq!(
            &first.maker_receive_spk.as_bytes()[2..],
            &first.receive_public_key
        );
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(first.maker_receive_spk.as_bytes())),
            first.maker_receive_spk_hash
        );
    }

    #[test]
    fn different_order_indices_separate_every_owned_key() {
        let keychain = DeadcatKeychain::from_mnemonic(MNEMONIC, "").expect("keychain");
        let a = keychain.derive_order(17, terms()).expect("derive");
        let b = keychain.derive_order(18, terms()).expect("derive");
        assert_ne!(a.maker_public_key, b.maker_public_key);
        assert_ne!(a.order_nonce, b.order_nonce);
        assert_ne!(a.maker_receive_spk_hash, b.maker_receive_spk_hash);
    }

    #[test]
    fn key_material_builds_public_order_params() {
        let keychain = DeadcatKeychain::from_mnemonic(MNEMONIC, "").expect("keychain");
        let terms = terms();
        let keys = keychain.derive_order(9, terms).expect("derive");
        let params = keys.params(terms);
        assert_eq!(params.maker_pubkey, keys.maker_public_key);
        assert_eq!(params.maker_receive_spk_hash, keys.maker_receive_spk_hash);
        assert_eq!(params.price, terms.price);
    }

    #[test]
    fn owned_order_binds_one_index_to_params_and_masked_hint() {
        let keychain = DeadcatKeychain::from_mnemonic(MNEMONIC, "").expect("keychain");
        let owned = keychain
            .derive_owned_order(
                513,
                Txid::from_byte_array([0x66; 32]),
                OrderSide::No,
                terms(),
            )
            .expect("derive");
        assert_eq!(owned.params, owned.keys.params(terms()));
        assert_eq!(owned.recovery_hint.side, OrderSide::No);
        assert_eq!(
            owned
                .recovery_hint
                .unmask_index(&keychain.deadcat_secret_key().expect("secret")),
            513
        );
    }
}

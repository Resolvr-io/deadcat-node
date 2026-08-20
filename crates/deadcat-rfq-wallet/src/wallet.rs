use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use deadcat_rfq_provider::{
    ConfidentialDestination, DestinationPurpose, ProviderIdentity, ProviderInputSignature,
    ProviderOutputRecovery, ProviderSigner, SigningJob, SigningResponse, WalletBoundaryError,
    WalletKeyLocator, WalletOwnedOutput,
};
use elements::bitcoin::NetworkKind;
use elements::bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use elements::encode::{deserialize, serialize};
use elements::hashes::Hash as _;
use elements::pset::PartiallySignedTransaction;
use elements::schnorr::TapTweak as _;
use elements::secp256k1_zkp::{Keypair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use elements::sighash::{Prevouts, SighashCache};
use elements::{AssetId, OutPoint, SchnorrSig, SchnorrSighashType, Script, TxOut};
use hmac::{Hmac, Mac as _};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use sha2::{Digest as _, Sha256, Sha512};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::keystore::UnlockedSeed;

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

const LOCATOR_VERSION: u8 = 1;
const LOCATOR_NONCE_BYTES: usize = 16;
const LOCATOR_TAG_BYTES: usize = 14;
const LOCATOR_PREFIX_BYTES: usize = 2 + LOCATOR_NONCE_BYTES;
const LOCATOR_BYTES: usize = LOCATOR_PREFIX_BYTES + LOCATOR_TAG_BYTES;
const MAX_DESTINATION_ATTEMPTS: usize = 16;

const BIP86_PURPOSE: u32 = 86;
const LIQUID_SLIP44_COIN_TYPE: u32 = 1_776;
const RFQ_ACCOUNT: u32 = 0;
const RANDOM_PATH_COMPONENTS: usize = 5;

const LOCATOR_AUTH_DOMAIN: &[u8] = b"deadcat/rfq/wallet/locator-auth/v1";
const LOCATOR_TAG_DOMAIN: &[u8] = b"deadcat/rfq/wallet/locator-tag/v1";
const LOCATOR_PATH_DOMAIN: &[u8] = b"deadcat/rfq/wallet/locator-path/v1";
const BACKUP_AUTH_DOMAIN: &[u8] = b"deadcat/rfq/wallet/backup-auth/v1";
const SLIP21_DOMAIN: &[u8] = b"Symmetric key seed";
const SLIP77_LABEL: &[u8] = b"SLIP-0077";

struct IssuanceState<R> {
    rng: R,
}

/// Unlocked, purpose-built provider hot wallet.
///
/// The wallet intentionally has no arbitrary-message or arbitrary-transaction
/// signing API. A signature can be requested only through [`ProviderSigner`]
/// with a durable [`SigningJob`]. Destination issuance uses a random 128-bit
/// namespace rather than a rollbackable counter. Therefore restoring the same
/// encrypted envelope does not deterministically replay an issuance sequence,
/// assuming a fresh operating-system CSPRNG state.
pub struct RfqWallet<R = OsRng> {
    identity: ProviderIdentity,
    wallet_id: [u8; 16],
    seed: Zeroizing<[u8; 64]>,
    master_blinding_key: Zeroizing<[u8; 32]>,
    locator_auth_key: Zeroizing<[u8; 32]>,
    issuance: Mutex<IssuanceState<R>>,
}

impl RfqWallet<OsRng> {
    pub fn new(unlocked: UnlockedSeed) -> Result<Self, RfqWalletError> {
        Self::with_rng(unlocked, OsRng)
    }
}

impl<R: RngCore + CryptoRng + Send> RfqWallet<R> {
    pub(crate) fn with_rng(unlocked: UnlockedSeed, rng: R) -> Result<Self, RfqWalletError> {
        let (seed, identity, wallet_id) = unlocked.into_parts();
        let master_blinding_key = derive_slip77_master(&seed[..])?;
        let locator_auth_key = derive_locator_auth_key(&seed, identity, wallet_id)?;
        Ok(Self {
            identity,
            wallet_id,
            seed,
            master_blinding_key,
            locator_auth_key,
            issuance: Mutex::new(IssuanceState { rng }),
        })
    }

    #[must_use]
    pub const fn identity(&self) -> ProviderIdentity {
        self.identity
    }

    pub(crate) const fn wallet_id(&self) -> [u8; 16] {
        self.wallet_id
    }

    pub(crate) fn candidate_inventory_destination(
        &self,
    ) -> Result<ConfidentialDestination, RfqWalletError> {
        self.issue_destination(KeyPurpose::InventoryDeposit)
    }

    pub(crate) fn candidate_settlement_destination(
        &self,
        purpose: DestinationPurpose,
    ) -> Result<ConfidentialDestination, RfqWalletError> {
        self.issue_destination(match purpose {
            DestinationPurpose::SettlementReceive => KeyPurpose::SettlementReceive,
            DestinationPurpose::SettlementChange => KeyPurpose::SettlementChange,
        })
    }

    /// Reconstruct the public spend script and blinding public key for an
    /// already-issued authenticated locator.
    ///
    /// This does not issue or burn a destination and never exports either
    /// private key. A chain scanner can use the returned script to query an
    /// authoritative UTXO view, then pass matching outputs through
    /// [`ProviderOutputRecovery`].
    pub fn recover_confidential_destination(
        &self,
        locator: WalletKeyLocator,
    ) -> Result<ConfidentialDestination, RfqWalletError> {
        self.destination_for_locator(locator)
    }

    /// Authenticate and recover one complete confidential wallet output while
    /// keeping its blinding factors inside the provider capability boundary.
    ///
    /// A concrete chain scanner supplies the creating outpoint and full
    /// consensus output, including its rangeproof and surjection proof. The
    /// returned value retains the opening only in the provider crate's
    /// redacted in-memory representation used for collaborative blinding.
    pub fn recover_owned_output(
        &self,
        locator: WalletKeyLocator,
        outpoint: OutPoint,
        txout: TxOut,
    ) -> Result<WalletOwnedOutput, RfqWalletError> {
        let decoded = self.decode_locator(locator)?;
        let mut keypair = self.derive_spend_keypair(decoded)?;
        let (internal_key, _) = keypair.0.x_only_public_key();
        let expected_script = Script::new_v1_p2tr(&Secp256k1::new(), internal_key, None);
        if txout.script_pubkey != expected_script
            || !txout.asset.is_confidential()
            || !txout.value.is_confidential()
            || !txout.nonce.is_confidential()
        {
            return Err(RfqWalletError::OutputScriptOrConfidentialityMismatch);
        }
        let mut blinding_secret = self.slip77_blinding_secret(&expected_script)?;
        let opening = txout
            .unblind(&Secp256k1::new(), blinding_secret.0)
            .map_err(|_| RfqWalletError::OutputUnblindFailed)?;
        blinding_secret.0.non_secure_erase();
        keypair.0.non_secure_erase();
        WalletOwnedOutput::new(outpoint, txout, opening, internal_key, locator)
            .map_err(RfqWalletError::from)
    }

    pub(crate) fn validate_locator(&self, locator: WalletKeyLocator) -> Result<(), RfqWalletError> {
        self.decode_locator(locator).map(|_| ())
    }

    pub(crate) fn locator_nonce(
        &self,
        locator: WalletKeyLocator,
    ) -> Result<[u8; LOCATOR_NONCE_BYTES], RfqWalletError> {
        self.decode_locator(locator).map(|decoded| decoded.nonce)
    }

    pub(crate) fn backup_authentication_tag(
        &self,
        payload: &[u8],
    ) -> Result<[u8; 32], RfqWalletError> {
        let mut mac = HmacSha256::new_from_slice(self.locator_auth_key.as_ref())
            .map_err(|_| RfqWalletError::KeyDerivationFailed)?;
        mac.update(BACKUP_AUTH_DOMAIN);
        mac.update(&identity_bytes(self.identity));
        mac.update(&self.wallet_id);
        mac.update(payload);
        Ok(mac.finalize().into_bytes().into())
    }

    fn issue_destination(
        &self,
        purpose: KeyPurpose,
    ) -> Result<ConfidentialDestination, RfqWalletError> {
        let mut issuance = self
            .issuance
            .lock()
            .map_err(|_| RfqWalletError::IssuanceLockPoisoned)?;
        for _ in 0..MAX_DESTINATION_ATTEMPTS {
            let mut nonce = [0_u8; LOCATOR_NONCE_BYTES];
            issuance.rng.fill_bytes(&mut nonce);
            if nonce == [0; LOCATOR_NONCE_BYTES] {
                continue;
            }
            let locator = self.encode_locator(purpose, nonce)?;
            match self.destination_for_locator(locator) {
                Ok(destination) => return Ok(destination),
                // SLIP-77 requires failure for the statistically negligible
                // invalid-scalar case. Burn this random namespace and retry.
                Err(RfqWalletError::InvalidBlindingScalar) => continue,
                Err(error) => return Err(error),
            }
        }
        Err(RfqWalletError::DestinationEntropyExhausted)
    }

    fn destination_for_locator(
        &self,
        locator: WalletKeyLocator,
    ) -> Result<ConfidentialDestination, RfqWalletError> {
        let decoded = self.decode_locator(locator)?;
        let mut keypair = self.derive_spend_keypair(decoded)?;
        let (internal_key, _) = keypair.0.x_only_public_key();
        let script_pubkey = Script::new_v1_p2tr(&Secp256k1::new(), internal_key, None);
        let mut blinding_secret = self.slip77_blinding_secret(&script_pubkey)?;
        let blinding_public_key = PublicKey::from_secret_key(&Secp256k1::new(), &blinding_secret.0);
        let destination = ConfidentialDestination::new(
            script_pubkey,
            blinding_public_key,
            internal_key,
            locator,
        )?;
        blinding_secret.0.non_secure_erase();
        keypair.0.non_secure_erase();
        Ok(destination)
    }

    fn encode_locator(
        &self,
        purpose: KeyPurpose,
        nonce: [u8; LOCATOR_NONCE_BYTES],
    ) -> Result<WalletKeyLocator, RfqWalletError> {
        let mut bytes = [0_u8; LOCATOR_BYTES];
        bytes[0] = LOCATOR_VERSION;
        bytes[1] = purpose_byte(purpose);
        bytes[2..LOCATOR_PREFIX_BYTES].copy_from_slice(&nonce);
        let tag = self.locator_tag(&bytes[..LOCATOR_PREFIX_BYTES])?;
        bytes[LOCATOR_PREFIX_BYTES..].copy_from_slice(&tag[..LOCATOR_TAG_BYTES]);
        WalletKeyLocator::new(bytes).map_err(|_| RfqWalletError::InvalidLocator)
    }

    fn decode_locator(&self, locator: WalletKeyLocator) -> Result<DecodedLocator, RfqWalletError> {
        let bytes = locator.to_bytes();
        if bytes[0] != LOCATOR_VERSION {
            return Err(RfqWalletError::UnsupportedLocatorVersion(bytes[0]));
        }
        let purpose = purpose_from_byte(bytes[1])?;
        let expected = self.locator_tag(&bytes[..LOCATOR_PREFIX_BYTES])?;
        if !bool::from(expected[..LOCATOR_TAG_BYTES].ct_eq(&bytes[LOCATOR_PREFIX_BYTES..])) {
            return Err(RfqWalletError::LocatorAuthenticationFailed);
        }
        let nonce = bytes[2..LOCATOR_PREFIX_BYTES]
            .try_into()
            .map_err(|_| RfqWalletError::InvalidLocator)?;
        Ok(DecodedLocator { purpose, nonce })
    }

    fn locator_tag(&self, prefix: &[u8]) -> Result<[u8; 32], RfqWalletError> {
        let mut mac = HmacSha256::new_from_slice(self.locator_auth_key.as_ref())
            .map_err(|_| RfqWalletError::KeyDerivationFailed)?;
        mac.update(LOCATOR_TAG_DOMAIN);
        mac.update(&identity_bytes(self.identity));
        mac.update(&self.wallet_id);
        mac.update(prefix);
        Ok(mac.finalize().into_bytes().into())
    }

    fn derive_spend_keypair(
        &self,
        locator: DecodedLocator,
    ) -> Result<SensitiveKeypair, RfqWalletError> {
        let secp = Secp256k1::new();
        let master = SensitiveXpriv(
            Xpriv::new_master(NetworkKind::Main, self.seed.as_ref())
                .map_err(|_| RfqWalletError::KeyDerivationFailed)?,
        );
        let path = locator_path(locator, self.identity, self.wallet_id)?;
        let child = SensitiveXpriv(
            master
                .0
                .derive_priv(&secp, &path)
                .map_err(|_| RfqWalletError::KeyDerivationFailed)?,
        );
        let keypair = Keypair::from_secret_key(&secp, &child.0.private_key);
        Ok(SensitiveKeypair(keypair))
    }

    fn slip77_blinding_secret(
        &self,
        script_pubkey: &Script,
    ) -> Result<SensitiveSecretKey, RfqWalletError> {
        derive_slip77_blinding_secret(&self.master_blinding_key, script_pubkey)
    }

    fn sign_targets(
        &self,
        payload: &[u8],
        targets: &[WalletSigningTarget],
    ) -> Result<Vec<ProviderInputSignature>, RfqWalletError> {
        if payload.is_empty() {
            return Err(RfqWalletError::InvalidSigningPayload("empty PSET"));
        }
        let pset = deserialize::<PartiallySignedTransaction>(payload)
            .map_err(|_| RfqWalletError::InvalidSigningPayload("PSET decode failed"))?;
        if serialize(&pset) != payload {
            return Err(RfqWalletError::InvalidSigningPayload(
                "PSET encoding is not canonical",
            ));
        }
        let transaction = pset
            .extract_tx()
            .map_err(|_| RfqWalletError::InvalidSigningPayload("PSET extraction failed"))?;
        let mut indexes = BTreeMap::new();
        let mut prevouts = Vec::with_capacity(pset.inputs().len());
        for (index, input) in pset.inputs().iter().enumerate() {
            let outpoint = OutPoint::new(input.previous_txid, input.previous_output_index);
            if indexes.insert(outpoint, index).is_some() {
                return Err(RfqWalletError::InvalidSigningPayload(
                    "duplicate input outpoint",
                ));
            }
            prevouts.push(input.witness_utxo.clone().ok_or(
                RfqWalletError::InvalidSigningPayload("input is missing its witness UTXO"),
            )?);
        }

        let secp = Secp256k1::new();
        let mut seen_targets = BTreeSet::new();
        let mut signatures = Vec::with_capacity(targets.len());
        for target in targets {
            if !seen_targets.insert(target.outpoint) {
                return Err(RfqWalletError::DuplicateSigningTarget(target.outpoint));
            }
            let index = indexes
                .get(&target.outpoint)
                .copied()
                .ok_or(RfqWalletError::MissingSigningTarget(target.outpoint))?;
            let input = &pset.inputs()[index];
            let prevout = &prevouts[index];
            let decoded = self.decode_locator(target.locator)?;
            let mut keypair = self.derive_spend_keypair(decoded)?;
            let (actual_internal_key, _) = keypair.0.x_only_public_key();
            if actual_internal_key != target.internal_key {
                return Err(RfqWalletError::InternalKeyMismatch(target.outpoint));
            }
            if input.tap_internal_key != Some(target.internal_key)
                || input.tap_merkle_root.is_some()
                || input.sighash_type != Some(SchnorrSighashType::All.into())
                || input.tap_key_sig.is_some()
                || input.final_script_witness.is_some()
                || prevout.script_pubkey != Script::new_v1_p2tr(&secp, target.internal_key, None)
            {
                return Err(RfqWalletError::InvalidSigningTarget(target.outpoint));
            }
            let sighash = SighashCache::new(&transaction)
                .taproot_key_spend_signature_hash(
                    index,
                    &Prevouts::All(&prevouts),
                    SchnorrSighashType::All,
                    self.identity.genesis_hash(),
                )
                .map_err(|_| RfqWalletError::InvalidSigningPayload("sighash failed"))?;
            let message = Message::from_digest(sighash.to_byte_array());
            // Elements deliberately uses the `TapTweak/elements` tagged hash.
            // Calling Bitcoin's TapTweak implementation here would authorize
            // a different key and make every wallet output unspendable.
            let tweaked = SensitiveKeypair(keypair.0.tap_tweak(&secp, None).to_inner());
            let signature = {
                let mut issuance = self
                    .issuance
                    .lock()
                    .map_err(|_| RfqWalletError::IssuanceLockPoisoned)?;
                secp.sign_schnorr_with_rng(&message, &tweaked.0, &mut issuance.rng)
            };
            let signature = SchnorrSig {
                sig: signature,
                hash_ty: SchnorrSighashType::All,
            };
            signatures.push(ProviderInputSignature::new(target.outpoint, signature)?);
            keypair.0.non_secure_erase();
        }
        Ok(signatures)
    }
}

impl<R> fmt::Debug for RfqWallet<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RfqWallet")
            .field("identity", &self.identity)
            .field("wallet_id", &"[opaque]")
            .field("secrets", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl<R: RngCore + CryptoRng + Send> ProviderOutputRecovery for RfqWallet<R> {
    type Error = RfqWalletError;

    fn validate_confidential_output(
        &self,
        wallet_locator: WalletKeyLocator,
        expected_internal_key: XOnlyPublicKey,
        txout: &TxOut,
        expected_asset: AssetId,
        expected_amount: u64,
    ) -> Result<(), Self::Error> {
        let decoded = self.decode_locator(wallet_locator)?;
        let mut keypair = self.derive_spend_keypair(decoded)?;
        let (actual_internal_key, _) = keypair.0.x_only_public_key();
        if actual_internal_key != expected_internal_key {
            return Err(RfqWalletError::OutputInternalKeyMismatch);
        }
        let expected_script = Script::new_v1_p2tr(&Secp256k1::new(), expected_internal_key, None);
        if txout.script_pubkey != expected_script
            || !txout.asset.is_confidential()
            || !txout.value.is_confidential()
            || !txout.nonce.is_confidential()
        {
            return Err(RfqWalletError::OutputScriptOrConfidentialityMismatch);
        }
        let mut blinding_secret = self.slip77_blinding_secret(&expected_script)?;
        let opening = txout
            .unblind(&Secp256k1::new(), blinding_secret.0)
            .map_err(|_| RfqWalletError::OutputUnblindFailed)?;
        blinding_secret.0.non_secure_erase();
        keypair.0.non_secure_erase();
        if opening.asset != expected_asset {
            return Err(RfqWalletError::OutputAssetMismatch);
        }
        if opening.value != expected_amount {
            return Err(RfqWalletError::OutputAmountMismatch);
        }
        Ok(())
    }
}

impl<R: RngCore + CryptoRng + Send> ProviderSigner for RfqWallet<R> {
    type Error = RfqWalletError;

    fn sign(&self, job: &SigningJob) -> Result<SigningResponse, Self::Error> {
        let targets = job
            .targets()
            .iter()
            .map(|target| WalletSigningTarget {
                outpoint: target.outpoint(),
                locator: target.wallet_locator(),
                internal_key: target.internal_key(),
            })
            .collect::<Vec<_>>();
        let signatures = self.sign_targets(job.pre_sign_payload(), &targets)?;
        SigningResponse::new(job, signatures).map_err(RfqWalletError::from)
    }
}

#[derive(Clone, Copy)]
struct DecodedLocator {
    purpose: KeyPurpose,
    nonce: [u8; LOCATOR_NONCE_BYTES],
}

#[derive(Clone, Copy)]
enum KeyPurpose {
    InventoryDeposit,
    SettlementReceive,
    SettlementChange,
}

#[derive(Clone, Copy)]
struct WalletSigningTarget {
    outpoint: OutPoint,
    locator: WalletKeyLocator,
    internal_key: XOnlyPublicKey,
}

struct SensitiveKeypair(Keypair);

impl Drop for SensitiveKeypair {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

struct SensitiveXpriv(Xpriv);

impl Drop for SensitiveXpriv {
    fn drop(&mut self) {
        self.0.private_key.non_secure_erase();
    }
}

struct SensitiveSecretKey(SecretKey);

impl Drop for SensitiveSecretKey {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

fn derive_locator_auth_key(
    seed: &[u8; 64],
    identity: ProviderIdentity,
    wallet_id: [u8; 16],
) -> Result<Zeroizing<[u8; 32]>, RfqWalletError> {
    let mut mac =
        HmacSha256::new_from_slice(seed).map_err(|_| RfqWalletError::KeyDerivationFailed)?;
    mac.update(LOCATOR_AUTH_DOMAIN);
    mac.update(&identity_bytes(identity));
    mac.update(&wallet_id);
    let mut output = Zeroizing::new([0_u8; 32]);
    output.copy_from_slice(&mac.finalize().into_bytes());
    Ok(output)
}

fn derive_slip77_master(seed: &[u8]) -> Result<Zeroizing<[u8; 32]>, RfqWalletError> {
    let mut root_mac = HmacSha512::new_from_slice(SLIP21_DOMAIN)
        .map_err(|_| RfqWalletError::KeyDerivationFailed)?;
    root_mac.update(seed);
    let mut root = Zeroizing::new([0_u8; 64]);
    root.copy_from_slice(&root_mac.finalize().into_bytes());

    let mut node_mac =
        HmacSha512::new_from_slice(&root[..32]).map_err(|_| RfqWalletError::KeyDerivationFailed)?;
    node_mac.update(&[0]);
    node_mac.update(SLIP77_LABEL);
    let mut node = Zeroizing::new([0_u8; 64]);
    node.copy_from_slice(&node_mac.finalize().into_bytes());
    let mut master = Zeroizing::new([0_u8; 32]);
    master.copy_from_slice(&node[32..]);
    Ok(master)
}

fn derive_slip77_blinding_secret(
    master_blinding_key: &[u8; 32],
    script_pubkey: &Script,
) -> Result<SensitiveSecretKey, RfqWalletError> {
    let mut mac = HmacSha256::new_from_slice(master_blinding_key)
        .map_err(|_| RfqWalletError::KeyDerivationFailed)?;
    mac.update(script_pubkey.as_bytes());
    let mut bytes = Zeroizing::new([0_u8; 32]);
    bytes.copy_from_slice(&mac.finalize().into_bytes());
    SecretKey::from_slice(bytes.as_ref())
        .map(SensitiveSecretKey)
        .map_err(|_| RfqWalletError::InvalidBlindingScalar)
}

fn locator_path(
    locator: DecodedLocator,
    identity: ProviderIdentity,
    wallet_id: [u8; 16],
) -> Result<DerivationPath, RfqWalletError> {
    let mut hasher = Sha256::new();
    hasher.update(LOCATOR_PATH_DOMAIN);
    // The same recovered seed must not derive the same spend branch for a
    // distinct wallet or provider identity, even if a locator nonce repeats.
    hasher.update(identity_bytes(identity));
    hasher.update(wallet_id);
    hasher.update([purpose_byte(locator.purpose)]);
    hasher.update(locator.nonce);
    let expanded: [u8; 32] = hasher.finalize().into();

    // This is deliberately only BIP86-shaped. Elements uses its own TapTweak
    // tag, and the random hardened suffix is application-specific, so these
    // paths are not represented as interoperable BIP86 descriptors.
    let mut path = Vec::with_capacity(4 + RANDOM_PATH_COMPONENTS);
    for index in [
        BIP86_PURPOSE,
        LIQUID_SLIP44_COIN_TYPE,
        RFQ_ACCOUNT,
        u32::from(purpose_byte(locator.purpose)),
    ] {
        path.push(
            ChildNumber::from_hardened_idx(index)
                .map_err(|_| RfqWalletError::KeyDerivationFailed)?,
        );
    }
    for chunk in expanded.chunks_exact(4).take(RANDOM_PATH_COMPONENTS) {
        let index = u32::from_be_bytes(
            chunk
                .try_into()
                .map_err(|_| RfqWalletError::KeyDerivationFailed)?,
        ) & 0x7fff_ffff;
        path.push(
            ChildNumber::from_hardened_idx(index)
                .map_err(|_| RfqWalletError::KeyDerivationFailed)?,
        );
    }
    Ok(DerivationPath::from(path))
}

const fn purpose_byte(purpose: KeyPurpose) -> u8 {
    match purpose {
        KeyPurpose::InventoryDeposit => 0,
        KeyPurpose::SettlementReceive => 1,
        KeyPurpose::SettlementChange => 2,
    }
}

fn purpose_from_byte(value: u8) -> Result<KeyPurpose, RfqWalletError> {
    match value {
        0 => Ok(KeyPurpose::InventoryDeposit),
        1 => Ok(KeyPurpose::SettlementReceive),
        2 => Ok(KeyPurpose::SettlementChange),
        _ => Err(RfqWalletError::InvalidLocatorPurpose(value)),
    }
}

fn identity_bytes(identity: ProviderIdentity) -> [u8; 96] {
    let mut bytes = [0_u8; 96];
    bytes[..32].copy_from_slice(&identity.provider().to_bytes());
    bytes[32..64].copy_from_slice(&identity.genesis_hash().to_byte_array());
    bytes[64..].copy_from_slice(&identity.policy_asset().into_inner().to_byte_array());
    bytes
}

#[derive(Debug, Error)]
pub enum RfqWalletError {
    #[error("wallet issuance lock is poisoned")]
    IssuanceLockPoisoned,
    #[error("fresh destination entropy was exhausted")]
    DestinationEntropyExhausted,
    #[error("wallet key derivation failed")]
    KeyDerivationFailed,
    #[error("derived SLIP-77 blinding key is not a secp256k1 scalar")]
    InvalidBlindingScalar,
    #[error("wallet locator is malformed")]
    InvalidLocator,
    #[error("unsupported wallet locator version {0}")]
    UnsupportedLocatorVersion(u8),
    #[error("wallet locator has invalid purpose {0}")]
    InvalidLocatorPurpose(u8),
    #[error("wallet locator authentication failed")]
    LocatorAuthenticationFailed,
    #[error("wallet output resolves to a different internal key")]
    OutputInternalKeyMismatch,
    #[error("wallet output script or confidential fields do not match")]
    OutputScriptOrConfidentialityMismatch,
    #[error("wallet output rangeproof could not be rewound")]
    OutputUnblindFailed,
    #[error("wallet output opens to the wrong asset")]
    OutputAssetMismatch,
    #[error("wallet output opens to the wrong amount")]
    OutputAmountMismatch,
    #[error("invalid durable signing payload: {0}")]
    InvalidSigningPayload(&'static str),
    #[error("durable signing job contains duplicate target {0:?}")]
    DuplicateSigningTarget(OutPoint),
    #[error("durable signing target is missing from the PSET: {0:?}")]
    MissingSigningTarget(OutPoint),
    #[error("durable signing target resolves to the wrong internal key: {0:?}")]
    InternalKeyMismatch(OutPoint),
    #[error("durable signing target has an unsupported PSET spend profile: {0:?}")]
    InvalidSigningTarget(OutPoint),
    #[error(transparent)]
    WalletBoundary(#[from] WalletBoundaryError),
}

#[cfg(test)]
mod tests {
    use core::str::FromStr as _;
    use std::fmt::Write as _;

    use deadcat_rfq_provider::{ProviderId, ProviderIdentity, ProviderOutputRecovery as _};
    use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
    use elements::hashes::Hash as _;
    use elements::hashes::hex::FromHex as _;
    use elements::pset::{Input as PsetInput, Output as PsetOutput};
    use elements::secp256k1_zkp::rand::thread_rng;
    use elements::{AssetId, BlockHash, Transaction, TxOutWitness, Txid};
    use rand::SeedableRng as _;
    use rand::rngs::StdRng;

    use super::*;
    use crate::{EncryptedKeystore, KdfParams};

    fn test_kdf() -> KdfParams {
        // The default RFC profile is covered by its constants. This bounded
        // profile keeps repeated unit-test unlocks fast while retaining Argon2.
        KdfParams::new(8 * 1_024, 1, 1).expect("test KDF")
    }

    fn identity(marker: u8) -> ProviderIdentity {
        ProviderIdentity::new(
            ProviderId::new([marker; 32]),
            BlockHash::from_byte_array([marker.wrapping_add(1); 32]),
            AssetId::from_byte_array([marker.wrapping_add(2); 32]),
        )
    }

    fn encode_hex(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
        }
        encoded
    }

    #[test]
    fn full_derivation_golden_vector() {
        let identity = ProviderIdentity::new(
            ProviderId::new([0x11; 32]),
            BlockHash::from_byte_array([0x22; 32]),
            AssetId::from_byte_array([0x33; 32]),
        );
        let wallet = RfqWallet::with_rng(
            UnlockedSeed::from_test_parts([0x55; 64], identity, [0x44; 16]),
            StdRng::seed_from_u64(0),
        )
        .expect("fixed wallet");
        let locator = wallet
            .encode_locator(KeyPurpose::SettlementReceive, [0x66; LOCATOR_NONCE_BYTES])
            .expect("fixed locator");
        let destination = wallet
            .recover_confidential_destination(locator)
            .expect("fixed destination");

        assert_eq!(
            encode_hex(&locator.to_bytes()),
            "010166666666666666666666666666666666970b636c3148f7dc87e48b3c3694"
        );
        assert_eq!(
            encode_hex(&destination.internal_key().serialize()),
            "699d9b18660872d0462e0250dfa61aedd89b97b1fb5f92328892fb16d210a07b"
        );
        assert_eq!(
            encode_hex(destination.script_pubkey().as_bytes()),
            "5120a334c1cac0d277db03c3e96ddb65cda9d11b8839ecd8f2739af39452113ea1ee"
        );
        assert_eq!(
            encode_hex(&destination.blinding_public_key().serialize()),
            "0319dfcfdaebce43ecc5ac5d921c4bc481b8485b3a601a51b17b8c9daaa47939e0"
        );
    }

    #[test]
    fn slip77_matches_published_master_and_per_script_vectors() {
        // Vectors shared by libwally, rust-elements, and
        // elements-miniscript's canonical SLIP-77 implementation.
        let seed =
            Vec::<u8>::from_hex("731e9b42eb9774f8a6b51af35a06f6ef1cdb6cf04402163ceacf0c8bace2831a")
                .expect("vector seed");
        let master = derive_slip77_master(&seed).expect("master key");
        assert_eq!(
            master.as_slice(),
            Vec::<u8>::from_hex("c2f338e32ad1a2bd9cac569e67728163bf4c326a1770ec2293ba65548a581e97")
                .expect("master vector")
        );
        let script = Script::from_str("a914afa92d77cd3541b443771649572db096cf49bf8c87")
            .expect("vector script");
        let secret = derive_slip77_blinding_secret(&master, &script).expect("blinding key");
        assert_eq!(
            secret.0.secret_bytes().as_slice(),
            Vec::<u8>::from_hex("02b067c374bb56c54c016fae29218c000ada60f81ef45b4aeebbeb24931bb8bc")
                .expect("blinding vector")
        );
    }

    fn wallets() -> (RfqWallet<StdRng>, RfqWallet<StdRng>) {
        let identity = identity(21);
        let envelope =
            EncryptedKeystore::generate_with_kdf(identity, b"wallet-test passphrase", test_kdf())
                .expect("envelope");
        let first = RfqWallet::with_rng(
            envelope
                .unlock(identity, b"wallet-test passphrase")
                .expect("unlock"),
            StdRng::seed_from_u64(1),
        )
        .expect("wallet");
        let restored = RfqWallet::with_rng(
            envelope
                .unlock(identity, b"wallet-test passphrase")
                .expect("unlock"),
            StdRng::seed_from_u64(2),
        )
        .expect("wallet");
        (first, restored)
    }

    #[test]
    fn destinations_are_tree_less_p2tr_and_counter_rollback_independent() {
        let (wallet, restored) = wallets();
        let receive = wallet
            .candidate_settlement_destination(DestinationPurpose::SettlementReceive)
            .expect("receive");
        let change = wallet
            .candidate_settlement_destination(DestinationPurpose::SettlementChange)
            .expect("change");
        let after_restore = restored
            .candidate_settlement_destination(DestinationPurpose::SettlementReceive)
            .expect("restored receive");
        let recovered_after_restore = restored
            .recover_confidential_destination(receive.wallet_locator())
            .expect("historical locator resolves after restart");

        assert_eq!(
            receive.script_pubkey(),
            &Script::new_v1_p2tr(&Secp256k1::new(), receive.internal_key(), None)
        );
        assert_ne!(receive.wallet_locator(), change.wallet_locator());
        assert_ne!(receive.wallet_locator(), after_restore.wallet_locator());
        assert_ne!(receive.script_pubkey(), change.script_pubkey());
        assert_ne!(receive.script_pubkey(), after_restore.script_pubkey());
        assert_eq!(
            recovered_after_restore.script_pubkey(),
            receive.script_pubkey()
        );
        assert_eq!(
            recovered_after_restore.internal_key(),
            receive.internal_key()
        );
        assert_eq!(
            recovered_after_restore.blinding_public_key(),
            receive.blinding_public_key()
        );
        assert!(!format!("{wallet:?}").contains("seed"));
    }

    #[test]
    fn locator_tampering_and_cross_wallet_use_fail_authentication() {
        let (wallet, _) = wallets();
        let destination = wallet
            .candidate_settlement_destination(DestinationPurpose::SettlementReceive)
            .expect("destination");
        let mut bytes = destination.wallet_locator().to_bytes();
        bytes[7] ^= 1;
        let tampered = WalletKeyLocator::new(bytes).expect("nonzero");
        assert!(matches!(
            wallet.recover_confidential_destination(tampered),
            Err(RfqWalletError::LocatorAuthenticationFailed)
        ));

        let other_identity = identity(22);
        let other = RfqWallet::new(
            EncryptedKeystore::generate_with_kdf(other_identity, b"other passphrase", test_kdf())
                .expect("other envelope")
                .unlock(other_identity, b"other passphrase")
                .expect("other unlock"),
        )
        .expect("other wallet");
        assert!(matches!(
            other.recover_confidential_destination(destination.wallet_locator()),
            Err(RfqWalletError::LocatorAuthenticationFailed)
        ));
    }

    #[test]
    fn output_recovery_requires_exact_locator_key_asset_and_amount() {
        let (wallet, _) = wallets();
        let destination = wallet
            .candidate_inventory_destination()
            .expect("inventory destination");
        let asset = AssetId::from_byte_array([77; 32]);
        let amount = 42_000;
        let explicit = TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(amount),
            nonce: Nonce::Null,
            script_pubkey: destination.script_pubkey().clone(),
            witness: TxOutWitness::default(),
        };
        let (confidential, _, _, _) = explicit
            .to_non_last_confidential(
                &mut thread_rng(),
                &Secp256k1::new(),
                destination.blinding_public_key(),
                &[elements::TxOutSecrets::new(
                    asset,
                    AssetBlindingFactor::zero(),
                    amount,
                    ValueBlindingFactor::zero(),
                )],
            )
            .expect("blind output");
        wallet
            .validate_confidential_output(
                destination.wallet_locator(),
                destination.internal_key(),
                &confidential,
                asset,
                amount,
            )
            .expect("recover");
        assert!(matches!(
            wallet.validate_confidential_output(
                destination.wallet_locator(),
                destination.internal_key(),
                &confidential,
                asset,
                amount + 1,
            ),
            Err(RfqWalletError::OutputAmountMismatch)
        ));
        assert!(matches!(
            wallet.validate_confidential_output(
                destination.wallet_locator(),
                destination.internal_key(),
                &confidential,
                AssetId::from_byte_array([78; 32]),
                amount,
            ),
            Err(RfqWalletError::OutputAssetMismatch)
        ));
    }

    #[test]
    fn signer_uses_elements_taptweak_and_explicit_sighash_all() {
        let (wallet, _) = wallets();
        let destination = wallet
            .candidate_inventory_destination()
            .expect("inventory destination");
        let outpoint = OutPoint::new(Txid::from_byte_array([90; 32]), 0);
        let prevout = TxOut {
            asset: Asset::Explicit(wallet.identity().policy_asset()),
            value: Value::Explicit(10_000),
            nonce: Nonce::Null,
            script_pubkey: destination.script_pubkey().clone(),
            witness: TxOutWitness::default(),
        };
        let mut input = PsetInput::from_prevout(outpoint);
        input.witness_utxo = Some(prevout.clone());
        input.tap_internal_key = Some(destination.internal_key());
        input.sighash_type = Some(SchnorrSighashType::All.into());
        let mut pset = PartiallySignedTransaction::new_v2();
        pset.add_input(input);
        pset.add_output(PsetOutput::from_txout(TxOut::new_fee(
            1_000,
            wallet.identity().policy_asset(),
        )));
        let payload = serialize(&pset);
        let signatures = wallet
            .sign_targets(
                &payload,
                &[WalletSigningTarget {
                    outpoint,
                    locator: destination.wallet_locator(),
                    internal_key: destination.internal_key(),
                }],
            )
            .expect("sign");
        assert_eq!(signatures.len(), 1);
        assert_eq!(
            signatures[0].serialized()[64],
            SchnorrSighashType::All as u8
        );

        let transaction: Transaction = pset.extract_tx().expect("extract");
        let sighash = SighashCache::new(&transaction)
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&[prevout]),
                SchnorrSighashType::All,
                wallet.identity().genesis_hash(),
            )
            .expect("sighash");
        let message = Message::from_digest(sighash.to_byte_array());
        let (output_key, _) = destination
            .internal_key()
            .tap_tweak(&Secp256k1::new(), None);
        Secp256k1::new()
            .verify_schnorr(
                &signatures[0].signature().sig,
                &message,
                output_key.as_inner(),
            )
            .expect("Elements-tweaked signature");
    }

    #[test]
    fn signer_rejects_wrong_internal_key_non_all_and_noncanonical_payload() {
        let (wallet, _) = wallets();
        let destination = wallet
            .candidate_settlement_destination(DestinationPurpose::SettlementReceive)
            .expect("destination");
        let other = wallet
            .candidate_settlement_destination(DestinationPurpose::SettlementReceive)
            .expect("other");
        let outpoint = OutPoint::new(Txid::from_byte_array([91; 32]), 1);
        let mut input = PsetInput::from_prevout(outpoint);
        input.witness_utxo = Some(TxOut {
            asset: Asset::Explicit(wallet.identity().policy_asset()),
            value: Value::Explicit(10_000),
            nonce: Nonce::Null,
            script_pubkey: destination.script_pubkey().clone(),
            witness: TxOutWitness::default(),
        });
        input.tap_internal_key = Some(destination.internal_key());
        input.sighash_type = Some(SchnorrSighashType::All.into());
        let mut pset = PartiallySignedTransaction::new_v2();
        pset.add_input(input);
        let payload = serialize(&pset);
        assert!(matches!(
            wallet.sign_targets(
                &payload,
                &[WalletSigningTarget {
                    outpoint,
                    locator: destination.wallet_locator(),
                    internal_key: other.internal_key(),
                }]
            ),
            Err(RfqWalletError::InternalKeyMismatch(_))
        ));

        pset.inputs_mut()[0].sighash_type = Some(SchnorrSighashType::None.into());
        assert!(matches!(
            wallet.sign_targets(
                &serialize(&pset),
                &[WalletSigningTarget {
                    outpoint,
                    locator: destination.wallet_locator(),
                    internal_key: destination.internal_key(),
                }]
            ),
            Err(RfqWalletError::InvalidSigningTarget(_))
        ));
        assert!(matches!(
            wallet.sign_targets(&[1, 2, 3], &[]),
            Err(RfqWalletError::InvalidSigningPayload(_))
        ));
    }
}

use core::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use bip39::{Language, Mnemonic};
use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use deadcat_rfq_provider::ProviderIdentity;
use elements::hashes::Hash as _;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

const MAGIC: &[u8; 8] = b"DCRFQKS\0";
const PAYLOAD_MAGIC: &[u8; 8] = b"DCRFQPL\0";
const FORMAT_VERSION: u16 = 1;
const PAYLOAD_VERSION: u16 = 1;
const KDF_ARGON2ID_V19: u8 = 1;
const AEAD_XCHACHA20_POLY1305: u8 = 1;

const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const WALLET_ID_BYTES: usize = 16;
const IDENTITY_BYTES: usize = 96;
const ENTROPY_BYTES: usize = 32;
const AEAD_TAG_BYTES: usize = 16;

const HEADER_BYTES: usize =
    8 + 2 + 1 + 1 + 4 + 4 + 4 + SALT_BYTES + NONCE_BYTES + WALLET_ID_BYTES + IDENTITY_BYTES + 4;
const PAYLOAD_BYTES: usize = 8 + 2 + ENTROPY_BYTES + WALLET_ID_BYTES;
const CIPHERTEXT_BYTES: usize = PAYLOAD_BYTES + AEAD_TAG_BYTES;
const ENVELOPE_BYTES: usize = HEADER_BYTES + CIPHERTEXT_BYTES;

const MIN_MEMORY_KIB: u32 = 8 * 1_024;
// Header authentication necessarily happens after the password KDF. Bound a
// corrupt or hostile unauthenticated header to a sane local allocation.
const MAX_MEMORY_KIB: u32 = 256 * 1_024;
const MAX_ITERATIONS: u32 = 16;
const MAX_LANES: u32 = 16;

/// Argon2id parameters stored in the authenticated keystore header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
}

impl KdfParams {
    /// Construct a bounded non-default Argon2id profile.
    ///
    /// Production deployments should normally use [`DEFAULT_KDF_PARAMS`]. A
    /// custom profile is useful only when its memory and latency have been
    /// measured on the deployment hardware or for resource-bounded tests.
    pub fn new(memory_kib: u32, iterations: u32, lanes: u32) -> Result<Self, KeystoreError> {
        let candidate = Self {
            memory_kib,
            iterations,
            lanes,
        };
        candidate.validate()?;
        Ok(candidate)
    }

    #[must_use]
    pub const fn memory_kib(self) -> u32 {
        self.memory_kib
    }

    #[must_use]
    pub const fn iterations(self) -> u32 {
        self.iterations
    }

    #[must_use]
    pub const fn lanes(self) -> u32 {
        self.lanes
    }

    fn validate(self) -> Result<(), KeystoreError> {
        if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib)
            || !(1..=MAX_ITERATIONS).contains(&self.iterations)
            || !(1..=MAX_LANES).contains(&self.lanes)
            || self.memory_kib < 8 * self.lanes
        {
            return Err(KeystoreError::InvalidKdfParams);
        }
        Ok(())
    }

    fn argon2(self) -> Result<Argon2<'static>, KeystoreError> {
        self.validate()?;
        let params = Params::new(self.memory_kib, self.iterations, self.lanes, Some(32))
            .map_err(|_| KeystoreError::InvalidKdfParams)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// RFC 9106's second recommended Argon2id profile.
pub const DEFAULT_KDF_PARAMS: KdfParams = KdfParams {
    memory_kib: 64 * 1_024,
    iterations: 3,
    lanes: 4,
};

/// Authenticated ciphertext containing one BIP39 entropy value.
///
/// The envelope is safe to serialize, but this type deliberately does not do
/// filesystem I/O. Production code must add atomic replacement, restrictive
/// permissions, directory synchronization, and protected passphrase delivery.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedKeystore {
    bytes: Vec<u8>,
}

impl EncryptedKeystore {
    /// Generate a new wallet for one provider identity using the default RFC
    /// 9106 Argon2id profile.
    pub fn generate(identity: ProviderIdentity, passphrase: &[u8]) -> Result<Self, KeystoreError> {
        Self::generate_with_kdf(identity, passphrase, DEFAULT_KDF_PARAMS)
    }

    /// Generate a new wallet with an explicitly selected, bounded Argon2id
    /// profile.
    ///
    /// Prefer [`Self::generate`] unless the deployment has benchmarked and
    /// documented a different profile.
    pub fn generate_with_kdf(
        identity: ProviderIdentity,
        passphrase: &[u8],
        kdf: KdfParams,
    ) -> Result<Self, KeystoreError> {
        Self::generate_with_rng(identity, passphrase, kdf, &mut OsRng)
    }

    fn generate_with_rng<R: RngCore + CryptoRng>(
        identity: ProviderIdentity,
        passphrase: &[u8],
        kdf: KdfParams,
        rng: &mut R,
    ) -> Result<Self, KeystoreError> {
        let mut entropy = Zeroizing::new([0_u8; ENTROPY_BYTES]);
        rng.fill_bytes(entropy.as_mut());
        Self::seal_entropy_with_rng(identity, passphrase, kdf, &entropy, rng)
    }

    pub(crate) fn seal_entropy_with_rng<R: RngCore + CryptoRng>(
        identity: ProviderIdentity,
        passphrase: &[u8],
        kdf: KdfParams,
        entropy: &[u8; ENTROPY_BYTES],
        rng: &mut R,
    ) -> Result<Self, KeystoreError> {
        if passphrase.is_empty() {
            return Err(KeystoreError::EmptyPassphrase);
        }
        kdf.validate()?;

        let mut salt = [0_u8; SALT_BYTES];
        let mut nonce = [0_u8; NONCE_BYTES];
        let mut wallet_id = [0_u8; WALLET_ID_BYTES];
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce);
        while wallet_id == [0; WALLET_ID_BYTES] {
            rng.fill_bytes(&mut wallet_id);
        }

        let mut header = Vec::with_capacity(HEADER_BYTES);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        header.push(KDF_ARGON2ID_V19);
        header.push(AEAD_XCHACHA20_POLY1305);
        header.extend_from_slice(&kdf.memory_kib.to_be_bytes());
        header.extend_from_slice(&kdf.iterations.to_be_bytes());
        header.extend_from_slice(&kdf.lanes.to_be_bytes());
        header.extend_from_slice(&salt);
        header.extend_from_slice(&nonce);
        header.extend_from_slice(&wallet_id);
        header.extend_from_slice(&identity_bytes(identity));
        header.extend_from_slice(&(CIPHERTEXT_BYTES as u32).to_be_bytes());
        debug_assert_eq!(header.len(), HEADER_BYTES);

        let mut plaintext = Zeroizing::new(Vec::with_capacity(PAYLOAD_BYTES));
        plaintext.extend_from_slice(PAYLOAD_MAGIC);
        plaintext.extend_from_slice(&PAYLOAD_VERSION.to_be_bytes());
        plaintext.extend_from_slice(entropy);
        plaintext.extend_from_slice(&wallet_id);
        debug_assert_eq!(plaintext.len(), PAYLOAD_BYTES);

        let key = derive_encryption_key(passphrase, &salt, kdf)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| KeystoreError::EncryptionFailed)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_ref(),
                    aad: &header,
                },
            )
            .map_err(|_| KeystoreError::EncryptionFailed)?;
        if ciphertext.len() != CIPHERTEXT_BYTES {
            return Err(KeystoreError::EncryptionFailed);
        }
        let mut bytes = header;
        bytes.extend_from_slice(&ciphertext);
        Ok(Self { bytes })
    }

    /// Parse and structurally validate an envelope without attempting unlock.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, KeystoreError> {
        parse_header(&bytes)?;
        Ok(Self { bytes })
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Authenticate, decrypt, and bind this wallet to `expected_identity`.
    pub fn unlock(
        &self,
        expected_identity: ProviderIdentity,
        passphrase: &[u8],
    ) -> Result<UnlockedSeed, KeystoreError> {
        if passphrase.is_empty() {
            return Err(KeystoreError::EmptyPassphrase);
        }
        let header = parse_header(&self.bytes)?;
        if header.identity != identity_bytes(expected_identity) {
            return Err(KeystoreError::IdentityMismatch);
        }
        let key = derive_encryption_key(passphrase, &header.salt, header.kdf)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| KeystoreError::DecryptionFailed)?;
        let mut plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&header.nonce),
                    Payload {
                        msg: &self.bytes[HEADER_BYTES..],
                        aad: &self.bytes[..HEADER_BYTES],
                    },
                )
                .map_err(|_| KeystoreError::DecryptionFailed)?,
        );
        if plaintext.len() != PAYLOAD_BYTES
            || &plaintext[..8] != PAYLOAD_MAGIC
            || u16::from_be_bytes([plaintext[8], plaintext[9]]) != PAYLOAD_VERSION
            || plaintext[42..58] != header.wallet_id
        {
            return Err(KeystoreError::InvalidPayload);
        }
        let mut entropy = Zeroizing::new([0_u8; ENTROPY_BYTES]);
        entropy.copy_from_slice(&plaintext[10..42]);
        plaintext.zeroize();

        let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy.as_ref())
            .map_err(|_| KeystoreError::InvalidPayload)?;
        let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
        drop(mnemonic);
        Ok(UnlockedSeed {
            seed,
            identity: expected_identity,
            wallet_id: header.wallet_id,
        })
    }
}

impl fmt::Debug for EncryptedKeystore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedKeystore")
            .field("bytes", &self.bytes.len())
            .field("contents", &"[authenticated ciphertext]")
            .finish()
    }
}

/// Decrypted root material. It is consumed by [`crate::RfqWallet`] and
/// zeroized on drop.
pub struct UnlockedSeed {
    seed: Zeroizing<[u8; 64]>,
    identity: ProviderIdentity,
    wallet_id: [u8; WALLET_ID_BYTES],
}

impl UnlockedSeed {
    #[cfg(test)]
    pub(crate) fn from_test_parts(
        seed: [u8; 64],
        identity: ProviderIdentity,
        wallet_id: [u8; WALLET_ID_BYTES],
    ) -> Self {
        Self {
            seed: Zeroizing::new(seed),
            identity,
            wallet_id,
        }
    }

    #[cfg(test)]
    pub(crate) fn seed(&self) -> &[u8; 64] {
        &self.seed
    }

    #[cfg(test)]
    pub(crate) const fn identity(&self) -> ProviderIdentity {
        self.identity
    }

    #[cfg(test)]
    pub(crate) const fn wallet_id(&self) -> [u8; WALLET_ID_BYTES] {
        self.wallet_id
    }

    pub(crate) fn into_parts(
        self,
    ) -> (Zeroizing<[u8; 64]>, ProviderIdentity, [u8; WALLET_ID_BYTES]) {
        (self.seed, self.identity, self.wallet_id)
    }
}

impl fmt::Debug for UnlockedSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnlockedSeed([redacted])")
    }
}

#[derive(Clone, Copy)]
struct ParsedHeader {
    kdf: KdfParams,
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
    wallet_id: [u8; WALLET_ID_BYTES],
    identity: [u8; IDENTITY_BYTES],
}

fn parse_header(bytes: &[u8]) -> Result<ParsedHeader, KeystoreError> {
    if bytes.len() != ENVELOPE_BYTES || &bytes[..8] != MAGIC {
        return Err(KeystoreError::InvalidEnvelope);
    }
    let version = u16::from_be_bytes([bytes[8], bytes[9]]);
    if version != FORMAT_VERSION {
        return Err(KeystoreError::UnsupportedVersion(version));
    }
    if bytes[10] != KDF_ARGON2ID_V19 || bytes[11] != AEAD_XCHACHA20_POLY1305 {
        return Err(KeystoreError::UnsupportedAlgorithms);
    }
    let kdf = KdfParams {
        memory_kib: read_u32(bytes, 12),
        iterations: read_u32(bytes, 16),
        lanes: read_u32(bytes, 20),
    };
    kdf.validate()?;
    let salt = bytes[24..40]
        .try_into()
        .map_err(|_| KeystoreError::InvalidEnvelope)?;
    let nonce = bytes[40..64]
        .try_into()
        .map_err(|_| KeystoreError::InvalidEnvelope)?;
    let wallet_id = bytes[64..80]
        .try_into()
        .map_err(|_| KeystoreError::InvalidEnvelope)?;
    if wallet_id == [0; WALLET_ID_BYTES] {
        return Err(KeystoreError::InvalidEnvelope);
    }
    let identity = bytes[80..176]
        .try_into()
        .map_err(|_| KeystoreError::InvalidEnvelope)?;
    if read_u32(bytes, 176) as usize != CIPHERTEXT_BYTES {
        return Err(KeystoreError::InvalidEnvelope);
    }
    Ok(ParsedHeader {
        kdf,
        salt,
        nonce,
        wallet_id,
        identity,
    })
}

fn derive_encryption_key(
    passphrase: &[u8],
    salt: &[u8; SALT_BYTES],
    kdf: KdfParams,
) -> Result<Zeroizing<[u8; 32]>, KeystoreError> {
    let mut key = Zeroizing::new([0_u8; 32]);
    kdf.argon2()?
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|_| KeystoreError::KeyDerivationFailed)?;
    Ok(key)
}

fn identity_bytes(identity: ProviderIdentity) -> [u8; IDENTITY_BYTES] {
    let mut bytes = [0_u8; IDENTITY_BYTES];
    bytes[..32].copy_from_slice(&identity.provider().to_bytes());
    bytes[32..64].copy_from_slice(&identity.genesis_hash().to_byte_array());
    bytes[64..].copy_from_slice(&identity.policy_asset().into_inner().to_byte_array());
    bytes
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed envelope offsets are in bounds"),
    )
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeystoreError {
    #[error("keystore passphrase must not be empty")]
    EmptyPassphrase,
    #[error("keystore Argon2id parameters are outside accepted bounds")]
    InvalidKdfParams,
    #[error("keystore envelope is malformed")]
    InvalidEnvelope,
    #[error("unsupported keystore format version {0}")]
    UnsupportedVersion(u16),
    #[error("unsupported keystore KDF or AEAD algorithm")]
    UnsupportedAlgorithms,
    #[error("keystore is bound to a different provider or chain identity")]
    IdentityMismatch,
    #[error("keystore key derivation failed")]
    KeyDerivationFailed,
    #[error("keystore encryption failed")]
    EncryptionFailed,
    #[error("keystore authentication or decryption failed")]
    DecryptionFailed,
    #[error("decrypted keystore payload is malformed")]
    InvalidPayload,
}

#[cfg(test)]
mod tests {
    use deadcat_rfq_provider::{ProviderId, ProviderIdentity};
    use elements::hashes::Hash as _;
    use elements::{AssetId, BlockHash};
    use rand::SeedableRng as _;
    use rand::rngs::StdRng;

    use super::*;

    const TEST_KDF: KdfParams = KdfParams {
        memory_kib: MIN_MEMORY_KIB,
        iterations: 1,
        lanes: 1,
    };

    fn identity(marker: u8) -> ProviderIdentity {
        ProviderIdentity::new(
            ProviderId::new([marker; 32]),
            BlockHash::from_byte_array([marker.wrapping_add(1); 32]),
            AssetId::from_byte_array([marker.wrapping_add(2); 32]),
        )
    }

    fn envelope(marker: u8) -> EncryptedKeystore {
        let mut rng = StdRng::seed_from_u64(u64::from(marker));
        EncryptedKeystore::seal_entropy_with_rng(
            identity(marker),
            b"a test-only strong passphrase",
            TEST_KDF,
            &[marker; 32],
            &mut rng,
        )
        .expect("seal")
    }

    #[test]
    fn round_trip_is_identity_bound_and_secret_debug_is_redacted() {
        let envelope = envelope(7);
        let unlocked = envelope
            .unlock(identity(7), b"a test-only strong passphrase")
            .expect("unlock");
        assert_eq!(unlocked.identity(), identity(7));
        assert_ne!(unlocked.wallet_id(), [0; WALLET_ID_BYTES]);
        assert_eq!(format!("{unlocked:?}"), "UnlockedSeed([redacted])");
        let debug = format!("{envelope:?}");
        assert!(!debug.contains("test-only"));
        assert!(!debug.contains(&hex_string(&[7; 32])));
        assert_eq!(
            EncryptedKeystore::from_bytes(envelope.as_bytes().to_vec()).expect("parse"),
            envelope
        );
    }

    #[test]
    fn wrong_passphrase_tampering_and_wrong_identity_fail_closed() {
        let envelope = envelope(8);
        assert!(matches!(
            envelope.unlock(identity(8), b"wrong passphrase"),
            Err(KeystoreError::DecryptionFailed)
        ));
        assert!(matches!(
            envelope.unlock(identity(9), b"a test-only strong passphrase"),
            Err(KeystoreError::IdentityMismatch)
        ));

        let mut tampered = envelope.as_bytes().to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let tampered = EncryptedKeystore::from_bytes(tampered).expect("structurally valid");
        assert!(matches!(
            tampered.unlock(identity(8), b"a test-only strong passphrase"),
            Err(KeystoreError::DecryptionFailed)
        ));
    }

    #[test]
    fn hostile_kdf_parameters_are_rejected_before_unlock() {
        let mut bytes = envelope(10).as_bytes().to_vec();
        bytes[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            EncryptedKeystore::from_bytes(bytes),
            Err(KeystoreError::InvalidKdfParams)
        );
        assert_eq!(
            KdfParams::new(MIN_MEMORY_KIB, 0, 1),
            Err(KeystoreError::InvalidKdfParams)
        );
    }

    #[test]
    fn encryption_is_randomized_for_the_same_entropy_and_identity() {
        let first = envelope(11);
        let mut rng = StdRng::seed_from_u64(12);
        let second = EncryptedKeystore::seal_entropy_with_rng(
            identity(11),
            b"a test-only strong passphrase",
            TEST_KDF,
            &[11; 32],
            &mut rng,
        )
        .expect("seal");
        assert_ne!(first, second);
        assert_eq!(
            first
                .unlock(identity(11), b"a test-only strong passphrase")
                .expect("first")
                .seed(),
            second
                .unlock(identity(11), b"a test-only strong passphrase")
                .expect("second")
                .seed()
        );
    }

    #[test]
    fn empty_passphrases_and_unknown_versions_are_rejected() {
        assert_eq!(
            EncryptedKeystore::generate_with_kdf(identity(1), b"", TEST_KDF),
            Err(KeystoreError::EmptyPassphrase)
        );
        let mut bytes = envelope(13).as_bytes().to_vec();
        bytes[8..10].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            EncryptedKeystore::from_bytes(bytes),
            Err(KeystoreError::UnsupportedVersion(2))
        );
    }

    fn hex_string(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

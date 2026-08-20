use core::fmt;
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use deadcat_rfq_provider::{
    ConfidentialDestination, DestinationPurpose, DestinationSource, ProviderIdentity,
    ProviderOutputRecovery, ProviderSigner, SigningJob, SigningResponse, WalletKeyLocator,
    WalletOwnedOutput,
};
use elements::{AssetId, OutPoint, TxOut};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use redb::{
    CommitError, Database, DatabaseError, Durability, ReadableDatabase as _, ReadableTable,
    ReadableTableMetadata as _, SetDurabilityError, StorageError, TableDefinition, TableError,
    TransactionError, WriteTransaction,
};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use tempfile::TempPath;
use thiserror::Error;

use crate::{
    DEFAULT_KDF_PARAMS, EncryptedKeystore, KdfParams, KeystoreError, RfqWallet, RfqWalletError,
};

const SCHEMA_VERSION: u32 = 1;
const CATALOG_CHECKPOINT_VERSION: u32 = 1;
const DATABASE_CACHE_BYTES: usize = 16 * 1024 * 1024;
const CATALOG_NONCE_BYTES: usize = 16;
const CATALOG_VALUE_BYTES: usize = 8 + 32;
const CHECKPOINT_BYTES: usize = 32;
const MAX_ISSUANCE_ATTEMPTS: usize = 32;

const SCHEMA_VERSION_KEY: &str = "schema_version";
const PROVIDER_IDENTITY_KEY: &str = "provider_identity";
const WALLET_ID_KEY: &str = "wallet_id";
const ENCRYPTED_KEYSTORE_KEY: &str = "encrypted_keystore";
const KEYSTORE_DIGEST_KEY: &str = "keystore_digest";
const CATALOG_REVISION_KEY: &str = "catalog_revision";
const CATALOG_CHECKPOINT_KEY: &str = "catalog_checkpoint";
const META_ENTRY_COUNT: u64 = 7;

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("wallet_meta");
// The nonce is the key rather than the complete locator so a repeated random
// namespace is rejected even when it is presented under a different purpose.
const CATALOG: TableDefinition<&[u8], &[u8]> = TableDefinition::new("issued_locators");

const CATALOG_ROOT_DOMAIN: &[u8] = b"deadcat/rfq/wallet/catalog-root/v1";
const CATALOG_ENTRY_DOMAIN: &[u8] = b"deadcat/rfq/wallet/catalog-entry/v1";

const BACKUP_MAGIC: &[u8; 8] = b"DCRFQWB\0";
const BACKUP_VERSION: u16 = 1;
const BACKUP_FLAGS: u16 = 0;
const BACKUP_HEADER_BYTES: usize = 8 + 2 + 2 + 4 + 96 + 16 + 8 + 4 + 4;
const BACKUP_TRAILER_BYTES: usize = CHECKPOINT_BYTES;
const MAX_BACKUP_KEYSTORE_BYTES: usize = 4 * 1024;

/// Hard bound shared by live issuance and logical backup parsing.
///
/// The catalog is append-only. A deployment approaching this deliberately
/// generous bound must rotate to a new wallet through an explicit operational
/// procedure rather than producing a backup that this implementation cannot
/// safely parse.
pub const MAX_WALLET_CATALOG_ENTRIES: u64 = 1_000_000;

/// One coherent, revisioned view of every destination locator ever issued by
/// this wallet.
#[derive(Clone, PartialEq, Eq)]
pub struct WalletCatalogSnapshot {
    revision: u64,
    checkpoint: [u8; CHECKPOINT_BYTES],
    locators: Vec<WalletKeyLocator>,
}

impl WalletCatalogSnapshot {
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn checkpoint(&self) -> [u8; CHECKPOINT_BYTES] {
        self.checkpoint
    }

    #[must_use]
    pub fn locators(&self) -> &[WalletKeyLocator] {
        &self.locators
    }
}

impl fmt::Debug for WalletCatalogSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletCatalogSnapshot")
            .field("revision", &self.revision)
            .field("checkpoint", &"[authenticated]")
            .field(
                "locators",
                &format_args!("[{} opaque entries]", self.locators.len()),
            )
            .finish()
    }
}

/// Bounded wallet-only recovery artifact.
///
/// This contains the encrypted keystore and append-only locator catalog, but
/// no provider reservation state, signing commitments, chain state, plaintext
/// key material, passphrase, or confidential openings. Restoring an authentic
/// stale artifact cannot discover random locators issued after its revision.
/// Bytes accepted through [`Self::from_bytes`] are only structurally checked;
/// the wallet-derived catalog checkpoint is authenticated during restore.
#[derive(Clone, PartialEq, Eq)]
pub struct WalletBackup {
    bytes: Vec<u8>,
}

impl WalletBackup {
    /// Parse and structurally bound a logical backup. Authentication is
    /// completed during [`PersistentRfqWallet::restore`], after the encrypted
    /// keystore has been unlocked.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, PersistentWalletError> {
        parse_backup(&bytes)?;
        Ok(Self { bytes })
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn revision(&self) -> u64 {
        // Construction has already validated all fixed offsets.
        read_u64(&self.bytes, 128)
    }

    #[must_use]
    pub fn checkpoint(&self) -> [u8; CHECKPOINT_BYTES] {
        self.bytes[self.bytes.len() - CHECKPOINT_BYTES..]
            .try_into()
            .expect("validated backup trailer has a fixed length")
    }
}

impl fmt::Debug for WalletBackup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletBackup")
            .field("bytes", &self.bytes.len())
            .field("declared_revision", &self.revision())
            .field(
                "contents",
                &"[encrypted keystore; opaque catalog; authentication deferred]",
            )
            .finish()
    }
}

/// Identity-bound wallet plus crash-durable destination catalog.
///
/// This is the only type in this crate that implements [`DestinationSource`].
/// Every returned destination is committed to redb with immediate durability
/// before it crosses the API boundary. An error after that commit may burn an
/// unused but still discoverable destination; an uncommitted destination is
/// never returned.
///
/// The current persistent backend is Unix-only and requires an owner-controlled
/// parent directory plus a local filesystem that supports exclusive file
/// locks. It rejects unsupported locking instead of accepting a single-writer
/// promise from the embedding service. The complete path hierarchy must be
/// trusted against rename or replacement; only the immediate parent is
/// validated directly.
///
/// Once no-clobber publication succeeds, a later inode check, directory sync,
/// or validation error is reported as
/// [`PersistentWalletError::PublishedButUnconfirmed`]. The caller must inspect
/// and reopen the existing target and must never blindly delete or recreate it.
pub struct PersistentRfqWallet<R = OsRng> {
    database: Database,
    wallet: RfqWallet<R>,
    identity: ProviderIdentity,
    operation_lock: Mutex<()>,
    poisoned: AtomicBool,
}

impl PersistentRfqWallet<OsRng> {
    /// Create a new wallet database at an absent path using the default KDF.
    pub fn create(
        path: impl AsRef<Path>,
        identity: ProviderIdentity,
        passphrase: &[u8],
    ) -> Result<Self, PersistentWalletError> {
        Self::create_with_kdf(path, identity, passphrase, DEFAULT_KDF_PARAMS)
    }

    /// Create a new wallet using an explicitly selected bounded KDF profile.
    pub fn create_with_kdf(
        path: impl AsRef<Path>,
        identity: ProviderIdentity,
        passphrase: &[u8],
        kdf: KdfParams,
    ) -> Result<Self, PersistentWalletError> {
        let envelope = EncryptedKeystore::generate_with_kdf(identity, passphrase, kdf)?;
        Self::create_from_envelope(path.as_ref(), identity, passphrase, &envelope, OsRng)
    }

    /// Open an existing wallet. This never creates or initializes a missing or
    /// empty database.
    pub fn open(
        path: impl AsRef<Path>,
        identity: ProviderIdentity,
        passphrase: &[u8],
    ) -> Result<Self, PersistentWalletError> {
        Self::open_with_rng(path.as_ref(), identity, passphrase, OsRng)
    }

    /// Restore an authenticated wallet-only backup into an absent path.
    ///
    /// The caller must reconcile the accompanying provider database and chain
    /// state before allowing the restored wallet to quote or sign. Running the
    /// restored wallet concurrently with its source clone is unsupported.
    pub fn restore(
        path: impl AsRef<Path>,
        identity: ProviderIdentity,
        passphrase: &[u8],
        backup: &WalletBackup,
    ) -> Result<Self, PersistentWalletError> {
        Self::restore_with_rng(path.as_ref(), identity, passphrase, backup, OsRng)
    }
}

impl<R: RngCore + CryptoRng + Send> PersistentRfqWallet<R> {
    fn create_from_envelope(
        path: &Path,
        identity: ProviderIdentity,
        passphrase: &[u8],
        envelope: &EncryptedKeystore,
        rng: R,
    ) -> Result<Self, PersistentWalletError> {
        let wallet = RfqWallet::with_rng(envelope.unlock(identity, passphrase)?, rng)?;
        let entries = Vec::new();
        let checkpoint = catalog_root_checkpoint(&wallet, envelope)?;
        let (database, staging, staging_identity) = create_staging_database(path)?;
        initialize_database(
            &database,
            identity,
            wallet.wallet_id(),
            envelope,
            &entries,
            checkpoint,
        )?;
        validate_database(&database, &wallet, identity, envelope)?;
        let database = publish_staging_database(database, staging, staging_identity, path)?;
        validate_database(&database, &wallet, identity, envelope)
            .map_err(PersistentWalletError::published_but_unconfirmed)?;
        Ok(Self {
            database,
            wallet,
            identity,
            operation_lock: Mutex::new(()),
            poisoned: AtomicBool::new(false),
        })
    }

    fn open_with_rng(
        path: &Path,
        identity: ProviderIdentity,
        passphrase: &[u8],
        rng: R,
    ) -> Result<Self, PersistentWalletError> {
        let database = open_database(path)?;
        let envelope = load_envelope(&database, identity)?;
        let wallet = RfqWallet::with_rng(envelope.unlock(identity, passphrase)?, rng)?;
        validate_database(&database, &wallet, identity, &envelope)?;
        Ok(Self {
            database,
            wallet,
            identity,
            operation_lock: Mutex::new(()),
            poisoned: AtomicBool::new(false),
        })
    }

    fn restore_with_rng(
        path: &Path,
        identity: ProviderIdentity,
        passphrase: &[u8],
        backup: &WalletBackup,
        rng: R,
    ) -> Result<Self, PersistentWalletError> {
        let parsed = parse_backup(backup.as_bytes())?;
        if parsed.identity != identity_bytes(identity) {
            return Err(PersistentWalletError::IdentityMismatch);
        }
        let envelope = EncryptedKeystore::from_bytes(parsed.keystore.to_vec())?;
        let wallet = RfqWallet::with_rng(envelope.unlock(identity, passphrase)?, rng)?;
        if wallet.wallet_id() != parsed.wallet_id {
            return Err(PersistentWalletError::WalletBindingMismatch);
        }
        let entries = validate_backup_catalog(&wallet, &envelope, &parsed)?;
        let (database, staging, staging_identity) = create_staging_database(path)?;
        initialize_database(
            &database,
            identity,
            wallet.wallet_id(),
            &envelope,
            &entries,
            parsed.checkpoint,
        )?;
        validate_database(&database, &wallet, identity, &envelope)?;
        let database = publish_staging_database(database, staging, staging_identity, path)?;
        validate_database(&database, &wallet, identity, &envelope)
            .map_err(PersistentWalletError::published_but_unconfirmed)?;
        Ok(Self {
            database,
            wallet,
            identity,
            operation_lock: Mutex::new(()),
            poisoned: AtomicBool::new(false),
        })
    }

    #[must_use]
    pub const fn identity(&self) -> ProviderIdentity {
        self.identity
    }

    /// Issue a durable confidential destination for initial or replenishment
    /// liquidity supplied by the operator.
    pub fn fresh_inventory_destination(
        &self,
    ) -> Result<ConfidentialDestination, PersistentWalletError> {
        self.issue_destination(IssuancePurpose::InventoryDeposit)
    }

    /// Reconstruct one authenticated destination without exporting private key
    /// material.
    pub fn recover_confidential_destination(
        &self,
        locator: WalletKeyLocator,
    ) -> Result<ConfidentialDestination, PersistentWalletError> {
        let _operation_guard = self.lock_operations()?;
        self.ensure_healthy()?;
        self.wallet
            .recover_confidential_destination(locator)
            .map_err(PersistentWalletError::from)
    }

    /// Recover a complete wallet-owned output for the future authoritative
    /// inventory scanner without exposing its confidential opening.
    pub fn recover_owned_output(
        &self,
        locator: WalletKeyLocator,
        outpoint: OutPoint,
        txout: TxOut,
    ) -> Result<WalletOwnedOutput, PersistentWalletError> {
        let _operation_guard = self.lock_operations()?;
        self.ensure_healthy()?;
        self.wallet
            .recover_owned_output(locator, outpoint, txout)
            .map_err(PersistentWalletError::from)
    }

    /// Read the catalog revision without retaining a database snapshot. A
    /// scanner compares this before and after its external chain observation.
    pub fn catalog_revision(&self) -> Result<u64, PersistentWalletError> {
        let _operation_guard = self.lock_operations()?;
        self.ensure_healthy()?;
        let read = self.database.begin_read()?;
        let meta = read.open_table(META)?;
        read_metadata_u64(&meta, CATALOG_REVISION_KEY)
    }

    /// Read and authenticate one coherent catalog snapshot.
    pub fn catalog_snapshot(&self) -> Result<WalletCatalogSnapshot, PersistentWalletError> {
        let _operation_guard = self.lock_operations()?;
        self.ensure_healthy()?;
        let state = read_and_validate_state(&self.database, &self.wallet, self.identity)?;
        Ok(WalletCatalogSnapshot {
            revision: state.revision,
            checkpoint: state.checkpoint,
            locators: state
                .entries
                .into_iter()
                .map(|entry| entry.locator)
                .collect(),
        })
    }

    /// Export one coherent logical wallet-only snapshot.
    pub fn export_backup(&self) -> Result<WalletBackup, PersistentWalletError> {
        let _operation_guard = self.lock_operations()?;
        self.ensure_healthy()?;
        let state = read_and_validate_state(&self.database, &self.wallet, self.identity)?;
        encode_backup(self.identity, self.wallet.wallet_id(), &state)
    }

    fn issue_destination(
        &self,
        purpose: IssuancePurpose,
    ) -> Result<ConfidentialDestination, PersistentWalletError> {
        let _operation_guard = self.lock_operations()?;
        self.ensure_healthy()?;
        for _ in 0..MAX_ISSUANCE_ATTEMPTS {
            let destination = match purpose {
                IssuancePurpose::InventoryDeposit => {
                    self.wallet.candidate_inventory_destination()?
                }
                IssuancePurpose::Settlement(purpose) => {
                    self.wallet.candidate_settlement_destination(purpose)?
                }
            };
            #[cfg(test)]
            mutation_failpoints::hit(mutation_failpoints::ISSUE_AFTER_DERIVATION)?;

            let locator = destination.wallet_locator();
            let nonce = self.wallet.locator_nonce(locator)?;
            let write = self.begin_immediate_write()?;
            let (revision, checkpoint) = {
                let meta = write.open_table(META)?;
                (
                    read_metadata_u64(&meta, CATALOG_REVISION_KEY)?,
                    read_metadata_array::<CHECKPOINT_BYTES>(&meta, CATALOG_CHECKPOINT_KEY)?,
                )
            };
            {
                let mut catalog = write.open_table(CATALOG)?;
                if catalog.get(nonce.as_slice())?.is_some() {
                    drop(catalog);
                    drop(write);
                    continue;
                }
                if revision >= MAX_WALLET_CATALOG_ENTRIES {
                    return Err(PersistentWalletError::CatalogFull);
                }
                let next_revision = revision
                    .checked_add(1)
                    .ok_or(PersistentWalletError::CatalogRevisionOverflow)?;
                let value = encode_catalog_value(next_revision, locator);
                catalog.insert(nonce.as_slice(), value.as_slice())?;
                #[cfg(test)]
                mutation_failpoints::hit(mutation_failpoints::ISSUE_AFTER_CATALOG_INSERT)?;
                drop(catalog);

                let next_checkpoint =
                    catalog_entry_checkpoint(&self.wallet, checkpoint, next_revision, locator)?;
                let mut meta = write.open_table(META)?;
                meta.insert(CATALOG_REVISION_KEY, next_revision.to_be_bytes().as_slice())?;
                #[cfg(test)]
                mutation_failpoints::hit(mutation_failpoints::ISSUE_AFTER_REVISION)?;
                meta.insert(CATALOG_CHECKPOINT_KEY, next_checkpoint.as_slice())?;
            }
            #[cfg(test)]
            mutation_failpoints::hit(mutation_failpoints::ISSUE_BEFORE_COMMIT)?;
            self.commit_write(write)?;
            #[cfg(test)]
            mutation_failpoints::hit(mutation_failpoints::ISSUE_AFTER_COMMIT)?;
            return Ok(destination);
        }
        Err(PersistentWalletError::DestinationEntropyExhausted)
    }

    fn lock_operations(&self) -> Result<MutexGuard<'_, ()>, PersistentWalletError> {
        self.operation_lock
            .lock()
            .map_err(|_| PersistentWalletError::OperationLockPoisoned)
    }

    fn ensure_healthy(&self) -> Result<(), PersistentWalletError> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(PersistentWalletError::Poisoned);
        }
        Ok(())
    }

    fn begin_immediate_write(&self) -> Result<WriteTransaction, PersistentWalletError> {
        self.ensure_healthy()?;
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        Ok(write)
    }

    fn commit_write(&self, write: WriteTransaction) -> Result<(), PersistentWalletError> {
        match write.commit() {
            Ok(()) => {
                #[cfg(test)]
                if let Err(error) =
                    mutation_failpoints::hit(mutation_failpoints::ISSUE_COMMIT_AMBIGUOUS)
                {
                    // Model a backend that reports failure after the commit's
                    // durability outcome can no longer be distinguished. The
                    // live handle must remain unusable until a clean reopen.
                    self.poisoned.store(true, Ordering::Release);
                    return Err(error);
                }
                Ok(())
            }
            Err(error) => {
                self.poisoned.store(true, Ordering::Release);
                Err(PersistentWalletError::Commit(error))
            }
        }
    }
}

impl<R> fmt::Debug for PersistentRfqWallet<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentRfqWallet")
            .field("identity", &self.identity)
            .field("wallet", &"[unlocked and redacted]")
            .field("catalog", &"[durable and opaque]")
            .finish_non_exhaustive()
    }
}

impl<R: RngCore + CryptoRng + Send> DestinationSource for PersistentRfqWallet<R> {
    type Error = PersistentWalletError;

    fn fresh_confidential_destination(
        &self,
        purpose: DestinationPurpose,
    ) -> Result<ConfidentialDestination, Self::Error> {
        self.issue_destination(IssuancePurpose::Settlement(purpose))
    }
}

impl<R: RngCore + CryptoRng + Send> ProviderOutputRecovery for PersistentRfqWallet<R> {
    type Error = PersistentWalletError;

    fn validate_confidential_output(
        &self,
        wallet_locator: WalletKeyLocator,
        expected_internal_key: elements::secp256k1_zkp::XOnlyPublicKey,
        txout: &TxOut,
        expected_asset: AssetId,
        expected_amount: u64,
    ) -> Result<(), Self::Error> {
        let _operation_guard = self.lock_operations()?;
        self.ensure_healthy()?;
        self.wallet
            .validate_confidential_output(
                wallet_locator,
                expected_internal_key,
                txout,
                expected_asset,
                expected_amount,
            )
            .map_err(PersistentWalletError::from)
    }
}

impl<R: RngCore + CryptoRng + Send> ProviderSigner for PersistentRfqWallet<R> {
    type Error = PersistentWalletError;

    fn sign(&self, job: &SigningJob) -> Result<SigningResponse, Self::Error> {
        let _operation_guard = self.lock_operations()?;
        self.ensure_healthy()?;
        // A durable provider job may legitimately contain a later authenticated
        // locator that is absent from a stale wallet-only backup. Locator MAC
        // validation still binds every target to this exact seed, identity,
        // and wallet id; catalog membership is an issuance/scanning concern.
        self.wallet.sign(job).map_err(PersistentWalletError::from)
    }
}

#[derive(Clone, Copy)]
enum IssuancePurpose {
    InventoryDeposit,
    Settlement(DestinationPurpose),
}

#[derive(Clone, Copy)]
struct CatalogEntry {
    revision: u64,
    locator: WalletKeyLocator,
}

struct StoredState {
    envelope: EncryptedKeystore,
    revision: u64,
    checkpoint: [u8; CHECKPOINT_BYTES],
    entries: Vec<CatalogEntry>,
}

fn initialize_database(
    database: &Database,
    identity: ProviderIdentity,
    wallet_id: [u8; 16],
    envelope: &EncryptedKeystore,
    entries: &[CatalogEntry],
    checkpoint: [u8; CHECKPOINT_BYTES],
) -> Result<(), PersistentWalletError> {
    if entries.len() as u64 > MAX_WALLET_CATALOG_ENTRIES {
        return Err(PersistentWalletError::CatalogFull);
    }
    let mut write = database.begin_write()?;
    write.set_durability(Durability::Immediate)?;
    {
        let mut meta = write.open_table(META)?;
        if !meta.is_empty()? {
            return Err(PersistentWalletError::NonemptyNewDatabase);
        }
        meta.insert(SCHEMA_VERSION_KEY, SCHEMA_VERSION.to_be_bytes().as_slice())?;
        meta.insert(PROVIDER_IDENTITY_KEY, identity_bytes(identity).as_slice())?;
        meta.insert(WALLET_ID_KEY, wallet_id.as_slice())?;
        meta.insert(ENCRYPTED_KEYSTORE_KEY, envelope.as_bytes())?;
        meta.insert(KEYSTORE_DIGEST_KEY, keystore_digest(envelope).as_slice())?;
        meta.insert(
            CATALOG_REVISION_KEY,
            (entries.len() as u64).to_be_bytes().as_slice(),
        )?;
        meta.insert(CATALOG_CHECKPOINT_KEY, checkpoint.as_slice())?;
    }
    {
        let mut catalog = write.open_table(CATALOG)?;
        if !catalog.is_empty()? {
            return Err(PersistentWalletError::NonemptyNewDatabase);
        }
        for entry in entries {
            let locator_bytes = entry.locator.to_bytes();
            let nonce = &locator_bytes[2..2 + CATALOG_NONCE_BYTES];
            let value = encode_catalog_value(entry.revision, entry.locator);
            if catalog.insert(nonce, value.as_slice())?.is_some() {
                return Err(PersistentWalletError::DuplicateCatalogNonce);
            }
        }
    }
    write.commit()?;
    Ok(())
}

fn load_envelope(
    database: &Database,
    expected_identity: ProviderIdentity,
) -> Result<EncryptedKeystore, PersistentWalletError> {
    let read = database.begin_read()?;
    let meta = read.open_table(META)?;
    if meta.len()? != META_ENTRY_COUNT {
        return Err(PersistentWalletError::CorruptMetadata);
    }
    let schema = read_metadata_u32(&meta, SCHEMA_VERSION_KEY)?;
    if schema != SCHEMA_VERSION {
        return Err(PersistentWalletError::UnsupportedSchemaVersion(schema));
    }
    let identity = read_metadata_array::<96>(&meta, PROVIDER_IDENTITY_KEY)?;
    if identity != identity_bytes(expected_identity) {
        return Err(PersistentWalletError::IdentityMismatch);
    }
    let bytes = read_metadata_vec(&meta, ENCRYPTED_KEYSTORE_KEY)?;
    let envelope = EncryptedKeystore::from_bytes(bytes)?;
    let expected_digest = read_metadata_array::<32>(&meta, KEYSTORE_DIGEST_KEY)?;
    if !bool::from(expected_digest.ct_eq(&keystore_digest(&envelope))) {
        return Err(PersistentWalletError::WalletBindingMismatch);
    }
    Ok(envelope)
}

fn validate_database<R: RngCore + CryptoRng + Send>(
    database: &Database,
    wallet: &RfqWallet<R>,
    identity: ProviderIdentity,
    envelope: &EncryptedKeystore,
) -> Result<(), PersistentWalletError> {
    let state = read_and_validate_state(database, wallet, identity)?;
    if state.envelope != *envelope {
        return Err(PersistentWalletError::WalletBindingMismatch);
    }
    Ok(())
}

fn read_and_validate_state<R: RngCore + CryptoRng + Send>(
    database: &Database,
    wallet: &RfqWallet<R>,
    expected_identity: ProviderIdentity,
) -> Result<StoredState, PersistentWalletError> {
    let read = database.begin_read()?;
    let meta = read.open_table(META)?;
    if meta.len()? != META_ENTRY_COUNT {
        return Err(PersistentWalletError::CorruptMetadata);
    }
    let schema = read_metadata_u32(&meta, SCHEMA_VERSION_KEY)?;
    if schema != SCHEMA_VERSION {
        return Err(PersistentWalletError::UnsupportedSchemaVersion(schema));
    }
    if read_metadata_array::<96>(&meta, PROVIDER_IDENTITY_KEY)? != identity_bytes(expected_identity)
    {
        return Err(PersistentWalletError::IdentityMismatch);
    }
    if read_metadata_array::<16>(&meta, WALLET_ID_KEY)? != wallet.wallet_id() {
        return Err(PersistentWalletError::WalletBindingMismatch);
    }
    let envelope =
        EncryptedKeystore::from_bytes(read_metadata_vec(&meta, ENCRYPTED_KEYSTORE_KEY)?)?;
    if !bool::from(
        read_metadata_array::<32>(&meta, KEYSTORE_DIGEST_KEY)?.ct_eq(&keystore_digest(&envelope)),
    ) {
        return Err(PersistentWalletError::WalletBindingMismatch);
    }
    let revision = read_metadata_u64(&meta, CATALOG_REVISION_KEY)?;
    if revision > MAX_WALLET_CATALOG_ENTRIES {
        return Err(PersistentWalletError::CatalogFull);
    }
    let checkpoint = read_metadata_array::<CHECKPOINT_BYTES>(&meta, CATALOG_CHECKPOINT_KEY)?;
    drop(meta);

    let catalog = read.open_table(CATALOG)?;
    if catalog.len()? != revision {
        return Err(PersistentWalletError::CatalogRevisionMismatch);
    }
    let mut entries = Vec::with_capacity(
        usize::try_from(revision).map_err(|_| PersistentWalletError::CatalogFull)?,
    );
    let mut revisions = BTreeSet::new();
    for row in catalog.iter()? {
        let (key, value) = row?;
        let entry = decode_catalog_entry(key.value(), value.value())?;
        wallet.validate_locator(entry.locator)?;
        if wallet.locator_nonce(entry.locator)?.as_slice() != key.value() {
            return Err(PersistentWalletError::CatalogNonceMismatch);
        }
        if !revisions.insert(entry.revision) {
            return Err(PersistentWalletError::DuplicateCatalogRevision);
        }
        entries.push(entry);
    }
    entries.sort_by_key(|entry| entry.revision);
    validate_contiguous_entries(&entries, revision)?;
    let actual_checkpoint = recompute_catalog_checkpoint(wallet, &envelope, &entries)?;
    if !bool::from(actual_checkpoint.ct_eq(&checkpoint)) {
        return Err(PersistentWalletError::CatalogCheckpointMismatch);
    }
    Ok(StoredState {
        envelope,
        revision,
        checkpoint,
        entries,
    })
}

fn validate_contiguous_entries(
    entries: &[CatalogEntry],
    revision: u64,
) -> Result<(), PersistentWalletError> {
    if entries.len() as u64 != revision {
        return Err(PersistentWalletError::CatalogRevisionMismatch);
    }
    for (index, entry) in entries.iter().enumerate() {
        if entry.revision != index as u64 + 1 {
            return Err(PersistentWalletError::CatalogRevisionMismatch);
        }
    }
    Ok(())
}

fn catalog_root_checkpoint<R: RngCore + CryptoRng + Send>(
    wallet: &RfqWallet<R>,
    envelope: &EncryptedKeystore,
) -> Result<[u8; CHECKPOINT_BYTES], PersistentWalletError> {
    let mut payload = Vec::with_capacity(CATALOG_ROOT_DOMAIN.len() + 4 + 96 + 16 + 32);
    payload.extend_from_slice(CATALOG_ROOT_DOMAIN);
    payload.extend_from_slice(&CATALOG_CHECKPOINT_VERSION.to_be_bytes());
    payload.extend_from_slice(&identity_bytes(wallet.identity()));
    payload.extend_from_slice(&wallet.wallet_id());
    payload.extend_from_slice(&keystore_digest(envelope));
    wallet
        .backup_authentication_tag(&payload)
        .map_err(PersistentWalletError::from)
}

fn catalog_entry_checkpoint<R: RngCore + CryptoRng + Send>(
    wallet: &RfqWallet<R>,
    previous: [u8; CHECKPOINT_BYTES],
    revision: u64,
    locator: WalletKeyLocator,
) -> Result<[u8; CHECKPOINT_BYTES], PersistentWalletError> {
    let mut payload = Vec::with_capacity(CATALOG_ENTRY_DOMAIN.len() + 32 + 8 + 32);
    payload.extend_from_slice(CATALOG_ENTRY_DOMAIN);
    payload.extend_from_slice(&previous);
    payload.extend_from_slice(&revision.to_be_bytes());
    payload.extend_from_slice(&locator.to_bytes());
    wallet
        .backup_authentication_tag(&payload)
        .map_err(PersistentWalletError::from)
}

fn recompute_catalog_checkpoint<R: RngCore + CryptoRng + Send>(
    wallet: &RfqWallet<R>,
    envelope: &EncryptedKeystore,
    entries: &[CatalogEntry],
) -> Result<[u8; CHECKPOINT_BYTES], PersistentWalletError> {
    let mut checkpoint = catalog_root_checkpoint(wallet, envelope)?;
    for entry in entries {
        checkpoint = catalog_entry_checkpoint(wallet, checkpoint, entry.revision, entry.locator)?;
    }
    Ok(checkpoint)
}

fn encode_catalog_value(revision: u64, locator: WalletKeyLocator) -> [u8; CATALOG_VALUE_BYTES] {
    let mut value = [0_u8; CATALOG_VALUE_BYTES];
    value[..8].copy_from_slice(&revision.to_be_bytes());
    value[8..].copy_from_slice(&locator.to_bytes());
    value
}

fn decode_catalog_entry(key: &[u8], value: &[u8]) -> Result<CatalogEntry, PersistentWalletError> {
    if key.len() != CATALOG_NONCE_BYTES || value.len() != CATALOG_VALUE_BYTES {
        return Err(PersistentWalletError::CorruptCatalogEntry);
    }
    let locator_bytes: [u8; 32] = value[8..]
        .try_into()
        .map_err(|_| PersistentWalletError::CorruptCatalogEntry)?;
    Ok(CatalogEntry {
        revision: read_u64(value, 0),
        locator: WalletKeyLocator::new(locator_bytes)
            .map_err(|_| PersistentWalletError::CorruptCatalogEntry)?,
    })
}

fn encode_backup(
    identity: ProviderIdentity,
    wallet_id: [u8; 16],
    state: &StoredState,
) -> Result<WalletBackup, PersistentWalletError> {
    let count =
        u32::try_from(state.entries.len()).map_err(|_| PersistentWalletError::BackupTooLarge)?;
    let keystore_len = u32::try_from(state.envelope.as_bytes().len())
        .map_err(|_| PersistentWalletError::BackupTooLarge)?;
    let total_len = BACKUP_HEADER_BYTES
        .checked_add(state.envelope.as_bytes().len())
        .and_then(|value| value.checked_add(state.entries.len().checked_mul(32)?))
        .and_then(|value| value.checked_add(BACKUP_TRAILER_BYTES))
        .ok_or(PersistentWalletError::BackupTooLarge)?;
    let total_len_u32 =
        u32::try_from(total_len).map_err(|_| PersistentWalletError::BackupTooLarge)?;
    let mut bytes = Vec::with_capacity(total_len);
    bytes.extend_from_slice(BACKUP_MAGIC);
    bytes.extend_from_slice(&BACKUP_VERSION.to_be_bytes());
    bytes.extend_from_slice(&BACKUP_FLAGS.to_be_bytes());
    bytes.extend_from_slice(&total_len_u32.to_be_bytes());
    bytes.extend_from_slice(&identity_bytes(identity));
    bytes.extend_from_slice(&wallet_id);
    bytes.extend_from_slice(&state.revision.to_be_bytes());
    bytes.extend_from_slice(&keystore_len.to_be_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(state.envelope.as_bytes());
    for entry in &state.entries {
        bytes.extend_from_slice(&entry.locator.to_bytes());
    }
    bytes.extend_from_slice(&state.checkpoint);
    debug_assert_eq!(bytes.len(), total_len);
    WalletBackup::from_bytes(bytes)
}

struct ParsedBackup<'a> {
    identity: [u8; 96],
    wallet_id: [u8; 16],
    revision: u64,
    keystore: &'a [u8],
    locators: &'a [u8],
    checkpoint: [u8; CHECKPOINT_BYTES],
}

fn parse_backup(bytes: &[u8]) -> Result<ParsedBackup<'_>, PersistentWalletError> {
    if bytes.len() < BACKUP_HEADER_BYTES + BACKUP_TRAILER_BYTES || &bytes[..8] != BACKUP_MAGIC {
        return Err(PersistentWalletError::InvalidBackup);
    }
    let version = read_u16(bytes, 8);
    if version != BACKUP_VERSION {
        return Err(PersistentWalletError::UnsupportedBackupVersion(version));
    }
    if read_u16(bytes, 10) != BACKUP_FLAGS {
        return Err(PersistentWalletError::UnsupportedBackupFlags);
    }
    let declared_len = read_u32(bytes, 12) as usize;
    if declared_len != bytes.len() {
        return Err(PersistentWalletError::InvalidBackup);
    }
    let identity = bytes[16..112]
        .try_into()
        .map_err(|_| PersistentWalletError::InvalidBackup)?;
    let wallet_id = bytes[112..128]
        .try_into()
        .map_err(|_| PersistentWalletError::InvalidBackup)?;
    if wallet_id == [0; 16] {
        return Err(PersistentWalletError::InvalidBackup);
    }
    let revision = read_u64(bytes, 128);
    let keystore_len = read_u32(bytes, 136) as usize;
    let locator_count = read_u32(bytes, 140) as u64;
    if revision != locator_count
        || revision > MAX_WALLET_CATALOG_ENTRIES
        || keystore_len == 0
        || keystore_len > MAX_BACKUP_KEYSTORE_BYTES
    {
        return Err(PersistentWalletError::InvalidBackup);
    }
    let locator_bytes = usize::try_from(locator_count)
        .ok()
        .and_then(|count| count.checked_mul(32))
        .ok_or(PersistentWalletError::BackupTooLarge)?;
    let expected_len = BACKUP_HEADER_BYTES
        .checked_add(keystore_len)
        .and_then(|value| value.checked_add(locator_bytes))
        .and_then(|value| value.checked_add(BACKUP_TRAILER_BYTES))
        .ok_or(PersistentWalletError::BackupTooLarge)?;
    if expected_len != bytes.len() {
        return Err(PersistentWalletError::InvalidBackup);
    }
    let keystore_end = BACKUP_HEADER_BYTES + keystore_len;
    let locators_end = keystore_end + locator_bytes;
    let keystore = &bytes[BACKUP_HEADER_BYTES..keystore_end];
    EncryptedKeystore::from_bytes(keystore.to_vec())?;
    let checkpoint = bytes[locators_end..]
        .try_into()
        .map_err(|_| PersistentWalletError::InvalidBackup)?;
    Ok(ParsedBackup {
        identity,
        wallet_id,
        revision,
        keystore,
        locators: &bytes[keystore_end..locators_end],
        checkpoint,
    })
}

fn validate_backup_catalog<R: RngCore + CryptoRng + Send>(
    wallet: &RfqWallet<R>,
    envelope: &EncryptedKeystore,
    backup: &ParsedBackup<'_>,
) -> Result<Vec<CatalogEntry>, PersistentWalletError> {
    let mut entries = Vec::with_capacity(
        usize::try_from(backup.revision).map_err(|_| PersistentWalletError::BackupTooLarge)?,
    );
    let mut nonces = BTreeSet::new();
    for (index, bytes) in backup.locators.chunks_exact(32).enumerate() {
        let locator = WalletKeyLocator::new(
            bytes
                .try_into()
                .map_err(|_| PersistentWalletError::InvalidBackup)?,
        )
        .map_err(|_| PersistentWalletError::InvalidBackup)?;
        wallet.validate_locator(locator)?;
        if !nonces.insert(wallet.locator_nonce(locator)?) {
            return Err(PersistentWalletError::DuplicateCatalogNonce);
        }
        entries.push(CatalogEntry {
            revision: index as u64 + 1,
            locator,
        });
    }
    let actual = recompute_catalog_checkpoint(wallet, envelope, &entries)?;
    if !bool::from(actual.ct_eq(&backup.checkpoint)) {
        return Err(PersistentWalletError::CatalogCheckpointMismatch);
    }
    Ok(entries)
}

fn keystore_digest(envelope: &EncryptedKeystore) -> [u8; 32] {
    Sha256::digest(envelope.as_bytes()).into()
}

fn identity_bytes(identity: ProviderIdentity) -> [u8; 96] {
    use elements::hashes::Hash as _;

    let mut bytes = [0_u8; 96];
    bytes[..32].copy_from_slice(&identity.provider().to_bytes());
    bytes[32..64].copy_from_slice(&identity.genesis_hash().to_byte_array());
    bytes[64..].copy_from_slice(&identity.policy_asset().into_inner().to_byte_array());
    bytes
}

fn read_metadata_vec(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &'static str,
) -> Result<Vec<u8>, PersistentWalletError> {
    table
        .get(key)?
        .map(|value| value.value().to_vec())
        .ok_or(PersistentWalletError::MissingMetadata(key))
}

fn read_metadata_array<const N: usize>(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &'static str,
) -> Result<[u8; N], PersistentWalletError> {
    let bytes = table
        .get(key)?
        .ok_or(PersistentWalletError::MissingMetadata(key))?;
    bytes
        .value()
        .try_into()
        .map_err(|_| PersistentWalletError::CorruptMetadata)
}

fn read_metadata_u32(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &'static str,
) -> Result<u32, PersistentWalletError> {
    read_metadata_array::<4>(table, key).map(u32::from_be_bytes)
}

fn read_metadata_u64(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &'static str,
) -> Result<u64, PersistentWalletError> {
    read_metadata_array::<8>(table, key).map(u64::from_be_bytes)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("validated fixed backup offset"),
    )
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("validated fixed backup offset"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("validated fixed backup offset"),
    )
}

fn create_staging_database(
    target: &Path,
) -> Result<(Database, TempPath, StagingFileIdentity), PersistentWalletError> {
    ensure_target_absent(target)?;
    validate_parent_directory(target)?;
    let parent = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let temporary = tempfile::Builder::new()
        .prefix(".deadcat-rfq-wallet-")
        .tempfile_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    validate_open_file(temporary.as_file())?;
    let identity = StagingFileIdentity::from_file(temporary.as_file())?;
    let (file, path) = temporary.into_parts();
    let database = database_from_file(file)?;
    Ok((database, path, identity))
}

fn publish_staging_database(
    database: Database,
    staging: TempPath,
    staging_identity: StagingFileIdentity,
    target: &Path,
) -> Result<Database, PersistentWalletError> {
    #[cfg(test)]
    mutation_failpoints::hit(mutation_failpoints::PUBLISH_BEFORE_LINK)?;
    staging
        .persist_noclobber(target)
        .map_err(|error| PersistentWalletError::Io(error.error))?;
    let confirmation = || -> Result<(), PersistentWalletError> {
        staging_identity.verify_target(target)?;
        #[cfg(test)]
        mutation_failpoints::hit(mutation_failpoints::PUBLISH_AFTER_LINK)?;
        sync_parent_directory(target)
    };
    confirmation().map_err(PersistentWalletError::published_but_unconfirmed)?;
    Ok(database)
}

fn ensure_target_absent(path: &Path) -> Result<(), PersistentWalletError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(PersistentWalletError::TargetAlreadyExists),
    }
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn validate_parent_directory(path: &Path) -> Result<(), PersistentWalletError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let parent = parent_directory(path);
        let metadata = fs::symlink_metadata(parent)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(PersistentWalletError::UnsupportedParentDirectory);
        }
        let expected_owner = rustix::process::geteuid().as_raw();
        if metadata.uid() != expected_owner {
            return Err(PersistentWalletError::ParentOwnerMismatch {
                expected: expected_owner,
                actual: metadata.uid(),
            });
        }
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o022 != 0 {
            return Err(PersistentWalletError::InsecureParentPermissions(mode));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(PersistentWalletError::UnsupportedPlatform)
    }
}

#[derive(Clone, Copy)]
struct StagingFileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl StagingFileIdentity {
    fn from_file(file: &File) -> Result<Self, PersistentWalletError> {
        Self::from_metadata(&file.metadata()?)
    }

    fn from_metadata(metadata: &fs::Metadata) -> Result<Self, PersistentWalletError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;

            if !metadata.file_type().is_file() {
                return Err(PersistentWalletError::UnsupportedFileType);
            }
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Err(PersistentWalletError::UnsupportedPlatform)
        }
    }

    fn verify_target(self, target: &Path) -> Result<(), PersistentWalletError> {
        let metadata = fs::symlink_metadata(target)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(PersistentWalletError::PublishedFileMismatch);
        }
        let actual = Self::from_metadata(&metadata)?;
        if actual.matches(self) {
            Ok(())
        } else {
            Err(PersistentWalletError::PublishedFileMismatch)
        }
    }

    fn verify_file(self, file: &File) -> Result<(), PersistentWalletError> {
        let actual = Self::from_file(file)?;
        if actual.matches(self) {
            Ok(())
        } else {
            Err(PersistentWalletError::PublishedFileMismatch)
        }
    }

    fn matches(self, other: Self) -> bool {
        #[cfg(unix)]
        {
            self.device == other.device && self.inode == other.inode
        }
        #[cfg(not(unix))]
        {
            let _ = (self, other);
            false
        }
    }
}

fn open_database(path: &Path) -> Result<Database, PersistentWalletError> {
    let file = secure_open_existing(path)?;
    if file.metadata()?.len() == 0 {
        return Err(PersistentWalletError::EmptyDatabase);
    }
    database_from_file(file).map_err(Into::into)
}

fn database_from_file(file: File) -> Result<Database, DatabaseError> {
    // redb deliberately continues when the backing filesystem reports that
    // file locks are unsupported. Probe and release one lock first so that
    // redb's immediately following acquisition is known to be supported. If
    // another process wins the tiny unlocked interval, redb fails with
    // DatabaseAlreadyOpen rather than admitting two writers.
    match file.try_lock() {
        Ok(()) => file.unlock()?,
        Err(TryLockError::WouldBlock) => return Err(DatabaseError::DatabaseAlreadyOpen),
        Err(TryLockError::Error(error)) => return Err(error.into()),
    }
    let mut builder = Database::builder();
    builder.set_cache_size(DATABASE_CACHE_BYTES);
    builder.create_file(file)
}

fn secure_open_existing(path: &Path) -> Result<File, PersistentWalletError> {
    validate_parent_directory(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(PersistentWalletError::UnsupportedFileType);
    }
    let expected_identity = StagingFileIdentity::from_metadata(&metadata)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    validate_open_file(&file)?;
    expected_identity.verify_file(&file)?;
    Ok(file)
}

fn validate_open_file(file: &File) -> Result<(), PersistentWalletError> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(PersistentWalletError::UnsupportedFileType);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let expected_owner = rustix::process::geteuid().as_raw();
        if metadata.uid() != expected_owner {
            return Err(PersistentWalletError::FileOwnerMismatch {
                expected: expected_owner,
                actual: metadata.uid(),
            });
        }
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(PersistentWalletError::InsecurePermissions(mode));
        }
    }
    Ok(())
}

fn sync_parent_directory(path: &Path) -> Result<(), PersistentWalletError> {
    #[cfg(unix)]
    {
        let parent = path.parent().filter(|path| !path.as_os_str().is_empty());
        let directory = File::open(parent.unwrap_or_else(|| Path::new(".")))?;
        directory.sync_all()?;
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum PersistentWalletError {
    #[error("wallet path already exists, is missing, or could not be accessed: {0}")]
    Io(#[from] std::io::Error),
    #[error("wallet database error: {0}")]
    Database(#[from] DatabaseError),
    #[error("wallet transaction error: {0}")]
    Transaction(#[from] TransactionError),
    #[error("wallet table error: {0}")]
    Table(#[from] TableError),
    #[error("wallet storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("wallet commit error: {0}")]
    Commit(#[from] CommitError),
    #[error("wallet durability configuration error: {0}")]
    Durability(#[from] SetDurabilityError),
    #[error(transparent)]
    Keystore(#[from] KeystoreError),
    #[error(transparent)]
    Wallet(#[from] RfqWalletError),
    #[error("wallet database is empty")]
    EmptyDatabase,
    #[error("wallet target already exists")]
    TargetAlreadyExists,
    #[error("wallet path is not a regular file")]
    UnsupportedFileType,
    #[error("wallet parent path is not a real directory")]
    UnsupportedParentDirectory,
    #[error("durable RFQ wallet storage is not supported on this platform")]
    UnsupportedPlatform,
    #[error("wallet file permissions are insecure: {0:#o}")]
    InsecurePermissions(u32),
    #[error("wallet file owner is {actual}, expected effective user {expected}")]
    FileOwnerMismatch { expected: u32, actual: u32 },
    #[error("wallet parent-directory permissions are insecure: {0:#o}")]
    InsecureParentPermissions(u32),
    #[error("wallet parent directory owner is {actual}, expected effective user {expected}")]
    ParentOwnerMismatch { expected: u32, actual: u32 },
    #[error("published wallet path does not name the database file that was created")]
    PublishedFileMismatch,
    #[error(
        "wallet publication reached the target but final confirmation failed; inspect and reopen the existing target instead of deleting it: {source}"
    )]
    PublishedButUnconfirmed {
        #[source]
        source: Box<PersistentWalletError>,
    },
    #[error("wallet database identity does not match the expected provider or chain")]
    IdentityMismatch,
    #[error("wallet database keystore, wallet id, or catalog binding does not match")]
    WalletBindingMismatch,
    #[error("wallet database metadata is corrupt")]
    CorruptMetadata,
    #[error("wallet database is missing metadata key {0}")]
    MissingMetadata(&'static str),
    #[error("wallet schema version {0} is unsupported")]
    UnsupportedSchemaVersion(u32),
    #[error("new wallet database unexpectedly contains state")]
    NonemptyNewDatabase,
    #[error("wallet catalog has reached its supported entry bound")]
    CatalogFull,
    #[error("wallet catalog revision overflowed")]
    CatalogRevisionOverflow,
    #[error("wallet catalog revision and entry count differ")]
    CatalogRevisionMismatch,
    #[error("wallet catalog contains a malformed entry")]
    CorruptCatalogEntry,
    #[error("wallet catalog contains a duplicate random nonce")]
    DuplicateCatalogNonce,
    #[error("wallet catalog contains duplicate issuance revisions")]
    DuplicateCatalogRevision,
    #[error("wallet catalog nonce does not match its authenticated locator")]
    CatalogNonceMismatch,
    #[error("wallet catalog authentication checkpoint does not match")]
    CatalogCheckpointMismatch,
    #[error("wallet destination entropy was exhausted by repeated catalog collisions")]
    DestinationEntropyExhausted,
    #[error("wallet operation lock is poisoned")]
    OperationLockPoisoned,
    #[error(
        "wallet is poisoned after an ambiguous durable commit failure; reopen it before using wallet capabilities"
    )]
    Poisoned,
    #[error("wallet backup is malformed")]
    InvalidBackup,
    #[error("wallet backup format version {0} is unsupported")]
    UnsupportedBackupVersion(u16),
    #[error("wallet backup flags are unsupported")]
    UnsupportedBackupFlags,
    #[error("wallet backup exceeds supported bounds")]
    BackupTooLarge,
    #[cfg(test)]
    #[error("injected wallet mutation failure at {0}")]
    InjectedMutationFailure(&'static str),
}

impl PersistentWalletError {
    fn published_but_unconfirmed(source: Self) -> Self {
        Self::PublishedButUnconfirmed {
            source: Box::new(source),
        }
    }
}

#[cfg(test)]
mod mutation_failpoints {
    use std::cell::RefCell;

    use super::PersistentWalletError;

    pub(super) const ISSUE_AFTER_DERIVATION: &str = "issue.after_derivation";
    pub(super) const ISSUE_AFTER_CATALOG_INSERT: &str = "issue.after_catalog_insert";
    pub(super) const ISSUE_AFTER_REVISION: &str = "issue.after_revision";
    pub(super) const ISSUE_BEFORE_COMMIT: &str = "issue.before_commit";
    pub(super) const ISSUE_COMMIT_AMBIGUOUS: &str = "issue.commit_ambiguous";
    pub(super) const ISSUE_AFTER_COMMIT: &str = "issue.after_commit";
    pub(super) const PUBLISH_BEFORE_LINK: &str = "publish.before_link";
    pub(super) const PUBLISH_AFTER_LINK: &str = "publish.after_link";

    thread_local! {
        static ACTIVE: RefCell<Option<&'static str>> = const { RefCell::new(None) };
    }

    pub(super) struct Guard;

    pub(super) fn arm(name: &'static str) -> Guard {
        ACTIVE.with(|active| {
            assert!(
                active.borrow().is_none(),
                "a wallet failpoint is already armed"
            );
            *active.borrow_mut() = Some(name);
        });
        Guard
    }

    pub(super) fn hit(name: &'static str) -> Result<(), PersistentWalletError> {
        ACTIVE.with(|active| {
            if active.borrow().as_ref() == Some(&name) {
                *active.borrow_mut() = None;
                return Err(PersistentWalletError::InjectedMutationFailure(name));
            }
            Ok(())
        })
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            ACTIVE.with(|active| *active.borrow_mut() = None);
        }
    }
}

#[cfg(test)]
mod tests;

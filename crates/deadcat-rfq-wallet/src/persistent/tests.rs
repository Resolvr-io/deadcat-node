use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use deadcat_rfq_provider::{
    DestinationPurpose, DestinationSource as _, ProviderId, ProviderIdentity,
};
use elements::hashes::Hash as _;
use elements::{AssetId, BlockHash};
use rand::rngs::StdRng;
use rand::{CryptoRng, Error as RandError, RngCore, SeedableRng as _};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

use super::*;

const PASSPHRASE: &[u8] = b"durable-wallet-test-only passphrase";

fn test_kdf() -> KdfParams {
    // Keep the persistence matrix fast while still exercising the real
    // Argon2id envelope on every create/open/restore boundary.
    KdfParams::new(8 * 1_024, 1, 1).expect("test KDF")
}

fn identity(marker: u8) -> ProviderIdentity {
    ProviderIdentity::new(
        ProviderId::new([marker; 32]),
        BlockHash::from_byte_array([marker.wrapping_add(1); 32]),
        AssetId::from_byte_array([marker.wrapping_add(2); 32]),
    )
}

fn envelope(identity: ProviderIdentity) -> EncryptedKeystore {
    EncryptedKeystore::generate_with_kdf(identity, PASSPHRASE, test_kdf()).expect("keystore")
}

fn create_seeded(
    path: &Path,
    identity: ProviderIdentity,
    seed: u64,
) -> PersistentRfqWallet<StdRng> {
    PersistentRfqWallet::create_from_envelope(
        path,
        identity,
        PASSPHRASE,
        &envelope(identity),
        StdRng::seed_from_u64(seed),
    )
    .expect("create persistent wallet")
}

fn open_seeded(path: &Path, identity: ProviderIdentity, seed: u64) -> PersistentRfqWallet<StdRng> {
    PersistentRfqWallet::open_with_rng(path, identity, PASSPHRASE, StdRng::seed_from_u64(seed))
        .expect("open persistent wallet")
}

fn issue_settlement(
    wallet: &impl DestinationSource<Error = PersistentWalletError>,
    purpose: DestinationPurpose,
) -> ConfidentialDestination {
    wallet
        .fresh_confidential_destination(purpose)
        .expect("issue settlement destination")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Default)]
struct ScriptedRng {
    bytes: VecDeque<u8>,
}

impl ScriptedRng {
    fn from_bytes(bytes: impl IntoIterator<Item = u8>) -> Self {
        Self {
            bytes: bytes.into_iter().collect(),
        }
    }

    fn from_nonces(nonces: impl IntoIterator<Item = [u8; CATALOG_NONCE_BYTES]>) -> Self {
        Self::from_bytes(nonces.into_iter().flatten())
    }
}

impl RngCore for ScriptedRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        for byte in destination {
            *byte = self
                .bytes
                .pop_front()
                .expect("scripted wallet RNG exhausted");
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for ScriptedRng {}

#[test]
fn create_issue_every_purpose_and_reopen_exact_catalog() {
    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("wallet.redb");
    let identity = identity(1);
    let wallet = create_seeded(&path, identity, 1);

    let inventory = wallet
        .fresh_inventory_destination()
        .expect("inventory destination");
    let receive = issue_settlement(&wallet, DestinationPurpose::SettlementReceive);
    let change = issue_settlement(&wallet, DestinationPurpose::SettlementChange);
    let expected_destinations = [inventory, receive, change];
    let expected_locators: Vec<_> = expected_destinations
        .iter()
        .map(ConfidentialDestination::wallet_locator)
        .collect();
    let before = wallet.catalog_snapshot().expect("catalog snapshot");

    assert_eq!(before.revision(), 3);
    assert_eq!(before.locators(), expected_locators);
    assert_eq!(
        expected_locators
            .iter()
            .map(|locator| locator.to_bytes()[1])
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );
    drop(wallet);

    let reopened = open_seeded(&path, identity, 2);
    assert_eq!(reopened.catalog_revision().expect("revision"), 3);
    assert_eq!(
        reopened.catalog_snapshot().expect("reopened snapshot"),
        before
    );
    for expected in expected_destinations {
        assert_eq!(
            reopened
                .recover_confidential_destination(expected.wallet_locator())
                .expect("recover destination"),
            expected
        );
    }
}

#[test]
fn staged_creation_publishes_only_a_complete_wallet() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(17);
    let envelope = envelope(identity);

    let before_link = directory.path().join("before-link.redb");
    let guard = mutation_failpoints::arm(mutation_failpoints::PUBLISH_BEFORE_LINK);
    assert!(matches!(
        PersistentRfqWallet::create_from_envelope(
            &before_link,
            identity,
            PASSPHRASE,
            &envelope,
            StdRng::seed_from_u64(32),
        ),
        Err(PersistentWalletError::InjectedMutationFailure(actual))
            if actual == mutation_failpoints::PUBLISH_BEFORE_LINK
    ));
    drop(guard);
    assert!(
        !before_link.exists(),
        "the final path must remain absent until the complete staging database is linked"
    );

    let after_link = directory.path().join("after-link.redb");
    let guard = mutation_failpoints::arm(mutation_failpoints::PUBLISH_AFTER_LINK);
    assert!(matches!(
        PersistentRfqWallet::create_from_envelope(
            &after_link,
            identity,
            PASSPHRASE,
            &envelope,
            StdRng::seed_from_u64(33),
        ),
        Err(PersistentWalletError::PublishedButUnconfirmed { source })
            if matches!(
                source.as_ref(),
                PersistentWalletError::InjectedMutationFailure(actual)
                    if *actual == mutation_failpoints::PUBLISH_AFTER_LINK
            )
    ));
    drop(guard);
    let reopened = open_seeded(&after_link, identity, 34);
    assert_eq!(reopened.catalog_revision().expect("complete wallet"), 0);
}

#[test]
fn backup_and_catalog_checkpoint_have_a_pinned_compatibility_vector() {
    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("golden.redb");
    let identity = identity(0x21);
    let mut envelope_rng =
        ScriptedRng::from_bytes([0xa1; 16].into_iter().chain([0xb2; 24]).chain([0xc3; 16]));
    let envelope = EncryptedKeystore::seal_entropy_with_rng(
        identity,
        PASSPHRASE,
        test_kdf(),
        &[0x55; 32],
        &mut envelope_rng,
    )
    .expect("fixed envelope");
    let wallet = PersistentRfqWallet::create_from_envelope(
        &path,
        identity,
        PASSPHRASE,
        &envelope,
        ScriptedRng::from_nonces([[0x11; CATALOG_NONCE_BYTES], [0x22; CATALOG_NONCE_BYTES]]),
    )
    .expect("fixed wallet");
    wallet
        .fresh_inventory_destination()
        .expect("first fixed destination");
    issue_settlement(&wallet, DestinationPurpose::SettlementReceive);
    let snapshot = wallet.catalog_snapshot().expect("fixed snapshot");
    let backup = wallet.export_backup().expect("fixed backup");

    assert_eq!(
        hex(&snapshot.checkpoint()),
        "7441a183727a17e7e382e104b45973083b9482acc8118615cd23d7b34ec34c68"
    );
    assert_eq!(backup.as_bytes().len(), 494);
    assert_eq!(
        hex(&Sha256::digest(backup.as_bytes())),
        "6c5c38e61a18aa462eefc378aff0e98d027ea76f7764abcf21fe947e6aa25e56"
    );
}

#[test]
fn missing_open_and_create_existing_are_non_mutating() {
    let directory = TempDir::new().expect("tempdir");
    let missing = directory.path().join("missing.redb");
    let identity = identity(2);

    assert!(matches!(
        PersistentRfqWallet::open(&missing, identity, PASSPHRASE),
        Err(PersistentWalletError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound
    ));
    assert!(!missing.exists(), "open must not initialize a missing path");

    let path = directory.path().join("wallet.redb");
    let wallet = create_seeded(&path, identity, 3);
    wallet
        .fresh_inventory_destination()
        .expect("inventory destination");
    let expected = wallet.catalog_snapshot().expect("snapshot");
    drop(wallet);
    let bytes_before = fs::read(&path).expect("database bytes");

    assert!(matches!(
        PersistentRfqWallet::create_from_envelope(
            &path,
            identity,
            PASSPHRASE,
            &envelope(identity),
            StdRng::seed_from_u64(4),
        ),
        Err(PersistentWalletError::TargetAlreadyExists)
    ));
    assert_eq!(fs::read(&path).expect("unchanged database"), bytes_before);
    assert_eq!(
        open_seeded(&path, identity, 5)
            .catalog_snapshot()
            .expect("unchanged snapshot"),
        expected
    );

    let empty = directory.path().join("already-exists");
    fs::write(&empty, []).expect("empty sentinel");
    let sentinel_before = fs::read(&empty).expect("sentinel");
    assert!(matches!(
        PersistentRfqWallet::create_from_envelope(
            &empty,
            identity,
            PASSPHRASE,
            &envelope(identity),
            StdRng::seed_from_u64(6),
        ),
        Err(PersistentWalletError::TargetAlreadyExists)
    ));
    assert_eq!(
        fs::read(empty).expect("unchanged sentinel"),
        sentinel_before
    );
}

#[test]
fn wrong_identity_and_passphrase_leave_the_wallet_unchanged() {
    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("wallet.redb");
    let identity = identity(3);
    let wallet = create_seeded(&path, identity, 7);
    wallet
        .fresh_inventory_destination()
        .expect("inventory destination");
    let expected = wallet.catalog_snapshot().expect("snapshot");
    drop(wallet);

    assert!(matches!(
        PersistentRfqWallet::open_with_rng(
            &path,
            identity,
            b"wrong passphrase",
            StdRng::seed_from_u64(8),
        ),
        Err(PersistentWalletError::Keystore(
            KeystoreError::DecryptionFailed
        ))
    ));
    assert!(matches!(
        PersistentRfqWallet::open_with_rng(
            &path,
            self::identity(4),
            PASSPHRASE,
            StdRng::seed_from_u64(9),
        ),
        Err(PersistentWalletError::IdentityMismatch)
    ));
    assert_eq!(
        open_seeded(&path, identity, 10)
            .catalog_snapshot()
            .expect("snapshot after rejected opens"),
        expected
    );
}

#[test]
fn provider_genesis_and_policy_identity_mismatches_each_fail_non_mutating() {
    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("wallet.redb");
    let identity = identity(24);
    let wallet = create_seeded(&path, identity, 56);
    wallet
        .fresh_inventory_destination()
        .expect("inventory destination");
    let expected = wallet.catalog_snapshot().expect("snapshot");
    let backup = wallet.export_backup().expect("backup");
    drop(wallet);

    let mismatches = [
        ProviderIdentity::new(
            ProviderId::new([0xf1; 32]),
            identity.genesis_hash(),
            identity.policy_asset(),
        ),
        ProviderIdentity::new(
            identity.provider(),
            BlockHash::from_byte_array([0xf2; 32]),
            identity.policy_asset(),
        ),
        ProviderIdentity::new(
            identity.provider(),
            identity.genesis_hash(),
            AssetId::from_byte_array([0xf3; 32]),
        ),
    ];
    for (index, mismatch) in mismatches.into_iter().enumerate() {
        assert!(matches!(
            PersistentRfqWallet::open_with_rng(
                &path,
                mismatch,
                PASSPHRASE,
                StdRng::seed_from_u64(57 + index as u64),
            ),
            Err(PersistentWalletError::IdentityMismatch)
        ));

        let restore_path = directory.path().join(format!("mismatch-{index}.redb"));
        assert!(matches!(
            PersistentRfqWallet::restore_with_rng(
                &restore_path,
                mismatch,
                PASSPHRASE,
                &backup,
                StdRng::seed_from_u64(60 + index as u64),
            ),
            Err(PersistentWalletError::IdentityMismatch)
        ));
        assert!(!restore_path.exists());
    }
    assert_eq!(
        open_seeded(&path, identity, 63)
            .catalog_snapshot()
            .expect("snapshot after rejected identities"),
        expected
    );
}

#[test]
fn wallet_database_is_exclusively_opened() {
    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("wallet.redb");
    let identity = identity(5);
    let wallet = create_seeded(&path, identity, 11);

    assert!(matches!(
        PersistentRfqWallet::open_with_rng(&path, identity, PASSPHRASE, StdRng::seed_from_u64(12),),
        Err(PersistentWalletError::Database(
            DatabaseError::DatabaseAlreadyOpen
        ))
    ));
    drop(wallet);
    open_seeded(&path, identity, 13);
}

#[test]
fn simultaneous_creation_has_one_no_clobber_winner() {
    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("wallet.redb");
    let identity = identity(25);
    let envelope = Arc::new(envelope(identity));
    let start = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for seed in [64, 65] {
        let path = path.clone();
        let envelope = Arc::clone(&envelope);
        let start = Arc::clone(&start);
        handles.push(thread::spawn(move || {
            start.wait();
            PersistentRfqWallet::create_from_envelope(
                &path,
                identity,
                PASSPHRASE,
                &envelope,
                StdRng::seed_from_u64(seed),
            )
        }));
    }
    start.wait();

    let mut winner = None;
    let mut conflicts = 0;
    for result in handles
        .into_iter()
        .map(|handle| handle.join().expect("creation thread"))
    {
        match result {
            Ok(wallet) => {
                assert!(winner.replace(wallet).is_none(), "two creates succeeded");
            }
            Err(PersistentWalletError::TargetAlreadyExists) => conflicts += 1,
            Err(PersistentWalletError::Io(error))
                if error.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                // Both creators may pass the initial absence check; the
                // atomic no-clobber publication is then the deciding boundary.
                conflicts += 1;
            }
            Err(error) => panic!("unexpected creation race error: {error}"),
        }
    }
    assert!(winner.is_some());
    assert_eq!(conflicts, 1);
    drop(winner);

    let reopened = open_seeded(&path, identity, 66);
    assert_eq!(reopened.catalog_revision().expect("winner revision"), 0);
    let entries: Vec<_> = fs::read_dir(directory.path())
        .expect("wallet directory")
        .map(|entry| entry.expect("directory entry").file_name())
        .collect();
    assert_eq!(entries, [path.file_name().expect("wallet filename")]);
}

#[cfg(unix)]
#[test]
fn newly_created_wallet_has_mode_0600_and_insecure_reopen_fails_closed() {
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::fs::symlink;

    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("wallet.redb");
    let identity = identity(6);
    drop(create_seeded(&path, identity, 14));

    assert_eq!(
        fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
        0o600
    );
    let link = directory.path().join("wallet-link.redb");
    symlink(&path, &link).expect("symlink");
    assert!(matches!(
        PersistentRfqWallet::open_with_rng(&link, identity, PASSPHRASE, StdRng::seed_from_u64(15),),
        Err(PersistentWalletError::UnsupportedFileType)
    ));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("widen permissions");
    assert!(matches!(
        PersistentRfqWallet::open_with_rng(&path, identity, PASSPHRASE, StdRng::seed_from_u64(16),),
        Err(PersistentWalletError::InsecurePermissions(0o640))
    ));
}

#[cfg(unix)]
#[test]
fn wallet_requires_an_owner_controlled_real_parent_directory() {
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::fs::symlink;

    let directory = TempDir::new().expect("tempdir");
    let identity = identity(22);

    let insecure_parent = directory.path().join("insecure-parent");
    fs::create_dir(&insecure_parent).expect("create insecure parent");
    fs::set_permissions(&insecure_parent, fs::Permissions::from_mode(0o770))
        .expect("widen parent permissions");
    let insecure_target = insecure_parent.join("wallet.redb");
    assert!(matches!(
        PersistentRfqWallet::create_from_envelope(
            &insecure_target,
            identity,
            PASSPHRASE,
            &envelope(identity),
            StdRng::seed_from_u64(52),
        ),
        Err(PersistentWalletError::InsecureParentPermissions(0o770))
    ));
    assert!(!insecure_target.exists());

    let changed_parent = directory.path().join("changed-parent");
    fs::create_dir(&changed_parent).expect("create initially secure parent");
    let changed_target = changed_parent.join("wallet.redb");
    drop(create_seeded(&changed_target, identity, 53));
    fs::set_permissions(&changed_parent, fs::Permissions::from_mode(0o772))
        .expect("make existing wallet parent insecure");
    assert!(matches!(
        PersistentRfqWallet::open_with_rng(
            &changed_target,
            identity,
            PASSPHRASE,
            StdRng::seed_from_u64(54),
        ),
        Err(PersistentWalletError::InsecureParentPermissions(0o772))
    ));
    fs::set_permissions(&changed_parent, fs::Permissions::from_mode(0o700))
        .expect("restore parent permissions for cleanup");

    let real_parent = directory.path().join("real-parent");
    fs::create_dir(&real_parent).expect("create real parent");
    let linked_parent = directory.path().join("linked-parent");
    symlink(&real_parent, &linked_parent).expect("link parent");
    let linked_target = linked_parent.join("wallet.redb");
    assert!(matches!(
        PersistentRfqWallet::create_from_envelope(
            &linked_target,
            identity,
            PASSPHRASE,
            &envelope(identity),
            StdRng::seed_from_u64(55),
        ),
        Err(PersistentWalletError::UnsupportedParentDirectory)
    ));
    assert!(!real_parent.join("wallet.redb").exists());
}

#[test]
fn cross_purpose_nonce_collision_after_reopen_is_burned_and_retried() {
    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("wallet.redb");
    let identity = identity(7);
    let first_nonce = [0x31; CATALOG_NONCE_BYTES];
    let second_nonce = [0x42; CATALOG_NONCE_BYTES];
    let envelope = envelope(identity);
    let wallet = PersistentRfqWallet::create_from_envelope(
        &path,
        identity,
        PASSPHRASE,
        &envelope,
        ScriptedRng::from_nonces([first_nonce]),
    )
    .expect("create wallet");
    let inventory = wallet
        .fresh_inventory_destination()
        .expect("inventory destination");
    assert_eq!(
        &inventory.wallet_locator().to_bytes()[2..18],
        first_nonce.as_slice()
    );
    drop(wallet);

    let reopened = PersistentRfqWallet::open_with_rng(
        &path,
        identity,
        PASSPHRASE,
        ScriptedRng::from_nonces([first_nonce, second_nonce]),
    )
    .expect("reopen wallet");
    let receive = issue_settlement(&reopened, DestinationPurpose::SettlementReceive);
    assert_eq!(
        &receive.wallet_locator().to_bytes()[2..18],
        second_nonce.as_slice()
    );
    let snapshot = reopened.catalog_snapshot().expect("snapshot");
    assert_eq!(snapshot.revision(), 2);
    assert_eq!(
        snapshot.locators(),
        [inventory.wallet_locator(), receive.wallet_locator()]
    );
}

#[test]
fn every_precommit_issuance_failpoint_rolls_back_exactly() {
    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("wallet.redb");
    let identity = identity(8);
    let wallet = create_seeded(&path, identity, 16);
    let initial = wallet.catalog_snapshot().expect("initial snapshot");

    for name in [
        mutation_failpoints::ISSUE_AFTER_DERIVATION,
        mutation_failpoints::ISSUE_AFTER_CATALOG_INSERT,
        mutation_failpoints::ISSUE_AFTER_REVISION,
        mutation_failpoints::ISSUE_BEFORE_COMMIT,
    ] {
        let guard = mutation_failpoints::arm(name);
        assert!(matches!(
            wallet.fresh_inventory_destination(),
            Err(PersistentWalletError::InjectedMutationFailure(actual)) if actual == name
        ));
        drop(guard);
        assert_eq!(
            wallet.catalog_snapshot().expect("rolled-back snapshot"),
            initial,
            "failpoint {name} leaked a catalog mutation"
        );
    }

    let issued = wallet
        .fresh_inventory_destination()
        .expect("issue after failures");
    let committed = wallet.catalog_snapshot().expect("committed snapshot");
    assert_eq!(committed.revision(), 1);
    assert_eq!(committed.locators(), [issued.wallet_locator()]);
    drop(wallet);
    assert_eq!(
        open_seeded(&path, identity, 17)
            .catalog_snapshot()
            .expect("reopened snapshot"),
        committed
    );
}

#[test]
fn corrupt_metadata_and_catalog_checkpoint_fail_closed_on_reopen() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(20);

    let checkpoint_path = directory.path().join("checkpoint.redb");
    let wallet = create_seeded(&checkpoint_path, identity, 40);
    wallet
        .fresh_inventory_destination()
        .expect("inventory destination");
    drop(wallet);
    let database = Database::open(&checkpoint_path).expect("raw test database");
    let mut write = database.begin_write().expect("write");
    write
        .set_durability(Durability::Immediate)
        .expect("durability");
    {
        let mut meta = write.open_table(META).expect("meta");
        meta.insert(CATALOG_CHECKPOINT_KEY, [0_u8; 32].as_slice())
            .expect("corrupt checkpoint");
    }
    write.commit().expect("commit corruption");
    drop(database);
    assert!(matches!(
        PersistentRfqWallet::open_with_rng(
            &checkpoint_path,
            identity,
            PASSPHRASE,
            StdRng::seed_from_u64(41),
        ),
        Err(PersistentWalletError::CatalogCheckpointMismatch)
    ));

    let missing_path = directory.path().join("missing-meta.redb");
    drop(create_seeded(&missing_path, identity, 42));
    let database = Database::open(&missing_path).expect("raw test database");
    let mut write = database.begin_write().expect("write");
    write
        .set_durability(Durability::Immediate)
        .expect("durability");
    {
        let mut meta = write.open_table(META).expect("meta");
        meta.remove(CATALOG_REVISION_KEY).expect("remove revision");
    }
    write.commit().expect("commit corruption");
    drop(database);
    assert!(matches!(
        PersistentRfqWallet::open_with_rng(
            &missing_path,
            identity,
            PASSPHRASE,
            StdRng::seed_from_u64(43),
        ),
        Err(PersistentWalletError::CorruptMetadata)
    ));
}

#[test]
fn after_commit_failure_burns_a_discoverable_destination() {
    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("wallet.redb");
    let identity = identity(9);
    let wallet = create_seeded(&path, identity, 18);

    let guard = mutation_failpoints::arm(mutation_failpoints::ISSUE_AFTER_COMMIT);
    assert!(matches!(
        wallet.fresh_inventory_destination(),
        Err(PersistentWalletError::InjectedMutationFailure(actual))
            if actual == mutation_failpoints::ISSUE_AFTER_COMMIT
    ));
    drop(guard);
    let burned = wallet.catalog_snapshot().expect("post-commit snapshot");
    assert_eq!(burned.revision(), 1);
    assert_eq!(burned.locators().len(), 1);
    wallet
        .recover_confidential_destination(burned.locators()[0])
        .expect("burned locator remains recoverable");

    let returned = wallet
        .fresh_inventory_destination()
        .expect("next destination");
    assert_ne!(returned.wallet_locator(), burned.locators()[0]);
    assert_eq!(wallet.catalog_revision().expect("revision"), 2);
}

#[test]
fn ambiguous_commit_poison_requires_reopen_before_any_capability() {
    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("wallet.redb");
    let identity = identity(23);
    let wallet = create_seeded(&path, identity, 54);

    let guard = mutation_failpoints::arm(mutation_failpoints::ISSUE_COMMIT_AMBIGUOUS);
    assert!(matches!(
        wallet.fresh_inventory_destination(),
        Err(PersistentWalletError::InjectedMutationFailure(actual))
            if actual == mutation_failpoints::ISSUE_COMMIT_AMBIGUOUS
    ));
    drop(guard);
    assert!(matches!(
        wallet.catalog_snapshot(),
        Err(PersistentWalletError::Poisoned)
    ));
    assert!(matches!(
        wallet.fresh_inventory_destination(),
        Err(PersistentWalletError::Poisoned)
    ));
    drop(wallet);

    let reopened = open_seeded(&path, identity, 55);
    let snapshot = reopened
        .catalog_snapshot()
        .expect("reopen resolves the durable outcome");
    assert_eq!(snapshot.revision(), 1);
    assert_eq!(snapshot.locators().len(), 1);
    reopened
        .recover_confidential_destination(snapshot.locators()[0])
        .expect("the committed locator remains recoverable");
}

#[test]
fn concurrent_issuance_returns_only_unique_durable_destinations() {
    const THREADS: usize = 12;

    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("wallet.redb");
    let identity = identity(10);
    let wallet = Arc::new(create_seeded(&path, identity, 19));
    let barrier = Arc::new(Barrier::new(THREADS + 1));
    let mut handles = Vec::new();
    for index in 0..THREADS {
        let wallet = Arc::clone(&wallet);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            match index % 3 {
                0 => wallet.fresh_inventory_destination(),
                1 => wallet.fresh_confidential_destination(DestinationPurpose::SettlementReceive),
                _ => wallet.fresh_confidential_destination(DestinationPurpose::SettlementChange),
            }
        }));
    }
    barrier.wait();
    let destinations: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("issuance thread").expect("issuance"))
        .collect();
    let returned: BTreeSet<_> = destinations
        .iter()
        .map(ConfidentialDestination::wallet_locator)
        .collect();
    assert_eq!(returned.len(), THREADS);

    let snapshot = wallet.catalog_snapshot().expect("snapshot");
    assert_eq!(snapshot.revision(), THREADS as u64);
    assert_eq!(snapshot.locators().len(), THREADS);
    assert_eq!(
        snapshot.locators().iter().copied().collect::<BTreeSet<_>>(),
        returned
    );
    let nonces: BTreeSet<_> = snapshot
        .locators()
        .iter()
        .map(|locator| locator.to_bytes()[2..18].to_vec())
        .collect();
    assert_eq!(nonces.len(), THREADS);
    drop(wallet);
    assert_eq!(
        open_seeded(&path, identity, 20)
            .catalog_snapshot()
            .expect("reopened snapshot"),
        snapshot
    );
}

#[test]
fn snapshots_racing_issuance_are_coherent_monotonic_prefixes() {
    const ISSUANCES: usize = 12;

    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("wallet.redb");
    let identity = identity(11);
    let wallet = Arc::new(create_seeded(&path, identity, 21));
    let start = Arc::new(Barrier::new(3));
    let done = Arc::new(AtomicBool::new(false));

    let issuer = {
        let wallet = Arc::clone(&wallet);
        let start = Arc::clone(&start);
        let done = Arc::clone(&done);
        thread::spawn(move || {
            start.wait();
            for _ in 0..ISSUANCES {
                wallet
                    .fresh_inventory_destination()
                    .expect("concurrent issuance");
                thread::yield_now();
            }
            done.store(true, Ordering::Release);
        })
    };
    let reader = {
        let wallet = Arc::clone(&wallet);
        let start = Arc::clone(&start);
        let done = Arc::clone(&done);
        thread::spawn(move || {
            start.wait();
            let mut previous = Vec::new();
            loop {
                let snapshot = wallet.catalog_snapshot().expect("concurrent snapshot");
                assert_eq!(snapshot.revision(), snapshot.locators().len() as u64);
                assert!(snapshot.locators().starts_with(&previous));
                previous = snapshot.locators().to_vec();
                if done.load(Ordering::Acquire) {
                    let final_snapshot = wallet
                        .catalog_snapshot()
                        .expect("snapshot after issuer completion");
                    assert!(final_snapshot.locators().starts_with(&previous));
                    return final_snapshot.locators().to_vec();
                }
                thread::yield_now();
            }
        })
    };
    start.wait();
    issuer.join().expect("issuer thread");
    let observed = reader.join().expect("reader thread");
    let final_snapshot = wallet.catalog_snapshot().expect("final snapshot");
    assert_eq!(final_snapshot.revision(), ISSUANCES as u64);
    assert_eq!(observed, final_snapshot.locators());
}

#[test]
fn logical_backup_restores_exactly_and_never_overwrites() {
    let directory = TempDir::new().expect("tempdir");
    let source_path = directory.path().join("source.redb");
    let restored_path = directory.path().join("restored.redb");
    let identity = identity(12);
    let source = create_seeded(&source_path, identity, 22);
    let destinations = [
        source
            .fresh_inventory_destination()
            .expect("inventory destination"),
        issue_settlement(&source, DestinationPurpose::SettlementReceive),
        issue_settlement(&source, DestinationPurpose::SettlementChange),
    ];
    let expected = source.catalog_snapshot().expect("source snapshot");
    let backup = source.export_backup().expect("backup");
    assert_eq!(backup.revision(), expected.revision());
    assert_eq!(backup.checkpoint(), expected.checkpoint());
    drop(source);

    let restored = PersistentRfqWallet::restore_with_rng(
        &restored_path,
        identity,
        PASSPHRASE,
        &backup,
        StdRng::seed_from_u64(23),
    )
    .expect("restore");
    assert_eq!(
        restored.catalog_snapshot().expect("restored snapshot"),
        expected
    );
    for destination in destinations {
        assert_eq!(
            restored
                .recover_confidential_destination(destination.wallet_locator())
                .expect("restored destination"),
            destination
        );
    }

    let existing = directory.path().join("existing");
    let sentinel = b"must not overwrite an existing recovery target";
    fs::write(&existing, sentinel).expect("write sentinel");
    assert!(matches!(
        PersistentRfqWallet::restore_with_rng(
            &existing,
            identity,
            PASSPHRASE,
            &backup,
            StdRng::seed_from_u64(24),
        ),
        Err(PersistentWalletError::TargetAlreadyExists)
    ));
    assert_eq!(fs::read(existing).expect("read sentinel"), sentinel);
}

#[test]
fn repeated_export_and_restore_preserve_the_exact_encrypted_envelope() {
    let directory = TempDir::new().expect("tempdir");
    let source_path = directory.path().join("source.redb");
    let restored_path = directory.path().join("restored.redb");
    let identity = identity(26);
    let envelope = envelope(identity);
    let source = PersistentRfqWallet::create_from_envelope(
        &source_path,
        identity,
        PASSPHRASE,
        &envelope,
        StdRng::seed_from_u64(67),
    )
    .expect("source wallet");
    source
        .fresh_inventory_destination()
        .expect("inventory destination");
    issue_settlement(&source, DestinationPurpose::SettlementChange);

    assert_eq!(
        load_envelope(&source.database, identity).expect("stored source envelope"),
        envelope
    );
    let first = source.export_backup().expect("first export");
    let second = source.export_backup().expect("repeat export");
    assert_eq!(first, second);
    assert_eq!(
        parse_backup(first.as_bytes())
            .expect("parse source backup")
            .keystore,
        envelope.as_bytes()
    );
    drop(source);

    let restored = PersistentRfqWallet::restore_with_rng(
        &restored_path,
        identity,
        PASSPHRASE,
        &first,
        StdRng::seed_from_u64(68),
    )
    .expect("restore");
    assert_eq!(
        load_envelope(&restored.database, identity).expect("stored restored envelope"),
        envelope
    );
    assert_eq!(restored.export_backup().expect("restored export"), first);
}

#[test]
fn backup_tampering_and_wrong_credentials_leave_no_restore_target() {
    let directory = TempDir::new().expect("tempdir");
    let source_path = directory.path().join("source.redb");
    let identity = identity(13);
    let source = create_seeded(&source_path, identity, 25);
    source
        .fresh_inventory_destination()
        .expect("inventory destination");
    let backup = source.export_backup().expect("backup");

    let wrong_passphrase_path = directory.path().join("wrong-passphrase.redb");
    assert!(matches!(
        PersistentRfqWallet::restore_with_rng(
            &wrong_passphrase_path,
            identity,
            b"wrong passphrase",
            &backup,
            StdRng::seed_from_u64(26),
        ),
        Err(PersistentWalletError::Keystore(
            KeystoreError::DecryptionFailed
        ))
    ));
    assert!(!wrong_passphrase_path.exists());

    let wrong_identity_path = directory.path().join("wrong-identity.redb");
    assert!(matches!(
        PersistentRfqWallet::restore_with_rng(
            &wrong_identity_path,
            self::identity(14),
            PASSPHRASE,
            &backup,
            StdRng::seed_from_u64(27),
        ),
        Err(PersistentWalletError::IdentityMismatch)
    ));
    assert!(!wrong_identity_path.exists());

    let mut tampered = backup.as_bytes().to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let tampered = WalletBackup::from_bytes(tampered).expect("structurally valid backup");
    let tampered_path = directory.path().join("tampered.redb");
    assert!(matches!(
        PersistentRfqWallet::restore_with_rng(
            &tampered_path,
            identity,
            PASSPHRASE,
            &tampered,
            StdRng::seed_from_u64(28),
        ),
        Err(PersistentWalletError::CatalogCheckpointMismatch)
    ));
    assert!(!tampered_path.exists());
}

#[test]
fn backup_parser_rejects_noncanonical_and_hostile_framing() {
    let directory = TempDir::new().expect("tempdir");
    let source_path = directory.path().join("source.redb");
    let identity = identity(18);
    let source = create_seeded(&source_path, identity, 35);
    source
        .fresh_inventory_destination()
        .expect("inventory destination");
    let backup = source.export_backup().expect("backup");

    let mut cases = Vec::new();
    let mut bad_magic = backup.as_bytes().to_vec();
    bad_magic[0] ^= 1;
    cases.push(bad_magic);
    let mut zero_wallet_id = backup.as_bytes().to_vec();
    zero_wallet_id[112..128].fill(0);
    cases.push(zero_wallet_id);
    let mut revision_count_mismatch = backup.as_bytes().to_vec();
    revision_count_mismatch[128..136].copy_from_slice(&2_u64.to_be_bytes());
    cases.push(revision_count_mismatch);
    let mut zero_keystore_length = backup.as_bytes().to_vec();
    zero_keystore_length[136..140].fill(0);
    cases.push(zero_keystore_length);
    let mut oversized_keystore = backup.as_bytes().to_vec();
    oversized_keystore[136..140]
        .copy_from_slice(&((MAX_BACKUP_KEYSTORE_BYTES + 1) as u32).to_be_bytes());
    cases.push(oversized_keystore);
    cases.push(backup.as_bytes()[..backup.as_bytes().len() - 1].to_vec());
    let mut trailing = backup.as_bytes().to_vec();
    trailing.push(0);
    cases.push(trailing);
    let mut version = backup.as_bytes().to_vec();
    version[8..10].copy_from_slice(&2_u16.to_be_bytes());
    cases.push(version);
    let mut flags = backup.as_bytes().to_vec();
    flags[10..12].copy_from_slice(&1_u16.to_be_bytes());
    cases.push(flags);
    let mut declared_length = backup.as_bytes().to_vec();
    declared_length[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
    cases.push(declared_length);
    let mut hostile_count = backup.as_bytes().to_vec();
    let too_many = MAX_WALLET_CATALOG_ENTRIES + 1;
    hostile_count[128..136].copy_from_slice(&too_many.to_be_bytes());
    hostile_count[140..144].copy_from_slice(&(too_many as u32).to_be_bytes());
    cases.push(hostile_count);

    for bytes in cases {
        assert!(
            WalletBackup::from_bytes(bytes).is_err(),
            "noncanonical backup framing was accepted"
        );
    }
}

#[test]
fn multi_entry_backup_rejects_delete_reorder_duplicate_and_cross_wallet_substitution() {
    let directory = TempDir::new().expect("tempdir");
    let source_path = directory.path().join("source.redb");
    let identity = identity(27);
    let source = create_seeded(&source_path, identity, 69);
    source
        .fresh_inventory_destination()
        .expect("inventory destination");
    issue_settlement(&source, DestinationPurpose::SettlementReceive);
    issue_settlement(&source, DestinationPurpose::SettlementChange);
    let backup = source.export_backup().expect("three-entry backup");
    let parsed = parse_backup(backup.as_bytes()).expect("parse backup");
    let locators_start = BACKUP_HEADER_BYTES + parsed.keystore.len();

    let mut deleted = backup.as_bytes().to_vec();
    deleted.drain(locators_start + 32..locators_start + 64);
    let deleted_len = u32::try_from(deleted.len()).expect("backup length");
    deleted[12..16].copy_from_slice(&deleted_len.to_be_bytes());
    deleted[128..136].copy_from_slice(&2_u64.to_be_bytes());
    deleted[140..144].copy_from_slice(&2_u32.to_be_bytes());
    let deleted = WalletBackup::from_bytes(deleted).expect("structurally valid deletion");
    assert!(matches!(
        PersistentRfqWallet::restore_with_rng(
            &directory.path().join("deleted.redb"),
            identity,
            PASSPHRASE,
            &deleted,
            StdRng::seed_from_u64(70),
        ),
        Err(PersistentWalletError::CatalogCheckpointMismatch)
    ));

    let mut reordered = backup.as_bytes().to_vec();
    let first = reordered[locators_start..locators_start + 32].to_vec();
    let second = reordered[locators_start + 32..locators_start + 64].to_vec();
    reordered[locators_start..locators_start + 32].copy_from_slice(&second);
    reordered[locators_start + 32..locators_start + 64].copy_from_slice(&first);
    let reordered = WalletBackup::from_bytes(reordered).expect("structurally valid reordering");
    assert!(matches!(
        PersistentRfqWallet::restore_with_rng(
            &directory.path().join("reordered.redb"),
            identity,
            PASSPHRASE,
            &reordered,
            StdRng::seed_from_u64(71),
        ),
        Err(PersistentWalletError::CatalogCheckpointMismatch)
    ));

    let mut duplicate = backup.as_bytes().to_vec();
    let first = duplicate[locators_start..locators_start + 32].to_vec();
    duplicate[locators_start + 32..locators_start + 64].copy_from_slice(&first);
    let duplicate = WalletBackup::from_bytes(duplicate).expect("structurally valid duplicate");
    assert!(matches!(
        PersistentRfqWallet::restore_with_rng(
            &directory.path().join("duplicate.redb"),
            identity,
            PASSPHRASE,
            &duplicate,
            StdRng::seed_from_u64(72),
        ),
        Err(PersistentWalletError::DuplicateCatalogNonce)
    ));

    let foreign_path = directory.path().join("foreign.redb");
    let foreign = create_seeded(&foreign_path, identity, 73);
    foreign
        .fresh_inventory_destination()
        .expect("foreign destination");
    let foreign_backup = foreign.export_backup().expect("foreign backup");
    let foreign_parsed = parse_backup(foreign_backup.as_bytes()).expect("parse foreign backup");
    let foreign_locator = &foreign_parsed.locators[..32];
    let mut substituted = backup.as_bytes().to_vec();
    substituted[locators_start + 32..locators_start + 64].copy_from_slice(foreign_locator);
    let substituted =
        WalletBackup::from_bytes(substituted).expect("structurally valid substitution");
    assert!(matches!(
        PersistentRfqWallet::restore_with_rng(
            &directory.path().join("cross-wallet.redb"),
            identity,
            PASSPHRASE,
            &substituted,
            StdRng::seed_from_u64(74),
        ),
        Err(PersistentWalletError::Wallet(
            RfqWalletError::LocatorAuthenticationFailed
        ))
    ));
}

#[test]
fn authenticated_backup_regions_cannot_be_substituted() {
    let directory = TempDir::new().expect("tempdir");
    let source_path = directory.path().join("source.redb");
    let identity = identity(19);
    let source = create_seeded(&source_path, identity, 36);
    source
        .fresh_inventory_destination()
        .expect("inventory destination");
    let backup = source.export_backup().expect("backup");

    let mut wallet_id = backup.as_bytes().to_vec();
    wallet_id[112] ^= 1;
    let wallet_id = WalletBackup::from_bytes(wallet_id).expect("structurally valid");
    assert!(matches!(
        PersistentRfqWallet::restore_with_rng(
            &directory.path().join("wallet-id.redb"),
            identity,
            PASSPHRASE,
            &wallet_id,
            StdRng::seed_from_u64(37),
        ),
        Err(PersistentWalletError::WalletBindingMismatch)
    ));

    let parsed = parse_backup(backup.as_bytes()).expect("parse source backup");
    let keystore_end = BACKUP_HEADER_BYTES + parsed.keystore.len();
    let mut ciphertext = backup.as_bytes().to_vec();
    ciphertext[keystore_end - 1] ^= 1;
    let ciphertext = WalletBackup::from_bytes(ciphertext).expect("structurally valid");
    assert!(matches!(
        PersistentRfqWallet::restore_with_rng(
            &directory.path().join("ciphertext.redb"),
            identity,
            PASSPHRASE,
            &ciphertext,
            StdRng::seed_from_u64(38),
        ),
        Err(PersistentWalletError::Keystore(
            KeystoreError::DecryptionFailed
        ))
    ));

    let mut locator = backup.as_bytes().to_vec();
    locator[keystore_end + 2] ^= 1;
    let locator = WalletBackup::from_bytes(locator).expect("structurally valid");
    assert!(matches!(
        PersistentRfqWallet::restore_with_rng(
            &directory.path().join("locator.redb"),
            identity,
            PASSPHRASE,
            &locator,
            StdRng::seed_from_u64(39),
        ),
        Err(PersistentWalletError::Wallet(
            RfqWalletError::LocatorAuthenticationFailed
        ))
    ));
}

#[test]
fn stale_backup_restores_only_its_cataloged_prefix() {
    let directory = TempDir::new().expect("tempdir");
    let source_path = directory.path().join("source.redb");
    let restored_path = directory.path().join("restored.redb");
    let identity = identity(15);
    let source = create_seeded(&source_path, identity, 29);
    let before_backup = source
        .fresh_inventory_destination()
        .expect("pre-backup destination");
    let backup = source.export_backup().expect("stale backup");
    let after_backup = issue_settlement(&source, DestinationPurpose::SettlementReceive);
    assert_eq!(source.catalog_revision().expect("source revision"), 2);
    drop(source);

    let restored = PersistentRfqWallet::restore_with_rng(
        &restored_path,
        identity,
        PASSPHRASE,
        &backup,
        StdRng::seed_from_u64(30),
    )
    .expect("restore stale backup");
    let snapshot = restored.catalog_snapshot().expect("restored snapshot");
    assert_eq!(snapshot.revision(), 1);
    assert_eq!(snapshot.locators(), [before_backup.wallet_locator()]);
    assert!(!snapshot.locators().contains(&after_backup.wallet_locator()));

    // The shared seed can still authenticate a later locator if some external
    // record supplies it, but a chain scanner driven by this stale catalog has
    // no way to discover that destination.
    assert_eq!(
        restored
            .recover_confidential_destination(after_backup.wallet_locator())
            .expect("externally supplied post-backup locator"),
        after_backup
    );
    let fresh_after_restore = issue_settlement(&restored, DestinationPurpose::SettlementReceive);
    assert_ne!(
        fresh_after_restore.wallet_locator(),
        after_backup.wallet_locator(),
        "fresh post-restore RNG state must not replay the omitted locator"
    );
    let after_fresh_issue = restored.catalog_snapshot().expect("updated stale catalog");
    assert_eq!(after_fresh_issue.revision(), 2);
    assert_eq!(
        after_fresh_issue.locators(),
        [
            before_backup.wallet_locator(),
            fresh_after_restore.wallet_locator()
        ]
    );
    assert!(
        !after_fresh_issue
            .locators()
            .contains(&after_backup.wallet_locator())
    );
}

#[test]
fn durable_types_redact_wallet_secrets_and_catalog_contents() {
    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("wallet.redb");
    let identity = identity(16);
    let wallet = create_seeded(&path, identity, 31);
    let destination = wallet
        .fresh_inventory_destination()
        .expect("inventory destination");
    let snapshot = wallet.catalog_snapshot().expect("snapshot");
    let backup = wallet.export_backup().expect("backup");

    let debug = format!("{wallet:?}\n{snapshot:?}\n{backup:?}");
    for secret in [
        String::from_utf8(PASSPHRASE.to_vec()).expect("UTF-8 passphrase"),
        hex(&destination.wallet_locator().to_bytes()),
        hex(&snapshot.checkpoint()),
        hex(&wallet.wallet.wallet_id()),
    ] {
        assert!(
            !debug.contains(&secret),
            "debug output disclosed sentinel {secret}"
        );
    }
    assert!(debug.contains("[unlocked and redacted]"));
    assert!(debug.contains("[1 opaque entries]"));
    assert!(debug.contains("[encrypted keystore; opaque catalog; authentication deferred]"));
}

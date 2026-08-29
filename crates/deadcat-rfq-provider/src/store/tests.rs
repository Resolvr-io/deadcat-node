use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;

use elements::encode::{deserialize, serialize};
use elements::hashes::Hash as _;
use elements::pset::PartiallySignedTransaction;
use elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use elements::{AssetId, BlockHash, LockTime, OutPoint, Transaction, TxIn, Txid};
use tempfile::TempDir;

use super::*;

fn asset(marker: u8) -> AssetId {
    AssetId::from_slice(&[marker; 32]).expect("asset")
}

fn outpoint(marker: u8, vout: u32) -> OutPoint {
    OutPoint::new(Txid::from_byte_array([marker; 32]), vout)
}

fn signed_pset(marker: u8) -> Vec<u8> {
    let transaction = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint(marker, 0),
            ..TxIn::default()
        }],
        output: Vec::new(),
    };
    serialize(&PartiallySignedTransaction::from_tx(transaction))
}

fn identity(marker: u8) -> ProviderIdentity {
    ProviderIdentity::new(
        ProviderId::new([marker; 32]),
        BlockHash::from_byte_array([marker.wrapping_add(1); 32]),
        asset(1),
    )
}

fn open_book(directory: &TempDir, identity: ProviderIdentity) -> ReservationBook {
    ReservationBook::open(directory.path().join("provider.redb"), identity).expect("book")
}

#[test]
fn explicit_database_lifecycle_creates_then_opens_but_never_creates_on_open() {
    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("provider.redb");
    let identity = identity(2);

    let error = match ReservationBook::open_existing(&path, identity) {
        Ok(_) => panic!("normal startup must not create a missing provider database"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        ProviderError::Io(error) if error.kind() == std::io::ErrorKind::NotFound
    ));
    assert!(!path.exists());

    let created = ReservationBook::create(&path, identity).expect("create provider database");
    assert_eq!(created.identity(), identity);
    assert_eq!(created.schema_version().expect("schema"), SCHEMA_VERSION);
    drop(created);

    let opened = ReservationBook::open_existing(&path, identity).expect("open provider database");
    assert_eq!(opened.identity(), identity);
    assert_eq!(opened.schema_version().expect("schema"), SCHEMA_VERSION);
}

#[test]
fn create_never_clobbers_an_existing_database() {
    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("provider.redb");
    let other_identity = identity(4);
    let identity = identity(3);
    let item = inventory(3);
    {
        let book = ReservationBook::create(&path, identity).expect("first creation");
        book.import_inventory(item, &UnixMillis::new(100))
            .expect("persist sentinel state");
    }

    assert!(matches!(
        ReservationBook::create(&path, other_identity),
        Err(ProviderError::TargetAlreadyExists)
    ));
    let reopened =
        ReservationBook::open_existing(&path, identity).expect("reopen original database");
    assert!(
        reopened
            .inventory(item.outpoint())
            .expect("sentinel inventory")
            .is_some()
    );
}

#[cfg(unix)]
#[test]
fn database_requires_exact_mode_and_rejects_symlinks() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("provider.redb");
    let identity = identity(4);
    drop(ReservationBook::create(&path, identity).expect("create provider database"));
    assert_eq!(
        fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
        0o600
    );

    let link = directory.path().join("provider-link.redb");
    symlink(&path, &link).expect("symlink");
    assert!(matches!(
        ReservationBook::open_existing(&link, identity),
        Err(ProviderError::UnsupportedFileType)
    ));
    assert!(matches!(
        ReservationBook::create(&link, identity),
        Err(ProviderError::TargetAlreadyExists)
    ));

    fs::set_permissions(&path, fs::Permissions::from_mode(0o640))
        .expect("widen provider database permissions");
    assert!(matches!(
        ReservationBook::open_existing(&path, identity),
        Err(ProviderError::InsecurePermissions(0o640))
    ));
}

#[cfg(unix)]
#[test]
fn database_requires_an_owner_controlled_real_parent_directory() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let directory = TempDir::new().expect("tempdir");
    let identity = identity(5);

    let insecure_parent = directory.path().join("insecure-parent");
    fs::create_dir(&insecure_parent).expect("create insecure parent");
    fs::set_permissions(&insecure_parent, fs::Permissions::from_mode(0o770))
        .expect("widen parent permissions");
    let insecure_target = insecure_parent.join("provider.redb");
    assert!(matches!(
        ReservationBook::create(&insecure_target, identity),
        Err(ProviderError::InsecureParentPermissions(0o770))
    ));
    assert!(!insecure_target.exists());
    fs::set_permissions(&insecure_parent, fs::Permissions::from_mode(0o700))
        .expect("restore parent permissions for cleanup");

    let changed_parent = directory.path().join("changed-parent");
    fs::create_dir(&changed_parent).expect("create secure parent");
    let changed_target = changed_parent.join("provider.redb");
    drop(ReservationBook::create(&changed_target, identity).expect("create provider database"));
    fs::set_permissions(&changed_parent, fs::Permissions::from_mode(0o772))
        .expect("make existing database parent insecure");
    assert!(matches!(
        ReservationBook::open_existing(&changed_target, identity),
        Err(ProviderError::InsecureParentPermissions(0o772))
    ));
    fs::set_permissions(&changed_parent, fs::Permissions::from_mode(0o700))
        .expect("restore parent permissions for cleanup");

    let real_parent = directory.path().join("real-parent");
    fs::create_dir(&real_parent).expect("create real parent");
    let linked_parent = directory.path().join("linked-parent");
    symlink(&real_parent, &linked_parent).expect("link parent");
    let linked_target = linked_parent.join("provider.redb");
    assert!(matches!(
        ReservationBook::create(&linked_target, identity),
        Err(ProviderError::UnsupportedParentDirectory)
    ));
    assert!(!real_parent.join("provider.redb").exists());
}

#[cfg(unix)]
#[test]
fn database_creation_enforces_mode_0600_under_a_restrictive_umask() {
    const CHILD_ENV: &str = "DEADCAT_RFQ_PROVIDER_UMASK_TEST_CHILD";
    if std::env::var_os(CHILD_ENV).is_some() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("provider.redb");
        let prior_umask = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o777));
        let result = ReservationBook::create(&path, identity(6));
        rustix::process::umask(prior_umask);
        drop(result.expect("create despite restrictive umask"));
        assert_eq!(
            fs::metadata(path).expect("metadata").permissions().mode() & 0o777,
            0o600
        );
        return;
    }

    let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "store::tests::database_creation_enforces_mode_0600_under_a_restrictive_umask",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .output()
        .expect("spawn isolated umask test");
    assert!(
        output.status.success(),
        "isolated umask test failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn fee_policy(identity: ProviderIdentity) -> FeePolicy {
    FeePolicy::new(
        identity.policy_asset(),
        2_000,
        50,
        4_000,
        FeeSizeMetric::DiscountVbytes,
    )
    .expect("fee policy")
}

fn transaction_fee(identity: ProviderIdentity, amount: u64) -> TransactionFee {
    TransactionFee::new(identity.policy_asset(), amount, 800, 200, 100).expect("transaction fee")
}

fn inventory(marker: u8) -> InventoryItem {
    inventory_variant(marker, marker)
}

fn inventory_variant(outpoint_marker: u8, metadata_marker: u8) -> InventoryItem {
    let secp = Secp256k1::new();
    let metadata_marker = metadata_marker.max(1);
    let secret_key = SecretKey::from_slice(&[metadata_marker; 32]).expect("secret key");
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let (internal_key, _) = XOnlyPublicKey::from_keypair(&keypair);
    InventoryItem::new(
        outpoint(outpoint_marker, 0),
        asset(2),
        10_000,
        WalletKeyLocator::new([metadata_marker; 32]).expect("wallet locator"),
        internal_key,
        InventoryBinding::new([metadata_marker.wrapping_add(1); 32]),
    )
    .expect("inventory")
}

fn owner(marker: u8) -> OwnerId {
    OwnerId::new([marker; 32])
}

fn plan(
    identity: ProviderIdentity,
    owner: OwnerId,
    request_marker: u8,
    quote_marker: u8,
    outpoints: Vec<OutPoint>,
    deadline: u64,
) -> ReservationPlan {
    ReservationPlan::new(
        owner,
        IdempotencyKey::new([request_marker; 32]),
        QuoteCommitment::new([quote_marker; 32]),
        outpoints,
        UnixMillis::new(deadline),
        fee_policy(identity),
    )
    .expect("plan")
}

fn reserve_one(
    book: &ReservationBook,
    identity: ProviderIdentity,
    item: InventoryItem,
    owner: OwnerId,
    request_marker: u8,
) -> ReservationView {
    let now = UnixMillis::new(100);
    book.import_inventory(item, &now).expect("inventory import");
    book.reserve(
        &plan(
            identity,
            owner,
            request_marker,
            request_marker.wrapping_add(1),
            vec![item.outpoint()],
            1_000,
        ),
        &now,
    )
    .expect("reservation")
    .reservation()
    .clone()
}

#[test]
fn fee_policy_uses_checked_ceiling_and_both_parties_bounds() {
    let identity = identity(10);
    let policy = fee_policy(identity);
    let exact = transaction_fee(identity, 200);
    assert_eq!(policy.required_fee(exact), Ok(200));
    assert_eq!(policy.validate(exact), Ok(()));

    let under = transaction_fee(identity, 199);
    assert_eq!(
        policy.validate(under),
        Err(FeePolicyViolation::FeeBelowMinimum {
            required: 200,
            actual: 199,
        })
    );
    let overweight =
        TransactionFee::new(identity.policy_asset(), 10_000, 4_001, 1_001, 1_001).expect("fee");
    assert_eq!(
        policy.validate(overweight),
        Err(FeePolicyViolation::TransactionOverweight {
            maximum: 4_000,
            actual: 4_001,
        })
    );
    let wrong_asset = TransactionFee::new(asset(9), 10_000, 800, 200, 100).expect("fee");
    assert!(matches!(
        policy.validate(wrong_asset),
        Err(FeePolicyViolation::WrongPolicyAsset { .. })
    ));
}

#[test]
fn wallet_inventory_batch_is_atomic_and_exact_rediscovery_is_idempotent() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(81);
    let book = open_book(&directory, identity);
    let existing = inventory(120);
    let new_item = inventory(121);
    let now = UnixMillis::new(100);
    assert_eq!(
        book.import_inventory_batch(&[existing], &now)
            .expect("first import"),
        1
    );
    assert_eq!(
        book.import_inventory_batch(&[existing], &now)
            .expect("exact retry"),
        0
    );

    let conflict = inventory_variant(120, 122);
    assert!(matches!(
        book.import_inventory_batch(&[new_item, conflict], &UnixMillis::new(101)),
        Err(ProviderError::InventoryMetadataConflict { outpoint: actual })
            if actual == existing.outpoint()
    ));
    assert!(
        book.inventory(new_item.outpoint())
            .expect("new inventory query")
            .is_none(),
        "a later conflict must roll back the entire discovery batch"
    );
    assert_eq!(book.audit_log().expect("audit").len(), 1);

    assert!(matches!(
        book.import_inventory_batch(&[new_item, new_item], &UnixMillis::new(102)),
        Err(ProviderError::DuplicateInventoryOutpoint(actual))
            if actual == new_item.outpoint()
    ));
    assert!(
        book.inventory(new_item.outpoint())
            .expect("duplicate inventory query")
            .is_none()
    );
}

#[test]
fn inventory_state_lookup_does_not_decode_unrelated_history() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(82);
    let book = open_book(&directory, identity);
    let requested = inventory(122);
    let unrelated = inventory(123);
    let now = UnixMillis::new(100);
    book.import_inventory_batch(&[requested, unrelated], &now)
        .expect("inventory import");

    // Poison an unrelated historical row after startup. A bounded snapshot
    // lookup must point-read only the requested outpoints; decoding the entire
    // append-only inventory table would encounter this row and fail.
    let write = book.database.begin_write().expect("raw write");
    {
        let mut inventory = write.open_table(INVENTORY).expect("inventory");
        let key = outpoint_key(unrelated.outpoint());
        inventory
            .insert(key.as_slice(), &[0xff_u8][..])
            .expect("poison unrelated inventory row");
    }
    write.commit().expect("commit fixture");

    let (views, allocation_revision) = book
        .inventory_state_for(&[requested.outpoint()])
        .expect("bounded inventory lookup");
    assert_eq!(allocation_revision, 0);
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].item(), requested);
    assert_eq!(views[0].state(), InventoryState::Available);
}

#[test]
fn reservation_is_atomic_idempotent_and_owner_authenticated() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(11);
    let book = open_book(&directory, identity);
    let first = inventory(20);
    let second = inventory(21);
    let now = UnixMillis::new(100);
    book.import_inventory(first, &now).expect("first inventory");
    book.import_inventory(second, &now)
        .expect("second inventory");
    let request = plan(
        identity,
        owner(1),
        2,
        3,
        vec![second.outpoint(), first.outpoint()],
        1_000,
    );

    let created = book.reserve(&request, &now).expect("reserve");
    assert!(created.created());
    assert_eq!(
        created.reservation().outpoints(),
        &[first.outpoint(), second.outpoint()]
    );
    let retry = book.reserve(&request, &now).expect("idempotent retry");
    assert!(!retry.created());
    assert_eq!(retry.reservation(), created.reservation());
    assert_eq!(book.audit_log().expect("audit").len(), 3);

    let wrong_owner = ReservationAccess::new(created.reservation().id(), owner(9));
    assert!(matches!(
        book.cancel(wrong_owner, &now),
        Err(ProviderError::ReservationOwnerMismatch(_))
    ));
    for item in [first, second] {
        assert!(matches!(
            book.inventory(item.outpoint()).expect("inventory").unwrap().state(),
            InventoryState::Reserved { reservation_id }
                if reservation_id == created.reservation().id()
        ));
    }
}

#[test]
fn reservation_status_rejects_a_different_owner() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(83);
    let book = open_book(&directory, identity);
    let reservation = reserve_one(&book, identity, inventory(124), owner(1), 1);

    assert!(matches!(
        book.reservation_status(ReservationAccess::new(reservation.id(), owner(2))),
        Err(ProviderError::ReservationOwnerMismatch(actual)) if actual == reservation.id()
    ));
}

#[test]
fn reserved_status_has_no_signed_artifact() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(84);
    let book = open_book(&directory, identity);
    let reservation = reserve_one(&book, identity, inventory(125), owner(1), 1);

    let status = book
        .reservation_status(ReservationAccess::new(
            reservation.id(),
            reservation.owner(),
        ))
        .expect("authorized reservation status");
    assert_eq!(status.reservation(), &reservation);
    assert_eq!(status.reservation().state(), ReservationState::Reserved);
    assert!(status.signed_artifact().is_none());
}

#[test]
fn targeted_status_expires_at_the_deadline_and_not_before() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(87);
    let item = inventory(128);
    let book = open_book(&directory, identity);
    let reservation = reserve_one(&book, identity, item, owner(1), 1);
    let access = ReservationAccess::new(reservation.id(), reservation.owner());

    let before = book
        .reservation_status_at(access, &UnixMillis::new(999))
        .expect("status before deadline");
    assert_eq!(before.reservation().state(), ReservationState::Reserved);

    let at = book
        .reservation_status_at(access, &UnixMillis::new(1_000))
        .expect("status at deadline");
    assert!(matches!(
        at.reservation().state(),
        ReservationState::Released {
            reason: ReleaseReason::Expired,
            at
        } if at == UnixMillis::new(1_000)
    ));
    assert_eq!(
        book.inventory(item.outpoint())
            .expect("inventory")
            .expect("known inventory")
            .state(),
        InventoryState::Available
    );
    drop(book);
    let reopened = open_book(&directory, identity);
    assert!(matches!(
        reopened
            .reservation_status(access)
            .expect("released status after reopen")
            .reservation()
            .state(),
        ReservationState::Released {
            reason: ReleaseReason::Expired,
            at
        } if at == UnixMillis::new(1_000)
    ));
}

#[test]
fn targeted_status_wrong_owner_cannot_expire_the_reservation() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(88);
    let book = open_book(&directory, identity);
    let reservation = reserve_one(&book, identity, inventory(129), owner(1), 1);

    assert!(matches!(
        book.reservation_status_at(
            ReservationAccess::new(reservation.id(), owner(2)),
            &UnixMillis::new(1_000),
        ),
        Err(ProviderError::ReservationOwnerMismatch(actual)) if actual == reservation.id()
    ));
    assert_eq!(
        book.reservation(reservation.id())
            .expect("reservation")
            .expect("known reservation")
            .state(),
        ReservationState::Reserved
    );
    assert_eq!(
        book.last_observed_time().expect("high watermark"),
        Some(UnixMillis::new(1_000))
    );
    drop(book);
    let reopened = open_book(&directory, identity);
    assert_eq!(
        reopened
            .reservation(reservation.id())
            .expect("reservation after reopen")
            .expect("known reservation")
            .state(),
        ReservationState::Reserved
    );
}

#[test]
fn targeted_status_does_not_release_after_the_point_of_no_return() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(89);
    let item = inventory(130);
    let book = open_book(&directory, identity);
    let reservation = reserve_one(&book, identity, item, owner(1), 1);
    let access = ReservationAccess::new(reservation.id(), reservation.owner());
    let committed = book
        .commit_before_sign(
            access,
            vec![1, 2, 3],
            transaction_fee(identity, 200),
            &UnixMillis::new(999),
        )
        .expect("commit before deadline");

    let status = book
        .reservation_status_at(access, &UnixMillis::new(1_000))
        .expect("committed status at deadline");
    assert!(matches!(
        status.reservation().state(),
        ReservationState::Committed { commitment, .. }
            if commitment == committed.signing_job().expect("job").commitment()
    ));
    assert_eq!(book.pending_signing_jobs(1).expect("pending").len(), 1);
}

#[test]
fn signed_status_replays_the_exact_durable_artifact() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(85);
    let book = open_book(&directory, identity);
    let reservation = reserve_one(&book, identity, inventory(126), owner(1), 1);
    let access = ReservationAccess::new(reservation.id(), reservation.owner());
    let committed = book
        .commit_before_sign(
            access,
            vec![1, 2, 3],
            transaction_fee(identity, 200),
            &UnixMillis::new(200),
        )
        .expect("commit signing intent");
    let commitment = committed
        .signing_job()
        .expect("new signing job")
        .commitment();
    let expected_bytes = signed_pset(9);
    let recorded = book
        .record_signed(
            reservation.id(),
            commitment,
            expected_bytes.clone(),
            &UnixMillis::new(201),
        )
        .expect("record signed artifact")
        .artifact()
        .clone();

    let status = book
        .reservation_status(access)
        .expect("authorized signed status");
    assert!(matches!(
        status.reservation().state(),
        ReservationState::Signed { .. }
    ));
    let replayed = status.signed_artifact().expect("signed artifact");
    assert_eq!(replayed, &recorded);
    assert_eq!(replayed.bytes(), expected_bytes);
}

#[test]
fn changed_request_cannot_reuse_an_idempotency_key() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(12);
    let book = open_book(&directory, identity);
    let item = inventory(22);
    let now = UnixMillis::new(100);
    book.import_inventory(item, &now).expect("inventory");
    let first = plan(identity, owner(1), 2, 3, vec![item.outpoint()], 1_000);
    book.reserve(&first, &now).expect("reserve");
    let changed = plan(identity, owner(1), 2, 4, vec![item.outpoint()], 1_000);
    assert!(matches!(
        book.reserve(&changed, &now),
        Err(ProviderError::IdempotencyConflict { .. })
    ));
}

#[test]
fn overlapping_multi_input_failure_never_partially_locks_inventory() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(13);
    let book = open_book(&directory, identity);
    let first = inventory(23);
    let second = inventory(24);
    let third = inventory(25);
    let now = UnixMillis::new(100);
    for item in [first, second, third] {
        book.import_inventory(item, &now).expect("inventory");
    }
    let winner = book
        .reserve(
            &plan(
                identity,
                owner(1),
                1,
                1,
                vec![first.outpoint(), second.outpoint()],
                1_000,
            ),
            &now,
        )
        .expect("winner");
    assert!(matches!(
        book.reserve(
            &plan(
                identity,
                owner(2),
                2,
                2,
                vec![second.outpoint(), third.outpoint()],
                1_000,
            ),
            &now,
        ),
        Err(ProviderError::OutpointUnavailable { outpoint, .. }) if outpoint == second.outpoint()
    ));
    assert_eq!(
        book.inventory(third.outpoint())
            .expect("third")
            .unwrap()
            .state(),
        InventoryState::Available
    );
    assert!(
        book.reservation(derive_reservation_id(
            owner(2),
            IdempotencyKey::new([2; 32])
        ))
        .expect("loser lookup")
        .is_none()
    );
    assert!(winner.created());
}

#[test]
fn deadline_is_exclusive_and_expiry_releases_only_uncommitted_inputs() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(14);
    let book = open_book(&directory, identity);
    let item = inventory(26);
    let reservation = reserve_one(&book, identity, item, owner(1), 1);

    let deadline = UnixMillis::new(1_000);
    assert!(matches!(
        book.commit_before_sign(
            ReservationAccess::new(reservation.id(), reservation.owner()),
            vec![1, 2, 3],
            transaction_fee(identity, 200),
            &deadline,
        ),
        Err(ProviderError::ReservationDeadlineElapsed { .. })
    ));
    assert!(matches!(
        book.reservation(reservation.id())
            .expect("reservation")
            .unwrap()
            .state(),
        ReservationState::Released {
            reason: ReleaseReason::Expired,
            ..
        }
    ));
    assert_eq!(
        book.inventory(item.outpoint())
            .expect("inventory")
            .unwrap()
            .state(),
        InventoryState::Available
    );

    let replacement = book
        .reserve(
            &plan(identity, owner(2), 2, 2, vec![item.outpoint()], 2_000),
            &UnixMillis::new(1_001),
        )
        .expect("replacement");
    assert!(replacement.created());
}

#[test]
fn expire_due_is_ordered_bounded_inclusive_and_restart_safe() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(74);
    let later_item = inventory(107);
    let earliest_item = inventory(108);
    let middle_item = inventory(109);
    let (later_id, earliest_id, middle_id) = {
        let book = open_book(&directory, identity);
        let now = UnixMillis::new(100);
        for item in [later_item, earliest_item, middle_item] {
            book.import_inventory(item, &now).expect("inventory");
        }

        // Insert out of deadline order so this test exercises the expiration
        // index rather than reservation insertion order.
        let later = book
            .reserve(
                &plan(identity, owner(1), 1, 1, vec![later_item.outpoint()], 700),
                &now,
            )
            .expect("later reservation")
            .reservation()
            .id();
        let earliest = book
            .reserve(
                &plan(
                    identity,
                    owner(2),
                    2,
                    2,
                    vec![earliest_item.outpoint()],
                    500,
                ),
                &now,
            )
            .expect("earliest reservation")
            .reservation()
            .id();
        let middle = book
            .reserve(
                &plan(identity, owner(3), 3, 3, vec![middle_item.outpoint()], 600),
                &now,
            )
            .expect("middle reservation")
            .reservation()
            .id();

        assert!(
            book.expire_due(&UnixMillis::new(499), usize::MAX)
                .expect("nothing due before the first deadline")
                .is_empty()
        );
        assert_eq!(
            book.expire_due(&UnixMillis::new(700), 2)
                .expect("bounded expiration batch"),
            vec![earliest, middle]
        );
        assert_eq!(
            book.inventory(later_item.outpoint())
                .expect("later inventory")
                .unwrap()
                .state(),
            InventoryState::Reserved {
                reservation_id: later,
            }
        );
        for (reservation_id, item) in [(earliest, earliest_item), (middle, middle_item)] {
            assert!(matches!(
                book.reservation(reservation_id)
                    .expect("expired reservation")
                    .unwrap()
                    .state(),
                ReservationState::Released {
                    reason: ReleaseReason::Expired,
                    at,
                } if at == UnixMillis::new(700)
            ));
            assert_eq!(
                book.inventory(item.outpoint())
                    .expect("released inventory")
                    .unwrap()
                    .state(),
                InventoryState::Available
            );
        }
        (later, earliest, middle)
    };

    let book = open_book(&directory, identity);
    assert_eq!(
        book.expire_due(&UnixMillis::new(700), 2)
            .expect("inclusive deadline after reopen"),
        vec![later_id]
    );
    assert!(
        book.expire_due(&UnixMillis::new(700), 2)
            .expect("expiration retry")
            .is_empty()
    );
    for (reservation_id, item) in [
        (earliest_id, earliest_item),
        (middle_id, middle_item),
        (later_id, later_item),
    ] {
        assert!(matches!(
            book.reservation(reservation_id)
                .expect("reservation")
                .unwrap()
                .state(),
            ReservationState::Released {
                reason: ReleaseReason::Expired,
                at,
            } if at == UnixMillis::new(700)
        ));
        assert_eq!(
            book.inventory(item.outpoint())
                .expect("inventory")
                .unwrap()
                .state(),
            InventoryState::Available
        );
    }
    let audit = book.audit_log().expect("audit");
    assert_eq!(audit.len(), 9);
    let expired_ids: Vec<_> = audit[6..]
        .iter()
        .map(|entry| match entry.event() {
            AuditEvent::ReservationReleased {
                reservation_id,
                reason: ReleaseReason::Expired,
            } => *reservation_id,
            other => panic!("unexpected expiration audit event: {other:?}"),
        })
        .collect();
    assert_eq!(expired_ids, vec![earliest_id, middle_id, later_id]);
    drop(book);

    let reopened = open_book(&directory, identity);
    assert!(
        reopened
            .expire_due(&UnixMillis::new(700), usize::MAX)
            .expect("reopened expiration retry")
            .is_empty()
    );
    assert_eq!(reopened.audit_log().expect("reopened audit").len(), 9);
}

#[test]
fn reserve_lazily_reclaims_only_the_expired_reservation_blocking_its_outpoint() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(75);
    let requested_item = inventory(110);
    let unrelated_item = inventory(111);
    let book = open_book(&directory, identity);
    let now = UnixMillis::new(100);
    for item in [requested_item, unrelated_item] {
        book.import_inventory(item, &now).expect("inventory");
    }
    let requested_old = book
        .reserve(
            &plan(
                identity,
                owner(1),
                1,
                1,
                vec![requested_item.outpoint()],
                500,
            ),
            &now,
        )
        .expect("requested old reservation")
        .reservation()
        .id();
    let unrelated = book
        .reserve(
            &plan(
                identity,
                owner(2),
                2,
                2,
                vec![unrelated_item.outpoint()],
                400,
            ),
            &now,
        )
        .expect("unrelated reservation")
        .reservation()
        .id();

    let replacement = book
        .reserve(
            &plan(
                identity,
                owner(3),
                3,
                3,
                vec![requested_item.outpoint()],
                1_000,
            ),
            &UnixMillis::new(500),
        )
        .expect("lazy reclaim replacement");
    assert!(replacement.created());
    assert!(matches!(
        book.reservation(requested_old)
            .expect("old reservation")
            .unwrap()
            .state(),
        ReservationState::Released {
            reason: ReleaseReason::Expired,
            at,
        } if at == UnixMillis::new(500)
    ));
    assert!(matches!(
        book.inventory(requested_item.outpoint())
            .expect("requested inventory")
            .unwrap()
            .state(),
        InventoryState::Reserved { reservation_id }
            if reservation_id == replacement.reservation().id()
    ));
    assert_eq!(
        book.reservation(unrelated)
            .expect("unrelated reservation")
            .unwrap()
            .state(),
        ReservationState::Reserved
    );
    assert!(matches!(
        book.inventory(unrelated_item.outpoint())
            .expect("unrelated inventory")
            .unwrap()
            .state(),
        InventoryState::Reserved { reservation_id } if reservation_id == unrelated
    ));
}

#[test]
fn fee_policy_is_rechecked_before_the_irreversible_transition() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(15);
    let book = open_book(&directory, identity);
    let item = inventory(27);
    let reservation = reserve_one(&book, identity, item, owner(1), 1);
    let access = ReservationAccess::new(reservation.id(), reservation.owner());
    let now = UnixMillis::new(200);

    assert!(matches!(
        book.commit_before_sign(access, vec![1, 2, 3], transaction_fee(identity, 199), &now,),
        Err(ProviderError::FeePolicy(
            FeePolicyViolation::FeeBelowMinimum { .. }
        ))
    ));
    assert_eq!(
        book.reservation(reservation.id())
            .expect("reservation")
            .unwrap()
            .state(),
        ReservationState::Reserved
    );

    let committed = book
        .commit_before_sign(access, vec![1, 2, 3], transaction_fee(identity, 200), &now)
        .expect("commit");
    assert!(committed.newly_committed());
    assert_eq!(
        committed
            .signing_job()
            .expect("new signing job")
            .pre_sign_payload(),
        &[1, 2, 3]
    );
}

#[test]
fn signing_commitment_covers_every_durable_wallet_target_field() {
    let identity = identity(18);
    let request = plan(identity, owner(1), 1, 2, vec![outpoint(30, 0)], 1_000);
    let reservation = StoredReservation {
        id: derive_reservation_id(request.owner(), request.idempotency_key()).to_bytes(),
        owner: request.owner().to_bytes(),
        idempotency_key: request.idempotency_key().to_bytes(),
        semantic_request_digest: request.request_digest().to_bytes(),
        request_digest: request_digest(identity, &request).expect("request digest"),
        quote_commitment: request.quote_commitment().to_bytes(),
        quote: None,
        outpoints: request.outpoints().to_vec(),
        created_at: 100,
        accept_before: request.accept_before().value(),
        fee_policy: StoredFeePolicy::from(request.fee_policy()),
        state: StoredReservationState::Reserved,
    };
    let base =
        StoredSigningTarget::from_inventory(StoredInventoryItem::from(inventory_variant(30, 30)));
    let alternate =
        StoredSigningTarget::from_inventory(StoredInventoryItem::from(inventory_variant(31, 31)));
    let expected = signing_commitment(
        &reservation,
        &[1, 2, 3],
        transaction_fee(identity, 200),
        &[base],
    )
    .expect("base commitment");

    let mut changed_outpoint = base;
    changed_outpoint.outpoint = alternate.outpoint;
    let mut changed_locator = base;
    changed_locator.wallet_locator = alternate.wallet_locator;
    let mut changed_key = base;
    changed_key.internal_key = alternate.internal_key;
    let mut changed_binding = base;
    changed_binding.inventory_binding = alternate.inventory_binding;

    for (field, target) in [
        ("outpoint", changed_outpoint),
        ("wallet locator", changed_locator),
        ("internal key", changed_key),
        ("inventory binding", changed_binding),
    ] {
        let actual = signing_commitment(
            &reservation,
            &[1, 2, 3],
            transaction_fee(identity, 200),
            &[target],
        )
        .expect("changed commitment");
        assert_ne!(expected, actual, "target {field} must be committed");
    }
}

#[test]
fn committed_outpoints_never_reopen_after_deadline_cancel_or_restart() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(16);
    let item = inventory(28);
    let (reservation_id, commitment) = {
        let book = open_book(&directory, identity);
        let reservation = reserve_one(&book, identity, item, owner(1), 1);
        let access = ReservationAccess::new(reservation.id(), reservation.owner());
        let committed = book
            .commit_before_sign(
                access,
                vec![9, 8, 7],
                transaction_fee(identity, 200),
                &UnixMillis::new(999),
            )
            .expect("commit");
        assert!(matches!(
            book.cancel(access, &UnixMillis::new(2_000)),
            Err(ProviderError::PointOfNoReturn(_))
        ));
        assert!(
            book.expire_due(&UnixMillis::new(2_000), usize::MAX)
                .expect("expire")
                .is_empty()
        );
        (
            reservation.id(),
            committed
                .signing_job()
                .expect("new signing job")
                .commitment(),
        )
    };

    let reopened = open_book(&directory, identity);
    assert!(matches!(
        reopened
            .inventory(item.outpoint())
            .expect("inventory")
            .unwrap()
            .state(),
        InventoryState::Committed {
            reservation_id: actual,
            commitment: actual_commitment,
        } if actual == reservation_id && actual_commitment == commitment
    ));
    assert!(matches!(
        reopened.recovery_actions().expect("recovery").as_slice(),
        [RecoveryAction::SignCommittedExact(job)]
            if job.reservation_id() == reservation_id
                && job.commitment() == commitment
                && job.pre_sign_payload() == [9, 8, 7]
                && job.targets().len() == 1
                && job.targets()[0].outpoint() == item.outpoint()
                && job.targets()[0].wallet_locator() == item.wallet_locator()
                && job.targets()[0].internal_key() == item.internal_key()
                && job.targets()[0].inventory_binding() == item.binding()
    ));
    assert!(matches!(
        reopened.reserve(
            &plan(identity, owner(2), 2, 2, vec![item.outpoint()], 3_000,),
            &UnixMillis::new(2_001),
        ),
        Err(ProviderError::OutpointUnavailable {
            state: InventoryState::Committed { .. },
            ..
        })
    ));
}

#[test]
fn commitment_and_signed_response_retries_are_exact_and_restart_safe() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(17);
    let item = inventory(29);
    let book = open_book(&directory, identity);
    let reservation = reserve_one(&book, identity, item, owner(1), 1);
    let access = ReservationAccess::new(reservation.id(), reservation.owner());
    let now = UnixMillis::new(200);
    let first = book
        .commit_before_sign(access, vec![1, 2, 3], transaction_fee(identity, 200), &now)
        .expect("commit");
    let retry = book
        .commit_before_sign(
            access,
            vec![1, 2, 3],
            transaction_fee(identity, 200),
            &UnixMillis::new(201),
        )
        .expect("commit retry");
    assert!(!retry.newly_committed());
    assert_eq!(retry.signing_job(), first.signing_job());
    let commitment = first.signing_job().expect("new signing job").commitment();
    assert!(matches!(
        book.commit_before_sign(
            access,
            vec![1, 2, 4],
            transaction_fee(identity, 200),
            &UnixMillis::new(202),
        ),
        Err(ProviderError::DifferentSigningIntent(_))
    ));

    let signed_bytes = signed_pset(5);
    let signed = book
        .record_signed(
            reservation.id(),
            commitment,
            signed_bytes.clone(),
            &UnixMillis::new(203),
        )
        .expect("signed");
    assert!(signed.recorded());
    let retry = book
        .record_signed(
            reservation.id(),
            commitment,
            signed_bytes,
            &UnixMillis::new(204),
        )
        .expect("signed retry");
    assert!(!retry.recorded());
    assert_eq!(retry.artifact(), signed.artifact());
    let completed_retry = book
        .commit_before_sign(
            access,
            vec![1, 2, 3],
            transaction_fee(identity, 200),
            &UnixMillis::new(205),
        )
        .expect("completed commit retry");
    assert_eq!(completed_retry.signed_artifact(), Some(signed.artifact()));
    assert!(matches!(
        book.record_signed(
            reservation.id(),
            commitment,
            signed_pset(6),
            &UnixMillis::new(206),
        ),
        Err(ProviderError::DifferentSignedArtifact(_))
    ));
    drop(book);

    let reopened = open_book(&directory, identity);
    assert!(matches!(
        reopened.recovery_actions().expect("recovery").as_slice(),
        [RecoveryAction::ReplaySignedExact(artifact)]
            if artifact == signed.artifact()
    ));
    assert!(
        reopened
            .pending_signing_jobs(usize::MAX)
            .expect("pending")
            .is_empty()
    );
}

#[test]
fn pending_signing_jobs_are_bounded_ordered_and_survive_reopen() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(90);
    let first_item = inventory(131);
    let second_item = inventory(132);
    let (first_job, second_job) = {
        let book = open_book(&directory, identity);
        let first = reserve_one(&book, identity, first_item, owner(1), 1);
        let first_job = book
            .commit_before_sign(
                ReservationAccess::new(first.id(), first.owner()),
                vec![1],
                transaction_fee(identity, 200),
                &UnixMillis::new(200),
            )
            .expect("first commit")
            .signing_job()
            .expect("first job")
            .clone();
        let retry = book
            .commit_before_sign(
                ReservationAccess::new(first.id(), first.owner()),
                vec![1],
                transaction_fee(identity, 200),
                &UnixMillis::new(201),
            )
            .expect("first commit retry");
        assert_eq!(retry.signing_job(), Some(&first_job));
        assert!(!retry.newly_committed());
        assert_eq!(
            book.pending_signing_jobs(usize::MAX)
                .expect("pending")
                .as_slice(),
            std::slice::from_ref(&first_job)
        );

        book.import_inventory(second_item, &UnixMillis::new(202))
            .expect("second inventory");
        let second = book
            .reserve(
                &plan(
                    identity,
                    owner(2),
                    2,
                    3,
                    vec![second_item.outpoint()],
                    2_000,
                ),
                &UnixMillis::new(202),
            )
            .expect("second reserve")
            .reservation()
            .clone();
        let second_job = book
            .commit_before_sign(
                ReservationAccess::new(second.id(), second.owner()),
                vec![2],
                transaction_fee(identity, 200),
                &UnixMillis::new(203),
            )
            .expect("second commit")
            .signing_job()
            .expect("second job")
            .clone();

        assert!(book.pending_signing_jobs(0).expect("zero batch").is_empty());
        assert_eq!(
            book.pending_signing_jobs(1).expect("one job").as_slice(),
            std::slice::from_ref(&first_job)
        );
        (first_job, second_job)
    };

    let reopened = open_book(&directory, identity);
    assert_eq!(
        reopened
            .pending_signing_jobs(usize::MAX)
            .expect("all pending jobs"),
        [first_job.clone(), second_job.clone()]
    );
    reopened
        .record_signed(
            first_job.reservation_id(),
            first_job.commitment(),
            signed_pset(9),
            &UnixMillis::new(204),
        )
        .expect("sign first");
    assert_eq!(
        reopened
            .pending_signing_jobs(usize::MAX)
            .expect("remaining"),
        [second_job]
    );
}

#[test]
fn pending_signing_batch_limit_is_hard_capped() {
    assert_eq!(pending_signing_batch_limit(0), 0);
    assert_eq!(
        pending_signing_batch_limit(MAX_PENDING_SIGNING_BATCH),
        MAX_PENDING_SIGNING_BATCH
    );
    assert_eq!(
        pending_signing_batch_limit(usize::MAX),
        MAX_PENDING_SIGNING_BATCH
    );
}

#[test]
fn signed_allocation_stays_retired_and_recoverable_after_deadline_and_reopen() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(76);
    let item = inventory(112);
    let (reservation_id, access, commitment, artifact) = {
        let book = open_book(&directory, identity);
        let reservation = reserve_one(&book, identity, item, owner(1), 1);
        let access = ReservationAccess::new(reservation.id(), reservation.owner());
        let committed = book
            .commit_before_sign(
                access,
                vec![1, 2, 3],
                transaction_fee(identity, 200),
                &UnixMillis::new(999),
            )
            .expect("commit before deadline");
        let commitment = committed.signing_job().expect("signing job").commitment();
        let signed = book
            .record_signed(
                reservation.id(),
                commitment,
                signed_pset(4),
                &UnixMillis::new(2_000),
            )
            .expect("signing may finish after durable acceptance deadline");
        assert!(signed.recorded());
        assert!(
            book.expire_due(&UnixMillis::new(3_000), usize::MAX)
                .expect("committed reservation is not expirable")
                .is_empty()
        );
        assert!(matches!(
            book.inventory(item.outpoint())
                .expect("inventory")
                .unwrap()
                .state(),
            InventoryState::Committed {
                reservation_id,
                commitment: actual,
            } if reservation_id == reservation.id() && actual == commitment
        ));
        (
            reservation.id(),
            access,
            commitment,
            signed.artifact().clone(),
        )
    };

    let reopened = open_book(&directory, identity);
    assert!(matches!(
        reopened
            .inventory(item.outpoint())
            .expect("inventory")
            .unwrap()
            .state(),
        InventoryState::Committed {
            reservation_id: actual_id,
            commitment: actual_commitment,
        } if actual_id == reservation_id && actual_commitment == commitment
    ));
    assert!(matches!(
        reopened.recovery_actions().expect("recovery").as_slice(),
        [RecoveryAction::ReplaySignedExact(recovered)] if recovered == &artifact
    ));
    let completed_retry = reopened
        .commit_before_sign(
            access,
            vec![1, 2, 3],
            transaction_fee(identity, 200),
            &UnixMillis::new(3_001),
        )
        .expect("exact post-deadline commitment retry");
    assert_eq!(completed_retry.signed_artifact(), Some(&artifact));
    assert!(matches!(
        reopened.reserve(
            &plan(identity, owner(2), 2, 2, vec![item.outpoint()], 4_000),
            &UnixMillis::new(3_002),
        ),
        Err(ProviderError::OutpointUnavailable {
            state: InventoryState::Committed { .. },
            ..
        })
    ));
}

#[test]
fn persisted_clock_high_watermark_fails_closed_on_rollback() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(18);
    let item = inventory(30);
    {
        let book = open_book(&directory, identity);
        book.import_inventory(item, &UnixMillis::new(500))
            .expect("inventory");
        assert_eq!(
            book.last_observed_time().expect("time"),
            Some(UnixMillis::new(500))
        );
    }
    let reopened = open_book(&directory, identity);
    assert!(matches!(
        reopened.reserve(
            &plan(
                identity,
                owner(1),
                1,
                1,
                vec![item.outpoint()],
                1_000,
            ),
            &UnixMillis::new(499),
        ),
        Err(ProviderError::ClockRegression {
            previous,
            now,
        }) if previous == UnixMillis::new(500) && now == UnixMillis::new(499)
    ));
    assert_eq!(
        reopened
            .inventory(item.outpoint())
            .expect("inventory")
            .unwrap()
            .state(),
        InventoryState::Available
    );
}

#[test]
fn failed_wrong_owner_operation_durably_advances_the_clock_high_watermark() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(77);
    let item = inventory(113);
    let book = open_book(&directory, identity);
    let reservation = reserve_one(&book, identity, item, owner(1), 1);
    let wrong_access = ReservationAccess::new(reservation.id(), owner(2));
    assert!(matches!(
        book.commit_before_sign(
            wrong_access,
            vec![1, 2, 3],
            transaction_fee(identity, 200),
            &UnixMillis::new(1_100),
        ),
        Err(ProviderError::ReservationOwnerMismatch(actual)) if actual == reservation.id()
    ));
    assert_eq!(
        book.last_observed_time().expect("time"),
        Some(UnixMillis::new(1_100))
    );
    assert!(matches!(
        book.commit_before_sign(
            ReservationAccess::new(reservation.id(), reservation.owner()),
            vec![1, 2, 3],
            transaction_fee(identity, 200),
            &UnixMillis::new(999),
        ),
        Err(ProviderError::ClockRegression { previous, now })
            if previous == UnixMillis::new(1_100) && now == UnixMillis::new(999)
    ));
    assert_eq!(
        book.reservation(reservation.id())
            .expect("reservation")
            .unwrap()
            .state(),
        ReservationState::Reserved
    );
    drop(book);

    let reopened = open_book(&directory, identity);
    assert_eq!(
        reopened.last_observed_time().expect("reopened time"),
        Some(UnixMillis::new(1_100))
    );
    assert!(matches!(
        reopened
            .inventory(item.outpoint())
            .expect("inventory")
            .unwrap()
            .state(),
        InventoryState::Reserved { reservation_id } if reservation_id == reservation.id()
    ));
}

#[test]
fn concurrent_reservations_have_one_durable_winner() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(19);
    let item = inventory(31);
    let book = Arc::new(open_book(&directory, identity));
    book.import_inventory(item, &UnixMillis::new(100))
        .expect("inventory");
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();
    for marker in 1..=8_u8 {
        let book = Arc::clone(&book);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let request = plan(
                identity,
                owner(marker),
                marker,
                marker,
                vec![item.outpoint()],
                1_000,
            );
            barrier.wait();
            book.reserve(&request, &UnixMillis::new(200))
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("thread"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(ProviderError::OutpointUnavailable { .. })))
            .count(),
        7
    );
    let winning_id = results
        .iter()
        .find_map(|result| result.as_ref().ok())
        .expect("winner")
        .reservation()
        .id();
    drop(results);
    drop(book);

    let reopened = open_book(&directory, identity);
    assert!(matches!(
        reopened
            .inventory(item.outpoint())
            .expect("inventory")
            .unwrap()
            .state(),
        InventoryState::Reserved { reservation_id } if reservation_id == winning_id
    ));
}

#[test]
fn concurrent_overlapping_multi_input_reservations_remain_atomic_after_reopen() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(78);
    let first = inventory(114);
    let shared = inventory(115);
    let third = inventory(116);
    let book = Arc::new(open_book(&directory, identity));
    for item in [first, shared, third] {
        book.import_inventory(item, &UnixMillis::new(100))
            .expect("inventory");
    }
    let left_owner = owner(1);
    let right_owner = owner(2);
    let left_key = IdempotencyKey::new([1; 32]);
    let right_key = IdempotencyKey::new([2; 32]);
    let left_id = derive_reservation_id(left_owner, left_key);
    let right_id = derive_reservation_id(right_owner, right_key);
    let barrier = Arc::new(Barrier::new(2));

    let left_book = Arc::clone(&book);
    let left_barrier = Arc::clone(&barrier);
    let left = thread::spawn(move || {
        let request = plan(
            identity,
            left_owner,
            1,
            1,
            vec![first.outpoint(), shared.outpoint()],
            1_000,
        );
        left_barrier.wait();
        left_book.reserve(&request, &UnixMillis::new(200))
    });
    let right_book = Arc::clone(&book);
    let right_barrier = Arc::clone(&barrier);
    let right = thread::spawn(move || {
        let request = plan(
            identity,
            right_owner,
            2,
            2,
            vec![shared.outpoint(), third.outpoint()],
            1_000,
        );
        right_barrier.wait();
        right_book.reserve(&request, &UnixMillis::new(200))
    });
    let left = left.join().expect("left thread");
    let right = right.join().expect("right thread");
    assert_ne!(left.is_ok(), right.is_ok());
    assert_eq!(
        [&left, &right]
            .into_iter()
            .filter(|result| {
                matches!(
                    result,
                    Err(ProviderError::OutpointUnavailable { outpoint, .. })
                        if *outpoint == shared.outpoint()
                )
            })
            .count(),
        1
    );

    let (winning_id, winning_items, losing_id, losing_only_item) = if left.is_ok() {
        (left_id, [first, shared], right_id, third)
    } else {
        (right_id, [shared, third], left_id, first)
    };
    for item in winning_items {
        assert!(matches!(
            book.inventory(item.outpoint())
                .expect("winning inventory")
                .unwrap()
                .state(),
            InventoryState::Reserved { reservation_id } if reservation_id == winning_id
        ));
    }
    assert_eq!(
        book.inventory(losing_only_item.outpoint())
            .expect("losing-only inventory")
            .unwrap()
            .state(),
        InventoryState::Available
    );
    assert!(
        book.reservation(losing_id)
            .expect("losing reservation")
            .is_none()
    );
    assert_eq!(book.audit_log().expect("audit").len(), 4);
    drop(left);
    drop(right);
    drop(book);

    let reopened = open_book(&directory, identity);
    assert_eq!(
        reopened
            .reservation(winning_id)
            .expect("winning reservation")
            .unwrap()
            .outpoints(),
        winning_items.map(InventoryItem::outpoint)
    );
    assert!(
        reopened
            .reservation(losing_id)
            .expect("losing reservation")
            .is_none()
    );
    for item in winning_items {
        assert!(matches!(
            reopened
                .inventory(item.outpoint())
                .expect("reopened winning inventory")
                .unwrap()
                .state(),
            InventoryState::Reserved { reservation_id } if reservation_id == winning_id
        ));
    }
    assert_eq!(
        reopened
            .inventory(losing_only_item.outpoint())
            .expect("reopened losing-only inventory")
            .unwrap()
            .state(),
        InventoryState::Available
    );
    assert_eq!(reopened.audit_log().expect("reopened audit").len(), 4);
}

#[test]
fn concurrent_cancel_and_commit_linearize_to_one_legal_state() {
    for iteration in 0..16_u8 {
        let directory = TempDir::new().expect("tempdir");
        let identity = identity(40_u8.wrapping_add(iteration));
        let item = inventory(80_u8.wrapping_add(iteration));
        let book = Arc::new(open_book(&directory, identity));
        let reservation = reserve_one(&book, identity, item, owner(1), 1);
        let access = ReservationAccess::new(reservation.id(), reservation.owner());
        let barrier = Arc::new(Barrier::new(2));

        let cancel_book = Arc::clone(&book);
        let cancel_barrier = Arc::clone(&barrier);
        let cancel = thread::spawn(move || {
            cancel_barrier.wait();
            cancel_book.cancel(access, &UnixMillis::new(200))
        });
        let commit_book = Arc::clone(&book);
        let commit_barrier = Arc::clone(&barrier);
        let commit = thread::spawn(move || {
            commit_barrier.wait();
            commit_book.commit_before_sign(
                access,
                vec![1, 2, 3],
                transaction_fee(identity, 200),
                &UnixMillis::new(200),
            )
        });
        let cancel = cancel.join().expect("cancel thread");
        let commit = commit.join().expect("commit thread");
        assert_ne!(cancel.is_ok(), commit.is_ok());
        let state = book
            .reservation(reservation.id())
            .expect("reservation")
            .unwrap()
            .state();
        match state {
            ReservationState::Released {
                reason: ReleaseReason::ClientCancelled,
                ..
            } => assert_eq!(
                book.inventory(item.outpoint())
                    .expect("inventory")
                    .unwrap()
                    .state(),
                InventoryState::Available
            ),
            ReservationState::Committed { commitment, .. } => assert!(matches!(
                book.inventory(item.outpoint())
                    .expect("inventory")
                    .unwrap()
                    .state(),
                InventoryState::Committed {
                    reservation_id,
                    commitment: actual,
                } if reservation_id == reservation.id() && actual == commitment
            )),
            other => panic!("illegal race result: {other:?}"),
        }
    }
}

#[test]
fn database_is_bound_to_one_provider_and_chain_identity() {
    let directory = TempDir::new().expect("tempdir");
    let first = identity(60);
    let book = open_book(&directory, first);
    assert_eq!(book.identity(), first);
    assert_eq!(book.schema_version().expect("schema"), SCHEMA_VERSION);
    drop(book);

    let error = match ReservationBook::open(directory.path().join("provider.redb"), identity(61)) {
        Ok(_) => panic!("identity mismatch must fail"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        ProviderError::ProviderIdentityMismatch {
            expected,
            actual,
        } if *expected == first && *actual == identity(61)
    ));
}

#[test]
fn audit_log_is_ordered_and_records_the_safety_boundaries() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(62);
    let book = open_book(&directory, identity);
    let item = inventory(90);
    let reservation = reserve_one(&book, identity, item, owner(1), 1);
    let committed = book
        .commit_before_sign(
            ReservationAccess::new(reservation.id(), reservation.owner()),
            vec![1],
            transaction_fee(identity, 200),
            &UnixMillis::new(200),
        )
        .expect("commit");
    book.record_signed(
        reservation.id(),
        committed
            .signing_job()
            .expect("new signing job")
            .commitment(),
        signed_pset(2),
        &UnixMillis::new(201),
    )
    .expect("signed");
    let audit = book.audit_log().expect("audit");
    assert_eq!(
        audit.iter().map(AuditEntry::sequence).collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    assert!(matches!(
        audit[0].event(),
        AuditEvent::InventoryImported { .. }
    ));
    assert!(matches!(
        audit[1].event(),
        AuditEvent::ReservationCreated { .. }
    ));
    assert!(matches!(
        audit[2].event(),
        AuditEvent::SigningCommitted { .. }
    ));
    assert!(matches!(
        audit[3].event(),
        AuditEvent::SignedArtifactStored { .. }
    ));
}

#[test]
fn startup_integrity_rejects_a_missing_committed_allocation() {
    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("provider.redb");
    let identity = identity(79);
    let item = inventory(117);
    {
        let book = ReservationBook::open(&path, identity).expect("book");
        let reservation = reserve_one(&book, identity, item, owner(1), 1);
        book.commit_before_sign(
            ReservationAccess::new(reservation.id(), reservation.owner()),
            vec![1, 2, 3],
            transaction_fee(identity, 200),
            &UnixMillis::new(200),
        )
        .expect("commit");
    }

    {
        let database = Database::create(&path).expect("raw database");
        let mut write = database.begin_write().expect("raw write");
        write
            .set_durability(Durability::Immediate)
            .expect("durability");
        let removed = {
            let mut allocations = write.open_table(ALLOCATIONS).expect("allocations");
            allocations
                .remove(outpoint_key(item.outpoint()).as_slice())
                .expect("remove")
                .is_some()
        };
        assert!(removed);
        write.commit().expect("commit corruption fixture");
    }

    let error = match ReservationBook::open(&path, identity) {
        Ok(_) => panic!("missing committed allocation must fail closed"),
        Err(error) => error,
    };
    assert!(matches!(error, ProviderError::CorruptState(message)
        if message.contains("permanent allocation")));
}

#[test]
fn startup_integrity_rejects_a_missing_pending_signing_entry() {
    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("provider.redb");
    let identity = identity(91);
    let reservation_id = {
        let book = ReservationBook::open(&path, identity).expect("book");
        let reservation = reserve_one(&book, identity, inventory(133), owner(1), 1);
        book.commit_before_sign(
            ReservationAccess::new(reservation.id(), reservation.owner()),
            vec![1, 2, 3],
            transaction_fee(identity, 200),
            &UnixMillis::new(200),
        )
        .expect("commit");
        reservation.id()
    };

    {
        let database = Database::create(&path).expect("raw database");
        let mut write = database.begin_write().expect("raw write");
        write
            .set_durability(Durability::Immediate)
            .expect("durability");
        let removed = write
            .open_table(PENDING_SIGNING)
            .expect("pending")
            .remove(pending_signing_key(UnixMillis::new(200), reservation_id).as_slice())
            .expect("remove")
            .is_some();
        assert!(removed);
        write.commit().expect("commit corruption fixture");
    }

    let error = match ReservationBook::open(&path, identity) {
        Ok(_) => panic!("missing pending-signing entry must fail closed"),
        Err(error) => error,
    };
    assert!(matches!(error, ProviderError::CorruptState(message)
        if message.contains("pending-signing index entry")));
}

#[test]
fn startup_integrity_rejects_a_pending_entry_for_a_signed_reservation() {
    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("provider.redb");
    let identity = identity(92);
    let reservation_id = {
        let book = ReservationBook::open(&path, identity).expect("book");
        let reservation = reserve_one(&book, identity, inventory(134), owner(1), 1);
        let job = book
            .commit_before_sign(
                ReservationAccess::new(reservation.id(), reservation.owner()),
                vec![1, 2, 3],
                transaction_fee(identity, 200),
                &UnixMillis::new(200),
            )
            .expect("commit")
            .signing_job()
            .expect("job")
            .clone();
        book.record_signed(
            reservation.id(),
            job.commitment(),
            signed_pset(4),
            &UnixMillis::new(300),
        )
        .expect("signed");
        reservation.id()
    };

    {
        let database = Database::create(&path).expect("raw database");
        let mut write = database.begin_write().expect("raw write");
        write
            .set_durability(Durability::Immediate)
            .expect("durability");
        let empty: &[u8] = &[];
        write
            .open_table(PENDING_SIGNING)
            .expect("pending")
            .insert(
                pending_signing_key(UnixMillis::new(200), reservation_id).as_slice(),
                empty,
            )
            .expect("insert");
        write.commit().expect("commit corruption fixture");
    }

    let error = match ReservationBook::open(&path, identity) {
        Ok(_) => panic!("signed reservation pending-signing entry must fail closed"),
        Err(error) => error,
    };
    assert!(matches!(error, ProviderError::CorruptState(message)
        if message.contains("non-committed reservation")));
}

#[test]
fn missing_schema_metadata_cannot_reinitialize_a_nonempty_database() {
    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("provider.redb");
    let identity = identity(80);
    {
        let book = ReservationBook::open(&path, identity).expect("book");
        book.import_inventory(inventory(118), &UnixMillis::new(100))
            .expect("inventory");
    }

    {
        let database = Database::create(&path).expect("raw database");
        let mut write = database.begin_write().expect("raw write");
        write
            .set_durability(Durability::Immediate)
            .expect("durability");
        let removed = {
            let mut meta = write.open_table(META).expect("meta");
            meta.remove(SCHEMA_VERSION_KEY).expect("remove").is_some()
        };
        assert!(removed);
        write.commit().expect("commit corruption fixture");
    }

    let error = match ReservationBook::open(&path, identity) {
        Ok(_) => panic!("nonempty database without schema metadata must fail closed"),
        Err(error) => error,
    };
    assert!(matches!(error, ProviderError::CorruptState(message)
        if message.contains("schema version is missing")));
}

#[test]
fn strict_record_codec_rejects_wrong_versions_and_trailing_bytes() {
    let encoded = encode_record(&StoredRequestBinding {
        reservation_id: [1; 32],
        semantic_request_digest: [2; 32],
        request_digest: [3; 32],
    })
    .expect("encode");
    let mut wrong_version = encoded.clone();
    wrong_version[0] = RECORD_VERSION.wrapping_add(1);
    assert!(matches!(
        decode_record::<StoredRequestBinding>(&wrong_version),
        Err(ProviderError::RecordVersionMismatch { .. })
    ));
    let mut trailing = encoded;
    trailing.push(0);
    assert!(matches!(
        decode_record::<StoredRequestBinding>(&trailing),
        Err(ProviderError::TrailingRecordBytes(1))
    ));
}

#[test]
fn reservation_failpoints_rollback_every_logical_table() {
    let failpoints = [
        (mutation_failpoints::RESERVE_AFTER_RECORD, 0),
        (mutation_failpoints::RESERVE_AFTER_REQUEST_KEY, 0),
        (mutation_failpoints::RESERVE_AFTER_ALLOCATION, 0),
        (mutation_failpoints::RESERVE_AFTER_ALLOCATION, 1),
        (mutation_failpoints::RESERVE_AFTER_EXPIRATION, 0),
        (mutation_failpoints::RESERVE_AFTER_AUDIT, 0),
    ];
    for (name, occurrence) in failpoints {
        let directory = TempDir::new().expect("tempdir");
        let identity = identity(70);
        let first = inventory(100);
        let second = inventory(101);
        let request = plan(
            identity,
            owner(1),
            1,
            1,
            vec![first.outpoint(), second.outpoint()],
            1_000,
        );
        let reservation_id = derive_reservation_id(owner(1), IdempotencyKey::new([1; 32]));
        {
            let book = open_book(&directory, identity);
            for item in [first, second] {
                book.import_inventory(item, &UnixMillis::new(100))
                    .expect("inventory");
            }
            let guard = mutation_failpoints::arm(name, occurrence);
            assert!(matches!(
                book.reserve(&request, &UnixMillis::new(200)),
                Err(ProviderError::InjectedMutationFailure(actual)) if actual == name
            ));
            drop(guard);
        }
        let reopened = open_book(&directory, identity);
        assert!(
            reopened
                .reservation(reservation_id)
                .expect("reservation")
                .is_none()
        );
        assert_eq!(reopened.audit_log().expect("audit").len(), 2);
        assert_eq!(
            reopened.last_observed_time().expect("time"),
            Some(UnixMillis::new(200))
        );
        for item in [first, second] {
            assert_eq!(
                reopened
                    .inventory(item.outpoint())
                    .expect("inventory")
                    .unwrap()
                    .state(),
                InventoryState::Available
            );
        }
        assert!(
            reopened
                .reserve(&request, &UnixMillis::new(200))
                .expect("retry")
                .created()
        );
    }
}

#[test]
fn release_failpoints_never_partially_unlock_a_reservation() {
    let failpoints = [
        (mutation_failpoints::RELEASE_AFTER_ALLOCATION, 0),
        (mutation_failpoints::RELEASE_AFTER_ALLOCATION, 1),
        (mutation_failpoints::RELEASE_AFTER_EXPIRATION, 0),
        (mutation_failpoints::RELEASE_AFTER_RECORD, 0),
        (mutation_failpoints::RELEASE_AFTER_AUDIT, 0),
    ];
    for (name, occurrence) in failpoints {
        let directory = TempDir::new().expect("tempdir");
        let identity = identity(71);
        let first = inventory(102);
        let second = inventory(103);
        let access = {
            let book = open_book(&directory, identity);
            let now = UnixMillis::new(100);
            for item in [first, second] {
                book.import_inventory(item, &now).expect("inventory");
            }
            let reservation = book
                .reserve(
                    &plan(
                        identity,
                        owner(1),
                        1,
                        1,
                        vec![first.outpoint(), second.outpoint()],
                        1_000,
                    ),
                    &now,
                )
                .expect("reserve")
                .reservation()
                .clone();
            let access = ReservationAccess::new(reservation.id(), reservation.owner());
            let guard = mutation_failpoints::arm(name, occurrence);
            assert!(matches!(
                book.cancel(access, &UnixMillis::new(200)),
                Err(ProviderError::InjectedMutationFailure(actual)) if actual == name
            ));
            drop(guard);
            access
        };
        let reopened = open_book(&directory, identity);
        assert_eq!(
            reopened
                .reservation(access.reservation_id())
                .expect("reservation")
                .unwrap()
                .state(),
            ReservationState::Reserved
        );
        assert_eq!(reopened.audit_log().expect("audit").len(), 3);
        for item in [first, second] {
            assert!(matches!(
                reopened
                    .inventory(item.outpoint())
                    .expect("inventory")
                    .unwrap()
                    .state(),
                InventoryState::Reserved { reservation_id }
                    if reservation_id == access.reservation_id()
            ));
        }
        assert!(
            reopened
                .cancel(access, &UnixMillis::new(200))
                .expect("retry")
        );
    }
}

#[test]
fn signing_commitment_failpoints_never_cross_the_point_of_no_return() {
    let failpoints = [
        (mutation_failpoints::COMMIT_AFTER_ALLOCATION, 0),
        (mutation_failpoints::COMMIT_AFTER_ALLOCATION, 1),
        (mutation_failpoints::COMMIT_AFTER_EXPIRATION, 0),
        (mutation_failpoints::COMMIT_AFTER_RECORD, 0),
        (mutation_failpoints::COMMIT_AFTER_PENDING_SIGNING, 0),
        (mutation_failpoints::COMMIT_AFTER_AUDIT, 0),
    ];
    for (name, occurrence) in failpoints {
        let directory = TempDir::new().expect("tempdir");
        let identity = identity(72);
        let first = inventory(104);
        let second = inventory(105);
        let access = {
            let book = open_book(&directory, identity);
            let now = UnixMillis::new(100);
            for item in [first, second] {
                book.import_inventory(item, &now).expect("inventory");
            }
            let reservation = book
                .reserve(
                    &plan(
                        identity,
                        owner(1),
                        1,
                        1,
                        vec![first.outpoint(), second.outpoint()],
                        1_000,
                    ),
                    &now,
                )
                .expect("reserve")
                .reservation()
                .clone();
            let access = ReservationAccess::new(reservation.id(), reservation.owner());
            let guard = mutation_failpoints::arm(name, occurrence);
            assert!(matches!(
                book.commit_before_sign(
                    access,
                    vec![1, 2, 3],
                    transaction_fee(identity, 200),
                    &UnixMillis::new(200),
                ),
                Err(ProviderError::InjectedMutationFailure(actual)) if actual == name
            ));
            drop(guard);
            access
        };
        let reopened = open_book(&directory, identity);
        assert_eq!(
            reopened
                .reservation(access.reservation_id())
                .expect("reservation")
                .unwrap()
                .state(),
            ReservationState::Reserved
        );
        assert!(reopened.recovery_actions().expect("recovery").is_empty());
        assert!(
            reopened
                .pending_signing_jobs(usize::MAX)
                .expect("pending")
                .is_empty()
        );
        assert_eq!(reopened.audit_log().expect("audit").len(), 3);
        for item in [first, second] {
            assert!(matches!(
                reopened
                    .inventory(item.outpoint())
                    .expect("inventory")
                    .unwrap()
                    .state(),
                InventoryState::Reserved { reservation_id }
                    if reservation_id == access.reservation_id()
            ));
        }
        assert!(
            reopened
                .commit_before_sign(
                    access,
                    vec![1, 2, 3],
                    transaction_fee(identity, 200),
                    &UnixMillis::new(200),
                )
                .expect("retry")
                .newly_committed()
        );
    }
}

#[test]
fn signed_artifact_failpoints_leave_an_exact_recoverable_signing_job() {
    let failpoints = [
        (mutation_failpoints::SIGNED_AFTER_RECORD, 0),
        (mutation_failpoints::SIGNED_AFTER_PENDING_SIGNING, 0),
        (mutation_failpoints::SIGNED_AFTER_RELAY_RECORD, 0),
        (mutation_failpoints::SIGNED_AFTER_RELAY_DUE, 0),
        (mutation_failpoints::SIGNED_AFTER_AUDIT, 0),
    ];
    for (name, occurrence) in failpoints {
        let directory = TempDir::new().expect("tempdir");
        let identity = identity(73);
        let item = inventory(106);
        let (reservation_id, commitment) = {
            let book = open_book(&directory, identity);
            let reservation = reserve_one(&book, identity, item, owner(1), 1);
            let committed = book
                .commit_before_sign(
                    ReservationAccess::new(reservation.id(), reservation.owner()),
                    vec![1, 2, 3],
                    transaction_fee(identity, 200),
                    &UnixMillis::new(200),
                )
                .expect("commit");
            let commitment = committed.signing_job().expect("signing job").commitment();
            let guard = mutation_failpoints::arm(name, occurrence);
            assert!(matches!(
                book.record_signed(
                    reservation.id(),
                    commitment,
                    signed_pset(4),
                    &UnixMillis::new(300),
                ),
                Err(ProviderError::InjectedMutationFailure(actual)) if actual == name
            ));
            drop(guard);
            (reservation.id(), commitment)
        };
        let reopened = open_book(&directory, identity);
        assert!(matches!(
            reopened.recovery_actions().expect("recovery").as_slice(),
            [RecoveryAction::SignCommittedExact(job)]
                if job.reservation_id() == reservation_id
                    && job.commitment() == commitment
                    && job.pre_sign_payload() == [1, 2, 3]
        ));
        assert!(matches!(
            reopened.pending_signing_jobs(usize::MAX).expect("pending").as_slice(),
            [job]
                if job.reservation_id() == reservation_id
                    && job.commitment() == commitment
                    && job.pre_sign_payload() == [1, 2, 3]
        ));
        assert_eq!(reopened.audit_log().expect("audit").len(), 3);
        assert!(
            reopened
                .record_signed(
                    reservation_id,
                    commitment,
                    signed_pset(4),
                    &UnixMillis::new(300),
                )
                .expect("retry")
                .recorded()
        );
    }
}

#[test]
fn signed_artifact_queues_one_exact_bounded_relay_job() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(90);
    let book = open_book(&directory, identity);
    let reservation = reserve_one(&book, identity, inventory(150), owner(1), 1);
    let committed = book
        .commit_before_sign(
            ReservationAccess::new(reservation.id(), reservation.owner()),
            vec![1, 2, 3],
            transaction_fee(identity, 200),
            &UnixMillis::new(200),
        )
        .expect("commit");
    let commitment = committed.signing_job().expect("job").commitment();
    let artifact_bytes = signed_pset(151);
    let signed = book
        .record_signed(
            reservation.id(),
            commitment,
            artifact_bytes.clone(),
            &UnixMillis::new(300),
        )
        .expect("signed")
        .artifact()
        .clone();
    assert!(
        book.due_relay_jobs(UnixMillis::new(299), usize::MAX)
            .expect("not due")
            .is_empty()
    );
    let jobs = book
        .due_relay_jobs(UnixMillis::new(300), usize::MAX)
        .expect("due");
    let [job] = jobs.as_slice() else {
        panic!("expected one relay job");
    };
    let transaction = deserialize::<PartiallySignedTransaction>(&artifact_bytes)
        .expect("pset")
        .extract_tx()
        .expect("transaction");
    assert_eq!(job.reservation_id(), reservation.id());
    assert_eq!(job.commitment(), commitment);
    assert_eq!(job.artifact(), signed.digest());
    assert_eq!(job.txid(), transaction.txid());
    assert_eq!(job.wtxid(), transaction.wtxid());
    assert_eq!(job.revision(), 0);
    assert_eq!(job.due_at(), UnixMillis::new(300));
    assert_eq!(job.observation(), RelayObservation::Unobserved);
    assert_eq!(job.attempt_count(), 0);
    assert_eq!(job.reorg_count(), 0);
    let record = book
        .relay_record(reservation.id())
        .expect("relay state")
        .expect("relay record");
    assert_eq!(record.txid(), transaction.txid());
    assert_eq!(record.wtxid(), transaction.wtxid());
    assert_eq!(record.next_attempt_at(), Some(UnixMillis::new(300)));

    let replay = book
        .record_signed(
            reservation.id(),
            commitment,
            artifact_bytes,
            &UnixMillis::new(301),
        )
        .expect("exact signed replay");
    assert!(!replay.recorded());
    assert_eq!(replay.artifact(), &signed);
}

#[test]
fn relay_attempt_is_leased_before_bytes_and_stale_workers_are_rejected() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(91);
    let item = inventory(152);
    let book = open_book(&directory, identity);
    let reservation = reserve_one(&book, identity, item, owner(1), 1);
    let commitment = book
        .commit_before_sign(
            ReservationAccess::new(reservation.id(), reservation.owner()),
            vec![1],
            transaction_fee(identity, 200),
            &UnixMillis::new(200),
        )
        .expect("commit")
        .signing_job()
        .expect("job")
        .commitment();
    let artifact_bytes = signed_pset(153);
    book.record_signed(
        reservation.id(),
        commitment,
        artifact_bytes,
        &UnixMillis::new(300),
    )
    .expect("signed");
    let job = book
        .due_relay_jobs(UnixMillis::new(300), 1)
        .expect("due")
        .pop()
        .expect("job");
    let attempt = book
        .begin_relay_attempt(&job, UnixMillis::new(400), &UnixMillis::new(301))
        .expect("lease");
    assert_eq!(attempt.revision(), 1);
    assert_eq!(attempt.attempt_count(), 1);
    assert_eq!(attempt.retry_at(), UnixMillis::new(400));
    assert!(!attempt.transaction_bytes().is_empty());
    assert!(
        book.due_relay_jobs(UnixMillis::new(399), 1)
            .expect("leased")
            .is_empty()
    );
    assert!(matches!(
        book.begin_relay_attempt(&job, UnixMillis::new(500), &UnixMillis::new(302)),
        Err(ProviderError::RelayRevisionMismatch {
            expected: 0,
            actual: 1,
            ..
        })
    ));

    let record = book
        .record_relay_outcome(
            &attempt,
            RelayObservation::BroadcastAccepted,
            None,
            Some(UnixMillis::new(350)),
            &UnixMillis::new(302),
        )
        .expect("record accepted broadcast");
    assert_eq!(record.revision(), 2);
    assert_eq!(record.attempt_count(), 1);
    assert_eq!(record.observation(), RelayObservation::BroadcastAccepted);
    assert_eq!(record.next_attempt_at(), Some(UnixMillis::new(350)));
    assert!(matches!(
        book.record_relay_outcome(
            &attempt,
            RelayObservation::Mempool,
            None,
            Some(UnixMillis::new(360)),
            &UnixMillis::new(303),
        ),
        Err(ProviderError::RelayRevisionMismatch {
            expected: 1,
            actual: 2,
            ..
        })
    ));
    assert!(matches!(
        book.inventory(item.outpoint()).expect("allocation").unwrap().state(),
        InventoryState::Committed { reservation_id, .. } if reservation_id == reservation.id()
    ));

    let next_job = book
        .due_relay_jobs(UnixMillis::new(350), 1)
        .expect("next due")
        .pop()
        .expect("next job");
    book.begin_relay_attempt(&next_job, UnixMillis::new(500), &UnixMillis::new(350))
        .expect("next lease");
    let write = book.begin_immediate_write().expect("write");
    let mut relay: StoredRelayRecord =
        read_record_from_write(&write, RELAY_RECORDS, &reservation.id().to_bytes())
            .expect("read relay")
            .expect("relay record");
    assert_eq!(relay.revision, 3);
    relay.next_attempt_at = None;
    write_record(&write, RELAY_RECORDS, &reservation.id().to_bytes(), &relay)
        .expect("corrupt relay");
    book.commit_write(write).expect("commit corruption fixture");
    assert!(matches!(
        book.relay_record(reservation.id()),
        Err(ProviderError::CorruptState(message))
            if message.contains("counters, timestamps, or initial state")
    ));
}

#[test]
fn relay_reconciliation_tracks_failures_reorgs_and_exact_conflicts() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(92);
    let book = open_book(&directory, identity);
    let reservation = reserve_one(&book, identity, inventory(154), owner(1), 1);
    let commitment = book
        .commit_before_sign(
            ReservationAccess::new(reservation.id(), reservation.owner()),
            vec![1],
            transaction_fee(identity, 200),
            &UnixMillis::new(200),
        )
        .expect("commit")
        .signing_job()
        .expect("job")
        .commitment();
    book.record_signed(
        reservation.id(),
        commitment,
        signed_pset(155),
        &UnixMillis::new(300),
    )
    .expect("signed");

    let first = book
        .due_relay_jobs(UnixMillis::new(300), 1)
        .expect("due")
        .pop()
        .expect("job");
    let first = book
        .begin_relay_attempt(&first, UnixMillis::new(400), &UnixMillis::new(301))
        .expect("first attempt");
    assert!(matches!(
        book.record_relay_outcome(
            &first,
            RelayObservation::Unobserved,
            None,
            Some(UnixMillis::new(320)),
            &UnixMillis::new(302),
        ),
        Err(ProviderError::InvalidRelayObservation(_))
    ));
    assert!(matches!(
        book.record_relay_outcome(
            &first,
            RelayObservation::Unobserved,
            Some(RelayFailureClass::PolicyRejected),
            Some(UnixMillis::new(320)),
            &UnixMillis::new(302),
        ),
        Err(ProviderError::InvalidRelayObservation(_))
    ));
    let first_record = book
        .record_relay_outcome(
            &first,
            RelayObservation::Unobserved,
            Some(RelayFailureClass::BackendUnavailable),
            Some(UnixMillis::new(320)),
            &UnixMillis::new(302),
        )
        .expect("failure observation");
    assert_eq!(
        first_record.last_failure(),
        Some(RelayFailureClass::BackendUnavailable)
    );
    assert_eq!(first_record.last_failure_at(), Some(UnixMillis::new(302)));
    assert_eq!(first_record.last_observed_at(), None);

    let second = book
        .due_relay_jobs(UnixMillis::new(320), 1)
        .expect("due")
        .pop()
        .expect("job");
    let second = book
        .begin_relay_attempt(&second, UnixMillis::new(420), &UnixMillis::new(320))
        .expect("second attempt");
    let first_block = BlockHash::from_byte_array([1; 32]);
    let confirmed = book
        .record_relay_outcome(
            &second,
            RelayObservation::Confirmed {
                block_hash: first_block,
                block_height: 10,
            },
            None,
            Some(UnixMillis::new(340)),
            &UnixMillis::new(321),
        )
        .expect("confirmed");
    assert_eq!(confirmed.reorg_count(), 0);
    assert_eq!(confirmed.last_failure(), None);
    assert_eq!(confirmed.last_failure_at(), None);

    let third = book
        .due_relay_jobs(UnixMillis::new(340), 1)
        .expect("due")
        .pop()
        .expect("job");
    let third = book
        .begin_relay_attempt(&third, UnixMillis::new(440), &UnixMillis::new(340))
        .expect("third attempt");
    let moved = book
        .record_relay_outcome(
            &third,
            RelayObservation::Confirmed {
                block_hash: BlockHash::from_byte_array([2; 32]),
                block_height: 11,
            },
            None,
            Some(UnixMillis::new(360)),
            &UnixMillis::new(341),
        )
        .expect("different canonical block");
    assert_eq!(moved.reorg_count(), 1);

    let fourth = book
        .due_relay_jobs(UnixMillis::new(360), 1)
        .expect("due")
        .pop()
        .expect("job");
    let fourth = book
        .begin_relay_attempt(&fourth, UnixMillis::new(460), &UnixMillis::new(360))
        .expect("fourth attempt");
    assert!(matches!(
        book.record_relay_outcome(
            &fourth,
            RelayObservation::Unobserved,
            Some(RelayFailureClass::BackendUnavailable),
            Some(UnixMillis::new(380)),
            &UnixMillis::new(361),
        ),
        Err(ProviderError::InvalidRelayObservation(_))
    ));
    assert!(matches!(
        book.record_relay_outcome(
            &fourth,
            RelayObservation::Conflicted {
                spent_input: outpoint(99, 0),
                conflicting_txid: None,
            },
            None,
            Some(UnixMillis::new(380)),
            &UnixMillis::new(361),
        ),
        Err(ProviderError::InvalidRelayObservation(_))
    ));
    let conflicted = book
        .record_relay_outcome(
            &fourth,
            RelayObservation::Conflicted {
                spent_input: outpoint(155, 0),
                // The same non-witness txid is valid conflict metadata when
                // Core observed a different witness serialization.
                conflicting_txid: Some(fourth.txid()),
            },
            None,
            Some(UnixMillis::new(380)),
            &UnixMillis::new(361),
        )
        .expect("exact conflict");
    assert_eq!(conflicted.reorg_count(), 2);
    assert_eq!(conflicted.attempt_count(), 4);
}

#[test]
fn startup_integrity_rejects_reorg_without_a_completed_outcome() {
    let directory = TempDir::new().expect("tempdir");
    let path = directory.path().join("provider.redb");
    let identity = identity(98);
    let reservation_id = {
        let book = open_book(&directory, identity);
        let reservation = reserve_one(&book, identity, inventory(198), owner(1), 1);
        let commitment = book
            .commit_before_sign(
                ReservationAccess::new(reservation.id(), reservation.owner()),
                vec![1],
                transaction_fee(identity, 200),
                &UnixMillis::new(200),
            )
            .expect("commit")
            .signing_job()
            .expect("job")
            .commitment();
        book.record_signed(
            reservation.id(),
            commitment,
            signed_pset(199),
            &UnixMillis::new(300),
        )
        .expect("signed");
        let job = book
            .due_relay_jobs(UnixMillis::new(300), 1)
            .expect("due")
            .pop()
            .expect("job");
        book.begin_relay_attempt(&job, UnixMillis::new(400), &UnixMillis::new(301))
            .expect("lease");

        let write = book.begin_immediate_write().expect("write");
        let mut relay: StoredRelayRecord =
            read_record_from_write(&write, RELAY_RECORDS, &reservation.id().to_bytes())
                .expect("read relay")
                .expect("relay record");
        assert_eq!(relay.revision, 1);
        assert_eq!(relay.attempt_count, 1);
        relay.reorg_count = 1;
        write_record(&write, RELAY_RECORDS, &reservation.id().to_bytes(), &relay)
            .expect("corrupt relay");
        book.commit_write(write).expect("commit corruption fixture");
        reservation.id()
    };

    let error = match ReservationBook::open_existing(&path, identity) {
        Ok(_) => panic!("reorg without a completed observation must fail closed"),
        Err(error) => error,
    };
    assert!(matches!(error, ProviderError::CorruptState(message)
        if message.contains(&format!("{reservation_id:?}"))
            && message.contains("counters, timestamps, or initial state")));
}

#[test]
fn relay_due_query_is_oldest_first_and_hard_capped_at_eight() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(93);
    let book = open_book(&directory, identity);
    let mut reservations = Vec::new();
    for marker in 1_u8..=10 {
        reservations.push(reserve_one(
            &book,
            identity,
            inventory(160_u8.wrapping_add(marker)),
            owner(1),
            marker,
        ));
    }
    let mut commitments = Vec::new();
    for (position, reservation) in reservations.iter().enumerate() {
        let position = u64::try_from(position).expect("small test position");
        commitments.push(
            book.commit_before_sign(
                ReservationAccess::new(reservation.id(), reservation.owner()),
                vec![1],
                transaction_fee(identity, 200),
                &UnixMillis::new(200 + position),
            )
            .expect("commit")
            .signing_job()
            .expect("job")
            .commitment(),
        );
    }
    for (position, (reservation, commitment)) in reservations.iter().zip(commitments).enumerate() {
        let position = u64::try_from(position).expect("small test position");
        book.record_signed(
            reservation.id(),
            commitment,
            signed_pset(180_u8.wrapping_add(u8::try_from(position).expect("position"))),
            &UnixMillis::new(300 + position),
        )
        .expect("signed");
    }
    let jobs = book
        .due_relay_jobs(UnixMillis::new(1_000), usize::MAX)
        .expect("jobs");
    assert_eq!(jobs.len(), MAX_RELAY_BATCH);
    assert_eq!(
        jobs.iter()
            .map(RelayJob::reservation_id)
            .collect::<Vec<_>>(),
        reservations[..MAX_RELAY_BATCH]
            .iter()
            .map(ReservationView::id)
            .collect::<Vec<_>>()
    );
}

#[test]
fn relay_mutation_failpoints_preserve_the_previous_exact_job() {
    for failpoint in [
        mutation_failpoints::RELAY_AFTER_DUE_REMOVE,
        mutation_failpoints::RELAY_AFTER_RECORD,
        mutation_failpoints::RELAY_AFTER_DUE_INSERT,
    ] {
        let directory = TempDir::new().expect("tempdir");
        let identity = identity(94);
        let (reservation_id, original_job) = {
            let book = open_book(&directory, identity);
            let reservation = reserve_one(&book, identity, inventory(191), owner(1), 1);
            let commitment = book
                .commit_before_sign(
                    ReservationAccess::new(reservation.id(), reservation.owner()),
                    vec![1],
                    transaction_fee(identity, 200),
                    &UnixMillis::new(200),
                )
                .expect("commit")
                .signing_job()
                .expect("job")
                .commitment();
            book.record_signed(
                reservation.id(),
                commitment,
                signed_pset(192),
                &UnixMillis::new(300),
            )
            .expect("signed");
            let job = book
                .due_relay_jobs(UnixMillis::new(300), 1)
                .expect("due")
                .pop()
                .expect("job");
            let guard = mutation_failpoints::arm(failpoint, 0);
            assert!(matches!(
                book.begin_relay_attempt(&job, UnixMillis::new(400), &UnixMillis::new(301)),
                Err(ProviderError::InjectedMutationFailure(actual)) if actual == failpoint
            ));
            drop(guard);
            (reservation.id(), job)
        };
        let reopened = open_book(&directory, identity);
        assert_eq!(
            reopened
                .due_relay_jobs(UnixMillis::new(300), 1)
                .expect("durable due job")
                .as_slice(),
            [original_job]
        );
        assert!(matches!(
            reopened
                .inventory(inventory(191).outpoint())
                .expect("allocation")
                .unwrap()
                .state(),
            InventoryState::Committed { reservation_id: actual, .. } if actual == reservation_id
        ));
    }
}

#[test]
fn relay_outcome_failpoints_preserve_the_leased_attempt_for_retry() {
    for failpoint in [
        mutation_failpoints::RELAY_AFTER_DUE_REMOVE,
        mutation_failpoints::RELAY_AFTER_RECORD,
        mutation_failpoints::RELAY_AFTER_DUE_INSERT,
    ] {
        let directory = TempDir::new().expect("tempdir");
        let identity = identity(95);
        let attempt = {
            let book = open_book(&directory, identity);
            let reservation = reserve_one(&book, identity, inventory(193), owner(1), 1);
            let commitment = book
                .commit_before_sign(
                    ReservationAccess::new(reservation.id(), reservation.owner()),
                    vec![1],
                    transaction_fee(identity, 200),
                    &UnixMillis::new(200),
                )
                .expect("commit")
                .signing_job()
                .expect("job")
                .commitment();
            book.record_signed(
                reservation.id(),
                commitment,
                signed_pset(194),
                &UnixMillis::new(300),
            )
            .expect("signed");
            let job = book
                .due_relay_jobs(UnixMillis::new(300), 1)
                .expect("due")
                .pop()
                .expect("job");
            let attempt = book
                .begin_relay_attempt(&job, UnixMillis::new(400), &UnixMillis::new(301))
                .expect("lease");
            let guard = mutation_failpoints::arm(failpoint, 0);
            assert!(matches!(
                book.record_relay_outcome(
                    &attempt,
                    RelayObservation::Mempool,
                    None,
                    Some(UnixMillis::new(350)),
                    &UnixMillis::new(302),
                ),
                Err(ProviderError::InjectedMutationFailure(actual)) if actual == failpoint
            ));
            drop(guard);
            attempt
        };
        let reopened = open_book(&directory, identity);
        let record = reopened
            .relay_record(attempt.reservation_id())
            .expect("relay state")
            .expect("relay record");
        assert_eq!(record.revision(), 1);
        assert_eq!(record.attempt_count(), 1);
        assert_eq!(record.observation(), RelayObservation::Unobserved);
        assert_eq!(record.next_attempt_at(), Some(UnixMillis::new(400)));
        assert!(
            reopened
                .due_relay_jobs(UnixMillis::new(399), 1)
                .expect("leased")
                .is_empty()
        );
        reopened
            .record_relay_outcome(
                &attempt,
                RelayObservation::Mempool,
                None,
                Some(UnixMillis::new(350)),
                &UnixMillis::new(302),
            )
            .expect("retry exact outcome");
    }
}

#[test]
fn signed_replay_fails_closed_when_its_relay_record_is_missing() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(96);
    let book = open_book(&directory, identity);
    let reservation = reserve_one(&book, identity, inventory(195), owner(1), 1);
    let commitment = book
        .commit_before_sign(
            ReservationAccess::new(reservation.id(), reservation.owner()),
            vec![1],
            transaction_fee(identity, 200),
            &UnixMillis::new(200),
        )
        .expect("commit")
        .signing_job()
        .expect("job")
        .commitment();
    let artifact = signed_pset(196);
    book.record_signed(
        reservation.id(),
        commitment,
        artifact.clone(),
        &UnixMillis::new(300),
    )
    .expect("signed");
    let write = book.begin_immediate_write().expect("write");
    assert!(
        write
            .open_table(RELAY_RECORDS)
            .expect("relay records")
            .remove(reservation.id().to_bytes().as_slice())
            .expect("remove")
            .is_some()
    );
    book.commit_write(write).expect("tamper for test");
    assert!(matches!(
        book.record_signed(
            reservation.id(),
            commitment,
            artifact,
            &UnixMillis::new(301),
        ),
        Err(ProviderError::CorruptState(detail)) if detail.contains("no relay record")
    ));
}

#[test]
fn opening_an_existing_store_requires_both_relay_tables() {
    for definition in [RELAY_RECORDS, RELAY_DUE] {
        let directory = TempDir::new().expect("tempdir");
        let identity = identity(97);
        let path = directory.path().join("provider.redb");
        let book = ReservationBook::create(&path, identity).expect("create");
        let write = book.begin_immediate_write().expect("write");
        assert!(write.delete_table(definition).expect("delete table"));
        book.commit_write(write).expect("commit test corruption");
        drop(book);
        assert!(matches!(
            ReservationBook::open_existing(&path, identity),
            Err(ProviderError::Table(_))
        ));
    }
}

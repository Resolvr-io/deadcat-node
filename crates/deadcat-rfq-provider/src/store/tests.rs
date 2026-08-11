use std::sync::{Arc, Barrier};
use std::thread;

use elements::hashes::Hash as _;
use elements::{AssetId, BlockHash, OutPoint, Txid};
use tempfile::TempDir;

use super::*;

fn asset(marker: u8) -> AssetId {
    AssetId::from_slice(&[marker; 32]).expect("asset")
}

fn outpoint(marker: u8, vout: u32) -> OutPoint {
    OutPoint::new(Txid::from_byte_array([marker; 32]), vout)
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
    InventoryItem::new(outpoint(marker, 0), asset(2), 10_000).expect("inventory")
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

    let signed = book
        .record_signed(
            reservation.id(),
            commitment,
            vec![5, 6, 7],
            &UnixMillis::new(203),
        )
        .expect("signed");
    assert!(signed.recorded());
    let retry = book
        .record_signed(
            reservation.id(),
            commitment,
            vec![5, 6, 7],
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
            vec![5, 6, 8],
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
                vec![4, 5, 6],
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
        vec![2],
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
        request_digest: [2; 32],
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
                    vec![4, 5, 6],
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
        assert_eq!(reopened.audit_log().expect("audit").len(), 3);
        assert!(
            reopened
                .record_signed(
                    reservation_id,
                    commitment,
                    vec![4, 5, 6],
                    &UnixMillis::new(300),
                )
                .expect("retry")
                .recorded()
        );
    }
}

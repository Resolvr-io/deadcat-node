use std::collections::VecDeque;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::hashes::Hash as _;
use elements::secp256k1_zkp::rand::thread_rng;
use elements::secp256k1_zkp::{Keypair, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use elements::{
    Address, AddressParams, AssetId, BlockHash, OutPoint, Script, TxOut, TxOutSecrets,
    TxOutWitness, Txid,
};
use tempfile::TempDir;
use thiserror::Error;

use super::*;
use crate::model::{
    FeePolicy, FeeSizeMetric, IdempotencyKey, OwnerId, ProviderId, QuoteCommitment,
    ReservationAccess, ReservationState, TransactionFee, WalletKeyLocator,
};
use crate::wallet::{InventorySnapshot, WalletBoundaryError};

#[derive(Clone)]
struct WalletFixture {
    internal_key: XOnlyPublicKey,
    blinding_public_key: PublicKey,
    script_pubkey: Script,
}

impl WalletFixture {
    fn new(spend_marker: u8, blind_marker: u8) -> Self {
        let secp = Secp256k1::new();
        let spend_secret = SecretKey::from_slice(&[spend_marker; 32]).expect("spend key");
        let spend_keypair = Keypair::from_secret_key(&secp, &spend_secret);
        let (internal_key, _) = spend_keypair.x_only_public_key();
        let blinding_secret = SecretKey::from_slice(&[blind_marker; 32]).expect("blinding key");
        let blinding_public_key = PublicKey::from_secret_key(&secp, &blinding_secret);
        let script_pubkey = Address::p2tr(
            &secp,
            internal_key,
            None,
            Some(blinding_public_key),
            &AddressParams::ELEMENTS,
        )
        .script_pubkey();
        Self {
            internal_key,
            blinding_public_key,
            script_pubkey,
        }
    }

    fn owned_output(&self, marker: u8) -> WalletOwnedOutput {
        let asset = asset(7);
        let amount = 10_000 + u64::from(marker);
        let explicit = TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(amount),
            nonce: Nonce::Null,
            script_pubkey: self.script_pubkey.clone(),
            witness: TxOutWitness::default(),
        };
        let (txout, asset_bf, value_bf, _) = explicit
            .to_non_last_confidential(
                &mut thread_rng(),
                &Secp256k1::new(),
                self.blinding_public_key,
                &[TxOutSecrets::new(
                    asset,
                    AssetBlindingFactor::zero(),
                    amount,
                    ValueBlindingFactor::zero(),
                )],
            )
            .expect("confidential output");
        WalletOwnedOutput::new(
            outpoint(marker),
            txout,
            TxOutSecrets::new(asset, asset_bf, amount, value_bf),
            self.internal_key,
            WalletKeyLocator::new([marker; 32]).expect("locator"),
        )
        .expect("owned output")
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
enum MockSourceError {
    #[error("mock wallet unavailable")]
    Unavailable,
}

struct MockSource {
    responses: Mutex<VecDeque<Result<InventorySnapshot, MockSourceError>>>,
}

struct SequenceClock {
    observations: Mutex<VecDeque<UnixMillis>>,
}

impl SequenceClock {
    fn new(observations: impl IntoIterator<Item = UnixMillis>) -> Self {
        Self {
            observations: Mutex::new(observations.into_iter().collect()),
        }
    }
}

impl Clock for SequenceClock {
    fn now(&self) -> UnixMillis {
        self.observations
            .lock()
            .expect("sequence clock lock")
            .pop_front()
            .expect("sequence clock exhausted")
    }
}

impl MockSource {
    fn new(
        responses: impl IntoIterator<Item = Result<InventorySnapshot, MockSourceError>>,
    ) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
        }
    }
}

impl InventorySource for MockSource {
    type Error = MockSourceError;

    fn inventory_snapshot(&self) -> Result<InventorySnapshot, Self::Error> {
        self.responses
            .lock()
            .expect("mock source lock")
            .pop_front()
            .unwrap_or(Err(MockSourceError::Unavailable))
    }
}

enum ControlledResponse {
    Immediate(InventorySnapshot),
    Blocked(InventorySnapshot),
}

struct ControlledSource {
    responses: Mutex<VecDeque<ControlledResponse>>,
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}

impl InventorySource for ControlledSource {
    type Error = MockSourceError;

    fn inventory_snapshot(&self) -> Result<InventorySnapshot, Self::Error> {
        match self
            .responses
            .lock()
            .expect("controlled source lock")
            .pop_front()
            .ok_or(MockSourceError::Unavailable)?
        {
            ControlledResponse::Immediate(snapshot) => Ok(snapshot),
            ControlledResponse::Blocked(snapshot) => {
                self.entered.wait();
                self.release.wait();
                Ok(snapshot)
            }
        }
    }
}

fn asset(marker: u8) -> AssetId {
    AssetId::from_byte_array([marker; 32])
}

fn outpoint(marker: u8) -> OutPoint {
    OutPoint::new(Txid::from_byte_array([marker; 32]), u32::from(marker))
}

fn identity(marker: u8) -> ProviderIdentity {
    ProviderIdentity::new(
        ProviderId::new([marker; 32]),
        BlockHash::from_byte_array([marker.wrapping_add(1); 32]),
        asset(1),
    )
}

fn snapshot(
    identity: ProviderIdentity,
    anchor_marker: u8,
    outputs: Vec<WalletOwnedOutput>,
) -> Result<InventorySnapshot, WalletBoundaryError> {
    InventorySnapshot::new(
        identity,
        WalletScanAnchor::new(
            BlockHash::from_byte_array([anchor_marker; 32]),
            u32::from(anchor_marker),
        ),
        outputs,
    )
}

fn policy(max_age: u64, max_outputs: usize) -> InventoryFreshnessPolicy {
    InventoryFreshnessPolicy::new(max_age, max_outputs).expect("freshness policy")
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

fn plan(
    identity: ProviderIdentity,
    owner_marker: u8,
    request_marker: u8,
    outpoints: Vec<OutPoint>,
) -> ReservationPlan {
    ReservationPlan::new(
        OwnerId::new([owner_marker; 32]),
        IdempotencyKey::new([request_marker; 32]),
        QuoteCommitment::new([request_marker.wrapping_add(1); 32]),
        outpoints,
        UnixMillis::new(1_000),
        fee_policy(identity),
    )
    .expect("reservation plan")
}

fn coordinator(
    directory: &TempDir,
    identity: ProviderIdentity,
    source: MockSource,
    policy: InventoryFreshnessPolicy,
) -> InventoryCoordinator<MockSource> {
    let book = ReservationBook::open(directory.path().join("provider.redb"), identity)
        .expect("reservation book");
    InventoryCoordinator::new(book, source, policy)
}

#[test]
fn quoteable_inventory_requires_a_fresh_scan_and_durable_availability() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(10);
    let wallet = WalletFixture::new(2, 3);
    let first = wallet.owned_output(11);
    let second = wallet.owned_output(12);
    let source = MockSource::new([Ok(snapshot(
        identity,
        20,
        vec![first.clone(), second.clone()],
    )
    .expect("snapshot"))]);
    let coordinator = coordinator(&directory, identity, source, policy(100, 4));

    assert!(matches!(
        coordinator.eligible(&UnixMillis::new(99)),
        Err(InventoryCoordinatorError::NoPublishedSnapshot)
    ));
    let eligible = coordinator.refresh(&UnixMillis::new(100)).expect("refresh");
    assert_eq!(eligible.outputs(), &[first.clone(), second.clone()]);

    let reservation = coordinator
        .reserve(
            &eligible,
            &plan(identity, 1, 1, vec![first.outpoint()]),
            &UnixMillis::new(101),
        )
        .expect("reserve")
        .reservation()
        .clone();
    let while_reserved = coordinator
        .eligible(&UnixMillis::new(102))
        .expect("eligible after reserve");
    assert_eq!(while_reserved.outputs(), std::slice::from_ref(&second));
    let current = coordinator
        .current(&UnixMillis::new(102))
        .expect("current complete inventory");
    assert_eq!(current.token(), while_reserved.token());
    assert_eq!(current.outputs(), &[first.clone(), second.clone()]);
    assert_eq!(
        current
            .output(first.outpoint())
            .expect("reserved output in current snapshot")
            .confidential_input_opening(),
        first.confidential_input_opening()
    );

    coordinator
        .reservation_book()
        .cancel(
            ReservationAccess::new(reservation.id(), reservation.owner()),
            &UnixMillis::new(103),
        )
        .expect("cancel");
    assert!(matches!(
        coordinator.reserve(
            &while_reserved,
            &plan(identity, 2, 2, vec![first.outpoint()]),
            &UnixMillis::new(104),
        ),
        Err(InventoryCoordinatorError::OutpointNotInEligibleView(actual))
            if actual == first.outpoint()
    ));
    let after_release = coordinator
        .eligible(&UnixMillis::new(104))
        .expect("eligible after release");
    assert_eq!(after_release.outputs(), &[first.clone(), second]);
    assert!(
        coordinator
            .reserve(
                &after_release,
                &plan(identity, 2, 2, vec![first.outpoint()]),
                &UnixMillis::new(104),
            )
            .expect("reserve from refreshed eligible view")
            .created()
    );
}

#[test]
fn latest_complete_snapshot_replaces_membership_without_deleting_history() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(20);
    let wallet = WalletFixture::new(4, 5);
    let first = wallet.owned_output(21);
    let second = wallet.owned_output(22);
    let source = MockSource::new([
        Ok(snapshot(identity, 30, vec![first.clone()]).expect("first snapshot")),
        Ok(snapshot(identity, 31, vec![second.clone()]).expect("second snapshot")),
    ]);
    let coordinator = coordinator(&directory, identity, source, policy(100, 4));
    let old = coordinator
        .refresh(&UnixMillis::new(100))
        .expect("first refresh");
    let current = coordinator
        .refresh(&UnixMillis::new(101))
        .expect("second refresh");
    assert_eq!(current.outputs(), &[second]);
    assert_eq!(
        coordinator
            .reservation_book()
            .inventory(first.outpoint())
            .expect("durable history")
            .expect("first inventory")
            .state(),
        InventoryState::Available
    );

    assert!(matches!(
        coordinator.reserve(
            &old,
            &plan(identity, 1, 1, vec![first.outpoint()]),
            &UnixMillis::new(102),
        ),
        Err(InventoryCoordinatorError::SnapshotSuperseded { .. })
    ));
    assert!(matches!(
        coordinator.reserve(
            &current,
            &plan(identity, 2, 2, vec![first.outpoint()]),
            &UnixMillis::new(102),
        ),
        Err(InventoryCoordinatorError::OutpointNotInFreshSnapshot(actual))
            if actual == first.outpoint()
    ));
}

#[test]
fn exact_reservation_retry_survives_snapshot_replacement() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(30);
    let wallet = WalletFixture::new(6, 7);
    let first = wallet.owned_output(31);
    let second = wallet.owned_output(32);
    let source = MockSource::new([
        Ok(snapshot(identity, 40, vec![first.clone()]).expect("first snapshot")),
        Ok(snapshot(identity, 41, vec![second]).expect("second snapshot")),
    ]);
    let coordinator = coordinator(&directory, identity, source, policy(100, 4));
    let old = coordinator
        .refresh(&UnixMillis::new(100))
        .expect("first refresh");
    let request = plan(identity, 1, 1, vec![first.outpoint()]);
    let created = coordinator
        .reserve(&old, &request, &UnixMillis::new(101))
        .expect("created reservation");
    assert!(created.created());
    coordinator
        .refresh(&UnixMillis::new(102))
        .expect("replacement refresh");

    let retry = coordinator
        .reserve(&old, &request, &UnixMillis::new(103))
        .expect("idempotent retry");
    assert!(!retry.created());
    assert_eq!(retry.reservation(), created.reservation());
}

#[test]
fn refresh_replacing_membership_cannot_race_an_old_snapshot_reservation() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(35);
    let wallet = WalletFixture::new(18, 19);
    let first = wallet.owned_output(36);
    let second = wallet.owned_output(37);
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let source = ControlledSource {
        responses: Mutex::new(VecDeque::from([
            ControlledResponse::Immediate(
                snapshot(identity, 42, vec![first.clone()]).expect("first snapshot"),
            ),
            ControlledResponse::Blocked(
                snapshot(identity, 43, vec![second]).expect("replacement snapshot"),
            ),
        ])),
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    };
    let book = ReservationBook::open(directory.path().join("provider.redb"), identity)
        .expect("reservation book");
    let coordinator = Arc::new(InventoryCoordinator::new(book, source, policy(100, 4)));
    let old = coordinator
        .refresh(&UnixMillis::new(100))
        .expect("first refresh");

    let refresh_coordinator = Arc::clone(&coordinator);
    let refresh = thread::spawn(move || refresh_coordinator.refresh(&UnixMillis::new(101)));
    entered.wait();

    let reserve_coordinator = Arc::clone(&coordinator);
    let requested_outpoint = first.outpoint();
    let reserve = thread::spawn(move || {
        reserve_coordinator.reserve(
            &old,
            &plan(identity, 1, 1, vec![requested_outpoint]),
            &UnixMillis::new(102),
        )
    });
    release.wait();
    refresh
        .join()
        .expect("refresh thread")
        .expect("replacement refresh");
    assert!(matches!(
        reserve.join().expect("reserve thread"),
        Err(InventoryCoordinatorError::SnapshotSuperseded { .. })
    ));
    assert_eq!(
        coordinator
            .reservation_book()
            .inventory(first.outpoint())
            .expect("inventory")
            .expect("first output")
            .state(),
        InventoryState::Available
    );
}

#[test]
fn freshness_boundary_is_exclusive_and_clock_rollback_fails_closed() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(40);
    let wallet = WalletFixture::new(8, 9);
    let output = wallet.owned_output(41);
    let source = MockSource::new([Ok(snapshot(identity, 50, vec![output]).expect("snapshot"))]);
    let coordinator = coordinator(&directory, identity, source, policy(10, 4));
    coordinator.refresh(&UnixMillis::new(100)).expect("refresh");
    coordinator
        .eligible(&UnixMillis::new(109))
        .expect("last fresh millisecond");
    assert!(matches!(
        coordinator.eligible(&UnixMillis::new(110)),
        Err(InventoryCoordinatorError::SnapshotStale {
            observed_at,
            now,
            maximum_age_millis: 10,
        }) if observed_at == UnixMillis::new(100) && now == UnixMillis::new(110)
    ));
    assert!(matches!(
        coordinator.eligible(&UnixMillis::new(99)),
        Err(InventoryCoordinatorError::Provider(
            ProviderError::ClockRegression { previous, now }
        )) if previous == UnixMillis::new(100) && now == UnixMillis::new(99)
    ));
}

#[test]
fn reservation_rechecks_snapshot_freshness_after_the_durable_writer_lock() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(45);
    let wallet = WalletFixture::new(20, 21);
    let output = wallet.owned_output(46);
    let source = MockSource::new([Ok(
        snapshot(identity, 55, vec![output.clone()]).expect("snapshot")
    )]);
    let coordinator = coordinator(&directory, identity, source, policy(10, 4));
    let eligible = coordinator.refresh(&UnixMillis::new(100)).expect("refresh");
    let clock = SequenceClock::new([UnixMillis::new(109), UnixMillis::new(110)]);

    assert!(matches!(
        coordinator.reserve(
            &eligible,
            &plan(identity, 1, 1, vec![output.outpoint()]),
            &clock,
        ),
        Err(InventoryCoordinatorError::Provider(
            ProviderError::InventorySnapshotStale {
                observed_at,
                now,
                maximum_age_millis: 10,
            }
        )) if observed_at == UnixMillis::new(100) && now == UnixMillis::new(110)
    ));
    assert_eq!(
        coordinator
            .reservation_book()
            .inventory(output.outpoint())
            .expect("inventory")
            .expect("known output")
            .state(),
        InventoryState::Available
    );
}

#[test]
fn source_failure_retains_bounded_cache_but_rejected_new_scan_invalidates_it() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(50);
    let wallet = WalletFixture::new(10, 11);
    let first = wallet.owned_output(51);
    let new_item = wallet.owned_output(52);
    let conflicting_wallet = WalletFixture::new(12, 13);
    let conflict = conflicting_wallet.owned_output(51);
    let source = MockSource::new([
        Ok(snapshot(identity, 60, vec![first.clone()]).expect("first snapshot")),
        Err(MockSourceError::Unavailable),
        Ok(snapshot(identity, 61, vec![new_item.clone(), conflict]).expect("conflicting snapshot")),
    ]);
    let coordinator = coordinator(&directory, identity, source, policy(10, 4));
    let first_view = coordinator
        .refresh(&UnixMillis::new(100))
        .expect("first refresh");

    assert!(matches!(
        coordinator.refresh(&UnixMillis::new(105)),
        Err(InventoryCoordinatorError::Source(
            MockSourceError::Unavailable
        ))
    ));
    assert_eq!(
        coordinator
            .eligible(&UnixMillis::new(109))
            .expect("old snapshot remains fresh")
            .token(),
        first_view.token()
    );

    assert!(matches!(
        coordinator.refresh(&UnixMillis::new(109)),
        Err(InventoryCoordinatorError::Provider(
            ProviderError::InventoryMetadataConflict { outpoint: actual }
        )) if actual == first.outpoint()
    ));
    assert!(
        coordinator
            .reservation_book()
            .inventory(new_item.outpoint())
            .expect("new item query")
            .is_none(),
        "metadata conflict must roll back every new item in the scan"
    );
    assert!(matches!(
        coordinator.eligible(&UnixMillis::new(109)),
        Err(InventoryCoordinatorError::NoPublishedSnapshot)
    ));
    assert!(matches!(
        coordinator.current(&UnixMillis::new(109)),
        Err(InventoryCoordinatorError::NoPublishedSnapshot)
    ));
    assert!(matches!(
        coordinator.reserve(
            &first_view,
            &plan(identity, 1, 1, vec![first.outpoint()]),
            &UnixMillis::new(109),
        ),
        Err(InventoryCoordinatorError::NoPublishedSnapshot)
    ));
}

#[test]
fn wrong_identity_and_oversized_snapshot_never_publish() {
    let directory = TempDir::new().expect("tempdir");
    let expected = identity(60);
    let wallet = WalletFixture::new(14, 15);
    let first = wallet.owned_output(61);
    let second = wallet.owned_output(62);
    let source = MockSource::new([
        Ok(snapshot(identity(61), 70, vec![first.clone()]).expect("wrong identity snapshot")),
        Ok(snapshot(expected, 71, vec![first.clone(), second.clone()])
            .expect("oversized snapshot")),
    ]);
    let coordinator = coordinator(&directory, expected, source, policy(100, 1));

    assert!(matches!(
        coordinator.refresh(&UnixMillis::new(100)),
        Err(InventoryCoordinatorError::IdentityMismatch { .. })
    ));
    assert!(
        coordinator
            .reservation_book()
            .inventory(first.outpoint())
            .expect("wrong identity query")
            .is_none()
    );
    assert!(matches!(
        coordinator.refresh(&UnixMillis::new(101)),
        Err(InventoryCoordinatorError::SnapshotTooLarge {
            maximum: 1,
            actual: 2,
        })
    ));
    for output in [&first, &second] {
        assert!(
            coordinator
                .reservation_book()
                .inventory(output.outpoint())
                .expect("oversized query")
                .is_none()
        );
    }
    assert!(matches!(
        coordinator.eligible(&UnixMillis::new(101)),
        Err(InventoryCoordinatorError::NoPublishedSnapshot)
    ));
}

#[test]
fn restart_requires_rediscovery_and_committed_inventory_never_reopens() {
    let directory = TempDir::new().expect("tempdir");
    let identity = identity(70);
    let wallet = WalletFixture::new(16, 17);
    let output = wallet.owned_output(71);
    let reservation_id;
    {
        let source = MockSource::new([Ok(
            snapshot(identity, 80, vec![output.clone()]).expect("snapshot")
        )]);
        let coordinator = coordinator(&directory, identity, source, policy(100, 4));
        let eligible = coordinator.refresh(&UnixMillis::new(100)).expect("refresh");
        let reservation = coordinator
            .reserve(
                &eligible,
                &plan(identity, 1, 1, vec![output.outpoint()]),
                &UnixMillis::new(101),
            )
            .expect("reserve")
            .reservation()
            .clone();
        reservation_id = reservation.id();
        let fee = TransactionFee::new(identity.policy_asset(), 200, 800, 200, 100)
            .expect("transaction fee");
        coordinator
            .reservation_book()
            .commit_before_sign(
                ReservationAccess::new(reservation.id(), reservation.owner()),
                vec![1, 2, 3],
                fee,
                &UnixMillis::new(102),
            )
            .expect("commit");
    }

    let source = MockSource::new([Ok(
        snapshot(identity, 81, vec![output.clone()]).expect("rediscovery snapshot")
    )]);
    let reopened = coordinator(&directory, identity, source, policy(100, 4));
    assert!(matches!(
        reopened.eligible(&UnixMillis::new(103)),
        Err(InventoryCoordinatorError::NoPublishedSnapshot)
    ));
    assert!(matches!(
        reopened
            .reservation_book()
            .reservation(reservation_id)
            .expect("reservation")
            .expect("persisted reservation")
            .state(),
        ReservationState::Committed { .. }
    ));
    let eligible = reopened
        .refresh(&UnixMillis::new(104))
        .expect("rediscovery");
    assert!(
        eligible.outputs().is_empty(),
        "fresh rediscovery must not make committed inventory quoteable"
    );
    let current = reopened
        .current(&UnixMillis::new(104))
        .expect("fresh current inventory");
    assert_eq!(current.token(), eligible.token());
    assert_eq!(
        current
            .output(output.outpoint())
            .expect("committed output remains available for recovery")
            .confidential_input_opening(),
        output.confidential_input_opening()
    );
}

#[test]
fn policy_rejects_zero_limits() {
    assert_eq!(
        InventoryFreshnessPolicy::new(0, 1),
        Err(InventoryPolicyError::ZeroMaximumSnapshotAge)
    );
    assert_eq!(
        InventoryFreshnessPolicy::new(1, 0),
        Err(InventoryPolicyError::ZeroMaximumInventoryOutputs)
    );
}

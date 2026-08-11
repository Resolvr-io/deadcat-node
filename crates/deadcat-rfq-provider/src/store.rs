use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use elements::hashes::Hash as _;
use elements::{AssetId, BlockHash, OutPoint};
use redb::{
    Database, Durability, ReadableDatabase as _, ReadableTable as _, TableDefinition,
    WriteTransaction,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::model::{
    AuditEntry, AuditEvent, Clock, FeePolicy, FeePolicyViolation, FeeSizeMetric, IdempotencyKey,
    InventoryItem, InventoryState, InventoryView, MAX_RESERVATION_INPUTS, MAX_SETTLEMENT_BYTES,
    OwnerId, ProviderId, ProviderIdentity, QuoteCommitment, RecoveryAction, ReleaseReason,
    ReservationAccess, ReservationId, ReservationPlan, ReservationState, ReservationView,
    SignedArtifact, SignedArtifactDigest, SigningCommitment, SigningJob, TransactionFee,
    UnixMillis,
};

pub const SCHEMA_VERSION: u32 = 1;
/// Maximum number of unrelated expirations one explicit sweep may mutate in a
/// single immediate-durability transaction.
pub const MAX_EXPIRATION_BATCH: usize = 256;
const RECORD_VERSION: u8 = 1;

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const INVENTORY: TableDefinition<&[u8], &[u8]> = TableDefinition::new("inventory");
const ALLOCATIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("allocations");
const RESERVATIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("reservations");
const REQUEST_KEYS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("request_keys");
const EXPIRATIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("expirations");
const AUDIT: TableDefinition<u64, &[u8]> = TableDefinition::new("audit");

const SCHEMA_VERSION_KEY: &str = "schema_version";
const PROVIDER_IDENTITY_KEY: &str = "provider_identity";
const LAST_OBSERVED_TIME_KEY: &str = "last_observed_unix_millis";
const AUDIT_SEQUENCE_KEY: &str = "audit_sequence";

const RESERVATION_ID_DOMAIN: &[u8] = b"deadcat/rfq/reservation-id/v1";
const REQUEST_DOMAIN: &[u8] = b"deadcat/rfq/reservation-request/v1";
const SIGNING_DOMAIN: &[u8] = b"deadcat/rfq/signing-transcript/v1";
const SIGNED_ARTIFACT_DOMAIN: &[u8] = b"deadcat/rfq/signed-artifact/v1";

/// Graceful mutation failures used to prove that every logical transition is
/// one redb commit. These are not a simulation of process death, torn writes,
/// or redb's own crash-recovery machinery.
#[cfg(test)]
mod mutation_failpoints {
    use std::cell::RefCell;

    use super::ProviderError;

    pub(super) const RESERVE_AFTER_RECORD: &str = "reserve.after_record";
    pub(super) const RESERVE_AFTER_REQUEST_KEY: &str = "reserve.after_request_key";
    pub(super) const RESERVE_AFTER_ALLOCATION: &str = "reserve.after_allocation";
    pub(super) const RESERVE_AFTER_EXPIRATION: &str = "reserve.after_expiration";
    pub(super) const RESERVE_AFTER_AUDIT: &str = "reserve.after_audit";
    pub(super) const RELEASE_AFTER_ALLOCATION: &str = "release.after_allocation";
    pub(super) const RELEASE_AFTER_EXPIRATION: &str = "release.after_expiration";
    pub(super) const RELEASE_AFTER_RECORD: &str = "release.after_record";
    pub(super) const RELEASE_AFTER_AUDIT: &str = "release.after_audit";
    pub(super) const COMMIT_AFTER_ALLOCATION: &str = "commit.after_allocation";
    pub(super) const COMMIT_AFTER_EXPIRATION: &str = "commit.after_expiration";
    pub(super) const COMMIT_AFTER_RECORD: &str = "commit.after_record";
    pub(super) const COMMIT_AFTER_AUDIT: &str = "commit.after_audit";
    pub(super) const SIGNED_AFTER_RECORD: &str = "signed.after_record";
    pub(super) const SIGNED_AFTER_AUDIT: &str = "signed.after_audit";

    #[derive(Clone, Copy)]
    struct Active {
        name: &'static str,
        remaining_hits: usize,
    }

    thread_local! {
        static ACTIVE: RefCell<Option<Active>> = const { RefCell::new(None) };
    }

    pub(super) struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            ACTIVE.with(|active| *active.borrow_mut() = None);
        }
    }

    pub(super) fn arm(name: &'static str, occurrence: usize) -> Guard {
        ACTIVE.with(|active| {
            let mut active = active.borrow_mut();
            assert!(active.is_none(), "a mutation failpoint is already armed");
            *active = Some(Active {
                name,
                remaining_hits: occurrence,
            });
        });
        Guard
    }

    pub(super) fn hit(name: &'static str) -> Result<(), ProviderError> {
        ACTIVE.with(|active| {
            let mut active = active.borrow_mut();
            let Some(specification) = active.as_mut() else {
                return Ok(());
            };
            if specification.name != name {
                return Ok(());
            }
            if specification.remaining_hits != 0 {
                specification.remaining_hits -= 1;
                return Ok(());
            }
            *active = None;
            Err(ProviderError::InjectedMutationFailure(name))
        })
    }
}

/// Synchronous durable reservation state. Async service code should call this
/// through its blocking boundary rather than sharing wallet or network state.
pub struct ReservationBook {
    database: Database,
    identity: ProviderIdentity,
    poisoned: AtomicBool,
    operation_lock: Mutex<()>,
}

impl ReservationBook {
    pub fn open(path: impl AsRef<Path>, identity: ProviderIdentity) -> Result<Self, ProviderError> {
        let database = Database::create(path)?;
        let book = Self {
            database,
            identity,
            poisoned: AtomicBool::new(false),
            operation_lock: Mutex::new(()),
        };
        book.initialize_schema()?;
        Ok(book)
    }

    #[must_use]
    pub const fn identity(&self) -> ProviderIdentity {
        self.identity
    }

    pub fn schema_version(&self) -> Result<u32, ProviderError> {
        self.ensure_healthy()?;
        let read = self.database.begin_read()?;
        let table = read.open_table(META)?;
        let value = table
            .get(SCHEMA_VERSION_KEY)?
            .ok_or(ProviderError::MissingMetadata(SCHEMA_VERSION_KEY))?;
        decode_u32(value.value()).map_err(|()| ProviderError::CorruptSchemaVersion)
    }

    /// Add one wallet-discovered output without changing an existing record.
    /// Exact retries are idempotent; conflicting metadata is rejected.
    pub fn import_inventory<C: Clock>(
        &self,
        item: InventoryItem,
        clock: &C,
    ) -> Result<bool, ProviderError> {
        let (_operation_guard, write, now) = self.begin_timed_write(clock)?;
        let key = outpoint_key(item.outpoint());
        let stored = StoredInventoryItem::from(item);
        if let Some(existing) = read_record_from_write(&write, INVENTORY, &key)? {
            let existing: StoredInventoryItem = existing;
            if existing != stored {
                return Err(ProviderError::InventoryMetadataConflict {
                    outpoint: item.outpoint(),
                });
            }
            self.commit_write(write)?;
            return Ok(false);
        }
        write_record(&write, INVENTORY, &key, &stored)?;
        append_audit(
            &write,
            now,
            StoredAuditEvent::InventoryImported {
                outpoint: item.outpoint(),
            },
        )?;
        self.commit_write(write)?;
        Ok(true)
    }

    pub fn inventory(&self, outpoint: OutPoint) -> Result<Option<InventoryView>, ProviderError> {
        self.ensure_healthy()?;
        let read = self.database.begin_read()?;
        let inventory = read.open_table(INVENTORY)?;
        let key = outpoint_key(outpoint);
        let Some(item) = inventory.get(key.as_slice())? else {
            return Ok(None);
        };
        let item: StoredInventoryItem = decode_record(item.value())?;
        drop(inventory);
        let allocations = read.open_table(ALLOCATIONS)?;
        let state = allocations
            .get(key.as_slice())?
            .map(|allocation| decode_record::<StoredAllocation>(allocation.value()))
            .transpose()?
            .map_or(InventoryState::Available, StoredAllocation::to_view);
        Ok(Some(InventoryView::new(item.to_domain()?, state)))
    }

    pub fn inventory_all(&self) -> Result<Vec<InventoryView>, ProviderError> {
        self.ensure_healthy()?;
        let read = self.database.begin_read()?;
        let inventory = read.open_table(INVENTORY)?;
        let allocations = read.open_table(ALLOCATIONS)?;
        let mut result = Vec::new();
        for entry in inventory.iter()? {
            let (key, item) = entry?;
            let item: StoredInventoryItem = decode_record(item.value())?;
            let state = allocations
                .get(key.value())?
                .map(|allocation| decode_record::<StoredAllocation>(allocation.value()))
                .transpose()?
                .map_or(InventoryState::Available, StoredAllocation::to_view);
            result.push(InventoryView::new(item.to_domain()?, state));
        }
        Ok(result)
    }

    /// Atomically reserve every requested outpoint or none of them.
    ///
    /// The clock is sampled after acquiring redb's serial writer, so a request
    /// queued behind another writer cannot commit using a stale pre-lock time.
    pub fn reserve<C: Clock>(
        &self,
        plan: &ReservationPlan,
        clock: &C,
    ) -> Result<ReserveOutcome, ProviderError> {
        if plan.fee_policy().policy_asset() != self.identity.policy_asset() {
            return Err(ProviderError::WrongPolicyAsset {
                expected: self.identity.policy_asset(),
                actual: plan.fee_policy().policy_asset(),
            });
        }
        let request_digest = request_digest(self.identity, plan)?;
        let reservation_id = derive_reservation_id(plan.owner(), plan.idempotency_key());
        let (_operation_guard, write, now) = self.begin_timed_write(clock)?;
        expire_requested_in_write(&write, now, plan.outpoints())?;

        if let Some(binding) = read_request_binding(&write, plan.owner(), plan.idempotency_key())? {
            if binding.request_digest != request_digest {
                return Err(ProviderError::IdempotencyConflict {
                    owner: plan.owner(),
                    key: plan.idempotency_key(),
                });
            }
            let record =
                read_reservation_from_write(&write, ReservationId::new(binding.reservation_id))?
                    .ok_or(ProviderError::CorruptState(
                        "idempotency binding references a missing reservation".to_owned(),
                    ))?;
            self.commit_write(write)?;
            return Ok(ReserveOutcome {
                reservation: record.to_view()?,
                created: false,
            });
        }

        if now >= plan.accept_before() {
            self.commit_write(write)?;
            return Err(ProviderError::ReservationDeadlineElapsed {
                accept_before: plan.accept_before(),
                now,
            });
        }
        if read_reservation_from_write(&write, reservation_id)?.is_some() {
            return Err(ProviderError::ReservationIdCollision(reservation_id));
        }

        for outpoint in plan.outpoints() {
            let key = outpoint_key(*outpoint);
            if read_record_from_write::<StoredInventoryItem>(&write, INVENTORY, &key)?.is_none() {
                return Err(ProviderError::UnknownInventory(*outpoint));
            }
            if let Some(allocation) =
                read_record_from_write::<StoredAllocation>(&write, ALLOCATIONS, &key)?
            {
                return Err(ProviderError::OutpointUnavailable {
                    outpoint: *outpoint,
                    state: allocation.to_view(),
                });
            }
        }

        let record = StoredReservation {
            id: reservation_id.to_bytes(),
            owner: plan.owner().to_bytes(),
            idempotency_key: plan.idempotency_key().to_bytes(),
            request_digest,
            quote_commitment: plan.quote_commitment().to_bytes(),
            outpoints: plan.outpoints().to_vec(),
            created_at: now.value(),
            accept_before: plan.accept_before().value(),
            fee_policy: StoredFeePolicy::from(plan.fee_policy()),
            state: StoredReservationState::Reserved,
        };
        write_record(&write, RESERVATIONS, &reservation_id.to_bytes(), &record)?;
        #[cfg(test)]
        mutation_failpoints::hit(mutation_failpoints::RESERVE_AFTER_RECORD)?;
        let binding = StoredRequestBinding {
            reservation_id: reservation_id.to_bytes(),
            request_digest,
        };
        write_record(
            &write,
            REQUEST_KEYS,
            &request_key(plan.owner(), plan.idempotency_key()),
            &binding,
        )?;
        #[cfg(test)]
        mutation_failpoints::hit(mutation_failpoints::RESERVE_AFTER_REQUEST_KEY)?;
        for outpoint in plan.outpoints() {
            write_record(
                &write,
                ALLOCATIONS,
                &outpoint_key(*outpoint),
                &StoredAllocation::Reserved {
                    reservation_id: reservation_id.to_bytes(),
                },
            )?;
            #[cfg(test)]
            mutation_failpoints::hit(mutation_failpoints::RESERVE_AFTER_ALLOCATION)?;
        }
        let expiration_key = expiration_key(plan.accept_before(), reservation_id);
        let empty: &[u8] = &[];
        write
            .open_table(EXPIRATIONS)?
            .insert(expiration_key.as_slice(), empty)?;
        #[cfg(test)]
        mutation_failpoints::hit(mutation_failpoints::RESERVE_AFTER_EXPIRATION)?;
        append_audit(
            &write,
            now,
            StoredAuditEvent::ReservationCreated {
                reservation_id: reservation_id.to_bytes(),
                outpoints: plan.outpoints().to_vec(),
            },
        )?;
        #[cfg(test)]
        mutation_failpoints::hit(mutation_failpoints::RESERVE_AFTER_AUDIT)?;
        self.commit_write(write)?;
        Ok(ReserveOutcome {
            reservation: record.to_view()?,
            created: true,
        })
    }

    pub fn reservation(
        &self,
        reservation_id: ReservationId,
    ) -> Result<Option<ReservationView>, ProviderError> {
        self.ensure_healthy()?;
        let read = self.database.begin_read()?;
        let table = read.open_table(RESERVATIONS)?;
        let record = table
            .get(reservation_id.to_bytes().as_slice())?
            .map(|value| decode_record::<StoredReservation>(value.value()))
            .transpose()?;
        record
            .map(|record| {
                if record.id() != reservation_id {
                    return Err(ProviderError::CorruptState(
                        "reservation key and record ID disagree".to_owned(),
                    ));
                }
                record.validate()?;
                record.to_view()
            })
            .transpose()
    }

    /// Cancel a reservation only while it remains before the signing point of
    /// no return. Cancellation at or after the deadline is recorded as expiry.
    pub fn cancel<C: Clock>(
        &self,
        access: ReservationAccess,
        clock: &C,
    ) -> Result<bool, ProviderError> {
        let (_operation_guard, write, now) = self.begin_timed_write(clock)?;
        let mut record = require_authorized_reservation(&write, access)?;
        match record.state {
            StoredReservationState::Reserved => {
                let reason = if now >= UnixMillis::new(record.accept_before) {
                    ReleaseReason::Expired
                } else {
                    ReleaseReason::ClientCancelled
                };
                release_reserved(&write, &mut record, reason, now)?;
                self.commit_write(write)?;
                Ok(true)
            }
            StoredReservationState::Released {
                reason: StoredReleaseReason::ClientCancelled,
                ..
            } => {
                self.commit_write(write)?;
                Ok(false)
            }
            StoredReservationState::Released { .. } => {
                Err(ProviderError::ReservationAlreadyReleased(record.id()))
            }
            StoredReservationState::Committed { .. } | StoredReservationState::Signed { .. } => {
                Err(ProviderError::PointOfNoReturn(record.id()))
            }
        }
    }

    /// Provider-side rejection before commitment. This is distinct from a
    /// client cancellation in the durable audit trail.
    pub fn reject_uncommitted<C: Clock>(
        &self,
        reservation_id: ReservationId,
        clock: &C,
    ) -> Result<bool, ProviderError> {
        let (_operation_guard, write, now) = self.begin_timed_write(clock)?;
        let mut record = read_reservation_from_write(&write, reservation_id)?
            .ok_or(ProviderError::ReservationNotFound(reservation_id))?;
        match record.state {
            StoredReservationState::Reserved => {
                let reason = if now >= UnixMillis::new(record.accept_before) {
                    ReleaseReason::Expired
                } else {
                    ReleaseReason::ProviderRejected
                };
                release_reserved(&write, &mut record, reason, now)?;
                self.commit_write(write)?;
                Ok(true)
            }
            StoredReservationState::Released { .. } => {
                self.commit_write(write)?;
                Ok(false)
            }
            StoredReservationState::Committed { .. } | StoredReservationState::Signed { .. } => {
                Err(ProviderError::PointOfNoReturn(reservation_id))
            }
        }
    }

    /// Release up to `limit` expired reservations, oldest deadline first.
    pub fn expire_due<C: Clock>(
        &self,
        clock: &C,
        limit: usize,
    ) -> Result<Vec<ReservationId>, ProviderError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let (_operation_guard, write, now) = self.begin_timed_write(clock)?;
        let expired = expire_due_in_write(&write, now, limit.min(MAX_EXPIRATION_BATCH))?;
        self.commit_write(write)?;
        Ok(expired)
    }

    /// Atomically bind the reserved inputs to exact, already-validated bytes
    /// before any wallet or HSM signer is invoked.
    ///
    /// `pre_sign_payload` must be the complete immutable provider signing
    /// transcript produced by the later settlement validator, including the
    /// finalized transaction body, proofs, authoritative prevouts, existing
    /// user witnesses, approved sighash profile, and quote economics.
    // The concrete validator added in the next provider layer will be this
    // method's only production caller. Keeping the transition crate-private
    // prevents detached fee assertions from crossing the trust boundary.
    #[allow(dead_code)]
    pub(crate) fn commit_before_sign<C: Clock>(
        &self,
        access: ReservationAccess,
        pre_sign_payload: Vec<u8>,
        fee: TransactionFee,
        clock: &C,
    ) -> Result<CommitOutcome, ProviderError> {
        validate_settlement_bytes(&pre_sign_payload)?;
        let (_operation_guard, write, now) = self.begin_timed_write(clock)?;
        let mut record = require_authorized_reservation(&write, access)?;

        match &record.state {
            StoredReservationState::Committed { intent } => {
                let proposed = signing_commitment(&record, &pre_sign_payload, fee)?;
                if intent.commitment != proposed.to_bytes()
                    || intent.pre_sign_payload != pre_sign_payload
                    || intent.fee != StoredTransactionFee::from(fee)
                {
                    return Err(ProviderError::DifferentSigningIntent(record.id()));
                }
                let job = intent.to_job(record.id())?;
                self.commit_write(write)?;
                return Ok(CommitOutcome::AlreadyCommitted(job));
            }
            StoredReservationState::Signed { intent, artifact } => {
                let proposed = signing_commitment(&record, &pre_sign_payload, fee)?;
                if intent.commitment != proposed.to_bytes()
                    || intent.pre_sign_payload != pre_sign_payload
                    || intent.fee != StoredTransactionFee::from(fee)
                {
                    return Err(ProviderError::DifferentSigningIntent(record.id()));
                }
                let artifact = artifact.to_domain(record.id(), proposed)?;
                self.commit_write(write)?;
                return Ok(CommitOutcome::AlreadySigned(artifact));
            }
            StoredReservationState::Released { .. } => {
                return Err(ProviderError::ReservationAlreadyReleased(record.id()));
            }
            StoredReservationState::Reserved => {}
        }

        if now >= UnixMillis::new(record.accept_before) {
            let deadline = UnixMillis::new(record.accept_before);
            release_reserved(&write, &mut record, ReleaseReason::Expired, now)?;
            self.commit_write(write)?;
            return Err(ProviderError::ReservationDeadlineElapsed {
                accept_before: deadline,
                now,
            });
        }

        let policy = record.fee_policy.to_domain()?;
        policy.validate(fee)?;
        let commitment = signing_commitment(&record, &pre_sign_payload, fee)?;
        for outpoint in &record.outpoints {
            let key = outpoint_key(*outpoint);
            let allocation = read_record_from_write::<StoredAllocation>(&write, ALLOCATIONS, &key)?
                .ok_or_else(|| {
                    ProviderError::CorruptState(format!(
                        "reserved outpoint {outpoint:?} has no allocation"
                    ))
                })?;
            if allocation
                != (StoredAllocation::Reserved {
                    reservation_id: record.id,
                })
            {
                return Err(ProviderError::CorruptState(format!(
                    "reserved outpoint {outpoint:?} has a different allocation"
                )));
            }
        }

        let intent = StoredSigningIntent {
            commitment: commitment.to_bytes(),
            pre_sign_payload,
            fee: StoredTransactionFee::from(fee),
            committed_at: now.value(),
        };
        for outpoint in &record.outpoints {
            write_record(
                &write,
                ALLOCATIONS,
                &outpoint_key(*outpoint),
                &StoredAllocation::Committed {
                    reservation_id: record.id,
                    commitment: commitment.to_bytes(),
                },
            )?;
            #[cfg(test)]
            mutation_failpoints::hit(mutation_failpoints::COMMIT_AFTER_ALLOCATION)?;
        }
        let expiration_key = expiration_key(UnixMillis::new(record.accept_before), record.id());
        let removed_expiration = {
            let mut expirations = write.open_table(EXPIRATIONS)?;
            expirations.remove(expiration_key.as_slice())?.is_some()
        };
        if !removed_expiration {
            return Err(ProviderError::CorruptState(
                "reserved reservation has no expiration index entry".to_owned(),
            ));
        }
        #[cfg(test)]
        mutation_failpoints::hit(mutation_failpoints::COMMIT_AFTER_EXPIRATION)?;
        record.state = StoredReservationState::Committed {
            intent: intent.clone(),
        };
        write_record(&write, RESERVATIONS, &record.id, &record)?;
        #[cfg(test)]
        mutation_failpoints::hit(mutation_failpoints::COMMIT_AFTER_RECORD)?;
        append_audit(
            &write,
            now,
            StoredAuditEvent::SigningCommitted {
                reservation_id: record.id,
                commitment: commitment.to_bytes(),
            },
        )?;
        #[cfg(test)]
        mutation_failpoints::hit(mutation_failpoints::COMMIT_AFTER_AUDIT)?;
        let job = intent.to_job(record.id())?;
        self.commit_write(write)?;
        Ok(CommitOutcome::NewlyCommitted(job))
    }

    /// Persist exact signed bytes before they can be returned or relayed.
    // The signer adapter added in the next provider layer will verify and
    // canonicalize its result before invoking this crate-private transition.
    #[allow(dead_code)]
    pub(crate) fn record_signed<C: Clock>(
        &self,
        reservation_id: ReservationId,
        expected_commitment: SigningCommitment,
        signed_bytes: Vec<u8>,
        clock: &C,
    ) -> Result<SignedOutcome, ProviderError> {
        validate_settlement_bytes(&signed_bytes)?;
        let (_operation_guard, write, now) = self.begin_timed_write(clock)?;
        let mut record = read_reservation_from_write(&write, reservation_id)?
            .ok_or(ProviderError::ReservationNotFound(reservation_id))?;
        let intent = match &record.state {
            StoredReservationState::Committed { intent } => intent.clone(),
            StoredReservationState::Signed { intent, artifact } => {
                if intent.commitment != expected_commitment.to_bytes()
                    || artifact.bytes != signed_bytes
                {
                    return Err(ProviderError::DifferentSignedArtifact(reservation_id));
                }
                let artifact = artifact.to_domain(reservation_id, expected_commitment)?;
                self.commit_write(write)?;
                return Ok(SignedOutcome {
                    artifact,
                    recorded: false,
                });
            }
            StoredReservationState::Reserved => {
                return Err(ProviderError::SigningIntentNotCommitted(reservation_id));
            }
            StoredReservationState::Released { .. } => {
                return Err(ProviderError::ReservationAlreadyReleased(reservation_id));
            }
        };
        if intent.commitment != expected_commitment.to_bytes() {
            return Err(ProviderError::SigningCommitmentMismatch {
                reservation_id,
                expected: SigningCommitment::new(intent.commitment),
                actual: expected_commitment,
            });
        }
        let digest = signed_artifact_digest(expected_commitment, &signed_bytes);
        let stored_artifact = StoredSignedArtifact {
            digest: digest.to_bytes(),
            bytes: signed_bytes,
            signed_at: now.value(),
        };
        let artifact = stored_artifact.to_domain(reservation_id, expected_commitment)?;
        record.state = StoredReservationState::Signed {
            intent,
            artifact: stored_artifact,
        };
        write_record(&write, RESERVATIONS, &reservation_id.to_bytes(), &record)?;
        #[cfg(test)]
        mutation_failpoints::hit(mutation_failpoints::SIGNED_AFTER_RECORD)?;
        append_audit(
            &write,
            now,
            StoredAuditEvent::SignedArtifactStored {
                reservation_id: reservation_id.to_bytes(),
                artifact: digest.to_bytes(),
            },
        )?;
        #[cfg(test)]
        mutation_failpoints::hit(mutation_failpoints::SIGNED_AFTER_AUDIT)?;
        self.commit_write(write)?;
        Ok(SignedOutcome {
            artifact,
            recorded: true,
        })
    }

    /// Exact actions safe to resume after restart. The caller must sign or
    /// replay only the returned durable bytes.
    pub fn recovery_actions(&self) -> Result<Vec<RecoveryAction>, ProviderError> {
        self.ensure_healthy()?;
        let read = self.database.begin_read()?;
        let table = read.open_table(RESERVATIONS)?;
        let mut actions = Vec::new();
        for entry in table.iter()? {
            let (_, value) = entry?;
            let record: StoredReservation = decode_record(value.value())?;
            record.validate()?;
            match &record.state {
                StoredReservationState::Committed { intent } => actions.push(
                    RecoveryAction::SignCommittedExact(intent.to_job(record.id())?),
                ),
                StoredReservationState::Signed { intent, artifact } => {
                    let commitment = SigningCommitment::new(intent.commitment);
                    actions.push(RecoveryAction::ReplaySignedExact(
                        artifact.to_domain(record.id(), commitment)?,
                    ));
                }
                StoredReservationState::Reserved | StoredReservationState::Released { .. } => {}
            }
        }
        Ok(actions)
    }

    pub fn audit_log(&self) -> Result<Vec<AuditEntry>, ProviderError> {
        self.ensure_healthy()?;
        let read = self.database.begin_read()?;
        let table = read.open_table(AUDIT)?;
        let mut entries = Vec::new();
        for entry in table.iter()? {
            let (sequence, value) = entry?;
            let stored: StoredAuditEntry = decode_record(value.value())?;
            if stored.sequence != sequence.value() {
                return Err(ProviderError::CorruptState(
                    "audit key and record sequence disagree".to_owned(),
                ));
            }
            entries.push(stored.to_domain());
        }
        Ok(entries)
    }

    pub fn last_observed_time(&self) -> Result<Option<UnixMillis>, ProviderError> {
        self.ensure_healthy()?;
        let read = self.database.begin_read()?;
        let table = read.open_table(META)?;
        table
            .get(LAST_OBSERVED_TIME_KEY)?
            .map(|value| {
                decode_u64(value.value())
                    .map(UnixMillis::new)
                    .map_err(|()| ProviderError::CorruptTimeHighWatermark)
            })
            .transpose()
    }

    fn initialize_schema(&self) -> Result<(), ProviderError> {
        let write = self.begin_immediate_write()?;
        create_tables(&write)?;
        let existing_schema = {
            let meta = write.open_table(META)?;
            meta.get(SCHEMA_VERSION_KEY)?
                .map(|value| value.value().to_vec())
        };
        match existing_schema {
            Some(value) => {
                let actual =
                    decode_u32(&value).map_err(|()| ProviderError::CorruptSchemaVersion)?;
                if actual != SCHEMA_VERSION {
                    return Err(ProviderError::SchemaMismatch {
                        expected: SCHEMA_VERSION,
                        actual,
                    });
                }
                let meta = write.open_table(META)?;
                let identity = meta
                    .get(PROVIDER_IDENTITY_KEY)?
                    .ok_or(ProviderError::MissingMetadata(PROVIDER_IDENTITY_KEY))?;
                let actual: StoredProviderIdentity = decode_record(identity.value())?;
                let actual = actual.to_domain();
                if actual != self.identity {
                    return Err(ProviderError::ProviderIdentityMismatch {
                        expected: Box::new(actual),
                        actual: Box::new(self.identity),
                    });
                }
                if meta.get(AUDIT_SEQUENCE_KEY)?.is_none() {
                    return Err(ProviderError::MissingMetadata(AUDIT_SEQUENCE_KEY));
                }
            }
            None => {
                if provider_tables_are_nonempty(&write)? {
                    return Err(ProviderError::CorruptState(
                        "schema version is missing from a nonempty provider database".to_owned(),
                    ));
                }
                let mut meta = write.open_table(META)?;
                meta.insert(SCHEMA_VERSION_KEY, SCHEMA_VERSION.to_be_bytes().as_slice())?;
                let identity = encode_record(&StoredProviderIdentity::from(self.identity))?;
                meta.insert(PROVIDER_IDENTITY_KEY, identity.as_slice())?;
                meta.insert(AUDIT_SEQUENCE_KEY, 0_u64.to_be_bytes().as_slice())?;
            }
        }
        validate_store_integrity(&write, self.identity)?;
        self.commit_write(write)?;
        Ok(())
    }

    fn begin_immediate_write(&self) -> Result<WriteTransaction, ProviderError> {
        self.ensure_healthy()?;
        let mut write = self.database.begin_write()?;
        self.ensure_healthy()?;
        // A returned reservation or signing commitment is safe to expose only
        // after redb guarantees that its input locks survived a crash.
        write.set_durability(Durability::Immediate)?;
        Ok(write)
    }

    /// Serialize a complete timed operation and durably advance the clock
    /// high-water mark before starting its logical mutation.
    ///
    /// The separate immediate commit is intentional: authentication,
    /// validation, or injected mutation failures must roll back the business
    /// transaction without erasing the fact that the later time was observed.
    /// Holding this process lock across both transactions prevents an older
    /// operation from mutating state after a newer observation. redb's
    /// exclusive database open prevents a second process from bypassing it.
    fn begin_timed_write<C: Clock>(
        &self,
        clock: &C,
    ) -> Result<(MutexGuard<'_, ()>, WriteTransaction, UnixMillis), ProviderError> {
        let operation_guard = self
            .operation_lock
            .lock()
            .map_err(|_| ProviderError::OperationLockPoisoned)?;
        let observation = self.begin_immediate_write()?;
        let now = observe_time(&observation, clock)?;
        self.commit_write(observation)?;
        let write = self.begin_immediate_write()?;
        Ok((operation_guard, write, now))
    }

    fn commit_write(&self, write: WriteTransaction) -> Result<(), ProviderError> {
        match write.commit() {
            Ok(()) => Ok(()),
            Err(error) => {
                // A commit error is an ambiguous durability boundary. Require
                // the service to drop and reopen the database before it makes
                // another availability or signing decision.
                self.poisoned.store(true, Ordering::SeqCst);
                Err(ProviderError::Commit(error))
            }
        }
    }

    fn ensure_healthy(&self) -> Result<(), ProviderError> {
        if self.poisoned.load(Ordering::SeqCst) {
            return Err(ProviderError::DatabaseRequiresReopen);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReserveOutcome {
    reservation: ReservationView,
    created: bool,
}

impl ReserveOutcome {
    #[must_use]
    pub const fn reservation(&self) -> &ReservationView {
        &self.reservation
    }

    #[must_use]
    pub const fn created(&self) -> bool {
        self.created
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitOutcome {
    NewlyCommitted(SigningJob),
    AlreadyCommitted(SigningJob),
    AlreadySigned(SignedArtifact),
}

impl CommitOutcome {
    #[must_use]
    pub const fn signing_job(&self) -> Option<&SigningJob> {
        match self {
            Self::NewlyCommitted(job) | Self::AlreadyCommitted(job) => Some(job),
            Self::AlreadySigned(_) => None,
        }
    }

    #[must_use]
    pub const fn signed_artifact(&self) -> Option<&SignedArtifact> {
        match self {
            Self::AlreadySigned(artifact) => Some(artifact),
            Self::NewlyCommitted(_) | Self::AlreadyCommitted(_) => None,
        }
    }

    #[must_use]
    pub const fn newly_committed(&self) -> bool {
        matches!(self, Self::NewlyCommitted(_))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedOutcome {
    artifact: SignedArtifact,
    recorded: bool,
}

impl SignedOutcome {
    #[must_use]
    pub const fn artifact(&self) -> &SignedArtifact {
        &self.artifact
    }

    #[must_use]
    pub const fn recorded(&self) -> bool {
        self.recorded
    }
}

fn observe_time<C: Clock>(
    write: &WriteTransaction,
    clock: &C,
) -> Result<UnixMillis, ProviderError> {
    let now = clock.now();
    let mut meta = write.open_table(META)?;
    if let Some(previous) = meta.get(LAST_OBSERVED_TIME_KEY)? {
        let previous =
            decode_u64(previous.value()).map_err(|()| ProviderError::CorruptTimeHighWatermark)?;
        if now.value() < previous {
            return Err(ProviderError::ClockRegression {
                previous: UnixMillis::new(previous),
                now,
            });
        }
    }
    meta.insert(LAST_OBSERVED_TIME_KEY, now.value().to_be_bytes().as_slice())?;
    Ok(now)
}

fn expire_due_in_write(
    write: &WriteTransaction,
    now: UnixMillis,
    limit: usize,
) -> Result<Vec<ReservationId>, ProviderError> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let due = {
        let expirations = write.open_table(EXPIRATIONS)?;
        let mut due = Vec::new();
        for entry in expirations.iter()? {
            let (key, _) = entry?;
            let (deadline, reservation_id) = decode_expiration_key(key.value())?;
            if deadline > now {
                break;
            }
            due.push((deadline, reservation_id));
            if due.len() == limit {
                break;
            }
        }
        due
    };
    for (deadline, reservation_id) in &due {
        let mut record = read_reservation_from_write(write, *reservation_id)?.ok_or_else(|| {
            ProviderError::CorruptState(
                "expiration index references a missing reservation".to_owned(),
            )
        })?;
        if record.accept_before != deadline.value() {
            return Err(ProviderError::CorruptState(
                "expiration index and reservation deadline disagree".to_owned(),
            ));
        }
        match record.state {
            StoredReservationState::Reserved => {
                if UnixMillis::new(record.accept_before) > now {
                    return Err(ProviderError::CorruptState(
                        "expiration index precedes reservation deadline".to_owned(),
                    ));
                }
                release_reserved(write, &mut record, ReleaseReason::Expired, now)?;
            }
            _ => {
                return Err(ProviderError::CorruptState(
                    "expiration index references a terminal reservation".to_owned(),
                ));
            }
        }
    }
    Ok(due
        .into_iter()
        .map(|(_, reservation_id)| reservation_id)
        .collect())
}

/// Lazily reclaim only expired reservations that block this request. This
/// keeps the hot path bounded by the request and reservation input limits;
/// the service is responsible for draining unrelated expirations through
/// [`ReservationBook::expire_due`] with an explicit batch size.
fn expire_requested_in_write(
    write: &WriteTransaction,
    now: UnixMillis,
    requested: &[OutPoint],
) -> Result<Vec<ReservationId>, ProviderError> {
    let mut expired = Vec::new();
    for requested_outpoint in requested {
        let Some(allocation) = read_record_from_write::<StoredAllocation>(
            write,
            ALLOCATIONS,
            &outpoint_key(*requested_outpoint),
        )?
        else {
            continue;
        };
        let StoredAllocation::Reserved { reservation_id } = allocation else {
            continue;
        };
        let reservation_id = ReservationId::new(reservation_id);
        if expired.contains(&reservation_id) {
            continue;
        }
        let mut record = read_reservation_from_write(write, reservation_id)?.ok_or_else(|| {
            ProviderError::CorruptState("allocation references a missing reservation".to_owned())
        })?;
        if !record.outpoints.contains(requested_outpoint) {
            return Err(ProviderError::CorruptState(
                "reservation does not contain its allocated outpoint".to_owned(),
            ));
        }
        if !matches!(record.state, StoredReservationState::Reserved) {
            return Err(ProviderError::CorruptState(
                "reserved allocation references a terminal reservation".to_owned(),
            ));
        }
        if now >= UnixMillis::new(record.accept_before) {
            release_reserved(write, &mut record, ReleaseReason::Expired, now)?;
            expired.push(reservation_id);
        }
    }
    Ok(expired)
}

fn release_reserved(
    write: &WriteTransaction,
    record: &mut StoredReservation,
    reason: ReleaseReason,
    at: UnixMillis,
) -> Result<(), ProviderError> {
    if !matches!(record.state, StoredReservationState::Reserved) {
        return Err(ProviderError::PointOfNoReturn(record.id()));
    }
    for outpoint in &record.outpoints {
        let key = outpoint_key(*outpoint);
        let allocation = read_record_from_write::<StoredAllocation>(write, ALLOCATIONS, &key)?
            .ok_or_else(|| {
                ProviderError::CorruptState(format!(
                    "reserved outpoint {outpoint:?} has no allocation"
                ))
            })?;
        if allocation
            != (StoredAllocation::Reserved {
                reservation_id: record.id,
            })
        {
            return Err(ProviderError::CorruptState(format!(
                "reserved outpoint {outpoint:?} has a different allocation"
            )));
        }
    }
    for outpoint in &record.outpoints {
        write
            .open_table(ALLOCATIONS)?
            .remove(outpoint_key(*outpoint).as_slice())?;
        #[cfg(test)]
        mutation_failpoints::hit(mutation_failpoints::RELEASE_AFTER_ALLOCATION)?;
    }
    let expiration_key = expiration_key(UnixMillis::new(record.accept_before), record.id());
    let removed_expiration = {
        let mut expirations = write.open_table(EXPIRATIONS)?;
        expirations.remove(expiration_key.as_slice())?.is_some()
    };
    if !removed_expiration {
        return Err(ProviderError::CorruptState(
            "reserved reservation has no expiration index entry".to_owned(),
        ));
    }
    #[cfg(test)]
    mutation_failpoints::hit(mutation_failpoints::RELEASE_AFTER_EXPIRATION)?;
    record.state = StoredReservationState::Released {
        reason: StoredReleaseReason::from(reason),
        at: at.value(),
    };
    write_record(write, RESERVATIONS, &record.id, record)?;
    #[cfg(test)]
    mutation_failpoints::hit(mutation_failpoints::RELEASE_AFTER_RECORD)?;
    append_audit(
        write,
        at,
        StoredAuditEvent::ReservationReleased {
            reservation_id: record.id,
            reason: reason.into(),
        },
    )?;
    #[cfg(test)]
    mutation_failpoints::hit(mutation_failpoints::RELEASE_AFTER_AUDIT)?;
    Ok(())
}

fn require_authorized_reservation(
    write: &WriteTransaction,
    access: ReservationAccess,
) -> Result<StoredReservation, ProviderError> {
    let record = read_reservation_from_write(write, access.reservation_id())?
        .ok_or(ProviderError::ReservationNotFound(access.reservation_id()))?;
    if record.owner != access.owner().to_bytes() {
        return Err(ProviderError::ReservationOwnerMismatch(
            access.reservation_id(),
        ));
    }
    Ok(record)
}

fn read_reservation_from_write(
    write: &WriteTransaction,
    reservation_id: ReservationId,
) -> Result<Option<StoredReservation>, ProviderError> {
    let record = read_record_from_write::<StoredReservation>(
        write,
        RESERVATIONS,
        &reservation_id.to_bytes(),
    )?;
    record
        .map(|record| {
            if record.id() != reservation_id {
                return Err(ProviderError::CorruptState(
                    "reservation key and record ID disagree".to_owned(),
                ));
            }
            record.validate()?;
            Ok(record)
        })
        .transpose()
}

fn read_request_binding(
    write: &WriteTransaction,
    owner: OwnerId,
    key: IdempotencyKey,
) -> Result<Option<StoredRequestBinding>, ProviderError> {
    read_record_from_write(write, REQUEST_KEYS, &request_key(owner, key))
}

fn signing_commitment(
    reservation: &StoredReservation,
    pre_sign_payload: &[u8],
    fee: TransactionFee,
) -> Result<SigningCommitment, ProviderError> {
    let transcript = StoredSigningTranscript {
        request_digest: reservation.request_digest,
        reservation_id: reservation.id,
        outpoints: reservation.outpoints.clone(),
        quote_commitment: reservation.quote_commitment,
        fee_policy: reservation.fee_policy,
        fee: StoredTransactionFee::from(fee),
        pre_sign_payload,
    };
    Ok(SigningCommitment::new(domain_digest(
        SIGNING_DOMAIN,
        &transcript,
    )?))
}

fn signed_artifact_digest(commitment: SigningCommitment, bytes: &[u8]) -> SignedArtifactDigest {
    let mut hasher = Sha256::new();
    hasher.update(SIGNED_ARTIFACT_DOMAIN);
    hasher.update(commitment.to_bytes());
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    SignedArtifactDigest::new(hasher.finalize().into())
}

fn request_digest(
    identity: ProviderIdentity,
    plan: &ReservationPlan,
) -> Result<[u8; 32], ProviderError> {
    let fingerprint = StoredRequestFingerprint {
        identity: StoredProviderIdentity::from(identity),
        owner: plan.owner().to_bytes(),
        idempotency_key: plan.idempotency_key().to_bytes(),
        quote_commitment: plan.quote_commitment().to_bytes(),
        outpoints: plan.outpoints(),
        accept_before: plan.accept_before().value(),
        fee_policy: StoredFeePolicy::from(plan.fee_policy()),
    };
    domain_digest(REQUEST_DOMAIN, &fingerprint)
}

fn stored_request_digest(
    identity: ProviderIdentity,
    reservation: &StoredReservation,
) -> Result<[u8; 32], ProviderError> {
    let fingerprint = StoredRequestFingerprint {
        identity: StoredProviderIdentity::from(identity),
        owner: reservation.owner,
        idempotency_key: reservation.idempotency_key,
        quote_commitment: reservation.quote_commitment,
        outpoints: &reservation.outpoints,
        accept_before: reservation.accept_before,
        fee_policy: reservation.fee_policy,
    };
    domain_digest(REQUEST_DOMAIN, &fingerprint)
}

fn derive_reservation_id(owner: OwnerId, key: IdempotencyKey) -> ReservationId {
    let mut hasher = Sha256::new();
    hasher.update(RESERVATION_ID_DOMAIN);
    hasher.update(owner.to_bytes());
    hasher.update(key.to_bytes());
    ReservationId::new(hasher.finalize().into())
}

fn domain_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<[u8; 32], ProviderError> {
    let encoded = postcard::to_allocvec(value)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}

fn validate_settlement_bytes(bytes: &[u8]) -> Result<(), ProviderError> {
    if bytes.is_empty() {
        return Err(ProviderError::EmptySettlementPayload);
    }
    if bytes.len() > MAX_SETTLEMENT_BYTES {
        return Err(ProviderError::SettlementPayloadTooLarge {
            maximum: MAX_SETTLEMENT_BYTES,
            actual: bytes.len(),
        });
    }
    Ok(())
}

fn append_audit(
    write: &WriteTransaction,
    at: UnixMillis,
    event: StoredAuditEvent,
) -> Result<(), ProviderError> {
    let sequence = {
        let mut meta = write.open_table(META)?;
        let current = {
            let current = meta
                .get(AUDIT_SEQUENCE_KEY)?
                .ok_or(ProviderError::MissingMetadata(AUDIT_SEQUENCE_KEY))?;
            current.value().to_vec()
        };
        let current = decode_u64(&current).map_err(|()| ProviderError::CorruptAuditSequence)?;
        let next = current
            .checked_add(1)
            .ok_or(ProviderError::AuditSequenceOverflow)?;
        meta.insert(AUDIT_SEQUENCE_KEY, next.to_be_bytes().as_slice())?;
        next
    };
    let entry = StoredAuditEntry {
        sequence,
        at: at.value(),
        event,
    };
    let encoded = encode_record(&entry)?;
    write
        .open_table(AUDIT)?
        .insert(sequence, encoded.as_slice())?;
    Ok(())
}

fn provider_tables_are_nonempty(write: &WriteTransaction) -> Result<bool, ProviderError> {
    {
        let table = write.open_table(META)?;
        if table.iter()?.next().transpose()?.is_some() {
            return Ok(true);
        }
    }
    for definition in [
        INVENTORY,
        ALLOCATIONS,
        RESERVATIONS,
        REQUEST_KEYS,
        EXPIRATIONS,
    ] {
        let table = write.open_table(definition)?;
        if table.iter()?.next().transpose()?.is_some() {
            return Ok(true);
        }
    }
    let audit = write.open_table(AUDIT)?;
    Ok(audit.iter()?.next().transpose()?.is_some())
}

/// Validate every durable relationship before the database can answer an
/// availability question or return a recovery job. In particular, absence
/// from `ALLOCATIONS` means available only after this proves that no live or
/// committed reservation still owns the inventory outpoint.
fn validate_store_integrity(
    write: &WriteTransaction,
    identity: ProviderIdentity,
) -> Result<(), ProviderError> {
    let (audit_sequence, last_observed_time) = {
        let meta = write.open_table(META)?;
        let audit_sequence = meta
            .get(AUDIT_SEQUENCE_KEY)?
            .ok_or(ProviderError::MissingMetadata(AUDIT_SEQUENCE_KEY))?;
        let audit_sequence =
            decode_u64(audit_sequence.value()).map_err(|()| ProviderError::CorruptAuditSequence)?;
        let last_observed_time = meta
            .get(LAST_OBSERVED_TIME_KEY)?
            .map(|value| {
                decode_u64(value.value()).map_err(|()| ProviderError::CorruptTimeHighWatermark)
            })
            .transpose()?;
        (audit_sequence, last_observed_time)
    };

    let inventory = {
        let table = write.open_table(INVENTORY)?;
        let mut records = BTreeMap::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let key = decode_table_key::<36>("inventory", key.value())?;
            let item: StoredInventoryItem = decode_record(value.value())?;
            let domain = item.to_domain()?;
            if key != outpoint_key(domain.outpoint()) {
                return Err(ProviderError::CorruptState(format!(
                    "inventory key does not match record outpoint {:?}",
                    domain.outpoint()
                )));
            }
            records.insert(key, item);
        }
        records
    };

    let reservations = {
        let table = write.open_table(RESERVATIONS)?;
        let mut records = BTreeMap::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let key = decode_table_key::<32>("reservation", key.value())?;
            let record: StoredReservation = decode_record(value.value())?;
            if key != record.id {
                return Err(ProviderError::CorruptState(
                    "reservation key and record ID disagree".to_owned(),
                ));
            }
            record.validate()?;
            if record.fee_policy.policy_asset != identity.policy_asset() {
                return Err(ProviderError::CorruptState(format!(
                    "reservation {:?} uses a fee policy for the wrong asset",
                    record.id()
                )));
            }
            let expected_request_digest = stored_request_digest(identity, &record)?;
            if record.request_digest != expected_request_digest {
                return Err(ProviderError::CorruptState(format!(
                    "reservation {:?} request digest does not match its immutable terms",
                    record.id()
                )));
            }
            validate_reservation_times(&record, last_observed_time)?;
            records.insert(key, record);
        }
        records
    };

    let request_bindings = {
        let table = write.open_table(REQUEST_KEYS)?;
        let mut records = BTreeMap::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let key = decode_table_key::<64>("request binding", key.value())?;
            let binding: StoredRequestBinding = decode_record(value.value())?;
            records.insert(key, binding);
        }
        records
    };

    let allocations = {
        let table = write.open_table(ALLOCATIONS)?;
        let mut records = BTreeMap::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let key = decode_table_key::<36>("allocation", key.value())?;
            let allocation: StoredAllocation = decode_record(value.value())?;
            records.insert(key, allocation);
        }
        records
    };

    let expirations = {
        let table = write.open_table(EXPIRATIONS)?;
        let mut keys = BTreeSet::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let key = decode_table_key::<40>("expiration", key.value())?;
            if !value.value().is_empty() {
                return Err(ProviderError::CorruptState(
                    "expiration index value is not empty".to_owned(),
                ));
            }
            keys.insert(key);
        }
        keys
    };

    for record in reservations.values() {
        let expected_request_key = request_key(
            OwnerId::new(record.owner),
            IdempotencyKey::new(record.idempotency_key),
        );
        let binding = request_bindings.get(&expected_request_key).ok_or_else(|| {
            ProviderError::CorruptState(format!(
                "reservation {:?} has no request-key binding",
                record.id()
            ))
        })?;
        if binding.reservation_id != record.id || binding.request_digest != record.request_digest {
            return Err(ProviderError::CorruptState(format!(
                "reservation {:?} request-key binding disagrees with its record",
                record.id()
            )));
        }

        let expected_expiration =
            expiration_key(UnixMillis::new(record.accept_before), record.id());
        let has_expiration = expirations.contains(&expected_expiration);
        match &record.state {
            StoredReservationState::Reserved => {
                if !has_expiration {
                    return Err(ProviderError::CorruptState(format!(
                        "reserved reservation {:?} has no expiration index entry",
                        record.id()
                    )));
                }
            }
            StoredReservationState::Released { .. }
            | StoredReservationState::Committed { .. }
            | StoredReservationState::Signed { .. } => {
                if has_expiration {
                    return Err(ProviderError::CorruptState(format!(
                        "terminal reservation {:?} still has an expiration index entry",
                        record.id()
                    )));
                }
            }
        }

        for outpoint in &record.outpoints {
            let key = outpoint_key(*outpoint);
            if !inventory.contains_key(&key) {
                return Err(ProviderError::CorruptState(format!(
                    "reservation {:?} references missing inventory {outpoint:?}",
                    record.id()
                )));
            }
            let allocation = allocations.get(&key);
            match &record.state {
                StoredReservationState::Reserved => {
                    if allocation
                        != Some(&StoredAllocation::Reserved {
                            reservation_id: record.id,
                        })
                    {
                        return Err(ProviderError::CorruptState(format!(
                            "reserved reservation {:?} does not own allocation {outpoint:?}",
                            record.id()
                        )));
                    }
                }
                StoredReservationState::Committed { intent }
                | StoredReservationState::Signed { intent, .. } => {
                    if allocation
                        != Some(&StoredAllocation::Committed {
                            reservation_id: record.id,
                            commitment: intent.commitment,
                        })
                    {
                        return Err(ProviderError::CorruptState(format!(
                            "committed reservation {:?} does not own its permanent allocation {outpoint:?}",
                            record.id()
                        )));
                    }
                }
                StoredReservationState::Released { .. } => {
                    let still_owned = allocation.is_some_and(|allocation| match allocation {
                        StoredAllocation::Reserved { reservation_id }
                        | StoredAllocation::Committed { reservation_id, .. } => {
                            *reservation_id == record.id
                        }
                    });
                    if still_owned {
                        return Err(ProviderError::CorruptState(format!(
                            "released reservation {:?} still owns allocation {outpoint:?}",
                            record.id()
                        )));
                    }
                }
            }
        }
    }

    for (key, binding) in &request_bindings {
        let record = reservations.get(&binding.reservation_id).ok_or_else(|| {
            ProviderError::CorruptState(
                "request-key binding references a missing reservation".to_owned(),
            )
        })?;
        let expected_key = request_key(
            OwnerId::new(record.owner),
            IdempotencyKey::new(record.idempotency_key),
        );
        if *key != expected_key || binding.request_digest != record.request_digest {
            return Err(ProviderError::CorruptState(format!(
                "request-key binding for reservation {:?} has inconsistent key or digest",
                record.id()
            )));
        }
    }

    for (key, allocation) in &allocations {
        let item = inventory.get(key).ok_or_else(|| {
            ProviderError::CorruptState("allocation references missing inventory".to_owned())
        })?;
        let (reservation_id, allocated_commitment) = match allocation {
            StoredAllocation::Reserved { reservation_id } => (*reservation_id, None),
            StoredAllocation::Committed {
                reservation_id,
                commitment,
            } => (*reservation_id, Some(*commitment)),
        };
        let record = reservations.get(&reservation_id).ok_or_else(|| {
            ProviderError::CorruptState("allocation references a missing reservation".to_owned())
        })?;
        if record.outpoints.binary_search(&item.outpoint).is_err() {
            return Err(ProviderError::CorruptState(format!(
                "allocation for {:?} is absent from reservation {:?}",
                item.outpoint,
                record.id()
            )));
        }
        match (&record.state, allocated_commitment) {
            (StoredReservationState::Reserved, None) => {}
            (StoredReservationState::Committed { intent }, Some(commitment))
            | (StoredReservationState::Signed { intent, .. }, Some(commitment))
                if intent.commitment == commitment => {}
            _ => {
                return Err(ProviderError::CorruptState(format!(
                    "allocation for {:?} disagrees with reservation {:?} state",
                    item.outpoint,
                    record.id()
                )));
            }
        }
    }

    for key in &expirations {
        let (deadline, reservation_id) = decode_expiration_key(key)?;
        let record = reservations
            .get(&reservation_id.to_bytes())
            .ok_or_else(|| {
                ProviderError::CorruptState(
                    "expiration index references a missing reservation".to_owned(),
                )
            })?;
        if !matches!(record.state, StoredReservationState::Reserved)
            || record.accept_before != deadline.value()
        {
            return Err(ProviderError::CorruptState(format!(
                "expiration index disagrees with reservation {:?}",
                record.id()
            )));
        }
    }

    validate_audit_integrity(
        write,
        audit_sequence,
        last_observed_time,
        &inventory,
        &reservations,
    )
}

fn validate_reservation_times(
    record: &StoredReservation,
    last_observed_time: Option<u64>,
) -> Result<(), ProviderError> {
    let high_watermark = last_observed_time.ok_or_else(|| {
        ProviderError::CorruptState(format!(
            "reservation {:?} exists without a clock high-water mark",
            record.id()
        ))
    })?;
    if record.created_at > high_watermark {
        return Err(ProviderError::CorruptState(format!(
            "reservation {:?} was created after the clock high-water mark",
            record.id()
        )));
    }
    match &record.state {
        StoredReservationState::Reserved => {}
        StoredReservationState::Released { reason, at } => {
            if *at < record.created_at || *at > high_watermark {
                return Err(ProviderError::CorruptState(format!(
                    "reservation {:?} has an invalid release time",
                    record.id()
                )));
            }
            let deadline_relation_is_valid = match reason {
                StoredReleaseReason::Expired => *at >= record.accept_before,
                StoredReleaseReason::ClientCancelled | StoredReleaseReason::ProviderRejected => {
                    *at < record.accept_before
                }
            };
            if !deadline_relation_is_valid {
                return Err(ProviderError::CorruptState(format!(
                    "reservation {:?} release reason disagrees with its deadline",
                    record.id()
                )));
            }
        }
        StoredReservationState::Committed { intent } => {
            validate_commit_time(record, intent.committed_at, high_watermark)?;
        }
        StoredReservationState::Signed { intent, artifact } => {
            validate_commit_time(record, intent.committed_at, high_watermark)?;
            if artifact.signed_at < intent.committed_at || artifact.signed_at > high_watermark {
                return Err(ProviderError::CorruptState(format!(
                    "reservation {:?} has an invalid signed-artifact time",
                    record.id()
                )));
            }
        }
    }
    Ok(())
}

fn validate_commit_time(
    record: &StoredReservation,
    committed_at: u64,
    high_watermark: u64,
) -> Result<(), ProviderError> {
    if committed_at < record.created_at
        || committed_at >= record.accept_before
        || committed_at > high_watermark
    {
        return Err(ProviderError::CorruptState(format!(
            "reservation {:?} has an invalid commit time",
            record.id()
        )));
    }
    Ok(())
}

fn validate_audit_integrity(
    write: &WriteTransaction,
    declared_sequence: u64,
    last_observed_time: Option<u64>,
    inventory: &BTreeMap<[u8; 36], StoredInventoryItem>,
    reservations: &BTreeMap<[u8; 32], StoredReservation>,
) -> Result<(), ProviderError> {
    let table = write.open_table(AUDIT)?;
    let mut previous_sequence = 0_u64;
    let mut previous_time = None;
    let mut imported = BTreeSet::new();
    let mut created = BTreeSet::new();
    let mut released = BTreeSet::new();
    let mut committed = BTreeSet::new();
    let mut signed = BTreeSet::new();

    for entry in table.iter()? {
        let (sequence, value) = entry?;
        let sequence = sequence.value();
        let expected = previous_sequence
            .checked_add(1)
            .ok_or(ProviderError::AuditSequenceOverflow)?;
        if sequence != expected {
            return Err(ProviderError::CorruptState(format!(
                "audit sequence is not contiguous: expected {expected}, found {sequence}"
            )));
        }
        let entry: StoredAuditEntry = decode_record(value.value())?;
        if entry.sequence != sequence {
            return Err(ProviderError::CorruptState(
                "audit key and record sequence disagree".to_owned(),
            ));
        }
        if previous_time.is_some_and(|previous| entry.at < previous) {
            return Err(ProviderError::CorruptState(
                "audit timestamps moved backwards".to_owned(),
            ));
        }
        let high_watermark = last_observed_time.ok_or_else(|| {
            ProviderError::CorruptState(
                "audit entries exist without a clock high-water mark".to_owned(),
            )
        })?;
        if entry.at > high_watermark {
            return Err(ProviderError::CorruptState(
                "audit entry is later than the clock high-water mark".to_owned(),
            ));
        }
        match &entry.event {
            StoredAuditEvent::InventoryImported { outpoint } => {
                let key = outpoint_key(*outpoint);
                if !inventory.contains_key(&key) || !imported.insert(key) {
                    return Err(ProviderError::CorruptState(
                        "inventory import audit entry is missing its record or duplicated"
                            .to_owned(),
                    ));
                }
            }
            StoredAuditEvent::ReservationCreated {
                reservation_id,
                outpoints,
            } => {
                let record = reservations.get(reservation_id).ok_or_else(|| {
                    ProviderError::CorruptState(
                        "reservation-created audit entry references a missing reservation"
                            .to_owned(),
                    )
                })?;
                if entry.at != record.created_at
                    || *outpoints != record.outpoints
                    || !created.insert(*reservation_id)
                {
                    return Err(ProviderError::CorruptState(format!(
                        "reservation-created audit entry disagrees with reservation {:?}",
                        record.id()
                    )));
                }
            }
            StoredAuditEvent::ReservationReleased {
                reservation_id,
                reason,
            } => {
                let record = reservations.get(reservation_id).ok_or_else(|| {
                    ProviderError::CorruptState(
                        "reservation-released audit entry references a missing reservation"
                            .to_owned(),
                    )
                })?;
                let matches_state = matches!(
                    record.state,
                    StoredReservationState::Released {
                        reason: stored_reason,
                        at,
                    } if stored_reason == *reason && at == entry.at
                );
                if !matches_state || !released.insert(*reservation_id) {
                    return Err(ProviderError::CorruptState(format!(
                        "reservation-released audit entry disagrees with reservation {:?}",
                        record.id()
                    )));
                }
            }
            StoredAuditEvent::SigningCommitted {
                reservation_id,
                commitment,
            } => {
                let record = reservations.get(reservation_id).ok_or_else(|| {
                    ProviderError::CorruptState(
                        "signing-committed audit entry references a missing reservation".to_owned(),
                    )
                })?;
                let matches_state = matches!(
                    &record.state,
                    StoredReservationState::Committed { intent }
                        | StoredReservationState::Signed { intent, .. }
                        if intent.commitment == *commitment && intent.committed_at == entry.at
                );
                if !matches_state || !committed.insert(*reservation_id) {
                    return Err(ProviderError::CorruptState(format!(
                        "signing-committed audit entry disagrees with reservation {:?}",
                        record.id()
                    )));
                }
            }
            StoredAuditEvent::SignedArtifactStored {
                reservation_id,
                artifact,
            } => {
                let record = reservations.get(reservation_id).ok_or_else(|| {
                    ProviderError::CorruptState(
                        "signed-artifact audit entry references a missing reservation".to_owned(),
                    )
                })?;
                let matches_state = matches!(
                    &record.state,
                    StoredReservationState::Signed {
                        artifact: stored_artifact,
                        ..
                    } if stored_artifact.digest == *artifact && stored_artifact.signed_at == entry.at
                );
                if !matches_state || !signed.insert(*reservation_id) {
                    return Err(ProviderError::CorruptState(format!(
                        "signed-artifact audit entry disagrees with reservation {:?}",
                        record.id()
                    )));
                }
            }
        }
        previous_sequence = sequence;
        previous_time = Some(entry.at);
    }

    if previous_sequence != declared_sequence {
        return Err(ProviderError::CorruptState(format!(
            "audit sequence metadata is {declared_sequence}, but the log ends at {previous_sequence}"
        )));
    }
    for key in inventory.keys() {
        if !imported.contains(key) {
            return Err(ProviderError::CorruptState(
                "inventory record has no import audit entry".to_owned(),
            ));
        }
    }
    for (reservation_id, record) in reservations {
        if !created.contains(reservation_id) {
            return Err(ProviderError::CorruptState(format!(
                "reservation {:?} has no creation audit entry",
                record.id()
            )));
        }
        let audit_shape_is_valid = match record.state {
            StoredReservationState::Reserved => {
                !released.contains(reservation_id)
                    && !committed.contains(reservation_id)
                    && !signed.contains(reservation_id)
            }
            StoredReservationState::Released { .. } => {
                released.contains(reservation_id)
                    && !committed.contains(reservation_id)
                    && !signed.contains(reservation_id)
            }
            StoredReservationState::Committed { .. } => {
                !released.contains(reservation_id)
                    && committed.contains(reservation_id)
                    && !signed.contains(reservation_id)
            }
            StoredReservationState::Signed { .. } => {
                !released.contains(reservation_id)
                    && committed.contains(reservation_id)
                    && signed.contains(reservation_id)
            }
        };
        if !audit_shape_is_valid {
            return Err(ProviderError::CorruptState(format!(
                "reservation {:?} state disagrees with its audit history",
                record.id()
            )));
        }
    }
    Ok(())
}

fn decode_table_key<const LENGTH: usize>(
    table: &'static str,
    bytes: &[u8],
) -> Result<[u8; LENGTH], ProviderError> {
    bytes.try_into().map_err(|_| {
        ProviderError::CorruptState(format!(
            "{table} key has length {}, expected {LENGTH}",
            bytes.len()
        ))
    })
}

fn create_tables(write: &WriteTransaction) -> Result<(), ProviderError> {
    write.open_table(INVENTORY)?;
    write.open_table(ALLOCATIONS)?;
    write.open_table(RESERVATIONS)?;
    write.open_table(REQUEST_KEYS)?;
    write.open_table(EXPIRATIONS)?;
    write.open_table(AUDIT)?;
    Ok(())
}

fn write_record<T: Serialize>(
    write: &WriteTransaction,
    definition: TableDefinition<&[u8], &[u8]>,
    key: &[u8],
    value: &T,
) -> Result<(), ProviderError> {
    let encoded = encode_record(value)?;
    write
        .open_table(definition)?
        .insert(key, encoded.as_slice())?;
    Ok(())
}

fn read_record_from_write<T: DeserializeOwned>(
    write: &WriteTransaction,
    definition: TableDefinition<&[u8], &[u8]>,
    key: &[u8],
) -> Result<Option<T>, ProviderError> {
    let table = write.open_table(definition)?;
    table
        .get(key)?
        .map(|value| decode_record(value.value()))
        .transpose()
}

fn encode_record<T: Serialize>(value: &T) -> Result<Vec<u8>, ProviderError> {
    let mut encoded = Vec::with_capacity(64);
    encoded.push(RECORD_VERSION);
    encoded.extend(postcard::to_allocvec(value)?);
    Ok(encoded)
}

fn decode_record<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ProviderError> {
    let (&version, payload) = bytes.split_first().ok_or(ProviderError::EmptyRecord)?;
    if version != RECORD_VERSION {
        return Err(ProviderError::RecordVersionMismatch {
            expected: RECORD_VERSION,
            actual: version,
        });
    }
    let (value, trailing) = postcard::take_from_bytes(payload)?;
    if !trailing.is_empty() {
        return Err(ProviderError::TrailingRecordBytes(trailing.len()));
    }
    Ok(value)
}

fn outpoint_key(outpoint: OutPoint) -> [u8; 36] {
    let mut key = [0_u8; 36];
    key[..32].copy_from_slice(&outpoint.txid.to_byte_array());
    key[32..].copy_from_slice(&outpoint.vout.to_be_bytes());
    key
}

fn request_key(owner: OwnerId, key: IdempotencyKey) -> [u8; 64] {
    let mut encoded = [0_u8; 64];
    encoded[..32].copy_from_slice(&owner.to_bytes());
    encoded[32..].copy_from_slice(&key.to_bytes());
    encoded
}

fn expiration_key(deadline: UnixMillis, reservation_id: ReservationId) -> [u8; 40] {
    let mut key = [0_u8; 40];
    key[..8].copy_from_slice(&deadline.value().to_be_bytes());
    key[8..].copy_from_slice(&reservation_id.to_bytes());
    key
}

fn decode_expiration_key(bytes: &[u8]) -> Result<(UnixMillis, ReservationId), ProviderError> {
    let bytes: [u8; 40] = bytes
        .try_into()
        .map_err(|_| ProviderError::CorruptExpirationKey(bytes.len()))?;
    let deadline = u64::from_be_bytes(bytes[..8].try_into().expect("fixed slice"));
    let reservation_id = bytes[8..].try_into().expect("fixed slice");
    Ok((
        UnixMillis::new(deadline),
        ReservationId::new(reservation_id),
    ))
}

fn decode_u32(bytes: &[u8]) -> Result<u32, ()> {
    Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| ())?))
}

fn decode_u64(bytes: &[u8]) -> Result<u64, ()> {
    Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| ())?))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredProviderIdentity {
    provider: [u8; 32],
    genesis_hash: BlockHash,
    policy_asset: AssetId,
}

impl From<ProviderIdentity> for StoredProviderIdentity {
    fn from(value: ProviderIdentity) -> Self {
        Self {
            provider: value.provider().to_bytes(),
            genesis_hash: value.genesis_hash(),
            policy_asset: value.policy_asset(),
        }
    }
}

impl StoredProviderIdentity {
    fn to_domain(self) -> ProviderIdentity {
        ProviderIdentity::new(
            ProviderId::new(self.provider),
            self.genesis_hash,
            self.policy_asset,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredInventoryItem {
    outpoint: OutPoint,
    asset: AssetId,
    amount: u64,
}

impl From<InventoryItem> for StoredInventoryItem {
    fn from(value: InventoryItem) -> Self {
        Self {
            outpoint: value.outpoint(),
            asset: value.asset(),
            amount: value.amount(),
        }
    }
}

impl StoredInventoryItem {
    fn to_domain(self) -> Result<InventoryItem, ProviderError> {
        InventoryItem::new(self.outpoint, self.asset, self.amount).map_err(|error| {
            ProviderError::CorruptState(format!("invalid persisted inventory: {error}"))
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum StoredFeeSizeMetric {
    RegularVbytes,
    DiscountVbytes,
}

impl From<FeeSizeMetric> for StoredFeeSizeMetric {
    fn from(value: FeeSizeMetric) -> Self {
        match value {
            FeeSizeMetric::RegularVbytes => Self::RegularVbytes,
            FeeSizeMetric::DiscountVbytes => Self::DiscountVbytes,
        }
    }
}

impl StoredFeeSizeMetric {
    const fn to_domain(self) -> FeeSizeMetric {
        match self {
            Self::RegularVbytes => FeeSizeMetric::RegularVbytes,
            Self::DiscountVbytes => FeeSizeMetric::DiscountVbytes,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredFeePolicy {
    policy_asset: AssetId,
    minimum_sats_per_kvb: u64,
    minimum_absolute_fee: u64,
    maximum_transaction_weight: u64,
    size_metric: StoredFeeSizeMetric,
}

impl From<FeePolicy> for StoredFeePolicy {
    fn from(value: FeePolicy) -> Self {
        Self {
            policy_asset: value.policy_asset(),
            minimum_sats_per_kvb: value.minimum_sats_per_kvb(),
            minimum_absolute_fee: value.minimum_absolute_fee(),
            maximum_transaction_weight: value.maximum_transaction_weight(),
            size_metric: value.size_metric().into(),
        }
    }
}

impl StoredFeePolicy {
    fn to_domain(self) -> Result<FeePolicy, ProviderError> {
        FeePolicy::new(
            self.policy_asset,
            self.minimum_sats_per_kvb,
            self.minimum_absolute_fee,
            self.maximum_transaction_weight,
            self.size_metric.to_domain(),
        )
        .map_err(|error| {
            ProviderError::CorruptState(format!("invalid persisted fee policy: {error}"))
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredTransactionFee {
    policy_asset: AssetId,
    amount: u64,
    weight: u64,
    regular_vsize: u64,
    discount_vsize: u64,
}

impl From<TransactionFee> for StoredTransactionFee {
    fn from(value: TransactionFee) -> Self {
        Self {
            policy_asset: value.policy_asset(),
            amount: value.amount(),
            weight: value.weight(),
            regular_vsize: value.regular_vsize(),
            discount_vsize: value.discount_vsize(),
        }
    }
}

impl StoredTransactionFee {
    fn to_domain(self) -> Result<TransactionFee, ProviderError> {
        TransactionFee::new(
            self.policy_asset,
            self.amount,
            self.weight,
            self.regular_vsize,
            self.discount_vsize,
        )
        .map_err(|error| {
            ProviderError::CorruptState(format!("invalid persisted transaction fee: {error}"))
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum StoredAllocation {
    Reserved {
        reservation_id: [u8; 32],
    },
    Committed {
        reservation_id: [u8; 32],
        commitment: [u8; 32],
    },
}

impl StoredAllocation {
    const fn to_view(self) -> InventoryState {
        match self {
            Self::Reserved { reservation_id } => InventoryState::Reserved {
                reservation_id: ReservationId::new(reservation_id),
            },
            Self::Committed {
                reservation_id,
                commitment,
            } => InventoryState::Committed {
                reservation_id: ReservationId::new(reservation_id),
                commitment: SigningCommitment::new(commitment),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum StoredReleaseReason {
    Expired,
    ClientCancelled,
    ProviderRejected,
}

impl From<ReleaseReason> for StoredReleaseReason {
    fn from(value: ReleaseReason) -> Self {
        match value {
            ReleaseReason::Expired => Self::Expired,
            ReleaseReason::ClientCancelled => Self::ClientCancelled,
            ReleaseReason::ProviderRejected => Self::ProviderRejected,
        }
    }
}

impl StoredReleaseReason {
    const fn to_domain(self) -> ReleaseReason {
        match self {
            Self::Expired => ReleaseReason::Expired,
            Self::ClientCancelled => ReleaseReason::ClientCancelled,
            Self::ProviderRejected => ReleaseReason::ProviderRejected,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredSigningIntent {
    commitment: [u8; 32],
    pre_sign_payload: Vec<u8>,
    fee: StoredTransactionFee,
    committed_at: u64,
}

impl StoredSigningIntent {
    fn to_job(&self, reservation_id: ReservationId) -> Result<SigningJob, ProviderError> {
        validate_settlement_bytes(&self.pre_sign_payload).map_err(|error| {
            ProviderError::CorruptState(format!("invalid persisted signing payload: {error}"))
        })?;
        Ok(SigningJob {
            reservation_id,
            commitment: SigningCommitment::new(self.commitment),
            pre_sign_payload: self.pre_sign_payload.clone(),
            fee: self.fee.to_domain()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredSignedArtifact {
    digest: [u8; 32],
    bytes: Vec<u8>,
    signed_at: u64,
}

impl StoredSignedArtifact {
    fn to_domain(
        &self,
        reservation_id: ReservationId,
        commitment: SigningCommitment,
    ) -> Result<SignedArtifact, ProviderError> {
        validate_settlement_bytes(&self.bytes).map_err(|error| {
            ProviderError::CorruptState(format!("invalid persisted signed artifact: {error}"))
        })?;
        let expected = signed_artifact_digest(commitment, &self.bytes);
        if expected.to_bytes() != self.digest {
            return Err(ProviderError::CorruptState(
                "persisted signed artifact digest does not match its bytes".to_owned(),
            ));
        }
        Ok(SignedArtifact {
            reservation_id,
            commitment,
            digest: SignedArtifactDigest::new(self.digest),
            bytes: self.bytes.clone(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum StoredReservationState {
    Reserved,
    Released {
        reason: StoredReleaseReason,
        at: u64,
    },
    Committed {
        intent: StoredSigningIntent,
    },
    Signed {
        intent: StoredSigningIntent,
        artifact: StoredSignedArtifact,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredReservation {
    id: [u8; 32],
    owner: [u8; 32],
    idempotency_key: [u8; 32],
    request_digest: [u8; 32],
    quote_commitment: [u8; 32],
    outpoints: Vec<OutPoint>,
    created_at: u64,
    accept_before: u64,
    fee_policy: StoredFeePolicy,
    state: StoredReservationState,
}

impl StoredReservation {
    const fn id(&self) -> ReservationId {
        ReservationId::new(self.id)
    }

    fn validate(&self) -> Result<(), ProviderError> {
        if self.id()
            != derive_reservation_id(
                OwnerId::new(self.owner),
                IdempotencyKey::new(self.idempotency_key),
            )
        {
            return Err(ProviderError::CorruptState(
                "reservation ID does not match its owner and idempotency key".to_owned(),
            ));
        }
        if self.outpoints.is_empty() || self.outpoints.len() > MAX_RESERVATION_INPUTS {
            return Err(ProviderError::CorruptState(
                "reservation has an invalid outpoint count".to_owned(),
            ));
        }
        if self.accept_before <= self.created_at {
            return Err(ProviderError::CorruptState(
                "reservation deadline is not after its creation time".to_owned(),
            ));
        }
        for outpoint in &self.outpoints {
            if outpoint.is_null() || outpoint.vout & 0xc000_0000 != 0 {
                return Err(ProviderError::CorruptState(format!(
                    "reservation contains invalid outpoint {outpoint:?}"
                )));
            }
        }
        if self.outpoints.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ProviderError::CorruptState(
                "reservation outpoints are not strictly sorted".to_owned(),
            ));
        }
        let policy = self.fee_policy.to_domain()?;
        match &self.state {
            StoredReservationState::Committed { intent }
            | StoredReservationState::Signed { intent, .. } => {
                validate_settlement_bytes(&intent.pre_sign_payload).map_err(|error| {
                    ProviderError::CorruptState(format!(
                        "invalid persisted signing payload: {error}"
                    ))
                })?;
                let fee = intent.fee.to_domain()?;
                policy.validate(fee).map_err(|error| {
                    ProviderError::CorruptState(format!(
                        "persisted signing fee violates its policy: {error}"
                    ))
                })?;
                let expected = signing_commitment(self, &intent.pre_sign_payload, fee)?;
                if expected.to_bytes() != intent.commitment {
                    return Err(ProviderError::CorruptState(
                        "persisted signing commitment does not match its transcript".to_owned(),
                    ));
                }
            }
            StoredReservationState::Reserved | StoredReservationState::Released { .. } => {}
        }
        if let StoredReservationState::Signed { intent, artifact } = &self.state {
            artifact.to_domain(self.id(), SigningCommitment::new(intent.commitment))?;
        }
        Ok(())
    }

    fn to_view(&self) -> Result<ReservationView, ProviderError> {
        self.validate()?;
        let fee_policy = self.fee_policy.to_domain()?;
        let state = match &self.state {
            StoredReservationState::Reserved => ReservationState::Reserved,
            StoredReservationState::Released { reason, at } => ReservationState::Released {
                reason: reason.to_domain(),
                at: UnixMillis::new(*at),
            },
            StoredReservationState::Committed { intent } => ReservationState::Committed {
                commitment: SigningCommitment::new(intent.commitment),
                committed_at: UnixMillis::new(intent.committed_at),
            },
            StoredReservationState::Signed { intent, artifact } => ReservationState::Signed {
                commitment: SigningCommitment::new(intent.commitment),
                artifact: SignedArtifactDigest::new(artifact.digest),
                committed_at: UnixMillis::new(intent.committed_at),
                signed_at: UnixMillis::new(artifact.signed_at),
            },
        };
        Ok(ReservationView {
            id: self.id(),
            owner: OwnerId::new(self.owner),
            quote_commitment: QuoteCommitment::new(self.quote_commitment),
            outpoints: self.outpoints.clone(),
            created_at: UnixMillis::new(self.created_at),
            accept_before: UnixMillis::new(self.accept_before),
            fee_policy,
            state,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredRequestBinding {
    reservation_id: [u8; 32],
    request_digest: [u8; 32],
}

#[derive(Serialize)]
struct StoredRequestFingerprint<'a> {
    identity: StoredProviderIdentity,
    owner: [u8; 32],
    idempotency_key: [u8; 32],
    quote_commitment: [u8; 32],
    outpoints: &'a [OutPoint],
    accept_before: u64,
    fee_policy: StoredFeePolicy,
}

#[derive(Serialize)]
struct StoredSigningTranscript<'a> {
    request_digest: [u8; 32],
    reservation_id: [u8; 32],
    outpoints: Vec<OutPoint>,
    quote_commitment: [u8; 32],
    fee_policy: StoredFeePolicy,
    fee: StoredTransactionFee,
    pre_sign_payload: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredAuditEntry {
    sequence: u64,
    at: u64,
    event: StoredAuditEvent,
}

impl StoredAuditEntry {
    fn to_domain(&self) -> AuditEntry {
        AuditEntry {
            sequence: self.sequence,
            at: UnixMillis::new(self.at),
            event: self.event.to_domain(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum StoredAuditEvent {
    InventoryImported {
        outpoint: OutPoint,
    },
    ReservationCreated {
        reservation_id: [u8; 32],
        outpoints: Vec<OutPoint>,
    },
    ReservationReleased {
        reservation_id: [u8; 32],
        reason: StoredReleaseReason,
    },
    SigningCommitted {
        reservation_id: [u8; 32],
        commitment: [u8; 32],
    },
    SignedArtifactStored {
        reservation_id: [u8; 32],
        artifact: [u8; 32],
    },
}

impl StoredAuditEvent {
    fn to_domain(&self) -> AuditEvent {
        match self {
            Self::InventoryImported { outpoint } => AuditEvent::InventoryImported {
                outpoint: *outpoint,
            },
            Self::ReservationCreated {
                reservation_id,
                outpoints,
            } => AuditEvent::ReservationCreated {
                reservation_id: ReservationId::new(*reservation_id),
                outpoints: outpoints.clone(),
            },
            Self::ReservationReleased {
                reservation_id,
                reason,
            } => AuditEvent::ReservationReleased {
                reservation_id: ReservationId::new(*reservation_id),
                reason: reason.to_domain(),
            },
            Self::SigningCommitted {
                reservation_id,
                commitment,
            } => AuditEvent::SigningCommitted {
                reservation_id: ReservationId::new(*reservation_id),
                commitment: SigningCommitment::new(*commitment),
            },
            Self::SignedArtifactStored {
                reservation_id,
                artifact,
            } => AuditEvent::SignedArtifactStored {
                reservation_id: ReservationId::new(*reservation_id),
                artifact: SignedArtifactDigest::new(*artifact),
            },
        }
    }
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[cfg(test)]
    #[error("injected provider mutation failure at {0}")]
    InjectedMutationFailure(&'static str),
    #[error("redb database error: {0}")]
    Database(#[from] redb::DatabaseError),
    #[error("redb transaction error: {0}")]
    Transaction(#[from] redb::TransactionError),
    #[error("redb table error: {0}")]
    Table(#[from] redb::TableError),
    #[error("redb storage error: {0}")]
    Storage(#[from] redb::StorageError),
    #[error("redb commit error: {0}")]
    Commit(#[from] redb::CommitError),
    #[error("a prior commit was ambiguous; close and reopen the provider database")]
    DatabaseRequiresReopen,
    #[error("the provider operation lock was poisoned; close and reopen the provider database")]
    OperationLockPoisoned,
    #[error("redb durability configuration error: {0}")]
    Durability(#[from] redb::SetDurabilityError),
    #[error("record codec error: {0}")]
    Codec(#[from] postcard::Error),
    #[error("schema version has an invalid encoding")]
    CorruptSchemaVersion,
    #[error("schema mismatch: expected {expected}, found {actual}")]
    SchemaMismatch { expected: u32, actual: u32 },
    #[error("required metadata is missing: {0}")]
    MissingMetadata(&'static str),
    #[error("provider database identity mismatch: database has {expected:?}, requested {actual:?}")]
    ProviderIdentityMismatch {
        expected: Box<ProviderIdentity>,
        actual: Box<ProviderIdentity>,
    },
    #[error("persisted record is empty")]
    EmptyRecord,
    #[error("record version mismatch: expected {expected}, found {actual}")]
    RecordVersionMismatch { expected: u8, actual: u8 },
    #[error("persisted record has {0} trailing bytes from an incompatible shape")]
    TrailingRecordBytes(usize),
    #[error("persisted clock high-water mark is corrupt")]
    CorruptTimeHighWatermark,
    #[error("clock moved backwards from {previous:?} to {now:?}")]
    ClockRegression {
        previous: UnixMillis,
        now: UnixMillis,
    },
    #[error("persisted audit sequence is corrupt")]
    CorruptAuditSequence,
    #[error("audit sequence overflowed")]
    AuditSequenceOverflow,
    #[error("expiration index key has length {0}, expected 40")]
    CorruptExpirationKey(usize),
    #[error("provider state is internally inconsistent: {0}")]
    CorruptState(String),
    #[error("fee policy uses {actual}, expected provider policy asset {expected}")]
    WrongPolicyAsset { expected: AssetId, actual: AssetId },
    #[error("inventory outpoint is unknown: {0:?}")]
    UnknownInventory(OutPoint),
    #[error("inventory metadata conflicts at {outpoint:?}")]
    InventoryMetadataConflict { outpoint: OutPoint },
    #[error("outpoint {outpoint:?} is unavailable: {state:?}")]
    OutpointUnavailable {
        outpoint: OutPoint,
        state: InventoryState,
    },
    #[error("idempotency key {key:?} for owner {owner:?} was reused with different terms")]
    IdempotencyConflict { owner: OwnerId, key: IdempotencyKey },
    #[error("derived reservation ID collided: {0:?}")]
    ReservationIdCollision(ReservationId),
    #[error("reservation deadline {accept_before:?} elapsed at {now:?}")]
    ReservationDeadlineElapsed {
        accept_before: UnixMillis,
        now: UnixMillis,
    },
    #[error("reservation not found: {0:?}")]
    ReservationNotFound(ReservationId),
    #[error("reservation owner authentication failed: {0:?}")]
    ReservationOwnerMismatch(ReservationId),
    #[error("reservation is already released: {0:?}")]
    ReservationAlreadyReleased(ReservationId),
    #[error("reservation crossed the irreversible signing point: {0:?}")]
    PointOfNoReturn(ReservationId),
    #[error("reservation is already committed to a different signing intent: {0:?}")]
    DifferentSigningIntent(ReservationId),
    #[error("settlement payload must not be empty")]
    EmptySettlementPayload,
    #[error("settlement payload has {actual} bytes; maximum is {maximum}")]
    SettlementPayloadTooLarge { maximum: usize, actual: usize },
    #[error("reservation has not committed a signing intent: {0:?}")]
    SigningIntentNotCommitted(ReservationId),
    #[error(
        "reservation {reservation_id:?} expects signing commitment {expected:?}, got {actual:?}"
    )]
    SigningCommitmentMismatch {
        reservation_id: ReservationId,
        expected: SigningCommitment,
        actual: SigningCommitment,
    },
    #[error("reservation already stored a different signed artifact: {0:?}")]
    DifferentSignedArtifact(ReservationId),
    #[error("fee policy rejected the final transaction: {0}")]
    FeePolicy(#[from] FeePolicyViolation),
}

#[cfg(test)]
mod tests;

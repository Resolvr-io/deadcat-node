use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use elements::hashes::Hash as _;
use elements::secp256k1_zkp::{Secp256k1, XOnlyPublicKey};
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
    InventoryBinding, InventoryItem, InventoryState, InventoryView, MAX_RESERVATION_INPUTS,
    MAX_SETTLEMENT_BYTES, OwnerId, ProviderId, ProviderIdentity, QuoteCommitment, RecoveryAction,
    ReleaseReason, ReservationAccess, ReservationId, ReservationPlan, ReservationState,
    ReservationView, SignedArtifact, SignedArtifactDigest, SigningCommitment, SigningJob,
    SigningTarget, TransactionFee, UnixMillis, WalletKeyLocator,
};
use crate::quote::{
    FirmQuote, FirmQuoteDraft, FirmQuoteOutcome, FirmQuoteRequest, PricingDecision,
    QuoteContribution, QuoteEnginePolicy, QuoteExecution, QuoteOutputRole, QuoteSnapshotEvidence,
    QuotedProviderInput, finalize_quote, quote_from_stored_parts, quote_outcome,
    recompute_quote_commitment, recovery_metadata_commitment,
};
use crate::wallet::recompute_inventory_binding;

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
const LIVE_QUOTES_BY_OWNER: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("live_quotes_by_owner");
const AUDIT: TableDefinition<u64, &[u8]> = TableDefinition::new("audit");

const SCHEMA_VERSION_KEY: &str = "schema_version";
const PROVIDER_IDENTITY_KEY: &str = "provider_identity";
const LAST_OBSERVED_TIME_KEY: &str = "last_observed_unix_millis";
const AUDIT_SEQUENCE_KEY: &str = "audit_sequence";
const ALLOCATION_REVISION_KEY: &str = "allocation_revision";

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
    #[cfg(test)]
    pub(crate) fn import_inventory<C: Clock>(
        &self,
        item: InventoryItem,
        clock: &C,
    ) -> Result<bool, ProviderError> {
        Ok(self.import_inventory_batch(&[item], clock)? == 1)
    }

    /// Atomically import one complete wallet discovery set. Every item is
    /// validated against existing immutable metadata before any item is added.
    pub(crate) fn import_inventory_batch<C: Clock>(
        &self,
        items: &[InventoryItem],
        clock: &C,
    ) -> Result<usize, ProviderError> {
        let mut unique = BTreeSet::new();
        for item in items {
            if !unique.insert(item.outpoint()) {
                return Err(ProviderError::DuplicateInventoryOutpoint(item.outpoint()));
            }
        }
        let (_operation_guard, write, now) = self.begin_timed_write(clock)?;
        let mut pending = Vec::new();
        for item in items {
            let key = outpoint_key(item.outpoint());
            let stored = StoredInventoryItem::from(*item);
            if let Some(existing) = read_record_from_write(&write, INVENTORY, &key)? {
                let existing: StoredInventoryItem = existing;
                if existing != stored {
                    return Err(ProviderError::InventoryMetadataConflict {
                        outpoint: item.outpoint(),
                    });
                }
            } else {
                pending.push((key, stored));
            }
        }
        for (key, stored) in &pending {
            write_record(&write, INVENTORY, key, stored)?;
            append_audit(
                &write,
                now,
                StoredAuditEvent::InventoryImported {
                    outpoint: stored.outpoint,
                },
            )?;
        }
        self.commit_write(write)?;
        Ok(pending.len())
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

    /// Read only the requested durable inventory records and the allocation
    /// CAS token from one database snapshot.
    ///
    /// Durable inventory history is append-only, while a wallet snapshot is
    /// explicitly bounded. Point-reading the current snapshot prevents quote
    /// admission cost from growing with the provider's lifetime output history.
    pub(crate) fn inventory_state_for(
        &self,
        outpoints: &[OutPoint],
    ) -> Result<(Vec<InventoryView>, u64), ProviderError> {
        self.ensure_healthy()?;
        if outpoints.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ProviderError::CorruptState(
                "inventory-state lookup outpoints are not strictly sorted".to_owned(),
            ));
        }
        let read = self.database.begin_read()?;
        let inventory = read.open_table(INVENTORY)?;
        let allocations = read.open_table(ALLOCATIONS)?;
        let mut result = Vec::with_capacity(outpoints.len());
        for outpoint in outpoints {
            let key = outpoint_key(*outpoint);
            let item = inventory.get(key.as_slice())?.ok_or_else(|| {
                ProviderError::CorruptState(format!(
                    "published wallet output {outpoint:?} has no durable inventory record"
                ))
            })?;
            let item: StoredInventoryItem = decode_record(item.value())?;
            let domain = item.to_domain()?;
            if domain.outpoint() != *outpoint {
                return Err(ProviderError::CorruptState(format!(
                    "inventory key does not match requested outpoint {outpoint:?}"
                )));
            }
            let state = allocations
                .get(key.as_slice())?
                .map(|allocation| decode_record::<StoredAllocation>(allocation.value()))
                .transpose()?
                .map_or(InventoryState::Available, StoredAllocation::to_view);
            result.push(InventoryView::new(domain, state));
        }
        let meta = read.open_table(META)?;
        let revision = meta
            .get(ALLOCATION_REVISION_KEY)?
            .ok_or(ProviderError::MissingMetadata(ALLOCATION_REVISION_KEY))?;
        let revision =
            decode_u64(revision.value()).map_err(|()| ProviderError::CorruptAllocationRevision)?;
        Ok((result, revision))
    }

    /// Replay an exact request or preflight capacity before any pricing,
    /// inventory selection, or destination generation occurs.
    ///
    /// The bounded expiry cleanup is committed even when the caller is still
    /// over quota. That makes a backlog monotonically drain under ordinary
    /// quote traffic instead of rolling cleanup back with an admission error.
    pub(crate) fn preflight_firm_quote<C: Clock>(
        &self,
        owner: OwnerId,
        key: IdempotencyKey,
        request_digest: crate::model::QuoteRequestDigest,
        policy: QuoteEnginePolicy,
        clock: &C,
    ) -> Result<Option<FirmQuoteOutcome>, ProviderError> {
        let (_operation_guard, write, now) = self.begin_timed_write(clock)?;
        if let Some(binding) = read_request_binding(&write, owner, key)? {
            if binding.semantic_request_digest != request_digest.to_bytes() {
                return Err(ProviderError::IdempotencyConflict { owner, key });
            }
            let record = replay_binding_in_write(&write, binding, now)?;
            let outcome = record.to_firm_quote_outcome(self.identity, false)?;
            self.commit_write(write)?;
            return Ok(Some(outcome));
        }

        expire_due_in_write(&write, now, MAX_EXPIRATION_BATCH)?;
        match enforce_live_quote_limits(&write, owner, policy, now) {
            Ok(()) => {
                self.commit_write(write)?;
                Ok(None)
            }
            Err(
                error @ (ProviderError::OwnerLiveQuoteLimit { .. }
                | ProviderError::GlobalLiveQuoteLimit { .. }),
            ) => {
                self.commit_write(write)?;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    /// Replay a request that may have won after quote preflight but before the
    /// caller acquired the inventory-snapshot lock.
    pub(crate) fn replay_firm_quote<C: Clock>(
        &self,
        owner: OwnerId,
        key: IdempotencyKey,
        request_digest: crate::model::QuoteRequestDigest,
        clock: &C,
    ) -> Result<Option<FirmQuoteOutcome>, ProviderError> {
        let (_operation_guard, write, now) = self.begin_timed_write(clock)?;
        let Some(binding) = read_request_binding(&write, owner, key)? else {
            self.commit_write(write)?;
            return Ok(None);
        };
        if binding.semantic_request_digest != request_digest.to_bytes() {
            return Err(ProviderError::IdempotencyConflict { owner, key });
        }
        let record = replay_binding_in_write(&write, binding, now)?;
        let outcome = record.to_firm_quote_outcome(self.identity, false)?;
        self.commit_write(write)?;
        Ok(Some(outcome))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reserve_firm_quote_from_snapshot<C: Clock>(
        &self,
        owner: OwnerId,
        key: IdempotencyKey,
        semantic_request_digest: crate::model::QuoteRequestDigest,
        draft: &FirmQuoteDraft,
        policy: QuoteEnginePolicy,
        snapshot_observed_at: UnixMillis,
        maximum_snapshot_age_millis: u64,
        clock: &C,
    ) -> Result<FirmQuoteOutcome, ProviderError> {
        if policy.fee_policy().policy_asset() != self.identity.policy_asset() {
            return Err(ProviderError::WrongPolicyAsset {
                expected: self.identity.policy_asset(),
                actual: policy.fee_policy().policy_asset(),
            });
        }
        let reservation_id = derive_reservation_id(owner, key);
        let (_operation_guard, write, now) = self.begin_timed_write(clock)?;
        if let Some(binding) = read_request_binding(&write, owner, key)? {
            if binding.semantic_request_digest != semantic_request_digest.to_bytes() {
                return Err(ProviderError::IdempotencyConflict { owner, key });
            }
            let record = replay_binding_in_write(&write, binding, now)?;
            let outcome = record.to_firm_quote_outcome(self.identity, false)?;
            self.commit_write(write)?;
            return Ok(outcome);
        }
        if now < snapshot_observed_at {
            self.commit_write(write)?;
            return Err(ProviderError::InventorySnapshotObservedInFuture {
                observed_at: snapshot_observed_at,
                now,
            });
        }
        if now.value() - snapshot_observed_at.value() >= maximum_snapshot_age_millis {
            self.commit_write(write)?;
            return Err(ProviderError::InventorySnapshotStale {
                observed_at: snapshot_observed_at,
                now,
                maximum_age_millis: maximum_snapshot_age_millis,
            });
        }
        let current_allocation_revision = allocation_revision(&write)?;
        if current_allocation_revision != draft.snapshot.allocation_revision() {
            return Err(ProviderError::EligibleInventoryChanged);
        }
        let accept_before = UnixMillis::new(
            now.value()
                .checked_add(policy.quote_lifetime_millis())
                .ok_or(ProviderError::QuoteDeadlineOverflow)?,
        );
        let derived_request_digest =
            crate::quote::quote_request_digest(self.identity, owner, key, &draft.request)?;
        if derived_request_digest != semantic_request_digest {
            return Err(ProviderError::FirmQuoteRequestDigestMismatch);
        }
        let outpoints = draft.selected_outpoints();
        if read_reservation_from_write(&write, reservation_id)?.is_some() {
            return Err(ProviderError::ReservationIdCollision(reservation_id));
        }
        for outpoint in &outpoints {
            let key = outpoint_key(*outpoint);
            let item = read_record_from_write::<StoredInventoryItem>(&write, INVENTORY, &key)?
                .ok_or(ProviderError::UnknownInventory(*outpoint))?;
            let quoted_input = draft
                .contribution
                .inputs()
                .iter()
                .find(|input| input.outpoint() == *outpoint)
                .ok_or(ProviderError::FirmQuoteInventoryMismatch(*outpoint))?;
            if item.asset != draft.selected_asset
                || item.binding != quoted_input.inventory_binding().to_bytes()
            {
                return Err(ProviderError::FirmQuoteInventoryMismatch(*outpoint));
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
        if let Err(error) = enforce_live_quote_limits(&write, owner, policy, now) {
            // Preflight is advisory: another request may consume the final
            // slot before this authoritative allocation. Preserve bounded
            // expiry progress even when that race loses at the quota gate.
            if matches!(
                error,
                ProviderError::OwnerLiveQuoteLimit { .. }
                    | ProviderError::GlobalLiveQuoteLimit { .. }
            ) {
                self.commit_write(write)?;
            }
            return Err(error);
        }
        let quote = finalize_quote(
            self.identity,
            owner,
            key,
            semantic_request_digest,
            reservation_id,
            draft,
            now,
            accept_before,
            policy.fee_policy(),
        )?;
        let plan = ReservationPlan::with_request_digest(
            owner,
            key,
            semantic_request_digest,
            quote.commitment(),
            outpoints,
            accept_before,
            policy.fee_policy(),
        )
        .map_err(|error| {
            ProviderError::CorruptState(format!(
                "firm quote produced an invalid reservation plan: {error}"
            ))
        })?;
        let request_digest = request_digest(self.identity, &plan)?;
        let record = StoredReservation {
            id: reservation_id.to_bytes(),
            owner: owner.to_bytes(),
            idempotency_key: key.to_bytes(),
            semantic_request_digest: semantic_request_digest.to_bytes(),
            request_digest,
            quote_commitment: quote.commitment().to_bytes(),
            quote: Some(StoredFirmQuote::from_domain(&quote, draft)),
            outpoints: plan.outpoints().to_vec(),
            created_at: now.value(),
            accept_before: accept_before.value(),
            fee_policy: StoredFeePolicy::from(policy.fee_policy()),
            state: StoredReservationState::Reserved,
        };
        // Validate the exact durable representation before exposing a quote.
        // Replay and startup perform the same check, but doing it before the
        // first commit prevents an internal construction regression from
        // returning a quote that would make the database unreopenable.
        record.validate()?;
        let persisted_quote = record
            .quote
            .as_ref()
            .ok_or(ProviderError::FirmQuoteDraftInvalid)?;
        let validated_quote = persisted_quote.to_domain(self.identity, &record)?;
        let mut validated_selected_amount = 0_u64;
        for quoted_input in validated_quote.contribution().inputs() {
            let item = read_record_from_write::<StoredInventoryItem>(
                &write,
                INVENTORY,
                &outpoint_key(quoted_input.outpoint()),
            )?
            .ok_or(ProviderError::UnknownInventory(quoted_input.outpoint()))?;
            let domain_item = item.to_domain()?;
            if item.asset != persisted_quote.selected_asset
                || item.binding != quoted_input.inventory_binding().to_bytes()
                || recompute_inventory_binding(domain_item, quoted_input.witness_utxo())
                    != quoted_input.inventory_binding()
            {
                return Err(ProviderError::FirmQuoteInventoryMismatch(
                    quoted_input.outpoint(),
                ));
            }
            validated_selected_amount = validated_selected_amount
                .checked_add(item.amount)
                .ok_or(ProviderError::FirmQuoteDraftInvalid)?;
        }
        if validated_selected_amount != persisted_quote.selected_amount {
            return Err(ProviderError::FirmQuoteDraftInvalid);
        }
        persist_new_reservation(&write, &record)?;
        let reservation = record.to_view()?;
        self.commit_write(write)?;
        Ok(quote_outcome(quote, reservation, true))
    }

    /// Whether this exact authenticated request already has a durable binding.
    ///
    /// The wallet coordinator uses this read-only check to preserve idempotent
    /// retries even when the discovery snapshot used by the original request
    /// has since been superseded. A positive result must still be passed to
    /// [`Self::reserve`] so deadline expiry and state replay happen atomically.
    #[cfg(test)]
    pub(crate) fn has_matching_request(
        &self,
        plan: &ReservationPlan,
    ) -> Result<bool, ProviderError> {
        self.ensure_healthy()?;
        if plan.fee_policy().policy_asset() != self.identity.policy_asset() {
            return Err(ProviderError::WrongPolicyAsset {
                expected: self.identity.policy_asset(),
                actual: plan.fee_policy().policy_asset(),
            });
        }
        let read = self.database.begin_read()?;
        let request_keys = read.open_table(REQUEST_KEYS)?;
        let key = request_key(plan.owner(), plan.idempotency_key());
        let Some(binding) = request_keys.get(key.as_slice())? else {
            return Ok(false);
        };
        let binding: StoredRequestBinding = decode_record(binding.value())?;
        let expected_digest = request_digest(self.identity, plan)?;
        if binding.request_digest != expected_digest {
            return Err(ProviderError::IdempotencyConflict {
                owner: plan.owner(),
                key: plan.idempotency_key(),
            });
        }
        drop(request_keys);
        let reservations = read.open_table(RESERVATIONS)?;
        let record = reservations
            .get(binding.reservation_id.as_slice())?
            .ok_or_else(|| {
                ProviderError::CorruptState(
                    "idempotency binding references a missing reservation".to_owned(),
                )
            })?;
        let record: StoredReservation = decode_record(record.value())?;
        if record.id != binding.reservation_id || record.request_digest != binding.request_digest {
            return Err(ProviderError::CorruptState(
                "idempotency binding disagrees with its reservation".to_owned(),
            ));
        }
        record.validate()?;
        Ok(true)
    }

    /// Atomically reserve every requested outpoint or none of them.
    ///
    /// The clock is sampled after acquiring redb's serial writer, so a request
    /// queued behind another writer cannot commit using a stale pre-lock time.
    #[cfg(test)]
    pub(crate) fn reserve<C: Clock>(
        &self,
        plan: &ReservationPlan,
        clock: &C,
    ) -> Result<ReserveOutcome, ProviderError> {
        self.reserve_inner(plan, clock, None)
    }

    /// Reserve from one wallet snapshot, rechecking its exclusive freshness
    /// deadline using the same post-writer-lock observation as the quote
    /// deadline and durable allocation.
    #[cfg(test)]
    pub(crate) fn reserve_from_snapshot<C: Clock>(
        &self,
        plan: &ReservationPlan,
        snapshot_observed_at: UnixMillis,
        maximum_snapshot_age_millis: u64,
        clock: &C,
    ) -> Result<ReserveOutcome, ProviderError> {
        self.reserve_inner(
            plan,
            clock,
            Some((snapshot_observed_at, maximum_snapshot_age_millis)),
        )
    }

    #[cfg(test)]
    fn reserve_inner<C: Clock>(
        &self,
        plan: &ReservationPlan,
        clock: &C,
        snapshot_freshness: Option<(UnixMillis, u64)>,
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

        if let Some((observed_at, maximum_age_millis)) = snapshot_freshness {
            if now < observed_at {
                self.commit_write(write)?;
                return Err(ProviderError::InventorySnapshotObservedInFuture { observed_at, now });
            }
            if now.value() - observed_at.value() >= maximum_age_millis {
                self.commit_write(write)?;
                return Err(ProviderError::InventorySnapshotStale {
                    observed_at,
                    now,
                    maximum_age_millis,
                });
            }
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
            semantic_request_digest: plan.request_digest().to_bytes(),
            request_digest,
            quote_commitment: plan.quote_commitment().to_bytes(),
            quote: None,
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
            semantic_request_digest: plan.request_digest().to_bytes(),
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
        advance_allocation_revision(&write)?;
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
                let proposed =
                    signing_commitment(&record, &pre_sign_payload, fee, &intent.targets)?;
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
                let proposed =
                    signing_commitment(&record, &pre_sign_payload, fee, &intent.targets)?;
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
        let targets = signing_targets_for_reservation(&write, &record)?;
        let commitment = signing_commitment(&record, &pre_sign_payload, fee, &targets)?;
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
            targets,
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
        advance_allocation_revision(&write)?;
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
        remove_live_quote_index(&write, &record)?;
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
                if meta.get(ALLOCATION_REVISION_KEY)?.is_none() {
                    return Err(ProviderError::MissingMetadata(ALLOCATION_REVISION_KEY));
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
                meta.insert(ALLOCATION_REVISION_KEY, 0_u64.to_be_bytes().as_slice())?;
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

    #[cfg(test)]
    pub(crate) fn poison_inventory_record_for_test(
        &self,
        outpoint: OutPoint,
    ) -> Result<(), ProviderError> {
        let _operation_guard = self
            .operation_lock
            .lock()
            .map_err(|_| ProviderError::OperationLockPoisoned)?;
        let write = self.begin_immediate_write()?;
        {
            let mut inventory = write.open_table(INVENTORY)?;
            let key = outpoint_key(outpoint);
            inventory.insert(key.as_slice(), &[0xff_u8][..])?;
        }
        self.commit_write(write)
    }
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReserveOutcome {
    reservation: ReservationView,
    created: bool,
}

#[cfg(test)]
impl ReserveOutcome {
    #[must_use]
    pub(crate) const fn reservation(&self) -> &ReservationView {
        &self.reservation
    }

    #[must_use]
    pub(crate) const fn created(&self) -> bool {
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
#[cfg(test)]
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
    advance_allocation_revision(write)?;
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
    remove_live_quote_index(write, record)?;
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

fn remove_live_quote_index(
    write: &WriteTransaction,
    record: &StoredReservation,
) -> Result<(), ProviderError> {
    let removed = write
        .open_table(LIVE_QUOTES_BY_OWNER)?
        .remove(
            live_quote_key(
                UnixMillis::new(record.accept_before),
                OwnerId::new(record.owner),
                record.id(),
            )
            .as_slice(),
        )?
        .is_some();
    if record.quote.is_some() && !removed {
        return Err(ProviderError::CorruptState(
            "reserved firm quote has no owner live-quote index entry".to_owned(),
        ));
    }
    if record.quote.is_none() && removed {
        return Err(ProviderError::CorruptState(
            "legacy reservation unexpectedly owns a firm-quote live index entry".to_owned(),
        ));
    }
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

fn replay_binding_in_write(
    write: &WriteTransaction,
    binding: StoredRequestBinding,
    now: UnixMillis,
) -> Result<StoredReservation, ProviderError> {
    let mut record =
        read_reservation_from_write(write, ReservationId::new(binding.reservation_id))?
            .ok_or_else(|| {
                ProviderError::CorruptState(
                    "idempotency binding references a missing reservation".to_owned(),
                )
            })?;
    if record.id != binding.reservation_id
        || record.semantic_request_digest != binding.semantic_request_digest
        || record.request_digest != binding.request_digest
    {
        return Err(ProviderError::CorruptState(
            "idempotency binding disagrees with its reservation".to_owned(),
        ));
    }
    if matches!(record.state, StoredReservationState::Reserved)
        && now >= UnixMillis::new(record.accept_before)
    {
        release_reserved(write, &mut record, ReleaseReason::Expired, now)?;
    }
    Ok(record)
}

fn enforce_live_quote_limits(
    write: &WriteTransaction,
    owner: OwnerId,
    policy: QuoteEnginePolicy,
    now: UnixMillis,
) -> Result<(), ProviderError> {
    let live = write.open_table(LIVE_QUOTES_BY_OWNER)?;
    let Some(first_deadline) = now.value().checked_add(1) else {
        return Ok(());
    };
    let first = live_quote_key(
        UnixMillis::new(first_deadline),
        OwnerId::new([0; 32]),
        ReservationId::new([0; 32]),
    );
    let mut global_live = 0_usize;
    let mut owner_live = 0_usize;
    for entry in live.range(first.as_slice()..)? {
        let (key, value) = entry?;
        let (deadline, indexed_owner, _) = decode_live_quote_key(key.value())?;
        if deadline <= now || !value.value().is_empty() {
            return Err(ProviderError::CorruptState(
                "owner live-quote index contains an invalid entry".to_owned(),
            ));
        }
        global_live = global_live
            .checked_add(1)
            .ok_or(ProviderError::LiveQuoteCountOverflow)?;
        if indexed_owner == owner {
            owner_live = owner_live
                .checked_add(1)
                .ok_or(ProviderError::LiveQuoteCountOverflow)?;
            if owner_live >= policy.maximum_live_quotes_per_owner() {
                return Err(ProviderError::OwnerLiveQuoteLimit {
                    owner,
                    maximum: policy.maximum_live_quotes_per_owner(),
                });
            }
        }
        if global_live >= policy.maximum_live_quotes_global() {
            return Err(ProviderError::GlobalLiveQuoteLimit {
                maximum: policy.maximum_live_quotes_global(),
            });
        }
    }
    Ok(())
}

fn persist_new_reservation(
    write: &WriteTransaction,
    record: &StoredReservation,
) -> Result<(), ProviderError> {
    write_record(write, RESERVATIONS, &record.id, record)?;
    #[cfg(test)]
    mutation_failpoints::hit(mutation_failpoints::RESERVE_AFTER_RECORD)?;
    write_record(
        write,
        REQUEST_KEYS,
        &request_key(
            OwnerId::new(record.owner),
            IdempotencyKey::new(record.idempotency_key),
        ),
        &StoredRequestBinding {
            reservation_id: record.id,
            semantic_request_digest: record.semantic_request_digest,
            request_digest: record.request_digest,
        },
    )?;
    #[cfg(test)]
    mutation_failpoints::hit(mutation_failpoints::RESERVE_AFTER_REQUEST_KEY)?;
    for outpoint in &record.outpoints {
        write_record(
            write,
            ALLOCATIONS,
            &outpoint_key(*outpoint),
            &StoredAllocation::Reserved {
                reservation_id: record.id,
            },
        )?;
        #[cfg(test)]
        mutation_failpoints::hit(mutation_failpoints::RESERVE_AFTER_ALLOCATION)?;
    }
    advance_allocation_revision(write)?;
    let empty: &[u8] = &[];
    write.open_table(EXPIRATIONS)?.insert(
        expiration_key(UnixMillis::new(record.accept_before), record.id()).as_slice(),
        empty,
    )?;
    write.open_table(LIVE_QUOTES_BY_OWNER)?.insert(
        live_quote_key(
            UnixMillis::new(record.accept_before),
            OwnerId::new(record.owner),
            record.id(),
        )
        .as_slice(),
        empty,
    )?;
    #[cfg(test)]
    mutation_failpoints::hit(mutation_failpoints::RESERVE_AFTER_EXPIRATION)?;
    append_audit(
        write,
        UnixMillis::new(record.created_at),
        StoredAuditEvent::ReservationCreated {
            reservation_id: record.id,
            outpoints: record.outpoints.clone(),
        },
    )?;
    #[cfg(test)]
    mutation_failpoints::hit(mutation_failpoints::RESERVE_AFTER_AUDIT)?;
    Ok(())
}

fn signing_targets_for_reservation(
    write: &WriteTransaction,
    reservation: &StoredReservation,
) -> Result<Vec<StoredSigningTarget>, ProviderError> {
    let mut targets = Vec::with_capacity(reservation.outpoints.len());
    for outpoint in &reservation.outpoints {
        let key = outpoint_key(*outpoint);
        let inventory = read_record_from_write::<StoredInventoryItem>(write, INVENTORY, &key)?
            .ok_or_else(|| {
                ProviderError::CorruptState(format!(
                    "reserved outpoint {outpoint:?} has no inventory metadata"
                ))
            })?;
        // Decode through the domain constructor before handing any persisted
        // locator or key material to a signer.
        inventory.to_domain()?;
        targets.push(StoredSigningTarget::from_inventory(inventory));
    }
    Ok(targets)
}

fn signing_commitment(
    reservation: &StoredReservation,
    pre_sign_payload: &[u8],
    fee: TransactionFee,
    targets: &[StoredSigningTarget],
) -> Result<SigningCommitment, ProviderError> {
    let transcript = StoredSigningTranscript {
        request_digest: reservation.request_digest,
        reservation_id: reservation.id,
        outpoints: reservation.outpoints.clone(),
        quote_commitment: reservation.quote_commitment,
        fee_policy: reservation.fee_policy,
        fee: StoredTransactionFee::from(fee),
        targets,
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
        semantic_request_digest: plan.request_digest().to_bytes(),
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
        semantic_request_digest: reservation.semantic_request_digest,
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

fn allocation_revision(write: &WriteTransaction) -> Result<u64, ProviderError> {
    let meta = write.open_table(META)?;
    let revision = meta
        .get(ALLOCATION_REVISION_KEY)?
        .ok_or(ProviderError::MissingMetadata(ALLOCATION_REVISION_KEY))?;
    decode_u64(revision.value()).map_err(|()| ProviderError::CorruptAllocationRevision)
}

fn advance_allocation_revision(write: &WriteTransaction) -> Result<u64, ProviderError> {
    let current = allocation_revision(write)?;
    let next = current
        .checked_add(1)
        .ok_or(ProviderError::AllocationRevisionOverflow)?;
    write
        .open_table(META)?
        .insert(ALLOCATION_REVISION_KEY, next.to_be_bytes().as_slice())?;
    Ok(next)
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
        LIVE_QUOTES_BY_OWNER,
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
    let (audit_sequence, last_observed_time, _allocation_revision) = {
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
        let allocation_revision = meta
            .get(ALLOCATION_REVISION_KEY)?
            .ok_or(ProviderError::MissingMetadata(ALLOCATION_REVISION_KEY))?;
        let allocation_revision = decode_u64(allocation_revision.value())
            .map_err(|()| ProviderError::CorruptAllocationRevision)?;
        (audit_sequence, last_observed_time, allocation_revision)
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
            if let Some(quote) = &record.quote {
                let domain = quote.to_domain(identity, &record)?;
                let mut selected_amount = 0_u64;
                for quoted_input in domain.contribution().inputs() {
                    let item = inventory
                        .get(&outpoint_key(quoted_input.outpoint()))
                        .ok_or_else(|| {
                            ProviderError::CorruptState(
                                "firm quote references missing durable inventory".to_owned(),
                            )
                        })?;
                    if item.asset != quote.selected_asset
                        || item.binding != quoted_input.inventory_binding().to_bytes()
                    {
                        return Err(ProviderError::CorruptState(
                            "firm quote input disagrees with durable inventory".to_owned(),
                        ));
                    }
                    let domain_item = item.to_domain()?;
                    if recompute_inventory_binding(domain_item, quoted_input.witness_utxo())
                        != quoted_input.inventory_binding()
                    {
                        return Err(ProviderError::CorruptState(
                            "firm quote input binding does not match durable recovery metadata"
                                .to_owned(),
                        ));
                    }
                    selected_amount =
                        selected_amount.checked_add(item.amount).ok_or_else(|| {
                            ProviderError::CorruptState(
                                "firm quote selected amount overflowed".to_owned(),
                            )
                        })?;
                }
                if selected_amount != quote.selected_amount {
                    return Err(ProviderError::CorruptState(
                        "firm quote selected amount disagrees with durable inventory".to_owned(),
                    ));
                }
            }
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

    let live_quotes = {
        let table = write.open_table(LIVE_QUOTES_BY_OWNER)?;
        let mut keys = BTreeSet::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let key = decode_table_key::<72>("owner live quote", key.value())?;
            if !value.value().is_empty() {
                return Err(ProviderError::CorruptState(
                    "owner live-quote index value is not empty".to_owned(),
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
        if binding.reservation_id != record.id
            || binding.semantic_request_digest != record.semantic_request_digest
            || binding.request_digest != record.request_digest
        {
            return Err(ProviderError::CorruptState(format!(
                "reservation {:?} request-key binding disagrees with its record",
                record.id()
            )));
        }

        let expected_expiration =
            expiration_key(UnixMillis::new(record.accept_before), record.id());
        let has_expiration = expirations.contains(&expected_expiration);
        let expected_live_quote = live_quote_key(
            UnixMillis::new(record.accept_before),
            OwnerId::new(record.owner),
            record.id(),
        );
        let has_live_quote = live_quotes.contains(&expected_live_quote);
        match &record.state {
            StoredReservationState::Reserved => {
                if !has_expiration {
                    return Err(ProviderError::CorruptState(format!(
                        "reserved reservation {:?} has no expiration index entry",
                        record.id()
                    )));
                }
                if has_live_quote != record.quote.is_some() {
                    return Err(ProviderError::CorruptState(format!(
                        "reserved reservation {:?} has inconsistent live-quote indexing",
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
                if has_live_quote {
                    return Err(ProviderError::CorruptState(format!(
                        "terminal reservation {:?} still has a live-quote index entry",
                        record.id()
                    )));
                }
            }
        }

        for (target_index, outpoint) in record.outpoints.iter().enumerate() {
            let key = outpoint_key(*outpoint);
            let inventory_item = inventory.get(&key).ok_or_else(|| {
                ProviderError::CorruptState(format!(
                    "reservation {:?} references missing inventory {outpoint:?}",
                    record.id()
                ))
            })?;
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
                    let expected_target = StoredSigningTarget::from_inventory(*inventory_item);
                    if intent.targets.get(target_index) != Some(&expected_target) {
                        return Err(ProviderError::CorruptState(format!(
                            "committed reservation {:?} signing target disagrees with inventory {outpoint:?}",
                            record.id()
                        )));
                    }
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
        if *key != expected_key
            || binding.semantic_request_digest != record.semantic_request_digest
            || binding.request_digest != record.request_digest
        {
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

    for key in &live_quotes {
        let deadline = UnixMillis::new(u64::from_be_bytes(
            key[..8].try_into().expect("fixed slice"),
        ));
        let owner = OwnerId::new(key[8..40].try_into().expect("fixed slice"));
        let reservation_id = ReservationId::new(key[40..].try_into().expect("fixed slice"));
        let record = reservations
            .get(&reservation_id.to_bytes())
            .ok_or_else(|| {
                ProviderError::CorruptState(
                    "owner live-quote index references a missing reservation".to_owned(),
                )
            })?;
        if deadline != UnixMillis::new(record.accept_before)
            || owner != OwnerId::new(record.owner)
            || record.quote.is_none()
            || !matches!(record.state, StoredReservationState::Reserved)
        {
            return Err(ProviderError::CorruptState(format!(
                "owner live-quote index disagrees with reservation {:?}",
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
    write.open_table(LIVE_QUOTES_BY_OWNER)?;
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

fn live_quote_key(deadline: UnixMillis, owner: OwnerId, reservation_id: ReservationId) -> [u8; 72] {
    let mut encoded = [0_u8; 72];
    encoded[..8].copy_from_slice(&deadline.value().to_be_bytes());
    encoded[8..40].copy_from_slice(&owner.to_bytes());
    encoded[40..].copy_from_slice(&reservation_id.to_bytes());
    encoded
}

fn decode_live_quote_key(
    bytes: &[u8],
) -> Result<(UnixMillis, OwnerId, ReservationId), ProviderError> {
    let encoded = decode_table_key::<72>("owner live quote", bytes)?;
    let mut deadline = [0_u8; 8];
    deadline.copy_from_slice(&encoded[..8]);
    let mut owner = [0_u8; 32];
    owner.copy_from_slice(&encoded[8..40]);
    let mut reservation_id = [0_u8; 32];
    reservation_id.copy_from_slice(&encoded[40..]);
    Ok((
        UnixMillis::new(u64::from_be_bytes(deadline)),
        OwnerId::new(owner),
        ReservationId::new(reservation_id),
    ))
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

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct StoredInventoryItem {
    outpoint: OutPoint,
    asset: AssetId,
    amount: u64,
    wallet_locator: [u8; 32],
    internal_key: [u8; 32],
    binding: [u8; 32],
}

impl std::fmt::Debug for StoredInventoryItem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredInventoryItem")
            .field("outpoint", &self.outpoint)
            .field("asset", &self.asset)
            .field("amount", &self.amount)
            .field("wallet_locator", &"[opaque]")
            .field("internal_key", &self.internal_key)
            .field("binding", &self.binding)
            .finish()
    }
}

impl From<InventoryItem> for StoredInventoryItem {
    fn from(value: InventoryItem) -> Self {
        Self {
            outpoint: value.outpoint(),
            asset: value.asset(),
            amount: value.amount(),
            wallet_locator: value.wallet_locator().to_bytes(),
            internal_key: value.internal_key().serialize(),
            binding: value.binding().to_bytes(),
        }
    }
}

impl StoredInventoryItem {
    fn to_domain(self) -> Result<InventoryItem, ProviderError> {
        let wallet_locator = WalletKeyLocator::new(self.wallet_locator).map_err(|error| {
            ProviderError::CorruptState(format!("invalid persisted inventory: {error}"))
        })?;
        let internal_key = XOnlyPublicKey::from_slice(&self.internal_key).map_err(|error| {
            ProviderError::CorruptState(format!(
                "invalid persisted inventory internal key: {error}"
            ))
        })?;
        InventoryItem::new(
            self.outpoint,
            self.asset,
            self.amount,
            wallet_locator,
            internal_key,
            InventoryBinding::new(self.binding),
        )
        .map_err(|error| {
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

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct StoredSigningTarget {
    outpoint: OutPoint,
    wallet_locator: [u8; 32],
    internal_key: [u8; 32],
    inventory_binding: [u8; 32],
}

impl std::fmt::Debug for StoredSigningTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredSigningTarget")
            .field("outpoint", &self.outpoint)
            .field("wallet_locator", &"[opaque]")
            .field("internal_key", &self.internal_key)
            .field("inventory_binding", &self.inventory_binding)
            .finish()
    }
}

impl StoredSigningTarget {
    fn from_inventory(item: StoredInventoryItem) -> Self {
        Self {
            outpoint: item.outpoint,
            wallet_locator: item.wallet_locator,
            internal_key: item.internal_key,
            inventory_binding: item.binding,
        }
    }

    fn to_domain(self) -> Result<SigningTarget, ProviderError> {
        let wallet_locator = WalletKeyLocator::new(self.wallet_locator).map_err(|error| {
            ProviderError::CorruptState(format!("invalid persisted signing locator: {error}"))
        })?;
        let internal_key = XOnlyPublicKey::from_slice(&self.internal_key).map_err(|error| {
            ProviderError::CorruptState(format!("invalid persisted signing key: {error}"))
        })?;
        Ok(SigningTarget {
            outpoint: self.outpoint,
            wallet_locator,
            internal_key,
            inventory_binding: InventoryBinding::new(self.inventory_binding),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredSigningIntent {
    commitment: [u8; 32],
    pre_sign_payload: Vec<u8>,
    fee: StoredTransactionFee,
    committed_at: u64,
    targets: Vec<StoredSigningTarget>,
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
            targets: self
                .targets
                .iter()
                .copied()
                .map(StoredSigningTarget::to_domain)
                .collect::<Result<_, _>>()?,
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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredFirmQuote {
    request: FirmQuoteRequest,
    execution: QuoteExecution,
    pricing: PricingDecision,
    snapshot: QuoteSnapshotEvidence,
    contribution: QuoteContribution,
    provider_receive_internal_key: [u8; 32],
    provider_receive_wallet_locator: [u8; 32],
    provider_change_internal_key: Option<[u8; 32]>,
    provider_change_wallet_locator: Option<[u8; 32]>,
    selected_asset: AssetId,
    selected_amount: u64,
}

impl std::fmt::Debug for StoredFirmQuote {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Wallet locators are opaque recovery capabilities. Keep them—and the
        // internal recovery keys that accompany them—out of diagnostics.
        formatter
            .debug_struct("StoredFirmQuote")
            .field("request", &self.request)
            .field("execution", &self.execution)
            .field("pricing", &self.pricing)
            .field("snapshot", &self.snapshot)
            .field("contribution", &self.contribution)
            .field("selected_asset", &self.selected_asset)
            .field("selected_amount", &self.selected_amount)
            .finish_non_exhaustive()
    }
}

impl StoredFirmQuote {
    fn from_domain(quote: &FirmQuote, draft: &FirmQuoteDraft) -> Self {
        Self {
            request: quote.request().clone(),
            execution: quote.execution(),
            pricing: quote.pricing(),
            snapshot: quote.snapshot(),
            contribution: quote.contribution().clone(),
            provider_receive_internal_key: draft.provider_receive_recovery.internal_key,
            provider_receive_wallet_locator: draft.provider_receive_recovery.wallet_locator,
            provider_change_internal_key: draft
                .provider_change_recovery
                .map(|recovery| recovery.internal_key),
            provider_change_wallet_locator: draft
                .provider_change_recovery
                .map(|recovery| recovery.wallet_locator),
            selected_asset: draft.selected_asset,
            selected_amount: draft.selected_amount,
        }
    }

    fn to_domain(
        &self,
        provider: ProviderIdentity,
        reservation: &StoredReservation,
    ) -> Result<FirmQuote, ProviderError> {
        let quote = quote_from_stored_parts(
            reservation.id(),
            provider,
            self.request.clone(),
            self.execution,
            self.pricing,
            self.snapshot,
            self.contribution.clone(),
            UnixMillis::new(reservation.created_at),
            UnixMillis::new(reservation.accept_before),
            reservation.fee_policy.to_domain()?,
            recovery_metadata_commitment(
                provider,
                reservation.id(),
                crate::quote::DestinationRecovery {
                    internal_key: self.provider_receive_internal_key,
                    wallet_locator: self.provider_receive_wallet_locator,
                },
                self.provider_change_internal_key,
                self.provider_change_wallet_locator,
            )?,
            QuoteCommitment::new(reservation.quote_commitment),
        );
        let expected = recompute_quote_commitment(
            OwnerId::new(reservation.owner),
            IdempotencyKey::new(reservation.idempotency_key),
            crate::model::QuoteRequestDigest::new(reservation.semantic_request_digest),
            &quote,
        )?;
        if expected != quote.commitment() {
            return Err(ProviderError::CorruptState(
                "persisted firm quote commitment does not match its transcript".to_owned(),
            ));
        }
        self.validate(provider, reservation, &quote)?;
        Ok(quote)
    }

    fn validate(
        &self,
        provider: ProviderIdentity,
        reservation: &StoredReservation,
        quote: &FirmQuote,
    ) -> Result<(), ProviderError> {
        if self.request.context().chain().genesis_hash != provider.genesis_hash()
            || self.request.context().policy_asset() != provider.policy_asset()
            || self.request.context().market().creation_anchor().is_null()
        {
            return Err(ProviderError::CorruptState(
                "persisted firm quote context disagrees with provider identity".to_owned(),
            ));
        }
        let request_digest = crate::quote::quote_request_digest(
            provider,
            OwnerId::new(reservation.owner),
            IdempotencyKey::new(reservation.idempotency_key),
            &self.request,
        )?;
        if request_digest.to_bytes() != reservation.semantic_request_digest {
            return Err(ProviderError::CorruptState(
                "persisted firm quote request digest does not match its semantics".to_owned(),
            ));
        }
        let outpoints = quote
            .contribution()
            .inputs()
            .iter()
            .map(QuotedProviderInput::outpoint)
            .collect::<Vec<_>>();
        if outpoints != reservation.outpoints {
            return Err(ProviderError::CorruptState(
                "persisted firm quote inputs do not match reservation outpoints".to_owned(),
            ));
        }
        validate_firm_quote_shape(quote)?;
        let normalized_rate = crate::quote::RationalRate::new(
            self.pricing.rate().numerator(),
            self.pricing.rate().denominator(),
        )
        .map_err(|error| {
            ProviderError::CorruptState(format!(
                "persisted firm quote has an invalid rate: {error}"
            ))
        })?;
        if normalized_rate != self.pricing.rate() {
            return Err(ProviderError::CorruptState(
                "persisted firm quote rate is not normalized".to_owned(),
            ));
        }
        let (request_input_asset, request_output_asset) = self.request.kind().pair();
        if request_input_asset == request_output_asset
            || self.execution.input().asset() != request_input_asset
            || self.execution.output().asset() != request_output_asset
        {
            return Err(ProviderError::CorruptState(
                "persisted firm quote pair is inconsistent".to_owned(),
            ));
        }
        let recipient_script = self.request.recipient().script_pubkey();
        if recipient_script.is_empty()
            || recipient_script.is_provably_unspendable()
            || recipient_script.len() > crate::quote::MAX_QUOTE_RECIPIENT_SCRIPT_BYTES
        {
            return Err(ProviderError::CorruptState(
                "persisted firm quote recipient is invalid".to_owned(),
            ));
        }
        if self.selected_amount == 0 || self.selected_asset != quote.execution().output().asset() {
            return Err(ProviderError::CorruptState(
                "persisted firm quote selected inventory is invalid".to_owned(),
            ));
        }
        let expected_execution = match self.request.kind() {
            crate::quote::QuoteKind::ExactIn {
                input,
                output_asset,
                minimum_output,
            } => {
                if input.amount() == 0 || minimum_output == 0 {
                    return Err(ProviderError::CorruptState(
                        "persisted exact-input quote contains a zero amount".to_owned(),
                    ));
                }
                let priced_input = input
                    .amount()
                    .checked_sub(self.pricing.input_asset_venue_fee())
                    .filter(|amount| *amount != 0)
                    .ok_or_else(|| {
                        ProviderError::CorruptState(
                            "persisted firm quote fee consumes exact input".to_owned(),
                        )
                    })?;
                let output = u128::from(priced_input)
                    .checked_mul(u128::from(self.pricing.rate().numerator()))
                    .ok_or_else(|| {
                        ProviderError::CorruptState(
                            "persisted firm quote pricing overflowed".to_owned(),
                        )
                    })?
                    / u128::from(self.pricing.rate().denominator());
                let output = u64::try_from(output).map_err(|_| {
                    ProviderError::CorruptState("persisted firm quote output overflowed".to_owned())
                })?;
                if output == 0
                    || output < minimum_output
                    || self.execution.input() != input
                    || self.execution.output().asset() != output_asset
                    || self.execution.output().amount() != output
                {
                    return Err(ProviderError::CorruptState(
                        "persisted exact-input quote has inconsistent pricing".to_owned(),
                    ));
                }
                self.execution
            }
            crate::quote::QuoteKind::ExactOut {
                input_asset,
                maximum_input,
                output,
            } => {
                if maximum_input == 0 || output.amount() == 0 {
                    return Err(ProviderError::CorruptState(
                        "persisted exact-output quote contains a zero amount".to_owned(),
                    ));
                }
                let product =
                    u128::from(output.amount()) * u128::from(self.pricing.rate().denominator());
                let divisor = u128::from(self.pricing.rate().numerator());
                if divisor == 0 {
                    return Err(ProviderError::CorruptState(
                        "persisted firm quote has a zero rate".to_owned(),
                    ));
                }
                let priced_input = product / divisor + u128::from(!product.is_multiple_of(divisor));
                let gross_input = u64::try_from(priced_input)
                    .ok()
                    .and_then(|amount| amount.checked_add(self.pricing.input_asset_venue_fee()))
                    .ok_or_else(|| {
                        ProviderError::CorruptState(
                            "persisted exact-output quote input overflowed".to_owned(),
                        )
                    })?;
                if gross_input == 0
                    || gross_input > maximum_input
                    || self.execution.input().asset() != input_asset
                    || self.execution.input().amount() != gross_input
                    || self.execution.output() != output
                {
                    return Err(ProviderError::CorruptState(
                        "persisted exact-output quote has inconsistent pricing".to_owned(),
                    ));
                }
                self.execution
            }
        };
        if expected_execution.input_asset_venue_fee() > self.request.maximum_input_asset_venue_fee()
        {
            return Err(ProviderError::CorruptState(
                "persisted firm quote exceeds its venue-fee bound".to_owned(),
            ));
        }
        let change = self
            .selected_amount
            .checked_sub(quote.execution().output().amount())
            .ok_or_else(|| {
                ProviderError::CorruptState(
                    "persisted firm quote inventory does not cover output".to_owned(),
                )
            })?;
        let change_outputs = quote
            .contribution()
            .outputs()
            .iter()
            .filter(|output| output.role() == QuoteOutputRole::ProviderChange)
            .collect::<Vec<_>>();
        if (change == 0 && !change_outputs.is_empty())
            || (change != 0
                && !matches!(change_outputs.as_slice(), [output]
                    if output.asset() == self.selected_asset && output.amount() == change))
        {
            return Err(ProviderError::CorruptState(
                "persisted firm quote change is inconsistent".to_owned(),
            ));
        }
        let has_change_recovery = self.provider_change_internal_key.is_some()
            && self.provider_change_wallet_locator.is_some();
        if has_change_recovery != (change != 0)
            || self.provider_change_internal_key.is_some()
                != self.provider_change_wallet_locator.is_some()
        {
            return Err(ProviderError::CorruptState(
                "persisted firm quote change recovery is inconsistent".to_owned(),
            ));
        }
        WalletKeyLocator::new(self.provider_receive_wallet_locator).map_err(|error| {
            ProviderError::CorruptState(format!(
                "invalid persisted provider receive recovery: {error}"
            ))
        })?;
        let receive_key =
            XOnlyPublicKey::from_slice(&self.provider_receive_internal_key).map_err(|error| {
                ProviderError::CorruptState(format!(
                    "invalid persisted provider receive recovery: {error}"
                ))
            })?;
        let provider_payment = quote
            .contribution()
            .outputs()
            .iter()
            .find(|output| output.role() == QuoteOutputRole::ProviderPayment)
            .ok_or_else(|| {
                ProviderError::CorruptState(
                    "persisted firm quote has no provider payment".to_owned(),
                )
            })?;
        if provider_payment.destination().script_pubkey()
            != &elements::Script::new_v1_p2tr(&Secp256k1::new(), receive_key, None)
        {
            return Err(ProviderError::CorruptState(
                "provider receive recovery key does not match the quoted script".to_owned(),
            ));
        }
        if let (Some(locator), Some(key)) = (
            self.provider_change_wallet_locator,
            self.provider_change_internal_key,
        ) {
            WalletKeyLocator::new(locator).map_err(|error| {
                ProviderError::CorruptState(format!(
                    "invalid persisted provider change recovery: {error}"
                ))
            })?;
            let change_key = XOnlyPublicKey::from_slice(&key).map_err(|error| {
                ProviderError::CorruptState(format!(
                    "invalid persisted provider change recovery: {error}"
                ))
            })?;
            let provider_change = change_outputs.first().ok_or_else(|| {
                ProviderError::CorruptState(
                    "provider change recovery has no quoted change output".to_owned(),
                )
            })?;
            if provider_change.destination().script_pubkey()
                != &elements::Script::new_v1_p2tr(&Secp256k1::new(), change_key, None)
            {
                return Err(ProviderError::CorruptState(
                    "provider change recovery key does not match the quoted script".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

fn validate_firm_quote_shape(quote: &FirmQuote) -> Result<(), ProviderError> {
    let inputs = quote.contribution().inputs();
    if inputs.is_empty() || inputs.len() > MAX_RESERVATION_INPUTS {
        return Err(ProviderError::CorruptState(
            "persisted firm quote has an invalid input count".to_owned(),
        ));
    }
    for (index, input) in inputs.iter().enumerate() {
        let expected_id = u16::try_from(index + 1).map_err(|_| {
            ProviderError::CorruptState("persisted firm quote has too many inputs".to_owned())
        })?;
        if input.id().value() != expected_id
            || !input.witness_utxo().asset.is_confidential()
            || !input.witness_utxo().value.is_confidential()
            || !input.witness_utxo().nonce.is_confidential()
            || input.witness_utxo().witness.surjection_proof.is_none()
            || input.witness_utxo().witness.rangeproof.is_none()
        {
            return Err(ProviderError::CorruptState(
                "persisted firm quote has an invalid provider input".to_owned(),
            ));
        }
    }

    let outputs = quote.contribution().outputs();
    let expected_roles = if outputs.len() == 2 {
        &[
            QuoteOutputRole::ProviderPayment,
            QuoteOutputRole::TakerReceive,
        ][..]
    } else if outputs.len() == 3 {
        &[
            QuoteOutputRole::ProviderPayment,
            QuoteOutputRole::TakerReceive,
            QuoteOutputRole::ProviderChange,
        ][..]
    } else {
        return Err(ProviderError::CorruptState(
            "persisted firm quote has an invalid output count".to_owned(),
        ));
    };
    let provider_blinder = crate::quote::QuoteBlinderRole::ProviderInput(inputs[0].id());
    for (index, (output, expected_role)) in outputs.iter().zip(expected_roles).enumerate() {
        let expected_id = u16::try_from(index + 1).expect("firm quote has at most three outputs");
        let expected_blinder = if *expected_role == QuoteOutputRole::ProviderPayment {
            crate::quote::QuoteBlinderRole::TakerPaymentInput
        } else {
            provider_blinder
        };
        if output.id().value() != expected_id
            || output.role() != *expected_role
            || output.amount() == 0
            || output.blinder() != expected_blinder
        {
            return Err(ProviderError::CorruptState(
                "persisted firm quote has an invalid output shape".to_owned(),
            ));
        }
    }

    let execution = quote.execution();
    let payment = &outputs[0];
    let receive = &outputs[1];
    if payment.asset() != execution.input().asset()
        || payment.amount() != execution.input().amount()
        || receive.asset() != execution.output().asset()
        || receive.amount() != execution.output().amount()
        || receive.destination() != quote.request().recipient()
        || execution.input_asset_venue_fee() != quote.pricing().input_asset_venue_fee()
    {
        return Err(ProviderError::CorruptState(
            "persisted firm quote contribution disagrees with its economics".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredReservation {
    id: [u8; 32],
    owner: [u8; 32],
    idempotency_key: [u8; 32],
    semantic_request_digest: [u8; 32],
    request_digest: [u8; 32],
    quote_commitment: [u8; 32],
    quote: Option<StoredFirmQuote>,
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
        if self.quote.is_none() && self.semantic_request_digest != self.quote_commitment {
            return Err(ProviderError::CorruptState(
                "legacy reservation semantic request digest is inconsistent".to_owned(),
            ));
        }
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
                if intent.targets.len() != self.outpoints.len()
                    || intent
                        .targets
                        .iter()
                        .zip(&self.outpoints)
                        .any(|(target, outpoint)| target.outpoint != *outpoint)
                {
                    return Err(ProviderError::CorruptState(
                        "persisted signing targets do not match reservation outpoints".to_owned(),
                    ));
                }
                for target in &intent.targets {
                    target.to_domain()?;
                }
                let expected =
                    signing_commitment(self, &intent.pre_sign_payload, fee, &intent.targets)?;
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

    fn to_firm_quote_outcome(
        &self,
        provider: ProviderIdentity,
        created: bool,
    ) -> Result<FirmQuoteOutcome, ProviderError> {
        let stored = self.quote.as_ref().ok_or_else(|| {
            ProviderError::CorruptState(
                "reservation was not created by the firm quote engine".to_owned(),
            )
        })?;
        let quote = stored.to_domain(provider, self)?;
        Ok(quote_outcome(quote, self.to_view()?, created))
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
    semantic_request_digest: [u8; 32],
    request_digest: [u8; 32],
}

#[derive(Serialize)]
struct StoredRequestFingerprint<'a> {
    identity: StoredProviderIdentity,
    owner: [u8; 32],
    idempotency_key: [u8; 32],
    semantic_request_digest: [u8; 32],
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
    targets: &'a [StoredSigningTarget],
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
    #[error("wallet snapshot observed at {observed_at:?} is in the future at {now:?}")]
    InventorySnapshotObservedInFuture {
        observed_at: UnixMillis,
        now: UnixMillis,
    },
    #[error(
        "wallet snapshot observed at {observed_at:?} is stale at {now:?}; maximum age is {maximum_age_millis} ms"
    )]
    InventorySnapshotStale {
        observed_at: UnixMillis,
        now: UnixMillis,
        maximum_age_millis: u64,
    },
    #[error("persisted audit sequence is corrupt")]
    CorruptAuditSequence,
    #[error("audit sequence overflowed")]
    AuditSequenceOverflow,
    #[error("persisted allocation revision is corrupt")]
    CorruptAllocationRevision,
    #[error("allocation revision overflowed")]
    AllocationRevisionOverflow,
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
    #[error("wallet discovery contains duplicate inventory outpoint {0:?}")]
    DuplicateInventoryOutpoint(OutPoint),
    #[error("outpoint {outpoint:?} is unavailable: {state:?}")]
    OutpointUnavailable {
        outpoint: OutPoint,
        state: InventoryState,
    },
    #[error("idempotency key {key:?} for owner {owner:?} was reused with different terms")]
    IdempotencyConflict { owner: OwnerId, key: IdempotencyKey },
    #[error("firm quote request digest disagrees with its semantic request")]
    FirmQuoteRequestDigestMismatch,
    #[error("firm quote snapshot evidence disagrees with the current eligible inventory")]
    FirmQuoteSnapshotMismatch,
    #[error("eligible inventory changed while the firm quote was being constructed; retry")]
    EligibleInventoryChanged,
    #[error("firm quote input disagrees with fresh wallet inventory at {0:?}")]
    FirmQuoteInventoryMismatch(OutPoint),
    #[error("firm quote draft is internally inconsistent")]
    FirmQuoteDraftInvalid,
    #[error("derived reservation ID collided: {0:?}")]
    ReservationIdCollision(ReservationId),
    #[error("reservation deadline {accept_before:?} elapsed at {now:?}")]
    ReservationDeadlineElapsed {
        accept_before: UnixMillis,
        now: UnixMillis,
    },
    #[error("firm quote deadline calculation overflowed")]
    QuoteDeadlineOverflow,
    #[error("live quote count overflowed")]
    LiveQuoteCountOverflow,
    #[error("owner {owner:?} reached the live quote limit of {maximum}")]
    OwnerLiveQuoteLimit { owner: OwnerId, maximum: usize },
    #[error("provider reached the global live quote limit of {maximum}")]
    GlobalLiveQuoteLimit { maximum: usize },
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

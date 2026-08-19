//! Fresh wallet discovery intersected with durable inventory allocation.
//!
//! The redb state machine intentionally knows only whether an outpoint is
//! allocated. In particular, its `Available` state does not mean that a wallet
//! still sees an unspent output. This coordinator is the quote-facing gate: it
//! publishes only outputs present in a recent complete wallet snapshot *and*
//! durably unallocated, and it holds the snapshot lock while reserving them.

use std::collections::BTreeMap;
#[cfg(test)]
use std::collections::BTreeSet;
use std::sync::{Mutex, MutexGuard};

use elements::OutPoint;
use elements::hashes::Hash as _;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

#[cfg(test)]
use crate::model::ReservationPlan;
use crate::model::{Clock, InventoryState, ProviderIdentity, UnixMillis};
use crate::model::{IdempotencyKey, OwnerId, QuoteRequestDigest};
use crate::quote::{FirmQuoteDraft, FirmQuoteOutcome, QuoteEnginePolicy};
#[cfg(test)]
use crate::store::ReserveOutcome;
use crate::store::{ProviderError, ReservationBook};
use crate::wallet::{
    InventorySnapshotCommitment, InventorySource, WalletOwnedOutput, WalletScanAnchor,
};

/// Conservative default upper bound for one complete wallet scan.
pub const DEFAULT_MAX_INVENTORY_OUTPUTS: usize = 10_000;
const ELIGIBLE_INVENTORY_DOMAIN: &[u8] = b"deadcat/rfq/eligible-inventory/v1";

/// Quote-admission policy for wallet inventory snapshots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InventoryFreshnessPolicy {
    max_snapshot_age_millis: u64,
    max_inventory_outputs: usize,
}

impl InventoryFreshnessPolicy {
    pub fn new(
        max_snapshot_age_millis: u64,
        max_inventory_outputs: usize,
    ) -> Result<Self, InventoryPolicyError> {
        if max_snapshot_age_millis == 0 {
            return Err(InventoryPolicyError::ZeroMaximumSnapshotAge);
        }
        if max_inventory_outputs == 0 {
            return Err(InventoryPolicyError::ZeroMaximumInventoryOutputs);
        }
        Ok(Self {
            max_snapshot_age_millis,
            max_inventory_outputs,
        })
    }

    #[must_use]
    pub const fn max_snapshot_age_millis(self) -> u64 {
        self.max_snapshot_age_millis
    }

    #[must_use]
    pub const fn max_inventory_outputs(self) -> usize {
        self.max_inventory_outputs
    }
}

/// Invalid snapshot-admission configuration.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum InventoryPolicyError {
    #[error("maximum wallet-snapshot age must be nonzero")]
    ZeroMaximumSnapshotAge,
    #[error("maximum wallet-snapshot output count must be nonzero")]
    ZeroMaximumInventoryOutputs,
}

/// In-process proof that an eligible view came from the latest published scan.
///
/// Tokens are deliberately neither serialized nor persisted. A process restart
/// must complete a new authoritative wallet scan before it can quote inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EligibilityToken {
    generation: u64,
    snapshot: InventorySnapshotCommitment,
    observed_at: UnixMillis,
}

impl EligibilityToken {
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn snapshot(self) -> InventorySnapshotCommitment {
        self.snapshot
    }

    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }
}

/// The only inventory view suitable for quote construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EligibleInventory {
    token: EligibilityToken,
    anchor: WalletScanAnchor,
    allocation_revision: u64,
    eligible_commitment: [u8; 32],
    outputs: Vec<WalletOwnedOutput>,
}

/// Fresh complete wallet inventory, independent of durable allocation state.
///
/// This view is for transaction construction and final validation after an
/// output has been reserved and therefore disappeared from
/// [`EligibleInventory`]. It carries the same authenticated snapshot token and
/// retains each output's ephemeral confidential opening. It must never be used
/// by itself to decide quoteability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentInventory {
    token: EligibilityToken,
    anchor: WalletScanAnchor,
    outputs: Vec<WalletOwnedOutput>,
}

impl CurrentInventory {
    #[must_use]
    pub const fn token(&self) -> EligibilityToken {
        self.token
    }

    #[must_use]
    pub const fn anchor(&self) -> WalletScanAnchor {
        self.anchor
    }

    #[must_use]
    pub fn outputs(&self) -> &[WalletOwnedOutput] {
        &self.outputs
    }

    /// Look up one wallet-authenticated output in this exact snapshot.
    #[must_use]
    pub fn output(&self, outpoint: OutPoint) -> Option<&WalletOwnedOutput> {
        self.outputs
            .binary_search_by_key(&outpoint, WalletOwnedOutput::outpoint)
            .ok()
            .map(|index| &self.outputs[index])
    }
}

impl EligibleInventory {
    #[must_use]
    pub const fn token(&self) -> EligibilityToken {
        self.token
    }

    #[must_use]
    pub const fn anchor(&self) -> WalletScanAnchor {
        self.anchor
    }

    /// Monotonic durable revision of inventory allocation state.
    #[must_use]
    pub const fn allocation_revision(&self) -> u64 {
        self.allocation_revision
    }

    /// Commitment to the exact eligible outpoints and wallet bindings.
    #[must_use]
    pub const fn eligible_commitment(&self) -> [u8; 32] {
        self.eligible_commitment
    }

    #[must_use]
    pub fn outputs(&self) -> &[WalletOwnedOutput] {
        &self.outputs
    }
}

struct PublishedSnapshot {
    token: EligibilityToken,
    anchor: WalletScanAnchor,
    outputs: Vec<WalletOwnedOutput>,
}

#[derive(Default)]
struct CoordinatorState {
    generation: u64,
    latest: Option<PublishedSnapshot>,
}

/// Owns the single quote-facing path from wallet discovery to reservation.
///
/// Discovery calls are serialized with eligibility reads and reservation.
/// Consequently an older or missing snapshot cannot race a newer scan and
/// allocate an outpoint after that newer scan removed it. Chain state can of
/// course change immediately after any scan; the final transaction validator
/// must recheck authoritative prevouts before the point of no return.
pub struct InventoryCoordinator<S> {
    book: ReservationBook,
    source: S,
    policy: InventoryFreshnessPolicy,
    state: Mutex<CoordinatorState>,
}

impl<S> InventoryCoordinator<S>
where
    S: InventorySource,
{
    #[must_use]
    pub fn new(book: ReservationBook, source: S, policy: InventoryFreshnessPolicy) -> Self {
        Self {
            book,
            source,
            policy,
            state: Mutex::new(CoordinatorState::default()),
        }
    }

    #[must_use]
    pub const fn identity(&self) -> ProviderIdentity {
        self.book.identity()
    }

    /// Durable state access for cancellation, expiry, status, audit, and
    /// recovery. Inventory import and reservation themselves remain private to
    /// this coordinator so callers cannot bypass freshness.
    #[must_use]
    pub const fn reservation_book(&self) -> &ReservationBook {
        &self.book
    }

    /// Run and atomically publish one complete authoritative wallet scan.
    ///
    /// All discovered metadata is checked against redb in one transaction.
    /// A source error may retain the bounded previous snapshot, but once the
    /// source returns a newer complete view, any identity, policy, import, or
    /// reconciliation failure invalidates the previous positive cache. No
    /// rejected result can leave an older view quoteable.
    pub fn refresh<C: Clock>(
        &self,
        clock: &C,
    ) -> Result<EligibleInventory, InventoryCoordinatorError<S::Error>> {
        let mut state = self.lock_state()?;
        let snapshot = self
            .source
            .inventory_snapshot()
            .map_err(InventoryCoordinatorError::Source)?;
        // A complete newer source result supersedes the previous observation
        // even when later validation rejects it. Retaining the old positive
        // cache after a contradiction could quote an output the authoritative
        // source has just reported with different or unsafe metadata.
        state.latest = None;
        if snapshot.identity() != self.book.identity() {
            return Err(InventoryCoordinatorError::IdentityMismatch {
                expected: Box::new(self.book.identity()),
                actual: Box::new(snapshot.identity()),
            });
        }
        if snapshot.outputs().len() > self.policy.max_inventory_outputs {
            return Err(InventoryCoordinatorError::SnapshotTooLarge {
                maximum: self.policy.max_inventory_outputs,
                actual: snapshot.outputs().len(),
            });
        }
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(InventoryCoordinatorError::GenerationOverflow)?;
        let now = clock.now();
        let inventory = snapshot
            .outputs()
            .iter()
            .map(WalletOwnedOutput::inventory_item)
            .collect::<Vec<_>>();
        self.book.import_inventory_batch(&inventory, &now)?;

        let token = EligibilityToken {
            generation,
            snapshot: snapshot.commitment(),
            observed_at: now,
        };
        let published = PublishedSnapshot {
            token,
            anchor: snapshot.anchor(),
            outputs: snapshot.outputs().to_vec(),
        };
        // Finish the durable intersection before publishing the positive
        // in-memory observation. A read/integrity failure after import leaves
        // durable history intact but cannot make a partially successful scan
        // current.
        let eligible = self.eligible_from_snapshot(&published)?;
        state.generation = generation;
        state.latest = Some(published);
        Ok(eligible)
    }

    /// Re-evaluate durable availability against the latest in-memory scan.
    /// A reopened process has no latest scan and therefore no quoteable output.
    pub fn eligible<C: Clock>(
        &self,
        clock: &C,
    ) -> Result<EligibleInventory, InventoryCoordinatorError<S::Error>> {
        let state = self.lock_state()?;
        let latest = self.require_fresh(&state, clock.now())?;
        self.eligible_from_snapshot(latest)
    }

    /// Return every output in the latest fresh authenticated wallet snapshot,
    /// including outputs currently reserved or committed in durable state.
    /// Quote construction must use [`Self::eligible`] instead.
    pub fn current<C: Clock>(
        &self,
        clock: &C,
    ) -> Result<CurrentInventory, InventoryCoordinatorError<S::Error>> {
        let state = self.lock_state()?;
        let latest = self.require_fresh(&state, clock.now())?;
        Ok(CurrentInventory {
            token: latest.token,
            anchor: latest.anchor,
            outputs: latest.outputs.clone(),
        })
    }

    /// Reserve a plan selected from `eligible`, rechecking freshness and exact
    /// membership while preventing a concurrent refresh from replacing it.
    ///
    /// Existing exact idempotent requests are replayed independently of the
    /// old discovery token; they never allocate inventory a second time.
    #[cfg(test)]
    pub(crate) fn reserve<C: Clock>(
        &self,
        eligible: &EligibleInventory,
        plan: &ReservationPlan,
        clock: &C,
    ) -> Result<ReserveOutcome, InventoryCoordinatorError<S::Error>> {
        if self.book.has_matching_request(plan)? {
            return self
                .book
                .reserve(plan, clock)
                .map_err(InventoryCoordinatorError::Provider);
        }

        let state = self.lock_state()?;
        // Close the race between the first read-only retry check and acquiring
        // the scan lock. Every production reservation uses this coordinator.
        if self.book.has_matching_request(plan)? {
            return self
                .book
                .reserve(plan, clock)
                .map_err(InventoryCoordinatorError::Provider);
        }
        let now = clock.now();
        let latest = self.require_fresh(&state, now)?;
        if latest.token != eligible.token {
            return Err(InventoryCoordinatorError::SnapshotSuperseded {
                requested: eligible.token,
                current: latest.token,
            });
        }
        let current_outpoints = latest
            .outputs
            .iter()
            .map(WalletOwnedOutput::outpoint)
            .collect::<BTreeSet<_>>();
        if let Some(outpoint) = plan
            .outpoints()
            .iter()
            .find(|outpoint| !current_outpoints.contains(outpoint))
        {
            return Err(InventoryCoordinatorError::OutpointNotInFreshSnapshot(
                *outpoint,
            ));
        }
        let eligible_outpoints = eligible
            .outputs
            .iter()
            .map(WalletOwnedOutput::outpoint)
            .collect::<BTreeSet<_>>();
        if let Some(outpoint) = plan
            .outpoints()
            .iter()
            .find(|outpoint| !eligible_outpoints.contains(outpoint))
        {
            return Err(InventoryCoordinatorError::OutpointNotInEligibleView(
                *outpoint,
            ));
        }
        self.book
            .reserve_from_snapshot(
                plan,
                latest.token.observed_at,
                self.policy.max_snapshot_age_millis,
                clock,
            )
            .map_err(Into::into)
    }

    /// Atomically reserve the exact provider inputs and persist the complete
    /// firm quote selected from `eligible`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reserve_firm_quote<C: Clock>(
        &self,
        eligible: &EligibleInventory,
        owner: OwnerId,
        key: IdempotencyKey,
        request_digest: QuoteRequestDigest,
        draft: &FirmQuoteDraft,
        policy: QuoteEnginePolicy,
        clock: &C,
    ) -> Result<FirmQuoteOutcome, InventoryCoordinatorError<S::Error>> {
        draft.validate().map_err(|_| {
            InventoryCoordinatorError::Provider(ProviderError::FirmQuoteDraftInvalid)
        })?;
        let state = self.lock_state()?;
        // Preflight runs before pricing so failed capacity checks cannot burn
        // wallet destinations. Recheck only idempotency after taking the
        // snapshot lock: a concurrent identical request may have won in the
        // interval, and replay must not depend on the now-stale snapshot.
        if let Some(replayed) = self
            .book
            .replay_firm_quote(owner, key, request_digest, clock)?
        {
            return Ok(replayed);
        }
        let now = clock.now();
        let latest = self.require_fresh(&state, now)?;
        if latest.token != eligible.token {
            return Err(InventoryCoordinatorError::SnapshotSuperseded {
                requested: eligible.token,
                current: latest.token,
            });
        }
        let current_eligible = self.eligible_from_snapshot(latest)?;
        if draft.snapshot.allocation_revision() != current_eligible.allocation_revision
            || draft.snapshot.eligible_commitment() != current_eligible.eligible_commitment
        {
            return Err(InventoryCoordinatorError::Provider(
                ProviderError::EligibleInventoryChanged,
            ));
        }
        if draft.snapshot.anchor() != latest.anchor
            || draft.snapshot.commitment() != latest.token.snapshot
        {
            return Err(InventoryCoordinatorError::Provider(
                ProviderError::FirmQuoteSnapshotMismatch,
            ));
        }
        for quoted_input in draft.contribution.inputs() {
            let Some(output) = current_eligible
                .outputs
                .iter()
                .find(|output| output.outpoint() == quoted_input.outpoint())
            else {
                return Err(InventoryCoordinatorError::OutpointNotInEligibleView(
                    quoted_input.outpoint(),
                ));
            };
            if output.asset() != draft.selected_asset
                || output.txout() != quoted_input.witness_utxo()
                || output.binding() != quoted_input.inventory_binding()
            {
                return Err(InventoryCoordinatorError::Provider(
                    ProviderError::FirmQuoteInventoryMismatch(quoted_input.outpoint()),
                ));
            }
        }
        self.book
            .reserve_firm_quote_from_snapshot(
                owner,
                key,
                request_digest,
                draft,
                policy,
                latest.token.observed_at,
                self.policy.max_snapshot_age_millis,
                clock,
            )
            .map_err(Into::into)
    }

    fn eligible_from_snapshot(
        &self,
        latest: &PublishedSnapshot,
    ) -> Result<EligibleInventory, InventoryCoordinatorError<S::Error>> {
        let outpoints = latest
            .outputs
            .iter()
            .map(WalletOwnedOutput::outpoint)
            .collect::<Vec<_>>();
        let (durable, allocation_revision) = self.book.inventory_state_for(&outpoints)?;
        let durable = durable
            .into_iter()
            .map(|view| (view.item().outpoint(), view))
            .collect::<BTreeMap<_, _>>();
        let mut outputs = Vec::new();
        for output in &latest.outputs {
            let view = durable.get(&output.outpoint()).ok_or_else(|| {
                ProviderError::CorruptState(format!(
                    "published wallet output {:?} has no durable inventory record",
                    output.outpoint()
                ))
            })?;
            if view.item() != output.inventory_item() {
                return Err(ProviderError::CorruptState(format!(
                    "published wallet output {:?} disagrees with durable metadata",
                    output.outpoint()
                ))
                .into());
            }
            if view.state() == InventoryState::Available {
                outputs.push(output.clone());
            }
        }
        Ok(EligibleInventory {
            token: latest.token,
            anchor: latest.anchor,
            allocation_revision,
            eligible_commitment: eligible_commitment(&outputs),
            outputs,
        })
    }

    fn require_fresh<'a>(
        &self,
        state: &'a CoordinatorState,
        now: UnixMillis,
    ) -> Result<&'a PublishedSnapshot, InventoryCoordinatorError<S::Error>> {
        if let Some(previous) = self.book.last_observed_time()?
            && now < previous
        {
            return Err(ProviderError::ClockRegression { previous, now }.into());
        }
        let latest = state
            .latest
            .as_ref()
            .ok_or(InventoryCoordinatorError::NoPublishedSnapshot)?;
        if now < latest.token.observed_at {
            return Err(InventoryCoordinatorError::SnapshotObservedInFuture {
                observed_at: latest.token.observed_at,
                now,
            });
        }
        let age = now.value() - latest.token.observed_at.value();
        if age >= self.policy.max_snapshot_age_millis {
            return Err(InventoryCoordinatorError::SnapshotStale {
                observed_at: latest.token.observed_at,
                now,
                maximum_age_millis: self.policy.max_snapshot_age_millis,
            });
        }
        Ok(latest)
    }

    fn lock_state(
        &self,
    ) -> Result<MutexGuard<'_, CoordinatorState>, InventoryCoordinatorError<S::Error>> {
        self.state
            .lock()
            .map_err(|_| InventoryCoordinatorError::CoordinatorLockPoisoned)
    }
}

fn eligible_commitment(outputs: &[WalletOwnedOutput]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ELIGIBLE_INVENTORY_DOMAIN);
    hasher.update((outputs.len() as u64).to_be_bytes());
    for output in outputs {
        hasher.update(output.outpoint().txid.to_byte_array());
        hasher.update(output.outpoint().vout.to_be_bytes());
        hasher.update(output.binding().to_bytes());
    }
    hasher.finalize().into()
}

/// Fail-closed discovery, freshness, or durable-allocation error.
#[derive(Debug, Error)]
pub enum InventoryCoordinatorError<SourceError>
where
    SourceError: std::error::Error + Send + Sync + 'static,
{
    #[error("wallet inventory discovery failed: {0}")]
    Source(#[source] SourceError),
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error("wallet inventory coordinator lock is poisoned")]
    CoordinatorLockPoisoned,
    #[error("wallet snapshot identity mismatch: expected {expected:?}, got {actual:?}")]
    IdentityMismatch {
        expected: Box<ProviderIdentity>,
        actual: Box<ProviderIdentity>,
    },
    #[error("wallet snapshot has {actual} outputs; maximum is {maximum}")]
    SnapshotTooLarge { maximum: usize, actual: usize },
    #[error("wallet snapshot generation counter overflowed")]
    GenerationOverflow,
    #[error("no wallet snapshot has been published in this process")]
    NoPublishedSnapshot,
    #[error("wallet snapshot observed at {observed_at:?} is in the future at {now:?}")]
    SnapshotObservedInFuture {
        observed_at: UnixMillis,
        now: UnixMillis,
    },
    #[error(
        "wallet snapshot observed at {observed_at:?} is stale at {now:?}; maximum age is {maximum_age_millis} ms"
    )]
    SnapshotStale {
        observed_at: UnixMillis,
        now: UnixMillis,
        maximum_age_millis: u64,
    },
    #[error("wallet snapshot token was superseded: requested {requested:?}, current {current:?}")]
    SnapshotSuperseded {
        requested: EligibilityToken,
        current: EligibilityToken,
    },
    #[error("outpoint {0:?} is absent from the current fresh wallet snapshot")]
    OutpointNotInFreshSnapshot(OutPoint),
    #[error("outpoint {0:?} was not quoteable in the supplied eligible-inventory view")]
    OutpointNotInEligibleView(OutPoint),
}

#[cfg(test)]
#[path = "inventory_tests.rs"]
mod tests;

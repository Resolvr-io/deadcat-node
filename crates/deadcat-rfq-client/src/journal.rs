//! Durable taker execution records and exact-retry capabilities.

use std::fmt;
use std::fs::OpenOptions;
use std::path::Path;

use deadcat_rfq_rpc::{
    AttestationError, FixedBytes32, RelayObservationDto, RelayStatusDto, ReservationIdDto,
    ReservationStateDto, ReservationStatusDto,
};
use deadcat_types::ChainIdentity;
use elements::AssetId;
use iroh::EndpointId;
use redb::{
    CommitError, Database, DatabaseError, Durability, ReadableDatabase as _, ReadableTable as _,
    SetDurabilityError, StorageError, TableDefinition, TableError, TableHandle as _,
    TransactionError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::session::{
    AuthenticatedExecutionStatus, QUOTE_RECOVERY_RECORD_VERSION, QuoteRecoveryRecord,
    ReservationHandle,
};
use crate::settlement::{
    ExecutionAttempt, ExecutionAttemptError, ExecutionAttemptRecord, ExecutionBinding,
    SignedExecutionError,
};

pub const EXECUTION_JOURNAL_RECORD_VERSION: u32 = 1;
pub const EXECUTION_JOURNAL_BINDING_VERSION: u32 = 1;
pub const MAX_EXECUTION_JOURNAL_PAGE_SIZE: usize = 256;

const RECORD_DIGEST_DOMAIN: &[u8] = b"deadcat/rfq/client-execution-journal/v1";
const BINDING_METADATA_KEY: &str = "binding";
const METADATA: TableDefinition<&str, &[u8]> = TableDefinition::new("rfq_journal_metadata");
const EXECUTIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("rfq_executions");

/// Immutable identity of one wallet/journal state bundle.
///
/// The embedding process must create one random nonzero `bundle_id`, pair it
/// with the concrete wallet instance, and use this exact value whenever it
/// opens the journal. The client endpoint, chain, and policy asset additionally
/// prevent state created for another taker or Liquid chain from being accepted
/// under the same paths.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionJournalBinding {
    version: u32,
    bundle_id: FixedBytes32,
    wallet_instance_id: FixedBytes32,
    client_endpoint: EndpointId,
    chain: ChainIdentity,
    policy_asset: AssetId,
}

impl ExecutionJournalBinding {
    pub fn new(
        bundle_id: FixedBytes32,
        wallet_instance_id: FixedBytes32,
        client_endpoint: EndpointId,
        chain: ChainIdentity,
        policy_asset: AssetId,
    ) -> Result<Self, ExecutionJournalBindingError> {
        let binding = Self {
            version: EXECUTION_JOURNAL_BINDING_VERSION,
            bundle_id,
            wallet_instance_id,
            client_endpoint,
            chain,
            policy_asset,
        };
        binding.validate()?;
        Ok(binding)
    }

    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    #[must_use]
    pub const fn bundle_id(&self) -> FixedBytes32 {
        self.bundle_id
    }

    #[must_use]
    pub const fn wallet_instance_id(&self) -> FixedBytes32 {
        self.wallet_instance_id
    }

    #[must_use]
    pub const fn client_endpoint(&self) -> EndpointId {
        self.client_endpoint
    }

    #[must_use]
    pub const fn chain(&self) -> ChainIdentity {
        self.chain
    }

    #[must_use]
    pub const fn policy_asset(&self) -> AssetId {
        self.policy_asset
    }

    fn validate(&self) -> Result<(), ExecutionJournalBindingError> {
        if self.version != EXECUTION_JOURNAL_BINDING_VERSION {
            return Err(ExecutionJournalBindingError::UnsupportedVersion {
                actual: self.version,
            });
        }
        if self.bundle_id.to_bytes() == [0; 32] {
            return Err(ExecutionJournalBindingError::ZeroBundleId);
        }
        if self.wallet_instance_id.to_bytes() == [0; 32] {
            return Err(ExecutionJournalBindingError::ZeroWalletInstanceId);
        }
        Ok(())
    }
}

impl fmt::Debug for ExecutionJournalBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionJournalBinding")
            .field("version", &self.version)
            .field("bundle_id", &"[opaque]")
            .field("wallet_instance_id", &"[opaque]")
            .field("client_endpoint", &self.client_endpoint)
            .field("chain", &self.chain)
            .field("policy_asset", &self.policy_asset)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ExecutionJournalBindingError {
    #[error("unsupported execution-journal binding version {actual}")]
    UnsupportedVersion { actual: u32 },
    #[error("execution-journal bundle ID must be nonzero")]
    ZeroBundleId,
    #[error("execution-journal wallet instance ID must be nonzero")]
    ZeroWalletInstanceId,
}

/// Collision-resistant durable lookup key for one owner-scoped reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionJournalKey {
    provider_endpoint: FixedBytes32,
    client_endpoint: FixedBytes32,
    reservation_id: ReservationIdDto,
}

impl ExecutionJournalKey {
    fn from_binding(binding: &ExecutionBinding) -> Self {
        Self {
            provider_endpoint: binding.provider_endpoint(),
            client_endpoint: binding.client_endpoint(),
            reservation_id: binding.reservation_id(),
        }
    }

    /// Derive the deterministic journal lookup key before attempting a durable
    /// arm. This carries no execution authority; it lets callers locate a
    /// record after an ambiguous storage result.
    #[must_use]
    pub fn for_attempt(attempt: &ExecutionAttempt) -> Self {
        Self::from_binding(attempt.binding())
    }

    #[must_use]
    pub const fn provider_endpoint(&self) -> FixedBytes32 {
        self.provider_endpoint
    }

    #[must_use]
    pub const fn client_endpoint(&self) -> FixedBytes32 {
        self.client_endpoint
    }

    #[must_use]
    pub const fn reservation_id(&self) -> ReservationIdDto {
        self.reservation_id
    }

    fn to_bytes(self) -> [u8; 96] {
        let mut bytes = [0_u8; 96];
        bytes[..32].copy_from_slice(&self.provider_endpoint.to_bytes());
        bytes[32..64].copy_from_slice(&self.client_endpoint.to_bytes());
        bytes[64..].copy_from_slice(&self.reservation_id.to_bytes());
        bytes
    }
}

/// Latest durable knowledge about the provider-side reservation.
///
/// `Armed` means the exact attempt may have been submitted. A transport error
/// never advances this to a terminal failure state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionJournalObservation {
    Armed,
    Reserved(ReservationStatusDto),
    Released(ReservationStatusDto),
    Committed(ReservationStatusDto),
    Signed(ReservationStatusDto),
}

impl ExecutionJournalObservation {
    #[must_use]
    pub const fn status(&self) -> Option<&ReservationStatusDto> {
        match self {
            Self::Armed => None,
            Self::Reserved(status)
            | Self::Released(status)
            | Self::Committed(status)
            | Self::Signed(status) => Some(status),
        }
    }

    /// Whether wallet inputs associated with this attempt must remain
    /// unavailable to new taker settlements.
    ///
    /// Only an authenticated, durably recorded `Released` observation proves
    /// that the provider can no longer sign the attempt. Every other state is
    /// therefore conservatively treated as still owning the taker funding.
    #[must_use]
    pub const fn requires_taker_funding_exclusion(&self) -> bool {
        !matches!(self, Self::Released(_))
    }

    fn from_status(status: ReservationStatusDto) -> Self {
        match status.state {
            ReservationStateDto::Reserved => Self::Reserved(status),
            ReservationStateDto::Released { .. } => Self::Released(status),
            ReservationStateDto::Committed { .. } => Self::Committed(status),
            ReservationStateDto::Signed { .. } => Self::Signed(status),
        }
    }
}

/// Versioned durable state for one exact taker-authorized attempt.
///
/// The embedded digest detects accidental corruption and inconsistent record
/// assembly. It is not a MAC and does not authenticate a database controlled by
/// an attacker; callers must protect the journal file as wallet state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionJournalRecord {
    version: u32,
    revision: u64,
    quote: QuoteRecoveryRecord,
    attempt: ExecutionAttemptRecord,
    observation: ExecutionJournalObservation,
    digest: FixedBytes32,
}

impl ExecutionJournalRecord {
    fn armed(
        quote: QuoteRecoveryRecord,
        attempt: ExecutionAttemptRecord,
    ) -> Result<Self, ExecutionJournalRecordError> {
        let mut record = Self {
            version: EXECUTION_JOURNAL_RECORD_VERSION,
            revision: 0,
            quote,
            attempt,
            observation: ExecutionJournalObservation::Armed,
            digest: FixedBytes32::new([0; 32]),
        };
        record.digest = record_digest(&record)?;
        JournaledExecution::from_record(record.clone())?;
        Ok(record)
    }

    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn quote(&self) -> &QuoteRecoveryRecord {
        &self.quote
    }

    #[must_use]
    pub const fn attempt(&self) -> &ExecutionAttemptRecord {
        &self.attempt
    }

    #[must_use]
    pub const fn observation(&self) -> &ExecutionJournalObservation {
        &self.observation
    }

    #[must_use]
    pub const fn digest(&self) -> FixedBytes32 {
        self.digest
    }

    /// Validate an untrusted serialized record without minting execution
    /// authority. Only a journal implementation may return the capability
    /// accepted by network execution methods.
    pub fn validate(&self) -> Result<(), ExecutionJournalRecordError> {
        JournaledExecution::from_record(self.clone()).map(|_| ())
    }

    #[cfg(test)]
    pub(crate) fn recompute_digest_for_test(&mut self) -> Result<(), ExecutionJournalRecordError> {
        self.digest = record_digest(self)?;
        Ok(())
    }
}

/// A fully validated record returned only after durable arm or load.
///
/// `RfqSession` requires this capability for post-expiry exact replay.
#[derive(Clone, Debug)]
pub struct JournaledExecution {
    record: ExecutionJournalRecord,
    attempt: ExecutionAttempt,
}

impl JournaledExecution {
    /// Validate an untrusted serialized record before using it for recovery.
    fn from_record(record: ExecutionJournalRecord) -> Result<Self, ExecutionJournalRecordError> {
        if record.version != EXECUTION_JOURNAL_RECORD_VERSION {
            return Err(ExecutionJournalRecordError::UnsupportedVersion {
                actual: record.version,
            });
        }
        if record.quote.version() != QUOTE_RECOVERY_RECORD_VERSION {
            return Err(ExecutionJournalRecordError::UnsupportedQuoteVersion {
                actual: record.quote.version(),
            });
        }
        if record.digest != record_digest(&record)? {
            return Err(ExecutionJournalRecordError::DigestMismatch);
        }
        record
            .quote
            .validate_integrity()
            .map_err(|_| ExecutionJournalRecordError::InvalidQuoteRecoveryRecord)?;
        validate_self_contained_quote(&record.quote)?;
        let attempt = ExecutionAttempt::from_record(record.attempt.clone())?;
        validate_quote_attempt_binding(&record.quote, attempt.binding())?;
        attempt
            .layout()
            .validate_for_quote(&record.quote.signed_quote().quote)
            .map_err(ExecutionJournalRecordError::InvalidLayoutForQuote)?;
        if let Some(status) = record.observation.status() {
            validate_status_binding(attempt.binding(), status)?;
            validate_observation_variant(&record.observation, status)?;
            validate_signed_result(&attempt, status)?;
        }
        Ok(Self { record, attempt })
    }

    #[must_use]
    pub fn key(&self) -> ExecutionJournalKey {
        ExecutionJournalKey::from_binding(self.attempt.binding())
    }

    #[must_use]
    pub const fn quote(&self) -> &QuoteRecoveryRecord {
        &self.record.quote
    }

    #[must_use]
    pub const fn attempt(&self) -> &ExecutionAttempt {
        &self.attempt
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.record.revision
    }

    #[must_use]
    pub const fn observation(&self) -> &ExecutionJournalObservation {
        &self.record.observation
    }

    #[must_use]
    pub fn to_record(&self) -> ExecutionJournalRecord {
        self.record.clone()
    }

    pub(crate) fn validate_handle(
        &self,
        handle: &ReservationHandle,
    ) -> Result<(), ExecutionAttemptError> {
        let binding = self.attempt.binding();
        let matches = binding.provider_endpoint().to_bytes()
            == *handle.provider_endpoint().as_bytes()
            && binding.client_endpoint().to_bytes() == *handle.client_endpoint().as_bytes()
            && binding.chain() == handle.chain()
            && binding.policy_asset() == handle.policy_asset()
            && binding.reservation_id() == handle.reservation_id()
            && binding.quote_commitment() == handle.quote_commitment()
            && binding.created_at_millis() == handle.created_at_millis()
            && binding.accept_before_millis() == handle.accept_before_millis();
        if !matches {
            return Err(ExecutionAttemptError::ReservationBindingMismatch);
        }
        Ok(())
    }

    pub(crate) fn validate_next_status(
        &self,
        status: &ReservationStatusDto,
    ) -> Result<(), ExecutionJournalRecordError> {
        validate_status_binding(self.attempt.binding(), status)?;
        validate_signed_result(&self.attempt, status)?;
        validate_transition(&self.record.observation, status).map(|_| ())
    }

    pub(crate) fn validate_dispatchable(&self) -> Result<(), ExecutionJournalRecordError> {
        if matches!(
            self.observation(),
            ExecutionJournalObservation::Armed | ExecutionJournalObservation::Reserved(_)
        ) {
            return Ok(());
        }
        Err(ExecutionJournalRecordError::NotDispatchable)
    }
}

/// Synchronous durable storage contract for exact execution attempts.
pub trait ExecutionJournal: sealed::Sealed {
    /// Immutable wallet, client, and chain identity persisted with this
    /// journal when it was created.
    #[must_use]
    fn binding(&self) -> ExecutionJournalBinding;

    /// Atomically persist the exact attempt before its first network dispatch.
    fn arm(
        &self,
        quote: &QuoteRecoveryRecord,
        attempt: &ExecutionAttempt,
    ) -> Result<JournaledExecution, ExecutionJournalError>;

    fn load(
        &self,
        key: ExecutionJournalKey,
    ) -> Result<Option<JournaledExecution>, ExecutionJournalError>;

    /// Discover durable records in deterministic key order after restart.
    /// Pass the last key from the previous page as `after`.
    fn list_after(
        &self,
        after: Option<ExecutionJournalKey>,
        limit: usize,
    ) -> Result<Vec<JournaledExecution>, ExecutionJournalError>;

    /// Compare-and-swap one authenticated provider execution observation.
    ///
    /// The opaque capability proves the status came from an authenticated
    /// execution or exact-retry session path. The journal independently
    /// validates its binding and state transition before persisting it.
    fn observe(
        &self,
        key: ExecutionJournalKey,
        expected_revision: u64,
        observation: &AuthenticatedExecutionStatus,
    ) -> Result<JournaledExecution, ExecutionJournalError>;
}

mod sealed {
    pub trait Sealed {}
}

/// redb-backed journal with immediate durability for every mutation.
///
/// A commit error is conservatively ambiguous: reopen the database and use
/// [`ExecutionJournal::list_after`] before deciding whether to retry.
pub struct RedbExecutionJournal {
    database: Database,
    binding: ExecutionJournalBinding,
}

impl sealed::Sealed for RedbExecutionJournal {}

impl RedbExecutionJournal {
    /// Bootstrap a new execution journal without replacing any existing file.
    ///
    /// Failure after the file is created may leave an invalid file behind. A
    /// subsequent call will still fail rather than silently replacing it.
    /// This is an explicit initialization operation, never a fallback after
    /// [`Self::open`] fails. The embedding process owns secure path selection,
    /// permissions, directory durability, and wallet/journal lifecycle pairing.
    pub fn create(
        path: impl AsRef<Path>,
        binding: ExecutionJournalBinding,
    ) -> Result<Self, ExecutionJournalError> {
        binding.validate()?;
        let encoded_binding = encode_binding(&binding)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(DatabaseError::from)?;
        let database = Database::builder().create_file(file)?;
        let journal = Self { database, binding };
        let mut write = journal.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        {
            let mut metadata = write.open_table(METADATA)?;
            metadata.insert(BINDING_METADATA_KEY, encoded_binding.as_slice())?;
        }
        {
            let _executions = write.open_table(EXECUTIONS)?;
        }
        write.commit()?;
        Ok(journal)
    }

    /// Open an existing execution journal without creating a missing file or
    /// initializing a missing table.
    ///
    /// redb may repair an unclean existing database while opening it. The
    /// persisted binding must exactly equal `expected_binding`; opening a valid
    /// but unrelated empty journal therefore fails closed.
    ///
    /// The binding identifies a state generation; it is not a monotonic
    /// freshness proof. An older snapshot of this same bound journal still
    /// matches. The embedding process must therefore coordinate wallet and
    /// journal backup/restore and provide any required rollback protection.
    pub fn open(
        path: impl AsRef<Path>,
        expected_binding: ExecutionJournalBinding,
    ) -> Result<Self, ExecutionJournalError> {
        expected_binding.validate()?;
        let database = Database::open(path)?;
        let binding = {
            let read = database.begin_read()?;
            let _executions = read.open_table(EXECUTIONS)?;
            let metadata = read.open_table(METADATA).map_err(|error| match error {
                TableError::TableDoesNotExist(name) if name == METADATA.name() => {
                    ExecutionJournalError::MissingBindingMetadata
                }
                other => ExecutionJournalError::Table(other),
            })?;
            let Some(encoded) = metadata.get(BINDING_METADATA_KEY)? else {
                return Err(ExecutionJournalError::MissingBindingMetadata);
            };
            decode_binding(encoded.value())?
        };
        validate_expected_binding(binding, expected_binding)?;
        Ok(Self { database, binding })
    }

    #[cfg(test)]
    pub(crate) fn overwrite_record_at_storage_key_for_test(
        &self,
        key: ExecutionJournalKey,
        record: &ExecutionJournalRecord,
    ) -> Result<(), ExecutionJournalError> {
        let key = key.to_bytes();
        let encoded = encode_record(record)?;
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        {
            let mut table = write.open_table(EXECUTIONS)?;
            table.insert(key.as_slice(), encoded.as_slice())?;
        }
        write.commit()?;
        Ok(())
    }
}

impl ExecutionJournal for RedbExecutionJournal {
    fn binding(&self) -> ExecutionJournalBinding {
        self.binding
    }

    fn arm(
        &self,
        quote: &QuoteRecoveryRecord,
        attempt: &ExecutionAttempt,
    ) -> Result<JournaledExecution, ExecutionJournalError> {
        validate_execution_binding(self.binding, attempt.binding())?;
        let candidate = ExecutionJournalRecord::armed(quote.clone(), attempt.to_record())?;
        let validated = JournaledExecution::from_record(candidate.clone())?;
        let key = validated.key().to_bytes();
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        {
            let mut table = write.open_table(EXECUTIONS)?;
            if let Some(existing) = table.get(key.as_slice())? {
                let existing = decode_record(existing.value())?;
                let existing = JournaledExecution::from_record(existing)?;
                if existing.quote() == quote
                    && existing.attempt().to_record() == attempt.to_record()
                {
                    return Ok(existing);
                }
                return Err(ExecutionJournalError::AttemptConflict);
            }
            let encoded = encode_record(&candidate)?;
            table.insert(key.as_slice(), encoded.as_slice())?;
        }
        write.commit()?;
        Ok(validated)
    }

    fn load(
        &self,
        key: ExecutionJournalKey,
    ) -> Result<Option<JournaledExecution>, ExecutionJournalError> {
        let key_bytes = key.to_bytes();
        let read = self.database.begin_read()?;
        let table = read.open_table(EXECUTIONS)?;
        let Some(value) = table.get(key_bytes.as_slice())? else {
            return Ok(None);
        };
        let record = JournaledExecution::from_record(decode_record(value.value())?)?;
        if record.key() != key {
            return Err(ExecutionJournalError::KeyMismatch);
        }
        validate_execution_binding(self.binding, record.attempt().binding())?;
        Ok(Some(record))
    }

    fn list_after(
        &self,
        after: Option<ExecutionJournalKey>,
        limit: usize,
    ) -> Result<Vec<JournaledExecution>, ExecutionJournalError> {
        if limit == 0 || limit > MAX_EXECUTION_JOURNAL_PAGE_SIZE {
            return Err(ExecutionJournalError::InvalidPageSize { limit });
        }
        let read = self.database.begin_read()?;
        let table = read.open_table(EXECUTIONS)?;
        let mut records = Vec::with_capacity(limit);
        for row in table.iter()? {
            let (key, value) = row?;
            let record = JournaledExecution::from_record(decode_record(value.value())?)?;
            if key.value() != record.key().to_bytes() {
                return Err(ExecutionJournalError::KeyMismatch);
            }
            validate_execution_binding(self.binding, record.attempt().binding())?;
            if after.is_some_and(|after| record.key() <= after) {
                continue;
            }
            records.push(record);
            if records.len() == limit {
                break;
            }
        }
        Ok(records)
    }

    fn observe(
        &self,
        key: ExecutionJournalKey,
        expected_revision: u64,
        authenticated: &AuthenticatedExecutionStatus,
    ) -> Result<JournaledExecution, ExecutionJournalError> {
        let status = authenticated.status();
        let key_bytes = key.to_bytes();
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        let updated = {
            let mut table = write.open_table(EXECUTIONS)?;
            let Some(existing) = table.get(key_bytes.as_slice())? else {
                return Err(ExecutionJournalError::NotFound);
            };
            let current = JournaledExecution::from_record(decode_record(existing.value())?)?;
            drop(existing);
            if current.key() != key {
                return Err(ExecutionJournalError::KeyMismatch);
            }
            validate_execution_binding(self.binding, current.attempt().binding())?;
            if authenticated.journal_key() != key
                || authenticated.attempt_digest() != current.attempt().digest()
            {
                return Err(ExecutionJournalError::AuthenticatedStatusAttemptMismatch);
            }
            if current.revision() != expected_revision {
                return Err(ExecutionJournalError::RevisionConflict {
                    expected: expected_revision,
                    actual: current.revision(),
                });
            }
            current.validate_next_status(status)?;
            let observation = validate_transition(current.observation(), status)?;
            if &observation == current.observation() {
                return Ok(current);
            }
            let revision = current
                .revision()
                .checked_add(1)
                .ok_or(ExecutionJournalError::RevisionExhausted)?;
            let mut record = ExecutionJournalRecord {
                version: EXECUTION_JOURNAL_RECORD_VERSION,
                revision,
                quote: current.quote().clone(),
                attempt: current.attempt().to_record(),
                observation,
                digest: FixedBytes32::new([0; 32]),
            };
            record.digest = record_digest(&record)?;
            let updated = JournaledExecution::from_record(record.clone())?;
            let encoded = encode_record(&record)?;
            table.insert(key_bytes.as_slice(), encoded.as_slice())?;
            updated
        };
        write.commit()?;
        Ok(updated)
    }
}

fn validate_self_contained_quote(
    record: &QuoteRecoveryRecord,
) -> Result<(), ExecutionJournalRecordError> {
    let provider = EndpointId::from_bytes(
        &record
            .signed_quote()
            .attestation
            .provider_endpoint
            .to_bytes(),
    )
    .map_err(|_| ExecutionJournalRecordError::InvalidProviderEndpoint)?;
    let client =
        EndpointId::from_bytes(&record.signed_quote().attestation.client_endpoint.to_bytes())
            .map_err(|_| ExecutionJournalRecordError::InvalidClientEndpoint)?;
    record.signed_quote().clone().verify(
        provider,
        client,
        record.idempotency_key(),
        record.request(),
    )?;
    Ok(())
}

fn validate_quote_attempt_binding(
    recovery: &QuoteRecoveryRecord,
    binding: &ExecutionBinding,
) -> Result<(), ExecutionJournalRecordError> {
    let signed = recovery.signed_quote();
    let quote = &signed.quote;
    let matches = binding.provider_endpoint() == signed.attestation.provider_endpoint
        && binding.client_endpoint() == signed.attestation.client_endpoint
        && binding.chain().network == quote.network
        && binding.chain().genesis_hash == quote.genesis_hash
        && binding.policy_asset() == quote.policy_asset
        && binding.reservation_id() == quote.reservation_id
        && binding.quote_commitment() == quote.quote_commitment
        && binding.created_at_millis() == quote.created_at_millis
        && binding.accept_before_millis() == quote.accept_before_millis;
    if !matches {
        return Err(ExecutionJournalRecordError::QuoteAttemptBindingMismatch);
    }
    Ok(())
}

fn validate_status_binding(
    binding: &ExecutionBinding,
    status: &ReservationStatusDto,
) -> Result<(), ExecutionJournalRecordError> {
    status
        .validate()
        .map_err(ExecutionJournalRecordError::InvalidStatus)?;
    let matches = binding.reservation_id() == status.reservation_id
        && binding.quote_commitment() == status.quote_commitment
        && binding.created_at_millis() == status.created_at_millis
        && binding.accept_before_millis() == status.accept_before_millis;
    if !matches {
        return Err(ExecutionJournalRecordError::StatusBindingMismatch);
    }
    Ok(())
}

fn validate_signed_result(
    attempt: &ExecutionAttempt,
    status: &ReservationStatusDto,
) -> Result<(), ExecutionJournalRecordError> {
    if let ReservationStateDto::Signed { signed_pset, .. } = &status.state {
        attempt.verify_signed_result(signed_pset)?;
    }
    Ok(())
}

fn validate_observation_variant(
    observation: &ExecutionJournalObservation,
    status: &ReservationStatusDto,
) -> Result<(), ExecutionJournalRecordError> {
    let matches = matches!(
        (observation, &status.state),
        (
            ExecutionJournalObservation::Reserved(_),
            ReservationStateDto::Reserved
        ) | (
            ExecutionJournalObservation::Released(_),
            ReservationStateDto::Released { .. }
        ) | (
            ExecutionJournalObservation::Committed(_),
            ReservationStateDto::Committed { .. }
        ) | (
            ExecutionJournalObservation::Signed(_),
            ReservationStateDto::Signed { .. }
        )
    );
    if !matches {
        return Err(ExecutionJournalRecordError::ObservationStateMismatch);
    }
    Ok(())
}

fn validate_transition(
    current: &ExecutionJournalObservation,
    next: &ReservationStatusDto,
) -> Result<ExecutionJournalObservation, ExecutionJournalRecordError> {
    if current.status() == Some(next) {
        return Ok(current.clone());
    }
    let allowed = match (current, &next.state) {
        (ExecutionJournalObservation::Armed, _) => true,
        (ExecutionJournalObservation::Reserved(_), ReservationStateDto::Reserved) => true,
        (ExecutionJournalObservation::Reserved(_), ReservationStateDto::Released { .. }) => true,
        (ExecutionJournalObservation::Reserved(_), ReservationStateDto::Committed { .. }) => true,
        (ExecutionJournalObservation::Reserved(_), ReservationStateDto::Signed { .. }) => true,
        (
            ExecutionJournalObservation::Committed(previous),
            ReservationStateDto::Committed {
                signing_commitment,
                committed_at_millis,
            },
        ) => matches!(
            previous.state,
            ReservationStateDto::Committed {
                signing_commitment: previous_commitment,
                committed_at_millis: previous_at,
            } if previous_commitment == *signing_commitment && previous_at == *committed_at_millis
        ),
        (
            ExecutionJournalObservation::Committed(previous),
            ReservationStateDto::Signed {
                signing_commitment,
                committed_at_millis,
                ..
            },
        ) => matches!(
            previous.state,
            ReservationStateDto::Committed {
                signing_commitment: previous_commitment,
                committed_at_millis: previous_at,
            } if previous_commitment == *signing_commitment && previous_at == *committed_at_millis
        ),
        (
            ExecutionJournalObservation::Signed(previous),
            ReservationStateDto::Signed {
                signing_commitment,
                artifact_digest,
                committed_at_millis,
                signed_at_millis,
                signed_pset,
                relay,
            },
        ) => matches!(
            &previous.state,
            ReservationStateDto::Signed {
                signing_commitment: previous_commitment,
                artifact_digest: previous_artifact,
                committed_at_millis: previous_committed_at,
                signed_at_millis: previous_signed_at,
                signed_pset: previous_pset,
                relay: previous_relay,
            } if previous_commitment == signing_commitment
                && previous_artifact == artifact_digest
                && previous_committed_at == committed_at_millis
                && previous_signed_at == signed_at_millis
                && previous_pset.as_bytes() == signed_pset.as_bytes()
                && valid_relay_update(previous_relay, relay)
        ),
        (ExecutionJournalObservation::Released(_), _)
        | (ExecutionJournalObservation::Signed(_), _)
        | (ExecutionJournalObservation::Committed(_), _) => false,
    };
    if !allowed {
        return Err(ExecutionJournalRecordError::StatusRegression);
    }
    Ok(ExecutionJournalObservation::from_status(next.clone()))
}

fn valid_relay_update(previous: &RelayStatusDto, next: &RelayStatusDto) -> bool {
    let observation_time_is_monotonic = match (
        previous.last_observed_at_millis,
        next.last_observed_at_millis,
    ) {
        (Some(previous), Some(next)) => next >= previous,
        (Some(_), None) => false,
        _ => true,
    };
    let failure_time_is_monotonic =
        match (previous.last_failure_at_millis, next.last_failure_at_millis) {
            (Some(previous), Some(next)) => next >= previous,
            _ => true,
        };
    let confirmed_reorg = match (previous.observation, next.observation) {
        (
            RelayObservationDto::Confirmed {
                block_hash: previous_hash,
                block_height: previous_height,
            },
            RelayObservationDto::Confirmed {
                block_hash: next_hash,
                block_height: next_height,
            },
        ) => previous_hash != next_hash || previous_height != next_height,
        (RelayObservationDto::Confirmed { .. }, _) => true,
        _ => false,
    };
    let regressed_to_unobserved = !matches!(previous.observation, RelayObservationDto::Unobserved)
        && matches!(next.observation, RelayObservationDto::Unobserved);

    previous.txid == next.txid
        && previous.wtxid == next.wtxid
        && next.revision > previous.revision
        && next.attempt_count >= previous.attempt_count
        && next.reorg_count >= previous.reorg_count
        && observation_time_is_monotonic
        && failure_time_is_monotonic
        && !regressed_to_unobserved
        && (!confirmed_reorg || next.reorg_count > previous.reorg_count)
}

#[derive(Serialize)]
struct RecordDigestInput<'a> {
    version: u32,
    revision: u64,
    quote: &'a QuoteRecoveryRecord,
    attempt: &'a ExecutionAttemptRecord,
    observation: &'a ExecutionJournalObservation,
}

fn record_digest(
    record: &ExecutionJournalRecord,
) -> Result<FixedBytes32, ExecutionJournalRecordError> {
    let input = RecordDigestInput {
        version: record.version,
        revision: record.revision,
        quote: &record.quote,
        attempt: &record.attempt,
        observation: &record.observation,
    };
    let encoded = postcard::to_allocvec(&input)?;
    let mut digest = Sha256::new();
    digest.update(RECORD_DIGEST_DOMAIN);
    digest.update((encoded.len() as u64).to_be_bytes());
    digest.update(encoded);
    Ok(FixedBytes32::new(digest.finalize().into()))
}

fn encode_record(record: &ExecutionJournalRecord) -> Result<Vec<u8>, ExecutionJournalError> {
    postcard::to_allocvec(record).map_err(ExecutionJournalError::Encoding)
}

fn decode_record(bytes: &[u8]) -> Result<ExecutionJournalRecord, ExecutionJournalError> {
    postcard::from_bytes(bytes).map_err(ExecutionJournalError::Encoding)
}

fn encode_binding(binding: &ExecutionJournalBinding) -> Result<Vec<u8>, ExecutionJournalError> {
    postcard::to_allocvec(binding).map_err(ExecutionJournalError::BindingEncoding)
}

fn decode_binding(bytes: &[u8]) -> Result<ExecutionJournalBinding, ExecutionJournalError> {
    let binding: ExecutionJournalBinding =
        postcard::from_bytes(bytes).map_err(ExecutionJournalError::BindingEncoding)?;
    binding.validate()?;
    Ok(binding)
}

fn validate_expected_binding(
    actual: ExecutionJournalBinding,
    expected: ExecutionJournalBinding,
) -> Result<(), ExecutionJournalError> {
    if actual.bundle_id != expected.bundle_id {
        return Err(ExecutionJournalError::BundleIdMismatch);
    }
    if actual.wallet_instance_id != expected.wallet_instance_id {
        return Err(ExecutionJournalError::WalletInstanceIdMismatch);
    }
    if actual.client_endpoint != expected.client_endpoint {
        return Err(ExecutionJournalError::ClientEndpointMismatch);
    }
    if actual.chain != expected.chain {
        return Err(ExecutionJournalError::ChainIdentityMismatch);
    }
    if actual.policy_asset != expected.policy_asset {
        return Err(ExecutionJournalError::PolicyAssetMismatch);
    }
    Ok(())
}

fn validate_execution_binding(
    journal: ExecutionJournalBinding,
    execution: &ExecutionBinding,
) -> Result<(), ExecutionJournalError> {
    if execution.client_endpoint().to_bytes() != *journal.client_endpoint.as_bytes() {
        return Err(ExecutionJournalError::AttemptClientEndpointMismatch);
    }
    if execution.chain() != journal.chain {
        return Err(ExecutionJournalError::AttemptChainIdentityMismatch);
    }
    if execution.policy_asset() != journal.policy_asset {
        return Err(ExecutionJournalError::AttemptPolicyAssetMismatch);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ExecutionJournalRecordError {
    #[error("unsupported execution-journal record version {actual}")]
    UnsupportedVersion { actual: u32 },
    #[error("unsupported quote-recovery record version {actual}")]
    UnsupportedQuoteVersion { actual: u32 },
    #[error("execution-journal record digest does not match its contents")]
    DigestMismatch,
    #[error("nested quote-recovery record failed its own integrity check")]
    InvalidQuoteRecoveryRecord,
    #[error("quote-recovery provider endpoint is invalid")]
    InvalidProviderEndpoint,
    #[error("quote-recovery client endpoint is invalid")]
    InvalidClientEndpoint,
    #[error("quote-recovery attestation is invalid: {0}")]
    InvalidQuote(#[from] AttestationError),
    #[error("execution attempt is invalid: {0}")]
    InvalidAttempt(#[from] ExecutionAttemptError),
    #[error("provider-signed execution is invalid: {0}")]
    InvalidSignedExecution(#[from] SignedExecutionError),
    #[error("quote recovery and execution attempt bindings differ")]
    QuoteAttemptBindingMismatch,
    #[error("execution layout is incomplete or invalid for the signed quote: {0}")]
    InvalidLayoutForQuote(#[source] deadcat_rfq_rpc::FirmQuoteValidationError),
    #[error("reservation status is invalid: {0}")]
    InvalidStatus(#[source] deadcat_rfq_rpc::FirmQuoteValidationError),
    #[error("reservation status differs from the execution binding")]
    StatusBindingMismatch,
    #[error("journal observation variant differs from its embedded status")]
    ObservationStateMismatch,
    #[error("reservation status regressed or changed an immutable commitment")]
    StatusRegression,
    #[error("terminal execution-journal state cannot be dispatched")]
    NotDispatchable,
    #[error("execution-journal record encoding failed: {0}")]
    Encoding(#[from] postcard::Error),
}

#[derive(Debug, Error)]
pub enum ExecutionJournalError {
    #[error("execution-journal binding is invalid: {0}")]
    InvalidBinding(#[from] ExecutionJournalBindingError),
    #[error("execution-journal binding metadata is missing")]
    MissingBindingMetadata,
    #[error("execution-journal bundle ID differs from the expected state bundle")]
    BundleIdMismatch,
    #[error("execution-journal wallet instance ID differs from the expected wallet")]
    WalletInstanceIdMismatch,
    #[error("execution-journal client endpoint differs from the expected client")]
    ClientEndpointMismatch,
    #[error("execution-journal chain identity differs from the expected chain")]
    ChainIdentityMismatch,
    #[error("execution-journal policy asset differs from the expected policy asset")]
    PolicyAssetMismatch,
    #[error("execution attempt client endpoint differs from the journal binding")]
    AttemptClientEndpointMismatch,
    #[error("execution attempt chain identity differs from the journal binding")]
    AttemptChainIdentityMismatch,
    #[error("execution attempt policy asset differs from the journal binding")]
    AttemptPolicyAssetMismatch,
    #[error("execution-journal record is invalid: {0}")]
    InvalidRecord(#[from] ExecutionJournalRecordError),
    #[error("a different attempt is already armed for this reservation")]
    AttemptConflict,
    #[error("execution-journal record was not found")]
    NotFound,
    #[error("execution-journal lookup key differs from the stored record")]
    KeyMismatch,
    #[error("authenticated reservation status belongs to a different execution attempt")]
    AuthenticatedStatusAttemptMismatch,
    #[error("execution-journal revision conflict: expected {expected}, actual {actual}")]
    RevisionConflict { expected: u64, actual: u64 },
    #[error("execution-journal revision space is exhausted")]
    RevisionExhausted,
    #[error("execution-journal page size {limit} is outside 1..={MAX_EXECUTION_JOURNAL_PAGE_SIZE}")]
    InvalidPageSize { limit: usize },
    #[error("execution-journal encoding failed: {0}")]
    Encoding(postcard::Error),
    #[error("execution-journal binding encoding failed: {0}")]
    BindingEncoding(postcard::Error),
    #[error("redb database error: {0}")]
    Database(#[from] DatabaseError),
    #[error("redb transaction error: {0}")]
    Transaction(#[from] TransactionError),
    #[error("redb table error: {0}")]
    Table(#[from] TableError),
    #[error("redb storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("redb commit error: {0}")]
    Commit(#[from] CommitError),
    #[error("redb durability configuration error: {0}")]
    Durability(#[from] SetDurabilityError),
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;

    use super::*;
    use deadcat_rfq_rpc::{ReleaseReasonDto, SettlementPset};
    use deadcat_types::LiquidNetwork;
    use elements::hashes::Hash as _;
    use elements::pset::PartiallySignedTransaction;
    use iroh::SecretKey;

    fn binding() -> ExecutionJournalBinding {
        ExecutionJournalBinding::new(
            FixedBytes32::new([0x31; 32]),
            FixedBytes32::new([0x32; 32]),
            SecretKey::from_bytes(&[0x33; 32]).public(),
            ChainIdentity {
                network: LiquidNetwork::ElementsRegtest,
                genesis_hash: elements::BlockHash::from_byte_array([0x34; 32]),
            },
            AssetId::from_slice(&[0x35; 32]).expect("fixture policy asset"),
        )
        .expect("valid execution-journal binding")
    }

    fn status(state: ReservationStateDto) -> ReservationStatusDto {
        ReservationStatusDto {
            reservation_id: ReservationIdDto::new([0x11; 32]),
            quote_commitment: FixedBytes32::new([0x22; 32]),
            created_at_millis: 100,
            accept_before_millis: 200,
            state,
        }
    }

    fn unobserved_relay(pset: &SettlementPset, signed_at_millis: u64) -> RelayStatusDto {
        let transaction = pset
            .to_pset()
            .expect("fixture PSET")
            .extract_tx()
            .expect("fixture transaction");
        RelayStatusDto {
            txid: transaction.txid(),
            wtxid: transaction.wtxid(),
            revision: 0,
            observation: RelayObservationDto::Unobserved,
            last_observed_at_millis: None,
            next_attempt_at_millis: Some(signed_at_millis),
            last_failure: None,
            last_failure_at_millis: None,
            attempt_count: 0,
            reorg_count: 0,
        }
    }

    fn observed_relay(
        pset: &SettlementPset,
        revision: u64,
        attempt_count: u64,
        observation: RelayObservationDto,
    ) -> RelayStatusDto {
        let mut relay = unobserved_relay(pset, 160);
        relay.revision = revision;
        relay.attempt_count = attempt_count;
        relay.observation = observation;
        relay.last_observed_at_millis = Some(160 + revision);
        relay.next_attempt_at_millis = Some(161 + revision);
        relay
    }

    fn assert_database_io_kind(
        result: Result<RedbExecutionJournal, ExecutionJournalError>,
        expected: ErrorKind,
    ) {
        assert!(matches!(
            result,
            Err(ExecutionJournalError::Database(DatabaseError::Storage(
                StorageError::Io(error)
            ))) if error.kind() == expected
        ));
    }

    #[test]
    fn journal_create_is_no_clobber_and_open_requires_an_existing_journal() {
        let directory = tempfile::tempdir().expect("journal directory");
        let path = directory.path().join("executions.redb");
        let binding = binding();

        assert_database_io_kind(
            RedbExecutionJournal::open(&path, binding),
            ErrorKind::NotFound,
        );
        assert!(!path.exists(), "open must not create a missing journal");

        let journal = RedbExecutionJournal::create(&path, binding).expect("create new journal");
        assert!(path.exists());
        assert_eq!(journal.binding(), binding);
        assert_database_io_kind(
            RedbExecutionJournal::create(&path, binding),
            ErrorKind::AlreadyExists,
        );
        drop(journal);

        assert_database_io_kind(
            RedbExecutionJournal::create(&path, binding),
            ErrorKind::AlreadyExists,
        );
        let reopened = RedbExecutionJournal::open(&path, binding).expect("open existing journal");
        assert_eq!(reopened.binding(), binding);
        assert!(
            reopened
                .list_after(None, 1)
                .expect("read initialized journal")
                .is_empty()
        );
    }

    #[test]
    fn journal_binding_rejects_zero_bundle_and_wallet_instance_ids() {
        let valid = binding();
        assert_eq!(valid.version(), EXECUTION_JOURNAL_BINDING_VERSION);
        assert_eq!(valid.bundle_id(), FixedBytes32::new([0x31; 32]));
        assert_eq!(valid.wallet_instance_id(), FixedBytes32::new([0x32; 32]));
        assert_eq!(
            valid.client_endpoint(),
            SecretKey::from_bytes(&[0x33; 32]).public()
        );
        assert_eq!(valid.chain().network, LiquidNetwork::ElementsRegtest);
        assert_eq!(
            valid.policy_asset(),
            AssetId::from_slice(&[0x35; 32]).expect("fixture policy asset")
        );

        assert!(matches!(
            ExecutionJournalBinding::new(
                FixedBytes32::new([0; 32]),
                valid.wallet_instance_id(),
                valid.client_endpoint(),
                valid.chain(),
                valid.policy_asset(),
            ),
            Err(ExecutionJournalBindingError::ZeroBundleId)
        ));
        assert!(matches!(
            ExecutionJournalBinding::new(
                valid.bundle_id(),
                FixedBytes32::new([0; 32]),
                valid.client_endpoint(),
                valid.chain(),
                valid.policy_asset(),
            ),
            Err(ExecutionJournalBindingError::ZeroWalletInstanceId)
        ));
    }

    #[test]
    fn open_rejects_a_journal_missing_binding_metadata_without_mutating_it() {
        let directory = tempfile::tempdir().expect("journal directory");
        let path = directory.path().join("legacy.redb");
        let database = Database::create(&path).expect("create legacy journal database");
        let write = database.begin_write().expect("begin legacy journal write");
        {
            let _executions = write
                .open_table(EXECUTIONS)
                .expect("create legacy executions table");
        }
        write.commit().expect("commit legacy journal");
        drop(database);

        assert!(matches!(
            RedbExecutionJournal::open(&path, binding()),
            Err(ExecutionJournalError::MissingBindingMetadata)
        ));

        let database = Database::open(&path).expect("reopen legacy journal database");
        let read = database.begin_read().expect("read legacy journal database");
        let tables = read
            .list_tables()
            .expect("list legacy journal tables")
            .map(|table| table.name().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(tables, [EXECUTIONS.name()]);
    }

    #[test]
    fn open_rejects_an_empty_journal_from_another_state_bundle() {
        let directory = tempfile::tempdir().expect("journal directory");
        let path = directory.path().join("swapped.redb");
        let expected = binding();
        let swapped = ExecutionJournalBinding::new(
            FixedBytes32::new([0x41; 32]),
            expected.wallet_instance_id(),
            expected.client_endpoint(),
            expected.chain(),
            expected.policy_asset(),
        )
        .expect("valid swapped binding");
        drop(RedbExecutionJournal::create(&path, swapped).expect("create empty swapped journal"));

        assert!(matches!(
            RedbExecutionJournal::open(&path, expected),
            Err(ExecutionJournalError::BundleIdMismatch)
        ));
    }

    #[test]
    fn open_rejects_each_binding_field_mismatch_independently() {
        let directory = tempfile::tempdir().expect("journal directory");
        let path = directory.path().join("executions.redb");
        let actual = binding();
        drop(RedbExecutionJournal::create(&path, actual).expect("create bound journal"));

        let wrong_bundle = ExecutionJournalBinding::new(
            FixedBytes32::new([0x41; 32]),
            actual.wallet_instance_id(),
            actual.client_endpoint(),
            actual.chain(),
            actual.policy_asset(),
        )
        .expect("wrong bundle binding");
        assert!(matches!(
            RedbExecutionJournal::open(&path, wrong_bundle),
            Err(ExecutionJournalError::BundleIdMismatch)
        ));

        let wrong_wallet = ExecutionJournalBinding::new(
            actual.bundle_id(),
            FixedBytes32::new([0x42; 32]),
            actual.client_endpoint(),
            actual.chain(),
            actual.policy_asset(),
        )
        .expect("wrong wallet binding");
        assert!(matches!(
            RedbExecutionJournal::open(&path, wrong_wallet),
            Err(ExecutionJournalError::WalletInstanceIdMismatch)
        ));

        let wrong_client = ExecutionJournalBinding::new(
            actual.bundle_id(),
            actual.wallet_instance_id(),
            SecretKey::from_bytes(&[0x43; 32]).public(),
            actual.chain(),
            actual.policy_asset(),
        )
        .expect("wrong client binding");
        assert!(matches!(
            RedbExecutionJournal::open(&path, wrong_client),
            Err(ExecutionJournalError::ClientEndpointMismatch)
        ));

        let wrong_chain = ExecutionJournalBinding::new(
            actual.bundle_id(),
            actual.wallet_instance_id(),
            actual.client_endpoint(),
            ChainIdentity {
                network: LiquidNetwork::LiquidTestnet,
                ..actual.chain()
            },
            actual.policy_asset(),
        )
        .expect("wrong chain binding");
        assert!(matches!(
            RedbExecutionJournal::open(&path, wrong_chain),
            Err(ExecutionJournalError::ChainIdentityMismatch)
        ));

        let wrong_policy = ExecutionJournalBinding::new(
            actual.bundle_id(),
            actual.wallet_instance_id(),
            actual.client_endpoint(),
            actual.chain(),
            AssetId::from_slice(&[0x44; 32]).expect("wrong policy asset"),
        )
        .expect("wrong policy binding");
        assert!(matches!(
            RedbExecutionJournal::open(&path, wrong_policy),
            Err(ExecutionJournalError::PolicyAssetMismatch)
        ));
    }

    #[test]
    fn open_rejects_an_existing_non_journal_database_without_mutating_it() {
        let directory = tempfile::tempdir().expect("journal directory");
        let path = directory.path().join("not-a-journal.redb");
        drop(Database::create(&path).expect("create unrelated redb database"));

        assert!(matches!(
            RedbExecutionJournal::open(&path, binding()),
            Err(ExecutionJournalError::Table(TableError::TableDoesNotExist(name)))
                if name == EXECUTIONS.name()
        ));
        assert_database_io_kind(
            RedbExecutionJournal::create(&path, binding()),
            ErrorKind::AlreadyExists,
        );

        let database = Database::open(&path).expect("reopen unrelated database");
        let read = database.begin_read().expect("read unrelated database");
        assert!(
            read.list_tables()
                .expect("list unrelated database tables")
                .next()
                .is_none(),
            "opening as a journal must not create the executions table"
        );
    }

    #[test]
    fn open_rejects_an_empty_replacement_without_initializing_it() {
        let directory = tempfile::tempdir().expect("journal directory");
        let path = directory.path().join("replaced.redb");
        drop(std::fs::File::create(&path).expect("create empty replacement"));

        assert!(RedbExecutionJournal::open(&path, binding()).is_err());
        assert_database_io_kind(
            RedbExecutionJournal::create(&path, binding()),
            ErrorKind::AlreadyExists,
        );
        assert_eq!(
            std::fs::metadata(&path)
                .expect("replacement metadata")
                .len(),
            0,
            "opening an empty replacement must not initialize it as a journal"
        );
    }

    #[test]
    fn only_released_observations_allow_taker_funding_reuse() {
        let reserved = ExecutionJournalObservation::Reserved(status(ReservationStateDto::Reserved));
        let released =
            ExecutionJournalObservation::Released(status(ReservationStateDto::Released {
                reason: ReleaseReasonDto::ClientCancelled,
                at_millis: 150,
            }));
        let committed =
            ExecutionJournalObservation::Committed(status(ReservationStateDto::Committed {
                signing_commitment: FixedBytes32::new([0x33; 32]),
                committed_at_millis: 150,
            }));
        let signed_pset = SettlementPset::from_pset(&PartiallySignedTransaction::new_v2())
            .expect("empty fixture PSET");
        let signed = ExecutionJournalObservation::Signed(status(ReservationStateDto::Signed {
            signing_commitment: FixedBytes32::new([0x33; 32]),
            artifact_digest: FixedBytes32::new([0x44; 32]),
            committed_at_millis: 150,
            signed_at_millis: 160,
            relay: unobserved_relay(&signed_pset, 160),
            signed_pset,
        }));

        assert!(ExecutionJournalObservation::Armed.requires_taker_funding_exclusion());
        assert!(reserved.requires_taker_funding_exclusion());
        assert!(!released.requires_taker_funding_exclusion());
        assert!(committed.requires_taker_funding_exclusion());
        assert!(signed.requires_taker_funding_exclusion());
    }

    #[test]
    fn signed_status_accepts_revisioned_relay_reorgs_but_not_artifact_changes() {
        let signed_pset = SettlementPset::from_pset(&PartiallySignedTransaction::new_v2())
            .expect("empty fixture PSET");
        let signed_state = |relay| ReservationStateDto::Signed {
            signing_commitment: FixedBytes32::new([0x33; 32]),
            artifact_digest: FixedBytes32::new([0x44; 32]),
            committed_at_millis: 150,
            signed_at_millis: 160,
            signed_pset: signed_pset.clone(),
            relay,
        };
        let previous = status(signed_state(observed_relay(
            &signed_pset,
            4,
            2,
            RelayObservationDto::Confirmed {
                block_hash: elements::BlockHash::from_byte_array([0x55; 32]),
                block_height: 42,
            },
        )));
        let current = ExecutionJournalObservation::Signed(previous.clone());

        let mut reorged_relay = observed_relay(&signed_pset, 6, 3, RelayObservationDto::Absent);
        reorged_relay.reorg_count = 1;
        let reorged = status(signed_state(reorged_relay));
        assert!(matches!(
            validate_transition(&current, &reorged),
            Ok(ExecutionJournalObservation::Signed(status)) if status == reorged
        ));

        let missing_reorg = status(signed_state(observed_relay(
            &signed_pset,
            6,
            3,
            RelayObservationDto::Absent,
        )));
        assert!(matches!(
            validate_transition(&current, &missing_reorg),
            Err(ExecutionJournalRecordError::StatusRegression)
        ));

        let moved_block_without_reorg = status(signed_state(observed_relay(
            &signed_pset,
            6,
            3,
            RelayObservationDto::Confirmed {
                block_hash: elements::BlockHash::from_byte_array([0x56; 32]),
                block_height: 43,
            },
        )));
        assert!(matches!(
            validate_transition(&current, &moved_block_without_reorg),
            Err(ExecutionJournalRecordError::StatusRegression)
        ));

        let mut moved_relay = observed_relay(
            &signed_pset,
            6,
            3,
            RelayObservationDto::Confirmed {
                block_hash: elements::BlockHash::from_byte_array([0x56; 32]),
                block_height: 43,
            },
        );
        moved_relay.reorg_count = 1;
        let moved_block = status(signed_state(moved_relay));
        assert!(matches!(
            validate_transition(&current, &moved_block),
            Ok(ExecutionJournalObservation::Signed(status)) if status == moved_block
        ));

        let stale = status(signed_state(observed_relay(
            &signed_pset,
            4,
            2,
            RelayObservationDto::Mempool,
        )));
        assert!(matches!(
            validate_transition(&current, &stale),
            Err(ExecutionJournalRecordError::StatusRegression)
        ));

        let mut previous_failure_relay =
            observed_relay(&signed_pset, 4, 2, RelayObservationDto::Mempool);
        previous_failure_relay.last_failure =
            Some(deadcat_rfq_rpc::RelayFailureClassDto::BackendUnavailable);
        previous_failure_relay.last_failure_at_millis = Some(165);
        let failure_current =
            ExecutionJournalObservation::Signed(status(signed_state(previous_failure_relay)));
        let mut stale_failure_relay =
            observed_relay(&signed_pset, 6, 3, RelayObservationDto::Mempool);
        stale_failure_relay.last_failure =
            Some(deadcat_rfq_rpc::RelayFailureClassDto::BackendUnavailable);
        stale_failure_relay.last_failure_at_millis = Some(164);
        let stale_failure = status(signed_state(stale_failure_relay));
        assert!(matches!(
            validate_transition(&failure_current, &stale_failure),
            Err(ExecutionJournalRecordError::StatusRegression)
        ));

        let mut changed_artifact = reorged.clone();
        let ReservationStateDto::Signed {
            artifact_digest, ..
        } = &mut changed_artifact.state
        else {
            unreachable!("signed fixture")
        };
        *artifact_digest = FixedBytes32::new([0x45; 32]);
        assert!(matches!(
            validate_transition(&current, &changed_artifact),
            Err(ExecutionJournalRecordError::StatusRegression)
        ));

        let mut changed_pset = reorged;
        let ReservationStateDto::Signed { signed_pset, .. } = &mut changed_pset.state else {
            unreachable!("signed fixture")
        };
        let mut different_pset = PartiallySignedTransaction::new_v2();
        different_pset.global.tx_data.tx_modifiable = Some(1);
        *signed_pset = SettlementPset::from_pset(&different_pset).expect("different fixture PSET");
        assert!(matches!(
            validate_transition(&current, &changed_pset),
            Err(ExecutionJournalRecordError::StatusRegression)
        ));
    }
}

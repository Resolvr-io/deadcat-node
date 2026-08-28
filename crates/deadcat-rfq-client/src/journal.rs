//! Durable taker execution records and exact-retry capabilities.

use std::path::Path;

use deadcat_rfq_rpc::{
    AttestationError, FixedBytes32, ReservationIdDto, ReservationStateDto, ReservationStatusDto,
};
use iroh::EndpointId;
use redb::{
    CommitError, Database, DatabaseError, Durability, ReadableDatabase as _, ReadableTable as _,
    SetDurabilityError, StorageError, TableDefinition, TableError, TransactionError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::session::{QUOTE_RECOVERY_RECORD_VERSION, QuoteRecoveryRecord, ReservationHandle};
use crate::settlement::{
    ExecutionAttempt, ExecutionAttemptError, ExecutionAttemptRecord, ExecutionBinding,
    SignedExecutionError,
};

pub const EXECUTION_JOURNAL_RECORD_VERSION: u32 = 1;
pub const MAX_EXECUTION_JOURNAL_PAGE_SIZE: usize = 256;

const RECORD_DIGEST_DOMAIN: &[u8] = b"deadcat/rfq/client-execution-journal/v1";
const EXECUTIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("rfq_executions");

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

    /// Compare-and-swap one authenticated provider status observation.
    ///
    /// `status` must come from the session's authenticated status or Execute
    /// response path. The journal validates its binding and state transition,
    /// but the DTO alone does not carry transport authentication.
    fn observe(
        &self,
        key: ExecutionJournalKey,
        expected_revision: u64,
        status: ReservationStatusDto,
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
}

impl sealed::Sealed for RedbExecutionJournal {}

impl RedbExecutionJournal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ExecutionJournalError> {
        let database = Database::create(path)?;
        let journal = Self { database };
        let mut write = journal.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        write.open_table(EXECUTIONS)?;
        write.commit()?;
        Ok(journal)
    }
}

impl ExecutionJournal for RedbExecutionJournal {
    fn arm(
        &self,
        quote: &QuoteRecoveryRecord,
        attempt: &ExecutionAttempt,
    ) -> Result<JournaledExecution, ExecutionJournalError> {
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
            if after.is_some_and(|after| record.key() <= after) {
                continue;
            }
            if key.value() != record.key().to_bytes() {
                return Err(ExecutionJournalError::KeyMismatch);
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
        status: ReservationStatusDto,
    ) -> Result<JournaledExecution, ExecutionJournalError> {
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
            if current.revision() != expected_revision {
                return Err(ExecutionJournalError::RevisionConflict {
                    expected: expected_revision,
                    actual: current.revision(),
                });
            }
            current.validate_next_status(&status)?;
            let observation = validate_transition(current.observation(), &status)?;
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
        (ExecutionJournalObservation::Released(_), _)
        | (ExecutionJournalObservation::Signed(_), _)
        | (ExecutionJournalObservation::Committed(_), _) => false,
    };
    if !allowed {
        return Err(ExecutionJournalRecordError::StatusRegression);
    }
    Ok(ExecutionJournalObservation::from_status(next.clone()))
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
    #[error("execution-journal record is invalid: {0}")]
    InvalidRecord(#[from] ExecutionJournalRecordError),
    #[error("a different attempt is already armed for this reservation")]
    AttemptConflict,
    #[error("execution-journal record was not found")]
    NotFound,
    #[error("execution-journal lookup key differs from the stored record")]
    KeyMismatch,
    #[error("execution-journal revision conflict: expected {expected}, actual {actual}")]
    RevisionConflict { expected: u64, actual: u64 },
    #[error("execution-journal revision space is exhausted")]
    RevisionExhausted,
    #[error("execution-journal page size {limit} is outside 1..={MAX_EXECUTION_JOURNAL_PAGE_SIZE}")]
    InvalidPageSize { limit: usize },
    #[error("execution-journal encoding failed: {0}")]
    Encoding(postcard::Error),
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

//! Authenticated taker-side integration for the Deadcat RFQ protocol.
//!
//! This crate is the boundary between the provider-specific network protocol
//! and the transport-free venue/router types in `deadcat-client`. It pins the
//! remote provider and chain, verifies quote attestations and validity, and
//! converts an accepted quote into a symbolic transaction contribution.
//!
//! It never owns taker wallet keys. Its keyless whole-PSET coordinator validates
//! the provider's blinding turn, delegates balancing blinding and taker signing
//! through caller-owned wallet capabilities, and independently validates the
//! result. Broadcast and confirmation monitoring remain caller responsibilities.

#![forbid(unsafe_code)]

mod journal;
mod session;
mod settlement;
mod taker_authorization;
mod venue;

pub use journal::{
    EXECUTION_JOURNAL_RECORD_VERSION, ExecutionJournal, ExecutionJournalError, ExecutionJournalKey,
    ExecutionJournalObservation, ExecutionJournalRecord, ExecutionJournalRecordError,
    JournaledExecution, MAX_EXECUTION_JOURNAL_PAGE_SIZE, RedbExecutionJournal,
};
pub use session::{
    AuthenticatedExecutionStatus, ExecuteError, LiveQuoteReservation, ProviderTarget,
    QUOTE_RECOVERY_RECORD_VERSION, QuoteRecoveryRecord, QuoteReplay, ReservationHandle,
    ResolvedRfqSettlement, RfqSession, SessionConfig, SessionError,
};
pub use settlement::{
    EXECUTION_ATTEMPT_RECORD_VERSION, ExecutionAttempt, ExecutionAttemptDigest,
    ExecutionAttemptError, ExecutionAttemptRecord, ExecutionBinding, ProviderBlindedPset,
    SignedExecutionError, TakerAuthorizedSettlement, TakerSettlementAuthorizer,
    VerifiedSignedExecution,
};
pub use taker_authorization::{
    AuthoritativeTakerPrevout, OwnedOutputExpectation, OwnedOutputKind, OwnedOutputValidation,
    TakerAuthorizationError, TakerSettlementCoordinator, TakerSettlementPlan,
    TakerSettlementPlanError, TakerSettlementSnapshot, TakerSettlementSource,
    TakerWalletBlindingJob, TakerWalletFinalizer, TakerWalletSigningJob,
};
pub use venue::{
    PreparedRfqLeg, QuoteBounds, RfqLegBinding, RfqQuoteIntent, RfqVenueError, TradingMarket,
};

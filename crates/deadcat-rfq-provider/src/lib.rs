//! Transport-free durable state for a noncustodial RFQ provider.
//!
//! This crate owns neither networking nor wallet keys. Its job is narrower:
//! make inventory allocation and the provider's signing point of no return
//! durable and auditable. The required ordering is:
//!
//! `validate -> commit exact payload -> sign -> persist signed bytes -> release`
//!
//! Only an uncommitted reservation can expire or be cancelled. Once a signing
//! payload is committed, every reserved outpoint remains retired even across
//! expiry, process restart, signer ambiguity, mempool eviction, or reorg.
//!
//! This first state-only layer does not yet expose the commit or signed-result
//! transitions outside the crate. A later concrete transaction validator and
//! signer adapter must be the only producers of those transition inputs.

mod model;
mod store;

pub use model::{
    AuditEntry, AuditEvent, Clock, FeePolicy, FeePolicyViolation, FeeSizeMetric, IdempotencyKey,
    InventoryItem, InventoryState, InventoryView, MAX_RESERVATION_INPUTS, MAX_SETTLEMENT_BYTES,
    ModelError, OwnerId, ProviderId, ProviderIdentity, QuoteCommitment, RecoveryAction,
    ReleaseReason, ReservationAccess, ReservationId, ReservationPlan, ReservationState,
    ReservationView, SignedArtifact, SignedArtifactDigest, SigningCommitment, SigningJob,
    TransactionFee, UnixMillis,
};
pub use store::{
    CommitOutcome, MAX_EXPIRATION_BATCH, ProviderError, ReservationBook, ReserveOutcome,
    SCHEMA_VERSION, SignedOutcome,
};

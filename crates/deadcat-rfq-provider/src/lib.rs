//! Transport-free durable state for a noncustodial RFQ provider.
//!
//! This crate owns neither networking nor wallet keys. It defines the
//! backend-neutral wallet capabilities and makes inventory allocation and the
//! provider's signing point of no return durable and auditable. The required
//! ordering is:
//!
//! `validate -> commit exact payload -> sign -> persist signed bytes -> release`
//!
//! Only an uncommitted reservation can expire or be cancelled. Once a signing
//! payload is committed, every reserved outpoint remains retired even across
//! expiry, process restart, signer ambiguity, mempool eviction, or reorg.
//!
//! Wallet discovery admits only confidential tree-less P2TR outputs and quote
//! eligibility is the intersection of a fresh complete scan with durable
//! unallocated state. Concrete wallet/RPC/HSM implementations remain outside
//! this crate. The commit and signed-result transitions also remain private
//! until the concrete transaction validator and signer adapter can be their
//! only producers.

mod inventory;
mod model;
mod store;
mod wallet;

pub use inventory::{
    CurrentInventory, DEFAULT_MAX_INVENTORY_OUTPUTS, EligibilityToken, EligibleInventory,
    InventoryCoordinator, InventoryCoordinatorError, InventoryFreshnessPolicy,
    InventoryPolicyError,
};
pub use model::{
    AuditEntry, AuditEvent, Clock, FeePolicy, FeePolicyViolation, FeeSizeMetric, IdempotencyKey,
    InventoryBinding, InventoryItem, InventoryState, InventoryView, MAX_RESERVATION_INPUTS,
    MAX_SETTLEMENT_BYTES, ModelError, OwnerId, ProviderId, ProviderIdentity, QuoteCommitment,
    RecoveryAction, ReleaseReason, ReservationAccess, ReservationId, ReservationPlan,
    ReservationState, ReservationView, SignedArtifact, SignedArtifactDigest, SigningCommitment,
    SigningJob, SigningTarget, TransactionFee, UnixMillis, WalletKeyLocator,
};
pub use store::{
    CommitOutcome, MAX_EXPIRATION_BATCH, ProviderError, ReservationBook, ReserveOutcome,
    SCHEMA_VERSION, SignedOutcome,
};
pub use wallet::{
    ConfidentialDestination, DestinationPurpose, DestinationSource, InventorySnapshot,
    InventorySnapshotCommitment, InventorySource, P2TR_SIGHASH_ALL_SCRIPT_WITNESS_BYTES,
    P2TR_SIGHASH_ALL_SIGNATURE_BYTES, ProviderInputSignature, ProviderSigner, SigningResponse,
    WalletBoundaryError, WalletOwnedOutput, WalletScanAnchor,
};

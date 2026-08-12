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
mod quote;
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
    QuoteRequestDigest, RecoveryAction, ReleaseReason, ReservationAccess, ReservationId,
    ReservationState, ReservationView, SignedArtifact, SignedArtifactDigest, SigningCommitment,
    SigningJob, SigningTarget, TransactionFee, UnixMillis, WalletKeyLocator,
};
pub use quote::{
    AmountRange, AssetAmount, BinaryMarketAssets, DEFAULT_MAX_LIVE_QUOTES_PER_OWNER,
    DEFAULT_MAX_QUOTE_INPUTS, DEFAULT_QUOTE_LIFETIME_MILLIS, DEFAULT_SELECTION_SEARCH_NODE_BUDGET,
    FirmQuote, FirmQuoteOutcome, FirmQuoteRequest, InventorySummary,
    MAX_QUOTE_RECIPIENT_SCRIPT_BYTES, MarketQuoteConfig, PairLimits, PairRule, PricingDecision,
    PricingPolicy, PricingPolicyId, PricingRequest, PricingRevision, PricingSide,
    QuoteAdmissionError, QuoteBlinderRole, QuoteConfigurationError, QuoteContext,
    QuoteContribution, QuoteEngine, QuoteEngineError, QuoteEnginePolicy, QuoteExecution,
    QuoteInputId, QuoteKind, QuoteModelError, QuoteOutputId, QuoteOutputRole, QuoteRecipient,
    QuoteSnapshotEvidence, QuotedOutput, QuotedProviderInput, RationalRate, StaticPricingError,
    StaticRateRule, StaticRationalPricing,
};
pub use store::{
    CommitOutcome, MAX_EXPIRATION_BATCH, ProviderError, ReservationBook, SCHEMA_VERSION,
    SignedOutcome,
};
pub use wallet::{
    ConfidentialDestination, DestinationPurpose, DestinationSource, InventorySnapshot,
    InventorySnapshotCommitment, InventorySource, P2TR_SIGHASH_ALL_SCRIPT_WITNESS_BYTES,
    P2TR_SIGHASH_ALL_SIGNATURE_BYTES, ProviderInputSignature, ProviderSigner, SigningResponse,
    WalletBoundaryError, WalletOwnedOutput, WalletScanAnchor,
};

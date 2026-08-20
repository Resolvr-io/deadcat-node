//! Transport-free durable state for a noncustodial RFQ provider.
//!
//! This crate owns neither networking nor wallet keys. It defines the
//! backend-neutral wallet capabilities and makes inventory allocation and the
//! provider's signing point of no return durable and auditable. The required
//! ordering is:
//!
//! `validate -> commit exact payload -> sign -> persist signed bytes -> return/relay`
//!
//! Only an uncommitted reservation can expire or be cancelled. Once a signing
//! payload is committed, every reserved outpoint remains retired even across
//! expiry, process restart, signer ambiguity, mempool eviction, or reorg.
//!
//! Wallet discovery admits only confidential tree-less P2TR outputs and quote
//! eligibility is the intersection of a fresh complete scan with durable
//! unallocated state. The final-PSET validator is the sole production path to
//! the commit transition: it rechecks the durable quote, authoritative
//! prevouts, complete taker signatures, confidential proofs and openings, and
//! exact fee/weight facts before it emits a one-shot signing capability.
//! After durable commitment, the signing coordinator invokes only the
//! committed job, verifies and inserts its provider signatures, revalidates
//! the completed PSET, and makes a private verified-PSET capability the only
//! path to signed-artifact persistence. Concrete wallet/RPC/HSM
//! implementations remain outside this crate.

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
    AuthoritativePrevout, CommitOutcome, DEFAULT_MAX_SETTLEMENT_INPUTS,
    DEFAULT_MAX_SETTLEMENT_OUTPUTS, MAX_EXPIRATION_BATCH, ProviderBlindedPset,
    ProviderBlindingCoordinator, ProviderBlindingError, ProviderError, ProviderSettlementValidator,
    ProviderSigningCoordinator, ReservationBook, SCHEMA_VERSION, SettlementChainSource,
    SettlementInputPlacement, SettlementLayout, SettlementLayoutError, SettlementLimitsError,
    SettlementOutputPlacement, SettlementValidationError, SettlementValidationLimits,
    SignedOutcome, SigningFinalizationError, ValidatedSigningIntent,
};
pub use wallet::{
    ConfidentialDestination, DestinationPurpose, DestinationSource, InventorySnapshot,
    InventorySnapshotCommitment, InventorySource, P2TR_SIGHASH_ALL_SCRIPT_WITNESS_BYTES,
    P2TR_SIGHASH_ALL_SIGNATURE_BYTES, ProviderInputSignature, ProviderOutputRecovery,
    ProviderSigner, SigningResponse, WalletBoundaryError, WalletOwnedOutput, WalletScanAnchor,
};

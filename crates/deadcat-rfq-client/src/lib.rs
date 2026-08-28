//! Authenticated taker-side integration for the Deadcat RFQ protocol.
//!
//! This crate is the boundary between the provider-specific network protocol
//! and the transport-free venue/router types in `deadcat-client`. It pins the
//! remote provider and chain, verifies quote attestations and validity, and
//! converts an accepted quote into a symbolic transaction contribution.
//!
//! It deliberately does not own taker wallet keys, blind the final balancing
//! outputs, authorize a complete PSET for signing, or broadcast a transaction.
//! Those capabilities require a wallet-specific whole-transaction boundary.

#![forbid(unsafe_code)]

mod session;
mod settlement;
mod venue;

pub use session::{
    ExecuteError, LiveQuoteReservation, ProviderTarget, QuoteReplay, ReservationHandle,
    ResolvedRfqSettlement, RfqSession, SessionConfig, SessionError,
};
pub use settlement::{
    EXECUTION_ATTEMPT_RECORD_VERSION, ExecutionAttempt, ExecutionAttemptDigest,
    ExecutionAttemptError, ExecutionAttemptRecord, ExecutionBinding, ProviderBlindedPset,
    TakerAuthorizedSettlement, TakerSettlementAuthorizer,
};
pub use venue::{
    PreparedRfqLeg, QuoteBounds, RfqLegBinding, RfqQuoteIntent, RfqVenueError, TradingMarket,
};

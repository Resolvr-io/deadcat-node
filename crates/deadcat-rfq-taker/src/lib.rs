//! Fail-closed orchestration for one-provider, wallet-backed RFQ execution.
//!
//! The lower-level RFQ client deliberately exposes transport and recovery
//! primitives independently of wallet inventory. This facade owns their
//! required safety ordering: reserve wallet inputs before quote I/O, authorize the
//! final PSET, durably journal it, promote those inputs into the wallet's
//! durable exclusion set, and only then dispatch Execute. Startup and refresh
//! likewise rebuild exclusions from the complete execution journal before
//! admitting new funding work.
//!
//! This crate owns orchestration, not filesystem deployment. Its embedding
//! process must protect and durably pair the wallet and journal as one state
//! bundle; opening or recreating either through an unrelated path is outside
//! this capability boundary.

#![forbid(unsafe_code)]

mod fee;
mod node;
mod recovery;
mod runtime;
mod source;

pub use deadcat_elements_core::{ElementsCoreAuth, ElementsCoreConfig};
pub use fee::{FeePlanningError, plan_network_fee};
pub use node::{IrohTakerNodeSource, TakerNodeSource, TakerNodeSourceError};
pub use recovery::{FundingRecoveryError, FundingRecoverySnapshot, load_funding_recovery};
pub use runtime::{
    ExactInRfqTrade, ExactOutRfqTrade, PostArmFailure, PreparedRfqTrade, ReservedRfqTrade,
    RfqExecutionHandle, RfqTakerConfig, RfqTakerError, RfqTakerRuntime, TakerClockError,
};
pub use source::{
    DEFAULT_MAX_BLOCKING_TASKS, DEFAULT_MAX_SNAPSHOT_ATTEMPTS, DEFAULT_SNAPSHOT_RETRY_DELAY,
    ElementsTakerSource as TrustedNodeTakerSource,
    ElementsTakerSourceConfig as TrustedNodeTakerSourceConfig,
    ElementsTakerSourceError as TrustedNodeTakerSourceError, TakerInventorySource,
    TakerMarketSource,
};

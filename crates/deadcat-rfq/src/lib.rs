//! Runtime composition for the noncustodial Deadcat RFQ service.
//!
//! The transport-free provider state machine and the encrypted provider wallet
//! remain separate crates. This crate owns production runtime adapters that
//! connect those capabilities to external systems without putting liquidity
//! keys in the keyless Deadcat indexer.

#![forbid(unsafe_code)]

mod clock;
mod wallet;

pub mod elements;

pub use clock::{SystemClock, SystemClockError};
pub use wallet::SharedRfqWallet;

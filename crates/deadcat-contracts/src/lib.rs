//! Canonical Deadcat contracts, recovery encodings, and pure interpreters.

#[allow(dead_code, unreachable_pub)]
mod artifacts;

pub mod binary_market;
pub mod interpret;
pub mod maker_order;
pub mod market_crypto;
pub mod recovery;
pub mod rt;

pub use simplex::provider::SimplicityNetwork;

//! Isolated, non-production comparison of Deadcat RT blinding schedules.
//!
//! The canonical rolling covenant remains in `deadcat-contracts`. This crate
//! exists to compare it with an A/B constant-CBF candidate before v1 freezes.

#[allow(dead_code, unreachable_pub)]
mod artifacts;

pub mod schedule;

#[cfg(test)]
mod regtest;

#[cfg(test)]
mod tests;

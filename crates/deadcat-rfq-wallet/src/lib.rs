//! Narrow, purpose-built hot-wallet capabilities for an RFQ provider.
//!
//! This crate owns no chain index. It provides a versioned encrypted keystore
//! envelope, fresh confidential tree-less P2TR destinations,
//! confidential-output recovery, and exact durable-job signing. The envelope
//! bytes can be copied and reopened, but a production daemon must still supply
//! atomic filesystem persistence, protected passphrase delivery,
//! authoritative chain scanning, and tested backup transport and verification.
//!
//! Secret buffers owned here are erased on drop where their underlying type
//! permits it. This is defense in depth, not a claim that Rust temporaries,
//! allocator copies, swap, core dumps, or process memory are comprehensively
//! protected; the embedding daemon must provide the corresponding host-level
//! hardening.

#![forbid(unsafe_code)]

mod keystore;
mod wallet;

pub use keystore::{DEFAULT_KDF_PARAMS, EncryptedKeystore, KdfParams, KeystoreError, UnlockedSeed};
pub use wallet::{RfqWallet, RfqWalletError};

//! Narrow, purpose-built hot-wallet capabilities for an RFQ provider.
//!
//! This crate owns no chain index. It provides a versioned encrypted keystore,
//! an identity-bound durable locator catalog, fresh confidential tree-less
//! P2TR destinations, confidential-output recovery, and exact durable-job
//! signing. A production daemon must still supply protected passphrase
//! delivery, authoritative chain scanning, coordinated service backup, and
//! host-level memory hardening.
//!
//! Secret buffers owned here are erased on drop where their underlying type
//! permits it. This is defense in depth, not a claim that Rust temporaries,
//! allocator copies, swap, core dumps, or process memory are comprehensively
//! protected; the embedding daemon must provide the corresponding host-level
//! hardening.

#![forbid(unsafe_code)]

mod keystore;
mod persistent;
mod wallet;

pub use keystore::{DEFAULT_KDF_PARAMS, EncryptedKeystore, KdfParams, KeystoreError, UnlockedSeed};
pub use persistent::{
    MAX_WALLET_CATALOG_ENTRIES, PersistentRfqWallet, PersistentWalletError, WalletBackup,
    WalletCatalogSnapshot,
};
pub use wallet::{RfqWallet, RfqWalletError};

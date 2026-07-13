//! Canonical chain-source boundary shared by Elements RPC and Esplora.

pub mod elements_rpc;
pub mod esplora;

mod http;

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use deadcat_types::{ChainAnchor, ChainPosition, DeadcatOutPoint};
use elements::{AssetId, Block, BlockHash, Script, Transaction, Txid};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmedTransaction {
    pub position: ChainPosition,
    pub block_hash: BlockHash,
    pub transaction: Transaction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionStatus {
    Unconfirmed,
    Confirmed { anchor: ChainAnchor, tx_index: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outspend {
    pub spending_txid: Txid,
    pub input_index: u32,
    pub status: TransactionStatus,
}

/// Chain data required by synchronization, registration, and evidence RPCs.
///
/// Implementations must return complete canonical blocks in transaction order.
/// Script histories contain confirmed transactions in ascending canonical chain
/// order and exclude mempool entries. Fee rates are expressed in satoshis per
/// virtual byte.
/// The coordinator verifies continuity and restarts a fetched range if the
/// source changes branch while it is being read.
#[async_trait]
pub trait ChainSource: Send + Sync + 'static {
    async fn tip(&self) -> Result<ChainAnchor, ChainSourceError>;
    async fn block_hash(&self, height: u32) -> Result<BlockHash, ChainSourceError>;
    async fn block(&self, hash: BlockHash) -> Result<Block, ChainSourceError>;
    async fn transaction(&self, txid: Txid) -> Result<Transaction, ChainSourceError>;
    async fn transaction_status(&self, txid: Txid) -> Result<TransactionStatus, ChainSourceError>;
    async fn outspend(
        &self,
        outpoint: DeadcatOutPoint,
    ) -> Result<Option<Outspend>, ChainSourceError>;
    async fn script_history(&self, script: &Script) -> Result<Vec<Txid>, ChainSourceError>;
    async fn issuance_transaction(
        &self,
        asset_id: AssetId,
    ) -> Result<Option<Txid>, ChainSourceError>;
    async fn estimate_fee_rate(&self, target_blocks: u16) -> Result<f64, ChainSourceError>;
    async fn broadcast(&self, transaction: &Transaction) -> Result<Txid, ChainSourceError>;
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ChainSourceError {
    #[error("chain object not found: {0}")]
    NotFound(String),
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    #[error("backend returned invalid data: {0}")]
    InvalidData(String),
    #[error("backend changed branches during a pinned fetch")]
    BranchChanged,
    #[error("broadcast rejected: {0}")]
    BroadcastRejected(String),
    #[error("backend operation is unsupported: {0}")]
    Unsupported(String),
}

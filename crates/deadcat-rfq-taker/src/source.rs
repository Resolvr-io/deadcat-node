use std::error::Error;

use async_trait::async_trait;
use deadcat_rfq_wallet::TakerWalletUtxo;

/// Authoritative, coherent inventory scan for one taker wallet.
///
/// Implementations must return only currently spendable outputs authenticated
/// by the wallet, preserve complete confidential output witnesses, and fail if
/// the wallet catalog or chain anchor changes during the scan. Runtime refresh
/// obtains an exclusion revision token before invoking this method; startup
/// instead holds the wallet-wide funding authority throughout its initial scan
/// and journal reconstruction.
/// Implementations may perform network or blocking Core work, but must expose
/// it through this asynchronous boundary. A blocking adapter must move the
/// whole bounded scan onto an explicit blocking-task executor rather than
/// blocking an async runtime worker.
#[async_trait]
pub trait TakerInventorySource: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    async fn inventory(&self) -> Result<Vec<TakerWalletUtxo>, Self::Error>;
}

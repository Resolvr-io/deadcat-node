use std::error::Error;

use deadcat_rfq_wallet::TakerWalletUtxo;

/// Authoritative, coherent inventory scan for one taker wallet.
///
/// Implementations must return only currently spendable outputs authenticated
/// by the wallet, preserve complete confidential output witnesses, and fail if
/// the wallet catalog or chain anchor changes during the scan. Runtime refresh
/// obtains an exclusion revision token before invoking this method; startup
/// instead holds the wallet-wide funding authority throughout its initial scan
/// and journal reconstruction.
pub trait TakerInventorySource {
    type Error: Error + Send + Sync + 'static;

    fn inventory(&self) -> Result<Vec<TakerWalletUtxo>, Self::Error>;
}

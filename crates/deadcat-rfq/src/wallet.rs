//! Cheap-clone runtime access to the persistent provider wallet.

use core::fmt;
use std::sync::Arc;

use deadcat_rfq_provider::{
    ConfidentialDestination, DestinationPurpose, DestinationSource, ProviderIdentity,
    ProviderOutputRecovery, ProviderSigner, SigningJob, SigningResponse, WalletKeyLocator,
    WalletOwnedOutput,
};
use deadcat_rfq_wallet::{PersistentRfqWallet, PersistentWalletError, WalletCatalogSnapshot};
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, OutPoint, TxOut};

/// Shared, narrow access to one unlocked persistent RFQ wallet.
///
/// Clones share the exact same wallet handle, operation lock, durable catalog,
/// and unlocked key material. The wrapper exists so the quote engine, Elements
/// scanner, settlement validator, and signing coordinator can each own a cheap
/// capability handle without reopening the wallet or duplicating secrets.
#[derive(Clone)]
pub struct SharedRfqWallet {
    wallet: Arc<PersistentRfqWallet>,
}

impl SharedRfqWallet {
    #[must_use]
    pub fn new(wallet: PersistentRfqWallet) -> Self {
        Self {
            wallet: Arc::new(wallet),
        }
    }

    #[must_use]
    pub fn identity(&self) -> ProviderIdentity {
        self.wallet.identity()
    }

    /// Issue a durable destination for operator-supplied or replenished
    /// inventory.
    pub fn fresh_inventory_destination(
        &self,
    ) -> Result<ConfidentialDestination, PersistentWalletError> {
        self.wallet.fresh_inventory_destination()
    }

    /// Read the catalog revision around an external chain observation.
    pub fn catalog_revision(&self) -> Result<u64, PersistentWalletError> {
        self.wallet.catalog_revision()
    }

    /// Return one authenticated, coherent view of every issued locator.
    pub fn catalog_snapshot(&self) -> Result<WalletCatalogSnapshot, PersistentWalletError> {
        self.wallet.catalog_snapshot()
    }

    /// Recover the public destination bound to an authenticated catalog
    /// locator without exposing private key material.
    pub fn recover_confidential_destination(
        &self,
        locator: WalletKeyLocator,
    ) -> Result<ConfidentialDestination, PersistentWalletError> {
        self.wallet.recover_confidential_destination(locator)
    }

    /// Authenticate and unblind a scanner-discovered output while retaining
    /// its opening only inside the provider's redacted inventory type.
    pub fn recover_owned_output(
        &self,
        locator: WalletKeyLocator,
        outpoint: OutPoint,
        txout: TxOut,
    ) -> Result<WalletOwnedOutput, PersistentWalletError> {
        self.wallet.recover_owned_output(locator, outpoint, txout)
    }
}

impl fmt::Debug for SharedRfqWallet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedRfqWallet")
            .field("identity", &self.identity())
            .field("wallet", &"[shared, unlocked, and redacted]")
            .finish()
    }
}

impl DestinationSource for SharedRfqWallet {
    type Error = PersistentWalletError;

    fn fresh_confidential_destination(
        &self,
        purpose: DestinationPurpose,
    ) -> Result<ConfidentialDestination, Self::Error> {
        DestinationSource::fresh_confidential_destination(self.wallet.as_ref(), purpose)
    }
}

impl ProviderOutputRecovery for SharedRfqWallet {
    type Error = PersistentWalletError;

    fn validate_confidential_output(
        &self,
        wallet_locator: WalletKeyLocator,
        expected_internal_key: XOnlyPublicKey,
        txout: &TxOut,
        expected_asset: AssetId,
        expected_amount: u64,
    ) -> Result<(), Self::Error> {
        ProviderOutputRecovery::validate_confidential_output(
            self.wallet.as_ref(),
            wallet_locator,
            expected_internal_key,
            txout,
            expected_asset,
            expected_amount,
        )
    }
}

impl ProviderSigner for SharedRfqWallet {
    type Error = PersistentWalletError;

    fn sign(&self, job: &SigningJob) -> Result<SigningResponse, Self::Error> {
        ProviderSigner::sign(self.wallet.as_ref(), job)
    }
}

#[cfg(test)]
mod tests {
    use deadcat_rfq_provider::{ProviderId, ProviderOutputRecovery as _};
    use deadcat_rfq_wallet::KdfParams;
    use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
    use elements::hashes::Hash as _;
    use elements::secp256k1_zkp::{Secp256k1, rand::thread_rng};
    use elements::{BlockHash, TxOutSecrets, TxOutWitness, Txid};
    use tempfile::{TempDir, tempdir};

    use super::*;

    const PASSPHRASE: &[u8] = b"shared-wallet unit-test passphrase";

    fn identity() -> ProviderIdentity {
        ProviderIdentity::new(
            ProviderId::new([41; 32]),
            BlockHash::from_byte_array([42; 32]),
            AssetId::from_byte_array([43; 32]),
        )
    }

    fn wallet() -> (TempDir, SharedRfqWallet) {
        let directory = tempdir().expect("temporary wallet directory");
        let persistent = PersistentRfqWallet::create_with_kdf(
            directory.path().join("wallet.redb"),
            identity(),
            PASSPHRASE,
            KdfParams::new(8 * 1_024, 1, 1).expect("bounded test KDF"),
        )
        .expect("persistent wallet");
        (directory, SharedRfqWallet::new(persistent))
    }

    fn assert_runtime_capabilities<T>()
    where
        T: Clone
            + Send
            + Sync
            + DestinationSource<Error = PersistentWalletError>
            + ProviderOutputRecovery<Error = PersistentWalletError>
            + ProviderSigner<Error = PersistentWalletError>,
    {
    }

    #[test]
    fn clones_share_one_durable_catalog_and_all_runtime_capabilities() {
        assert_runtime_capabilities::<SharedRfqWallet>();
        let _signer_method: fn(
            &SharedRfqWallet,
            &SigningJob,
        ) -> Result<SigningResponse, PersistentWalletError> =
            <SharedRfqWallet as ProviderSigner>::sign;

        let (_directory, wallet) = wallet();
        let clone = wallet.clone();
        assert_eq!(wallet.identity(), identity());
        assert_eq!(wallet.catalog_revision().expect("initial revision"), 0);

        let receive = clone
            .fresh_confidential_destination(DestinationPurpose::SettlementReceive)
            .expect("durable receive destination");
        assert_eq!(wallet.catalog_revision().expect("shared revision"), 1);
        assert_eq!(
            wallet
                .recover_confidential_destination(receive.wallet_locator())
                .expect("recover through original handle"),
            receive
        );

        let inventory = wallet
            .fresh_inventory_destination()
            .expect("durable inventory destination");
        let snapshot = clone.catalog_snapshot().expect("shared catalog snapshot");
        assert_eq!(snapshot.revision(), 2);
        assert_eq!(snapshot.locators().len(), 2);
        assert!(snapshot.locators().contains(&receive.wallet_locator()));
        assert!(snapshot.locators().contains(&inventory.wallet_locator()));

        let debug = format!("{wallet:?}");
        assert!(debug.contains("[shared, unlocked, and redacted]"));
        assert!(!debug.contains("passphrase"));
    }

    #[test]
    fn scanner_recovery_and_output_validation_delegate_to_the_same_wallet() {
        let (_directory, wallet) = wallet();
        let destination = wallet
            .fresh_inventory_destination()
            .expect("inventory destination");
        let asset = AssetId::from_byte_array([71; 32]);
        let amount = 42_000;
        let explicit = TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(amount),
            nonce: Nonce::Null,
            script_pubkey: destination.script_pubkey().clone(),
            witness: TxOutWitness::default(),
        };
        let (confidential, _, _, _) = explicit
            .to_non_last_confidential(
                &mut thread_rng(),
                &Secp256k1::new(),
                destination.blinding_public_key(),
                &[TxOutSecrets::new(
                    asset,
                    AssetBlindingFactor::zero(),
                    amount,
                    ValueBlindingFactor::zero(),
                )],
            )
            .expect("blind inventory output");
        let outpoint = OutPoint::new(Txid::from_byte_array([72; 32]), 3);

        let recovered = wallet
            .recover_owned_output(destination.wallet_locator(), outpoint, confidential.clone())
            .expect("scanner recovery");
        assert_eq!(recovered.outpoint(), outpoint);
        assert_eq!(recovered.asset(), asset);
        assert_eq!(recovered.amount(), amount);
        assert_eq!(recovered.txout(), &confidential);

        wallet
            .validate_confidential_output(
                destination.wallet_locator(),
                destination.internal_key(),
                &confidential,
                asset,
                amount,
            )
            .expect("provider output validation");
        assert!(
            wallet
                .validate_confidential_output(
                    destination.wallet_locator(),
                    destination.internal_key(),
                    &confidential,
                    asset,
                    amount + 1,
                )
                .is_err()
        );
    }
}

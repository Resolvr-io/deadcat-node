use deadcat_rfq_provider::{
    InventorySource as _, ProviderId, ProviderIdentity, SettlementChainSource,
};
use deadcat_rfq_wallet::{KdfParams, PersistentRfqWallet};
use deadcat_types::{ChainIdentity, LiquidNetwork};
use elements::confidential::{Asset, Nonce, Value};
use elements::hashes::Hash as _;
use elements::{AssetId, BlockHash, OutPoint, Script, TxOut, TxOutWitness, Txid};
use tempfile::{TempDir, tempdir};

use super::*;

const PASSPHRASE: &[u8] = b"elements-adapter unit-test passphrase";

fn hash(marker: u8) -> BlockHash {
    BlockHash::from_byte_array([marker; 32])
}

fn asset(marker: u8) -> AssetId {
    AssetId::from_byte_array([marker; 32])
}

fn identity() -> ProviderIdentity {
    ProviderIdentity::new(ProviderId::new([41; 32]), hash(42), asset(43))
}

fn chain() -> ChainIdentity {
    ChainIdentity {
        network: LiquidNetwork::ElementsRegtest,
        genesis_hash: identity().genesis_hash(),
    }
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

fn config() -> ElementsCoreConfig {
    ElementsCoreConfig::new("http://127.0.0.1:1", ElementsCoreAuth::None)
}

fn assert_runtime_source<T>()
where
    T: Clone
        + Send
        + Sync
        + InventorySource<Error = ElementsCoreSourceError>
        + SettlementChainSource<Error = ElementsCoreSourceError>
        + ProviderRelaySource<Error = ElementsCoreSourceError>,
{
}

#[derive(Clone)]
struct StaticScan {
    snapshot: InventoryScanSnapshot,
}

impl InventoryScanHandle for StaticScan {
    fn check(&self) -> Result<(), ElementsCoreError> {
        Ok(())
    }

    fn scan_unspent_scripts(
        &self,
        _scripts: &[Script],
    ) -> Result<InventoryScanSnapshot, ElementsCoreError> {
        Ok(self.snapshot.clone())
    }
}

struct CatalogChangingScan {
    wallet: SharedRfqWallet,
}

impl InventoryScanHandle for CatalogChangingScan {
    fn check(&self) -> Result<(), ElementsCoreError> {
        Ok(())
    }

    fn scan_unspent_scripts(
        &self,
        _scripts: &[Script],
    ) -> Result<InventoryScanSnapshot, ElementsCoreError> {
        self.wallet
            .fresh_inventory_destination()
            .expect("concurrent catalog mutation");
        Ok(InventoryScanSnapshot {
            anchor: ChainAnchor {
                height: 7,
                hash: hash(8),
            },
            outputs: Vec::new(),
        })
    }
}

fn explicit_txout(script_pubkey: Script) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset(44)),
        value: Value::Explicit(1),
        nonce: Nonce::Null,
        script_pubkey,
        witness: TxOutWitness::default(),
    }
}

#[test]
fn adapter_composes_runtime_traits_and_redacts_core_credentials() {
    assert_runtime_source::<ElementsCoreSource>();
    let (_directory, wallet) = wallet();
    let config = ElementsCoreConfig::new(
        "http://127.0.0.1:1",
        ElementsCoreAuth::Basic {
            username: "operator".to_owned(),
            password: "never-print-this".to_owned(),
        },
    );
    let source = ElementsCoreSource::new(config, chain(), wallet).expect("bound adapter");
    let debug = format!("{source:?}");
    assert!(debug.contains("ElementsCoreSource"));
    assert!(debug.contains("redacted"));
    assert!(!debug.contains("never-print-this"));
}

#[test]
fn adapter_rejects_a_core_client_bound_to_another_wallet_chain() {
    let (_directory, wallet) = wallet();
    let wrong_chain = ChainIdentity {
        network: LiquidNetwork::ElementsRegtest,
        genesis_hash: hash(99),
    };
    assert!(matches!(
        ElementsCoreSource::new(config(), wrong_chain, wallet),
        Err(ElementsCoreSourceError::WalletChainMismatch {
            wallet,
            configured,
        }) if wallet == identity().genesis_hash() && configured == wrong_chain.genesis_hash
    ));
}

#[test]
fn catalog_bound_is_checked_before_any_core_rpc() {
    let (_directory, wallet) = wallet();
    wallet
        .fresh_inventory_destination()
        .expect("first catalog destination");
    wallet
        .fresh_inventory_destination()
        .expect("second catalog destination");
    let mut bounded = config();
    bounded.max_scan_scripts = 1;
    let source = ElementsCoreSource::new(bounded, chain(), wallet).expect("bounded adapter");
    assert!(matches!(
        source.inventory_snapshot(),
        Err(ElementsCoreSourceError::CatalogTooLarge {
            maximum: 1,
            actual: 2,
        })
    ));
}

#[test]
fn every_neutral_relay_observation_maps_without_losing_identity() {
    let spent_input = OutPoint::new(Txid::from_byte_array([8; 32]), 2);
    let conflicting_txid = Txid::from_byte_array([9; 32]);
    let cases = [
        (
            CoreRelayObservation::BroadcastAccepted,
            RelayObservation::BroadcastAccepted,
        ),
        (CoreRelayObservation::Mempool, RelayObservation::Mempool),
        (
            CoreRelayObservation::Confirmed {
                block_hash: hash(10),
                block_height: 11,
            },
            RelayObservation::Confirmed {
                block_hash: hash(10),
                block_height: 11,
            },
        ),
        (CoreRelayObservation::Absent, RelayObservation::Absent),
        (
            CoreRelayObservation::Conflicted {
                spent_input,
                conflicting_txid: Some(conflicting_txid),
            },
            RelayObservation::Conflicted {
                spent_input,
                conflicting_txid: Some(conflicting_txid),
            },
        ),
    ];
    for (core, expected) in cases {
        assert_eq!(provider_observation(core), expected);
    }
}

#[test]
fn policy_rejection_is_preserved_alongside_the_latest_observation() {
    let result = provider_relay_result(CoreRelayObservation::Mempool, true);
    assert_eq!(result.observation(), RelayObservation::Mempool);
    assert_eq!(
        result.last_failure(),
        Some(RelayFailureClass::PolicyRejected)
    );

    let accepted = provider_relay_result(CoreRelayObservation::BroadcastAccepted, false);
    assert_eq!(accepted.observation(), RelayObservation::BroadcastAccepted);
    assert_eq!(accepted.last_failure(), None);
}

#[test]
fn inventory_scan_rejects_a_catalog_revision_race() {
    let (_directory, wallet) = wallet();
    wallet
        .fresh_inventory_destination()
        .expect("initial catalog destination");
    let scan = CatalogChangingScan {
        wallet: wallet.clone(),
    };

    assert!(matches!(
        inventory_snapshot_with_scan(&wallet, 2, &scan),
        Err(ElementsCoreSourceError::CatalogChangedDuringScan {
            before: 1,
            after: 2,
        })
    ));
}

#[test]
fn inventory_scan_rejects_an_output_for_an_unrequested_script() {
    let (_directory, wallet) = wallet();
    wallet
        .fresh_inventory_destination()
        .expect("catalog destination");
    let outpoint = OutPoint::new(Txid::from_byte_array([45; 32]), 0);
    let scan = StaticScan {
        snapshot: InventoryScanSnapshot {
            anchor: ChainAnchor {
                height: 7,
                hash: hash(8),
            },
            outputs: vec![InventoryScanOutput {
                script_pubkey: Script::from(vec![0x51]),
                outpoint,
                txout: explicit_txout(Script::from(vec![0x51])),
            }],
        },
    };

    assert!(matches!(
        inventory_snapshot_with_scan(&wallet, 1, &scan),
        Err(ElementsCoreSourceError::UnexpectedScanScript(observed)) if observed == outpoint
    ));
}

#[test]
fn inventory_scan_requires_wallet_authentication_of_every_output() {
    let (_directory, wallet) = wallet();
    let destination = wallet
        .fresh_inventory_destination()
        .expect("catalog destination");
    let script = destination.script_pubkey().clone();
    let scan = StaticScan {
        snapshot: InventoryScanSnapshot {
            anchor: ChainAnchor {
                height: 7,
                hash: hash(8),
            },
            outputs: vec![InventoryScanOutput {
                script_pubkey: script.clone(),
                outpoint: OutPoint::new(Txid::from_byte_array([46; 32]), 0),
                txout: explicit_txout(script),
            }],
        },
    };

    assert!(matches!(
        inventory_snapshot_with_scan(&wallet, 1, &scan),
        Err(ElementsCoreSourceError::Wallet(_))
    ));
}

#[test]
fn core_availability_classification_maps_to_provider_admission_policy() {
    let unavailable =
        ElementsCoreSourceError::Core(ElementsCoreError::BackendUnavailable("offline".to_owned()));
    assert_eq!(
        relay_failure_class(&unavailable),
        RelayFailureClass::BackendUnavailable
    );

    let timed_out =
        ElementsCoreSourceError::Core(ElementsCoreError::OperationTimedOut { operation: "relay" });
    assert_eq!(
        relay_failure_class(&timed_out),
        RelayFailureClass::BackendUnavailable
    );

    let invalid = ElementsCoreSourceError::Core(ElementsCoreError::InvalidRpcResponse(
        "wrong witness".to_owned(),
    ));
    assert_eq!(
        relay_failure_class(&invalid),
        RelayFailureClass::InvalidBackendData
    );
}

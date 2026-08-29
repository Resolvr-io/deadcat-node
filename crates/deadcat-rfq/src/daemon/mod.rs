mod config;
mod state;

use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, bail};
use clap::{Args as ClapArgs, Parser, Subcommand};
use deadcat_rfq::elements::{
    ElementsCoreChainStatus, ElementsCoreNetwork, ElementsCoreSource, probe_elements_core,
};
use deadcat_rfq::{AuthenticatedRfqHandler, ProviderRfqBackend, SharedRfqWallet, SystemClock};
use deadcat_rfq_provider::{
    InventoryCoordinator, ProviderId, ProviderIdentity, QuoteEngine, ReservationBook,
};
use deadcat_rfq_wallet::PersistentRfqWallet;
use deadcat_types::LiquidNetwork;
use elements::{Address, AddressParams};
use serde_json::json;
use tracing_subscriber::EnvFilter;

use self::config::{FileConfig, ValidatedConfig};
use self::state::{ProviderManifest, StatePaths};

#[derive(Parser)]
#[command(
    name = "deadcat-rfq",
    version,
    about = "Noncustodial Deadcat RFQ liquidity service"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create one provider identity, encrypted wallet, and reservation database.
    Init(CommonArgs),
    /// Issue a durable confidential address for funding provider inventory.
    DepositAddress(CommonArgs),
    /// Reconcile existing state, recover signing jobs, and serve RFQ requests.
    Run(CommonArgs),
}

#[derive(ClapArgs)]
struct CommonArgs {
    /// Strict JSON configuration. It must not be group- or world-writable.
    #[arg(long, default_value = "./deadcat-rfq.json")]
    config: PathBuf,
    /// Private RFQ state directory (mode 0700).
    #[arg(long, default_value = "./deadcat-rfq-data")]
    state_dir: PathBuf,
    /// Owner-only credential file containing the wallet passphrase.
    #[arg(long)]
    passphrase_file: PathBuf,
}

pub(super) async fn run_cli() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Init(args) => initialize(args).await,
        Command::DepositAddress(args) => deposit_address(args).await,
        Command::Run(args) => run(args).await,
    }
}

pub(super) fn init_tracing() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("deadcat_rfq=info")),
        )
        .try_init()
        .map_err(|error| anyhow::anyhow!(error))
}

async fn initialize(args: CommonArgs) -> anyhow::Result<()> {
    let config = load_config(&args.config)?;
    SystemClock
        .try_now()
        .context("validate host wall clock before initialization")?;
    let chain = preflight(&config).await?;
    let passphrase = state::read_passphrase(&args.passphrase_file)
        .context("read protected wallet passphrase")?;
    let paths = StatePaths::new(args.state_dir);
    state::create_state_directory(&paths.directory)?;
    paths.require_uninitialized()?;

    let secret = state::create_iroh_secret(&paths.iroh_secret)
        .context("create persistent RFQ Iroh identity")?;
    let identity = ProviderIdentity::new(
        ProviderId::new(*secret.public().as_bytes()),
        config.chain.genesis_hash,
        config.policy_asset,
    );
    let wallet = PersistentRfqWallet::create(&paths.wallet, identity, passphrase.as_slice())
        .context("create encrypted RFQ wallet")?;
    drop(passphrase);
    drop(wallet);
    let book = ReservationBook::create(&paths.provider, identity)
        .context("create RFQ reservation database")?;
    book.schema_version()
        .context("verify new RFQ reservation database")?;
    drop(book);
    let manifest = ProviderManifest::new(identity, config.chain.network);
    state::write_manifest(&paths.manifest, &manifest)
        .context("publish completed RFQ state manifest")?;

    print_json(&json!({
        "status": "initialized",
        "profile": "regtest_static_v1",
        "provider_id": hex::encode(identity.provider().to_bytes()),
        "network": config.chain.network,
        "genesis_hash": config.chain.genesis_hash,
        "policy_asset": config.policy_asset,
        "elements_tip": {
            "height": chain.tip_height(),
            "hash": chain.tip_hash(),
        },
    }))
}

async fn deposit_address(args: CommonArgs) -> anyhow::Result<()> {
    let config = load_config(&args.config)?;
    SystemClock
        .try_now()
        .context("validate host wall clock before issuing a destination")?;
    let _chain = preflight(&config).await?;
    let paths = StatePaths::new(args.state_dir);
    let (identity, wallet, book, _secret) =
        open_existing_state(&paths, &config, &args.passphrase_file)?;
    drop(book);
    let destination = wallet
        .fresh_inventory_destination()
        .context("issue durable inventory destination")?;
    let address = Address::from_script(
        destination.script_pubkey(),
        Some(destination.blinding_public_key()),
        address_params(config.chain.network),
    )
    .context("wallet returned a destination that cannot be encoded as an Elements address")?;
    let catalog_revision = wallet
        .catalog_revision()
        .context("read wallet catalog revision")?;
    print_json(&json!({
        "address": address.to_string(),
        "catalog_revision": catalog_revision.to_string(),
        "provider_id": hex::encode(identity.provider().to_bytes()),
    }))
}

async fn run(args: CommonArgs) -> anyhow::Result<()> {
    let config = load_config(&args.config)?;
    SystemClock
        .try_now()
        .context("validate host wall clock before startup")?;
    let chain_status = preflight(&config).await?;
    let paths = StatePaths::new(args.state_dir);
    let (identity, wallet, book, secret) =
        open_existing_state(&paths, &config, &args.passphrase_file)?;

    let elements = config.elements.clone();
    let source_wallet = wallet.clone();
    let source =
        tokio::task::spawn_blocking(move || ElementsCoreSource::new(elements, source_wallet))
            .await
            .context("Elements provider source construction panicked")?
            .context("construct authoritative Elements provider source")?;
    let inventory = InventoryCoordinator::new(book, source.clone(), config.inventory);
    let engine = QuoteEngine::new(
        inventory,
        wallet.clone(),
        config.pricing,
        config.markets,
        config.quote,
    )
    .context("construct RFQ quote engine")?;
    let backend = ProviderRfqBackend::new(engine, source, wallet, SystemClock, config.chain)
        .context("bind RFQ runtime identities")?;
    let handler = Arc::new(
        AuthenticatedRfqHandler::start_with_config(backend, secret, config.handler)
            .await
            .context("reconcile inventory and recover pending signing before readiness")?,
    );
    let server = match Arc::clone(&handler)
        .bind_server(config.discovery, config.server)
        .await
    {
        Ok(server) => server,
        Err(error) => {
            return return_after_shutdown(
                Err(error).context("bind authenticated RFQ Iroh service"),
                handler.shutdown(),
            )
            .await;
        }
    };
    let endpoint_address = server.endpoint_addr();
    let mut server = server.spawn();
    if let Err(output_error) = print_json(&json!({
        "status": "ready",
        "profile": "regtest_static_v1",
        "endpoint": endpoint_address,
        "provider_id": hex::encode(identity.provider().to_bytes()),
        "network": config.chain.network,
        "genesis_hash": config.chain.genesis_hash,
        "policy_asset": config.policy_asset,
        "elements_tip": {
            "height": chain_status.tip_height(),
            "hash": chain_status.tip_hash(),
        },
    })) {
        if let Err(cleanup_error) = server.shutdown_and_join().await {
            tracing::error!(
                error = %cleanup_error,
                "RFQ transport cleanup also failed after readiness output failure"
            );
        }
        return return_after_shutdown(Err(output_error), handler.shutdown()).await;
    }

    let stop = tokio::select! {
        signal = shutdown_signal() => DaemonStop::Signal(signal),
        result = server.wait() => DaemonStop::Transport(result),
    };
    let outcome = match stop {
        DaemonStop::Signal(signal) => {
            if let Ok(signal) = &signal {
                tracing::info!(signal, "graceful RFQ shutdown requested");
            }
            let transport = server
                .shutdown_and_join()
                .await
                .context("stop RFQ Iroh transport");
            signal.map(drop).and(transport)
        }
        DaemonStop::Transport(Ok(())) => {
            Err(anyhow::anyhow!("RFQ Iroh transport stopped unexpectedly"))
        }
        DaemonStop::Transport(Err(error)) => Err(error).context("RFQ Iroh transport task failed"),
    };
    return_after_shutdown(outcome, handler.shutdown()).await
}

enum DaemonStop {
    Signal(anyhow::Result<&'static str>),
    Transport(Result<(), deadcat_rfq_iroh::ServerError>),
}

async fn return_after_shutdown<T, F>(outcome: anyhow::Result<T>, shutdown: F) -> anyhow::Result<T>
where
    F: Future<Output = ()>,
{
    // Transport closes first. Even when transport shutdown itself failed, the
    // handler must close admission, drain every accepted validate->commit
    // operation, and drain durable signing recovery before the error escapes.
    shutdown.await;
    outcome
}

fn load_config(path: &Path) -> anyhow::Result<ValidatedConfig> {
    state::read_config::<FileConfig>(path)?.validate()
}

async fn preflight(config: &ValidatedConfig) -> anyhow::Result<ElementsCoreChainStatus> {
    let elements = config.elements.clone();
    let expected = config.chain.genesis_hash;
    let status = tokio::task::spawn_blocking(move || probe_elements_core(&elements))
        .await
        .context("Elements Core startup probe panicked")?
        .context("probe Elements Core chain and transaction index")?;
    if status.network() != ElementsCoreNetwork::ElementsRegtest {
        bail!("Elements Core is not running the required liquidregtest chain");
    }
    validate_preflight_identity(
        expected,
        config.policy_asset,
        status.genesis_hash(),
        status.pegged_asset(),
    )?;
    Ok(status)
}

fn validate_preflight_identity(
    expected_genesis: elements::BlockHash,
    expected_policy_asset: elements::AssetId,
    actual_genesis: elements::BlockHash,
    actual_pegged_asset: elements::AssetId,
) -> anyhow::Result<()> {
    if actual_genesis != expected_genesis {
        bail!(
            "Elements Core genesis {actual_genesis} does not match configured genesis {expected_genesis}"
        );
    }
    if actual_pegged_asset != expected_policy_asset {
        bail!(
            "Elements Core pegged asset {actual_pegged_asset} does not match configured policy asset {expected_policy_asset}; regtest_static_v1 requires Core's default fee-asset policy"
        );
    }
    Ok(())
}

fn open_existing_state(
    paths: &StatePaths,
    config: &ValidatedConfig,
    passphrase_file: &Path,
) -> anyhow::Result<(
    ProviderIdentity,
    SharedRfqWallet,
    ReservationBook,
    deadcat_rfq_iroh::SecretKey,
)> {
    state::validate_state_directory(&paths.directory)?;
    let manifest = state::load_manifest(&paths.manifest)?;
    let identity = manifest.identity()?;
    if manifest.network != config.chain.network
        || identity.genesis_hash() != config.chain.genesis_hash
        || identity.policy_asset() != config.policy_asset
    {
        bail!("RFQ state manifest does not match the configured chain identity");
    }
    let secret = state::load_iroh_secret(&paths.iroh_secret)?;
    if identity.provider().to_bytes() != *secret.public().as_bytes() {
        bail!("RFQ Iroh secret does not match the completed state manifest");
    }
    let passphrase =
        state::read_passphrase(passphrase_file).context("read protected wallet passphrase")?;
    let wallet = PersistentRfqWallet::open(&paths.wallet, identity, passphrase.as_slice())
        .context("open encrypted RFQ wallet")?;
    drop(passphrase);
    let wallet = SharedRfqWallet::new(wallet);
    let book = ReservationBook::open_existing(&paths.provider, identity)
        .context("open existing RFQ reservation database")?;
    Ok((identity, wallet, book, secret))
}

const fn address_params(network: LiquidNetwork) -> &'static AddressParams {
    match network {
        LiquidNetwork::Liquid => &AddressParams::LIQUID,
        LiquidNetwork::LiquidTestnet => &AddressParams::LIQUID_TESTNET,
        LiquidNetwork::ElementsRegtest => &AddressParams::ELEMENTS,
    }
}

async fn shutdown_signal() -> anyhow::Result<&'static str> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("install SIGTERM handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.context("install SIGINT handler")?;
                Ok("SIGINT")
            }
            _ = terminate.recv() => Ok("SIGTERM"),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("install Ctrl-C handler")?;
        Ok("Ctrl-C")
    }
}

fn print_json(value: &serde_json::Value) -> anyhow::Result<()> {
    let stdout = std::io::stdout();
    print_json_to(stdout.lock(), value)
}

fn print_json_to(mut writer: impl Write, value: &serde_json::Value) -> anyhow::Result<()> {
    serde_json::to_writer(&mut writer, value).context("serialize daemon output")?;
    writer
        .write_all(b"\n")
        .context("write daemon output terminator")?;
    writer.flush().context("flush daemon output")
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::atomic::{AtomicBool, Ordering};

    use elements::hashes::Hash as _;

    use super::*;

    #[tokio::test]
    async fn transport_errors_are_returned_only_after_handler_shutdown() {
        let shutdown_ran = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&shutdown_ran);
        let result =
            return_after_shutdown::<(), _>(Err(anyhow::anyhow!("transport failed")), async move {
                marker.store(true, Ordering::SeqCst);
            })
            .await;
        assert!(shutdown_ran.load(Ordering::SeqCst));
        assert_eq!(
            result.expect_err("original error survives").to_string(),
            "transport failed"
        );
    }

    #[test]
    fn preflight_rejects_wrong_genesis_and_pegged_asset_before_state_open() {
        let genesis = elements::BlockHash::from_byte_array([1; 32]);
        let policy = elements::AssetId::from_byte_array([2; 32]);
        assert!(validate_preflight_identity(genesis, policy, genesis, policy).is_ok());
        assert!(
            validate_preflight_identity(
                genesis,
                policy,
                elements::BlockHash::from_byte_array([3; 32]),
                policy,
            )
            .is_err()
        );
        assert!(
            validate_preflight_identity(
                genesis,
                policy,
                genesis,
                elements::AssetId::from_byte_array([4; 32]),
            )
            .is_err()
        );
    }

    #[test]
    fn daemon_json_output_reports_writer_failure_without_panicking() {
        struct BrokenWriter;

        impl Write for BrokenWriter {
            fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed output"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        assert!(print_json_to(BrokenWriter, &json!({"status": "ready"})).is_err());
    }
}

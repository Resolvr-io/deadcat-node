use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use deadcat_iroh::{DiscoveryMode as IrohDiscoveryMode, SecretKey, Server, ServerConfig};
use deadcat_node::chain::ChainSource;
use deadcat_node::chain::elements_rpc::{
    ElementsRpcAuth, ElementsRpcChainSource, ElementsRpcConfig,
};
use deadcat_node::chain::esplora::{EsploraAuth, EsploraChainSource, EsploraConfig};
use deadcat_node::interpreter::DeadcatInterpreter;
use deadcat_node::rpc_handler::{NodeRpcHandler, RpcHandlerConfig};
use deadcat_node::store::{ChainIdentity, Store};
use deadcat_node::sync::{SyncCoordinator, SyncOutcome};
use deadcat_rpc::{BackendKind, SyncStatus};
use deadcat_types::{ChainAnchor, DiscoveryCoverage, DiscoveryMode, LiquidNetwork};
use elements::AssetId;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "deadcat-node",
    version,
    about = "Keyless Deadcat Liquid index and evidence server"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run chain synchronization and the deadcat/1 Iroh evidence service.
    Run {
        #[command(flatten)]
        common: RunArgs,
        #[command(subcommand)]
        backend: BackendArgs,
    },
}

#[derive(Debug, ClapArgs)]
struct RunArgs {
    #[arg(long, default_value = "./deadcat-node-data/store.redb")]
    database: PathBuf,
    /// Stable raw 32-byte Iroh secret. Defaults beside the database.
    #[arg(long)]
    iroh_secret: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = CliNetwork::ElementsRegtest)]
    network: CliNetwork,
    #[arg(long)]
    policy_asset: AssetId,
    /// Existing canonical checkpoint immediately before the desired scan range.
    #[arg(long, default_value_t = 0)]
    baseline_height: u32,
    #[arg(long, default_value_t = 5)]
    sync_interval_seconds: u64,
    #[arg(long)]
    registration_bearer_token: Option<String>,
    /// Disable n0 relay/discovery and advertise direct addresses only.
    #[arg(long)]
    direct_only: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliNetwork {
    Liquid,
    LiquidTestnet,
    ElementsRegtest,
}

impl From<CliNetwork> for LiquidNetwork {
    fn from(value: CliNetwork) -> Self {
        match value {
            CliNetwork::Liquid => Self::Liquid,
            CliNetwork::LiquidTestnet => Self::LiquidTestnet,
            CliNetwork::ElementsRegtest => Self::ElementsRegtest,
        }
    }
}

#[derive(Debug, Subcommand)]
enum BackendArgs {
    /// A locally validating Elements Core JSON-RPC backend.
    Elements {
        #[arg(long, default_value = "http://127.0.0.1:7041")]
        url: String,
        #[arg(long)]
        cookie_file: Option<PathBuf>,
        #[arg(long, requires = "rpc_password", conflicts_with = "cookie_file")]
        rpc_user: Option<String>,
        #[arg(long, requires = "rpc_user", conflicts_with = "cookie_file")]
        rpc_password: Option<String>,
    },
    /// A lightweight Liquid Esplora backend. Global discovery remains advisory.
    Esplora {
        #[arg(long)]
        url: String,
        #[arg(long)]
        bearer_token: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing()?;
    let cli = Cli::parse();
    match cli.command {
        Command::Run { common, backend } => match backend {
            BackendArgs::Elements {
                url,
                cookie_file,
                rpc_user,
                rpc_password,
            } => {
                let auth = match (cookie_file, rpc_user, rpc_password) {
                    (Some(path), None, None) => ElementsRpcAuth::CookieFile(path),
                    (None, Some(username), Some(password)) => {
                        ElementsRpcAuth::Basic { username, password }
                    }
                    (None, None, None) => ElementsRpcAuth::None,
                    _ => bail!("Elements RPC authentication flags are inconsistent"),
                };
                let source = ElementsRpcChainSource::new(ElementsRpcConfig::new(url, auth))?;
                run(common, source, BackendKind::ElementsRpc).await
            }
            BackendArgs::Esplora { url, bearer_token } => {
                let mut config = EsploraConfig::new(url);
                if let Some(token) = bearer_token {
                    config.auth = EsploraAuth::Bearer(token);
                }
                let source = EsploraChainSource::new(config)?;
                run(common, source, BackendKind::Esplora).await
            }
        },
    }
}

async fn run<S>(args: RunArgs, source: S, backend: BackendKind) -> anyhow::Result<()>
where
    S: ChainSource,
{
    if args.sync_interval_seconds == 0 {
        bail!("sync interval must be nonzero");
    }
    if let Some(parent) = args.database.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create data directory {}", parent.display()))?;
    }
    let store = Arc::new(Store::open(&args.database)?);
    let source = Arc::new(source);
    let network = LiquidNetwork::from(args.network);

    let (identity, discovery_from) = match (store.chain_identity()?, store.tip()?) {
        (Some(identity), Some(_)) => {
            if identity.network != network || identity.policy_asset != args.policy_asset {
                bail!("configured network/policy asset does not match the existing database");
            }
            let from = store
                .canonical_anchor(args.baseline_height)?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "baseline height {} is not retained by this database",
                        args.baseline_height
                    )
                })?;
            (identity, from)
        }
        (None, None) => {
            let genesis_hash = source
                .block_hash(0)
                .await
                .context("fetch genesis hash for a new database")?;
            let baseline_hash = source
                .block_hash(args.baseline_height)
                .await
                .context("fetch baseline checkpoint for a new database")?;
            let identity = ChainIdentity {
                network,
                genesis_hash,
                policy_asset: args.policy_asset,
            };
            let baseline = ChainAnchor {
                height: args.baseline_height,
                hash: baseline_hash,
            };
            store.bind_chain(identity)?;
            store.initialize_tip(baseline)?;
            (identity, baseline)
        }
        _ => bail!("database has only one of chain identity or indexed tip; rebuild is required"),
    };
    // Idempotently validates an already-bound database as well.
    store.bind_chain(identity)?;

    let indexed = store
        .tip()?
        .ok_or_else(|| anyhow::anyhow!("indexed tip disappeared after initialization"))?;
    let target = source.tip().await.unwrap_or(indexed);
    let discovery_mode = match backend {
        BackendKind::ElementsRpc => DiscoveryMode::FullHintScan,
        BackendKind::Esplora => DiscoveryMode::AdvisoryOnly,
    };
    let discovery = DiscoveryCoverage {
        mode: discovery_mode,
        from: discovery_from,
        scanned_through: indexed,
        target_tip: target,
        canonical_market_complete: false,
    };
    let handler = Arc::new(
        NodeRpcHandler::new(
            Arc::clone(&source),
            Arc::clone(&store),
            RpcHandlerConfig {
                network,
                genesis_hash: identity.genesis_hash,
                policy_asset: identity.policy_asset,
                backend,
                discovery,
                registration_bearer_token: args.registration_bearer_token,
                max_concurrent_registrations: 8,
                max_concurrent_broadcasts: 32,
                subscription_buffer: 256,
                subscription_poll_interval: Duration::from_millis(250),
            },
        )
        .map_err(|error| anyhow::anyhow!("invalid RPC handler configuration: {}", error.message))?,
    );

    let secret_path = args
        .iroh_secret
        .unwrap_or_else(|| args.database.with_extension("iroh-secret"));
    let secret = load_or_create_secret(&secret_path)?;
    let server = Server::bind(
        secret,
        if args.direct_only {
            IrohDiscoveryMode::Disabled
        } else {
            IrohDiscoveryMode::N0Defaults
        },
        ServerConfig::default(),
        Arc::clone(&handler),
    )
    .await?;
    println!(
        "{}",
        serde_json::to_string(&server.endpoint_addr())
            .context("serialize Iroh endpoint address")?
    );
    let server = server.spawn();

    let sync_source = Arc::clone(&source);
    let sync_store = Arc::clone(&store);
    let sync_handler = Arc::clone(&handler);
    let interval = Duration::from_secs(args.sync_interval_seconds);
    let sync_task = tokio::spawn(async move {
        let interpreter = DeadcatInterpreter::new(network, identity.policy_asset);
        loop {
            let target = sync_source.tip().await;
            match target {
                Ok(target) => {
                    if let Ok(Some(indexed)) = sync_store.tip() {
                        let _ = sync_handler.set_discovery_coverage(DiscoveryCoverage {
                            mode: discovery_mode,
                            from: discovery_from,
                            scanned_through: indexed,
                            target_tip: target,
                            canonical_market_complete: false,
                        });
                    }
                    match SyncCoordinator::new(
                        sync_source.as_ref(),
                        sync_store.as_ref(),
                        &interpreter,
                    )
                    .sync_to_tip()
                    .await
                    {
                        Ok(SyncOutcome::Ready(report)) => {
                            let _ = sync_handler.set_discovery_coverage(DiscoveryCoverage {
                                mode: discovery_mode,
                                from: discovery_from,
                                scanned_through: report.indexed_tip,
                                target_tip: report.indexed_tip,
                                canonical_market_complete: matches!(
                                    discovery_mode,
                                    DiscoveryMode::FullHintScan
                                ),
                            });
                        }
                        Ok(SyncOutcome::RescanRequired { .. }) => {
                            tracing::error!("deep reorg requires an explicit rebuild");
                        }
                        Err(error) => {
                            tracing::warn!(%error, "chain synchronization failed");
                            let _ = sync_store.set_sync_status(SyncStatus::BackendUnavailable);
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "chain backend is unavailable");
                    let _ = sync_store.set_sync_status(SyncStatus::BackendUnavailable);
                }
            }
            tokio::time::sleep(interval).await;
        }
    });

    tokio::signal::ctrl_c()
        .await
        .context("install Ctrl-C handler")?;
    server.shutdown_and_join().await?;
    sync_task.abort();
    let _ = sync_task.await;
    Ok(())
}

fn load_or_create_secret(path: &Path) -> anyhow::Result<SecretKey> {
    match fs::read(path) {
        Ok(bytes) => return secret_from_bytes(path, &bytes),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create Iroh key directory {}", parent.display()))?;
    }
    let key = SecretKey::generate();
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(&key.to_bytes())?;
            file.sync_all()?;
            Ok(key)
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            secret_from_bytes(path, &fs::read(path)?)
        }
        Err(error) => Err(error).with_context(|| format!("create {}", path.display())),
    }
}

fn secret_from_bytes(path: &Path, bytes: &[u8]) -> anyhow::Result<SecretKey> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} must contain exactly 32 bytes", path.display()))?;
    Ok(SecretKey::from_bytes(&bytes))
}

fn init_tracing() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("deadcat=info")),
        )
        .try_init()
        .map_err(|error| anyhow::anyhow!(error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iroh_secret_is_persisted_and_reused_exactly() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("identity.key");
        let first = load_or_create_secret(&path).expect("create key");
        let second = load_or_create_secret(&path).expect("reload key");
        assert_eq!(first.to_bytes(), second.to_bytes());
        assert_eq!(fs::read(path).expect("key bytes").len(), 32);
    }

    #[test]
    fn malformed_iroh_secret_fails_closed() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("identity.key");
        fs::write(&path, [0_u8; 31]).expect("write malformed key");
        let error = load_or_create_secret(&path).expect_err("malformed key");
        assert!(error.to_string().contains("exactly 32 bytes"));
    }
}

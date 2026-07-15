use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use deadcat_iroh::{DiscoveryMode as IrohDiscoveryMode, SecretKey, Server, ServerConfig};
use deadcat_node::activation::resolve_activation_anchor;
use deadcat_node::chain::ChainSource;
use deadcat_node::chain::elements_rpc::{
    ElementsRpcAuth, ElementsRpcChainSource, ElementsRpcConfig,
};
use deadcat_node::chain::esplora::{EsploraAuth, EsploraChainSource, EsploraConfig};
use deadcat_node::interpreter::DeadcatInterpreter;
use deadcat_node::rpc_handler::{NodeRpcHandler, RpcHandlerConfig};
use deadcat_node::store::{ChainIdentity, Store};
use deadcat_node::sync::{SyncCoordinator, SyncError, SyncOutcome};
use deadcat_rpc::{BackendKind, SyncStatus};
use deadcat_types::LiquidNetwork;
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
    /// Explicitly rebuild an invalidated database from its stored activation checkpoint.
    Rebuild {
        #[command(flatten)]
        common: RebuildArgs,
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
    /// Elements-regtest-only checkpoint immediately before the desired scan range.
    #[arg(long)]
    baseline_height: Option<u32>,
    #[arg(long, default_value_t = 5)]
    sync_interval_seconds: u64,
    #[arg(long)]
    registration_bearer_token: Option<String>,
    /// Disable n0 relay/discovery and advertise direct addresses only.
    #[arg(long)]
    direct_only: bool,
}

#[derive(Debug, ClapArgs)]
struct RebuildArgs {
    #[arg(long, default_value = "./deadcat-node-data/store.redb")]
    database: PathBuf,
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
                let auth = elements_auth(cookie_file, rpc_user, rpc_password)?;
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
        Command::Rebuild { common, backend } => match backend {
            BackendArgs::Elements {
                url,
                cookie_file,
                rpc_user,
                rpc_password,
            } => {
                let auth = elements_auth(cookie_file, rpc_user, rpc_password)?;
                let source = ElementsRpcChainSource::new(ElementsRpcConfig::new(url, auth))?;
                rebuild(common, source).await
            }
            BackendArgs::Esplora { url, bearer_token } => {
                let mut config = EsploraConfig::new(url);
                if let Some(token) = bearer_token {
                    config.auth = EsploraAuth::Bearer(token);
                }
                let source = EsploraChainSource::new(config)?;
                rebuild(common, source).await
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
    let source = Arc::new(source);
    let network = LiquidNetwork::from(args.network);
    let activation_anchor =
        resolve_activation_anchor(source.as_ref(), network, args.baseline_height)
            .await
            .context("verify v1 activation checkpoint")?;
    let identity = ChainIdentity {
        network,
        genesis_hash: source
            .block_hash(0)
            .await
            .context("fetch and verify chain genesis")?,
        policy_asset: args.policy_asset,
    };
    if let Some(parent) = args.database.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create data directory {}", parent.display()))?;
    }
    let store = Arc::new(Store::open(&args.database)?);
    store.initialize_chain(identity, activation_anchor)?;

    let handler = Arc::new(
        NodeRpcHandler::new(
            Arc::clone(&source),
            Arc::clone(&store),
            RpcHandlerConfig {
                backend,
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
    let interval = Duration::from_secs(args.sync_interval_seconds);
    let sync_task = tokio::spawn(async move {
        let interpreter = DeadcatInterpreter::new(network, identity.policy_asset);
        loop {
            match SyncCoordinator::new(sync_source.as_ref(), sync_store.as_ref(), &interpreter)
                .sync_to_tip()
                .await
            {
                Ok(SyncOutcome::Ready(_)) => {}
                Ok(SyncOutcome::RescanRequired { .. }) => {
                    tracing::error!(
                        "deep reorg requires stopping the daemon and running deadcat-node rebuild"
                    );
                }
                Err(error) => {
                    tracing::warn!(%error, "chain synchronization failed");
                    if matches!(&error, SyncError::ChainSource(_)) {
                        // RescanRequired is sticky; this cannot accidentally
                        // remove the rebuild write barrier.
                        let _ = sync_store.set_sync_status(SyncStatus::BackendUnavailable);
                    }
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

async fn rebuild<S>(args: RebuildArgs, source: S) -> anyhow::Result<()>
where
    S: ChainSource,
{
    if !args.database.is_file() {
        bail!(
            "rebuild requires an existing database at {}",
            args.database.display()
        );
    }
    let store = Store::open(&args.database)?;
    let identity = store
        .chain_identity()?
        .ok_or_else(|| anyhow::anyhow!("database chain identity is not initialized"))?;
    let activation = store
        .activation_anchor()?
        .ok_or_else(|| anyhow::anyhow!("database v1 activation checkpoint is not initialized"))?;

    let source_genesis = source
        .block_hash(0)
        .await
        .context("fetch and verify chain genesis before rebuild")?;
    if source_genesis != identity.genesis_hash {
        bail!(
            "backend genesis {} does not match database genesis {}",
            source_genesis,
            identity.genesis_hash
        );
    }
    let regtest_baseline =
        (identity.network == LiquidNetwork::ElementsRegtest).then_some(activation.height);
    let expected_activation =
        resolve_activation_anchor(&source, identity.network, regtest_baseline)
            .await
            .context("verify v1 activation checkpoint before rebuild")?;
    if expected_activation != activation {
        bail!(
            "compiled activation checkpoint {expected_activation:?} does not match database checkpoint {activation:?}"
        );
    }
    // Verifies the persisted identity, activation checkpoint, tip boundary,
    // and the database's retained canonical checkpoint before mutation.
    store.initialize_chain(identity, activation)?;

    let interpreter = DeadcatInterpreter::new(identity.network, identity.policy_asset);
    match SyncCoordinator::new(&source, &store, &interpreter)
        .rebuild_to_tip()
        .await?
    {
        SyncOutcome::Ready(report) => {
            println!(
                "rebuild complete at {}:{} ({} blocks applied)",
                report.indexed_tip.height, report.indexed_tip.hash, report.blocks_applied
            );
            Ok(())
        }
        SyncOutcome::RescanRequired {
            indexed_tip,
            source_tip,
        } => bail!(
            "another deep branch change interrupted rebuild at {indexed_tip:?} toward {source_tip:?}; rerun rebuild"
        ),
    }
}

fn elements_auth(
    cookie_file: Option<PathBuf>,
    rpc_user: Option<String>,
    rpc_password: Option<String>,
) -> anyhow::Result<ElementsRpcAuth> {
    match (cookie_file, rpc_user, rpc_password) {
        (Some(path), None, None) => Ok(ElementsRpcAuth::CookieFile(path)),
        (None, Some(username), Some(password)) => Ok(ElementsRpcAuth::Basic { username, password }),
        (None, None, None) => Ok(ElementsRpcAuth::None),
        _ => bail!("Elements RPC authentication flags are inconsistent"),
    }
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
    use async_trait::async_trait;
    use deadcat_node::chain::{ChainSourceError, Outspend, TransactionStatus};
    use deadcat_types::ChainAnchor;
    use elements::hashes::Hash as _;
    use elements::{Block, BlockHash, OutPoint, Script, Transaction, Txid};

    use super::*;

    #[derive(Clone, Copy)]
    struct TipOnlySource {
        tip: ChainAnchor,
    }

    #[async_trait]
    impl ChainSource for TipOnlySource {
        async fn tip(&self) -> Result<ChainAnchor, ChainSourceError> {
            Ok(self.tip)
        }

        async fn block_hash(&self, height: u32) -> Result<BlockHash, ChainSourceError> {
            if height == self.tip.height {
                Ok(self.tip.hash)
            } else {
                Err(ChainSourceError::NotFound(format!("block {height}")))
            }
        }

        async fn block(&self, _hash: BlockHash) -> Result<Block, ChainSourceError> {
            Err(unused_source_call())
        }

        async fn transaction(&self, _txid: Txid) -> Result<Transaction, ChainSourceError> {
            Err(unused_source_call())
        }

        async fn transaction_status(
            &self,
            _txid: Txid,
        ) -> Result<TransactionStatus, ChainSourceError> {
            Err(unused_source_call())
        }

        async fn outspend(
            &self,
            _outpoint: OutPoint,
        ) -> Result<Option<Outspend>, ChainSourceError> {
            Err(unused_source_call())
        }

        async fn script_history(&self, _script: &Script) -> Result<Vec<Txid>, ChainSourceError> {
            Err(unused_source_call())
        }

        async fn issuance_transaction(
            &self,
            _asset_id: AssetId,
        ) -> Result<Option<Txid>, ChainSourceError> {
            Err(unused_source_call())
        }

        async fn estimate_fee_rate(&self, _target_blocks: u16) -> Result<f64, ChainSourceError> {
            Err(unused_source_call())
        }

        async fn broadcast(&self, _transaction: &Transaction) -> Result<Txid, ChainSourceError> {
            Err(unused_source_call())
        }
    }

    fn unused_source_call() -> ChainSourceError {
        ChainSourceError::Unsupported("unused test source method".to_owned())
    }

    fn test_anchor(byte: u8) -> ChainAnchor {
        ChainAnchor {
            height: 0,
            hash: BlockHash::from_byte_array([byte; 32]),
        }
    }

    fn test_asset(byte: u8) -> AssetId {
        AssetId::from_slice(&[byte; 32]).expect("asset")
    }

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

    #[test]
    fn rebuild_cli_uses_only_the_existing_database_and_selected_backend() {
        let cli = Cli::try_parse_from([
            "deadcat-node",
            "rebuild",
            "--database",
            "/tmp/deadcat.redb",
            "elements",
            "--url",
            "http://127.0.0.1:7041",
        ])
        .expect("parse rebuild command");
        let Command::Rebuild { common, backend } = cli.command else {
            panic!("expected rebuild command")
        };
        assert_eq!(common.database, PathBuf::from("/tmp/deadcat.redb"));
        assert!(matches!(
            backend,
            BackendArgs::Elements {
                url,
                cookie_file: None,
                rpc_user: None,
                rpc_password: None,
            } if url == "http://127.0.0.1:7041"
        ));
    }

    #[tokio::test]
    async fn operator_rebuild_recovers_invalidated_store_and_wrong_genesis_is_non_mutating() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("deadcat.redb");
        let activation = test_anchor(0x11);
        let identity = ChainIdentity {
            network: LiquidNetwork::ElementsRegtest,
            genesis_hash: activation.hash,
            policy_asset: test_asset(0x22),
        };
        let store = Store::open(&database).expect("open store");
        store
            .initialize_chain(identity, activation)
            .expect("initialize chain");
        store.invalidate_for_rebuild().expect("invalidate store");
        let invalidated = store.status_snapshot().expect("invalidated snapshot");
        drop(store);

        let error = rebuild(
            RebuildArgs {
                database: database.clone(),
            },
            TipOnlySource {
                tip: test_anchor(0x33),
            },
        )
        .await
        .expect_err("wrong genesis must fail before reset");
        assert!(error.to_string().contains("backend genesis"));
        let unchanged = Store::open(&database).expect("reopen invalidated store");
        assert_eq!(
            unchanged.status_snapshot().expect("unchanged snapshot"),
            invalidated
        );
        drop(unchanged);

        rebuild(
            RebuildArgs {
                database: database.clone(),
            },
            TipOnlySource { tip: activation },
        )
        .await
        .expect("operator rebuild");
        let rebuilt = Store::open(&database).expect("reopen rebuilt store");
        let snapshot = rebuilt.status_snapshot().expect("rebuilt snapshot");
        assert_eq!(snapshot.indexed_tip, activation);
        assert_eq!(snapshot.sync_status, SyncStatus::Ready);
        assert_eq!(
            snapshot.event_high_watermark.epoch,
            invalidated.event_high_watermark.epoch
        );
    }
}

use std::fs;
use std::io::{self, Read as _, Write as _};
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context as _, Result, anyhow, bail};
use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use deadcat_iroh::{Client, ClientConfig, EndpointAddr, EndpointId};
use deadcat_rpc::{
    EventFilter, PageRequest, RecoveryFamily, Request, RequestEnvelope, RequestId, SCHEMA_VERSION,
    SnapshotCursor,
};
use deadcat_types::{
    ChainPosition, ContractId, ContractPackage, EventCursor, OrderDirection, OrderSide,
};
use elements::encode::deserialize;
use elements::{AssetId, Transaction};
use serde::Serialize;

const DEFAULT_PAGE_LIMIT: u16 = 100;

#[derive(Debug, Parser)]
#[command(name = "deadcat", version, about = "Deadcat client and operator CLI")]
struct Cli {
    /// Iroh endpoint ID of the deadcat node.
    #[arg(long)]
    endpoint_id: EndpointId,

    /// Direct UDP address for the node (IP:PORT). May be repeated. If omitted,
    /// Iroh discovery resolves the endpoint ID.
    #[arg(long, value_name = "IP:PORT")]
    direct_addr: Vec<SocketAddr>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Fetch node identity, chain position, discovery coverage, and capabilities.
    GetInfo,
    /// Validate and atomically register an on-chain contract package.
    Register {
        #[command(flatten)]
        package: JsonSource,
        /// Optional registration authorization token. No wallet secrets are sent.
        #[arg(long)]
        bearer_token: Option<String>,
    },
    /// Fetch one contract by its creation-anchor outpoint.
    GetContract {
        #[arg(value_parser = parse_contract_id)]
        contract_id: ContractId,
    },
    /// List binary markets in a stable snapshot.
    ListMarkets {
        #[command(flatten)]
        page: PageArgs,
    },
    /// Fetch a binary market and its current state.
    MarketSnapshot {
        #[arg(value_parser = parse_contract_id)]
        market_id: ContractId,
    },
    /// List maker orders for a market.
    ListOrders {
        #[arg(value_parser = parse_contract_id)]
        market_id: ContractId,
        #[arg(long)]
        side: Option<SideArg>,
        #[arg(long)]
        direction: Option<DirectionArg>,
        #[command(flatten)]
        page: PageArgs,
    },
    /// Fetch a market's aggregated maker order book.
    OrderBook {
        #[arg(value_parser = parse_contract_id)]
        market_id: ContractId,
    },
    /// List public chain-recovery hints.
    ListHints {
        #[arg(long)]
        family: Option<FamilyArg>,
        #[command(flatten)]
        page: PageArgs,
    },
    /// Fetch confirmed transition history for one contract.
    History {
        #[arg(value_parser = parse_contract_id)]
        contract_id: ContractId,
        /// Exclusive chain position formatted HEIGHT:TX_INDEX.
        #[arg(long, value_parser = parse_chain_position)]
        after: Option<ChainPosition>,
        #[arg(long, default_value_t = DEFAULT_PAGE_LIMIT, value_parser = nonzero_u16)]
        limit: u16,
    },
    /// Fetch transaction evidence at HEIGHT:TX_INDEX.
    Transaction {
        #[arg(value_parser = parse_chain_position)]
        position: ChainPosition,
    },
    /// Find registered contract relationships for an asset ID.
    Asset { asset_id: AssetId },
    /// Estimate the integer sat/kVB fee rate for a confirmation target.
    Fee {
        #[arg(long, default_value_t = 2, value_parser = nonzero_u16)]
        target_blocks: u16,
    },
    /// Ask the node for an advisory order route. The client must still verify it.
    Route {
        #[arg(value_parser = parse_contract_id)]
        market_id: ContractId,
        #[arg(long)]
        side: SideArg,
        #[arg(long)]
        direction: DirectionArg,
        #[arg(long, value_parser = nonzero_u64)]
        base_amount: u64,
        #[arg(long, default_value_t = 100, value_parser = nonzero_u16)]
        max_orders: u16,
    },
    /// Broadcast a fully signed Elements transaction encoded as consensus hex.
    Broadcast {
        #[command(flatten)]
        transaction: HexSource,
    },
    /// Send any non-subscription RPC Request encoded as strict JSON.
    Request {
        #[command(flatten)]
        request: JsonSource,
    },
    /// Open a cursor-resumable durable event stream.
    Subscribe {
        /// EventCursor encoded as strict RPC JSON.
        #[arg(long, value_name = "JSON", value_parser = parse_event_cursor)]
        after_json: Option<EventCursor>,
        /// EventFilter encoded as strict RPC JSON (default: "all").
        #[arg(long, value_name = "JSON", default_value = "\"all\"", value_parser = parse_event_filter)]
        filter_json: EventFilter,
    },
}

#[derive(Clone, Debug, ClapArgs)]
struct PageArgs {
    /// SnapshotCursor encoded as strict RPC JSON.
    #[arg(long, value_name = "JSON", value_parser = parse_snapshot_cursor)]
    cursor_json: Option<SnapshotCursor>,
    #[arg(long, default_value_t = DEFAULT_PAGE_LIMIT, value_parser = nonzero_u16)]
    limit: u16,
}

impl PageArgs {
    fn into_request(self) -> PageRequest {
        PageRequest {
            cursor: self.cursor_json,
            limit: self.limit,
        }
    }
}

#[derive(Clone, Debug, ClapArgs)]
struct JsonSource {
    /// Read JSON from this argument.
    #[arg(long, value_name = "JSON", conflicts_with_all = ["file", "stdin"], required_unless_present_any = ["file", "stdin"])]
    json: Option<String>,
    /// Read JSON from this UTF-8 file.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["json", "stdin"])]
    file: Option<PathBuf>,
    /// Read JSON from standard input.
    #[arg(long, conflicts_with_all = ["json", "file"])]
    stdin: bool,
}

impl JsonSource {
    fn read(&self) -> Result<String> {
        read_source(self.json.as_deref(), self.file.as_ref(), self.stdin, "JSON")
    }

    fn parse<T>(&self, description: &str) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let source = self.read()?;
        serde_json::from_str(&source).with_context(|| format!("invalid {description} JSON"))
    }
}

#[derive(Clone, Debug, ClapArgs)]
struct HexSource {
    /// Read consensus hex from this argument.
    #[arg(long, value_name = "HEX", conflicts_with_all = ["file", "stdin"], required_unless_present_any = ["file", "stdin"])]
    hex: Option<String>,
    /// Read consensus hex from this UTF-8 file.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["hex", "stdin"])]
    file: Option<PathBuf>,
    /// Read consensus hex from standard input.
    #[arg(long, conflicts_with_all = ["hex", "file"])]
    stdin: bool,
}

impl HexSource {
    fn transaction(&self) -> Result<Transaction> {
        let source = read_source(self.hex.as_deref(), self.file.as_ref(), self.stdin, "hex")?;
        let bytes = hex::decode(source.trim()).context("transaction must be hexadecimal")?;
        if bytes.is_empty() {
            bail!("transaction must not be empty");
        }
        deserialize(&bytes).context("invalid Elements consensus transaction")
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SideArg {
    Yes,
    No,
}

impl From<SideArg> for OrderSide {
    fn from(value: SideArg) -> Self {
        match value {
            SideArg::Yes => Self::Yes,
            SideArg::No => Self::No,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum DirectionArg {
    SellBase,
    SellQuote,
}

impl From<DirectionArg> for OrderDirection {
    fn from(value: DirectionArg) -> Self {
        match value {
            DirectionArg::SellBase => Self::SellBase,
            DirectionArg::SellQuote => Self::SellQuote,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum FamilyArg {
    BinaryMarketV1,
    MakerOrderV1,
}

impl From<FamilyArg> for RecoveryFamily {
    fn from(value: FamilyArg) -> Self {
        match value {
            FamilyArg::BinaryMarketV1 => Self::BinaryMarketV1,
            FamilyArg::MakerOrderV1 => Self::MakerOrderV1,
        }
    }
}

#[derive(Debug, Default)]
struct RequestIds {
    next: u64,
}

impl RequestIds {
    fn next(&mut self) -> Result<RequestId> {
        self.next = self
            .next
            .checked_add(1)
            .ok_or_else(|| anyhow!("request ID space exhausted"))?;
        Ok(RequestId(self.next))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    run(cli).await
}

async fn run(cli: Cli) -> Result<()> {
    let request = command_request(&cli.command)?;
    let target = endpoint_addr(cli.endpoint_id, &cli.direct_addr);
    let client = Client::connect(target, ClientConfig::default())
        .await
        .context("failed to connect to deadcat node")?;
    let mut ids = RequestIds::default();
    let envelope = RequestEnvelope {
        schema_version: SCHEMA_VERSION,
        request_id: ids.next()?,
        request,
    };

    if matches!(envelope.request, Request::SubscribeEvents { .. }) {
        let result = run_subscription(&client, envelope).await;
        client.close().await;
        result
    } else {
        let response = client.call(envelope).await.context("RPC request failed")?;
        print_json(&response)?;
        client.close().await;
        Ok(())
    }
}

fn command_request(command: &Command) -> Result<Request> {
    Ok(match command {
        Command::GetInfo => Request::GetInfo,
        Command::Register {
            package,
            bearer_token,
        } => Request::RegisterContractPackage {
            package: package.parse::<ContractPackage>("contract package")?,
            bearer_token: bearer_token.clone(),
        },
        Command::GetContract { contract_id } => Request::GetContract {
            contract_id: *contract_id,
        },
        Command::ListMarkets { page } => Request::ListMarkets {
            page: page.clone().into_request(),
        },
        Command::MarketSnapshot { market_id } => Request::GetMarketSnapshot {
            market_id: *market_id,
        },
        Command::ListOrders {
            market_id,
            side,
            direction,
            page,
        } => Request::ListOrders {
            market_id: *market_id,
            side: side.map(Into::into),
            direction: direction.map(Into::into),
            page: page.clone().into_request(),
        },
        Command::OrderBook { market_id } => Request::GetOrderBook {
            market_id: *market_id,
        },
        Command::ListHints { family, page } => Request::ListRecoveryHints {
            family: family.map(Into::into),
            page: page.clone().into_request(),
        },
        Command::History {
            contract_id,
            after,
            limit,
        } => Request::GetContractHistory {
            contract_id: *contract_id,
            after: *after,
            limit: *limit,
        },
        Command::Transaction { position } => Request::GetTransaction {
            position: *position,
        },
        Command::Asset { asset_id } => Request::LookupAsset {
            asset_id: *asset_id,
        },
        Command::Fee { target_blocks } => Request::EstimateFeerate {
            target_blocks: *target_blocks,
        },
        Command::Route {
            market_id,
            side,
            direction,
            base_amount,
            max_orders,
        } => Request::SuggestRoute {
            market_id: *market_id,
            side: (*side).into(),
            direction: (*direction).into(),
            base_amount: *base_amount,
            max_orders: *max_orders,
        },
        Command::Broadcast { transaction } => Request::BroadcastSignedTransaction {
            transaction: transaction.transaction()?,
        },
        Command::Request { request } => {
            let request = request.parse::<Request>("RPC request")?;
            if matches!(request, Request::SubscribeEvents { .. }) {
                bail!("use the subscribe command for subscription requests");
            }
            request
        }
        Command::Subscribe {
            after_json,
            filter_json,
        } => Request::SubscribeEvents {
            after: *after_json,
            filter: filter_json.clone(),
        },
    })
}

async fn run_subscription(client: &Client, envelope: RequestEnvelope) -> Result<()> {
    let mut stream = client
        .subscribe(envelope)
        .await
        .context("failed to open event subscription")?;
    print_json(&serde_json::json!({
        "subscription_opened": { "through": stream.opened_through() }
    }))?;

    loop {
        tokio::select! {
            event = stream.next() => match event.context("event subscription failed")? {
                Some(event) => print_json(&event)?,
                None => break,
            },
            result = tokio::signal::ctrl_c() => {
                result.context("failed to listen for Ctrl-C")?;
                break;
            }
        }
    }
    Ok(())
}

fn endpoint_addr(endpoint_id: EndpointId, direct_addrs: &[SocketAddr]) -> EndpointAddr {
    direct_addrs
        .iter()
        .copied()
        .fold(EndpointAddr::new(endpoint_id), EndpointAddr::with_ip_addr)
}

fn print_json(value: &impl Serialize) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value).context("failed to serialize output")?;
    output.write_all(b"\n").context("failed to write output")?;
    output.flush().context("failed to flush output")
}

fn read_source(
    inline: Option<&str>,
    file: Option<&PathBuf>,
    stdin: bool,
    description: &str,
) -> Result<String> {
    match (inline, file, stdin) {
        (Some(value), None, false) => Ok(value.to_owned()),
        (None, Some(path), false) => fs::read_to_string(path)
            .with_context(|| format!("failed to read {} from {}", description, path.display())),
        (None, None, true) => {
            let mut value = String::new();
            io::stdin()
                .lock()
                .read_to_string(&mut value)
                .with_context(|| format!("failed to read {description} from standard input"))?;
            Ok(value)
        }
        _ => bail!("select exactly one {description} input source"),
    }
}

fn parse_contract_id(value: &str) -> std::result::Result<ContractId, String> {
    value
        .parse()
        .map_err(|error| format!("expected TXID:VOUT contract ID: {error}"))
}

fn parse_chain_position(value: &str) -> std::result::Result<ChainPosition, String> {
    let (height, tx_index) = value
        .split_once(':')
        .ok_or_else(|| "expected HEIGHT:TX_INDEX".to_owned())?;
    Ok(ChainPosition {
        block_height: height
            .parse()
            .map_err(|error| format!("invalid block height: {error}"))?,
        tx_index: tx_index
            .parse()
            .map_err(|error| format!("invalid transaction index: {error}"))?,
    })
}

fn parse_snapshot_cursor(value: &str) -> std::result::Result<SnapshotCursor, String> {
    parse_json_arg(value, "snapshot cursor")
}

fn parse_event_cursor(value: &str) -> std::result::Result<EventCursor, String> {
    parse_json_arg(value, "event cursor")
}

fn parse_event_filter(value: &str) -> std::result::Result<EventFilter, String> {
    parse_json_arg(value, "event filter")
}

fn parse_json_arg<T>(value: &str, description: &str) -> std::result::Result<T, String>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_str(value).map_err(|error| format!("invalid {description} JSON: {error}"))
}

fn nonzero_u16(value: &str) -> std::result::Result<u16, String> {
    let value: u16 = value
        .parse()
        .map_err(|error| format!("invalid integer: {error}"))?;
    if value == 0 {
        Err("value must be nonzero".to_owned())
    } else {
        Ok(value)
    }
}

fn nonzero_u64(value: &str) -> std::result::Result<u64, String> {
    let value: u64 = value
        .parse()
        .map_err(|error| format!("invalid integer: {error}"))?;
    if value == 0 {
        Err("value must be nonzero".to_owned())
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::*;
    use clap::error::ErrorKind;

    // RFC 8032 test-vector public key; valid as an Iroh endpoint ID.
    const ENDPOINT_ID: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const TXID: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("valid CLI")
    }

    #[test]
    fn endpoint_id_only_uses_discovery_address() {
        let cli = parse(&["deadcat", "--endpoint-id", ENDPOINT_ID, "get-info"]);
        let target = endpoint_addr(cli.endpoint_id, &cli.direct_addr);
        assert!(target.is_empty());
    }

    #[test]
    fn repeated_direct_addresses_are_preserved() {
        let cli = parse(&[
            "deadcat",
            "--endpoint-id",
            ENDPOINT_ID,
            "--direct-addr",
            "127.0.0.1:4919",
            "--direct-addr",
            "[::1]:4920",
            "get-info",
        ]);
        let target = endpoint_addr(cli.endpoint_id, &cli.direct_addr);
        assert_eq!(target.ip_addrs().count(), 2);
    }

    #[test]
    fn compact_contract_and_position_parsers_are_exact() {
        let id = parse_contract_id(&format!("{TXID}:7")).expect("contract id");
        assert_eq!(id.txid(), elements::Txid::from_str(TXID).expect("txid"));
        assert_eq!(id.vout(), 7);
        assert_eq!(
            parse_chain_position("42:7").expect("position"),
            ChainPosition {
                block_height: 42,
                tx_index: 7,
            }
        );
        assert!(parse_contract_id(&format!("11:{TXID}")).is_err());
        assert!(parse_chain_position("42").is_err());
    }

    #[test]
    fn typed_commands_build_rpc_requests() {
        let cli = parse(&[
            "deadcat",
            "--endpoint-id",
            ENDPOINT_ID,
            "route",
            &format!("{TXID}:2"),
            "--side",
            "yes",
            "--direction",
            "sell-base",
            "--base-amount",
            "25",
        ]);
        assert!(matches!(
            command_request(&cli.command).expect("request"),
            Request::SuggestRoute {
                side: OrderSide::Yes,
                direction: OrderDirection::SellBase,
                base_amount: 25,
                max_orders: 100,
                ..
            }
        ));

        let cli = parse(&[
            "deadcat",
            "--endpoint-id",
            ENDPOINT_ID,
            "subscribe",
            "--after-json",
            r#"{"epoch":"00000000000000000000000000000000","sequence":"9"}"#,
            "--filter-json",
            r#"{"contracts":{"contract_ids":[]}}"#,
        ]);
        assert!(matches!(
            command_request(&cli.command).expect("request"),
            Request::SubscribeEvents {
                after: Some(EventCursor { sequence: 9, .. }),
                filter: EventFilter::Contracts { .. },
            }
        ));

        let cli = parse(&[
            "deadcat",
            "--endpoint-id",
            ENDPOINT_ID,
            "list-hints",
            "--family",
            "maker-order-v1",
            "--cursor-json",
            r#"{"as_of":{"height":42,"hash":"1111111111111111111111111111111111111111111111111111111111111111"},"event_high_watermark":{"epoch":"000102030405060708090a0b0c0d0e0f","sequence":"9"},"scope":{"recovery_hints":{"family":"maker_order_v1"}},"after_key":"0000002a0000000300000004"}"#,
            "--limit",
            "3",
        ]);
        assert!(matches!(
            command_request(&cli.command).expect("request"),
            Request::ListRecoveryHints {
                family: Some(RecoveryFamily::MakerOrderV1),
                page: PageRequest {
                    cursor: Some(SnapshotCursor { after_key, .. }),
                    limit: 3,
                },
            } if after_key == hex::decode("0000002a0000000300000004").expect("hex")
        ));
    }

    #[test]
    fn register_json_and_file_sources_build_the_exact_package_request() {
        let fixture: RequestEnvelope = serde_json::from_str(include_str!(
            "../../../fixtures/wire-v1/register-contract-package-request.json"
        ))
        .expect("registration request fixture");
        let Request::RegisterContractPackage { package, .. } = fixture.request else {
            panic!("registration request fixture")
        };
        let package_json = serde_json::to_string(&package).expect("package JSON");

        let inline = parse(&[
            "deadcat",
            "--endpoint-id",
            ENDPOINT_ID,
            "register",
            "--json",
            &package_json,
            "--bearer-token",
            "secret",
        ]);
        assert_eq!(
            command_request(&inline.command).expect("inline registration request"),
            Request::RegisterContractPackage {
                package: package.clone(),
                bearer_token: Some("secret".to_owned()),
            }
        );

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("package.json");
        fs::write(&path, &package_json).expect("write package fixture");
        let path = path.to_str().expect("UTF-8 temporary path");
        let from_file = parse(&[
            "deadcat",
            "--endpoint-id",
            ENDPOINT_ID,
            "register",
            "--file",
            path,
        ]);
        assert_eq!(
            command_request(&from_file.command).expect("file registration request"),
            Request::RegisterContractPackage {
                package,
                bearer_token: None,
            }
        );
    }

    #[test]
    fn json_source_is_required_and_mutually_exclusive() {
        let missing = Cli::try_parse_from(["deadcat", "--endpoint-id", ENDPOINT_ID, "register"])
            .expect_err("missing source");
        assert_eq!(missing.kind(), ErrorKind::MissingRequiredArgument);

        let conflicting = Cli::try_parse_from([
            "deadcat",
            "--endpoint-id",
            ENDPOINT_ID,
            "request",
            "--json",
            "\"get_info\"",
            "--stdin",
        ])
        .expect_err("conflicting sources");
        assert_eq!(conflicting.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn generic_request_rejects_subscriptions() {
        let cli = parse(&[
            "deadcat",
            "--endpoint-id",
            ENDPOINT_ID,
            "request",
            "--json",
            r#"{"subscribe_events":{"after":null,"filter":"all"}}"#,
        ]);
        assert!(command_request(&cli.command).is_err());
    }

    #[test]
    fn request_ids_are_monotonic_and_wire_safe() {
        let mut ids = RequestIds::default();
        assert_eq!(ids.next().expect("id"), RequestId(1));
        assert_eq!(ids.next().expect("id"), RequestId(2));
        let encoded = serde_json::to_string(&ids.next().expect("id")).expect("JSON");
        assert_eq!(encoded, "\"3\"");
    }

    #[test]
    fn broadcast_decodes_consensus_hex_and_rejects_bad_input() {
        let transaction = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let encoded = hex::encode(elements::encode::serialize(&transaction));
        let source = HexSource {
            hex: Some(encoded),
            file: None,
            stdin: false,
        };
        assert_eq!(source.transaction().expect("transaction"), transaction);

        let source = HexSource {
            hex: Some("not-hex".to_owned()),
            file: None,
            stdin: false,
        };
        assert!(source.transaction().is_err());
    }

    #[test]
    fn nonzero_validators_reject_zero() {
        assert!(nonzero_u16("0").is_err());
        assert!(nonzero_u64("0").is_err());
        assert_eq!(nonzero_u16("7").expect("valid"), 7);
    }
}

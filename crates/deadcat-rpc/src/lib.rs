//! Transport-independent v1 Deadcat RPC schema.

use deadcat_types::{
    BinaryMarketParams, BinaryMarketState, ChainAnchor, ChainPosition, ContractId, ContractKind,
    ContractPackage, ContractSyncState, DiscoveryCoverage, EventCursor, LiquidNetwork,
    MakerOrderParams, MakerOrderState, OrderDirection, OrderSide, RecoveryHintLocation,
};
use elements::{AssetId, BlockHash, OutPoint, Transaction, Txid};
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(#[serde(with = "deadcat_types::serde_u64_string")] pub u64);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    pub schema_version: u32,
    pub request_id: RequestId,
    pub request: Request,
}

impl RequestEnvelope {
    pub fn validate_version(&self) -> Result<(), RpcError> {
        if self.schema_version == SCHEMA_VERSION {
            Ok(())
        } else {
            Err(RpcError::new(
                RpcErrorCode::UnsupportedVersion,
                format!(
                    "unsupported RPC schema {}; expected {SCHEMA_VERSION}",
                    self.schema_version
                ),
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerEnvelope {
    pub schema_version: u32,
    pub request_id: RequestId,
    pub frame: ServerFrame,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    GetInfo,
    RegisterContractPackage {
        package: ContractPackage,
        bearer_token: Option<String>,
    },
    GetContract {
        contract_id: ContractId,
    },
    ListMarkets {
        page: PageRequest,
    },
    GetMarketSnapshot {
        market_id: ContractId,
    },
    ListOrders {
        market_id: ContractId,
        side: Option<OrderSide>,
        direction: Option<OrderDirection>,
        page: PageRequest,
    },
    GetOrderBook {
        market_id: ContractId,
    },
    ListRecoveryHints {
        family: Option<RecoveryFamily>,
        page: PageRequest,
    },
    GetContractHistory {
        contract_id: ContractId,
        after: Option<ChainPosition>,
        limit: u16,
    },
    GetTransaction {
        position: ChainPosition,
    },
    InterpretTransaction {
        transaction: Transaction,
    },
    LookupAsset {
        asset_id: AssetId,
    },
    EstimateFeerate {
        target_blocks: u16,
    },
    SuggestRoute {
        market_id: ContractId,
        side: OrderSide,
        direction: OrderDirection,
        #[serde(with = "deadcat_types::serde_u64_string")]
        base_amount: u64,
        max_orders: u16,
    },
    BroadcastSignedTransaction {
        transaction: Transaction,
    },
    SubscribeEvents {
        after: Option<EventCursor>,
        filter: EventFilter,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryFamily {
    BinaryMarketV1,
    MakerOrderV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
// Wire DTOs deliberately keep their JSON shape direct. They are framed and
// bounded before decoding and are not retained in large in-memory arrays.
#[allow(clippy::large_enum_variant)]
pub enum ServerFrame {
    Unary { outcome: RpcOutcome<Response> },
    SubscriptionOpened { through: EventCursor },
    SubscriptionEvent { event: EventEnvelope },
    SubscriptionEnded { reason: SubscriptionEnd },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RpcOutcome<T> {
    Success { value: T },
    Error { error: RpcError },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum Response {
    Info {
        info: NodeInfo,
    },
    RegistrationAccepted {
        registration: PackageRegistrationReceipt,
    },
    Contract {
        contract: Option<ContractView>,
    },
    Markets {
        page: ContractPage,
    },
    MarketSnapshot {
        snapshot: MarketSnapshot,
    },
    Orders {
        page: ContractPage,
    },
    OrderBook {
        book: OrderBookSnapshot,
    },
    RecoveryHints {
        page: RecoveryHintPage,
    },
    ContractHistory {
        page: ContractHistoryPage,
    },
    Transaction {
        evidence: Option<TransactionEvidence>,
    },
    Interpretation {
        interpretation: TransactionInterpretation,
    },
    Asset {
        lookup: AssetLookup,
    },
    Feerate {
        estimate: FeeRateEstimate,
    },
    Route {
        route: RouteSuggestion,
    },
    BroadcastAccepted {
        txid: Txid,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeInfo {
    pub network: LiquidNetwork,
    pub genesis_hash: BlockHash,
    pub policy_asset: AssetId,
    pub backend: BackendKind,
    /// Absent while the configured backend is unavailable. Except while
    /// `sync_status` is `RescanRequired`, the indexed tip remains an exact
    /// canonical anchor for the evidence already stored. `RescanRequired`
    /// deliberately exposes the last indexed, now-untrusted branch tip only
    /// for operator diagnosis; chain-derived RPCs fail closed in that state.
    pub source_tip: Option<ChainAnchor>,
    pub indexed_tip: ChainAnchor,
    pub sync_status: SyncStatus,
    pub rollback_retention_blocks: u8,
    pub discovery: DiscoveryCoverage,
    pub capabilities: Vec<Capability>,
    pub event_high_watermark: EventCursor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    ElementsRpc,
    Esplora,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncStatus {
    Starting,
    Syncing,
    Ready,
    RescanRequired,
    BackendUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    BinaryMarketV1,
    MakerOrderV1,
    ElementsRpc,
    Esplora,
    FullHintScan,
    RegisterContractPackage,
    BroadcastSignedTransaction,
    EvidenceQueries,
    DurableSubscriptions,
    AdvisoryRouting,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub contract_id: ContractId,
    pub sync_state: ContractSyncState,
    pub already_registered: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageRegistrationReceipt {
    pub roots: Vec<ContractId>,
    pub contracts: Vec<RegistrationReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractView {
    pub contract_id: ContractId,
    pub kind: ContractKind,
    pub sync_state: ContractSyncState,
    pub creation_position: ChainPosition,
    pub parameters: ContractParametersView,
    pub state: ContractStateView,
    pub parent_market: Option<ContractId>,
    pub outcome_side: Option<OrderSide>,
    pub live_outpoints: Vec<LiveOutpoint>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageRequest {
    pub cursor: Option<SnapshotCursor>,
    pub limit: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotCursor {
    pub as_of: ChainAnchor,
    pub event_high_watermark: EventCursor,
    /// Exact query and filters that produced this continuation. Servers reject
    /// a cursor if it is replayed against a different scope.
    pub scope: SnapshotScope,
    #[serde(with = "hex::serde")]
    pub after_key: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SnapshotScope {
    Markets,
    Orders {
        market_id: ContractId,
        side: Option<OrderSide>,
        direction: Option<OrderDirection>,
    },
    RecoveryHints {
        family: Option<RecoveryFamily>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotMetadata {
    pub as_of: ChainAnchor,
    pub event_high_watermark: EventCursor,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractPage {
    pub snapshot: SnapshotMetadata,
    pub contracts: Vec<ContractView>,
    pub next: Option<SnapshotCursor>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ContractParametersView {
    BinaryMarket { params: BinaryMarketParams },
    MakerOrder { params: MakerOrderParams },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ContractStateView {
    BinaryMarket { state: BinaryMarketState },
    MakerOrder { state: MakerOrderState },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveOutpoint {
    pub role: u8,
    #[serde(with = "deadcat_types::serde_outpoint_object")]
    pub outpoint: OutPoint,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarketSnapshot {
    pub snapshot: SnapshotMetadata,
    pub contract: ContractView,
    pub params: BinaryMarketParams,
    pub state: BinaryMarketState,
    pub live_outpoints: Vec<LiveOutpoint>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderBookSnapshot {
    pub snapshot: SnapshotMetadata,
    pub market_id: ContractId,
    pub asks: Vec<OrderBookLevel>,
    pub bids: Vec<OrderBookLevel>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderBookLevel {
    pub contract_id: ContractId,
    pub side: OrderSide,
    pub direction: OrderDirection,
    pub price: u32,
    #[serde(with = "deadcat_types::serde_u64_string")]
    pub remaining_base: u64,
    pub creation_position: ChainPosition,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryHintPage {
    pub snapshot: SnapshotMetadata,
    pub hints: Vec<RecoveryHintRecord>,
    pub next: Option<SnapshotCursor>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractHistoryPage {
    pub snapshot: SnapshotMetadata,
    pub contract_id: ContractId,
    pub entries: Vec<HistoryEntry>,
    pub next: Option<ChainPosition>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntry {
    pub position: ChainPosition,
    pub txid: Txid,
    pub transition_kind: u16,
    #[serde(with = "hex::serde")]
    pub transition_payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionEvidence {
    pub position: ChainPosition,
    pub block_hash: BlockHash,
    pub txid: Txid,
    pub transaction: Transaction,
    pub affected_contract_ids: Vec<ContractId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionInterpretation {
    pub txid: Txid,
    pub created_contracts: Vec<ContractView>,
    pub transitions: Vec<InterpretedTransition>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterpretedTransition {
    pub contract_id: ContractId,
    pub kind: u16,
    #[serde(with = "hex::serde")]
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetLookup {
    pub asset_id: AssetId,
    pub relations: Vec<AssetRelation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetRelationKind {
    Collateral,
    YesToken,
    NoToken,
    YesReissuanceToken,
    NoReissuanceToken,
    OrderBase,
    OrderQuote,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetRelation {
    pub contract_id: ContractId,
    pub kind: AssetRelationKind,
    pub role: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeeRateEstimate {
    pub target_blocks: u16,
    /// Integer satoshis per 1,000 virtual bytes; no floating-point wire value.
    pub sats_per_kvb: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteSuggestion {
    pub snapshot: SnapshotMetadata,
    pub market_id: ContractId,
    pub legs: Vec<RouteLeg>,
    #[serde(with = "deadcat_types::serde_u64_string")]
    pub total_base: u64,
    #[serde(with = "deadcat_types::serde_u64_string")]
    pub total_quote: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteLeg {
    pub order_id: ContractId,
    #[serde(with = "deadcat_types::serde_u64_string")]
    pub base_amount: u64,
    #[serde(with = "deadcat_types::serde_u64_string")]
    pub quote_amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryHintRecord {
    pub location: RecoveryHintLocation,
    pub creation_txid: Txid,
    pub family: RecoveryFamily,
    #[serde(with = "hex::serde")]
    pub payload: Vec<u8>,
    pub associated_contract: Option<ContractId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum EventFilter {
    All,
    Contracts { contract_ids: Vec<ContractId> },
    MarketTree { market_id: ContractId },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventEnvelope {
    pub cursor: EventCursor,
    pub event: Event,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    ContractRegistered {
        contract_id: ContractId,
    },
    ContractReady {
        contract_id: ContractId,
        through: ChainAnchor,
    },
    TransactionApplied {
        anchor: ChainAnchor,
        txid: Txid,
        position: ChainPosition,
        affected_contract_ids: Vec<ContractId>,
        affected_market_ids: Vec<ContractId>,
    },
    BackfillApplied {
        contract_id: ContractId,
        through: ChainAnchor,
        transition_count: u32,
    },
    ChainRolledBack {
        old_tip: ChainAnchor,
        new_tip: ChainAnchor,
        orphaned_positions: Vec<ChainPosition>,
        affected_contract_ids: Vec<ContractId>,
        affected_market_ids: Vec<ContractId>,
    },
    SyncStatusChanged {
        status: SyncStatus,
    },
    CaughtUp {
        through_cursor: EventCursor,
        indexed_tip: ChainAnchor,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionEnd {
    ServerShutdown,
    StaleCursor,
    Backpressure,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcError {
    pub code: RpcErrorCode,
    pub message: String,
}

impl RpcError {
    #[must_use]
    pub fn new(code: RpcErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcErrorCode {
    UnsupportedVersion,
    NotFound,
    NotSynced,
    RescanRequired,
    StaleCursor,
    SnapshotInvalidated,
    InvalidRegistration,
    ForkConflict,
    RateLimited,
    BackendUnavailable,
    InvalidTransaction,
    CovenantInvariantViolation,
    Unauthorized,
    UnsupportedOperation,
}

#[cfg(test)]
mod tests {
    use super::*;
    use deadcat_types::{
        CONTRACT_PACKAGE_FORMAT_VERSION, ChainIdentity, ContractDeclaration, ContractDescriptor,
    };
    use elements::hashes::Hash as _;
    use std::str::FromStr as _;

    const PACKAGE_TXID: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn package_fixture() -> ContractPackage {
        let market_id = ContractId::new(OutPoint::new(
            Txid::from_str(PACKAGE_TXID).expect("txid"),
            2,
        ));
        let order_id = ContractId::new(OutPoint::new(
            Txid::from_str(PACKAGE_TXID).expect("txid"),
            9,
        ));
        let asset =
            |byte: &str| AssetId::from_str(&byte.repeat(32)).expect("fixture asset identifier");

        ContractPackage {
            format_version: CONTRACT_PACKAGE_FORMAT_VERSION,
            chain: ChainIdentity {
                network: LiquidNetwork::ElementsRegtest,
                genesis_hash: BlockHash::from_str(&"aa".repeat(32)).expect("genesis hash"),
            },
            roots: vec![order_id],
            // Dependency order is intentionally reversed. The wire contract
            // preserves declaration order even though verification topologically
            // evaluates the market before its order.
            declarations: vec![
                ContractDeclaration {
                    contract_id: order_id,
                    descriptor: ContractDescriptor::MakerOrderV1 {
                        parent_market: market_id,
                        side: OrderSide::Yes,
                        params: MakerOrderParams {
                            base_asset_id: asset("22"),
                            quote_asset_id: asset("11"),
                            price: 2_500,
                            min_active_base: 10,
                            direction: OrderDirection::SellQuote,
                            maker_receive_spk_hash: [0x66; 32],
                            maker_pubkey: [0x77; 32],
                        },
                    },
                },
                ContractDeclaration {
                    contract_id: market_id,
                    descriptor: ContractDescriptor::BinaryMarketV1 {
                        params: BinaryMarketParams {
                            oracle_public_key: [0x02; 32],
                            collateral_asset_id: asset("11"),
                            yes_token_asset_id: asset("22"),
                            no_token_asset_id: asset("33"),
                            yes_reissuance_token_id: asset("44"),
                            no_reissuance_token_id: asset("55"),
                            base_payout: 100_000_000,
                            expiry_height: 1_234,
                        },
                    },
                },
            ],
        }
    }

    #[test]
    fn request_ids_are_decimal_strings() {
        let envelope = RequestEnvelope {
            schema_version: SCHEMA_VERSION,
            request_id: RequestId(u64::MAX),
            request: Request::GetInfo,
        };
        let json = serde_json::to_string(&envelope).expect("serialize");
        assert!(json.contains(r#""request_id":"18446744073709551615""#));
        assert_eq!(
            serde_json::from_str::<RequestEnvelope>(&json).expect("deserialize"),
            envelope
        );
    }

    #[test]
    fn get_info_request_matches_committed_fixture() {
        let envelope = RequestEnvelope {
            schema_version: SCHEMA_VERSION,
            request_id: RequestId(1),
            request: Request::GetInfo,
        };
        let json = serde_json::to_string(&envelope).expect("serialize");
        assert_eq!(
            json,
            include_str!("../../../fixtures/wire-v1/get-info-request.json").trim()
        );
    }

    #[test]
    fn register_package_request_matches_committed_fixture() {
        let envelope = RequestEnvelope {
            schema_version: SCHEMA_VERSION,
            request_id: RequestId(7),
            request: Request::RegisterContractPackage {
                package: package_fixture(),
                bearer_token: None,
            },
        };
        let json = serde_json::to_string(&envelope).expect("serialize");
        assert_eq!(
            json,
            include_str!("../../../fixtures/wire-v1/register-contract-package-request.json").trim()
        );
        assert_eq!(
            serde_json::from_str::<RequestEnvelope>(&json).expect("deserialize"),
            envelope
        );
    }

    #[test]
    fn registration_receipt_matches_committed_fixture_and_preserves_order() {
        let package = package_fixture();
        let synced_through = ChainAnchor {
            height: 321,
            hash: BlockHash::from_str(&"bb".repeat(32)).expect("block hash"),
        };
        let envelope = ServerEnvelope {
            schema_version: SCHEMA_VERSION,
            request_id: RequestId(7),
            frame: ServerFrame::Unary {
                outcome: RpcOutcome::Success {
                    value: Response::RegistrationAccepted {
                        registration: PackageRegistrationReceipt {
                            roots: package.roots.clone(),
                            contracts: vec![
                                RegistrationReceipt {
                                    contract_id: package.declarations[0].contract_id,
                                    sync_state: ContractSyncState::CatchingUp { synced_through },
                                    already_registered: false,
                                },
                                RegistrationReceipt {
                                    contract_id: package.declarations[1].contract_id,
                                    sync_state: ContractSyncState::CatchingUp { synced_through },
                                    already_registered: false,
                                },
                            ],
                        },
                    },
                },
            },
        };
        let json = serde_json::to_string(&envelope).expect("serialize");
        assert_eq!(
            json,
            include_str!("../../../fixtures/wire-v1/register-contract-package-receipt.json").trim()
        );
        assert_eq!(
            serde_json::from_str::<ServerEnvelope>(&json).expect("deserialize"),
            envelope
        );
    }

    #[test]
    fn recovery_hint_page_request_matches_committed_fixture() {
        let envelope = RequestEnvelope {
            schema_version: SCHEMA_VERSION,
            request_id: RequestId(8),
            request: Request::ListRecoveryHints {
                family: Some(RecoveryFamily::MakerOrderV1),
                page: PageRequest {
                    cursor: None,
                    limit: 2,
                },
            },
        };
        let json = serde_json::to_string(&envelope).expect("serialize");
        assert_eq!(
            json,
            include_str!("../../../fixtures/wire-v1/list-recovery-hints-request.json").trim()
        );
        assert_eq!(
            serde_json::from_str::<RequestEnvelope>(&json).expect("deserialize"),
            envelope
        );
    }

    #[test]
    fn recovery_hint_page_response_binds_next_cursor_to_snapshot_and_scope() {
        let as_of = ChainAnchor {
            height: 42,
            hash: BlockHash::from_str(&"bb".repeat(32)).expect("block hash"),
        };
        let event_high_watermark = EventCursor {
            epoch: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            sequence: 9,
        };
        let snapshot = SnapshotMetadata {
            as_of,
            event_high_watermark,
        };
        let contract_id = ContractId::new(OutPoint::new(
            Txid::from_str(PACKAGE_TXID).expect("txid"),
            9,
        ));
        let location = RecoveryHintLocation {
            position: ChainPosition {
                block_height: 42,
                tx_index: 3,
            },
            output_index: 4,
        };
        let mut payload = vec![0x40, 0x00, 0x01];
        payload.extend_from_slice(&contract_id.txid().to_byte_array());
        payload.extend_from_slice(&2_500_u32.to_be_bytes());
        payload.extend_from_slice(&10_u32.to_be_bytes());
        assert_eq!(payload.len(), 43);
        let envelope = ServerEnvelope {
            schema_version: SCHEMA_VERSION,
            request_id: RequestId(8),
            frame: ServerFrame::Unary {
                outcome: RpcOutcome::Success {
                    value: Response::RecoveryHints {
                        page: RecoveryHintPage {
                            snapshot,
                            hints: vec![RecoveryHintRecord {
                                location,
                                creation_txid: contract_id.txid(),
                                family: RecoveryFamily::MakerOrderV1,
                                payload,
                                associated_contract: None,
                            }],
                            next: Some(SnapshotCursor {
                                as_of,
                                event_high_watermark,
                                scope: SnapshotScope::RecoveryHints {
                                    family: Some(RecoveryFamily::MakerOrderV1),
                                },
                                after_key: vec![0, 0, 0, 42, 0, 0, 0, 3, 0, 0, 0, 4],
                            }),
                        },
                    },
                },
            },
        };
        let json = serde_json::to_string(&envelope).expect("serialize");
        assert_eq!(
            json,
            include_str!("../../../fixtures/wire-v1/list-recovery-hints-response.json").trim()
        );
        assert_eq!(
            serde_json::from_str::<ServerEnvelope>(&json).expect("deserialize"),
            envelope
        );
    }

    #[test]
    fn nested_package_unknown_fields_are_rejected() {
        let envelope = RequestEnvelope {
            schema_version: SCHEMA_VERSION,
            request_id: RequestId(7),
            request: Request::RegisterContractPackage {
                package: package_fixture(),
                bearer_token: None,
            },
        };
        let mut json = serde_json::to_value(envelope).expect("serialize");
        json["request"]["register_contract_package"]["package"]["declarations"][1]
            ["descriptor"]["binary_market_v1"]["params"]
            .as_object_mut()
            .expect("params object")
            .insert("surprise".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<RequestEnvelope>(json).is_err());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let json = r#"{
            "schema_version":1,
            "request_id":"1",
            "request":"get_info",
            "surprise":true
        }"#;
        assert!(serde_json::from_str::<RequestEnvelope>(json).is_err());
    }

    #[test]
    fn unsupported_version_is_typed() {
        let request = RequestEnvelope {
            schema_version: SCHEMA_VERSION + 1,
            request_id: RequestId(1),
            request: Request::GetInfo,
        };
        assert_eq!(
            request.validate_version().expect_err("unsupported"),
            RpcError::new(
                RpcErrorCode::UnsupportedVersion,
                "unsupported RPC schema 2; expected 1"
            )
        );
    }

    #[test]
    fn live_outpoints_keep_strict_object_json_while_using_elements_type() {
        let outpoint = OutPoint::new(Txid::from_byte_array([0x22; 32]), 3);
        let live = LiveOutpoint { role: 7, outpoint };
        let json = serde_json::to_value(live).expect("serialize");
        assert_eq!(json["outpoint"]["txid"], outpoint.txid.to_string());
        assert_eq!(json["outpoint"]["vout"], 3);
        assert_eq!(
            serde_json::from_value::<LiveOutpoint>(json).expect("deserialize"),
            live
        );
        assert!(
            serde_json::from_str::<LiveOutpoint>(&format!(
                r#"{{"role":7,"outpoint":"{outpoint}"}}"#
            ))
            .is_err()
        );
    }
}

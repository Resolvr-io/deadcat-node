# Storage, synchronization, and RPC

## Canonical types

```rust
#[repr(transparent)]
pub struct ContractId(elements::OutPoint); // canonical creation anchor

pub struct ChainPosition {
    pub block_height: u32,
    pub tx_index: u32,
}

pub struct ChainAnchor {
    pub height: u32,
    pub hash: BlockHash,
}
```

`ContractId` is not the oracle `market_id`. The former identifies an on-chain
contract instance by one exact creation-anchor output; the latter is the binary
asset-pair digest signed by the oracle. Market ContractIds anchor at the initial
dormant YES RT output; maker ContractIds anchor at the initial order output.
The ID remains stable as live outpoints change and is not itself proof that the
claimed contract is valid.

Keys use stable, manually encoded big-endian components. Rust struct
serialization is not used directly for redb keys. Values use an explicitly
versioned encoding. A ContractId key is 36 bytes:
`txid_internal_bytes[32] || vout_be_u32[4]`. Its strict human-readable RPC form
is `{"txid":"...","vout":n}`.

Ordinary chain and live-state references use `elements::OutPoint` directly.
Only the creation anchor receives the nominal ContractId wrapper, preventing a
current or wallet outpoint from being used accidentally as identity without
duplicating rust-elements' native Liquid transaction type or coupling storage
to a wallet library.

### Portable registration types

```rust
pub enum ContractDescriptor {
    BinaryMarketV1 { params: BinaryMarketParams },
    MakerOrderV1 {
        parent_market: ContractId,
        side: OrderSide,
        params: MakerOrderParams,
    },
}

pub struct ContractDeclaration {
    pub contract_id: ContractId,
    pub descriptor: ContractDescriptor,
}

pub struct ContractPackage {
    pub format_version: u16, // exactly 1 in v1
    pub chain: ChainIdentity, // network + genesis hash
    pub roots: Vec<ContractId>,
    pub declarations: Vec<ContractDeclaration>,
}
```

The descriptor says what to compile, the declaration claims where it was
created, and the package carries the requested roots plus any parent dependency
closure. All are untrusted input. V1 accepts 1..=16 unique declared roots and
1..=64 unique declarations. It rejects duplicate IDs/roots, self-dependencies,
undeclared roots, and declarations unreachable from a root. A referenced parent
must be declared in the package or already verified in this node; an included
maker parent must be a binary market. Package order is irrelevant to dependency
verification. A successful receipt returns roots in package root order and
per-contract results in declaration order, including idempotent results.

## Redb schema

The initial schema contains:

| Table | Purpose |
|---|---|
| `meta` | schema version, chain identity, immutable activation anchor, event epoch/high-watermark, sync status |
| `chain_tip` | singleton indexed canonical tip |
| `chain_checkpoints` | height to block hash and previous hash |
| `contracts` | immutable params, kind/version, creation, current state, provenance |
| `retained_contract_declarations` | explicitly registered, normalized declarations retained across rollback/rebuild |
| `outpoint_owners` | outpoint to contract and slot/role |
| `contract_outpoints` | contract and slot/role to current outpoint |
| `script_index` | script hash, contract, and role multimap |
| `asset_relations` | asset, relation kind, contract, and role multimap |
| `market_children` | market to outcome/side and child contract relationships |
| `order_book` | market, side, direction, price, FIFO position, order to capacity |
| `recovery_hints` | chain position/output index to validated envelope and parsed public fields |
| `chain_transactions` | position to block hash, txid, raw tx, and all transitions |
| `contract_history` | contract and position to transition reference |
| `backfill_progress` | catching-up contract to pinned anchor and next scan position |
| `undo_transactions` | recent pre-state and index mutations for rollback |
| `events` | durable epoch/sequence cursor to event envelope |

Current state is materialized for read performance. `chain_transactions` and
`contract_history` are the canonical audit trail and are retained indefinitely
in v1. Undo retention is a separate two-block operational window.

`retained_contract_declarations` is the deliberate exception to the
chain-derived tables. A declaration is written only after its package has been
fully verified, but it remains watch intent rather than chain authority. A
rollback or rebuild preserves it and canonical replay recompiles it against the
replacement branch before recreating any materialized contract state. Package
roots and boundaries are not retained: the normalized union of accepted
declarations is the dependency/watch set.

The asset index is many-to-many. A market token can be referenced by its parent
market and by many orders, and later by pools.

The order-book key uses exact `u32` price followed by confirmed creation
position and contract ID. Asks scan ascending and bids scan descending. FIFO is
canonical chain order, never Nostr timestamp or server arrival time.

## Atomic write model

The coordinator interprets one `ChainTxDelta` per confirmed transaction:

```rust
pub struct ChainTxDelta {
    pub position: ChainPosition,
    pub block_hash: BlockHash,
    pub txid: Txid,
    pub raw_tx: Transaction,
    pub created_contracts: Vec<TrackedContract>,
    pub state_updates: Vec<StateUpdate>,
}

pub struct BlockDelta {
    pub anchor: ChainAnchor,
    pub prev_block_hash: BlockHash,
    pub ordered_txids: Vec<Txid>,
    pub relevant_transactions: Vec<ChainTxDelta>,
}
```

If one transaction advances a market and three orders, all four legs must be in
the delta or interpretation fails.

`ordered_txids` covers the complete block. `relevant_transactions` contains a
delta for every transaction that creates or touches a tracked contract; redb
does not archive unrelated Liquid transactions.

The public store operation is `apply_block(BlockDelta)`. Relevant deltas are
validated and applied in `tx_index` order inside one redb write transaction.
This is stronger than the required per-chain-transaction atomicity and prevents
a crash from exposing a partially indexed block. Each chain transaction remains
a separate history and event unit.

One commit changes together:

- current states;
- live outpoints;
- script, asset, relationship, and order-book indexes;
- raw transaction and contract histories;
- undo records;
- durable events; and
- the indexed checkpoint/tip.

Retrying the same position, block hash, and txid is a no-op only if the persisted
result matches. A different transaction at an occupied position is a fork
conflict and requires rollback. Spending a tracked contract input without a
valid corresponding transition is fail-closed.

Before mutation, `apply_block` rejects:

- a height other than the indexed tip plus one or a mismatched previous hash;
- an empty complete-block txid list, or a duplicate, non-monotonic, or
  out-of-range relevant transaction index;
- a delta txid that does not match both its raw transaction and the complete
  block txid at that index;
- more than one state update for the same `ContractId` in one transaction; or
- any tracked input that is not accounted for exactly once by the complete
  transition batch.

Redb work runs through a dedicated writer actor or blocking worker, not directly
on Tokio/Iroh request tasks.

## Synchronization

One chain-ordered coordinator replaces one follower task per contract:

1. compare the source tip with stored checkpoints;
2. fetch complete blocks in ascending order;
3. process transactions by block index;
4. detect tracked inputs through `outpoint_owners`;
5. discover candidate creations from registered references and canonical hints;
6. interpret every affected contract against the same raw transaction;
7. commit the complete block; and
8. wake subscribers after the durable commit.

Same-block child spends see the state produced by earlier transactions in that
block. Static market/order scripts can be batched during catch-up. A future LMSR
pool will be followed primarily through its active outpoint lineage.

The coordinator pins a source anchor for each fetch range and verifies every
returned block's height, hash, previous hash, transaction indexes, and txids.
It restarts the range if Elements Core or Esplora changes branches during the
fetch.

Canonical redb state contains confirmed transactions only. A future mempool
preview is explicitly noncanonical and cannot alter current state or history.

### Global hint discovery

Each protocol release defines a network-specific activation anchor. The anchor
is an exclusive checkpoint: valid v1 creation and scanning begin at
`anchor.height + 1`. V1 fixes these production checkpoints:

| Network | Height | Block hash |
|---|---:|---|
| Liquid | 3,974,391 | `705d699fe1d7f9433837f5f8fec9347c2d5f25aebec5c70ce838db50db890c35` |
| Liquid testnet | 2,529,866 | `78fe3d5ce6a0df49e7f41adf2e20e610f34f2813dfeaaf50be869ad0e32f510e` |

Elements regtest uses its dynamically selected checkpoint, genesis by default.
The node verifies the exact height/hash against its backend before creating or
opening the database and atomically binds chain identity, activation, and the
initial tip. Package registration rejects every creation at or before the
checkpoint, which makes activation-forward retained-declaration replay
complete.

An archival Elements Core backend scans complete blocks once from immediately
after that anchor to the pinned tip. During the same ordered pass the node:

- stores every length-valid recognized recovery-hint envelope with its chain
  position and output index;
- fully reconstructs and registers canonical standalone market creations; and
- retains order hints as client-side mnemonic-recovery candidates even when the
  public fields are insufficient for the node to compile the order.

Automatic market discovery accepts only the fixed standalone creation shape.
Composed creations use complete contract-package registration, avoiding
combinatorial scans over attacker-supplied issuance sets. A standard Esplora
service has no global OP_RETURN-prefix index, so activation-to-tip scanning
requires downloading all raw blocks and may be unavailable or operationally
expensive. Nostr and manual registration remain fast-start paths.

`GetInfo` reports discovery coverage separately from contract synchronization:

```text
mode: FullHintScan | AdvisoryOnly
from: ChainAnchor
scanned_through: ChainAnchor
target_tip: ChainAnchor
canonical_market_complete: bool
```

`from` is the exclusive activation checkpoint. `scanned_through` is the
persisted indexed tip. `canonical_market_complete` is true only for
`FullHintScan` while sync status is `Ready` and the current source tip exactly
equals the indexed tip; it is derived rather than stored as a mutable flag.

A node can be fully synchronized for every registered contract while its global
market discovery remains incomplete.

### Package registration, late registration, and backfill

The verifier checks the package's exact chain identity and dependency graph,
fetches confirmed creation evidence from its configured chain source, resolves
parents before children, compiles each canonical descriptor, and validates each
nominated anchor plus the full family-specific creation invariant. The market
anchor must be the exact initial dormant YES RT output; the maker anchor must be
the exact initial order output. Every declaration is verified before one redb
transaction inserts the complete package, so failure cannot leave a partial
dependency graph. An identical retry is idempotent.

Registration initially stores a verified contract as `CatchingUp`, excluded
from active listings, order routing, and current snapshots. A backfill worker:

1. pins the current indexed anchor;
2. scans from the verified creation position through that anchor using stored
   evidence and/or the configured chain source;
3. replays all transitions, including a same-block creation and spend; and
4. calls an idempotent `apply_backfill_batch` operation.

The backfill operation verifies that every referenced block hash is still
canonical, merges newly recognized legs into any existing
`chain_transactions` row, updates contract history/state/indexes, advances
`backfill_progress`, and appends durable backfill events in one redb write
transaction. If the global tip advances, backfill continues to the newer
anchor. The final write changes the contract to `Ready` only when its
`synced_through` anchor equals the current indexed tip. A supplied current
outpoint is merely a scan hint; lineage replay is authoritative.

## Reorgs

The store keeps undo batches for the latest two blocks.

For a one- or two-block reorg, the coordinator finds the common ancestor and
rolls back orphaned blocks in reverse order. State, outpoints, indexes, history
visibility, contracts created on the orphan, and indexed tip are restored
atomically. Previously delivered event rows are not erased; a durable rollback
event records the affected contract IDs and market ancestry needed for
server-side filtering.

Orphaned rows are removed from the position-keyed `chain_transactions` and
`contract_history` canonical tables before replacement rows reuse those
positions. The append-only event log is the durable record that the orphaned
branch was once observed; an optional raw-transaction cache may retain its
bytes, but it is never returned as canonical history.

If no common ancestor exists in the retained window:

1. set `SyncStatus::RescanRequired`;
2. make that status sticky and reject chain-derived reads, interpretation,
   routing, and registration;
3. rotate the durable-event epoch;
4. require the local operator to stop the daemon and invoke
   `deadcat-node rebuild`;
5. reverify the backend genesis and immutable activation checkpoint before any
   destructive write;
6. clear chain materialization, history, index, and undo tables while retaining
   normalized declarations and the durable event journal;
7. reset the tip to the activation checkpoint; and
8. replay complete blocks before returning to `Ready`.

`RescanRequired` cannot be overwritten by a later backend outage or ordinary
status update; only the atomic reset exits it. Repeated invalidation is
idempotent and does not rotate the event epoch again. A crash before reset
leaves the invalidated database untouched. A crash after reset or any replayed
block leaves a complete persisted prefix, so `rebuild` or ordinary `run` can
resume without clearing again.

Two-block undo data is not claimed to restore an older checkpoint. The rebuild
is explicit and observable. The node never silently wipes, guesses, or
continues from inconsistent state.

## RPC

While `RescanRequired` is active, `GetInfo`, `SubscribeEvents`,
`EstimateFeerate`, and `BroadcastSignedTransaction` remain available. Every
registration and chain-derived query, interpretation, or routing request fails
with typed `RescanRequired` before dispatch. Chain-derived reads also
revalidate the durable-event epoch before returning, so an invalidation that
commits while a request is in flight cannot release known-stale materialized
state.

The transport-neutral request set begins with:

```text
GetInfo
RegisterContractPackage
GetContract
ListMarkets
GetMarketSnapshot
ListOrders / GetOrderBook
ListRecoveryHints
GetContractHistory
GetTransaction
InterpretTransaction
LookupAsset
SubscribeEvents
EstimateFeerate
SuggestRoute              (advisory)
BroadcastSignedTransaction
```

`GetInfo` returns protocol/schema versions, server identity, network/genesis,
backend kind, source and indexed tips, sync status, rollback retention, and
capabilities.

Snapshot and list responses come from one redb read transaction and include an
exact `as_of` anchor plus durable-event high-watermark. Pagination never splits
a block's canonical ordering semantics.

Every page cursor binds to that original anchor, event watermark, and exact
query scope. The scope records the endpoint and every result-set filter: the
market ID, side, and direction for orders, or the optional family for recovery
hints. Reusing a continuation with different filters is rejected rather than
silently skipping matches before its opaque `after_key`. Because v1 does not
retain arbitrary materialized snapshots, a subsequent page is also rejected
with `SnapshotInvalidated` if the indexed tip no longer exactly equals the
cursor anchor, including an ordinary tip advance. The client restarts from a
fresh snapshot rather than mixing versions or skipping entries.

`ListRecoveryHints` uses this same `PageRequest` / `SnapshotCursor` contract;
its optional family filter is part of the cursor's `RecoveryHints` scope. A
contract registration or recovery-hint association advances the durable-event
watermark, so a continuation created before that write is invalidated even when
the chain tip itself has not changed.

`InterpretTransaction` returns every recognized contract transition, not the
first match. It is a pure advisory RPC; canonical state changes only through the
coordinator.

Evidence responses contain raw creation/transition transactions, block hash,
chain position, parameters, CMR/script data, and typed input/output roles. The
client recompiles and replays locally. Before replay, an independent chain
source must authenticate the complete consensus transaction (including all
witnesses) at the reported block position. Matching only `txid` is insufficient
because Elements transaction IDs exclude the witness data that selects and
parameterizes Deadcat covenant transitions.

Typed errors include at least:

```text
UnsupportedVersion
NotFound
NotSynced
RescanRequired
StaleCursor
SnapshotInvalidated
InvalidRegistration
ForkConflict
RateLimited
BackendUnavailable
InvalidTransaction
CovenantInvariantViolation
```

## Durable events

```rust
pub struct EventCursor {
    pub epoch: [u8; 16],
    pub sequence: u64,
}

pub struct EventEnvelope {
    pub cursor: EventCursor,
    pub event: Event,
}
```

Events are append-only within an epoch and delivered at least once. Clients
deduplicate by the full cursor. A fresh random epoch is created on database
initialization and when the node first enters `RescanRequired`; sequence starts
at zero within it. The explicit reset and replay preserve that epoch, and
repeated invalidation while already invalidated does not rotate it again. A
cursor from another epoch, or ahead of the server's high-watermark, returns
`StaleCursor`. Backup and restore epoch policy remains future operational work.

```text
TransactionApplied { anchor, txid, position, transitions }
BackfillApplied { contract_id, through, transitions }
ChainRolledBack {
    old_tip,
    new_tip,
    orphaned_positions,
    affected_contract_ids,
    affected_market_ids
}
ContractRegistered
SyncStatusChanged
CaughtUp { through_cursor, indexed_tip }
```

`SyncStatusChanged` passes every subscription filter so contract- and
market-scoped subscribers observe invalidation and recovery even when no
contract transition is involved.

Subscriptions accept an optional prior cursor and an actual server-side filter:

```text
All
Contract(ids)
MarketTree(market_id)
```

The server reads a durable high-watermark, replays matching rows through it,
emits `CaughtUp` with that cursor even when no event matched the filter, and
then follows committed wakeups. Event sequence allocation and the meta
high-watermark commit atomically with the corresponding state change. Event
rows and their sequence counter are excluded from reorg undo; rollback appends
a new event containing immutable filter metadata. Broadcast notifications are
only wakeups; redb is the replay source. This makes snapshot-to-live handoff
gapless across reconnects and process restarts within an epoch.

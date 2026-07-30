# Storage, synchronization, and RPC

## Canonical records

`ContractId` is the exact creation-anchor outpoint. For `BinaryMarketV1`, that
anchor is the initial dormant YES reissuance-token output verified from the
complete creation transaction.

```rust
pub enum ContractDescriptor {
    BinaryMarketV1 { params: BinaryMarketParams },
}

pub struct ContractDeclaration {
    pub contract_id: ContractId,
    pub descriptor: ContractDescriptor,
}

pub struct ContractPackage {
    pub format_version: u16,
    pub chain: ChainIdentity,
    pub roots: Vec<ContractId>,
    pub declarations: Vec<ContractDeclaration>,
}
```

Packages are untrusted, chain-scoped atomic registration requests. The current
single-family protocol requires every independent declaration to be named as a
root. A shared creation transaction is fetched and stored once even when it
creates several declared markets. Caller order is preserved in receipts, but
has no authority over verification.

## Redb schema

Schema version 1 uses fixed binary keys and versioned values. Its logical
tables are:

| Table | Purpose |
|---|---|
| `meta` | schema, chain identity, activation anchor, sync status, event cursor |
| `chain_tip` / `chain_checkpoints` | indexed tip and retained block anchors |
| `chain_transactions` | shared raw transaction evidence by chain position |
| `outputs` | retained transaction outputs referenced by materialized state |
| `contracts` | verified market parameters, state, readiness, and live outputs |
| `retained_contract_declarations` | chain-independent watch intent |
| `outpoint_owners` / `contract_outpoints` | bidirectional live-output ownership |
| `script_index` | compiled script to market/slot candidates |
| `asset_relations` | market outcome and reissuance-token relationships |
| `recovery_hints` | discovered public market hints |
| `contract_history` | confirmed transition records |
| `backfill_progress` | late-registration replay progress |
| `undo_transactions` | shallow-reorg inverse data |
| `events` | durable append-only subscriber journal |

There is intentionally no order-book, parent/child, routing, or maker-state
index. Databases from the pre-removal alpha are unsupported and must be rebuilt;
the schema number remains 1 because no maker database reached production.

## Atomic write model

A complete block is the physical commit unit. Transactions are interpreted in
canonical block order, and all market legs affected by one transaction form one
`ChainTxDelta`. One redb write transaction applies:

1. shared raw evidence;
2. every affected market's before/after state and history;
3. live-output ownership and indexes;
4. recovery hints and backfill progress;
5. block and undo records; and
6. the new indexed tip.

If any leg fails, none of the transaction or block becomes visible. A retry of
the same canonical block is idempotent. Events are emitted only after the
corresponding state commit and remain in a durable journal across reorgs.

## Synchronization

The coordinator compares the source tip with the indexed tip, locates the
common ancestor within the two-block undo window, rolls back if necessary, and
then fetches and applies complete blocks in order. Static script candidates may
be batched, but interpretation always sees the overlay produced by earlier
transactions in the same block.

`ContractSyncState` is per-market:

- `CatchingUp { synced_through }` while a newly registered declaration is being
  replayed;
- `Ready { synced_through }` once it reaches the indexed tip.

Global `SyncStatus` is `Starting`, `Syncing`, `Ready`, `BackendUnavailable`, or
sticky `RescanRequired`. Chain-derived reads fail closed unless both the global
and per-market anchors satisfy the requested snapshot.

### Discovery and registration

With archival Elements Core, global discovery scans complete blocks after the
exclusive activation anchor for canonical market recovery outputs. A candidate
is accepted only after the node:

1. parses the compact hint;
2. locates the defining YES and NO issuances;
3. derives token and reissuance-token IDs;
4. compiles the market;
5. proves exact side-A dormant commitments and scripts; and
6. verifies the complete creation invariant.

Esplora lacks a standard global OP_RETURN-prefix query, so ordinary
Esplora-backed nodes use explicit `ContractPackage` registration. Registration
fetches canonical evidence from the node's own source, validates every market,
and inserts the entire package atomically. Late registration backfills only
transactions relevant to the market's compiled scripts or live outpoints.

Normalized declarations survive destructive reset. Chain-derived contracts,
history, outputs, indexes, and undo data do not. Replay from the immutable
activation checkpoint revalidates retained declarations against the replacement
branch; absent or invalid declarations remain dormant and do not block
unrelated synchronization.

## Reorgs and rebuild

The store retains undo information for the latest two blocks. A replacement
within that window restores exact prior state and then applies the new branch.
A deeper replacement atomically records `RescanRequired`; no chain-derived RPC
may present the now-untrusted branch as current.

The operator rebuild command verifies network, genesis, policy asset, and
activation hash before clearing derived state. It preserves retained
declarations and the durable event journal, changes the event epoch so old
cursors fail as stale, and resumes complete-block replay. The reset operation
is retryable after interruption.

## RPC

The versioned RPC surface is intentionally evidence-first and market-only:

```text
GetInfo
RegisterContractPackage
GetContract
ListMarkets
GetMarketSnapshot
ListRecoveryHints
GetContractHistory
GetTransaction
InterpretTransaction
LookupAsset
EstimateFeerate
BroadcastSignedTransaction
SubscribeEvents
```

There are no quote, order-book, or routing methods. RFQ/AMM/DLOB venue
interfaces belong to the client router and separate venue processes.

Responses that enumerate mutable state include:

- an exact `as_of { height, hash }` anchor;
- an event high-watermark;
- a scope-bound continuation cursor; and
- explicit readiness or stale-cursor errors.

`GetContractHistory` and `GetTransaction` expose enough raw evidence for the
client to recompile and replay a market independently. `InterpretTransaction`
is advisory and never substitutes for local signing-intent validation.

## Durable events

The event journal uses an epoch plus monotonically increasing sequence.
Subscriptions replay from an explicit cursor and then stream committed events.
A destructive rebuild starts a new epoch, making every old cursor
deterministically stale. Reorg events do not erase prior journal entries; they
describe the canonicality change so consumers can update their own views.

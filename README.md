# deadcat-node

`deadcat-node` is the authoritative implementation of the Deadcat protocol on
Liquid. It owns the canonical SimplicityHL contracts, interprets their confirmed
chain state, indexes that state in redb, and serves evidence over Iroh.

The node is deliberately not a wallet. Keys, wallet discovery, route selection,
PSET construction, confidential-transaction blinding, intent validation, and
signing stay on the client.

## V1 scope

V1 includes:

- a binary prediction-market covenant that enforces collateral solvency;
- a persistent maker limit-order covenant;
- confirmed chain indexing through either Elements Core RPC or Esplora;
- transaction-atomic, reorg-aware redb persistence; and
- an evidence-first Iroh RPC for hosted and self-hosted nodes.

An LMSR pool is part of the long-term protocol shape but is not implemented in
the first milestone. Until it exists, the protocol exposes best bid, best ask,
spread, and last fill, but no canonical continuous market price.

## Status

The clean-slate v1 alpha is implemented for binary markets and maker limit
orders. It includes the canonical `.simf` covenants, wallet-agnostic PSET
builders, mnemonic-derived order-recovery primitives, confirmed-transaction interpreters,
atomic redb state/history, two-block reorg undo, late-registration backfill,
Elements RPC and Esplora chain sources, evidence queries, advisory routing,
durable subscriptions, and bounded Iroh transport. Finalized Simplicity
execution tests cover every market lifecycle path and both order directions.
The binary-market candidate now uses fixed A/B reissuance-token commitments,
with side inferred from each raw chain output and an exact input-side
reissuance nonce. [ADR 0005](docs/adr/0005-rt-blinding-schedule.md) remains
Proposed while its [acceptance packet](docs/acceptance/binary-market-ab-v1.md)
awaits focused external review and protocol-owner approval. Its exhaustive
dual-side corpus, full-market measurements, live Elements lifecycle, recovery,
restart, and one-/two-block reorg gates are complete.

This is not yet a production release. Serial Elements regtest and public Liquid
testnet shakedowns, operational backup/restore tooling, Nostr announcement
ingestion, browser packaging of the full validator, and an external security
review remain. The Iroh transport itself passes a `wasm32-unknown-unknown`
compile gate; the pinned smplx 0.0.6 runtime currently pulls native regtest
dependencies into `deadcat-client`, so that larger WASM target remains an
upstream-integration task rather than a reason to add HTTP. LMSR is
intentionally deferred. Generated smplx Rust bindings under
`crates/deadcat-contracts/src/artifacts/` are build outputs and are never
committed.

## Development

All builds and CI checks run through the pinned Nix environment:

```sh
nix develop .#default
just ci
```

Before the repository has an initial commit, use `nix develop path:.#default`
so Nix includes the untracked workspace files.

Run against Elements Core:

```sh
just node run \
  --network elements-regtest \
  --policy-asset <asset-id> \
  --baseline-height 0 \
  elements --url http://127.0.0.1:7041 --cookie-file <cookie-path>
```

Or use a lightweight Esplora source:

```sh
just node run \
  --network liquid \
  --policy-asset <asset-id> \
  esplora --url https://<liquid-esplora>/api/
```

The daemon prints its serialized Iroh endpoint address on startup and persists
a stable endpoint secret beside the database. For a new database,
`--baseline-height` is the canonical checkpoint immediately before the block
range the node should scan. Elements-backed nodes report full public market
hint coverage; Esplora-backed nodes support validated manual registration and
report advisory discovery coverage.

Start with:

- [Architecture](docs/architecture.md)
- [V1 protocol](docs/protocol-v1.md)
- [Storage, synchronization, and RPC](docs/storage-sync-rpc.md)
- [Implementation plan](docs/implementation-plan.md)
- [Architecture decisions](docs/adr/README.md)
- [Binary-market A/B acceptance packet](docs/acceptance/binary-market-ab-v1.md)

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
builders, mnemonic-derived order-recovery primitives, confirmed-transaction
interpreters, atomic redb state/history, two-block reorg undo,
late-registration backfill, Elements RPC and Esplora chain sources, evidence
queries, advisory routing, durable subscriptions, and bounded Iroh transport.
Finalized Simplicity execution tests cover every market lifecycle path and both
order directions.
The binary-market candidate now uses fixed A/B reissuance-token commitments,
with side inferred from each raw chain output and an exact input-side
reissuance nonce. [ADR 0005](docs/adr/0005-rt-blinding-schedule.md) remains
Proposed while its [acceptance packet](docs/acceptance/binary-market-ab-v1.md)
awaits focused external review; protocol-owner approval was recorded on
2026-07-14. Its exhaustive
dual-side corpus, full-market measurements, live Elements lifecycle, recovery,
restart, and one-/two-block reorg gates are complete.
The maker-order candidate now has the same live Elements boundary: both order
directions execute partial and full covenant fills, mnemonic-derived Taproot
key cancellation, package registration and historical backfill, independent
client replay, restart, and real alternate-hash one-/two-block reorgs. The gate
also proves the intentional post-resolution split: Elements still accepts a
custom fill while official node routing refuses it.
The mandatory multi-contract liquidregtest gate extends protocol assurance from
isolated covenant lifecycles to composed chain ingestion. One real consensus
transaction advances a market and two maker orders, then is interpreted,
indexed, restarted, reorganized, and independently replayed as one atomic
transaction.

This is not yet a production release. Public Liquid testnet shakedowns,
operational backup/restore tooling, Nostr announcement ingestion, browser
packaging of the full validator, and an external security review remain. Public
operators should currently protect package
registration with `--registration-bearer-token` or an edge rate limiter: the
alpha bounds package size and concurrent verification, but per-peer admission,
a process-wide weighted evidence budget, and a stored-evidence fast path for
identical retries are still deployment hardening work. The Iroh transport
itself passes a `wasm32-unknown-unknown`
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

The focused live-chain gates can be run independently:

```sh
just regtest-market-ab
just regtest-maker-orders
just regtest-multi-contract
```

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
hint coverage; Esplora-backed nodes support chain-validated contract-package
registration and report advisory discovery coverage.

Contract identity and ingestion are deliberately separate. A compact
`ContractId` is the exact creation-anchor outpoint: the initial dormant YES RT
output for a market, or the initial covenant output for a maker order. A
portable `ContractPackage` carries complete untrusted declarations, their
dependency relationships, and the target network/genesis. The receiving node
fetches canonical chain evidence, recompiles and validates every declaration,
and registers the package atomically; the package publisher is never an
authority for contract validity.

Register a package over Iroh with the package object itself (not an RPC
envelope):

```sh
deadcat --endpoint-id <node-endpoint-id> register --file ./package.json
```

The committed
[`register_contract_package` wire fixture](fixtures/wire-v1/register-contract-package-request.json)
shows the exact strict JSON shape; `package.json` is its nested `package` value.
The CLI also accepts compact `TXID:VOUT` syntax for individual `ContractId`
arguments, while RPC JSON always uses `{"txid":"...","vout":n}`.

Start with:

- [Architecture](docs/architecture.md)
- [V1 protocol](docs/protocol-v1.md)
- [Storage, synchronization, and RPC](docs/storage-sync-rpc.md)
- [Implementation plan](docs/implementation-plan.md)
- [Architecture decisions](docs/adr/README.md)
- [Binary-market A/B acceptance packet](docs/acceptance/binary-market-ab-v1.md)
- [Maker-order live acceptance packet](docs/acceptance/maker-orders-v1.md)
- [Multi-contract live acceptance packet](docs/acceptance/multi-contract-v1.md)

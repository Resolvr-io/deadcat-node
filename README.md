# deadcat-node

`deadcat-node` is the authoritative implementation of Deadcat's binary
prediction-market protocol on Liquid. It owns the canonical SimplicityHL
contract, interprets confirmed chain state, indexes that state in redb, and
serves independently verifiable evidence over Iroh.

The node is deliberately not a wallet or trading venue. Keys, wallet discovery,
PSET construction, confidential-transaction blinding, intent validation, venue
selection, and signing stay on the client.

## Current scope

The clean-slate alpha includes:

- one collateral-solvent binary-market covenant;
- wallet-agnostic market creation and transition builders;
- confirmed-chain indexing through Elements Core RPC or Esplora;
- transaction-atomic, reorg-aware redb persistence;
- package registration and historical backfill for one or more markets; and
- an evidence-first, bounded Iroh RPC for hosted and self-hosted nodes.

The earlier on-chain maker-order experiment was removed before any contract
reached testnet or mainnet. Its audit, economics ADR, and live acceptance
packets remain in `docs/` as explicitly marked historical records.

[ADR 0006](docs/adr/0006-rfq-first-liquidity-scope.md) records the RFQ-first
direction: the planned initial venue is a separate noncustodial liquidity
service, with a client-side router responsible for quote validation and
transaction construction. A future AMM or decentralized limit-order book can
implement the same venue boundary. The RFQ service remains separate from
`deadcat-node`; future AMM and DLOB protocols are not implemented by this
repository today.

## Assurance

Generated and direct Simplicity execution tests cover every binary-market
lifecycle path. The mandatory live-chain gates prove:

- the complete binary-market lifecycle on liquidregtest;
- one transaction advancing two independent markets with atomic indexing,
  replay, reorg, reset, and retained-declaration rebuild behavior;
- equivalent state and evidence from the production Elements RPC and Esplora
  backends; and
- the daemon, Iroh transport, and CLI across real process boundaries.

The redb assurance suite additionally drives apply, retry, reopen, rollback,
deep-reorg, and rebuild paths against a deterministic model. Test-only
failpoints require exact pre-state recovery after an aborted mutation and exact
post-state after retry.

V1 activation is immutable per production network. Liquid mainnet begins after
block `3974391` (`705d699f…890c35`) and Liquid testnet begins after block
`2529866` (`78fe3d5c…2f510e`). The daemon derives each production network's
activation checkpoint and policy asset from `--network`; Elements regtest
remains dynamic and requires `--policy-asset`.

This is still an alpha. Public Liquid testnet shakedowns, operational
backup/restore tooling, announcement ingestion, full browser packaging, and an
external security review remain before production use.

## Development

All builds and checks run through the pinned Nix environment:

```sh
nix develop .#default
just ci
```

Focused live-chain gates:

```sh
just regtest-market-ab
just regtest-multi-market
just regtest-backend-equivalence
just regtest-process-boundary
```

Run against Elements Core:

```sh
just node run \
  --network elements-regtest \
  --policy-asset <asset-id> \
  elements --url http://127.0.0.1:7041 --cookie-file <cookie-path>
```

Or use an Esplora source:

```sh
just node run \
  --network liquid \
  esplora --url https://<liquid-esplora>/api/
```

After a fork exceeds the two-block undo window, stop the daemon and rebuild
against a backend for the same chain:

```sh
just node rebuild \
  --database ./deadcat-node-data/store.redb \
  elements --url http://127.0.0.1:7041 --cookie-file <cookie-path>
```

The rebuild verifies stored chain identity before clearing derived chain state,
preserves normalized market declarations and the durable event journal, and
replays complete blocks. Until reset, `RescanRequired` is sticky and
chain-derived RPCs fail closed.

## Contract packages

A `ContractId` is the exact initial dormant YES reissuance-token output of a
market. A portable `ContractPackage` carries one or more complete, untrusted
market declarations plus the target network and genesis hash. The receiving
node fetches canonical chain evidence, recompiles and validates every
declaration, and registers the package atomically; the publisher is never an
authority for contract validity.

Register the nested package object over Iroh:

```sh
deadcat --endpoint-id <node-endpoint-id> register --file ./package.json
```

The committed
[`register_contract_package` fixture](fixtures/wire-v1/register-contract-package-request.json)
shows the strict JSON shape. The CLI also accepts compact `TXID:VOUT` syntax
for individual `ContractId` arguments.

## Documentation

- [Architecture](docs/architecture.md)
- [V1 protocol](docs/protocol-v1.md)
- [Storage, synchronization, and RPC](docs/storage-sync-rpc.md)
- [Liquidity roadmap](docs/liquidity-roadmap.md)
- [Architecture decisions](docs/adr/README.md)
- [Binary-market A/B acceptance packet](docs/acceptance/binary-market-ab-v1.md)
- [Multi-market assurance test](crates/deadcat-client/tests/market_regtest.rs)
- [Elements RPC and Esplora backend-equivalence packet](docs/acceptance/backend-equivalence-v1.md)
- [Daemon/Iroh/CLI process-boundary packet](docs/acceptance/process-boundary-v1.md)
- [Completed v1 alpha implementation record](docs/implementation-plan.md)

Historical maker-order records:

- [Simplicity contract audit](docs/simplicity-contract-audit-2026-07-24.md)
- [Maker-order acceptance packet](docs/acceptance/maker-orders-v1.md)
- [Heterogeneous multi-contract acceptance packet](docs/acceptance/multi-contract-v1.md)
- [ADR 0003: retired order economics](docs/adr/0003-order-economics.md)

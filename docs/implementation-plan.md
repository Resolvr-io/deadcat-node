# V1 implementation plan

Every phase has a test gate. A later phase does not compensate for an ambiguous
or untested covenant invariant in an earlier one.

## Phase 0: Protocol lock and workspace scaffold

- Confirm byte order, key derivation, scalar-reduction behavior, and RT-burn behavior
  by committing the golden vectors required by
  [the protocol specification](protocol-v1.md).
- Create the Rust workspace and `publish = false` internal package boundaries.
- Pin Rust, `simplex`, smplx libraries, Elements Core, and Liquid Electrs in Nix.
- Commit lockfiles, `Simplex.toml`, and the build-time generation workflow;
  git-ignore generated Rust bindings.
- Define versioned RPC envelopes, IDs, cursors, and redb key codecs.
- Commit golden fixtures for the specified Iroh JSON envelopes, little-endian
  length prefix, request/response IDs, unary and subscription framing, frame
  caps, and strict unknown-version/field behavior.
- Add empty native and WASM connectivity smoke tests.

Gate: a clean checkout regenerates bindings with the pinned CLI and runs the
same formatting, linting, golden-vector, unit, and smoke checks locally and in
CI through Nix. CI fails if the CLI and Rust smplx pins differ.

## Phase 1: Binary market covenant

- Implement the fresh `.simf` contract and build-generated Rust binding.
- Implement typed parameters, slot scripts, oracle messages, fixed A/B RT
  construction with raw-`TxOut` side inference, interpreter, and local PSET
  builders.
- Commit fixed CMR, script/address, recovery-hint, issuance, and oracle vectors.

Gate: every issuance, cancellation, resolution, redemption, expiry, and dormant
terminal path passes pure, interpreter, BitMachine, and serial regtest tests.
Negative tests cover sibling substitution, wrong assets, collateral mismatch,
parasitic issuance, oracle domain/outcome, RT burns, side flips and nonces,
overflow, and output-window aliasing.

## Phase 2: Maker limit-order covenant

- Implement exact `u32` price and one `u32 min_active_base`.
- Implement positional maker payment and witness-selected remainder.
- Implement permissionless script-spend fill and maker-only key-spend cancel.
- Implement owner recovery derivation and public announcement verification.

Gate: SellBase and SellQuote full, partial, batched, minimum-boundary, overflow,
cancel, recovery, and post-resolution ingestion tests pass. Differential tests
run the same cases through the Simplicity program and Rust interpreter.

## Phase 3: Interpreter and redb

- Implement heterogeneous contract envelopes and raw transaction interpretation.
- Implement the redb tables, stable key codecs, materialized state, indexes,
  histories, late-registration backfill, undo, and epoch-qualified durable
  events.
- Add an in-memory reference model for randomized comparison.

Gate: injected failure at every mutation boundary leaves no partial state;
retries are idempotent; multiple same-block transitions retain order; and a
handcrafted transaction can atomically advance a market and several orders.
Late historical registration reproduces the same state, including a
same-block creation and spend, before the contract becomes routable.

## Phase 4: Central synchronization and chain backends

- Implement the chain-ordered coordinator.
- Implement Elements Core RPC and Esplora adapters against one compliance suite.
- Implement manual/Nostr registration, catch-up, restart, and readiness.
- Implement activation-anchor-to-tip market hint scanning and explicit
  discovery-coverage reporting.

Gate: backend fixtures produce identical state; restarts at every block boundary
are safe; one- and two-block reorgs recover; a deeper fork enters
`RescanRequired` and rebuilds; same-block create/spend transitions work; and a
source branch change during block fetch restarts from a pinned anchor. An
archival Elements backend recovers every canonical hinted market in the fixture
chain with no Nostr or manual seed data.

## Phase 5: RPC, Iroh, and client validation

- Implement evidence snapshots, histories, raw transactions, and lookup APIs.
- Implement paginated recovery-hint candidate export for local mnemonic
  filtering.
- Implement durable filtered subscriptions and reconnection.
- Implement local native/WASM replay, routing, PSET construction, and intent
  inspection.
- Add resource caps, timeouts, pagination, authentication options, and relay.

Gate: golden wire fixtures round-trip cross-target; snapshot-to-live delivery has
no gap; malformed or malicious parameter/script responses fail client-side;
filtered reconnect across rollback is gapless; pagination invalidated by a tip
change fails explicitly; and browser Iroh connectivity works with the pinned
dependency set.

## Phase 6: End-to-end hardening

- Exercise creation and every lifecycle operation through the official client.
- Run both chain backends against serial regtest.
- Test backup/reopen, rescan, rate limits, backpressure, and stalled backends.
- Perform manual Liquid testnet shakedowns.

Gate: custom transactions not produced by official builders confirm, index,
survive restart/reorg, and reproduce identical client-verified state. No node
API requires wallet secrets or unblinded wallet state. Backup restore and deep
rescan rotate the event epoch, and an old or ahead-of-server cursor fails
loudly rather than being reused.

## Development commands

The scaffold will expose one source of truth:

```text
nix develop .#default
just ci
nix flake check
```

Fast tests run in parallel. Regtest suites use isolated ports or explicit
serialization. A clean Cargo build inside the Nix environment invokes the
pinned `simplex` compiler and writes bindings to a crate-local git-ignored
directory. Shipped binaries have no runtime compiler dependency. Committed CMR,
script, recovery, and wire vectors fail when source/compiler behavior drifts.

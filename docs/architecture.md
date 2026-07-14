# Deadcat node architecture

## Purpose

`deadcat-node` is a shared-safe Deadcat chain index and evidence service. It is
the authoritative source repository for canonical contract implementations, but
runtime clients do not trust a remote node with keys, wallet state, transaction
construction, or contract semantics.

The first release tracks binary markets and maker orders. LMSR types are
reserved in versioned enums and capability negotiation without an implementation.

## Workspace shape

The intended workspace is:

```text
deadcat-types       internal canonical IDs, domain types, and fixed codecs
deadcat-contracts   canonical .simf, build-generated bindings,
                    parameters, interpreters, builders, and committed vectors
deadcat-client      local evidence replay, routing, PSET construction,
                    native/WASM-facing API
deadcat-rpc         transport-independent versioned DTOs and cursors
deadcat-iroh        bounded Iroh client/server framing
deadcat-node        chain coordinator, redb, discovery, backends,
                    and advisory route suggestions
deadcat-cli         operator and end-to-end client workflows
```

The contracts and client crates are internal implementation boundaries and may
be marked `publish = false`. There is no commitment to a generic public
`deadcat-core` library.

## Contract generation

Canonical `.simf` sources, `Simplex.toml`, `build.rs`, lockfiles, and golden
CMR/script/recovery vectors are committed. Generated Rust bindings live in a
crate-local ignored directory and are recreated by `simplex build` during a
clean Cargo build. Nix supplies the compiler, and CI verifies that its exact
smplx release/revision matches the Rust smplx libraries before generation.
Generated bindings are never hand-edited and shipped binaries do not need the
compiler at runtime.

## Runtime boundaries

### Client

The client owns:

- canonical contract templates pinned to a protocol release;
- verification of creation parameters, CMRs, scripts, and asset relationships;
- replay of raw transition evidence;
- parent-market freshness preflight for every trade;
- local order-book routing and verification of advisory route suggestions;
- wallet discovery, coin selection, and fee bounds;
- PSET construction, deterministic Deadcat pre-blinding, wallet-output
  blinding, inspection, and signing; and
- choice of one or more broadcasters.

The official client never compiles arbitrary SimplicityHL supplied by a node.

### Node

The node owns:

- candidate discovery from read-only Nostr and manual registration;
- canonical contract recompilation and chain verification;
- complete-block, transaction-ordered ingestion;
- materialized current state, indexes, raw transition evidence, and history;
- durable cursored subscriptions;
- sync/readiness reporting; and
- optional fee estimation, route suggestions, and signed-transaction relay.

The node has no wallet RPC. In particular it does not accept descriptors,
wallet scripts, unblinded wallet inputs, blinding factors, or unsigned PSET
construction requests.

## Evidence flow

Every derived state response is anchored to an exact chain and index position:

```text
network + genesis hash
source tip { height, hash }
indexed tip { height, hash }
sync status
contract synced_to
state hash
raw creation/transition references
```

A client can re-fetch raw transactions, compile the relevant canonical
contract, and replay the transition sequence. This detects fabricated derived
state and contract-inconsistent evidence. Against a single remote node it does
not establish that the supplied chain view is canonical, current, or complete,
so clients may compare another node or a local Elements backend.

## Chain sources

One internal `ChainSource` abstraction is implemented by:

- `ElementsRpcChainSource`, using a locally validating `elementsd`;
- `EsploraChainSource`, using a public, private, or OAuth-authenticated
  Esplora endpoint.

The interface must provide the current tip, block hashes and complete ordered
blocks, raw transactions, outspends, issuance-origin lookup, script discovery,
fee estimates, and optional broadcast. Both implementations pass the same
backend compliance suite.

The hosted production service should use its own Elements Core backend. Esplora
is the low-operations option for ordinary self-hosting and development.

Full public market recovery is a separate backend capability. With archival
Elements Core, the node scans complete blocks from the v1 activation anchor,
parses market hints, derives issuance assets, recompiles the market, verifies
the dormant RT outputs, and follows the resulting lineage. Esplora can provide
the same result only when raw historical blocks are available; standard Esplora
has no query for all OP_RETURNs matching a prefix, so a global scan is expensive.

## Discovery

Nostr events and manual RPC calls are advisory locators. Registration performs:

1. canonical field and version validation;
2. raw creation-transaction retrieval;
3. parent-market verification for child contracts;
4. contract compilation and script matching;
5. asset/issuance relationship validation; and
6. one atomic store transaction for metadata, scripts, indexes, and starting
   outpoints.

For a binary market, step 5 is a critical solvency check. The node and client
independently require each uniquely derived issuance to have a null initial
outcome-token amount and a one-unit RT amount fully accounted for by the exact
one-unit side-A commitment locked at its compiled dormant script. On a
consensus-valid Elements transaction, this proves that no creator-retained
spendable RT authority exists; accepting a script match without that creation
proof could admit outcome tokens reissued outside the collateral covenant. The
protocol specification defines the complete creation invariant.

That proof is relative to the supplied canonical chain evidence. Elements Core
mode validates the chain locally; an Esplora-backed node and a client using a
remote node retain the stale, incomplete, or false-chain-view risks described
in [ADR 0001](adr/0001-authority-and-shared-node.md). Contract-semantic replay
does not by itself prove that one remote source supplied the current canonical
Liquid chain.

Market recovery hints are publicly reconstructible. Order recovery hints are
mnemonic recovery aids for the maker; a public node needs the full announced or
manually registered order parameters before it can compile and verify an order.
The node nevertheless indexes raw, length-valid order hints so a client can
download candidates and test ownership locally without revealing its mnemonic
or derived keys.

## Transport and operations

Iroh is the only v1 application transport:

- ALPN `deadcat/1`;
- UTF-8 JSON frames encoded as `[u32 little-endian length][JSON bytes]`;
- explicit `{ schema_version: u32, request_id: u64, ... }` request and
  response envelopes, with the response echoing the request ID;
- one bidirectional QUIC stream per request: unary replies send one response
  and finish, while subscriptions send an acknowledgement followed by durable
  event envelopes;
- hard failure for unknown versions, variants, and fields rather than partial
  interpretation;
- a 16 MiB per-frame limit, incremental reads, and a 32 MiB process-wide
  inbound-byte semaphore so concurrent length prefixes cannot multiply memory
  without bound;
- stable server EndpointId and authenticated encryption;
- connection, stream, request, and idle limits;
- pagination for growing collections; and
- graceful shutdown with completed-task reaping.

The first scaffold includes a browser/WASM connection spike using the exact
pinned Iroh version. A transport failure requires a new decision record rather
than silently adding a public HTTP API.

Shared deployments expose public reads. Registration, expensive historical
work, and broadcast receive method-specific quotas and optional capabilities.
Iroh client identities are not treated as durable anti-Sybil identities.

Structured tracing includes chain-source latency, indexed lag, redb commit
latency, transitions by kind, RPC latency/errors, and subscription backpressure.
`GetInfo` is the protocol health and readiness endpoint.

## Security consequences

A malicious hosted node cannot make the official client sign a transaction that
violates its locally displayed and validated spend intent. It can still omit
data, show stale-but-valid state, reduce best execution, censor relay, and learn
query timing. Self-hosting and independent cross-checks reduce that residual
trust.

Post-resolution order risk is especially important: an independent order
remains covenant-fillable after its market terminates. Every trade snapshot
therefore includes the parent market even when the transaction will not spend
it. This is a client safety preflight, not a consensus guarantee.

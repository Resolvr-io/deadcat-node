# Deadcat node architecture

## Purpose

`deadcat-node` is a shared-safe binary-market chain index and evidence service.
This repository is authoritative for the canonical SimplicityHL market
implementation, but runtime clients do not trust a remote node with keys,
wallet state, transaction construction, contract semantics, or venue selection.

Trading venues are separate systems. The initial direction is a noncustodial
RFQ service; future AMM and DLOB venues can sit behind the same client-side
router boundary without becoming node RPC methods.

## Workspace shape

```text
deadcat-types       canonical IDs, domain types, and fixed codecs
deadcat-contracts   canonical .simf, generated bindings, economics,
                    interpretation, recovery, and committed vectors
deadcat-client      local evidence replay and market PSET construction
deadcat-rpc         transport-independent versioned DTOs and cursors
deadcat-iroh        bounded Iroh client/server framing
deadcat-node        chain coordinator, redb, discovery, and backends
deadcat-cli         operator and end-to-end client workflows
```

The package and multi-instance machinery is generic even though
`BinaryMarketV1` is currently the only supported contract family.

## Contract generation

Canonical `.simf` sources, `Simplex.toml`, `build.rs`, lockfiles, and golden
CMR/script/recovery vectors are committed. Generated Rust bindings are
crate-local ignored build outputs recreated by `simplex build`. Nix supplies
the compiler, and CI verifies that the exact smplx release matches the Rust
libraries before generation. Shipped binaries do not need the compiler.

## Runtime boundaries

### Client

The client owns:

- canonical market templates pinned to a protocol release;
- verification of creation parameters, CMRs, scripts, and asset relationships;
- replay of raw creation and transition evidence;
- wallet discovery, coin selection, and fee bounds;
- market PSET construction, deterministic reissuance-token blinding,
  wallet-output blinding, inspection, and signing;
- RFQ/AMM/DLOB venue queries and route selection; and
- choice of one or more broadcasters.

The official client never compiles arbitrary SimplicityHL supplied by a node.
Venue code must not treat node-derived state as quote authorization.

### Node

The node owns:

- public market-hint discovery plus ingestion of untrusted packages;
- canonical market recompilation and chain verification;
- complete-block, transaction-ordered ingestion;
- materialized state, indexes, raw evidence, and history;
- durable cursored subscriptions;
- synchronization and readiness reporting; and
- optional fee estimation and signed-transaction relay.

The node has no wallet RPC and no trading API. It does not accept wallet
descriptors, wallet scripts, unblinded inputs, blinding factors, quote
requests, routes, or unsigned-PSET construction requests.

## Evidence flow

Every derived response is anchored to an exact chain and index position:

```text
network + genesis hash
source tip { height, hash }
indexed tip { height, hash }
sync status
contract synced_to
raw creation/transition references
```

A client can fetch raw transactions, compile the canonical market, and replay
the transition sequence. This detects fabricated derived state and
contract-inconsistent evidence. Against one remote node it does not establish
that the supplied chain view is current, canonical, or complete, so a client
may compare another node or local Elements backend. The independent check must
authenticate the complete consensus transaction at its reported block
position, including witnesses: an Elements `txid` does not commit to witness
data, while Deadcat interpretation does.

## Identity and portable ingestion

```text
ContractId          exact market creation-anchor outpoint
ContractDescriptor  complete public semantics needed to compile a market
ContractDeclaration untrusted ContractId-plus-descriptor claim
ContractPackage     chain-bound roots plus declarations
```

`ContractId` is a nominal newtype around `elements::OutPoint`. A market uses
its initial dormant YES reissuance-token output as its anchor. An anchor alone
says nothing about alleged semantics; the declaration supplies semantics and
canonical chain verification proves or rejects the claim.

Package format v1 binds one to 16 roots and at most 64 declarations to an exact
Liquid network and genesis. Duplicate roots or IDs, missing root declarations,
and declarations not named as roots are rejected before expensive chain work.
Independent market declarations may share one creation transaction and are
still verified and committed atomically.

Registration:

1. validates package bounds, network/genesis, activation boundary, and roots;
2. fetches each shared confirmed creation transaction at most once;
3. compiles every declared market and verifies its exact anchor;
4. validates issuance, commitments, scripts, values, and recovery data; and
5. commits all declarations, evidence, indexes, and starting outpoints once.

If any declaration fails, none is registered. An identical retry is
idempotent. Normalized declarations form a non-chain-derived watch registry
that survives destructive rebuild so retained markets can be replayed on the
replacement branch.

## Chain sources and discovery

The internal `ChainSource` abstraction has two production implementations:

- `ElementsRpcChainSource`, backed by a locally validating `elementsd`;
- `EsploraChainSource`, backed by a public or private Esplora endpoint.

Both provide tip and block data, raw transactions, outspends, issuance-origin
lookup, script history, fee estimates, and optional broadcast, and both pass
the same backend-equivalence gate.

With archival Elements Core, the node scans complete blocks strictly after the
exclusive v1 activation anchor, parses public market hints, derives issuance
assets, recompiles markets, verifies dormant outputs, and follows their
lineages. Standard Esplora cannot globally query every matching OP_RETURN, so
Esplora-backed discovery relies on portable package registration unless the
deployment provides equivalent historical scanning.

The critical creation proof requires each defining issuance to create no
outcome-token amount and exactly one reissuance token, fully accounted for by
the expected side-A commitment at the compiled dormant script. A script match
without this proof could admit outcome tokens reissued outside the collateral
covenant.

## Persistence and reorgs

Blocks are interpreted in transaction order and committed atomically. All
markets affected by one transaction share one evidence record and either
advance together or not at all. The store retains enough undo data for the
supported shallow reorg window. A deeper fork enters sticky `RescanRequired`;
chain-derived reads fail closed until the operator verifies chain identity,
resets derived materialization, and replays from the immutable activation
checkpoint.

## Transport and operations

Iroh is the only v1 application transport:

- ALPN `deadcat/1`;
- UTF-8 JSON frames encoded as `[u32 little-endian length][JSON bytes]`;
- strict versioned request/response envelopes;
- one bidirectional QUIC stream per request;
- hard failure for unknown variants and fields;
- bounded per-frame and process-wide inbound memory;
- stable authenticated endpoint identity;
- pagination for growing collections; and
- graceful shutdown with task reaping.

Shared deployments expose public reads. Registration, historical evidence, and
broadcast receive method-specific bounds and optional authorization.

## Security consequences

A malicious hosted node cannot make the official client sign a transaction
that violates locally reconstructed market semantics and spend intent. It can
still omit data, show stale-but-valid state, censor relay, and learn query
timing. Self-hosting and independent cross-checks reduce that residual trust.

RFQ providers and future venues have a separate trust boundary: their quotes
may expire or become unfillable, but settlement remains noncustodial and the
client must verify the final atomic Liquid transaction before signing.

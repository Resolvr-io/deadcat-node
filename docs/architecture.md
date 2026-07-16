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

- hint discovery plus ingestion of untrusted declarations and packages from
  read-only Nostr and manual registration;
- canonical contract recompilation and chain verification;
- complete-block, transaction-ordered ingestion;
- materialized current state, indexes, raw transition evidence, and history;
- durable cursored subscriptions;
- sync/readiness reporting; and
- optional fee estimation, route suggestions, and signed-transaction relay.

The node has no wallet RPC. In particular it does not accept wallet
descriptors, wallet scripts, unblinded wallet inputs, blinding factors, or
unsigned PSET construction requests. A Deadcat `ContractDescriptor` is public
contract semantics for chain verification, not a wallet descriptor.

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
so clients may compare another node or a local Elements backend. That
independent comparison authenticates the complete consensus transaction at its
reported block position, including input and output witnesses: an Elements
`txid` excludes witness data, while Deadcat transition interpretation depends on
the Simplicity/Taproot witness.

## Identity and portable ingestion

These types have intentionally separate responsibilities:

```text
ContractId          exact creation-anchor outpoint; stable instance identity
ContractDescriptor  complete public semantics needed to compile a family
ContractDeclaration untrusted ContractId-plus-descriptor claim
ContractPackage     chain-bound roots plus declarations/dependencies
```

`ContractId` is a nominal newtype around `elements::OutPoint`, not a semantic
hash. A market uses its initial dormant YES RT output as its anchor; a maker
order uses its initial order output. The nominated output index distinguishes
multiple or identical contracts created in one transaction. A CMR identifies a
Simplicity program commitment, not an instance: it omits off-leaf Taproot data
such as the maker cancellation key and cannot distinguish identical outputs.
Conversely, an anchor alone says nothing about the alleged contract semantics.
The declaration supplies those semantics, and canonical chain verification
proves whether the claim is true.

Ordinary UTXO references use `elements::OutPoint` throughout the internal chain
and transaction APIs. `ContractId` exists only to prevent confusing an
arbitrary current/wallet outpoint with a canonical creation anchor. Explicit
wire and redb codecs preserve protocol stability without introducing a second
generic project-specific outpoint, converting through Bitcoin's distinct txid
type, or coupling the protocol to LWK.

Package format v1 binds declarations to the exact Liquid network and genesis,
names one through 16 declared roots, and carries at most 64 declarations. It
rejects duplicate roots/IDs, self-dependencies, missing root declarations, and
declarations unrelated to a root. A maker's parent market must be included in
the dependency closure or already verified by the node; package order is not
trusted. These bounds apply before expensive chain work.

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

`ChainIdentity` stores the selected network, genesis hash, and native policy
asset. Liquid and Liquid testnet policy assets are compiled network constants,
not operator-selected configuration. The CLI derives them when omitted and
rejects a conflicting override before database creation; Elements regtest
requires an explicit asset because its chain parameters are dynamic. The store
rechecks this invariant before opening its initialization write transaction,
and the RPC handler rechecks persisted identity before exposing any capability.
Consequently an embedder or malformed legacy database cannot advertise
`FullHintScan` while interpreting contracts against the wrong production
collateral asset.

Full public market recovery is a separate backend capability. With archival
Elements Core, the node scans complete blocks strictly after the exclusive v1
activation anchor,
parses market hints, derives issuance assets, recompiles the market, verifies
the dormant RT outputs, and follows the resulting lineage. Esplora can provide
the same result only when raw historical blocks are available; standard Esplora
has no query for all OP_RETURNs matching a prefix, so a global scan is expensive.

## Discovery

Nostr events and manual RPC calls carry untrusted `ContractPackage` values.
Registration performs:

1. package format, bounds, exact network/genesis, activation-height boundary,
   roots, and dependency-graph validation;
2. confirmed raw creation-transaction retrieval from the node's own chain
   source, with each shared transaction fetched at most once;
3. parent-market verification before child contracts, independent of supplied
   declaration order;
4. canonical contract compilation and exact anchor/script matching;
5. asset, issuance, value, and family-specific creation validation; and
6. after all declarations pass, one atomic store transaction for every
   contract's metadata, scripts, indexes, evidence, starting outpoints, and
   normalized durable declaration.

The sender is not an attesting authority. If any declaration fails, none of the
package is registered; an identical retry is idempotent. Package roots identify
the requested contracts, while included non-roots supply their dependency
closure. A dependency omitted from the package must already be verified in the
same node.

Idempotence here describes state, not a zero-cost request. The alpha verifier
still retrieves and checks evidence before recognizing an identical retry.
Hosted public operators must enable the registration bearer token or enforce an
equivalent edge rate limit. Per-peer admission, a process-wide weighted
evidence budget, and a canonical stored-evidence fast path remain explicit
availability hardening before a production release; this does not weaken the
atomic or chain-verifiable registration boundary.

Normalized declarations form a non-chain-derived watch registry. Materialized
records and their live outpoints are still discarded on a destructive rebuild;
the registry survives so replay from the persisted immutable v1 activation
checkpoint can verify retained markets before their retained maker children
against the exact replacement-branch transactions. Registration rejects
creation at or before that checkpoint, so the replay boundary cannot omit a
supported v1 contract. A declaration that is absent or invalid on the
replacement branch remains dormant and cannot prevent unrelated canonical
synchronization.

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

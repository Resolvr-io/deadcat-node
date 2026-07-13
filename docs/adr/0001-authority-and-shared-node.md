# ADR 0001: Repository authority and shared-node trust model

- Status: Accepted
- Date: 2026-07-12

## Context

Deadcat clients may use a hosted node or run the same node themselves. A hosted
operator is useful for users who do not want the operational burden of indexing
Liquid, but must not become a custodian or a source of transaction-signing
authority.

Earlier Deadcat design material described a reusable public core library and a
wallet-oriented runtime. That is not the product boundary selected for this
repository.

## Decision

This repository owns the canonical Deadcat contract sources, generator
configuration and pins, parameter encodings, golden vectors, transition
semantics, and node implementation. Generated Rust bindings are reproducible
build products and are not committed.
Internal crate boundaries may share pure code between the official node and
client, but they do not promise a stable public "implement your own node" API.

The same node protocol is used for hosted and self-hosted operation. It is
designed as though the operator may be remote and untrusted.

The node:

- discovers and registers candidate contracts;
- verifies canonical parameters against raw creation transactions;
- follows confirmed chain state;
- stores current state and ordered transition evidence;
- serves snapshots, histories, subscriptions, and raw transactions;
- provides advisory fee estimates and optional route suggestions; and
- may relay a fully signed transaction.

The node never receives wallet seeds, xpubs, descriptors, private keys,
blinding secrets, the wallet's complete script set, or unblinded wallet UTXOs.
It does not construct a PSET that a user is expected to sign.

The client:

- ships version-pinned canonical Deadcat contract templates;
- recompiles parameters and verifies CMRs and script pubkeys;
- replays raw transitions into typed state;
- verifies oracle signatures and asset relationships;
- selects routes and wallet inputs;
- constructs, blinds, inspects, and signs PSETs locally; and
- can relay through the node or an independent broadcaster.

The node may return a candidate route, but it is advisory. The client verifies
the route's inputs, outputs, assets, amounts, fees, change, contract witnesses,
and accepted slippage before signing.

## Residual hosted-node trust

Local validation removes custody and contract-semantics trust. It cannot prove
that a single server supplied a complete or current view of the chain.

A hosted node can still:

- serve an old but internally valid tip;
- omit a resolution, cancellation, fill, order, or better liquidity source;
- provide a suboptimal route or inflated fee estimate;
- withhold transaction relay; or
- learn which markets a client queries and when it broadcasts.

Every state response therefore carries the Liquid network and genesis hash, the
backend tip, the Deadcat indexed tip, the contract's `synced_to` position, and
raw evidence references. Clients can compare another node or chain source.
Self-hosting with a local Elements Core backend is the maximum-verification
mode.

Merkle inclusion proves that a transaction was included. It does not prove that
the claimed tip is current, that an outpoint remains unspent, or that the server
did not omit a later transaction.

## Chain backends

The node has one internal chain-source interface with two first-class adapters:

- Elements Core RPC: preferred for the hosted production service and for
  maximum-security self-hosting;
- Esplora: the lightweight option, supporting both unauthenticated and OAuth
  endpoints.

Both adapters must pass the same ordering, discovery, reorg, and restart
compliance suite.

## Discovery and transport

Manual registration and read-only Nostr ingestion supply candidate parameters
and creation-transaction references. Neither is authoritative. The node fetches
the chain data, compiles the canonical contract version, and compares the
resulting scripts before tracking it.

Iroh is the only v1 application transport. It uses a versioned ALPN, bounded
length-delimited messages, a stable server identity, connection and stream
limits, timeouts, and durable subscription cursors. Browser/WASM compatibility
with the pinned Iroh release is an early implementation spike. No public HTTP
API is part of v1.

## Consequences

- The official client needs an internal native/WASM verification and builder
  component from this repository.
- Hosted and self-hosted clients exercise the same security-critical path.
- The protocol is evidence-first rather than an opaque derived-data API.
- Shared deployments require global resource limits; ephemeral Iroh client IDs
  are not a sufficient anti-Sybil rate-limit identity.

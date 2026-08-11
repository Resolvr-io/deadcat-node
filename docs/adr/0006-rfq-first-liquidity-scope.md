# ADR 0006: RFQ-first production liquidity scope

- Status: Accepted
- Date: 2026-07-29
- Supersedes: ADR 0002's release-scope decision
- Retires as historical: ADR 0003
- Amends: ADR 0001's node-side advisory-routing responsibility
- Implementation status updated: 2026-08-11

## Context

At the time of this decision, the clean-slate alpha implemented both
`BinaryMarketV1` and `MakerOrderV1`. The maker contract supplied a useful
on-chain limit-order experiment and produced valuable contract-composition,
recovery, indexing, and acceptance evidence.

It is not the desired first public trading experience. A standing limit order
is an awkward primary interface for a binary prediction market, while carrying
the maker contract into production would commit the node, client, wire, store,
and user experience to semantics that the project already expects to redesign.

No `MakerOrderV1` instance has ever been created on Liquid mainnet or Liquid
testnet. Deadcat has not had a production deployment, customer balance,
supported public maker output, or compatibility commitment. Existing local
alpha databases, fixtures, generated artifacts, and regtest instances are
development state rather than user assets.

## Decision

### Production contract and liquidity scope

The first public production release supports `BinaryMarketV1` as its only
trading-related on-chain contract family.

ADR 0002's binary-market responsibility, terminal semantics, asset
confidentiality rules, and compatibility policy continue unchanged. This
decision replaces its two-contract release scope, maker-order responsibility,
and premature LMSR reservation.

`MakerOrderV1` is removed in place from the active contract sources and from all
official node, client, store, RPC, CLI, fixture, and CI surfaces. The production
node does not discover, register, interpret, index, route, or provide recovery
for maker orders. An output created later with the published alpha covenant is
an unsupported foreign contract.

The unused `LmsrV1Reserved` wire and capability surface is also removed. A
future AMM or DLOB receives its own design, contract identity, activation
decision, and acceptance boundary only after its requirements are selected.

### RFQ-first execution

Initial liquidity comes from one separate noncustodial RFQ provider using its
own funds and pre-issued YES/NO inventory. Additional providers remain a later
client-routing milestone.

The RFQ provider is a separate process, wallet, database, key domain, and
operational security principal from `deadcat-node`. It may quote, reserve its
own inputs, collaborate on blinding, validate the final transaction, sign its
own inputs, and relay the exact signed transaction. It never accepts customer
deposits, maintains customer balances, or receives general authority over a
customer wallet.

The client remains the user's execution authority. It validates market
evidence, expresses exact-in or exact-out intent, selects the venue, composes
and validates the complete PSET, controls wallet inputs and change, signs only
the approved transaction, and may broadcast through any relay.

An RFQ trade exchanges ordinary Liquid assets between the provider and user. It
does not require a new Simplicity contract or advance the binary-market
covenant on every fill. The provider uses the market covenant separately to
issue and cancel balanced pairs and redeem terminal inventory.

### Compatibility and versioning

There is no maker compatibility period, migration, recovery utility, retained
indexing mode, or feature flag. Removal is a deliberate clean alpha break.

The existing ALPN, RPC schema, contract-package format, and redb schema version
numbers remain unchanged. They identify the first supported production shape,
not every incompatible pre-production revision. Old alpha binaries, clients,
packages, and databases are unsupported after the removal:

- operators delete or rebuild local alpha databases;
- clients and nodes upgrade together;
- fixtures and generated artifacts are regenerated; and
- no code attempts to decode, migrate, or preserve maker records.

Historical ADRs, audits, and acceptance packets remain as dated engineering
evidence. Where active source files are removed, those documents point to an
immutable historical revision or state explicitly that their relative source
links apply only to that revision.

## Consequences

- ADR 0002 no longer defines production contract scope; its retained
  binary-market decisions are carried forward above.
- ADR 0003 is a historical record of the removed maker experiment and does not
  constrain a future DLOB.
- ADR 0001's keyless shared-node trust boundary remains accepted, but the node
  no longer suggests trading routes. Venue discovery and routing are
  client-local responsibilities.
- Maker-specific code and tests were deleted rather than deprecated in
  [PR #16](https://github.com/Resolvr-io/deadcat-node/pull/16).
- Generic atomic indexing, restart, reorg, rebuild, and composition guarantees
  received market-only replacements in
  [PR #15](https://github.com/Resolvr-io/deadcat-node/pull/15) before the maker
  fixtures were removed.
- Removing maker code does not relax the requirement that binary-market replay
  exactly match the covenant's expiry semantics, including transaction-global
  locktime activation and height-versus-time classification.
- The first RFQ milestone is a one-provider, one-leg confidential settlement.
  Multi-provider signing, AMM/DLOB contracts, and split routing remain deferred.

## Follow-up

1. **Completed in PR #15:** replace maker-dependent generic assurance fixtures
   with market-only equivalents.
2. **Completed in PR #16:** remove `MakerOrderV1` through every active code,
   storage, wire, CLI, fixture, test, and normative-document surface without
   changing version constants.
3. **Completed in PR #25:** prove a two-wallet confidential RFQ settlement on
   liquidregtest before freezing a remote RFQ protocol.
4. **Completed in PR #26 as a provisional client-local API:** add exact-in/exact-out
   aggregate intent, exact per-leg allocation, authenticated proposal binding,
   route-owned transaction composition, and no remote wire format.
5. **Provider core implemented under ADR 0007:** complete the separate wallet,
   quoting, transaction-validation, signer, relay, and remote-service layers.
6. Add production-shaped process, crash-recovery, mutation, reorg, and
   operational acceptance gates.

# Maker-order v1 live acceptance packet

Status: Complete for the local Elements protocol gate.

This packet records the production-shaped boundary for the v1 maker-order
covenant. It complements the pure Rust, generated Simplicity, interpreter,
store, RPC, and deterministic integration tests with transactions accepted by
an isolated `elementsd` liquidregtest chain.

## Accepted live lifecycle

One real binary market issues explicit YES and NO tokens. A fixed mnemonic then
derives four orders that are created together in one transaction at distinct
anchor outpoints:

| Index | Side | Direction | Live result |
|---:|---|---|---|
| 0 | YES | SellBase | Partial fill, then full fill |
| 1 | NO | SellQuote | Partial fill, then full fill |
| 2 | NO | SellBase | Maker-only Taproot key-path cancellation |
| 3 | YES | SellBase | Full custom fill after parent resolution |

Every accepted transaction passes `testmempoolaccept`, is broadcast, mined,
and confirmed. Partial continuations preserve the exact covenant script and
minimum capacity; both positive partial fills execute exactly at
`min_active_base`. Full fills have no tracked continuation. The cancellation is
signed with the mnemonic-derived maker key after applying the Elements Taproot
tweak for the exact compiled one-leaf tree and uses an Elements key-spend
sighash over all prevouts and the actual genesis hash.

The following balance-preserving invalid transactions are rejected by
`elementsd`:

- wrong exact maker payment;
- wrong maker receive script;
- an otherwise balanced fill below `min_active_base`;
- wrong SellQuote remainder amount;
- wrong continuation script; and
- cancellation signed by the untweaked maker key.

## Recovery and ingestion

The live creation transaction contains all four canonical 43-byte mnemonic
recovery hints. Recovery verifies the policy-asset zero-value envelope, unmasks
the candidate `u16` index locally, rederives the order, recompiles the exact
script, locates the unique explicit held-asset output, infers base capacity from
its chain value (including exact SellQuote divisibility), and rebuilds the
complete creation output. A foreign mnemonic still produces a candidate index
but matches no compiled output.

The same confirmed chain is processed through the production
`ElementsRpcChainSource`, `DeadcatInterpreter`, `SyncCoordinator`, and redb
`Store`. The parent market is discovered from its public market hint. A
market-plus-four-orders `ContractPackage` is then verified against live chain
evidence; the parent registration is idempotent and all maker declarations are
late-registered and historically backfilled. Maker hints deliberately retain
`associated_contract = None`: ownership association remains a client-local
mnemonic and exact-script test.

RPC contract views, complete histories, and raw transaction evidence are
replayed independently by `deadcat-client` against full transactions fetched
from canonical blocks. This compares witnesses as well as transaction IDs.
All states and histories survive closing and reopening redb, an idempotent sync,
and an idempotent package retry.

## Parent resolution and reorgs

After oracle resolution, production routing returns
`CovenantInvariantViolation` for the still-active order. The independently
composed fill nevertheless passes Elements consensus, is mined, and is indexed.
This is the intentional throughput trade-off: maker covenants do not co-spend
the parent singleton.

The harness then creates genuine alternate-hash branches with the regtest
`generateblock` RPC:

1. the resolution and post-resolution fill blocks are invalidated and replaced
   at the same heights, exercising a two-block rollback and replay; and
2. the fill block is replaced with an empty block, exercising a one-block
   rollback that leaves the parent resolved and order active; routing still
   refuses it, after which the custom fill is mined one block later.

The final state and independently replayed evidence reference only the
canonical replacement branch.

## Required commands

Run the focused gate:

```sh
nix develop .#default --command just regtest-maker-orders
```

Run every required local/CI gate:

```sh
nix develop .#default --command just ci
```

`.github/workflows/ci.yml` invokes `just regtest`, which includes the
binary-market A/B, maker-order, and multi-contract live suites. The test is
ignored only for ordinary `cargo test`; it is mandatory in CI.

## Deliberate boundaries

This gate uses the production Elements RPC backend. Backend compliance tests
cover Esplora separately. Iroh framing/transport is also covered separately;
the live test calls the production request handler directly so network timing
cannot weaken protocol assurance. A polished production cancellation composer
is not introduced here because destination, fee, and wallet-selection policy
belong to wallet UX; the test uses the existing public key and compilation
primitives to prove the consensus path directly.

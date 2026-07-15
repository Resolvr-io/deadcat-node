# Multi-contract v1 live acceptance packet

Status: Complete for the local Elements protocol gate; mandatory in CI.

This packet records the production-shaped acceptance boundary for one
transaction advancing heterogeneous Deadcat contracts. It supplements the
deterministic interpreter and redb atomicity fixtures with a real transaction
accepted and mined by an isolated `elementsd` liquidregtest chain. It introduces
no new market or maker-order consensus rule.

The gate is implemented by
`multi_contract_transaction_is_accepted_and_indexed_by_elementsd` in
`crates/deadcat-client/tests/market_regtest.rs`.

## Composed transaction

The fixture starts with one binary market in `Trading` state with 30 outstanding
pairs and 6,000 collateral units, one active YES/SellBase order with capacity
10, and one active NO/SellQuote order with capacity 10. A single six-input,
ten-output transaction performs all three covenant transitions:

| Contract | Action | Live result |
|---|---|---|
| Binary market | Subsequent `Issue { pairs: 10 }` | `Trading(30)` becomes `Trading(40)`, collateral becomes 8,000, and both RTs flip from side B to side A |
| YES/SellBase maker order | Partial fill of 3 at price 7 | Capacity becomes 7, total filled becomes 3, and the maker receives 21 quote units |
| NO/SellQuote maker order | Full fill of 10 at price 7 | The order becomes `Consumed` and the maker receives 10 NO units |

The exact output layout is part of the test fixture:

| Vout | Output |
|---:|---|
| 0-1 | The two continued market RT outputs on side A |
| 2 | The continued market collateral output with value 8,000 |
| 3 | The SellBase maker payment with value 21 quote units |
| 4 | The SellQuote maker payment with value 10 NO units |
| 5 | The SellBase continuation with value 7 YES units |
| 6 | Wallet change with value 13 YES units |
| 7 | Wallet change with value 49 quote units |
| 8 | Funding change with value 97,000 quote units |
| 9 | Explicit policy-asset fee with value 1,000 |

The valid transaction passes `testmempoolaccept`, is broadcast, mined, and read
back from its canonical block. A balance-preserving negative changes only the
SellQuote maker receive script at vout 4; Elements rejects the entire
transaction, demonstrating that an otherwise valid sibling transition cannot
hide one invalid covenant leg.

## Atomic node and client evidence

A chain-verified `ContractPackage` registers only the two maker-order roots and
their binary-market parent. Historical backfill reproduces the exact three
pre-transaction states before the composed transaction becomes visible.

After confirmation, one production `DeadcatInterpreter` pass returns all three
affected contract IDs. One redb commit updates together:

- the market's outstanding-pair count, collateral, and RT live outpoints;
- both maker states, the surviving SellBase outpoint, and the consumed
  SellQuote order;
- the order-book rows, leaving only the partial SellBase continuation ready;
- one history position per contract, all referring to the same transaction and
  chain position;
- one stored evidence record containing the exact full consensus transaction
  and all three affected IDs; and
- one durable transaction event naming all three contracts and their parent
  market.

The resulting committed view exposes no prefix of the transition. Closing and
reopening redb preserves the same state, and an immediate synchronization after
restart performs zero new work.

RPC contract views, histories, and raw transaction evidence for all three
contracts are independently replayed by `deadcat-client` against the full
transaction fetched from its canonical block. Equality includes witness data,
not only the transaction ID.

## Reorg boundary

The harness exercises genuine alternate-hash branches through regtest RPC:

1. a two-block replacement moves the composed transaction from height `H` to
   `H + 1`; all three contracts remain in their exact post-transaction states,
   and the composed history/evidence position for every affected contract moves
   together; and
2. a one-block empty replacement removes the composed transaction and restores
   all three pre-transaction states, live outpoints, histories, and order-book
   rows atomically. Mining the transaction again at `H + 2` restores all
   three post-transaction states together.

No orphaned position is returned as canonical evidence after either
replacement. Durable subscription events name the exact affected contracts and
market, and the rollback event precedes the replacement transaction event.

## Required commands

Run the focused gate:

```sh
nix develop .#default --command just regtest-multi-contract
```

Run every required local and CI gate:

```sh
nix develop .#default --command just ci
```

`.github/workflows/ci.yml` invokes `just regtest`, which includes the
binary-market A/B, maker-order, and multi-contract live suites. This test is
ignored only for ordinary `cargo test`; it is mandatory in CI.

## Deliberate boundaries

This is one deterministic, high-value composed transition, not the independent
randomized reference model or mutation-boundary fault-injection suite promised
by the implementation plan. Those remain separate protocol-assurance work.

The gate uses the production Elements RPC source. Live Esplora/Electrs backend
equivalence remains separate work, as do activation-anchor enforcement and the
operator deep-rebuild path after a reorg exceeds retained undo depth. The test
stays within the supported two-block automatic reorg window and runs on local
liquidregtest, not public Liquid testnet.

The live test invokes the production request handler directly for RPC replay;
it does not replace the separate Iroh framing/transport tests or the future
spawned-daemon process-boundary gate.

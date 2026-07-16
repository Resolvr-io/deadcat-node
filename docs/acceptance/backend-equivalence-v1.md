# Elements RPC and Esplora backend-equivalence gate

Status: Complete for local liquidregtest; mandatory in CI.

Deadcat supports either Elements Core RPC or Liquid Esplora as its confirmed
chain source. The live
`elements_and_esplora_backends_index_the_same_live_chain` test prevents those
two production adapters from silently developing different canonical views.
It starts the pinned `elementsd` and liquid-enabled Electrs daemons through the
isolated `smplx-regtest` harness and gives both adapters the same chain.

## Adapter boundary

The fixture funds a wallet, creates a binary market, and builds its first
issuance. The issuance is submitted through
`EsploraChainSource::broadcast`, not through the test's Elements RPC client.
Before and after confirmation, the gate exercises the production adapters for:

- canonical tip, height-to-hash lookup, and full raw-block decoding;
- raw transaction lookup and canonical transaction position;
- spent and unspent output lookup;
- asset-to-issuance lookup through Liquid Esplora;
- confirmed script history in canonical order;
- fee estimation, including the typed `Unavailable` result allowed when a
  fresh regtest has insufficient fee history; and
- transaction broadcast and mempool visibility.

Every block from the test activation point through the tip is required to have
the same hash and exact consensus bytes through both adapters. Genesis is also
read through both sources. Transaction bytes and confirmed positions must
match. Electrs must identify the market creation transaction for both issued
outcome assets.

The pinned Elements daemon does not implement `gettxspendingprevout`.
Consequently, the Elements adapter can prove that an output is spent but
correctly returns `Unsupported` when asked to identify its spender. Esplora is
required to return the exact spending transaction, input index, and canonical
status. Both sources must agree that a genuinely unspent output is unspent.
This is an explicit backend capability difference, not divergent chain state.

## Node-state differential

Two fresh redb stores are initialized at the same pre-creation liquidregtest
anchor. One `SyncCoordinator` reads from `ElementsRpcChainSource`; the other
reads from `EsploraChainSource`. Both use the production `DeadcatInterpreter`.
After synchronization, the test requires exact equality of:

- synchronization reports and indexed tips;
- the discovered market record, state, and live outpoints;
- canonical contract history;
- raw transaction evidence at creation and transition positions;
- stored output evidence; and
- outpoint-owner indexes.

The initial market issuance is then invalidated and replaced with an empty
block at the same height. Electrs must converge to the alternate hash within a
bounded 20-second deadline. Both stores must report one block rolled back and
one block applied, remove the orphaned evidence, and return the market to zero
outstanding pairs. The same issuance transaction is mined one height later;
both stores must restore identical trading state and evidence at the new
canonical position while leaving the orphaned position absent.

## Regression fixes captured by the gate

The first live run exposed two adapter issues now protected by focused unit
tests and this daemon-backed gate:

1. Elements may return a valid JSON-RPC error envelope with HTTP 404. The RPC
   adapter now decodes such an envelope before classifying error code `-32601`,
   allowing the documented `gettxspendingprevout` fallback to execute.
2. Blockstream Electrs' REST `/scripthash` endpoint accepts forward SHA256 byte
   order, unlike the reversed display convention used by the Electrum
   protocol. The Esplora adapter and its exact request fixture now use the REST
   convention.

## Required commands

Run only this gate:

```sh
nix develop .#default --command just regtest-backend-equivalence
```

Run every required repository gate:

```sh
nix develop .#default --command just ci
```

`just regtest` includes `regtest-backend-equivalence`, so the gate is ignored
only by ordinary `cargo test` and remains mandatory in GitHub Actions.

## Deliberate boundaries

This is a deterministic local liquidregtest differential, not a public Liquid
testnet shakedown. It tests a short history rather than Esplora pagination at
production scale, uses unauthenticated local Electrs, and does not test a
hosted provider's availability or OAuth implementation. Those operational
concerns remain separate from canonical adapter equivalence.

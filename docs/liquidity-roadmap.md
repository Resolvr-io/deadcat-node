# Liquidity roadmap: RFQ-first, venue-neutral execution

- Status: Active roadmap — launch direction accepted by
  [ADR 0006](adr/0006-rfq-first-liquidity-scope.md)
- Date: 2026-07-29
- Scope: Product and architecture roadmap

## Status and authority

This document describes the intended evolution of Deadcat liquidity and client
execution. It is not a consensus specification, a stable wire protocol, or an
activation decision.

[ADR 0006](adr/0006-rfq-first-liquidity-scope.md) is authoritative for the
market-only production scope, RFQ-first liquidity boundary, complete
`MakerOrderV1` retirement, and clean alpha compatibility policy. The detailed
future interfaces and phases in this roadmap remain non-normative until their
own specifications and acceptance work exist.

In particular, this roadmap is not an implementation mechanism and does not:

- change any deployed contract's semantics;
- supersede an accepted architecture decision record;
- define a stable RFQ, AMM, DLOB, or router API; or
- promise that every future route can be settled atomically.

Those changes require their own implementation, tests, and documentation
updates. ADR 0006 records that no maker contract reached Liquid testnet,
mainnet, or production and that incompatible local alpha data is disposable.
`MakerOrderV1` therefore has no compatibility, migration, recovery, indexing,
or versioning period; any later output using the published alpha covenant is an
unsupported foreign contract. The market-only implementation work was
completed by [PR #15](https://github.com/Resolvr-io/deadcat-node/pull/15) and
[PR #16](https://github.com/Resolvr-io/deadcat-node/pull/16).

The roadmap should be archived or split into normative specifications once
every phase has either shipped or been explicitly rejected and its surviving
behavior is fully covered by protocol, architecture, interface, and acceptance
documents.

Here, **launch** means the first public production release. It does not describe
the current alpha implementation or erase its acceptance history:

| Horizon | Supported liquidity scope |
|---|---|
| Current alpha | `BinaryMarketV1` only; the maker experiment is retained solely as historical evidence |
| First public production release | Binary-market lifecycle plus a separate noncustodial RFQ service |
| Future scope | Permissionless AMM and/or DLOB venues, followed by bounded atomic split routing |

Bounded atomic split routing is a required compatibility goal for future
contracts and builders. It is not an RFQ-launch deliverable, and it is not a
product guarantee until the composition acceptance gates in this document pass.

## Direction

Deadcat should launch with:

1. the binary-market covenant as the only supported trading-related contract
   family;
2. a separate, noncustodial RFQ liquidity service funded with the operator's
   own inventory;
3. a client-authoritative router that validates and settles every trade; and
4. no customer deposits, hosted balances, delegated wallet authority, or
   standing customer orders.

The RFQ service is the first execution venue, not a permanent protocol
authority. Future AMM pools, DLOB orders, and additional RFQ providers should
compete through the same client routing model:

```text
                                +-- RFQ provider(s)
user trade intent -> client ----+-- AMM pool(s) ----> validated plan -> PSET
                      router    +-- DLOB order(s)
```

The client owns venue discovery, route selection, transaction construction,
intent validation, blinding, signing, and broadcaster choice. Venues provide
quotes or executable state, and `deadcat-node` provides indexed evidence, but
neither selects the user's route. A single hosted node can provide internally
valid yet stale or incomplete evidence; clients that require stronger freshness
use an independent cross-check or local Elements node.

## Goals

- Give ordinary users a simple outcome-oriented interface such as "buy 100 YES"
  or "sell 50 NO."
- Keep user funds and signing authority in the user's wallet.
- Separate market solvency and redemption from liquidity-provider availability.
- Let multiple liquidity mechanisms coexist without privileging one in the
  market covenant.
- Make venue provenance, fees, state dependencies, and freshness explicit.
- Support exact-in and exact-out intents with fail-closed slippage and fee
  bounds.
- Design future contracts and client builders for bounded atomic multi-venue
  settlement.
- Derive public price history from reproducible evidence and clearly identified
  methodology.
- Preserve the keyless, evidence-first `deadcat-node` trust boundary.

## Non-goals

- Operating a custodial exchange or internal customer-balance ledger.
- Treating the RFQ provider as a source of contract or wallet authority.
- Making RFQ quote deadlines consensus-enforced upper timelocks.
- Guaranteeing that public AMM or DLOB state remains unspent for any duration.
- Making unbounded route splitting economical or reliable.
- Treating one venue's spot price as objectively correct.
- Using a trading price to resolve the prediction market.
- Freezing exact public wire types before the venue semantics are tested.

## Components and trust boundaries

### Binary market

The binary-market covenant remains responsible for:

- fully collateralized equal YES/NO pair issuance;
- equal-pair cancellation and collateral release;
- oracle-authorized terminal resolution;
- permissionless expiry where specified; and
- winning or expired token redemption.

It does not choose a trading venue, quote a one-sided outcome price, custody
wallet funds, or authorize a client signature.

### Client router

The client router is the execution authority for the user's intent. It:

- validates the market and state evidence under its configured chain-source
  trust model;
- obtains and verifies venue liquidity;
- computes a fee-aware allocation;
- prepares exact executable legs;
- composes one complete PSET;
- validates every leg and the aggregate user result;
- coordinates blinding and finalization;
- signs only the final approved transaction; and
- broadcasts directly or through one or more relays.

The router must not accept one unexplained `market.price`. Quotes and market
metrics retain their venue and methodology provenance.

### Deadcat node

`deadcat-node` remains a keyless chain index and evidence service. It may:

- index canonical market, AMM, and DLOB contract state;
- provide raw state and transition evidence;
- report exact live outpoints and chain positions;
- publish reproducible liquidity views derived from indexed public contracts;
  and
- relay a fully signed transaction.

It does not hold LP inventory, reserve quote inputs, receive wallet secrets,
construct an opaque PSET for blind signing, or sign an RFQ leg.

### RFQ liquidity service

The RFQ service is a separate inventory-bearing security principal. It:

- issues or acquires YES/NO inventory using its own collateral;
- advertises indicative liquidity;
- reserves exact inputs for a short-lived quote;
- contributes its exact inputs and outputs to a final PSET;
- validates the complete transaction;
- durably accepts a signing intent only while its reservation remains live;
- signs only the exact durably accepted transaction; and
- returns its signature for the exact finalized transaction and may relay that
  same transaction immediately.

The service never needs customer deposits or generic spending authority. If it
becomes unavailable, new RFQ trades stop, but users retain their wallet assets
and independent market redemption rights.

### AMM

A future AMM supplies permissionless, deterministic liquidity from a published
curve and exact live pool state. It should provide:

- independently reproducible quotes;
- explicit invariant, rounding, and fee rules;
- permissionless transition validation;
- chain-replayable pool and trade history; and
- output layouts compatible with transaction composition.

An AMM is not automatically simple, unbiased, or manipulation-resistant.
Prediction-specific complementary pricing, LP accounting, terminal handling,
fixed-point arithmetic, and UTXO contention all require separate design and
review.

### DLOB

A future decentralized limit-order book consists of independently spendable
on-chain offers plus permissionless discovery and routing. A new DLOB contract
should be designed from its own requirements rather than treating
`MakerOrderV1` as immutable precedent.

Likely requirements include:

- an exact, partition-independent price and lot representation;
- well-defined partial-fill and minimum-remainder semantics;
- consensus-safe output-claim isolation;
- independent receive, cancellation, and recovery authority;
- bounded discovery and recovery metadata; and
- composition-friendly input and output constraints.

## Delivery phases

The later AMM and DLOB ordering remains data-driven. The working product
hypothesis favors an AMM before a DLOB for simple, continuously quoted baseline
liquidity and public price history, but the roadmap does not make that ordering
a protocol commitment.

### Phase 0: scope and documentation alignment

ADR 0006 completes the scope and compatibility decision:

| Surface | Accepted disposition |
|---|---|
| Creation and routing | Remove all official maker creation and routing |
| Recognition and indexing | Remove maker registration, discovery, interpretation, and materialization |
| Cancellation and recovery | Retain no legacy utility because no deployed output exists |
| RPC, package, store, and ALPN | Remove maker variants in place and retain current version numbers |
| Activation and capabilities | Remove maker and unused LMSR reservations |
| CI and acceptance evidence | Replace maker-dependent generic gates; retain dated packets as historical evidence |
| Existing alpha data | Delete or rebuild; no migration or compatibility decoding |

Phase 0 is complete:

- [PR #15](https://github.com/Resolvr-io/deadcat-node/pull/15) replaced
  maker-dependent generic assurance with atomic market-only coverage.
- [PR #16](https://github.com/Resolvr-io/deadcat-node/pull/16) made the active
  contract, client, node, storage, wire, CLI, fixture, CI, and normative
  documentation surfaces market-only.
- The maker-order audit and acceptance work remains as dated historical
  evidence with immutable source references.
- The RFQ process is explicitly separate from `deadcat-node`.

### Phase 1: one noncustodial RFQ provider

- Support exact buy and sell quotes for YES and NO.
- Pre-issue provider inventory rather than advancing the shared market state for
  every customer trade.
- Implement the first RFQ behind a provisional venue-adapter seam rather than
  wiring provider-specific economics into the wallet.
- Implement quote reservations, exact PSET composition, collaborative blinding,
  full-transaction validation, user-first signing, provider-last signing, and
  immediate relay of the exact signed transaction.
- Keep quote expiry as signed service policy rather than an `nLockTime` upper
  bound.
- Publish explicit provider fees and quote provenance.
- Keep redemption independent of the provider and hosted node.
- Establish production thresholds for quote latency, reservation-expiry and
  refusal rates, quote-to-confirmation conversion, crash-safe inventory locking,
  transaction weight, and network fee before launch.

### Phase 2: provider-neutral routing

- Harden the provisional venue-adapter seam and stabilize venue-neutral user
  intents and internal quote models.
- Allow multiple RFQ providers to advertise comparable liquidity.
- Let the client choose the best exact execution after fees and transaction
  cost.
- Keep each provider independently optional.
- Add signed execution receipts or another explicit provenance mechanism if RFQ
  trades are included in public market data.
- Measure provider fallback success, allocation reproducibility, quote response
  time, and end-to-end execution outcomes before making the adapter stable.

Atomic settlement across multiple independent RFQ signers is not required in
this phase. The client may choose one provider per transaction.

### Phase 3A: permissionless AMM

- Select and specify a prediction-market-appropriate invariant.
- Define public pool state, LP shares, fees, rounding, terminal behavior, and
  state concurrency.
- Add an evidence-validated AMM curve adapter to the client router.
- Index pool transitions and reproducible price metrics.
- Measure manipulation cost, depth, state-conflict rate, and transaction weight.
- Establish production thresholds for stale-state conflicts, successful
  replanning, confirmation latency, transaction weight, and fee.

### Phase 3B: decentralized limit-order book

- Select, specify, and audit an exact, partition-independent price and lot
  representation for a generic limit-order contract.
- Add chain discovery, state replay, order-book construction, and client-local
  curve generation.
- Add permissionless full and partial fills.
- Prove output isolation and heterogeneous transaction composition.
- Establish production thresholds for index lag, stale-order conflicts,
  successful replanning, transaction weight, and fee.

Phase 3A and Phase 3B may be implemented in either order.

### Phase 4: bounded split routing

- Split one user-level exact-in or exact-out intent across multiple on-chain
  venues.
- Permit at most one RFQ signer initially.
- Set hard route limits for legs, inputs, outputs, PSET bytes, covenant cost, and
  counterparties.
- Add stale-state replanning and explicit failure UX.
- Enable a leg only when its price improvement exceeds its marginal network fee,
  proof cost, and reliability penalty.
- First pass a heterogeneous RFQ-plus-one-on-chain-venue gate. Combining RFQ,
  AMM, and DLOB legs in one transaction is a later gate once both on-chain venue
  families exist.
- Measure realized improvement after all fees, route-build latency, signing
  latency, state-conflict and replan rates, transaction weight, and abandonment
  rate against declared production thresholds.

## Trade intents

The user-facing intent should describe an economic result rather than a venue:

```text
ExactIn:
    spend exactly X units of asset_in
    receive at least Y units of asset_out

ExactOut:
    receive exactly Y units of asset_out
    spend at most X units of asset_in
```

For example, buying 100 YES sets collateral as `asset_in` and YES as
`asset_out`; selling 50 NO reverses that direction.

Every economic intent also carries:

- network and market identity;
- exact `asset_in` and `asset_out` IDs;
- per-asset hard fee bounds, including a policy-asset network-fee bound;
- client freshness policy; and
- accepted venue policy, if restricted.

Fees denominated in different assets are not literally summed. Hard signing
bounds remain in native integer units per asset. A router may use an explicitly
identified advisory valuation model to compare mixed-asset economic costs, but
that model is not wallet authorization.

Maximum legs, inputs, outputs, counterparties, PSET bytes, and proof cost are
local execution-policy limits. The selected legs, exact aggregate result,
fees-by-asset, validity intersection, and final transaction review summary are
route results rather than user economic intent.

All amounts and calculations use exact integer asset units. Floating-point
display values are never signing authority.

## Two-phase venue interface

Discovery and execution preparation have different semantics and should not be
combined into one overloaded quote call.

The venue interface is a client-local adapter contract. An RFQ adapter speaks to
a remote provider, while AMM and DLOB adapters normally transform chain evidence
into the same local model. The normalized model must retain its source evidence
and provenance; it is not itself a new trusted quote server.

The types below are an architecture sketch within this roadmap. They illustrate
responsibilities only and are not stable wire formats. Once validated in Phase
1, their detailed form should move to a versioned companion interface
specification.

### Phase A: liquidity discovery

```text
LiquidityCurve {
    venue
    market and asset pair
    source evidence and provenance
    observed chain position under the configured trust model
    optional backend-local mempool observations
    minimum and maximum fill
    fill granularity
    size-dependent execution model
    venue fees
    estimated marginal transaction footprint
}
```

A liquidity curve is generally indicative and state-bound, not a settlement
promise. Mempool observations are advisory and backend-local: another honest
backend may expose a different transaction set or ordering.

Venue adapters expose different source models:

- RFQ: a signed indicative ladder or sampled size tiers;
- DLOB: an exact step curve derived from live order outpoints, capacities,
  prices, lots, and remainder rules; and
- AMM: evidence-validated pool state plus a versioned deterministic curve that
  the client evaluates locally.

A mere minimum/maximum price range is insufficient. The router needs a
size-dependent amount function because AMM slippage is nonlinear, DLOB depth is
piecewise and sometimes non-convex, and RFQ pricing may be tiered.

### Phase B: exact preparation

After choosing an allocation, the client prepares each exact leg:

```text
ExecutableLeg {
    exact amount in and amount out
    exact venue fees by asset
    exact state and outpoint dependencies
    global market-policy dependencies
    validity conditions
    symbolic transaction contribution
    covenant finalizer or remote signer requirements
    conservative weight estimate
}
```

The provisional ordinary-output API uses the narrower name `PreparedLeg`: its
economics and output claims are authorized, but venue-specific completion and
the final signer checks still have to succeed before it is executable on chain.

For an RFQ leg, preparation reserves exact provider inventory and returns a
signed short-lived commitment.

For a DLOB or AMM leg, preparation refreshes and pins exact public state. It does
not reserve that state against another valid transaction.

Preparation produces a user-level object across all selected legs:

```text
ExecutableRoute {
    intent identity
    aggregate exact amount in and amount out
    selected executable legs
    exact fees by asset
    policy-asset network fee
    global market and chain dependencies
    combined validity = intersection of every leg condition
    conservative transaction and proof-resource estimate
    final review summary
}
```

The route is usable only while every leg and global dependency remains
acceptable. Atomic settlement means all prepared legs confirm together or none
does; it does not make their execution availability firm before broadcast.

## Validity and freshness

Time validity, state validity, and client freshness policy are distinct.

| Venue | Native execution condition | Can become stale at any time? |
|---|---|---|
| RFQ | Provider reservation remains live, exact inputs remain usable, and the provider is still willing to sign | Operational failure remains possible |
| DLOB | Every selected order outpoint remains unspent and its covenant conditions remain satisfiable | Yes |
| AMM | The exact selected pool-state outpoint set remains unspent | Yes |

Parent-market trading state is a global client pre-sign policy for every venue
unless a venue covenant explicitly consumes or authenticates live market state.
The retired alpha `MakerOrderV1`, for example, did not natively close its fill
path when its parent market terminated. A future venue can likewise be invalid
under client policy even while each selected venue input remains
consensus-spendable.

An illustrative validity model is:

```text
ReservedUntil {
    reservation_id
    provider identity and signature
    service deadline
    reserved outpoints
}

WhileUnspent {
    exact outpoints
    observed confirmed tip
    optional observed mempool revision
}
```

A leg may require both variants.

### RFQ deadline

An RFQ deadline is enforced by service behavior:

1. reserve provider inputs;
2. assemble and blind the final transaction;
3. have the user authenticate the final transaction body and proof set under an
   explicitly approved sighash and proof-authentication profile;
4. while the reservation is live, have the provider durably commit its inputs
   to the exact validated pre-sign transcript;
5. have the provider sign only that persisted transcript, then durably store
   the signed response; and
6. return the provider signature for that exact finalized transaction and
   immediately relay it according to the quote policy.

The provider commitment creates accountability and operational firmness, not a
consensus guarantee that the provider cannot fail. Once created, a transaction
signature has no service-level expiry while its inputs remain spendable. The
provider must therefore refuse new durable acceptance after the deadline, mark
the reserved inputs committed before it invokes the signer, and never make
them available again merely because a local timer elapsed. Signing and relay
may finish after the deadline when durable acceptance won beforehand. The
client retains final
verification and may relay the exact same transaction through any broadcaster.
Ambiguous broadcast or deliberate conflict handling requires a documented
state machine that checks the exact transaction and input outspends. An absolute
transaction locktime cannot enforce an upper quote expiry.

### Public state

An AMM or DLOB execution can become unavailable immediately after observation.
This must be explicit rather than hidden behind an arbitrary time-to-live.

The UTXO model nevertheless gives a strong fail-closed property: a transaction
spends exact predecessor outpoints. If another transaction consumes one, the
stale route conflicts or fails; it cannot silently execute against a newer state
at an unexpectedly worse price.

The client should:

- subscribe to relevant outspends and state changes;
- reject snapshots older than its own `max_snapshot_age` under the configured
  chain-source trust model;
- use an independent chain cross-check or local Elements node when its freshness
  requirements exceed the guarantees of one remote source;
- refresh immediately before final assembly;
- preflight before signing and broadcast;
- use only explicitly permitted sighash profiles and authenticate any final
  proof or witness data that those sighashes do not commit; and
- reroute from fresh state after any conflict.

## Atomic multi-venue settlement

One Liquid transaction can settle a bounded route across an RFQ provider, one or
more DLOB orders, and one or more AMM pools:

```text
inputs:
    user funding
    RFQ inventory
    selected DLOB order outpoints
    selected AMM pool state

outputs:
    aggregate user receive
    RFQ payment and change
    DLOB maker payments and continuations
    AMM pool continuations
    user change
    one policy-asset fee
```

Elements enforces transaction-wide multi-asset conservation. Independent
Simplicity inputs enforce their local state transitions, and wallet signatures
bind the user's aggregate result. Every leg confirms together or none does.

The existing
[multi-contract acceptance packet](acceptance/multi-contract-v1.md) is
historical proof that the pre-removal toolchain, interpreter, store, and
Elements boundary processed one transaction advancing heterogeneous contracts.
The active
[multi-market gate](../crates/deadcat-client/tests/market_regtest.rs) proves the
current market-only stack still indexes, replays, rolls back, and rebuilds one
transaction advancing multiple contracts atomically. Neither result proves
that future RFQ, AMM, and DLOB layouts will compose safely.

### Current implementation footholds

The current client contains useful shapes, but none is the stable venue
interface proposed here:

- [`BinaryMarketTransitionPlan`](../crates/deadcat-client/src/market_builder.rs)
  exposes mandatory outputs at a caller-chosen base and finalizes only against
  the composed PSET.
- [Client validation](../crates/deadcat-client/src/validation.rs) is already a
  separate authority boundary from node indexing.
- The [live multi-market fixture](../crates/deadcat-client/tests/market_regtest.rs)
  composes two market transitions and proves transaction-atomic behavior.
- The [confidential RFQ fixture](../crates/deadcat-client/tests/rfq_regtest.rs)
  proves two-wallet P2TR settlement, collaborative blinding, exact
  whole-transaction validation, and spendable recipient outputs on
  liquidregtest.
- The provisional client-local [venue model](../crates/deadcat-client/src/venue.rs)
  and [transaction composer](../crates/deadcat-client/src/composition.rs)
  separate aggregate user intent from exact per-leg allocation, bind an
  authenticated venue proposal to real payment/receipt outputs and the user's
  exact confidential destination, and allocate contribution-local symbolic
  fragments without defining a remote wire format. A validated route owns the
  exact legs and network fee consumed by composition, so validation and
  assembly cannot silently diverge. This route validation does not infer wallet
  change, validate ancillary-output net effects or per-asset transaction
  balance, or authorize signing; each participant's final whole-transaction
  validator remains a separate boundary.
- Cross-contribution blinding roles refer to exact outpoints rather than a
  shared numeric namespace. A venue may assign only its claimed payment output
  to the payer's external blinder; its user receipt and ancillary confidential
  outputs remain assigned to inputs local to that venue contribution.
- The composer's `UnblindedStructureManifest` is intentionally not signing
  authorization. It freezes transaction-body fields and clear output intent,
  while participant-specific validation must still authorize sighash and spend
  policy, verify confidential commitments and proofs, and rewind owned outputs.
- The initial generic venue binding supports ordinary confidential exclusive
  payment and receipt outputs. Trusted client-local covenant builders have a
  separate private template path; a non-issuance binary-market transition is
  tested at nonzero composer offsets. Issuance fields and future AMM/DLOB
  economic-delta bindings remain deliberately deferred.
- The retired
  [`MakerFillPlan`](https://github.com/Resolvr-io/deadcat-node/blob/d7be35b27a020a61333e471b2ded5f59e3a0a039/crates/deadcat-client/src/maker_builder.rs)
  and
  [heterogeneous live fixture](https://github.com/Resolvr-io/deadcat-node/blob/d7be35b27a020a61333e471b2ded5f59e3a0a039/crates/deadcat-client/tests/market_regtest.rs)
  remain historical composition evidence, not production interfaces.

Phase 1 has extracted and tested the smallest generic plan/composer seam from
these patterns without making the router depend on maker-specific types. The
API remains provisional until real remote RFQ evidence and a production signer
exercise it.

### Symbolic transaction contributions

The router must not merge independently assembled PSETs. Proof domains,
transaction sighashes, locktime, sequences, input order, output order, and
covenant witnesses depend on the final global transaction.

Each venue adapter instead contributes a symbolic fragment containing:

- exact input groups and witness UTXOs;
- input ordering or adjacency constraints;
- mandatory output templates;
- output ordering or adjacency constraints;
- gross unsigned user spends and receives, with fees itemized separately;
- explicit or confidential output policy;
- global locktime and sequence requirements;
- an exclusive output-claim policy; any future aggregation requires explicit
  compatibility and a proven collaborative-blinding construction;
- a local covenant finalizer or remote signer role; and
- a conservative resource estimate.

The router:

1. obtains fresh curves;
2. computes a fee-aware allocation;
3. prepares exact legs and RFQ reservations;
4. rejects duplicate outpoint dependencies;
5. allocates compatible global input and output positions;
6. adds user funding, aggregate receive, change, and fee outputs;
7. freezes the transaction shape;
8. completes collaborative blinding and proofs;
9. finalizes every covenant against the complete PSET;
10. validates every leg and the aggregate user intent;
11. obtains the user signature;
12. obtains RFQ signatures while reservations remain live; and
13. broadcasts and monitors the exact transaction.

### Future covenant composition rules

Future AMM and DLOB covenants should:

- avoid assuming global input or output index zero;
- avoid requiring an exact total transaction input or output count;
- use allocatable local windows or another documented global slot convention;
- prevent the same output from satisfying multiple independent covenant claims;
- define exact behavior when multiple instances share an asset or script;
- leave aggregate taker receive and change outputs unconstrained where the
  taker's aggregate intent validation and approved signature and
  proof-authentication profile safely protect them;
- support finalization only after the complete input set and proof set are fixed;
  and
- expose exact mandatory outputs and resource bounds to the client composer.

## Efficiency and route limits

Atomic composition provides:

- one transaction base overhead;
- one fee output;
- netting of intermediate multi-asset flows;
- consolidated user receive and change outputs where safe;
- one confirmation boundary; and
- no partial cross-venue settlement exposure.

Costs still grow roughly linearly with route complexity:

- each DLOB order adds an input, covenant witness, maker payment, and sometimes a
  continuation;
- each AMM adds its pool-state inputs, continuations, and proof work;
- each RFQ provider adds wallet inputs, signatures, coordination, and blinding;
  and
- confidential outputs add rangeproof and surjection-proof weight.

The route objective therefore includes, after conversion through a declared
advisory valuation model:

```text
economic execution cost
+ venue fees
+ network fee from marginal weight
+ state-conflict penalty
+ signer/reliability penalty
```

The router should split only when the resulting improvement is material after
all five terms. This comparable score is an optimization aid, not a signing
limit; the final wallet check still enforces each asset's native integer bounds.

Initial multi-venue routing should allow at most one RFQ provider. Multiple RFQ
providers can sign one transaction, but any provider can abort the entire route
by withholding its signature. No funds are lost, but every other reservation
and signature is wasted.

## AMM state contention

A UTXO AMM normally consumes an exact live pool-state outpoint set and creates
its successor. Concurrent transactions built from the same state conflict, so
only one branch can confirm.

Consequences include:

- rapidly stale quotes during activity;
- serialized throughput for one pool instance;
- transaction replacement and retry UX;
- potential reliance on mempool views that differ between backends; and
- pressure toward a convenience coordinator.

Possible mitigations include:

- multiple independently funded pools;
- explicitly sharded pool instances;
- batching;
- carefully supported chaining from an unconfirmed continuation; and
- an optional noncustodial sequencer.

An RFQ provider can mask some contention by settling immediately from reserved
inventory and rebalancing against the AMM later. That operational role remains
useful after the AMM launches.

## Collaborative blinding and signing

Multi-party confidential settlement is a separate protocol boundary and needs a
dedicated acceptance gate.

The design should:

- avoid exposing wallet input secrets unnecessarily;
- freeze all transaction inputs and outputs before final proof generation;
- define participant blinder roles and scalar-offset exchange;
- validate every nonce, commitment, proof, fee, and change output before signing;
- specify exactly which transaction body and witness fields each permitted
  signature profile commits;
- separately authenticate final proofs or witnesses that a permitted sighash
  does not commit;
- prevent a participant from substituting a non-rewindable receive output; and
- fail without broadcasting if any required participant or proof is missing.

The RFQ-first implementation may simplify this boundary with one provider and
explicit venue-side settlement outputs before enabling more private or
multi-provider shapes.

## Price data and provenance

Execution quotes and market metrics are different products.

An execution quote answers:

> What exact amount can this user receive now for this trade size, under these
> dependencies and fees?

A market metric answers:

> What calculation over identified historical or current evidence should the UI
> display as a spot, trade, TWAP, VWAP, mark, or index value?

Every metric records:

- source venue or composite inputs;
- metric kind;
- methodology version;
- pool, order-book, or provider identity;
- block and state reference;
- fee treatment;
- time or block window; and
- liquidity or depth context where relevant.

### RFQ data

An RFQ quote is provider-attested. A confidential bilateral settlement may not
reveal enough public information for an indexer to reconstruct its price.
Public RFQ history therefore requires signed execution receipts, selective
disclosure, or another explicit provenance mechanism.

### AMM data

An AMM with public state can provide independently reproducible:

- marginal curve price;
- amount-specific executable price;
- confirmed execution history;
- block-weighted TWAP;
- volume-weighted trade metrics; and
- depth and price-impact measures.

This makes the data procedurally neutral and chain-verifiable, not objectively
correct or manipulation-proof. Thin liquidity, initial seeding, pool ownership,
fees, curve parameters, slow arbitrage, and transaction ordering can all move
the result.

Public reproducibility also constrains confidentiality: observers need enough
pool state or proof data to derive the price. A fully blinded pool visible only
to a view-key holder does not provide a neutral public price feed without
additional proofs.

### DLOB data

A DLOB provides reproducible bids, asks, depth, cancellations, and confirmed
fills. Resting liquidity can be canceled or spoofed; confirmed execution and
depth-aware metrics have different evidentiary weight from an advertised order.

### Binary complement

Fully collateralized binary claims should economically tend toward:

```text
YES price + NO price = collateral per pair
```

Fees, latency, oracle risk, settlement delay, and constrained arbitrage can
create a complement gap. Independent YES/collateral and NO/collateral pools may
diverge. The UI and indexer should expose that gap rather than silently
normalizing it away.

The AMM or DLOB price is market-implied belief, not evidence of the real-world
outcome. Market resolution remains exclusively governed by the market's oracle
and expiry rules.

## Failure and retry semantics

Atomicity prevents partial settlement but does not guarantee execution.

The client must distinguish:

- RFQ reservation expiry or provider refusal;
- spent DLOB order;
- advanced AMM state;
- market resolution or expiry;
- mempool rejection;
- fee-policy change;
- collaborative blinding failure;
- signer timeout;
- broadcast ambiguity; and
- confirmation followed by reorganization.

Before the provider durably accepts the exact signing transcript, failure can
discard the transaction, release or expire RFQ reservations, refresh state,
and reroute. After durable acceptance, the reservation is committed even if
the signer or response later becomes ambiguous: local timeout alone is not
enough to recycle its inputs.

After ambiguous broadcast, the client first checks the exact transaction and
its input outspends before constructing a conflicting replacement. After a
reorganization, it derives state from canonical chain evidence and never assumes
that an orphaned venue transition remains live.

## Acceptance gates

### RFQ-first gate

- Users never deposit funds or grant generic signing authority.
- The client rejects wrong assets, amounts, fees, change, market identity, and
  stale market state.
- The user's signature cannot authorize a different input/output transaction
  body, and omitted witness commitments are covered by the approved
  proof-authentication protocol.
- The provider refuses new signing commitments at or after the quote deadline,
  durably commits exact inputs and transcript before invoking the signer,
  stores the exact signed response before external release, and immediately
  relays only that transaction according to policy.
- Reserved provider inputs cannot be double-allocated, including across process
  crashes, restarts, or ambiguous broadcast.
- Collaborative blinding outputs remain spendable by their intended recipients.
- Provider failure leaves user funds unaffected.
- Redemption succeeds without the provider or hosted node.
- Quote latency, reservation expiry and refusal, quote-to-confirmation
  conversion, transaction weight, fee, and signing latency meet declared
  production thresholds.

### Router gate

- Exact-in and exact-out allocations reproduce from curves and their retained
  source evidence.
- Integer rounding is identical across discovery, preparation, and settlement.
- Marginal transaction cost can reverse an otherwise better route.
- Duplicate dependencies and incompatible fragment constraints fail closed.
- Route caps apply before expensive PSET work.
- Hosted suggestions cannot cause the client to violate its local intent.
- The prepared `ExecutableRoute` reports aggregate amounts, fees by asset,
  global dependencies, resource estimates, and the intersection of all leg
  validity conditions.

### AMM gate

- Every invariant, fee, rounding, LP, and terminal path passes differential and
  live Elements execution tests.
- Independent replay derives identical pool state and price metrics.
- Stale-state transactions conflict rather than execute at another price.
- State contention, manipulation cost, and transaction resource use are
  measured under production-shaped load.

### DLOB gate

- Price and lot arithmetic is exact and partition-independent.
- Partial fills cannot create unsupported or unfillable continuations.
- Independent covenant claims cannot alias one output.
- Cancellation, recovery, discovery, replay, and reorg behavior is complete.
- Multiple orders compose without relying on official-builder-only assumptions.

### First heterogeneous atomic gate

One production-shaped PSET combines:

- user funding;
- one RFQ provider;
- at least one on-chain venue, either DLOB or AMM;
- confidential user receive and change; and
- a policy-asset fee.

The finalized transaction must pass client validation, every covenant,
`testmempoolaccept`, broadcast, confirmation, restart, independent replay, and
reorganization. Mutating any one leg must reject the entire transaction without
leaving a partial materialized state.

The gate also measures transaction bytes, weight, proof generation, covenant
cost, signing latency, and stale-state failure rate.

### Full heterogeneous atomic gate

After both on-chain venue families exist, a second production-shaped PSET
combines one RFQ provider, at least one DLOB order, and at least one AMM pool.
It must pass the same mutation, mempool, confirmation, restart, replay, reorg,
resource, and stale-state checks. Passing the first gate does not imply that
three independently designed fragment layouts compose safely.

## Open decisions

- Which AMM family best fits complementary binary claims: LMSR, a fixed-product
  market maker, separate outcome/collateral pools, or another invariant?
- Should AMM or DLOB follow multi-provider RFQ routing first?
- What public pool state is required for reproducible prices?
- How are LP shares, fees, and terminal withdrawals represented?
- What output-slot convention safely composes future AMM and DLOB covenants?
- Which exact curve model is internal-only, and which portions need a stable
  network representation?
- How are signed RFQ executions published without unnecessarily sacrificing
  trade privacy?
- Which sighash profiles are supported for each input type, what fields does
  each profile commit, and how are omitted proofs or witnesses authenticated?
- ADR 0007 resolves reservation, commit-before-sign, signature persistence, and
  permanent input retirement. Exact relay, ambiguous-broadcast, and canonical
  outspend reconciliation remain to be specified with the service layer.
- Which chain and mempool evidence is required before a route is considered
  fresh enough to display or sign?
- When should multiple RFQ signers be allowed in one transaction?
- Should an AMM use sharded pools, batching, or an optional sequencer?
- Which price metric, if any, should be the default portfolio mark?
- What route-size and proof-cost measurements determine production caps?

## Documentation follow-up

ADR 0006 accepted the direction, superseded the release-scope decision in
[ADR 0002](adr/0002-v1-contract-scope.md), and retired
[ADR 0003](adr/0003-order-economics.md) as historical. The Phase 0 documentation
work is complete:

1. the [README](../README.md) and [architecture](architecture.md) distinguish
   the keyless node from the inventory-bearing RFQ service;
2. the [existing implementation plan](implementation-plan.md) is a
   completed alpha record;
3. the protocol and storage/RPC specifications match the market-only code and
   capability surface;
4. dated maker-order audits and acceptance packets are preserved with immutable
   source references; and
5. the heterogeneous multi-contract result remains historical evidence while
   the active gate uses two independent markets.

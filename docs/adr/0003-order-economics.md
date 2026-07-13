# ADR 0003: Limit-order economics and quantity policy

- Status: Accepted
- Date: 2026-07-12

## Context

V1 needs an order price that is exactly enforceable in indivisible Liquid asset
units, compactly recoverable, easy to sort, and safe under arbitrary partial
fill partitioning.

The legacy `u24` convention cannot encode the full supported binary payout
range: `u24::MAX` is 16,777,215 while the current maximum binary pair cost is
20,000,000 collateral atoms. Arbitrary rational prices with per-fill ceiling
rounding make proceeds depend on fill partitioning and complicate both order
priority and SellQuote conservation.

## Decision

An order uses:

```rust
pub struct OrderPrice(pub u32);       // quote atoms per base atom
pub struct MinActiveBase(pub u32);    // base atoms
```

Canonical parameters satisfy:

```text
1 <= price <= parent_market.collateral_per_pair
1 <= min_active_base
```

The user interface may restrict ordinary order entry to 1%-99%, but the
protocol permits the exact endpoints `1` and `collateral_per_pair`.

All monetary products use checked `u128` intermediates and must fit the
consensus output-amount domain before construction. The Simplicity fill path
independently rejects a nonzero high product half or other overflow, so custom
builders cannot bypass this rule.

## Exact fill equations

Let `P` be price and `M` be `min_active_base`.

For SellBase, the order input holds BASE atoms:

```text
filled_base = input_base - remainder_base
maker_quote = filled_base * P
```

For SellQuote, the order input holds QUOTE atoms:

```text
quote_consumed = input_quote - remainder_quote
quote_consumed = maker_base * P
```

Creation is expressed in base quantity for both directions. A SellQuote order
for `offered_base` atoms locks exactly `offered_base * P` quote atoms. This
prevents an unfillable `input_quote mod P` remainder.

Every fill transfers at least `M` base atoms. Every nonzero continuation has at
least `M` base atoms of remaining capacity:

```text
SellBase continuation: remainder_base >= M
SellQuote continuation: remainder_quote >= M * P
```

A complete fill has no covenant continuation output. These rules use one field
instead of independent fill and remainder minimums, preventing a partial fill
from creating an active order that is too small for any later legal fill.

## Consequences

- Settlement is exact and independent of how a taker partitions fills.
- All orders share a one-base-atom quantity grid.
- Probability resolution is `1 / collateral_per_pair`; the UI shows any price
  snapping before confirmation.
- The 32-bit price and quantity fields leave headroom without custom bit-width
  arithmetic. The few extra recovery bytes are paid once at order creation.
- A future exact lot-pair order can be added as a new contract version if real
  demand for sub-atomic-unit limit prices justifies its routing and UX costs.

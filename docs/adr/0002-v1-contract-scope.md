# ADR 0002: V1 contract scope and lifecycle

- Status: Accepted
- Date: 2026-07-12

## Decision

V1 implements two fresh, incompatible-with-legacy contract families:

1. a binary prediction market;
2. a persistent maker limit order.

The existing Deadcat SDK contracts are reference material only. V1 does not
preserve their CMRs, parameter encodings, witnesses, or deployed instances.

An LMSR pool contract and its price-history API are reserved in versioned enums
and capability negotiation but are not implemented. Multi-outcome markets are
also outside v1.

## Binary market responsibility

The market covenant guarantees that every outstanding winning claim remains
fully collateralized under either oracle outcome and under the expiry outcome.
It supports permissionless pair issuance, pair cancellation, redemption, and
expiry. Oracle authority is restricted to selecting YES or NO through a tagged
BIP-340 attestation.

`expiry_height` is an exact `u32` CLTV-style block-height threshold. It is not
rounded or stored in a custom-width field, and canonical values are below the
`500_000_000` timestamp-locktime boundary. A transaction using threshold `H`
is first confirmable in block `H + 1` under consensus locktime semantics.

The terminal rule is transaction based, not wall-clock-exclusive:

- oracle resolution remains available at every height;
- once the threshold is consensus-final, the permissionless expiry transition
  is also available;
- Bitcoin and Elements timelocks can open a path but cannot close the oracle
  path after an upper deadline;
- the first valid terminal transaction confirmed on the canonical chain wins.

Choosing an oracle therefore includes trusting it to follow the market's
advertised settlement policy.

## Order responsibility

The order covenant represents a good-until-cancelled on-chain offer. Anyone may
fill it through the Simplicity script path. The maker may cancel through the
Taproot key path. There is no fill cosigner and no duplicate script-cancel path.

An order does not consume the parent market on each fill. It therefore remains
covenant-fillable after the market resolves or expires until its maker cancels
it. This is an explicit throughput trade-off: requiring a shared live-market
UTXO would serialize otherwise independent order fills.

Nodes and official clients stop routing an order as soon as they observe the
parent market leave its trading state, but this is policy rather than covenant
protection. Every trade preflight includes the parent market's observed state,
even when the transaction does not co-spend it.

## Asset confidentiality

Market collateral state and order state outputs use explicit assets and values
so covenants and independent indexers can validate them. Reissuance-token
outputs follow the deterministic confidential construction required by
Elements issuance. Wallet-owned receive and change outputs may remain
confidential where the transaction shape permits it.

Markets accept any Liquid collateral `AssetId`. Fees are paid in the network
policy asset. The recovery format has compact identifiers for well-known assets
and a full-ID escape for other collateral.

## Compatibility policy

The node tracks canonical, versioned Deadcat contract families. It interprets
every covenant-valid transaction arrangement involving those contracts,
including multi-contract transactions built by independent software. It does
not assume that a transaction came from the official builder.

Recovery hints are advisory discovery metadata rather than a covenant-validity
condition. Full manual registration can track an otherwise canonical instance
without a hint when its parameters, creation output, asset relationships, and
initial lineage are unambiguous; the node reports that v1 hint recovery is not
available for that instance.

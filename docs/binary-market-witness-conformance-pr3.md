# Binary-market PR3 witness conformance

Status: implementation conformance note for the proposed v1 binary-market
witness refactor. The normative protocol description remains in
`docs/protocol-v1.md`.

## Typed ABI

Coordinator spends decode exactly two source witnesses:

```text
SLOT: u8
ACTION: Either<Either<u32, u32>,
               Either<(u32, bool, Signature), Either<u32, u32>>>
```

The five `ACTION` branches are, in order:

| Operation | Structural branch | Payload |
|---|---|---|
| Issue | `Left(Left(...))` | `output_base: u32` |
| Cancel | `Left(Right(...))` | `output_base: u32` |
| Resolve | `Right(Left(...))` | `(output_base: u32, outcome_yes: bool, signature: Signature)` |
| Expire | `Right(Right(Left(...)))` | `output_base: u32` |
| Redeem | `Right(Right(Right(...)))` | `output_base: u32` |

Simplicity represents the three-element Resolve tuple as the right-associated
product `(u32, (bool, Signature))`. Redeem-program pruning replaces inactive
`ACTION` alternatives with unit while retaining the selected sum path. The five
exact finalized types are therefore:

```text
Issue:   Either<Either<u32, ()>, ()>
Cancel:  Either<Either<(), u32>, ()>
Resolve: Either<(), Either<(u32, (bool, Signature)), ()>>
Expire:  Either<(), Either<(), Either<u32, ()>>>
Redeem:  Either<(), Either<(), Either<(), u32>>>
```

An interpreter must match one of these complete branch-pruned structural types
before decoding its value. Matching anonymous bit widths or accepting a
differently associated product is non-conforming.

Follower roles read only `SLOT`; they authenticate their coordinator group and
do not consult `ACTION`. Confirmed-spend interpretation begins from the tracked
coordinator input, so its decoded program must contain exactly one `SLOT` and
one branch-pruned `ACTION` value of the complete types above.

## Derived layout

`PATH` is not a witness. The interpreter uses the shared
`BinaryMarketCoordinatorRole` and `BinaryMarketLayout` domain mapping:

| Coordinator slot | Operation | Transaction discriminator | Legacy path |
|---|---|---|---|
| 0 | Issue | — | Initial issuance |
| 2 | Issue | — | Subsequent issuance |
| 2 | Cancel | output `base + 2` is collateral | Partial cancellation |
| 2 | Cancel | output `base + 2` is a YES burn | Full cancellation |
| 2 | Resolve | — | Active resolution |
| 0 | Resolve | — | Dormant resolution |
| 2 | Expire | — | Active expiry |
| 0 | Expire | — | Dormant expiry |
| 5 or 6 | Redeem | — | Resolved redemption |
| 7 | Redeem | — | Expiry redemption |

Dormant YES/NO RT siblings must share a prior transaction but may occupy
nonconsecutive vouts so composed creation remains valid. Unresolved YES/NO/
collateral siblings must share a prior transaction and occupy consecutive
vouts in that order.

For redemption, an explicit collateral asset at `output_base` selects the
partial layout and moves the burn to `output_base + 1`; otherwise the burn is at
`output_base`. The explicit burn supplies both token quantity and, after
expiry, YES/NO side. These values are never reconstructed from spare witness
bits.

## Fail-closed checks

Conforming interpretation rejects missing, duplicate, unexpected, or
wrongly-typed witness values; a `SLOT` that disagrees with the authenticated
control block/state; an operation invalid for the coordinator role; and any
transaction that fails independent input, issuance, output, burn, oracle,
locktime, or economic validation. It performs one interpretation from the
decoded action rather than searching candidate paths or payload values.

The unit conformance matrix covers all five nested `ACTION` leaves and malformed
near-miss structural types. Shared domain tests cover all ten legacy paths and
every coordinator/follower role; confirmed-transaction tests cover exact
output-base selection and independently invalid transaction shapes.

## Candidate identity and resource bounds

For the canonical golden parameter fixture, this refactor originally produced CMR
`e8912f8e5deb3c04ba47eaacacc8d194ae0473e35cee9e171b8a71e3513abca0`.
The nonuniform-asset fixture originally produced
`2d350901b53cfeb3204f97e7708980fd62bf24914bf8e4aafb6530ce025dbb7f`.
A later semantic-preserving compiler change precomputed the two oracle messages,
changing the current CMRs while retaining this witness ABI. The current identity
and derived-message vectors are recorded in the
[oracle-precomputation note](binary-market-oracle-precomputation.md). The
golden-vector suite pins both current CMRs, the source ABI, and all eight
resulting Taproot script/control-block pairs.

The all-path, both-RT-side budget corpus records these current maxima:

| Resource | Maximum |
|---|---:|
| Covenant cost | 3,633,302 milliweight |
| Extra cells | 72,462 |
| Extra frames | 62 |
| Finalized covenant stack | 4,339 bytes |
| Transaction size | 13,624 bytes |
| Transaction weight | 15,574 WU |
| Transaction vsize | 3,894 vB |

These overall maxima remain current after oracle-message precomputation because
non-resolution paths determine them. CI uses rounded ceilings above the
measurements and fails if a later compiler or covenant change crosses them.

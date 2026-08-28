# Binary-market oracle-message precomputation

The canonical binary-market compiler derives the two possible oracle messages
from the YES and NO token asset IDs and binds both digests into the instantiated
Simplicity program. The covenant selects the bound digest from the authenticated
outcome bit and performs only BIP340 verification at spend time.

This is an implementation-boundary change, not an oracle-protocol change. The
message remains:

```text
market_id = SHA256(yes_token_asset_id_bytes || no_token_asset_id_bytes)
message = tagged_hash("deadcat/oracle_attestation", market_id || outcome_byte)
```

`outcome_byte` remains `0x01` for YES and `0x00` for NO. The compiler-derived
messages are not independently selectable market parameters. Independent
clients derive them from the public outcome asset IDs, recompile the covenant,
and verify the resulting script as before.

## Golden identity

For the canonical golden fixture, the oracle-precomputation candidate produced
CMR:

```text
702f5d04f15bcdec3fa1070540bf2f68c0ecdcf40bc8aa8024e1e77ef19cd5ee
```

The position-sensitive nonuniform-asset fixture has CMR:

```text
090548f91e2f07d2e691216336b578bf15fcdbde96f2e4255e4e70c60e4c1931
```

Its independently frozen oracle digests are:

```text
YES = 0091d6c79a16ced37737ac34a7a461359d93ce1eebebca50eefd9197a1bc0876
NO  = 10c3d52c18c0a9d2d1d9cd90dc1ae4537ad53cf2e2a4e980b5dd4f04b5f1263e
```

At that candidate point, the golden-vector suite also froze all eight resulting
Taproot scripts and control blocks. A later source-legibility refactor changed
the compiled identity without changing oracle-message derivation; its current
vectors are recorded in the
[SimplicityHL legibility note](binary-market-simf-legibility.md).

## Resource measurements

Immediately after precomputation, the all-path, both-RT-side finalized corpus
measured the following worst resolution rows. Each covenant value is
aggregated over all market inputs in that transaction.

| Resolution shape | Cost (mw) | Program bytes | Stack bytes | Transaction bytes | vB |
|---|---:|---:|---:|---:|---:|
| Active | 3,127,815 | 3,733 | 4,117 | 13,188 | 3,624 |
| Dormant | 1,457,852 | 2,362 | 2,641 | 11,588 | 3,135 |

The overall corpus maxima remain determined by non-resolution paths:

| Resource | Maximum |
|---|---:|
| Covenant cost | 3,633,302 milliweight |
| Extra cells | 72,462 |
| Extra frames | 62 |
| Finalized covenant stack | 4,339 bytes |
| Transaction size | 13,624 bytes |
| Transaction weight | 15,574 WU |
| Transaction vsize | 3,894 vB |

The corpus executes active and dormant YES and NO resolution, both RT input
sides, corrupt signatures, and cross-outcome signatures. These values preserve
the oracle-precomputation candidate as historical evidence; current all-path
bounds and compiled identities are recorded in the
[SimplicityHL legibility note](binary-market-simf-legibility.md).

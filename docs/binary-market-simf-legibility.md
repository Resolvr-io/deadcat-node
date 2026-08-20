# Binary-market SimplicityHL legibility refactor

The undeployed binary-market v1 covenant was reorganized to make its role
authentication, action dispatch, and transition invariants easier to audit.
This is a source-structure and naming change: the public market parameters,
`SLOT`/`ACTION` witness ABI, transaction layouts, and protocol behavior are
unchanged.

## Dispatch structure

The entry point now performs four visible steps:

1. Read `SLOT` and the current input index.
2. Authenticate the current input script against that slot.
3. Authenticate the complete coordinator or follower role group.
4. Read and dispatch `ACTION` only for an authenticated coordinator.

SimplicityHL 0.6 requires witness expressions to remain in `main`, so the
follower selection stays there. Coordinator-group authentication and the
five-operation action dispatch are separate named functions. Named aliases
document the structural `ACTION` branches without changing their encoded
sum/product type, and a slot legend records all eight Taproot roles.

The shared and transition modules also use explicit names for RT sides,
confidential commitments, issuance quantities, burn outputs, collateral
amounts, and consecutive previous outpoints. Intentionally ignored values use
`_` bindings.

Follower programs still do not consult `ACTION`. Invalid slots still fail role
authentication, and every coordinator action retains its slot-specific guard.

## Golden identity

Extracting the coordinator and dispatch logic into named functions changes the
compiled Simplicity structure and therefore intentionally changes CMRs,
Taproot scripts, and some control-block parity bytes. For the canonical golden
fixture, the CMR changed from the oracle-precomputed value

```text
702f5d04f15bcdec3fa1070540bf2f68c0ecdcf40bc8aa8024e1e77ef19cd5ee
```

to:

```text
00e4bab69ce3f9d6346fe67fe186d4ef08d3c608ef31b4c4ade8a47459852447
```

The position-sensitive nonuniform-asset fixture changed from

```text
090548f91e2f07d2e691216336b578bf15fcdbde96f2e4255e4e70c60e4c1931
```

to:

```text
53fac89c22d842a74174c3f1d2f703708c0d323bd18e5d1cfe78c08fe0fb3ccc
```

The committed golden-vector suite freezes both new CMRs, the unchanged source
ABI, and all eight resulting script/control-block pairs.

## Resource measurements

The all-path finalized corpus executes every transition with both RT input
sides. These are the aggregate worst-case values before and after the
legibility refactor:

| Resource | Oracle-precomputed | Legibility refactor | Change |
|---|---:|---:|---:|
| Covenant cost | 3,633,302 mw | 3,635,230 mw | +1,928 mw |
| Extra cells | 72,462 | 73,049 | +587 |
| Extra frames | 62 | 64 | +2 |
| Pruned program | 4,019 bytes | 4,051 bytes | +32 bytes |
| Witness | 72 bytes | 72 bytes | 0 |
| Finalized covenant stack | 4,339 bytes | 4,371 bytes | +32 bytes |
| Transaction size | 13,624 bytes | 13,656 bytes | +32 bytes |
| Transaction weight | 15,574 WU | 15,606 WU | +32 WU |
| Transaction vsize | 3,894 vB | 3,902 vB | +8 vB |
| Discounted weight | 6,768 WU | 6,800 WU | +32 WU |
| Discounted vsize | 1,692 vB | 1,700 vB | +8 vB |

All values remain below the rounded CI ceilings. Annex padding remains zero on
every path.

# ADR 0005: Reissuance-token blinding schedule

- Status: Proposed — research recommendation only
- Date: 2026-07-12

## Context

Elements requires a confidential reissuance-token (RT) input's asset blinding
factor to be known when the token is used for reissuance. Surjection-proof
construction also requires the continuing output to use an asset generator
different from the generator being spent. Deadcat's RT factors are public
consensus data rather than privacy secrets; their purpose is to make an
anyone-can-continue covenant compatible with those Elements rules.

The current binary-market prototype uses an outpoint-derived rolling schedule:

```text
creation ABF = hash_to_scalar("deadcat/rt_abf", defining_outpoint)
creation VBF = hash_to_scalar("deadcat/rt_vbf", defining_outpoint)
creation CBF = ABF + VBF mod n

continuation ABF = hash_to_scalar("deadcat/rt_abf", spent_rt_outpoint)
continuation CBF = input CBF
continuation VBF = CBF - ABF mod n
```

This is coherent and keeps each one-unit RT's effective commitment blinder
constant. It nevertheless makes a valid continuation depend on mirrored
outpoint serialization, tagged hashing, scalar reduction, and witness-supplied
input factors. Its distinct-generator guarantee is probabilistic: equality
between consecutive hash-derived ABFs is cryptographically negligible, but not
excluded by construction.

Astrolabe demonstrates a simpler two-side schedule in production-shaped code,
but its fixed-VBF design does not preserve a constant effective commitment
blinder. This record therefore evaluates an A/B schedule adapted to Deadcat's
composition and explicit-transaction goals rather than copying Astrolabe's VBF
rule.

## Research recommendation

The research recommendation is to replace rolling ABFs with two fixed public
ABFs and a constant effective commitment blinder per RT leg. The YES and NO
leg CBFs should be additive inverses so that canonical two-leg market creation
is locally balanced.

This is **not an accepted protocol decision and does not authorize a production
migration**. The rolling implementation remains the authoritative v1 behavior
until the live-regtest, full-contract, and adversarial evidence listed below is
complete and this ADR is explicitly accepted. In particular, this proposal
alone must not be used to replace the market covenant, update its golden CMR,
or advertise A/B-created markets as canonical.

## Proposed schedule

Let `n` be the secp256k1 group order. Use these fixed, valid, nonzero scalars:

```text
ABF_A    = 0x0101010101010101010101010101010101010101010101010101010101010101
ABF_B    = 0x0202020202020202020202020202020202020202020202020202020202020202
C        = 0x0303030303030303030303030303030303030303030303030303030303030303
YES_CBF  = C
NO_CBF   = -C mod n
         = 0xfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfbb7abd9e3ac459d38bccf5b89cd333e3e
```

For RT leg `r` and side `s`:

```text
VBF(r, s) = CBF(r) - ABF(s) mod n
```

The resulting VBFs are:

| Leg | Side A | Side B |
|---|---|---|
| YES | `0x02` repeated 32 bytes | `0x01` repeated 32 bytes |
| NO | `0xfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfab6aad8e2ab449c37bbce5a88cc323d3d` | `0xfafafafafafafafafafafafafafafaf9b5a9d7e1aa439b36bacd5987cb313c3c` |

For an RT whose value is exactly one, the commitments are:

```text
asset(r, s) = H(asset_id(r)) + ABF(s) * G
value(r)    = H(asset_id(r)) + CBF(r) * G
```

The value commitment is therefore identical on A and B. Canonical creation
places both RT legs on A. Every live continuation flips A to B or B to A. A
terminal RT burn also uses the opposite confidential side and a bare
`OP_RETURN`; making the burn explicit would discard the local CBF balance, and
using the input side would recreate the prohibited equal-generator case.

The formula above is specific to a one-unit RT. If an RT amount ever differs
from one, the effective blinder is `amount * ABF + VBF`; this schedule must not
be generalized without revisiting that algebra.

## Why the CBFs are complementary

Preserving a leg's CBF makes every continuation locally neutral in the
transaction's Pedersen sum. Using the same positive CBF for both creation legs,
however, leaves a `2 * C * G` term relative to two explicit one-unit issuance
pseudo-inputs. A separate confidential output would have to absorb it.

With `YES_CBF + NO_CBF = 0 mod n`, the canonical creation commitments satisfy:

```text
value(YES) + value(NO)
    = H(yes_rt) + C*G + H(no_rt) - C*G
    = H(yes_rt) + H(no_rt)
```

The RT part of market creation can consequently balance with explicit issuance
pseudo-inputs and explicit wallet funding/change. Later operations remain
locally balanced per leg. This property is useful for custom multi-contract
transactions because one contract does not impose a hidden VBF-balancing
obligation on another contract or on wallet change.

## Covenant and client shape

The proposed covenant infers the input side from its exact asset commitment,
requires the role-specific fixed value commitment, and requires the output to
use the opposite asset commitment with the same value commitment. No factor or
side supplied by a witness is authoritative.

The preferred implementation derives and binds six internal compile-time
commitments from the existing market parameters:

- YES asset generator A, asset generator B, and value commitment;
- NO asset generator A, asset generator B, and value commitment.

These are derived compilation inputs, not independently selectable public
market parameters. Clients and nodes recompile them from the RT asset IDs and
the constants above. Prebinding removes runtime curve generation and outpoint
hashing while preserving the normal CMR/script verification trust model.

Off-chain code should expose typed `RtLeg` and `RtSide` values and derive
factors from them. A live RT is accepted only after its raw `TxOut` matches one
exact side; a node-provided side is at most a convenience hint. Reissuance uses
the inferred input side's ABF as `asset_blinding_nonce`. The Rust interpreter
must independently enforce the same input recognition, opposite-side output,
and fixed value commitment as the covenant.

## Recovery and composition

The A/B schedule improves public recovery:

- creation recovery requires the normal OP_RETURN parameters and the raw
  creation transaction;
- canonical creation requires both exact side-A commitments;
- a later live side is inferred directly from the asset commitment;
- neither factor history nor outpoint-derived scalar reconstruction is needed.

The side need not be persisted as independent database truth. It can be
derived from stored raw output evidence after restart or rollback. Creation
side A remains a node/client canonicality rule because a covenant executing a
dormant state cannot distinguish initial creation from a later return to that
state.

For composition, each A/B continuation and burn has the same input and output
value commitment. Each canonical binary-market creation is also locally
balanced by the complementary leg CBFs. Surjection proofs must still use the
complete Elements input domain in canonical order. A same-asset A/B generator
collision is structurally excluded by the distinct ABFs; equality across
different, uniquely issued RT assets remains a cryptographic collision
assumption.

## Isolated measurements

The comparison harness measures one RT continuation under each schedule. The
A/B candidate uses prebound commitments and carries an output index plus a
terminal-path bit. The rolling candidate mirrors the current outpoint-derived
rule and additionally carries the input ABF and input CBF. Both fixtures
contain the same broad transaction shape: one confidential RT input, one
explicit decoy input, and one confidential RT output with a rangeproof and
surjection proof.

| Metric | Rolling | A/B complementary CBF |
|---|---:|---:|
| Simplicity cost, milliweight | 669,509 | 90,861 |
| Program bytes | 637 | 480 |
| Witness bytes | 69 | 5 |
| Serialized execution stack bytes | 778 | 557 |
| Padding bytes | 0 | 0 |
| Transaction bytes | 5,257 | 5,036 |
| Transaction weight | 5,842 | 5,621 |
| Transaction vsize | 1,461 | 1,406 |
| Discount weight | 1,471 | 1,250 |
| Discount vsize | 368 | 313 |

These numbers are directional, not full-market fee estimates. They do not
include the complete binary-market program, repeated market input witnesses,
wallet signatures, creation, reissuance fields, or mined Elements validation.
The absolute transaction sizes are dominated by the
isolated Simplicity witness and confidential proofs. Full market savings may
not scale linearly. The machine-readable fixture and live regtest results are
in [`../measurements/rt-blinding-v1.json`](../measurements/rt-blinding-v1.json).

## Live Elements regtest

A dedicated ignored test starts one Elements Core 23.3.3 liquid-regtest daemon
and Electrs instance and runs both schedules serially. Every valid transaction
passed `testmempoolaccept`, broadcast, mining, and confirmation. Both
nonterminal transitions reissue seven units of each underlying asset with the
stored entropy and the current RT input ABF as the actual Elements reissuance
nonce. The sequence uses explicit wallet composition first, confidential wallet
composition second, and ends in confidential opposite-factor bare-OP_RETURN
burns. Removing an RT surjection proof is rejected before broadcast.

| Transaction stage | Rolling vsize | A/B vsize | Rolling discounted vsize | A/B discounted vsize |
|---|---:|---:|---:|---:|
| Creation | 3,899 | 2,766 | 564 | 564 |
| Explicit reissuance | 3,303 | 3,193 | 1,101 | 992 |
| Confidential reissuance | 4,436 | 4,323 | 1,101 | 989 |
| Terminal burn | 3,031 | 2,924 | 829 | 722 |

A/B creation uses only explicit wallet funding/change because the complementary
CBFs balance locally. Rolling creation requires a confidential balancing
change. Across the two RT covenant inputs, nonterminal A/B execution uses about
181 thousand milliweight and 10 witness bytes, versus about 1.339 million and
138 bytes for rolling.

This remains an RT-slice test, not the full binary-market covenant. The micro
covenants validate the RT commitment transition and terminal shape while
Elements consensus validates the nonterminal issuance fields. Full-market path
equivalence remains an acceptance gate below. Exact live byte counts can vary
slightly between runs because the fresh daemon creates new issuance outpoints,
asset IDs, signatures, and proofs; the schedule ordering and isolated fixture
are deterministic. The rolling micro-covenant uses the outpoint-derived next
ABF for its terminal burn, which is a valid but stricter choice than the
production rolling market's arbitrary witness-selected burn factors; terminal
cost figures are therefore not an exact production-path comparison.

## Protocol-independent hardening found by the study

The comparison exposed two correctness gaps in the rolling implementation that
do not depend on accepting the A/B proposal:

- The confirmed-transaction interpreter previously checked only that tracked
  and continuing RT outputs were confidential and used the expected script. It
  now reconstructs the rolling commitments from the decoded covenant witness,
  validates both live inputs, validates the exact outpoint-derived continuation
  commitments, and validates terminal burn commitments.
- Four continuation paths produced a valid BitMachine execution stack that was
  too small for Elements' Simplicity cost-budget rule. Client finalization now
  appends the padding annex returned by the Simplicity cost bound when needed.
  An exhaustive regression covers every market lifecycle path, every sibling
  input, both resolution outcomes, both redemption shapes, and all maker fill
  shapes.

These changes preserve the rolling covenant, CMR, and source-level witness ABI.
They make the existing off-chain interpretation and transaction finalization
match rules that the current covenant and Elements consensus already enforce.

## Security trade-offs

The proposed A/B schedule provides:

- structural inequality between a leg's input and output asset generators;
- no hash-collision or zero-scalar continuation liveness edge case;
- substantially less covenant witness data;
- direct side inference and a smaller Rust/Simplicity mirroring surface;
- local Pedersen balance for creation, continuation, terminal burn, and
  composition; and
- fixed commitments that are straightforward to cover with external golden
  vectors.

The costs and risks are:

- fixed factors and commitment encodings become consensus constants;
- the two-state pattern is publicly recognizable, although RT state and
  factors are intentionally public and provide no privacy today;
- the negative NO CBF, scalar byte order, and all four derived VBFs require
  external golden vectors;
- rangeproof construction must use the side-specific VBF even though the
  side-A and side-B value commitments are byte-identical;
- a terminal confidential `OP_RETURN` output must be demonstrated against
  Elements consensus; and
- the prebound commitment approach must be checked for cost and program-size
  behavior inside the full parameterized market, not only the isolated study.

Rolling factors retain one modest property: every lineage and transition uses
a different-looking ABF rather than one of two protocol-wide values. That does
not currently provide useful confidentiality because the derivation and RT
lineage are public.

## Evidence required before acceptance

This ADR must remain proposed until all of the following are complete:

1. **Complete:** a serial `elementsd` regtest proves canonical A/B
   explicit-only creation,
   `A -> B -> A` reissuance, confidential-wallet composition, and the terminal
   confidential burn through `testmempoolaccept`, broadcast, and mining.
2. The candidate is integrated into an experimental full binary-market
   covenant and every lifecycle path passes the same positive and adversarial
   BitMachine corpus as rolling.
3. The Rust interpreter rejects wrong-side, same-side, wrong-role-CBF, wrong
   value-commitment, and malformed issuance-nonce transactions whenever the
   covenant rejects them.
4. Full-market cost, witness, weight, and vsize measurements replace or
   supplement the isolated continuation figures.
5. Recovery, restart/reorg replay, terminal burns, and custom multi-contract
   compositions pass differential tests.
6. The final constants, algebra, commitment vectors, and migration diff receive
   focused external review.

## Consequences if later accepted

Acceptance would intentionally change the binary-market CMR, witness schema,
creation commitments, golden vectors, builder API, interpreter rules, and
recovery validation. Because Deadcat v1 is not deployed and has no compatibility
requirement, the preferred migration would be a clean replacement rather than
support for both schedules under one contract version.

Until then, none of those production changes follows from this record.

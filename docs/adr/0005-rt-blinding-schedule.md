# ADR 0005: Reissuance-token blinding schedule

- Status: Proposed — engineering evidence complete; human acceptance pending
- Date: 2026-07-13

## Context

Elements requires a confidential reissuance-token (RT) input's asset blinding
factor to be known when the token is used for reissuance. Surjection-proof
construction also requires the continuing output to use an asset generator
different from the generator being spent. Deadcat's RT factors are public
consensus data rather than privacy secrets; their purpose is to make an
anyone-can-continue covenant compatible with those Elements rules.

The binary-market baseline at commit
`ed6de4c4c8a177b4a4ba92c2bac17f55b324781f` uses an outpoint-derived rolling
schedule:

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

## Candidate decision

Replace rolling ABFs in the candidate v1 implementation with two fixed public
ABFs and a constant effective commitment blinder per RT leg. The YES and NO
leg CBFs are additive inverses so canonical two-leg market creation is locally
balanced.

This is **not yet an accepted protocol decision**. The production-shaped
implementation and engineering evidence are complete, but that does not make
the constants final or authorize deployment. ADR acceptance still requires a
focused external review and explicit protocol-owner sign-off.

For the committed golden test parameter set, the candidate binary-market CMR
is:

```text
74031c77c0d4e678913f7a8685425fea07458851e0246496fd3174d734379301
```

That value is parameterized-vector evidence, not a universal CMR for every
market. The rolling baseline remains available at the commit above for an
exact source and covenant/witness diff audit.

## Candidate schedule

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

The candidate covenant infers the input side from its exact asset commitment,
requires the role-specific fixed value commitment, and requires the output to
use the opposite asset commitment with the same value commitment. No factor or
side supplied by a witness is authoritative.

The implementation derives and binds six internal compile-time
commitments from the existing market parameters:

- YES asset generator A, asset generator B, and value commitment;
- NO asset generator A, asset generator B, and value commitment.

These are derived compilation inputs, not independently selectable public
market parameters. Clients and nodes recompile them from the RT asset IDs and
the constants above. Prebinding removes runtime curve generation and outpoint
hashing while preserving the normal CMR/script verification trust model.

Off-chain code exposes typed `RtLeg` and `RtSide` values and derives
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
not scale linearly. The historical machine-readable fixture and RT-slice
regtest results are in
[`../measurements/rt-blinding-v1.json`](../measurements/rt-blinding-v1.json).

## Historical RT-slice Elements regtest

The isolated study at commit `25ad4092293e86d71108cf6d10f490ed4d65dc4b`
starts one Elements Core 23.3.3 liquid-regtest daemon and Electrs instance and
runs both schedules serially. Every valid transaction passed
`testmempoolaccept`, broadcast, mining, and confirmation. Both
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
Elements consensus validates the nonterminal issuance fields. The later
full-market harness supersedes this acceptance boundary. Exact live byte counts can vary
slightly between runs because the fresh daemon creates new issuance outpoints,
asset IDs, signatures, and proofs; the schedule ordering and isolated fixture
are deterministic. The rolling micro-covenant uses the outpoint-derived next
ABF for its terminal burn, which is a valid but stricter choice than the
production rolling market's arbitrary witness-selected burn factors; terminal
cost figures are therefore not an exact production-path comparison.

## Protocol-independent hardening found by the study

The comparison exposed two correctness gaps in the baseline implementation
that do not depend on accepting the A/B candidate:

- The confirmed-transaction interpreter previously checked only that tracked
  and continuing RT outputs were confidential and used the expected script. It
  was hardened on the rolling baseline to reconstruct exact commitments from
  decoded covenant data and to validate both live inputs, continuations, and
  terminal burns. The A/B interpreter now performs the simpler exact-side
  equivalent directly from raw outputs.
- Four continuation paths produced a valid BitMachine execution stack that was
  too small for Elements' Simplicity cost-budget rule. Client finalization now
  appends the padding annex returned by the Simplicity cost bound when needed.
  An exhaustive regression covers every market lifecycle path, every sibling
  input, both resolution outcomes, both redemption shapes, and all maker fill
  shapes.

The first hardening commit preserved the rolling covenant, CMR, and
source-level witness ABI. It established a stronger baseline before the
intentional A/B protocol change. Cost-budget finalization remains part of the
A/B implementation.

## Full-market implementation and local evidence

The candidate is integrated across the production-shaped binary-market stack:

- SimplicityHL receives the two asset commitments and one value commitment for
  each RT role as derived compile-time arguments. It recognizes the raw input
  side, requires the opposite output side, requires the role-specific value
  commitment, and binds each reissuance nonce to the inferred input-side ABF.
- The factor arrays were removed from the market covenant witness. Neither the
  covenant nor the Rust interpreter treats witness-supplied blinders as truth.
- Creation, registration, and independent client replay require both RT legs on
  side A. The unchanged recovery hint supplies the same 38-byte or 70-byte
  payload; A/B adds no field.
- `MarketRtInput` carries the outpoint and exact raw `TxOut`. Builders infer the
  side from that output, require the two live legs to agree, and recheck the
  PSET `witness_utxo` before finalization.
- Continuations and terminal bare-`OP_RETURN` burns use the opposite side.
  Issuance uses the input-side ABF as the exact Elements
  `asset_blinding_nonce` while the output flips.
- Registration and client history replay reject non-A creation commitments.

Local test evidence covers both `A -> B` and `B -> A`, side-A creation, exact
scalar vectors, complementary CBF balance, commitment-to-side round trips,
surjection/rangeproof construction, every binary-market lifecycle builder and
interpreter path, both input sides for every RT-consuming path, sufficient
finalized Simplicity budgets, and focused BitMachine execution of RT-continuing
and terminal shapes.
Commitment golden vectors include nonuniform asset IDs independently derived
with direct libsecp256k1-zkp calls, making an accidental `AssetId` display-order
reversal observable.
Adversarial cases reject same-side output/burn, mixed live sides,
wrong-role CBF/value commitments, wrong input-side reissuance nonces, malformed
creation side, sibling substitution, and designated-output tampering.

The production-shaped live harness additionally mined three markets through 16
transactions. It covers canonical creation, A→B and B→A issuance, confidential
wallet composition, partial/full cancellation, return to Dormant, B-side
Dormant reissuance, YES/NO resolution, active expiry, both terminal flip
directions, and partial/full redemption. Every valid stage passed
`testmempoolaccept`, broadcast, mining, and confirmation; missing and corrupted
surjection proofs were rejected.

Concrete-block sync tests start with no registered contract and exercise
OP_RETURN recovery through `SyncCoordinator + DeadcatInterpreter`, redb reopen,
idempotent replay, and coordinator-driven one-/two-block branch replacement. A
separate two-market transaction proves atomic interpreter/store orchestration.
Exact full-market and live measurements are preserved in
[`../measurements/binary-market-ab-v1.json`](../measurements/binary-market-ab-v1.json)
and the acceptance packet.

The A/B full-market rows are emitted by the committed reporter. The rolling
full-market rows were captured with temporary instrumentation against the
hardened baseline, but that reporter patch was not committed. Those exact rows
are therefore historical capture rather than directly reproducible evidence;
the earlier isolated rolling/A-B harness at `25ad409...` remains reproducible.

## Security trade-offs

The candidate A/B schedule provides:

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
- terminal confidential `OP_RETURN` outputs depend on Elements confidential
  proof behavior and therefore remain consensus-sensitive, although both flip
  directions now pass live Elements regtest; and
- prebinding adds consensus-critical commitment encodings to compilation, so
  literal golden vectors and independent reproduction remain important even
  though full-market cost/program behavior is now measured.

Rolling factors retain one modest property: every lineage and transition uses
a different-looking ABF rather than one of two protocol-wide values. That does
not currently provide useful confidentiality because the derivation and RT
lineage are public.

## Evidence required before acceptance

This ADR must remain Proposed until all of the following are complete. The
full checklist and evidence locations live in
[`../acceptance/binary-market-ab-v1.md`](../acceptance/binary-market-ab-v1.md).

1. **Complete — RT slice:** serial `elementsd` regtest proves A/B
   explicit-only creation, `A -> B -> A` reissuance, confidential-wallet
   composition, and terminal confidential burns through mempool acceptance,
   broadcast, and mining.
2. **Complete — implementation:** the A/B candidate is integrated into the
   full binary-market covenant, builders, interpreter, registration, and client
   replay. The golden test parameter set compiles to the CMR recorded above.
3. **Complete — deterministic local tests:** both directions and all lifecycle
   builder/interpreter shapes are covered, with focused BitMachine and
   adversarial rejection of same-side, mixed-side, wrong-role-CBF/value,
   wrong-nonce, and malformed-creation cases.
4. **Complete — full live lifecycle and measurements:** three
   production-shaped market chains pass Elements mempool acceptance, broadcast,
   mining, and confirmation across every lifecycle class. The deterministic
   corpus emits machine-readable metrics, and one live run preserves txids,
   block hashes, sizes, weights, and proof bytes.
5. **Complete — recovery and orchestration:** zero-seed concrete-block recovery,
   generic chain-verified registration, restart, direct and coordinator-driven
   one-/two-block reorg replay, live wallet composition, and two-market atomic
   indexing pass the candidate corpus.
6. **Pending — review and approval:** the constants, scalar byte order,
   complementary-CBF algebra, derived commitments, CMR change, and clean
   replacement diff must receive focused external review, after which the
   protocol owner must explicitly sign off.

## Consequences if accepted

Acceptance makes the A/B CMR, witness shape, creation commitments, golden
vectors, builder API, interpreter rules, and recovery validation canonical v1.
Deadcat has no deployed rolling markets or databases, so this is a clean source
replacement: there is no rolling compatibility mode, migration path, or redb
schema-version bump. Disposable development databases may be deleted and
reindexed if they contain rolling-era records.

Rolling implementation and comparison-study code have been removed from the
candidate. The hardened baseline commit, isolated-study commit, ADR, and
machine-readable measurements remain the permanent historical reference.

Until external review and explicit protocol-owner approval are recorded, this
ADR remains Proposed and the candidate must not be described as production
ready.

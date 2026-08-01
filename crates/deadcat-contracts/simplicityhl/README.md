# Binary-market SimplicityHL responsibility model

This document defines the responsibility boundary for the binary-market
SimplicityHL covenant. It is a design and review guide, not a description of a
particular source revision. Detailed transaction shapes, encodings, and
consensus assumptions remain in the [v1 protocol specification][protocol-v1].

The central model is:

> Given a compliant creation transaction and a valid current market state,
> every covenant-authorized spend must produce either a valid successor state
> or a valid terminal payout.

The creation transaction proves the base case. The covenant proves the
inductive step for every subsequent state transition. Neither part establishes
the market's safety on its own.

## Goals

The covenant has two primary goals:

1. **Collateral safety:** every reachable market state honors the liabilities
   created by outstanding YES and NO tokens.
2. **Permissionless progress:** no valid transition can poison the market state
   or introduce a new private capability required to continue, settle, expire,
   or redeem the market.

These properties are related but distinct. A market can remain fully
collateralized while its funds are permanently inaccessible. That is a failure
of permissionless progress or redeemability, not an arithmetic shortfall.

## The validated-creation boundary

The Simplicity program does not execute when the initial market outputs are
created and cannot validate that transaction retrospectively. Independent
creation validation is therefore a load-bearing security boundary, not merely
a discovery or indexing convention.

Before treating a market as valid, a node or client must establish from a
confirmed, consensus-valid creation transaction that:

- the YES and NO defining issuances uniquely derive the advertised outcome
  assets and reissuance-token (RT) assets;
- each defining issuance creates no initial outcome-token supply and exactly
  one unit of its RT;
- the complete spendable supply of each RT is locked by the expected dormant
  covenant script;
- both RT outputs use the expected public initial commitments;
- the covenant parameters, derived RT commitments, and locking scripts agree;
  and
- no creator-retained RT authority can issue outcome tokens outside the
  covenant.

The exact creation layout used for automatic discovery may be narrower than
these security conditions. Fixed input and output positions are a profile for
efficient discovery; exhausting the RT supply under the correct scripts is the
load-bearing invariant.

Once this base case is established, control of the complete RT supply lets the
covenant preserve the outcome-token supply and collateral relationship by
induction.

## Collateral-safety invariant

Let `P` be the base payout and let one pair mean one YES token plus one NO
token. A pair is backed by `2P` units of the collateral asset.

The covenant must preserve the following relationships:

- **Dormant:** there are no outstanding pairs and no market collateral.
- **Unresolved:** if `N` pairs are outstanding, the covenant holds exactly
  `2PN` collateral.
- **Resolved YES:** each outstanding YES token has a claim of `2P`; NO has no
  claim.
- **Resolved NO:** each outstanding NO token has a claim of `2P`; YES has no
  claim.
- **Expired:** each outstanding YES and each outstanding NO token has a claim
  of `P`, preserving the original `2P` liability per pair.

The covenant does not need to store `N` directly. Starting from the validated
creation, it preserves the relationship by constraining every operation:

- issuance creates equal, nonzero YES and NO quantities and adds exactly the
  corresponding collateral;
- cancellation burns equal, nonzero YES and NO quantities and releases exactly
  the corresponding collateral;
- resolution authenticates one oracle outcome and carries all collateral
  unchanged into the matching resolved state;
- expiry carries all collateral unchanged into the symmetric expired state;
  and
- redemption releases exactly the liability represented by the explicitly
  burned tokens and preserves any remaining collateral under the correct
  terminal covenant.

All amount and index arithmetic used by a transition must fail on overflow,
underflow, or an impossible zero quantity. No unchecked arithmetic may turn an
invalid transition into a valid one.

## Permissionless progress

The covenant cannot guarantee block inclusion, fee availability, or oracle
cooperation before expiry. It can guarantee that a confirmed market transition
does not create an unintended gatekeeper for future transitions.

Every valid continuing state must therefore be reconstructible and spendable
from public chain data plus the authorization explicitly required by the
protocol. In particular:

- RT asset and value commitments use the public deterministic schedule;
- both RT legs occupy the same schedule side and move to the opposite side
  together;
- no spender can substitute a commitment whose opening is known only to that
  spender;
- every continuation returns each live role to the correct covenant script;
- multi-output market state moves atomically, so a follower cannot be detached
  from or authorize less than its complete coordinator group;
- an oracle attestation selects the outcome but is relayable by anyone; the
  oracle does not acquire exclusive spending authority; and
- after the configured expiry condition is satisfied, terminal progress does
  not require an oracle attestation or another privileged secret.

The deterministic RT blinding schedule is consequently a covenant invariant,
not a wallet implementation detail. Its purpose is public future spendability,
not confidentiality.

## Transition authorization and state integrity

For every path, the Simplicity program is responsible for validating all
market-controlled inputs and outputs that make the transition safe. Depending
on the path, this includes:

- authenticating the executing input's committed market role;
- requiring the exact sibling roles and atomic input grouping;
- binding continuations to the same parameterized covenant instance;
- validating the relevant asset IDs, explicit values, issuance fields, burns,
  and output scripts;
- rejecting issuance on paths that do not explicitly authorize it;
- checking deterministic RT continuation or terminal-burn commitments;
- verifying the oracle's outcome attestation for resolution;
- enforcing the configured lock-height condition for expiry; and
- preventing any transition out of a terminal state except a valid redemption
  or completion.

A follower input may rely on transaction atomicity only after proving that it
belongs to the exact coordinator group. Witness-selected path data must not let
a follower authorize an unrelated or incomplete transition.

## Static instance assumptions

Market parameters and compiler-derived constants are committed by the
parameterized program and can be verified before anyone accepts or funds the
market. The compiler and creation verifier are responsible for establishing
static instance facts such as:

- valid and distinct collateral, outcome-token, and RT asset identities;
- a valid oracle public key;
- correct derivation of both oracle messages from the outcome-token identities
  and the protocol domain;
- correct derivation of the public RT commitments from the RT asset IDs;
- a positive base payout whose per-pair collateral is representable; and
- an expiry value with the advertised block-height semantics.

The covenant must still use checked arithmetic and enforce the configured
values on every applicable transition. Repeating a static profile check during
every spend is not a substitute for validating the instance and creation
transaction.

## Responsibilities outside SimplicityHL

The following concerns do not determine whether a spend preserves collateral
safety or permissionless progress and should remain outside the covenant:

- recovery-hint presence, layout, and encoding;
- membership in a list of canonical payout denominations;
- well-known collateral-asset tables;
- the standalone creation layout used for automatic discovery;
- registration packages, activation checkpoints, indexing, history replay,
  and API representations;
- wallet input selection, fee funding, proof construction, and transaction
  broadcast;
- human-readable questions, categories, event descriptions, and other social
  market metadata; and
- transaction standardness, miner inclusion, and resistance to chain-level
  censorship.

Official software may reject or decline to discover an otherwise safe market
that does not follow a supported profile. That is an interoperability decision,
not a reason to make the market's covenant outputs unspendable.

## Where a check belongs

Classify each proposed check with these questions, in order:

1. **Can the violation first be introduced by a spend from a valid state?**
   If so, and it can break collateral safety, authorization, state integrity,
   or permissionless progress, the check belongs in SimplicityHL.
2. **Is it required to establish the initial state or the correctness of fixed
   program parameters?** If so, it belongs in compiler and creation validation,
   with independent verification before the market is accepted.
3. **Does it only determine whether software can discover, encode, index, or
   advertise the market under a supported profile?** If so, it belongs in
   tooling and protocol policy rather than SimplicityHL.

When a condition spans boundaries, each layer should enforce only its own part.
For example, the creation verifier establishes the initial deterministic RT
commitments, while the covenant ensures that every later RT continuation uses
the public deterministic schedule.

## Conformance evidence

After a SimplicityHL revision is complete, its review should map each invariant
above to:

- the covenant function or dispatch rule that enforces it;
- an independent interpreter check;
- at least one successful lifecycle test; and
- adversarial tests showing that omission or mutation of the relevant input,
  output, amount, asset, commitment, authorization, or sibling relationship is
  rejected.

That mapping is revision-specific and should not be folded into this stable
responsibility model. Golden CMRs, witness encodings, path numbers, and function
line references belong in versioned conformance evidence and the detailed
protocol specification.

[protocol-v1]: ../../../docs/protocol-v1.md

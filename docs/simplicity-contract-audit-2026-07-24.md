# Simplicity Contract Audit — 2026-07-24

## Status and scope

This document records an internal source-level audit of the two SimplicityHL
contracts in this repository:

- [`binary_market.simf`](../crates/deadcat-contracts/simplicityhl/binary_market.simf)
- [`maker_order.simf`](../crates/deadcat-contracts/simplicityhl/maker_order.simf)

The audited revision was `3efcc11` on branch
`codex/canonical-maker-orders`.

The review also covered the Rust compilers, builders, interpreters,
registration logic, independent client replay, and node atomic-batch handling.
Those components are part of the effective security boundary because neither
contract executes when its creation output is made, and several canonicality
rules are intentionally enforced outside Simplicity.

This consolidated report incorporates a second source pass completed on
2026-07-25. That pass rechecked the first-pass findings against the pinned
Simplicity and Elements implementations and exercised targeted adversarial
transactions in the BitMachine environment. Its verified results are folded
into the relevant sections below rather than retained as a separate report.

This is not a formal proof or an external security audit. The conclusions are
based on source inspection, comparison with the pinned Simplicity transaction
environment, and the daemon-free test suites listed under
[Verification](#verification).

### Document lifecycle

**Status:** Active audit record.

This report describes revision `3efcc11`; it is a historical security record,
not the normative protocol specification. Findings should be updated with links
to their fix, accepted-risk decision, or other disposition.

Mark this report **Superseded** when:

- every finding has a documented disposition;
- permanent regression coverage exists for the corrected behavior;
- surviving protocol boundaries and operational guidance have been incorporated
  into the protocol, ADR, or acceptance documentation; and
- a later audit covers the then-current contracts.

Delete it only when a replacement report preserves a finding-by-finding
disposition mapping, no repository documents link here, and this report
contains no unique security rationale or verification evidence. Otherwise,
retain it as a historical audit record.

## Executive summary

The core arithmetic and state-transition equations are sound for canonically
created and registered contracts. The review did not find a direct
under-collateralized issuance path, maker-underpayment path, arithmetic
wraparound, zero-progress fill, or unauthorized market key-spend path within
that supported envelope.

The review found:

| Severity | Count | Summary |
|---|---:|---|
| High | 2 | Expiry covenant/interpreter disagreement; incomplete independent maker replay |
| Medium | 2 | Chosen-key payment aliasing; receive/cancellation key compromise coupling |
| Low or scoped | 6 | Foreign-order semantic mismatch, generic liveness edge, same-script deposit aliasing, builder/policy/version issues |

Counts follow the finding IDs. L-3 is included in the Low or scoped row even
though its API-footgun severity can rise toward Medium depending on how callers
interpret the helper's canonicality promise.

The most urgent defect is a mismatch between the actual semantics of
Simplicity's `check_lock_height` jet and the Rust interpreter. A permissionless
expiry transaction can satisfy the covenant and confirm on chain while being
rejected by the node and client interpreters.

The principal intentional economic risk is that maker orders are
good-until-cancelled covenants. They remain consensus-fillable after their
parent market resolves or expires, including in the same transaction that
terminates the market.

The second pass found no new theft or insolvency path inside the canonical
supported state. It did show that an untracked deposit to an existing maker
script can share the tracked order's payment or continuation output. Any extra
extraction is bounded by the untracked deposit, but makers must cancel and
recreate orders rather than top up their public covenant scripts. It also
demonstrated how duplicate market states could alias issuance and redemption
outputs if the creation-time reissuance-token supply checks ever regressed.

## Severity-ranked findings

### H-1: Covenant-valid expiry transactions can be rejected by Deadcat

**Severity:** High

**Disposition:** Remediation is proposed in
[PR #11](https://github.com/Resolvr-io/deadcat-node/pull/11). It makes the
shared interpreter reproduce the transaction-global `check_lock_height`
predicate and retains covenant/interpreter regressions for a non-final
follower, all-final inputs, and a time-typed lock. Mark this finding resolved
when that PR merges.

**Affected components:**

- [`binary_market.simf`](../crates/deadcat-contracts/simplicityhl/binary_market.simf#L574-L616)
- [`interpret/binary_market.rs`](../crates/deadcat-contracts/src/interpret/binary_market.rs#L984-L996)
- [`sync.rs`](../crates/deadcat-node/src/sync.rs#L473-L476)
- Independent client history replay, which uses the same interpreter

#### Contract behavior

Both expiry transitions call:

```text
jet::check_lock_height(param::EXPIRY_HEIGHT)
```

The pinned Simplicity transaction environment defines the effective lock
height as the transaction's `nLockTime` when:

1. `nLockTime < 500_000_000`, so it is height-typed; and
2. the transaction is not final.

For this jet, the transaction is non-final when **any input** has a sequence
below `0xffffffff`. The condition is transaction-global; it is not tied to the
input currently executing the program.

The Rust interpreter instead checks:

```rust
if transaction.lock_time.to_consensus_u32() < expiry || input.sequence.is_final() {
    return Err(InterpretError::Inconsistent("expiry locktime"));
}
```

Here, `input` is the YES coordinator at `input_base`. The interpreter therefore
requires that particular input to be non-final.

The interpreter also compares `nLockTime` only numerically. It does not reject a
time-typed `nLockTime >= 500_000_000`, although `check_lock_height` treats that
as having an effective height of zero.

#### Reproduction

For an active expiry, construct a transaction with:

```text
nLockTime = expiry_height
YES coordinator sequence = 0xffffffff
NO follower sequence = 0xfffffffe
collateral follower sequence = 0xffffffff
```

The transaction-wide non-final sequence activates the height lock. The
Simplicity coordinator accepts the expiry, as do the path-independent follower
programs. The Rust interpreter looks only at the YES coordinator's final
sequence and returns `InterpretError::Inconsistent`.

The dormant expiry has the same issue with a final YES coordinator and
non-final NO follower.

#### Impact

Expiry is permissionless. An attacker does not need a private key or oracle
signature to construct the mixed-sequence transaction.

Once such a spend confirms:

- the tracked market outpoints are gone;
- canonical node synchronization returns `SyncError::Interpretation`;
- client replay rejects the real, confirmed history; and
- the locally tracked state cannot advance to the on-chain expired state.

This is an inexpensive contract-specific indexing and availability failure,
not a direct collateral theft.

The official builder does not expose the issue because
[`prepare_expiry`](../crates/deadcat-client/src/market_builder.rs#L484-L508)
sets every contract input to a non-final sequence, and
[`verify_expiry`](../crates/deadcat-client/src/market_builder.rs#L769-L799)
requires all contract inputs to remain non-final. A custom transaction is not
bound by that stricter builder policy.

#### Recommended correction

Make the Rust interpreter reproduce the jet exactly:

```rust
let locktime = transaction.lock_time.to_consensus_u32();
let has_nonfinal_input = transaction
    .input
    .iter()
    .any(|input| !input.sequence.is_final());

if locktime < expiry || locktime >= 500_000_000 || !has_nonfinal_input {
    return Err(InterpretError::Inconsistent("expiry locktime"));
}
```

The builder may continue enforcing the stricter all-contract-inputs-non-final
policy, but the confirmed-transaction interpreter must accept every
covenant-valid arrangement.

#### Recommended regression

The narrowest red-to-green regression belongs beside the active-expiry tests in
[`tests/interpret.rs`](../crates/deadcat-contracts/tests/interpret.rs#L478-L645):

1. Refactor `finalized_active_expiry` to accept three input sequences.
2. Build the mixed sequence array
   `[Sequence::MAX, Sequence(0xffff_fffe), Sequence::MAX]`.
3. Finalize or execute the YES coordinator Simplicity program against that
   exact PSET. This proves the covenant accepts the transaction.
4. Extract the transaction with the generated witness.
5. Pass it to `interpret_binary_market_spend`.
6. Require a successful `BinaryMarketPath::ActiveExpiry` interpretation.

Before the interpreter correction, step 6 fails with the expiry-locktime
inconsistency. After the correction, the same test passes without changing the
fixture.

An additional negative case should set all three sequences to `Sequence::MAX`
and require both covenant execution and interpretation to reject the expiry.

### H-2: Independent maker replay does not prove canonical identity or parent

**Severity:** High

**Affected components:**

- [`validation.rs::replay_contract_history`](../crates/deadcat-client/src/validation.rs#L398-L480)
- [`validation.rs::replay_maker`](../crates/deadcat-client/src/validation.rs#L517-L616)

#### Current behavior

Independent replay validates that:

- the supplied creation transaction is in the caller-verified canonical block;
- the nominated output exists;
- the output script matches the supplied maker parameters;
- the asset, value, explicit form, and initial capacity are coherent; and
- subsequent spends reproduce the reported state and live outpoints.

It does not:

- rederive `instance_id` from the creation input set and nominated vout;
- validate the required adjacent recovery hint;
- require replay-validated evidence for the parent market;
- prove that the supplied parent view itself exists on chain; or
- enforce the network activation checkpoint used by registration.

`replay_contract_history` accepts `Option<&ContractView>` for the parent.
[`validate_order_against_parent`](../crates/deadcat-client/src/validation.rs#L155-L201)
checks structural and economic consistency, but a raw `ContractView` is not
evidence that the parent was canonically created or replayed.

Node registration correctly rederives the instance identity at
[`registration.rs`](../crates/deadcat-node/src/registration.rs#L662-L673) and
checks the parent and recovery hint at
[`registration.rs`](../crates/deadcat-node/src/registration.rs#L674-L778).

The existing test
[`maker_creation_replay_uses_the_exact_nominated_output`](../crates/deadcat-client/src/validation.rs#L1791-L1865)
constructs a zero-input transaction containing two identical order outputs and
expects either vout to replay independently. Canonical instance derivation
explicitly rejects an empty creation-input set.

#### Impact

A malicious hosted node cannot forge canonical block contents, but it can point
the client at a real, confirmed foreign output with an arbitrary or reused
instance ID, attach it to an invented-but-coherent parent view, and obtain a
`ValidatedContractReplay`.

The individual foreign covenant still enforces the displayed price. The defect
is a failure of the independent validation boundary: an unsupported foreign
contract is represented as a canonical Deadcat replay even though normal node
registration rejects it.

#### Recommended correction

- Rederive `instance_id` from every creation prevout plus
  `contract_id.vout()`.
- Reject zero-input creation and mismatched instance IDs.
- Decide one recovery-hint policy and apply it consistently in registration and
  replay.
- Accept a replay-validated parent type, or accept and validate the parent's
  complete creation/history evidence in the same call.
- Include the immutable activation anchor in replay validation for both
  contract families.
- Replace the zero-input/duplicate-output success test with rejection tests.

### M-1: Chosen maker keys defeat cross-order payment-output uniqueness

**Severity:** Medium

**Affected components:**

- [`maker_order/compiled.rs`](../crates/deadcat-contracts/src/maker_order/compiled.rs#L30-L50)
- [`maker_order.simf`](../crates/deadcat-contracts/simplicityhl/maker_order.simf#L67-L84)
- [`interpreter.rs::validate_atomic_claims`](../crates/deadcat-node/src/interpreter.rs#L378-L408)
- The uniqueness claim in
  [`protocol-v1.md`](protocol-v1.md#fill-layout)

#### Current derivation

The receive key is derived by a public additive tweak:

```text
Qreceive = even(Pmaker) + Hreceive(instance_id)G
```

The covenant commits to the hash of the resulting receive script, not directly
to `maker_pubkey` or `instance_id`.

#### Chosen-key construction

For a target receive x-only key `Q` and a candidate canonical instance tweak
`t`, a creator can compute candidate public points:

```text
P =  Q - tG
P = -Q - tG
```

The creator can grind canonical creation inputs until one candidate has the
required even lift, then use that x-only point as `maker_pubkey`. Registration
does not require proof of possession of the maker private key.

The resulting canonical order has a different instance ID and covenant output
but the same maker receive script as the target order.

Two suitably arranged full fills can nominate one exact payment output. Both
covenants accept it. Node atomic-batch validation rejects duplicate spent and
continuation outpoints, but does not reject duplicate payment-output claims.
Both histories can consequently record the same consideration.

#### Impact

This is principally an accounting and integrity issue:

- one output can be counted as payment for multiple fills;
- reported volume and consideration can be inflated; and
- the protocol's documented global receive-script uniqueness claim is false
  against adversarially chosen maker keys.

It is not a direct theft from an honest maker. A colliding order must contribute
its own locked asset, and the shared payment still goes to the target receive
key.

#### Recommended correction

Use one or more of:

- bind the base maker key into a nonlinear tweak, for example
  `H(domain || maker_pubkey || instance_id)`;
- require proof of possession of `maker_pubkey` during canonical registration;
- detect duplicate maker-payment output claims across one interpreted atomic
  batch; and
- adjust the protocol text so canonical instance uniqueness is not treated as
  sufficient by itself.

### M-2: Receive and cancellation keys are not compromise-isolated

**Severity:** Medium operational risk

**Affected components:**

- [`deadcat-client/src/keys.rs`](../crates/deadcat-client/src/keys.rs#L109-L164)
- [`maker_order/compiled.rs`](../crates/deadcat-contracts/src/maker_order/compiled.rs#L30-L50)

Both private keys have the form:

```text
cancel_secret  = normalized_maker_secret + public_cancel_tweak
receive_secret = normalized_maker_secret + public_receive_tweak
```

Anyone who obtains either child private scalar can subtract its public tweak,
recover `normalized_maker_secret`, and derive the other child private key.

A receive-key leak can therefore be converted into cancellation authority over
the live order remainder. A cancellation-key leak also compromises the maker's
receive outputs.

The domain tags provide address separation, but not compromise isolation.
Documentation and key-handling code should not treat one path as hot and the
other as cold unless they are derived from independent private branches.

If compromise isolation is desired, cancellation and receive keys should use
separate hardened/private derivation branches or independently generated base
keys. Merely adding more public data to an additive tweak does not prevent
recovery of the common base scalar from a leaked child scalar.

### L-1: Foreign `SellQuote` remainder semantics differ from the interpreter

**Severity:** Low; unreachable from canonical creation

The partial `SellQuote` covenant checks:

```text
input_quote = filled_base * price + remainder_quote
remainder_quote >= min_active_base * price
```

See
[`maker_order.simf`](../crates/deadcat-contracts/simplicityhl/maker_order.simf#L121-L152).
It does not require `remainder_quote % price == 0`.

The Rust economics/interpreter rejects a non-integral remainder at
[`maker_order.rs`](../crates/deadcat-contracts/src/maker_order.rs#L204-L227).

For example:

```text
price = 7
minimum = 3
input_quote = 71
filled_base = 4
remainder_quote = 43
```

The covenant equations pass, but `43 % 7 != 0`, so the Rust interpreter rejects
the spend.

Canonical creation requires the initial locked quote to be an exact price
multiple. The partial-fill equation

```text
filled_base * price + remainder_quote = input_quote
```

implies `remainder_quote ≡ input_quote (mod price)`, so every canonical
transition preserves divisibility inductively. The Rust divisibility check is
therefore redundant defense for canonical orders. The mismatch affects directly
funded or otherwise unsupported foreign instances, not registered orders.

The contract and interpreter should nevertheless either agree on the full
primitive semantics or explicitly document that interpreter support is limited
to the canonical divisible state space.

### L-2: Some generic `SellBase` instances have no script-path fill

**Severity:** Low; prevented by canonical parent economics

Generic maker-order creation validates nonzero price, nonzero minimum, distinct
assets, and capacity at least the minimum. For `SellBase`, it does not establish
that at least one fill can satisfy checked multiplication and the two-sided
minimum rule.

Example:

```text
price = 2^32 - 1
minimum = 2^32 - 1
locked base = 2^32 + 2
```

- A full fill overflows `locked_base * price`.
- A partial fill is impossible because the input is less than
  `2 * minimum`, so fill and remainder cannot both meet the minimum.

Only maker key-path cancellation remains.

Canonical Deadcat parent validation caps price at the market's collateral per
pair, which prevents this shape. The generic builder/compiler still accepts it.
If the maker primitive is intended to be safe independently of a parent, its
creation validation should prove that a full or partial fill exists.

### L-3: The maker creation helper can construct node-rejected orders

**Severity:** Low to medium API footgun

[`maker_order_creation_outputs`](../crates/deadcat-client/src/maker_builder.rs#L22-L59)
is described as constructing canonical creation outputs, but it receives no
verified parent market. It cannot validate:

- outcome side against the parent's YES/NO asset;
- quote asset against parent collateral;
- price against parent collateral per pair; or
- recovery-hint parent and side against the actual parent.

Node registration enforces these relationships later. A caller can therefore
construct and broadcast an output through the canonical helper that the node
will refuse to register.

The helper should accept validated parent parameters and side, or its naming
and documentation should make clear that it creates only locally well-formed,
not registerable/canonical, outputs.

### L-4: Recovery-hint policy is inconsistent

**Severity:** Low

[`ADR 0002`](adr/0002-v1-contract-scope.md#compatibility-policy) says recovery
hints are advisory and that manual registration can track an otherwise
canonical contract without one.

Maker registration unconditionally requires an adjacent matching hint at
[`registration.rs`](../crates/deadcat-node/src/registration.rs#L750-L778).
Independent client replay checks no hint at all.

As a result, the sets of:

- covenant-valid orders;
- client-replay-accepted orders; and
- node-registerable orders

are different in a way the documented policy does not describe.

### L-5: The Simplex version guard uses substring matching

**Severity:** Low

[`build.rs`](../crates/deadcat-contracts/build.rs#L3-L21) accepts a compiler
version when:

```rust
version.contains("0.0.6")
```

Versions such as `0.0.60` or unrelated output containing that substring pass
the guard. Nix pinning and golden CMR vectors mitigate this in the supported
build environment, but an exact parsed version comparison would make
out-of-environment builds safer and more reproducible.

### L-6: Untracked same-script deposits can reuse maker outputs

**Severity:** Low; extra extraction is bounded by an untracked deposit

**Affected components:**

- [`maker_order.simf`](../crates/deadcat-contracts/simplicityhl/maker_order.simf#L67-L181)
- [`interpreter.rs`](../crates/deadcat-node/src/interpreter.rs#L445-L481)
- The fill-layout uniqueness discussion in
  [`protocol-v1.md`](protocol-v1.md#fill-layout)

Each maker execution reads its held amount from the current input but selects
its maker-payment and optional continuation outputs by witness indices. If a
transaction spends two inputs carrying the exact same order script, both
executions can name the same outputs.

For a `SellBase` order with price 7, minimum 3, and two 10-BASE inputs, both
full-fill executions accept:

```text
maker payment: 70 QUOTE
taker output:  20 BASE
both witnesses: PAYMENT_INDEX = 0, REMAINDER_INDEX = 1,
                IS_PARTIAL = false
```

Both inputs independently require a 70-QUOTE payment and count the same output.
A partial variant can likewise share both outputs:

```text
maker payment: 28 QUOTE
continuation:   6 BASE at the order script
taker output:  14 BASE
both witnesses: PAYMENT_INDEX = 0, REMAINDER_INDEX = 1,
                IS_PARTIAL = true
```

Each execution interprets the shared 6-BASE continuation as a four-unit fill
and accepts the same 28-QUOTE payment.

A canonical order has one tracked live outpoint. Registration and history
interpretation identify contracts by exact outpoint, not merely by script, so a
second same-script UTXO is an untracked deposit rather than a second canonical
continuation. The node records the fair transition of the tracked order and
ignores the foreign input; tracked state and volume are not duplicated.

This shares M-1's general output-claim aliasing pattern but is operationally
distinct. Detecting duplicate payment claims across the node's interpreted
batch does not see the foreign input, because that input is not tracked or
interpreted as another canonical order.

Immediate extra extraction is at most the held-asset value contributed by
untracked same-script inputs. Equality is attainable when the alias releases
their complete balance, but is not guaranteed for every full/partial layout.
An attacker funding the extra input cannot thereby create profit. The party at
risk is someone who mistakenly tops up an order address and does not
participate in the sweep.

Canonical tooling and protocol documentation should therefore:

- retain exact-outpoint tracking;
- state that resizing requires cancellation and recreation, never a top-up;
- surface matching but untracked deposits separately where useful; and
- add full- and partial-fill boundary tests for the shared-output behavior.

Discovery must not reject an otherwise canonical order merely because another
UTXO exists at its public script: anyone could otherwise dust the script and
disable the order. If structural covenant-level uniqueness is required, the
fill leaf can instead scan the current transaction for another input carrying
its script, subject to an explicit Simplicity budget measurement.

## Contract behavior

### Binary market

The binary market is a fully collateralized YES/NO pair issuer. Its basic
economics are:

```text
collateral_per_pair = 2 * base_payout

oracle resolution:
    winning token redeems 2 * base_payout
    losing token redeems 0

expiry:
    YES redeems base_payout
    NO redeems base_payout
```

`base_payout` is restricted to the sixteen values represented by the v1
recovery format. `expiry_height` must be in
`1..500_000_000`.

#### Static slots

Eight Taproot slots encode the market roles:

| Slot | Role |
|---:|---|
| 0 | Dormant YES reissuance token; coordinator |
| 1 | Dormant NO reissuance token; follower |
| 2 | Unresolved YES reissuance token; coordinator |
| 3 | Unresolved NO reissuance token; follower |
| 4 | Unresolved collateral; follower |
| 5 | YES-resolved collateral |
| 6 | NO-resolved collateral |
| 7 | Expired collateral |

The slot is committed through a hidden TapData leaf. Every role shares the same
parameterized program CMR but has a distinct Taproot script.

Dormant state spends two adjacent transaction inputs. Both inputs must reference
outputs from the same previous transaction, but their previous vouts need not
be consecutive. The dormant-group helper intentionally compares only the two
previous transaction IDs; its currently bound-but-unused vout locals are code
hygiene candidates, not a missing adjacency check.

Unresolved state spends three adjacent transaction inputs. The previous
outpoints must share a transaction ID and use consecutive vouts.

Within each sibling group, the YES RT is the fixed coordinator. Followers
dispatch by their committed slot and require their exact coordinator sibling
group, while the coordinator validates the complete transition. All roles
nevertheless receive the program-wide witness shape described below. Canonical
creation supplies the separate global fact that only one live RT group exists;
the covenant proves group completeness, not the absence of a second independent
group elsewhere in the transaction.

#### Reissuance-token commitments

Each RT is held as a deterministic confidential one-unit commitment. Public
side-A and side-B asset blinding factors are paired with side-independent
one-unit value commitments.

Every market transition flips both RTs from A to B or B to A. Issuance must use
the consumed side's asset blinding factor as its reissuance nonce. Terminal
resolution and expiry also flip the commitments before placing them at a bare
`OP_RETURN` burn output.

The A/B schedule:

- proves the exact RT commitment shape;
- binds reissuance authorization to the consumed RT side;
- requires YES and NO to remain on the same side; and
- prevents a transition from silently preserving or substituting a malformed
  RT commitment.

#### Spend paths

| Path | From | Required effect | Result |
|---:|---|---|---|
| 0 | Dormant | Reissue equal nonzero YES/NO pairs and lock exact collateral | Unresolved |
| 1 | Unresolved | Reissue equal additional pairs and add exact collateral | Unresolved |
| 2 | Unresolved | Burn equal nonzero YES/NO pairs and release matching collateral | Unresolved with positive remainder |
| 3 | Unresolved | Burn every outstanding YES/NO pair and release all collateral | Dormant |
| 4 | Unresolved | Verify oracle outcome, burn both RTs, preserve collateral | Resolved YES or NO |
| 5 | Dormant | Verify oracle outcome and burn both RTs | Terminal with no collateral |
| 6 | Unresolved | Satisfy expiry height, burn both RTs, preserve collateral | Expired |
| 7 | Dormant | Satisfy expiry height and burn both RTs | Terminal with no collateral |
| 8 | Resolved | Burn winning tokens and release `2 * base_payout` each | Same resolved slot or complete |
| 9 | Expired | Burn either token and release `base_payout` each | Expired slot or complete |

Checked addition, subtraction, and multiplication reject overflow and
underflow. Partial cancellation must leave positive collateral. Redemption must
burn a positive number of tokens.

The oracle signs a tagged market/outcome message rather than the spending
transaction. The market ID is `SHA256(YES_TOKEN_ID || NO_TOKEN_ID)`, and the
outer oracle-attestation hash is domain-tagged over that market ID and the
outcome. The message does not separately include the payout, expiry, collateral
asset, or oracle public key. This is not an exploitable ambiguity in the
canonical model: the unique token IDs and live RT authority select one
parameterized market program, and signature verification inherently selects
the oracle key. Signing the full parameter tuple would be optional
defense-in-depth and a protocol-compatibility choice, not a required correction.

#### Creation solvency boundary

The covenant does not execute when its initial outputs are created. Creation
validation is therefore a solvency boundary, not merely discovery metadata.

Registration and independent market replay must establish:

- one unique canonical new issuance for each YES/NO leg;
- null initial outcome-token amount;
- one explicit RT unit issued per leg;
- the expected derived outcome-token and RT asset IDs;
- one exact side-A confidential value-one RT output per leg; and
- no retained positive RT authority elsewhere in the creation transaction.

The current market registration and client replay implement these checks.
Without them, a creator could retain RT authority outside the market and issue
unbacked claims without corresponding collateral.

The covenant can inspect the current transaction and its input UTXOs, but it
cannot fetch and open the complete transaction that created those UTXOs. Asset
IDs cryptographically bind the defining issuance identity, not the initial
outcome-token quantity, total RT quantity, or complete creation-output layout.
A dormant state is also not proof of a first spend because full cancellation
returns the market to that state. These facts make creation validation a
permanent off-chain boundary rather than a check that can be deferred to the
first covenant execution.

At the audited revision, both enforcement paths explicitly require:

```text
asset_issuance.amount == Value::Null
asset_issuance.inflation_keys == Value::Explicit(1)
```

No direct negative regression was found for either quantity predicate. Both
are load-bearing: a positive initial outcome-token amount creates unbacked
claims immediately, while excess RT quantity leaves authority that can reissue
claims later. Node registration and independent client replay should each
receive mutation tests for both predicates, ideally as part of a table that
independently falsifies every creation-validity conjunct.

Targeted covenant execution also established two consequences outside the
supported boundary:

- Two dormant RT pairs can each act as a complete sibling group while both
  coordinators select one shared issuance output window. Each group validates
  locally, so one collateral output can be counted against both reissuances.
- Two terminal collateral inputs can count one token-burn output twice. For
  example, a partial redemption of 600 units and a full redemption of 400
  units can share one two-token burn while continuing 200 units.

Neither construction yields theft from a canonically created market. The first
requires excess RT authority that the validators reject; that authority could
already reissue outside the covenant more simply. In the second, an additional
terminal UTXO is merely an untracked collateral donation unless duplicate
canonical liabilities were first created through a broken supply boundary.
The examples demonstrate why the creation checks are load-bearing; they are not
independent live vulnerabilities.

The Simplicity source itself validates payout and expiry parameters. The Rust
compiler additionally validates the oracle x-only key and requires collateral,
outcome-token, and RT asset IDs to be distinct at
[`binary_market/compiled.rs`](../crates/deadcat-contracts/src/binary_market/compiled.rs#L170-L195).
Bypassing that wrapper creates an unsupported foreign program.

### Maker order

A maker order is a persistent, exact-price limit order with two Taproot spend
classes.

#### Maker key path

The instance-derived cancellation key is the Taproot internal key. A valid key
spend is interpreted as cancellation. The covenant does not constrain
cancellation outputs.

#### Permissionless fill path

The Simplicity path requires:

- no issuance on the order input;
- an explicit input asset and amount;
- a witness-selected maker-payment output;
- an explicit full/partial branch;
- a distinct witness-selected remainder index; and
- for a partial fill, an exact same-script continuation.

For `SellBase`:

```text
input asset = BASE
maker payment asset = QUOTE

full:
    filled_base = input_base
    maker_payment = filled_base * price
    filled_base >= minimum

partial:
    filled_base = input_base - remainder_base
    maker_payment = filled_base * price
    filled_base >= minimum
    remainder_base >= minimum
```

For `SellQuote`:

```text
input asset = QUOTE
maker payment asset = BASE

full:
    maker_payment_base * price = input_quote
    maker_payment_base >= minimum

partial:
    maker_payment_base * price + remainder_quote = input_quote
    maker_payment_base >= minimum
    remainder_quote >= minimum * price
```

The maker payment must use the instance-derived receive script. A partial
remainder must reproduce the exact input covenant script. A full fill creates
no continuation.

The covenant does not constrain the taker's receive output. Transaction-wide
asset conservation supplies the complementary side of the exchange.

#### Canonicality boundary

The generic compiler accepts any 32-byte `instance_id`. Canonical builders and
registration derive it from the sorted creation prevout set plus the reserved
order-output vout.

The contract does not itself inspect:

- its parent market ID or state;
- outcome side;
- parent collateral;
- parent price bounds;
- its creation transaction; or
- recovery metadata.

These are registration and client-validation responsibilities.

Canonicality is attached to a live outpoint, not to exclusive ownership of a
script address. Anyone can send another output to a known order script. Such an
output may satisfy the covenant when spent, but it is not automatically adopted
as order state by the node or independent replay. This distinction bounds the
same-script alias in L-6 without making the public script dustable as a
registration or discovery rule.

### Witness shape and transaction identity

The binary-market program reads its complete witness shape before dispatching
by role and path. Followers and redemptions consequently carry values for
unused fields, including the 64-byte oracle signature. This is witness-size and
unquantified execution-budget overhead, not a semantic defect.

Some unused path-specific words admit multiple valid witness encodings. In
particular, a full maker fill does not inspect the nominated remainder output;
it only requires `REMAINDER_INDEX != PAYMENT_INDEX`. Different distinct
remainder words can therefore produce alternative valid witnesses.

Elements excludes transaction witnesses from the transaction ID. Rewriting
such a word changes the **wtxid**, not the **txid**. Output outpoints remain
unchanged and unconfirmed descendants remain valid. The practical consequence
is limited to systems that pin or display the raw witness or wtxid before
confirmation; it is not transaction-chain invalidation.

## Atomic orchestration

The contracts are designed to compose with unrelated wallet inputs, outputs,
and other contracts.

Binary-market input and output groups use witness-selected contiguous windows.
Maker orders independently select payment and remainder outputs. Global input
or output position zero has no special contract meaning.

Possible atomic arrangements include:

### Batched maker fills

Multiple independent maker inputs can be filled in one transaction. Each order
normally selects its own maker-payment output and, when partial, its own
continuation.

The chosen-key collision in [M-1](#m-1-chosen-maker-keys-defeat-cross-order-payment-output-uniqueness)
is the exception to the claimed global payment-output isolation.

### Direct order crossing

A `SellBase` order can supply the BASE used as maker payment for a compatible
`SellQuote` order. The `SellQuote` order's released QUOTE can simultaneously
fund the `SellBase` maker payment.

No newly created output is spent inside the transaction. The composition works
through transaction-wide asset balance and the constraints imposed by both
inputs.

### Issuance plus order fill

Newly reissued outcome tokens can fund the maker payment for an existing
`SellQuote` order. The quote collateral released by that order can contribute
to the market's required collateral continuation.

### Cancellation plus order fills

Outcome tokens released by compatible `SellBase` orders can fund the equal
YES/NO burn outputs required by a market cancellation. Collateral released from
the market can fund the maker-payment outputs.

### Redemption plus order fill

A winning token locked in a `SellBase` order can contribute to the market's
redemption burn. The collateral released by redemption can fund the order's
maker payment.

### Market termination plus stale order fill

Resolution or expiry and one or more maker fills may occur in the same
transaction. The order does not inspect the parent transition and remains
independently valid.

### Signature anchoring

An atomic transaction containing only covenant-controlled inputs may contain no
signature that commits to the unconstrained taker or change outputs. Another
party can copy and rebuild such a transaction while preserving every covenant
constraint but redirecting unconstrained surplus.

When the initiator's payout matters, the composition should include at least
one wallet-controlled input signed with a transaction-wide sighash such as
`SIGHASH_ALL`, or an equivalent signed anchor.

## Intentional design risks

These behaviors are not implementation bugs, but they materially affect the
security and economic model.

### Orders remain fillable after parent termination

The maker covenant is good until cancelled. It does not consume a live parent
UTXO on every fill.

After the outcome is known:

- an underpriced winning-token `SellBase` order can be filled before the maker
  redeems or cancels; and
- a `SellQuote` order can be filled with a losing token that has little or no
  economic value.

The fill can be composed with the parent resolution or expiry itself. Official
routing stops after observing a terminal parent, but that is policy rather than
consensus protection.

This is explicitly documented in
[`protocol-v1.md`](protocol-v1.md#parent-market-terminal-state) and
[`ADR 0002`](adr/0002-v1-contract-scope.md#order-responsibility).

### Expiry opens a path; it does not force termination

Reaching `expiry_height` makes the permissionless expiry path available. It
does not close:

- oracle resolution;
- issuance;
- partial or full cancellation; or
- any other otherwise valid unresolved-state transition.

All such transactions race for the same live market outpoints. The first valid
transaction confirmed in canonical chain order wins. An adversary can continue
racing terminalization by paying fees and supplying the assets required for
another nonterminal transition.

### Oracle equivocation and late resolution

Oracle signatures authorize an outcome, not a particular transaction or block
height. Resolution remains available after expiry becomes eligible.

If an oracle signs both outcomes, transactions for both may be valid in
isolation. Canonical chain order determines which shared state spend wins.
Choosing an oracle therefore includes trusting its publication and settlement
policy, not only its private-key security.

## Confirmed non-issues

Within the canonical supported state space, the review confirmed:

- checked arithmetic rejects all observed addition, subtraction, and
  multiplication wraparound;
- issuance requires equal nonzero YES and NO amounts;
- active collateral increases and decreases by the exact pair liability;
- full cancellation requires the exact outstanding collateral;
- partial cancellation cannot leave zero collateral;
- resolved and expired redemption formulas conserve collateral for each
  canonical terminal input;
- RT A/B sides cannot be mixed or silently preserved;
- followers cannot select a weaker transition path;
- each coordinator binds its complete sibling group, while canonical RT supply
  establishes that only one such group exists;
- maker full and partial payments use exact-price equations;
- maker fills and live remainders enforce the minimum;
- zero-progress maker rollover is rejected;
- payment and remainder output indices must differ;
- input and output indices occupy separate namespaces, so equal numeric values
  are not an alias;
- the oracle tagged-hash construction, including its token-ID/outcome scope,
  matches the Rust signing implementation;
- TapData initialization, lexicographically sorted TapBranches, Elements
  TapTweak construction, P2TR script bytes, and scriptPubKey hashing match the
  pinned Rust implementations;
- the nested reissuance-blinding decode rejects a new issuance and accepts only
  an actual reissuance; a real reissuance exposes its token amount as
  `Some(Explicit(0))`, matching the source comment;
- explicit/confidential sum arms and odd-Y parity conventions match the pinned
  implementation;
- Elements fee outputs use an empty script and cannot alias the bare
  `OP_RETURN` burn output, while canonical exhaustion of independent RT
  authority means burn outputs must be funded by token inputs;
- collateral donated to the unresolved-slot script is inert with respect to the
  canonical market group because the adjacent RT/collateral prevout checks
  exclude it;
- follower-index subtraction rejects underflow; and
- the bare `OP_RETURN` script hash constant matches `SHA256(0x6a)`.

## Recommended remediation order

1. Correct the expiry interpreter and add the mixed-sequence red-to-green
   regression described in H-1.
2. Close the independent maker replay boundary in H-2, including validated
   parent evidence and canonical instance derivation.
3. Add node and independent-client creation mutation tests for null initial
   outcome-token amounts, exactly one RT atom, and the remaining market
   creation-validity conjuncts.
4. Prevent or detect cross-order maker-payment aliasing from M-1.
5. Document and test the L-6 single-live-outpoint boundary, including the rule
   that an order must be cancelled and recreated rather than topped up.
6. Decide whether receive/cancellation compromise isolation is a requirement;
   if so, change the private-key derivation design before external use.
7. Align foreign-order covenant/interpreter semantics or explicitly narrow the
   supported primitive contract.
8. Reconcile builder naming, recovery-hint policy, and the Simplex version
   guard.
9. Clarify inherited coordinator uniqueness in source comments, remove the
   dormant helper's unused vout bindings, and measure the program-wide witness
   cost before considering ABI changes.

## Verification

The following daemon-free suites passed against the audited revision:

```text
nix develop .#default --command cargo test --locked -p deadcat-contracts
```

Results:

- 46 unit tests
- 12 covenant-execution tests
- 2 golden-vector tests
- 8 confirmed-transaction interpreter tests
- 68 total tests, all passing

The client Simplicity budget/adversarial suite also passed:

```text
nix develop .#default --command \
  cargo test --locked -p deadcat-client --test simplicity_budget
```

Results:

- 5 tests passed
- 0 failed

The second pass also constructed temporary integration fixtures against the
generated programs and real BitMachine transaction environment:

| Targeted probe | Observed result |
|---|---|
| Two same-script maker inputs sharing one full-fill payment | Both programs accepted |
| Two same-script maker inputs sharing a partial payment and continuation | Both programs accepted |
| Full fill with several distinct unused remainder words | Every witness accepted |
| Two dormant RT pairs sharing one issuance output window | All four programs accepted |
| Dormant pair at nonconsecutive previous vouts | Both programs accepted |
| Two terminal collateral inputs sharing one burn output | Both programs accepted |

These fixtures were removed after execution, so the table is audit evidence,
not a retained regression suite. The creation-quantity and canonical-boundary
tests recommended above should be checked in before relying on them for future
assurance.

Dependency-level verification used `simplicity-lang 0.7.0` with
`simplicity-sys 0.6.2`, as pinned by `Cargo.lock`.

No live Elements regtest campaign was run specifically for this audit. Existing
acceptance documents describe broader live-regtest coverage, but those results
should not be interpreted as having exercised the mixed-sequence expiry case
from H-1.

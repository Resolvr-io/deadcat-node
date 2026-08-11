# ADR 0007: RFQ provider reservation and signing state machine

- Status: Accepted
- Date: 2026-08-11
- Extends: [ADR 0006](0006-rfq-first-liquidity-scope.md)

## Context

ADR 0006 selects a separate, noncustodial RFQ provider as the first liquidity
venue. The client constructs and authorizes the complete transaction; the
provider reserves only its own inventory, validates the final transaction, and
signs only its own inputs.

Provider inventory is nevertheless a shared resource. A firm quote temporarily
removes exact outpoints from circulation, and a provider signature has no
service-level expiry while those outpoints remain spendable. Crash ambiguity,
response loss, a low-fee transaction, or a reorganization must never cause an
outpoint that may have a valid signature to be quoted again.

The provider also needs an exact definition of quote expiry. Requiring a signer
or network response to finish before a wall-clock deadline cannot be made
atomic with durable storage. It would leave crash windows in which the service
could not know whether a valid signature exists.

## Decision

### Separate durable authority

The RFQ provider owns a database and provider identity separate from
`deadcat-node`, the client, and every other provider. The database is bound to
one provider identity, Liquid genesis hash, and policy asset. It contains no
customer wallet secrets and gives no authority over customer funds.

The initial provider core is transport-free. Its persistence types are private
versioned records, not wire DTOs. It does not extend the node RPC, reuse the
`deadcat/1` ALPN, or make a network compatibility promise.

### Monotonic inventory states

Each provider outpoint has one authoritative allocation:

```text
Available
  -> Reserved(reservation)
       -> Available                  only by unused cancellation or expiry
       -> CommittedToExactPayload
            -> SignedBytesStored
            -> relay and chain reconciliation
```

There is no transition from `CommittedToExactPayload` or any later state back
to `Available`. A confirmed settlement may create a new provider change output,
but that output has a new outpoint and enters inventory independently.

Reservations, request-key bindings, input allocations, expiration indexes, and
audit entries change in one serializable redb write transaction. Terminal
reservation records and committed allocation tombstones remain durable for
retry and recovery.

### Deadline and point of no return

The quote deadline is an exclusive **durable accept-before deadline**:

- a reservation is live only when `now < accept_before`;
- at `now >= accept_before`, an uncommitted reservation expires; and
- a commitment that durably succeeds before the deadline remains valid even
  when signing, response delivery, relay, or restart recovery happens later.

The exact point of no return is the durable `Reserved -> Committed` transition,
not quote creation and not signature delivery. The provider follows this
ordering:

1. receive a complete blinded transaction with all required taker signatures;
2. validate its body, proofs, prevouts, economics, fee, and sighash policy;
3. atomically retire every reserved provider outpoint and persist the exact
   pre-sign transcript plus a domain-separated commitment;
4. invoke the wallet or HSM signer using only those persisted bytes;
5. persist the exact signed response; and only then
6. return or relay those same signed bytes.

A crash before step 3 leaves an ordinary reservation that may expire. A crash
after step 3 resumes only the persisted transcript. A crash after step 5
replays only the persisted signed response. Signer failure, timeout, mempool
absence, fee-market movement, or reorganization never reopens committed
outpoints.

This policy deliberately sacrifices provider inventory availability rather
than risk authorizing two transactions with the same outpoint.

### Authentication and retry

A public reservation ID is not authorization. Cancellation and commitment are
bound to an authenticated owner principal. Each owner supplies a high-entropy
idempotency key:

- an exact retry returns the existing reservation or completed result;
- the same key with different terms is rejected;
- a terminal reservation is never resurrected; and
- a new quote requires a new key.

The immutable reservation commits to the quote, exact outpoints, deadline, and
fee policy. The signing commitment additionally covers the exact pre-sign
payload and observed transaction fee facts. A transaction ID alone is
insufficient because Liquid proofs, witnesses, and PSET disclosures are not all
identified by the transaction ID.

### Time safety

The provider samples its clock once after acquiring the serial database writer.
Absolute Unix time is persisted because monotonic process time cannot survive a
restart. The database retains a last-observed time high-water mark; a backward
clock jump fails closed rather than extending a quote. Advancing that mark is a
separate immediate-durability commit performed while a process-wide operation
lock remains held. Consequently, a later time observation survives even when
authentication, policy validation, or the following logical mutation fails.
redb's exclusive database-open lock prevents another process from bypassing
that serialization.

### Fee and resource admission

Every firm reservation freezes:

- a minimum effective fee rate in integer satoshis per 1,000 policy virtual
  bytes;
- an optional minimum absolute fee;
- the regular or confidential-discounted size metric used by the provider's
  broadcasting Elements node; and
- a maximum transaction weight.

Before commitment, the provider recomputes policy size from the complete
blinded transaction, including the projected provider witness, and requires:

```text
fee >= max(minimum_absolute_fee,
           ceil(minimum_sats_per_kvb * policy_vsize / 1000))
```

The calculation uses checked integer arithmetic. The client independently
retains its maximum absolute network-fee authorization. Thus the client caps
overpayment while the provider rejects transactions likely to strand shared
inventory. CPFP is a provider-operated recovery mechanism, not a substitute
for initial fee admission and not a cost silently imposed on later traders.

The state-only crate in this change models and persists those validator-derived
facts, but deliberately does not expose its commit or signed-artifact recording
transitions as externally callable service APIs. They remain crate-internal
until the concrete PSET validator and signer adapter can construct their inputs;
detached caller assertions are not an admissible production trust boundary.

## Consequences

- The provider may strand inventory after an ambiguous signing failure, but it
  cannot silently double-allocate that inventory.
- A client timeout after submitting its signature means status unknown, not
  automatic cancellation. The later protocol must expose idempotent status and
  replay.
- Immediate provider relay and optional provider-funded CPFP reduce the time
  committed inventory remains unavailable; cooperative RBF is deferred.
- The state core stores no private keys and implements no pricing, inventory
  discovery, transaction validation, signing, networking, relay, mempool, or
  reorg policy. Those layers consume its transition-specific API.
- Multiple interactive RFQ signers remain deferred. Future AMM and DLOB legs
  may coexist because a reservation covers only the provider's exact leg and
  inputs, not the entire route.
- Reservation requests lazily expire only reservations blocking their requested
  outpoints. A service worker drains unrelated expirations through explicitly
  bounded batches (capped by the state core), so an accumulated expiry backlog
  cannot make one request's write transaction unbounded.

## Implementation and follow-up

The first implementation is the `deadcat-rfq-provider` library. It provides
provider/chain database binding, durable inventory import, atomic multi-input
reservation, owner-scoped idempotency, bounded expiry and cancellation,
fee-policy evaluation over future validator-derived facts, commit-before-sign
recovery state, signed-response persistence state, clock rollback protection,
startup integrity validation, and an audit log. The safety-critical commit and
signed-artifact transitions remain crate-internal until their validator and
signer producers land.

The next provider milestones are:

1. choose the wallet/signer and inventory-discovery boundary;
2. add configurable inventory-aware quote construction;
3. validate a concrete final Liquid PSET and derive its exact fee metrics;
4. define a dedicated RFQ protocol, identity, and ALPN;
5. persist relay and chain-reconciliation observations without ever reopening
   a committed outpoint; and
6. pass process-kill, signer ambiguity, mempool, confirmation, and reorg gates.

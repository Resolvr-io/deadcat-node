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

The durable state layer models and persists those validator-derived facts, but
deliberately does not expose its commit or signed-artifact recording transitions
as externally callable service APIs. They remain crate-internal until the
concrete PSET validator and signer adapter can construct their inputs; detached
caller assertions are not an admissible production trust boundary.

### Wallet capability and quote-eligibility boundary

The provider's first wallet boundary is backend-neutral: it defines complete
inventory discovery, fresh confidential receive/change destinations, and a
signer capability without selecting Elements RPC, a descriptor wallet, an HSM,
or another production backend.

Version-one provider inventory has one fixed spend profile:

- confidential asset, value, and nonce fields;
- present range and surjection proofs;
- an opening whose asset and value reconstruct the on-chain commitments;
- a valid rangeproof for the output script and commitments;
- an exact tree-less P2TR script for the wallet's untweaked internal key; and
- P2TR key-path signatures with an explicit `SIGHASH_ALL` byte.

Surjection-proof verification needs the creating transaction's complete input
generator domain, so isolated discovery requires proof presence and relies on
the wallet/chain backend's guarantee that the creating transaction passed its
configured chain or mempool validation policy. The later final-transaction
validator rechecks the authoritative prevout and validates the new settlement's
proofs and balance; it cannot reconstruct the historical proof's missing
generator domain from an isolated prevout.

Discovery returns a complete canonically ordered snapshot bound to the provider
identity and a chain anchor. After validating the complete discovery result,
the service stamps it with the same clock observation persisted by its atomic
inventory import.
The only inventory suitable for quote construction is:

```text
fresh complete wallet snapshot
    intersection
durable allocation state == Available
```

Durable `Available` by itself means only “not allocated in redb.” It never
means “currently unspent” or “fresh enough to quote.” A process restart has no
positive discovery cache and must scan again. A later complete snapshot
replaces membership without deleting durable inventory history; outputs absent
from it become ineligible, while reserved and committed outputs never re-enter
eligibility merely because the wallet rediscovers them.

A wallet-source error may retain the last successful view only within its
original freshness window. Once the source returns a newer complete view, that
result supersedes the old observation even if identity, size, immutable
metadata, import, or reconciliation checks reject it: the coordinator clears
the positive cache and requires another successful scan. An authoritative
contradiction can therefore never fall back to older quoteable inventory.

The coordinator serializes refresh, eligibility, and reservation. A reservation
must present the current in-process snapshot token and may name only outputs in
that exact eligible view. Token and membership are rechecked while the refresh
lock is held; snapshot freshness and the quote deadline are then sampled again
after acquiring the durable writer lock. This closes the local
list-then-reserve and queued-writer expiry races; authoritative prevouts must
still be rechecked before commitment because chain state can change immediately
after any scan. Exact idempotent reservation retries replay their durable result
even after the original snapshot has been superseded.

Wallet blinding factors authenticate discovery and remain only in the redacted
in-memory complete snapshot so provider-side collaborative blinding can consume
them. That fresh complete view does not filter out reserved or committed
outputs, so they remain available for transaction construction when the wallet
source still reports them; the separate eligible view contains only its
durable-`Available` intersection. redb never retains blinding factors: it stores
the unblinded asset and amount, untweaked public key, a fixed-size opaque
non-secret wallet locator, and a commitment to the public discovery metadata.
The locator must resolve through wallet ownership history, not only the current
unspent set. When a reservation crosses the point of no return, its exact
locators, keys, outpoints, and inventory commitments become part of the durable
signing job and signing commitment. Signing recovery therefore does not depend
on a committed input continuing to appear in `listunspent` after an ambiguous
signing or broadcast attempt. Restarted pre-commit collaborative blinding does
require a new authenticated wallet scan to recover the opening in memory.

The signer interface accepts only an unforgeable durable signing job. It cannot
be asked through this boundary to sign detached caller bytes or a
caller-selected sighash policy, and it returns exactly one ordered explicit
`SIGHASH_ALL` signature per durable provider target. Cryptographic signature
verification and insertion into the exact PSET remain duties of the next
validator/signer-adapter layer.

## Consequences

- The provider may strand inventory after an ambiguous signing failure, but it
  cannot silently double-allocate that inventory.
- A client timeout after submitting its signature means status unknown, not
  automatic cancellation. The later protocol must expose idempotent status and
  replay.
- Immediate provider relay and optional provider-funded CPFP reduce the time
  committed inventory remains unavailable; cooperative RBF is deferred.
- The persistence core stores no private keys and implements no pricing,
  transaction validation, signing, networking, relay, mempool, or reorg policy.
  Backend-neutral discovery and signer capabilities surround it, but a concrete
  wallet/RPC/HSM backend remains a separate security principal.
- Multiple interactive RFQ signers remain deferred. Future AMM and DLOB legs
  may coexist because a reservation covers only the provider's exact leg and
  inputs, not the entire route.
- Reservation requests lazily expire only reservations blocking their requested
  outpoints. A service worker drains unrelated expirations through explicitly
  bounded batches (capped by the state core), so an accumulated expiry backlog
  cannot make one request's write transaction unbounded.

## Implementation and follow-up

The first implementation is the `deadcat-rfq-provider` library. Its durable
state layer provides
provider/chain database binding, durable inventory import, atomic multi-input
reservation, owner-scoped idempotency, bounded expiry and cancellation,
fee-policy evaluation over future validator-derived facts, commit-before-sign
recovery state, signed-response persistence state, clock rollback protection,
startup integrity validation, and an audit log. The safety-critical commit and
signed-artifact transitions remain crate-internal until their validator and
signer producers land.

Its wallet layer now provides validated confidential tree-less P2TR discovery,
complete chain-anchored snapshots, atomic batch import followed by a
reserve-time-rechecked fresh-availability intersection, confidential input
openings kept only in redacted memory, destination and committed-job-only signer
capability interfaces, explicit `SIGHASH_ALL` response shape, durable non-secret
recovery locators, and adversarial restart, freshness, replacement, concurrency,
and metadata-conflict coverage. Destination non-reuse and authoritative
chain/mempool freshness are explicit backend obligations; the types cannot
prove them. The crate deliberately supplies no concrete wallet backend.

The remaining provider milestones are:

1. add configurable inventory-aware quote construction;
2. validate a concrete final Liquid PSET and derive its exact fee metrics;
3. define a dedicated RFQ protocol, identity, and ALPN;
4. persist relay and chain-reconciliation observations without ever reopening
   a committed outpoint; and
5. pass process-kill, signer ambiguity, mempool, confirmation, and reorg gates.

# ADR 0007: RFQ provider reservation and signing state machine

- Status: Accepted
- Date: 2026-08-11
- Extends: [ADR 0006](0006-rfq-first-liquidity-scope.md)
- Extended by: [ADR 0008](0008-rfq-service-owned-wallet.md), which selects the
  first concrete provider wallet boundary

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

This remains clean-slate preproduction storage. The provider schema version and
private record-layout version intentionally remain `1` while firm-quote records
and indexes are added. A local provider database created by an earlier alpha
build must be deleted and recreated; there is no migration or compatibility
decoder. Keeping version `1` is acceptable only because no provider database
has reached testnet, mainnet, or production, and a compatibility policy must be
chosen before that changes.

### Monotonic inventory states

Each provider outpoint has one authoritative allocation:

```text
Available
  -> Reserved(reservation)
       -> Available                  only by unused cancellation or expiry
       -> CommittedToExactPayload
            -> SignedBytesAndRelayIntentStored
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
5. atomically persist the exact signed response, exact final transaction, and
   immediately due relay record; and only then
6. return that signed response and relay the stored final transaction bytes.

A crash before step 3 leaves an ordinary reservation that may expire. A crash
after step 3 resumes only the persisted transcript. A crash after step 5
replays only the persisted signed response and exact relay transaction. Signer
failure, timeout, mempool absence, fee-market movement, or reorganization never
reopens committed outpoints.

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

The durable state layer models and persists those validator-derived facts. Its
commit transition is reachable only by consuming the final-PSET validator's
opaque one-shot intent; its signed-artifact recording transition accepts only
the signing coordinator's private verified-PSET capability. Detached caller
assertions are not an admissible production trust boundary.

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
`SIGHASH_ALL` signature per durable provider target. The transport-free signing
coordinator exact-matches the job against durable state before invoking that
capability, verifies every returned signature, inserts only the provider
signature fields, revalidates the completed PSET and fee facts, and persists
one canonical signed PSET before exposing it. A concurrent valid Schnorr
encoding loses to and replays the first durable artifact.

### Exact relay outbox and chain reconciliation

Signed-artifact persistence and relay scheduling are one atomic provider-state
transition. Before either the signed result or raw transaction is exposed
outside the provider state machine, the provider stores:

- the canonical signed PSET and its artifact digest;
- the exact consensus-serialized final transaction extracted from that PSET;
- both its transaction ID and witness transaction ID; and
- an initial `Unobserved` relay record scheduled for immediate work.

Transaction ID alone is not the relay identity because it does not commit to
witness data. The provider relays only the exact persisted bytes. In
particular, observing another serialization with the expected transaction ID
but a different witness transaction ID is a conflict with the durable artifact,
not successful settlement or permission to adopt the other witness.

The due-work query deliberately returns only a descriptor containing identity,
revision, schedule, and prior observation. Before external chain or broadcast
I/O can access raw transaction bytes, the store atomically issues a
revision-bound relay attempt: it increments the attempt counter, moves the due
index to a future crash-retry time, and only then returns the exact bytes. A
crash during an ambiguous send therefore leaves the same transaction scheduled
for retry. A stale worker cannot overwrite a newer observation because outcome
recording must match the leased revision and retry time.

Every attempt is status-first and idempotent:

1. validate the persisted bytes, transaction and witness IDs, chain identity,
   and synchronized transaction index;
2. look up the exact transaction before attempting broadcast and exact-match
   both its raw bytes and witness transaction ID;
3. when it is reported in a block, verify that block is canonical at the
   reported height;
4. when it is absent, inspect every input with mempool-aware `gettxout` calls
   under one stable chain tip, then look up the exact transaction again before
   declaring an input conflict;
5. only when the transaction is absent and every input remains unspent, run
   `testmempoolaccept` and submit the exact raw bytes; and
6. after an ambiguous, rejected, or unexpected send response, reconcile the
   exact transaction and its inputs again before recording the outcome.

The durable relay observation is orthogonal to the reservation state. A signed
reservation remains `Signed`; only its observation changes among `Unobserved`,
`BroadcastAccepted`, `Mempool`, `Confirmed(block hash, height)`, `Absent`, and
`Conflicted(spent input, optional conflicting transaction ID)`. Confirmed and
conflicted observations remain scheduled for periodic reconciliation rather
than becoming allocation-state terminals; `BroadcastAccepted` records only the
send response and is likewise not proof of mempool presence. A confirmed
observation that later becomes mempool, absent, conflicted, or confirmed in a
different block increments a durable reorganization counter. No observation,
backend failure, policy rejection, or reorganization reopens a committed input.

Authenticated status includes the exact signed artifact and its durable relay
record. Clients bind the record's transaction and witness IDs back to the
transaction extracted from that artifact and accept only revision-, counter-,
and reorganization-consistent updates. Status remains readable while relay is
degraded so either participant can recover and rebroadcast the same bytes.

The daemon processes due relay work after signing recovery and before readiness,
then runs a dedicated reconciliation worker. A relay backend outage or invalid
backend evidence closes quote, blind, and execute admission without interrupting
status reads or mutating allocations. Admission reopens only after a due item is
successfully reconciled; an empty pass does not prove that a leased failed item
has recovered. Transaction-specific policy rejection remains a durable
per-transaction failure rather than evidence that the entire relay backend is
unhealthy.

## Consequences

- The provider may strand inventory after an ambiguous signing failure, but it
  cannot silently double-allocate that inventory.
- A hostile taker may conflict-spend one of its own inputs after the provider's
  authoritative unspent check. The resulting settlement cannot confirm, but
  the already-committed provider outpoints still do not return to `Available`:
  there is no atomic bridge between a chain read and the redb commitment, and
  treating a transient or mistaken conflict as proof that reuse is safe would
  reintroduce double-signing risk. The remote service must reduce this
  availability exposure with authenticated-owner abuse controls, short quote
  windows, bounded outstanding inventory per owner, immediate signing/relay,
  and operational inventory fragmentation.
- A client timeout after submitting its signature means status unknown, not
  automatic cancellation. The protocol exposes idempotent status and exact
  signed-artifact replay, including the latest durable relay observation.
- Immediate provider relay and optional provider-funded CPFP reduce the time
  committed inventory remains unavailable; cooperative RBF is deferred.
- The persistence core stores no private keys. The transport-free quote engine
  owns exact arithmetic, inventory selection, and an injected pricing-policy
  boundary, with a static rational policy supplied for configuration and
  deterministic tests. The signing coordinator implements transport-free exact
  signing/finalization and durable replay. The adjacent runtime supplies the
  authenticated protocol and Elements-backed relay/reconciliation policy, but
  still has no production market-data source. ADR 0008 selects a narrow
  service-owned hot-wallet implementation in a separate crate; neither the
  provider core nor `deadcat-node` gains direct key access.
- Multiple interactive RFQ signers remain deferred. Future AMM and DLOB legs
  may coexist because a reservation covers only the provider's exact leg and
  inputs, not the entire route.
- Firm-quote admission drains all due reservations through explicitly bounded
  batches (capped by the state core) before selecting inventory. The lower-level
  reservation primitive used by state-core tests still reclaims only expirations
  blocking its requested outpoints, and an explicit sweep remains available to
  service maintenance. No single write transaction grows with an accumulated
  expiry backlog.

## Implementation and follow-up

The first implementation is the `deadcat-rfq-provider` library. Its durable
state layer provides
provider/chain database binding, durable inventory import, atomic multi-input
reservation, owner-scoped idempotency, bounded expiry and cancellation,
fee-policy evaluation over future validator-derived facts, commit-before-sign
recovery state, signed-response persistence state, clock rollback protection,
startup integrity validation, and an audit log. The safety-critical commit is
gated by the validator's opaque intent, and signed-artifact recording accepts
only the signing coordinator's private cryptographically verified PSET
capability. The same atomic signed-artifact transaction also persists the exact
final transaction and creates its immediately due relay record. Bounded due
indexes, store-issued revision leases, stable failure classes, exact status
replay, and durable observation, attempt, failure, and reorganization counters
make ambiguous relay work recoverable without exposing bytes before its retry
intent is durable.

Its backend-neutral wallet layer provides validated confidential tree-less P2TR
discovery, complete chain-anchored snapshots, atomic batch import followed by a
reserve-time-rechecked fresh-availability intersection, confidential input
openings kept only in redacted memory, destination and committed-job-only signer
capability interfaces, explicit `SIGHASH_ALL` response shape, durable non-secret
recovery locators, and adversarial restart, freshness, replacement, concurrency,
and metadata-conflict coverage. Destination non-reuse and authoritative
chain/mempool freshness are explicit backend obligations; the types cannot
prove them. The provider crate deliberately supplies no concrete wallet
backend. ADR 0008's adjacent `deadcat-rfq-wallet` crate implements destination,
output-recovery, and durable-job signing capabilities using an encrypted,
in-memory-unlocked provider seed plus an identity-bound persistent locator
catalog and wallet-only logical snapshot. The adjacent `deadcat-rfq` runtime
crate now implements the authoritative Elements-backed inventory and
settlement-chain adapter, including confirmed catalog scans, mempool-aware
unspent checks, complete confidential prevouts, and chain/catalog coherence
fences. It also implements exact status-first transaction lookup,
mempool-aware input reconciliation under a stable tip, canonical-block checks,
`testmempoolaccept`, exact-byte relay, and post-send ambiguity reconciliation.
The supervised `deadcat-rfq` daemon now connects these capabilities to protected
credential-file unlock, stable Iroh identity, the authenticated RFQ protocol,
explicit initialization/restart modes, signing and relay recovery before
readiness, admission health gates, and graceful draining. Coordinated
provider-state backup/restore remains separate work.

The settlement layer also implements the provider's non-last collaborative
blinding stage. It binds the complete unblinded PSET to the exact live reserved
contribution, permits provider input blinders only on declared provider outputs,
uses confidential openings only from the current in-memory wallet view, and
proves that no unrelated PSET field changed. It neither exposes blinding factors
nor crosses the durable point of no return.

Its quote layer now provides configured collateral-to-outcome and
outcome-to-collateral directions, exact-in and exact-out arithmetic with
direction-appropriate rounding and taker bounds, an injected pricing-policy
interface, deterministic bounded inventory selection, confidential provider
receive and change destinations, a symbolic contribution compatible with the
client's venue model, live-quote admission limits, and durable exact replay
across restart. Quote construction and reservation are one fail-closed path
over a fresh snapshot. The resulting provider-core `FirmQuote` remains an
internal artifact, but the runtime now maps it into the strict network schema
and signs an attestation bound to the provider endpoint, authenticated client
endpoint, idempotency key, and exact request. Only that signed network quote is
client evidence.

Market quote configuration is likewise not chain evidence. The service must
derive each configured contract ID and collateral/YES/NO asset tuple from an
independently validated canonical market view, rather than trusting operator or
remote asset labels. The remote service must also authenticate the owner,
rate-limit quote churn, and choose a bounded durable-retention/compaction policy
before exposing this engine publicly. Live-reservation quotas bound concurrent
inventory pressure; they do not by themselves bound terminal quote history.

The initial final-PSET profile treats every non-provider input as an already
finalized tree-less P2TR key-path `SIGHASH_ALL` spend. It therefore supports
ordinary wallet contributions around one interactive RFQ provider, but not yet
Simplicity covenant inputs or a second interactive provider. Those require an
authenticated venue/script verification seam; merely accepting an arbitrary
nonempty witness would not be participant authorization.

The remaining provider milestones are:

1. derive market configuration from canonical evidence and add production
   pricing plus authenticated-owner/global abuse controls and bounded history;
2. coordinate wallet, provider-state, and Iroh-identity backup/restore with
   external freshness checks; and
3. pass process-kill, signer ambiguity, live-Core relay, mempool, confirmation,
   reorg, and public-network acceptance gates before deployment.

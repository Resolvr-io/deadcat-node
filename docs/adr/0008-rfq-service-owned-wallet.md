# ADR 0008: RFQ service-owned hot wallet

- Status: Accepted
- Date: 2026-08-19
- Extends: [ADR 0007](0007-rfq-provider-state-machine.md)

## Context

ADR 0007 defines a narrow wallet capability boundary but deliberately does not
choose a concrete key backend. The first RFQ service needs to discover and
unblind its own inventory, create fresh confidential destinations, collaborate
in settlement blinding, and sign only an exact transaction that the provider
has already validated and durably committed.

Using an Elements Core wallet would reduce custom wallet code, but it would also
make the Elements daemon's general wallet RPC and policy part of the provider's
signing boundary. Requiring an HSM for the first release would preserve stronger
key isolation at the cost of making launch depend on a particular device and
its confidential-transaction support.

The service is noncustodial with respect to users: these keys control only the
provider's own liquidity. `deadcat-node` remains a separate, shared-safe,
keyless evidence service.

## Decision

The first RFQ provider will use a purpose-built, service-owned hot wallet loaded
inside the separate RFQ daemon. It is a narrow implementation of the capability
interfaces in ADR 0007, not a general wallet server or a new `deadcat-node`
subsystem.

### Keystore and derivation

The wallet root is stored in a versioned authenticated-encryption envelope and
is unlocked into service memory. The initial envelope uses Argon2id for
passphrase key derivation and XChaCha20-Poly1305 for authenticated encryption,
binds the ciphertext to the provider, genesis hash, policy asset, and a random
wallet identity, and zeroizes decrypted root material where the Rust ownership
boundary permits.

One root feeds two domain-separated derivation schemes:

- BIP32 derives provider spend keys through the hardened, BIP86-shaped path
  `m/86'/1776'/0'/purpose'/r0'/.../r4'`, where `1776` is Liquid's SLIP-44
  coin type and the five `r` components come from a domain-separated hash of
  the provider identity, persistent wallet identity, locator purpose, and
  random nonce; and
- SLIP-77 derives the confidential blinding key for each exact script.

The spend profile remains ADR 0007's tree-less P2TR key path. The output script
and signer use the Elements tap tweak for the untweaked internal key, and every
provider signature carries explicit `SIGHASH_ALL`. A Bitcoin-only tap-tweak
implementation, default sighash, script tree, or alternate spend profile is not
accepted by this wallet version.

The shared root means compromise of the unlocked wallet compromises both spend
and blinding derivation. Domain separation prevents accidental key reuse; it is
not a claim that the two domains have independent compromise boundaries.

### Recoverable, non-secret locators

Every receive or change destination uses a cryptographically random,
high-entropy locator rather than a mutable sequential address counter. The
opaque locator includes its version and purpose and authenticates its random
derivation material with a wallet-derived MAC. It contains no private key,
seed, blinding factor, or other secret.

After the provider durably records a locator, the same encrypted wallet state
(root plus persistent wallet identity) can validate it and recover the exact
spend and blinding keys after restart. A forged, cross-purpose, cross-wallet,
or malformed locator fails closed. Random derivation also avoids address reuse
caused solely by restoring a stale "next-address" counter. It does not by
itself provide a complete backup or chain-discovery system; the root alone is
not a complete backup of the random wallet identity or issued-locator catalog.

### Narrow capabilities

The wallet exposes only the provider capabilities needed by the state machine:

- fresh confidential inventory-deposit, settlement-receive, and change
  destinations;
- validation and recovery of an exact provider-owned confidential output; and
- signatures for the exact ordered targets in an unforgeable durable signing
  job.

It exposes no arbitrary transaction-signing, message-signing, private-key
export, seed-export, or send-money API. The signer resolves each durable locator
to the expected untweaked internal key, recomputes the exact Elements P2TR
sighash from the persisted PSET and prevouts, and returns only explicit
`SIGHASH_ALL` signatures. The provider signing coordinator still verifies and
inserts those signatures and persists one canonical signed artifact before any
result is returned.

### Elements Core boundary

Elements Core remains the provider's intended authority for chain state,
mempool and relay policy, transaction acceptance, and broadcast. It does not
derive provider destinations, hold provider keys or blinding secrets, unblind
inventory, or sign provider inputs. A later runtime adapter will translate
authoritative Elements RPC observations into the provider's chain and inventory
interfaces.

### Collaborative blinding

The provider performs the non-last stage of collaborative PSET blinding before
the taker completes the balancing stage. The provider coordinator reconstructs
the durable reserved contribution, binds it to the complete unblinded PSET,
uses only fresh in-memory openings for the quote's exact provider inputs, and
permits provider input blinders only on the quote's declared provider outputs.
It exposes no input opening or output blinding factor and rejects an already
blinded, aliased, expired, committed, or structurally different payload.

This blinding step remains pre-commit and does not cross ADR 0007's point of no
return. Only later final-PSET validation and durable commitment can authorize
signing.

## Initial implementation boundary

The first implementation slice is intentionally a cryptographic and
transport-free capability layer. It adds the encrypted keystore, destination
derivation, output recovery, durable-job signer, and provider-side non-last
blinding coordinator with focused adversarial tests.

It does **not** yet provide:

- atomic filesystem replacement, permissions, directory synchronization,
  passphrase delivery, unattended unlock, memory locking, or process-dump
  policy;
- an authoritative chain scanner or concrete `InventorySource`;
- RFQ-daemon startup/configuration wiring, bounded and rate-limited remote
  destination issuance, or a live wallet-backed regtest flow;
- a complete backup catalog, stale-backup discovery and recovery workflow, or
  key rotation;
- the authenticated remote RFQ protocol, signed network quote, pricing source,
  relay and outspend reconciliation; or
- an HSM or external-signer backend.

Those are launch requirements or later hardening work, not properties implied
by the existence of the wallet library. In particular, a serializable encrypted
envelope is not yet production backup tooling, and a self-authenticating locator
does not discover an output whose script is absent from every restored catalog
and chain scan.

## Consequences

- A compromise of the running RFQ daemon can steal or strand provider liquidity,
  but grants no authority over customer wallets or `deadcat-node`.
- The narrow signing API and durable-job verification reduce accidental or
  confused-deputy signing; they do not make an online hot wallet equivalent to
  an HSM.
- Elements Core can remain wallet-disabled and replaceable without changing the
  provider's key derivation or persisted locators.
- The capability boundary remains suitable for a later out-of-process signer or
  HSM without changing ADR 0007's reservation and commit-before-sign semantics.
- The service must not be described as production-ready until the deferred
  durability, scanning, runtime, recovery, and live acceptance work is complete.

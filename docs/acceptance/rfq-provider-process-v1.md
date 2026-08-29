# RFQ provider-process acceptance

## Purpose

The in-process RFQ suites prove quote, wallet, settlement, signing, and relay
components independently. They cannot prove that the shipped `deadcat-rfq`
binary, its command-line state lifecycle, authenticated Iroh protocol, custom
wallet, durable provider state, and Elements Core adapter compose into one
recoverable trade service. This mandatory liquidregtest gate crosses that
process boundary with real confidential transactions.

Run it inside the Nix development shell with:

```sh
just regtest-rfq-provider-process
```

`just regtest` includes this recipe, so the gate is part of the aggregate live
acceptance suite. The test invokes the production binary and public RFQ client
interface; it does not substitute an in-process provider handler.

## Accepted behavior

The test starts an isolated `elementsd`, prepares a funded node wallet, issues
distinct YES and NO assets, and configures the provider's intentionally static
liquidregtest profile. It then:

1. Runs the shipped `deadcat-rfq init` command against a fresh private state
   directory and records the provider identity.
2. Runs `deadcat-rfq deposit-address`, funds that confidential address with YES
   inventory, funds a separate persistent taker wallet with the policy asset,
   and confirms both outputs.
3. Spawns `deadcat-rfq run` with the production Elements adapter and direct-only
   Iroh discovery, then requires a bounded readiness record containing the same
   provider identity and a usable direct address.
4. Connects a real `RfqSession` with a persistent authenticated taker identity
   and requests an exact-in policy-asset-to-YES quote from the configured
   market.
5. Uses the high-level taker runtime to reserve authenticated wallet inputs,
   verify the signed quote, obtain provider blinding data, validate the final
   PSET, durably arm it, apply the taker's signature first, and submit it for
   provider execution.
6. Requires the provider to durably commit, sign, and relay the settlement. The
   signed PSET's transaction ID and witness transaction ID must match the relay
   record, and Elements Core must return exactly the same transaction bytes.
7. Hard-kills the provider after relay, waits until its durable relay work is
   due, and restarts the same binary over the same state. The restarted process
   must preserve its provider and Iroh identities, perform a new post-restart
   reconciliation attempt, and return the identical signed PSET.
8. Mines the transaction and requires the provider's durable status to report
   confirmation at the exact canonical block hash and height while Core still
   returns the exact signed transaction.
9. Closes the authenticated session and stops the restarted daemon through its
   graceful signal path.

Every daemon startup, one-shot command, request, status poll, and shutdown is
bounded. Spawned child processes are kill-on-drop, so an assertion failure does
not leave a provider daemon behind on the CI host.

## Boundary of this gate

This gate proves the current provider process and public RFQ protocol against a
real local consensus backend. The taker side deliberately uses the production
client/runtime/wallet libraries with a test-local Core-backed inventory and
settlement source because a runnable taker application and canonical node-backed
source do not exist yet. The market metadata is a validated static regtest
fixture rather than canonical indexed market evidence.

It does not claim public Liquid availability, relay/NAT traversal, production
pricing, a complete taker process, coordinated backup/restore, rate-limit or
load behavior, fee bumping, or HSM operation. Core outage, ambiguous-send,
conflict/outspend, and post-confirmation reorganization scenarios remain
separate process-level follow-ups. Their component semantics are covered by the
in-process Elements relay and handler suites; this packet records only the
boundary exercised here.

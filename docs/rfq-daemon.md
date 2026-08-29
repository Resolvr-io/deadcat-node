# RFQ daemon operations

`deadcat-rfq` is the separately operated, inventory-bearing RFQ process. It is
not part of the keyless `deadcat-node`, accepts no customer deposits, and has no
generic wallet or signing API.

## Current profile and limits

The first executable profile is deliberately named `regtest_static_v1` and
refuses Liquid mainnet and testnet. Its market-to-asset mapping and rational
rates come from static operator configuration. That is useful for integration,
restart, recovery, and live regtest work, but it is not independent evidence of
an on-chain market and it is not a production pricing source.

`regtest_static_v1` requires Elements Core's default policy/relay-fee asset,
which is the chain's pegged asset, and forbids starting Core with a custom
`-feeasset`. The daemon obtains the pegged asset from
`getsidechaininfo.pegged_asset` and requires the built-in `bitcoin` asset label
to match it as a supported-profile consistency check. Elements Core 23.3.3
exposes no RPC for the active `-feeasset` override, so the daemon cannot verify
that operator launch option itself; enforcing its absence is an operational
requirement of this profile. Older Elements tutorial material refers to a
`-policyasset` option, but the pinned Core 23.3.3 rejects that spelling;
`-feeasset` is the applicable override.

Before this profile can be enabled on a public network, the daemon must derive
market assets from independently validated canonical creation/history evidence
and use an operational pricing source. Authenticated-owner request-rate limits,
coordinated off-host backup recovery, host memory hardening, and production
process-kill and live-Core relay/reorganization acceptance coverage also remain
launch work. The durable relay state machine is implemented, but its current
coverage is not evidence that the profile is ready for Liquid testnet or
mainnet.

## State and secret model

One fixed private state directory contains:

- `iroh-secret`: the stable Iroh identity and quote-attestation key;
- `wallet.redb`: the encrypted, service-owned liquidity wallet;
- `provider.redb`: reservations, inventory allocations, signing commitments,
  signed artifacts, exact relay transactions, relay schedules and observations,
  and audit state; and
- `manifest.json`: the completion marker binding all three files to one
  provider, genesis hash, policy asset, and network.

The directory must be owned by the effective user with mode `0700`. Every file
above is created without replacement and must have mode `0600`. `run` opens
existing state only: a typo, missing file, symlink, widened permissions, wrong
identity, or incomplete `init` cannot silently generate a replacement wallet or
allocation database.

The implementation directly validates the state directory and each state file,
not every ancestor. The operator must therefore control and trust the complete
path hierarchy against directory rename or replacement for the lifetime of the
process.

The wallet passphrase is never accepted in configuration, an environment
variable, or a command-line value. `--passphrase-file` must name an owner-only
regular file with mode `0600`. The reader accepts at most 4 KiB, rejects empty
and NUL-containing values, removes one final LF or CRLF, preserves all other
bytes, and zeroizes its input buffer after wallet open.

## Configuration

The JSON file is bounded, rejects unknown fields, must be owned by the current
user, and must not be group- or world-writable. HTTP Elements RPC is accepted
only on a loopback address; remote RPC must use HTTPS. Cookie authentication is
preferred and requires an absolute, owner-only `0600` cookie file. Elements
Core must have a synchronized transaction index.

All integer amounts use native atomic asset units. Each rational rate is
`output units / input unit`; reverse directions are never inferred.

```json
{
  "schema_version": 1,
  "profile": "regtest_static_v1",
  "network": "elements_regtest",
  "genesis_hash": "<elements-regtest-genesis-hash>",
  "policy_asset": "<elements-regtest-policy-asset>",
  "elements": {
    "url": "http://127.0.0.1:7041",
    "auth": { "type": "cookie_file", "path": "/absolute/path/to/.cookie" }
  },
  "fee_policy": {
    "minimum_sats_per_kvb": 100,
    "minimum_absolute_fee": 100,
    "maximum_transaction_weight": 400000,
    "size_metric": "discount_vbytes"
  },
  "pricing_revision": 1,
  "markets": [
    {
      "market_id": { "txid": "<creation-txid>", "vout": 0 },
      "collateral_asset": "<collateral-asset>",
      "yes_asset": "<yes-asset>",
      "no_asset": "<no-asset>",
      "pairs": [
        {
          "input": "collateral",
          "output": "yes",
          "minimum_input": 1,
          "maximum_input": 100000000,
          "minimum_output": 1,
          "maximum_output": 100000000,
          "maximum_provider_inputs": 8,
          "minimum_positive_change": 1,
          "selection_search_node_budget": 250000,
          "rate_numerator": 2,
          "rate_denominator": 1
        }
      ]
    }
  ],
  "runtime": {
    "max_inventory_age_millis": 30000,
    "max_inventory_outputs": 10000,
    "quote_lifetime_millis": 15000,
    "maximum_live_quotes_per_owner": 4,
    "maximum_live_quotes_global": 1024,
    "execute_queue_capacity": 8,
    "max_blocking_operations": 16,
    "recovery_batch_size": 64,
    "recovery_interval_millis": 1000,
    "inventory_refresh_interval_millis": 10000,
    "direct_only": true
  }
}
```

## Lifecycle

Create a protected passphrase credential, then initialize exactly once:

```text
deadcat-rfq init \
  --config /absolute/path/to/deadcat-rfq.json \
  --state-dir /absolute/path/to/deadcat-rfq-data \
  --passphrase-file /absolute/path/to/wallet.passphrase
```

`init` validates the host clock, Elements genesis/tip/transaction index, all
configuration, and the passphrase credential before publishing identity state.
The manifest is written last. A failed partial initialization is never resumed
or overwritten automatically; preserve it for diagnosis. While all state is
strictly disposable and unfunded in preproduction, the operator may remove the
entire partial directory and start again.

Issue a confidential address whose locator is durable before it is printed:

```text
deadcat-rfq deposit-address \
  --config /absolute/path/to/deadcat-rfq.json \
  --state-dir /absolute/path/to/deadcat-rfq-data \
  --passphrase-file /absolute/path/to/wallet.passphrase
```

After funding and confirming that address, start the provider:

```text
deadcat-rfq run \
  --config /absolute/path/to/deadcat-rfq.json \
  --state-dir /absolute/path/to/deadcat-rfq-data \
  --passphrase-file /absolute/path/to/wallet.passphrase
```

Startup emits its JSON `ready` record only after all of the following succeed:

1. strict configuration, filesystem, identity, clock, chain, and txindex checks;
2. wallet and existing provider-database integrity checks;
3. a complete authoritative inventory refresh;
4. recovery of every durable pending signing job;
5. one complete pass, in bounded batches, over relay work currently due; and
6. binding the authenticated Iroh endpoint with the exact provider key.

SIGINT and SIGTERM stop the transport first, then close provider admission,
drain accepted execute operations through their durable commit boundary, drain
pending signing recovery, drain relay work accepted by the worker, and join the
daemon workers. A hard process kill is recovered from the durable signing and
relay indexes after restart.

## Relay and reconciliation

Recording a signed settlement atomically stores the canonical signed PSET, the
exact final transaction bytes derived from it, the transaction ID and witness
transaction ID, and an immediately due `Unobserved` relay record. The daemon
never substitutes a reconstructed or caller-provided transaction at relay time.

Before Elements Core can see those raw bytes, `provider.redb` issues a durable,
revision-bound lease and moves the same work item to a future crash-retry time.
This ordering means a process kill or lost RPC response can cause an idempotent
retry of the same bytes, but cannot cause the outpoints to be reassigned or a
different settlement to be selected. A stale worker cannot overwrite a newer
relay result.

Reconciliation always checks status before sending. It exact-matches an
existing transaction by raw bytes and witness transaction ID, verifies a
reported confirmation against the canonical block at that height, and otherwise
checks every input with mempool-aware `gettxout` calls under a stable tip. It
looks up the exact transaction again before classifying a spent input as a
conflict. Only a transaction that remains absent with every input unspent is
submitted to `testmempoolaccept` and then relayed. An ambiguous or rejected send
is followed by another exact status and input reconciliation.

The status lifecycle is independent of allocation state:

```text
Signed allocation (irreversible)
    + relay observation:
        Unobserved | BroadcastAccepted | Mempool
        | Confirmed(block hash, height) | Absent
        | Conflicted(spent input, optional conflicting txid)
```

The same signed allocation never returns to `Available`, including after a
policy rejection, conflicting spend, backend outage, or reorganization.
Confirmed and conflicted observations continue to be rechecked. A confirmation
that disappears or moves to another block increments a durable reorganization
counter. Another transaction serialization with the same transaction ID but a
different witness transaction ID is recorded as a conflict with the exact
durable artifact; it is not adopted as an equivalent settlement.

An Elements backend outage or invalid backend evidence marks relay degraded and
stops new quote, blind, and execute admission. Authenticated status remains
available for recovery. Admission is restored only after at least one due relay
item is successfully reconciled; an empty pass does not establish recovery.
Transaction-specific mempool policy rejection is retained on that transaction's
status and does not by itself mark the whole backend unhealthy.

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
and use an operational pricing source. Immediate relay plus durable
mempool/confirmation/reorg reconciliation, authenticated-owner request-rate
limits, coordinated off-host backup recovery, and host memory hardening also
remain launch work.

## State and secret model

One fixed private state directory contains:

- `iroh-secret`: the stable Iroh identity and quote-attestation key;
- `wallet.redb`: the encrypted, service-owned liquidity wallet;
- `provider.redb`: reservations, inventory allocations, signing commitments,
  signed artifacts, and audit state; and
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
4. recovery of every durable pending signing job; and
5. binding the authenticated Iroh endpoint with the exact provider key.

SIGINT and SIGTERM stop the transport first, then close provider admission,
drain accepted execute operations through their durable commit boundary, drain
pending signing recovery, and join the daemon workers. A hard process kill is
recovered from the same durable signing index on the next startup.

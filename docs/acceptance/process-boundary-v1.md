# Daemon, Iroh, and CLI process-boundary acceptance

## Purpose

The in-process suites prove protocol interpretation and storage semantics, but
they cannot prove that the shipped binaries, clap interfaces, Iroh transport,
background synchronization loop, signal handling, or operator rebuild command
compose correctly. This mandatory liquidregtest gate exercises that complete
production boundary with real processes and real Elements consensus.

Run it inside the Nix development shell with:

```sh
just regtest-process-boundary
```

`just regtest` includes this recipe, so the same gate is required in CI. The
recipe explicitly builds `deadcat-node` and `deadcat` before running the ignored
integration test; the test never substitutes an in-process handler for either
binary.

## Accepted behavior

The test starts an isolated `elementsd`, funds a wallet, and records an
exclusive activation checkpoint. It then:

1. Spawns `deadcat-node run` with a fresh redb database, a persistent Iroh
   secret, direct-only discovery, the production Elements adapter, and the
   dynamic liquidregtest policy asset.
2. Uses repeated, separately spawned `deadcat` CLI processes over the advertised
   direct Iroh address until the daemon reports `Ready` at the exact source tip.
3. Creates and confirms a real Simplicity binary market while the daemon is
   running, then requires full-hint discovery and durable subscription replay
   from a cursor captured before creation.
4. Sends a complete `ContractPackage` through the CLI registration command and
   reads the market, market list, history, and raw creation evidence through
   independent CLI invocations.
5. Builds and signs a wallet transaction locally, relays it through the CLI and
   Iroh server, mines it, and waits for exact indexed-tip convergence.
6. Stops the daemon with `SIGINT`, starts a new daemon process over the same
   files, and requires the same Iroh endpoint ID and persisted contract state.
7. Indexes three blocks, replaces that complete suffix with an alternate branch,
   and requires the running daemon to enter sticky `RescanRequired` without
   serving chain-derived contract state. Entering this state rotates the event
   epoch exactly once.
8. Stops the daemon and invokes the shipped `deadcat-node rebuild` command as a
   separate process. After a third daemon start, the database must be `Ready` at
   the replacement tip, preserve that rotated epoch, and return the registered
   market plus its exact raw creation evidence at the same creation position.
9. Attempts to resume with a pre-invalidation event cursor. The CLI must fail
   with an explicit stale-cursor error because that cursor belongs to the old
   durable event epoch.

All child processes have bounded startup, request, subscription, shutdown, and
rebuild deadlines. A hang therefore fails the gate instead of consuming an
unbounded CI runner.

## Boundary of this gate

This is a local real-daemon and real-consensus acceptance test. It does not
claim public Liquid testnet availability, relay/NAT traversal through n0,
production backup/restore procedure coverage, hostile process termination at
every redb fsync instruction, or hosted-service load behavior. Storage mutation
boundaries and deterministic reference-model equivalence are covered by the
`deadcat-node` library assurance tests; Elements-vs-Esplora behavior is covered
by the separate backend-equivalence gate.

# Binary-market A/B v1 acceptance packet

- Status: Engineering candidate complete; protocol-owner approved; focused external review pending
- Prepared: 2026-07-13
- Protocol-owner approval: Tommy Volk; 2026-07-14
- Decision record: [ADR 0005](../adr/0005-rt-blinding-schedule.md)
- Protocol specification: [Deadcat protocol v1](../protocol-v1.md)
- Hardened rolling baseline: `ed6de4c4c8a177b4a4ba92c2bac17f55b324781f`
- Candidate implementation commit: `7ed20b8b81306eaf81ee49b80b4ea65b49804871`

This packet is the acceptance boundary for replacing the experimental rolling
reissuance-token (RT) blinding schedule with fixed complementary A/B blinders
in binary-market v1. It covers the consensus design and its node/client
integration. It is not a claim that the entire Deadcat node is production
ready; broader operational shakedowns and maker-order ownership recovery remain
separate release work.

ADR 0005 remains Proposed until a focused reviewer records a conclusion. Tommy
Volk approved every protocol-owner choice below on 2026-07-14 against the
candidate implementation commit. Reviewer checkboxes remain for the independent
human review; test success does not check them automatically.

## Candidate identity

For the golden fixture in `deadcat-contracts/tests/golden_vectors.rs`, the
parameterized binary-market CMR is:

```text
74031c77c0d4e678913f7a8685425fea07458851e0246496fd3174d734379301
```

The v1 consensus scalars are big-endian 32-byte integers:

```text
ABF_A    = 0101010101010101010101010101010101010101010101010101010101010101
ABF_B    = 0202020202020202020202020202020202020202020202020202020202020202
YES_CBF  = 0303030303030303030303030303030303030303030303030303030303030303
NO_CBF   = fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfbb7abd9e3ac459d38bccf5b89cd333e3e
VBF(r,s) = CBF(r) - ABF(s) mod n
```

The golden test also freezes all four asset commitments, both
side-independent value commitments, and all eight Taproot script/control-block
pairs. A second set of independently derived commitments uses nonuniform asset
IDs so an accidental Elements display-order reversal cannot pass unnoticed.
The CMR above is not universal across market parameters.

## Engineering evidence

| Requirement | Result | Evidence |
|---|---|---|
| Fixed A/B algebra and complementary creation balance | Complete | Scalar/group tests plus literal golden vectors; `YES_CBF + NO_CBF = 0 mod n` |
| Raw-output side authority | Complete | Builder, covenant, interpreter, registration, and independent replay infer from exact `(asset, value)` commitments; no side field is trusted or persisted |
| Side-A-only creation | Complete | Builder output, node registration, and independent client replay reject side-B creation; three canonical creations mined on Elements regtest |
| Creation authority exhaustion | Complete | Each unique defining issuance creates no initial outcome tokens and exactly one RT atom, whose exact value-one commitment is locked at its compiled dormant script; Elements consensus then precludes any additional spendable RT authority |
| Mandatory synchronized flip/burn | Complete | SimplicityHL and Rust checks plus A→B, B→A, same-side, mixed-side, wrong-role, malformed-commitment, and terminal-burn tests |
| Input-side reissuance nonce | Complete | Covenant/builder/interpreter adversarial tests and live A/B issuances inspect the exact nonce |
| Every lifecycle shape | Complete | All 18 builder/BitMachine/interpreter shapes execute; every RT-consuming shape executes on both A and B, every sibling, with sufficient Simplicity budget |
| Elements consensus and policy | Complete | Three full-contract chains, 15 market transactions plus one setup-funding transaction confirmed; every valid stage through `testmempoolaccept`, broadcast, mining, and confirmation |
| Confidential proofs | Complete | Creation/continuation/burn rangeproofs and complete-domain surjection proofs accepted live; missing and parseable-corrupt proofs rejected |
| Golden integration identity | Complete | Constants, six fixture commitments, six independently derived nonuniform-ID commitments, CMR, eight scripts, and eight control blocks are literal regression vectors |
| Market public recovery and registration | Complete | Unchanged 38/70-byte hints; zero-seed concrete-block discovery through `SyncCoordinator + DeadcatInterpreter`; generic `ChainSource -> verify_and_register -> redb -> reopen`; backend transaction/status adapters tested separately |
| Restart and retained reorg depth | Complete | Two real A/B markets survive redb reopen; direct store and coordinator-driven one-/two-block branch replacement restore exact state, history, outputs, and raw evidence |
| Composition/orchestration | Complete for v1 gate | Live confidential wallet input/change composition; one synthetic transaction updates two markets atomically through the real interpreter/store |
| Full-market before/after measurements | Captured with provenance limitation | A/B reporter is reproducible; exact rolling rows are a preserved capture from temporary baseline instrumentation whose patch was not committed; isolated rolling/A-B study remains reproducible |
| Rolling retirement | Complete | No rolling implementation, compatibility mode, study crate, or schema migration remains in the candidate tree |
| Clean pinned-Nix CI | Passed on 2026-07-13 | `nix develop path:.#default --command just ci`; rerun after freezing nonuniform commitment vectors |
| Independent implementation review | Complete | Plain-integer scalar arithmetic, direct C libsecp256k1-zkp commitments, and isolated pinned-compiler CMR reproduction all match |
| Focused external human review | Pending | Reviewer record below |
| Protocol-owner approval | Complete | Tommy Volk; 2026-07-14; candidate implementation commit below |

The node-level composition fixture is intentionally distinguished from mined
multi-covenant evidence: it proves atomic orchestration of two contracts, while
the live harness proves Elements-valid composition with unrelated explicit and
confidential wallet inputs/change. Mining two covenants in one transaction is
additional assurance, not a distinct A/B consensus rule.

## Reproduction environment

Run from a clean checkout of the candidate commit:

```sh
nix develop path:.#default --command just ci
nix develop path:.#default --command just regtest-market-ab
nix develop path:.#default --command cargo test --locked \
  -p deadcat-client --test simplicity_budget \
  every_finalized_market_stack_has_sufficient_simplicity_budget \
  -- --exact --nocapture
```

| Component | Pinned value |
|---|---|
| `flake.lock` SHA-256 | `39cb5ac107c5930e0184e9d01a43f7ee7ae3229a230e0f6e37b3cf6cebe3d0d7` |
| nixpkgs revision | `50ab793786d9de88ee30ec4e4c24fb4236fc2674` |
| rustc | `1.94.1 (e408947bf 2026-03-25)` |
| Cargo | `1.94.0 (29ea6fb6a 2026-03-24)` |
| Simplex CLI / smplx crates | `0.0.6` |
| Elements Core | `23.3.3` |
| Electrs | `0.4.1` |
| Expanded live run | Passed, 44.81 seconds, 2026-07-13 |

## Live Elements record

The accepted run starts isolated Elements Core and Electrs instances. Every
row was accepted by `testmempoolaccept`, broadcast, mined, and read back with a
confirmation. Exact size, weight, discounted size, proof bytes, covenant stack
bytes, asset IDs, block hashes, and negative results are preserved in
[`binary-market-ab-live-2026-07-13.json`](../measurements/binary-market-ab-live-2026-07-13.json).
The table lists the 15 market transactions; the JSON also records the initial
confirmed setup-funding transaction, for 16 confirmed transactions total.

| Chain | Stage | Side | Height | Txid |
|---|---|---|---:|---|
| YES resolution | creation | start A | 105 | `00741193071a30d409403fcfc50b86e1feae971ba29515db5cf03ecad633c3c6` |
| YES resolution | initial issuance | A→B | 106 | `717aa7d18b8e30ae206eeaa125c9124a4f6c2a19bfcff6e3bce098ae00f5025a` |
| YES resolution | confidential-wallet subsequent issuance | B→A | 107 | `600cd78a5f85beecbe7b894d46debd9775f78de5a703669bce2be56e1d69afdd` |
| YES resolution | active YES terminal burn | A→B | 108 | `3741d71c9b444388adfb2fc53dcd01f6aa6064fd8043195128e4f596e7bdae32` |
| YES resolution | partial redemption | n/a | 109 | `9d71aebc47dad45b6eef59f098fc863d778df5757c453efc81db766efc425121` |
| YES resolution | full redemption to zero | n/a | 110 | `05101950bb92e9f48740de3633dfe69adff6daefb3c29803e75fb2289ace2673` |
| Cancel/reissue/NO | creation | start A | 111 | `aa1ef466beae2915834ac7a17e355ca392c8969183d957e235f8e33faa1e35dc` |
| Cancel/reissue/NO | initial issuance | A→B | 112 | `aa887ed90c7e9dbdfe405f8b91a6a1ffed9f6527287898663b348b3f8badc031` |
| Cancel/reissue/NO | partial cancellation | B→A | 113 | `67dae5f62b5370d3eb0fc2bd6b2bfeb90c2a3ebed39a8bd1f374acafdaef2d64` |
| Cancel/reissue/NO | full cancellation to Dormant | A→B | 114 | `9879a905195fc89902cf718babe596e9b359bdeb8039acdf1d1434b7ff1f4e83` |
| Cancel/reissue/NO | Dormant reissuance with B nonce | B→A | 115 | `f90de6ccd3b1a7fea0dad03a72cfe41ac78b4c4a291f774cde46438481e0e7df` |
| Cancel/reissue/NO | active NO terminal burn | A→B | 116 | `8aab1989b5e0677581af56c9b9dcb4c61e6516cd82105cd640423d2905c14c62` |
| Active expiry | creation | start A | 117 | `c148d3cbf1a3276ab020e6e9e8d1720e6ab9dd3c961d3984568f17bf6f9d971d` |
| Active expiry | initial issuance | A→B | 118 | `7afb9c08e641c81a94222f111eb0f56474fe1b1135f4164c09f03c8acde710e1` |
| Active expiry | lock-height terminal burn | B→A | 119 | `f6ff8237a18f52ddd99f970576e4565b2bc67838f0c490e20aaf767df155bc37` |

The expiry spend uses the exact market lock height and `0xfffffffe` on every
contract input. The two negative initial-issuance variants were rejected with
`bad-txns-in-ne-out` after respectively removing and corrupting a surjection
proof.

## Full-market measurements

The following totals sum the ten RT-consuming lifecycle shapes under an
identical finalized full-market fixture. They are comparison aggregates, not
the fee of one transaction. The A/B rows are emitted by the reproduction
command above. The rolling rows were captured with temporary instrumentation
against `ed6de4c...`; that patch was not committed, so the exact rolling numbers
must be treated as a preserved historical capture rather than independently
reproducible evidence. The rolling source and the isolated rolling/A-B study
remain available in Git history. Side-independent redemption metrics and every
individual shape are in
[`binary-market-ab-v1.json`](../measurements/binary-market-ab-v1.json).

| Metric | Rolling | A/B side A | Reduction | A/B side B | Reduction |
|---|---:|---:|---:|---:|---:|
| Covenant cost, milliweight | 55,547,413 | 38,446,095 | 30.8% | 38,428,635 | 30.8% |
| Program bytes | 62,873 | 61,332 | 2.5% | 61,276 | 2.5% |
| Witness bytes | 3,592 | 520 | 85.5% | 520 | 85.5% |
| Serialized stack bytes | 70,326 | 64,556 | 8.2% | 64,500 | 8.3% |
| Budget-padding bytes | 1,135 | 0 | 100% | 0 | 100% |
| Transaction bytes | 161,288 | 155,518 | 3.6% | 155,462 | 3.6% |
| Transaction vsize | 43,792 | 42,352 | 3.3% | 42,337 | 3.3% |
| Discounted vsize | 21,780 | 20,336 | 6.6% | 20,322 | 6.7% |

The engineering case is primarily reduced consensus/witness complexity and
direct recoverability, not fee savings alone. Prebound commitments make program
bytes fall only modestly, while removing eight factor words cuts covenant
witness bytes by 85.5% and eliminates required annex padding in this corpus.

## Protocol-owner checklist

Acceptance means each choice below is intentional:

- [x] Every market RT is confidential and has value exactly one.
- [x] The four published scalars become permanent binary-market-v1 consensus
  constants in the stated big-endian encoding.
- [x] Complementary YES/NO CBFs are relied on for explicit-only canonical
  creation and locally neutral composition.
- [x] Canonical creation always places both RT legs on A; all live pairs must
  share one side.
- [x] Every continuation and terminal burn flips both legs, including full
  cancellation back to Dormant.
- [x] Terminal RTs are opposite-side confidential outputs at bare `OP_RETURN`,
  not explicit burns.
- [x] Reissuance uses the inferred input-side ABF as its exact Elements nonce
  while the continuation goes to the opposite side.
- [x] Raw on-chain `TxOut` commitments are authoritative; RPC, database, or
  caller side metadata is never trusted as protocol state.
- [x] Side-specific VBFs remain necessary even though a leg's A/B value
  commitment is byte-identical.
- [x] Recovery payloads remain 38 or 70 bytes (40 or 72 complete script bytes),
  with no A/B field or tag change.
- [x] Rolling is replaced cleanly: no compatibility path, deployed-state
  migration, or redb schema-version bump.
- [x] The measured complexity/size trade-off is acceptable, including the
  documented provenance limitation on the exact rolling full-market rows.
- [x] The known oracle-resolution/expiry race and oracle trust model are
  unchanged by this decision.

## Focused review checklist

The external reviewer should work from the recorded implementation commit:

- [ ] Independently reduce `-YES_CBF mod n` and all four VBFs.
- [ ] Independently derive the six compressed commitments, including prefix
  parity and x-coordinate byte order, and reproduce the nonuniform-asset-ID
  vectors without using Rust `elements` commitment helpers.
- [ ] Confirm the one-unit Pedersen algebra and that it is not generalized to
  another RT amount.
- [ ] Confirm creation validation binds each unique defining issuance of exactly
  one RT atom to the exact value-one side-A dormant output and, given Elements
  consensus, thereby exhausts all spendable RT authority.
- [ ] Confirm the covenant recognizes exactly one role-specific input side,
  synchronizes both legs, and requires the opposite continuation/burn side.
- [ ] Confirm issuance binds the nonce to the input side for both legs.
- [ ] Confirm rangeproof VBFs and the complete canonical surjection domain agree
  with Elements serialization and proof APIs.
- [ ] Confirm Rust builder/interpreter, node registration, and independent
  client replay fail closed on the same commitment/side shapes.
- [ ] Reproduce the CMR and review the covenant/witness diff from
  `ed6de4c4c8a177b4a4ba92c2bac17f55b324781f`.
- [ ] Reproduce the current A/B full-market rows. If acceptance depends on the
  exact rolling full-market percentages, reconstruct and review equivalent
  instrumentation at `ed6de4c...`; otherwise record acceptance of the preserved
  capture and the independently reproducible isolated comparison.
- [ ] Confirm recovery tags and 38/70-byte payloads are unchanged and recover
  the fixed side-A commitments.
- [ ] Confirm no rolling path, migration machinery, generated smplx artifact,
  or schema bump is committed.

## Review and acceptance record

An automated read-only audit traced the scalar algebra through compiler,
Simplicity covenant, proof builder, Rust interpreter, registration, and client
replay and found no production-code defect. This is implementation assurance,
not a substitute for the focused human review above.

| Field | Value |
|---|---|
| Independent vector method/result | Python big integers reproduced all CBF/VBF arithmetic; standalone C using upstream libsecp256k1-zkp reproduced the fixture and nonuniform-asset-ID commitment sets; isolated Simplex 0.0.6 build reproduced the CMR; all matched on 2026-07-13 |
| Automated implementation audit | No production A/B findings; 2026-07-13 |
| External reviewer | `<PENDING>` |
| Commit reviewed | `<PENDING>` |
| Review date | `<PENDING>` |
| Findings and dispositions | `<PENDING>` |
| Reviewer conclusion | `<PENDING>` |

- [x] Clean pinned-Nix CI is recorded against the candidate commit.
- [ ] Every focused-review finding has a disposition.
- [x] Every protocol-owner checkbox is checked.
- [ ] ADR 0005 is changed from Proposed to Accepted only after those reviews.

| Role | Name | Date | Commit | Decision |
|---|---|---|---|---|
| Implementation owner | Codex candidate | 2026-07-13 | `7ed20b8b81306eaf81ee49b80b4ea65b49804871` | Engineering-complete |
| External reviewer | `<PENDING>` | `<PENDING>` | `<PENDING>` | `<PENDING>` |
| Protocol owner | Tommy Volk | 2026-07-14 | `7ed20b8b81306eaf81ee49b80b4ea65b49804871` | Approved |

## Rolling retirement record

The final candidate contains no rolling code or `deadcat-rt-study` crate. The
hardened rolling source remains at commit `ed6de4c...`, and the reproducible
isolated comparison remains at commit `25ad409...`. The exact rolling
full-market rows under `docs/measurements/` are a preserved capture with the
provenance limitation described above. The database schema stays at version 1
because no deployed data exists.

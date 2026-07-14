# Architecture decision records

These records capture protocol and architecture choices that are expensive to
change after covenant CMRs or public wire formats exist.

| ADR | Decision |
|---|---|
| [0001](0001-authority-and-shared-node.md) | This repository is authoritative; the node is shared-safe and keyless |
| [0002](0002-v1-contract-scope.md) | V1 contains the binary market and maker order; LMSR is deferred |
| [0003](0003-order-economics.md) | Orders use exact integer prices and one minimum active amount |
| [0004](0004-chain-state-and-reorgs.md) | Chain transactions apply atomically; confirmed-tip state rolls back two blocks |
| [0005](0005-rt-blinding-schedule.md) | **Proposed:** complementary A/B RT engineering evidence and protocol-owner approval are complete; focused external review remains |

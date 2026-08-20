# Architecture decision records

These records capture protocol and architecture choices that are expensive to
change after covenant CMRs or public wire formats exist.

| ADR | Decision |
|---|---|
| [0001](0001-authority-and-shared-node.md) | This repository is authoritative; the node is shared-safe and keyless; routing responsibility is amended by ADR 0006 |
| [0002](0002-v1-contract-scope.md) | **Partially superseded:** historical two-contract alpha scope; binary-market decisions retained by ADR 0006 |
| [0003](0003-order-economics.md) | **Historical:** the removed maker experiment used exact integer prices and one minimum active amount |
| [0004](0004-chain-state-and-reorgs.md) | Chain transactions apply atomically; confirmed-tip state rolls back two blocks |
| [0005](0005-rt-blinding-schedule.md) | **Proposed:** complementary A/B RT engineering evidence and protocol-owner approval are complete; focused external review remains |
| [0006](0006-rfq-first-liquidity-scope.md) | **Accepted:** production is market-only with separate noncustodial RFQ liquidity and client-owned routing |
| [0007](0007-rfq-provider-state-machine.md) | **Accepted:** RFQ inputs commit durably before signing and never reopen after ambiguous authorization |
| [0008](0008-rfq-service-owned-wallet.md) | **Accepted:** the separate RFQ daemon uses a narrow encrypted service-owned hot wallet; Elements Core holds no provider keys |

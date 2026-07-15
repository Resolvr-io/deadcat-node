# ADR 0004: Chain-state atomicity and reorg policy

- Status: Accepted
- Date: 2026-07-12

## Decision

Confirmed Liquid transaction order is the canonical state clock:

```rust
pub struct ChainPosition {
    pub block_height: u32,
    pub tx_index: u32,
}
```

Block height alone is insufficient because one contract may advance more than
once in a block and one transaction may advance multiple contracts.

The node uses one chain-ordered coordinator. Within each confirmed block it
processes transactions in `tx_index` order. For each transaction it:

1. resolves every tracked contract input touched by the transaction;
2. interprets all affected contract legs against the evolving intra-block
   snapshot; and
3. validates one complete, all-or-nothing transition batch.

It then commits all ordered transaction batches, current states, indexes,
transition rows, undo data, events, and the new block checkpoint in one redb
write transaction. This block-atomic write is stronger than the required
transaction atomicity: all legs caused by any one chain transaction still
appear together or not at all. Events publish only after the database commit
succeeds.

The idempotency identity is chain position, block hash, and transaction ID.
Replaying a previously committed block is a no-op only if every persisted
transaction result matches exactly. A different transaction at an occupied
position is a fork conflict and requires rollback first.

## Reorgs

The expected operational reorg bound is two blocks. The store retains atomic
per-block undo batches and chain checkpoints for at least that depth.

On a reorg of at most two blocks, rollback restores current states, indexes,
history visibility, subscriptions, and contracts created in orphaned blocks in
one coordinated operation before the replacement branch is applied.

A deeper reorg is not guessed through, and two-block undo is not treated as if
it could restore an older checkpoint. The node becomes unready, rotates its
durable-event epoch, makes `RescanRequired` sticky, and rejects chain-derived
RPCs. The local `deadcat-node rebuild` command reverifies the backend genesis
and immutable v1 activation checkpoint, clears chain materialization, history,
index, and undo tables, retains normalized contract declarations and the event
journal, and replays from the activation checkpoint before serving canonical
state again. Registration rejects creation at or before the activation
checkpoint, so that replay boundary cannot omit a supported v1 contract. Each
block is a complete persisted prefix, allowing an interrupted rebuild to
resume without another reset.

## Consequences

- There is no one-task-per-contract writer model.
- Static market/order script discovery and active-outpoint following feed one
  transaction coordinator.
- Subscribers observe durable committed order, including multiple events in
  one block and composite transactions.
- Current state is materialized for fast reads while the transition journal
  remains the canonical audit trail.

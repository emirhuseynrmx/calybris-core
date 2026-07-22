# Migrating persisted ledgers from 0.5.5 to 0.5.7

0.5.7 prevents reservation-ID reuse after recovery by storing a tagged allocator
fence in `BudgetSnapshot.version`. Untagged 0.5.5 snapshots are readable as JSON,
but are deliberately not directly restorable: the old file does not contain the
next reservation ID and the value cannot be reconstructed safely.

## Required procedure

1. Quiesce ledger writes and close or settle every active reservation.
2. Obtain `trusted_next_reservation_id` from durable history (the complete WAL,
   a database sequence, or another authoritative allocator record). It must be
   greater than every reservation ID ever issued before the checkpoint. Never
   guess it from the legacy snapshot.
3. Migrate to a **different** output path. The source file is never overwritten.
4. Restore and validate the migrated file in a staging process before switching
   the production pointer.
5. Retain the original snapshot for rollback; do not feed the tagged 0.5.7 file
   back to a 0.5.5 recovery process.

Rust:

```rust,no_run
use calybris_core::persistence::migrate_legacy_snapshot_file;

let migrated = migrate_legacy_snapshot_file(
    "checkpoint-0.5.5.json",
    "checkpoint-0.5.7.json",
    42_001, // trusted durable allocator fence
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Python:

```python
from calybris import BudgetGuard

migrated = BudgetGuard.migrate_legacy_snapshot_file(
    "checkpoint-0.5.5.json",
    "checkpoint-0.5.7.json",
    42_001,
)
```

The migration rejects active/ghost reservations, duplicate tenants, negative
ledger values, conservation failures, an absent/invalid fence, an already-tagged
snapshot, and any destination that resolves to the source through path
normalization, case folding, a symbolic link, or a hard link.

## JavaScript boundary

The recovery tag sets the high bit of the `u64` version, so the JSON value is
larger than JavaScript's exact `Number` range. Use a BigInt-aware JSON parser and
preserve the integer lexeme exactly. A `JSON.parse` → `Number` → `JSON.stringify`
round trip is unsupported and can corrupt the allocator fence.

# PHASE 4G-0A — Workstream D: Real DEV Core Export Dry Run

## Export mechanism identified

Core (`blumax-backend`) has **no dedicated export script or endpoint** for
this purpose — confirmed by search. The only available mechanism is a
direct, **read-only** SQL query against Core's own real DEV database
(`blumax` database on the shared `blumax-platform-postgres-1` server),
executed inside an explicit `BEGIN TRANSACTION READ ONLY; ... ROLLBACK;`
block so no accidental write is even possible at the protocol level.

## Classification of Core's real `users` table (read-only query results)

| Category | Count |
|---|---|
| Total rows | 86 |
| Soft-deleted (`is_deleted`) | 10 — excluded |
| Service accounts (`is_service`) | 20 — excluded (unusable `hashed_password`, not a human identity; Blumax Auth's `ServiceAccount` is a separate concern entirely) |
| **Eligible candidate rows** (`NOT is_deleted AND NOT is_service`) | **56** |
| — of which: platform admins (`is_platform_admin`) | 4 |
| — of which: inactive (`NOT is_active`) | 10 |
| — of which: pending temporary password (`must_change_password`) | 41 |
| Exact duplicate emails among eligible rows | 0 |
| Normalized (trim+lowercase) collisions among eligible rows | 0 |
| Whitespace-padded emails | 0 |
| Mixed-case emails | 0 |
| Null/blank emails | 0 |
| Hash format (all 56 eligible rows) | 100% bcrypt (`$2b$` prefix) |

**Honest finding, not oversold**: this DEV environment's real data is
clean — none of the anomaly categories Phase 4E/4F's synthetic datasets
deliberately exercised (duplicates, malformed UUIDs, case collisions)
actually occur here. The tool's handling of those anomalies was already
proven exhaustively against synthetic data; this phase's job was to
confirm the **real population is directly migratable**, which it is.

## Export produced

56 rows, `{id, identifier, hashed_password, is_active}` shape, written to
an immutable (`chmod 400`) scratch file. Service accounts and soft-deleted
rows were excluded from the export entirely (not merely flagged) — they
are not candidates for identity migration; migrating a service account's
row as a human identity would be meaningless (unusable password) and
migrating a soft-deleted user would resurrect a deliberately-removed
account.

## Dry run

```
Total source rows read: 56
Would migrate: 56
Already existing (idempotent skip, untouched): 0
Duplicates within source: 0
Conflicts: 0
Invalid rows: 0
Unexpected errors: 0
```
Exit code 0 (clean).

## Controlled DEV import

Pre-import gate, all confirmed before `--execute`:
- Target: `blumax_auth` database, dedicated role, on the real DEV Postgres server — not Core's or Labs' database.
- Environment: the real `dev-auth` service (Workstream A), not production (confirmed via Phase 4G-0's finding that Blumax Auth has never been deployed to production at all).
- A `pg_dump` snapshot of the (near-empty) `blumax_auth` database was taken before import.
- Core's `users` table row count reconfirmed unchanged (86) immediately before import, proving the earlier read-only export made no mutation.

Execution: **56/56 migrated, 0 errors.**

## Post-import verification

- **Row count**: 56 in `blumax_auth.users` immediately after import.
- **Idempotent re-run**: 0 migrated, 56 `already_exists`, row count unchanged at 56 — re-run is a true no-op.
- **Byte-for-byte integrity**: a 5-row sample compared directly between Core's `users` and Blumax Auth's `users` — `id`, email/identifier, `hashed_password`, and `is_active` are **identical**, confirming zero re-hashing and exact UUID preservation.
- **Login path exercised against real migrated identities**: a wrong-password attempt against a real migrated identifier (`hemanth@gmail.com`) and a nonexistent identifier both returned byte-identical `401 "Invalid credentials"` responses — confirming Blumax Auth's constant-time, no-enumeration design correctly protects real migrated identities. **Deliberately not attempted**: logging in with a *correct* real password, since this session has no legitimate way to know any real DEV user's actual password and guessing/brute-forcing one would not be an acceptable test method. The "correct password succeeds" path was already proven exhaustively with controlled, self-chosen passwords in Phase 4F and this phase's Workstream A/B live tests — this is a scope limitation, not a gap in the tool.

## Core database integrity

Confirmed unchanged throughout: `SELECT count(*) FROM users` on Core's
real database returned 86 both before the export and after the import —
the read-only transaction never wrote anything, and nothing in this
phase's work ever opened a write connection to Core's database.

## Idempotency / invariant checklist (real data)

- One bad row does not kill the batch — N/A this run (0 invalid rows in real data), already proven exhaustively on synthetic data (Phase 4F).
- Duplicates never silently merged — N/A this run (0 duplicates), already proven on synthetic data.
- Stable UUIDs remain stable — confirmed, byte-for-byte.
- A re-run is idempotent — confirmed, 0 migrated on second run.
- No production system was touched — confirmed; Blumax Auth has no production deployment to touch (Phase 4G-0).

## Cleanup

Five unrelated test identities this phase had created in `dev-auth` for
Workstream A/B verification were removed from the `blumax_auth` database
after use, leaving exactly the 56 genuinely migrated real identities.

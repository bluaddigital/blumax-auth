# PHASE 4F — LABS MIGRATION TOOL HARDENING REPORT

## A. Scope statement

This phase hardens `scripts/migrate_core_user.py` (blumax-auth repo) so a
real Core identity export can be validated safely before any production
cutover. It does **not** perform the Labs production authentication
cutover, does not remove or disable Core authentication, and does not
begin Phase 4G. No Core, Pharmacy, SuperAdmin, or production system was
touched. No destructive migration ran against any non-disposable
database.

## B. Starting state (read before modifying)

- Entry point: `scripts/migrate_core_user.py`, invoked as
  `python scripts/migrate_core_user.py --source-json <path> [--execute]`.
- Source identity schema (Core export, JSON): `id` (UUID string),
  `identifier` (string), `hashed_password` (bcrypt hash string),
  `is_active` (bool).
- Destination identity schema: `app/models/user.py`'s `User` — `id` (UUID
  PK), `identifier` (unique, NOT NULL), `hashed_password` (NOT NULL),
  `is_active` (NOT NULL). No tenant/role/facility columns by design.
- Pre-existing idempotency mechanism: an `id`-existence check before
  insert (kept, now explicitly ordered first in the new `classify`).
- Pre-existing uniqueness constraints: `users.identifier` unique index
  (DB-level); `users.id` primary key (DB-level). Neither was altered.
- Pre-existing failure behavior (Phase 4E findings, now fixed by this
  phase): a single malformed UUID crashed loading the entire source file;
  a single duplicate `identifier` aborted the whole batch via one
  end-of-batch `commit()`; email case/whitespace was never normalized,
  so two variants of the same mailbox silently became two distinct users.
- Pre-existing test coverage: 4 tests in `tests/test_migration_script.py`
  (fresh-insert, write-with-preserved-id, idempotent-skip,
  identifier-conflict-flagged). All 4 preserved under the new interface,
  intent unchanged (Section F).
- `tests/conftest.py`'s `db_session` fixture is a plain `AsyncSessionLocal()`
  with no outer transaction/SAVEPOINT wrapper (schema reset is a
  drop-all/create-all between tests instead) — confirmed before
  finalizing the per-row-commit design, so per-row `commit()` calls behave
  identically under test and in production.

## C. The four hardening items (what changed, and why)

1. **Preflight duplicate detection** (`classify`): source rows are now
   checked against each other, before any database write, using two
   indexes built over the rows not already migrated — by `id` and by
   normalized `identifier`. Every row sharing a duplicated key is
   excluded from `to_insert` and reported as `DUPLICATE_ID_IN_SOURCE` or
   `DUPLICATE_IDENTIFIER_IN_SOURCE`, naming every other row number it
   collides with. The tool never silently keeps one of two conflicting
   rows and discards the other — both are held back for operator
   resolution.
2. **Per-row-tolerant parsing** (`parse_row`/`load_source_json`): a
   malformed row (bad UUID, missing field, non-boolean `is_active`) is
   rejected individually, as an `InvalidRow` with a reason code, field
   name, and a safe-to-print value. The rest of the file still loads.
   Only a genuinely unparseable JSON *file* raises — a distinct,
   precondition-level failure, not a per-row one.
3. **Email normalization policy** (`normalize_identifier`): trim
   whitespace, then lowercase — nothing more. No dot-removal, no
   plus-addressing stripping, no Unicode or domain canonicalization.
   Documented at the top of the module and in the function's own
   docstring as a deliberate boundary, not an oversight. Used only for
   comparison; see Section D for what is actually persisted.
4. **Orphan detection** (`detect_orphans`): a new, optional, read-only
   cross-reference between an operator-supplied list of Labs'
   `LabUser.core_user_id` values (`--labs-core-user-ids-json`, a plain
   JSON array of UUID strings the Labs operator produces themselves) and
   the current run's source export. A Labs id absent from the export is
   reported as `ORPHAN_LABS_IDENTITY` — never auto-deleted, auto-unlinked,
   or auto-replaced with a new identity. This script has no live
   connection to Labs' or Core's database at all.

## D. Transaction-safety redesign

`apply_plan` now commits each row individually instead of once for the
whole batch. A row that fails at insert time (an `IntegrityError` the
preflight didn't anticipate, or any other unexpected exception) is caught,
rolled back **for that row only**, and recorded in an `errors` list —
processing continues with the next row. BAD ROW ≠ CORRUPTED MIGRATION:
an earlier row's already-committed insert is never undone by a later
row's failure, and no partially-written row is ever left behind (each
row is either fully committed or fully rolled back, never half-applied).

On the normalization/persistence split: the normalized identifier
(trim+lowercase) is both the comparison key and the value actually
stored in `users.identifier`, since Blumax Auth's schema has no separate
raw/normalized column. `ValidRow.raw_identifier` keeps the as-supplied
string around for reporting only, so an operator reading a duplicate or
conflict report sees exactly what Core exported, not a normalized form
that might look like a tool-introduced discrepancy.

## E. Reporting and exit-code policy

Exit code 0: every row classified as `migrated` (or `to_insert` on a
dry run) or `already_exists`, zero orphans if orphan-checking was
requested. Exit code 1: any `invalid`, `duplicate`, `conflict`, `error`,
or `orphan` row exists — in dry-run or `--execute`, identically, so a
problematic run can never be mistaken for a clean one by exit code alone.
Idempotent `already_exists` skips never count as a failure. Full category
counts are always printed, followed by a per-row breakdown for every
non-clean category; `hashed_password` values are never printed anywhere
in the report (Section K).

## F. Existing tests preserved

All 4 original tests (`test_fresh_rows_are_all_planned_for_insert`,
`test_apply_plan_writes_rows_with_preserved_ids`,
`test_already_migrated_id_is_skipped_not_reinserted`,
`test_identifier_conflict_is_flagged_not_silently_overwritten`) are
still present, under the same names, asserting the same intent —
adapted only to call `classify`/`ValidRow` instead of the old
`plan_migration`/`SourceUserRow` names, and to read `plan.already_exists`/
`plan.conflicts` (now a list of `ConflictRow` objects, not raw tuples).
None were deleted or weakened.

## G. New tests (A–K)

| Test | Proves |
|---|---|
| A | Duplicate `id` within source excludes **both** rows, neither silently kept |
| B | Duplicate identifier after case/whitespace normalization excludes **both** rows |
| C | A single malformed UUID is rejected per-row; the rest of the file still loads |
| D | Multiple malformed UUIDs (scattered through a file) are each rejected independently, with correct row numbers |
| E | Orphan detection is a pure, read-only function — reports exactly the Labs ids absent from the export, nothing else |
| F | A fully clean batch migrates with zero anomalies of any kind |
| G | A clean batch re-run is fully idempotent — second pass migrates 0, flags all as `already_exists`, row count unchanged |
| H | An existing destination identity is never overwritten, even if the source row's password/active-flag has changed in a stale re-export |
| I | Normalization is exactly trim+lowercase — explicitly confirms dot-addressing and plus-addressing are left untouched, and that a case/whitespace variant persists in normalized form |
| J | A 70-row mixed-quality batch (50 clean, 5 malformed, 5 duplicate, 5 conflicting, 5 already-existing) classifies every row into exactly the right category, in one run |
| K | An unexpected per-row DB failure (a NULL `hashed_password` slipping past preflight) is caught and reported without aborting rows before or after it in the batch |

## H. Regression results

- `tests/test_migration_script.py`: **15/15 passed** (4 preserved + 11 new).
- Full `blumax-auth` suite (`tests/`): **106/106 passed**, 0 failed, 0
  skipped (one pre-existing, unrelated `passlib`/`crypt` deprecation
  warning, not introduced by this phase).
- No Labs, Pharmacy, or SuperAdmin file was modified in this phase (confirmed
  by `git status` before and after, Section M) — their own test suites are
  therefore unaffected by construction and were not re-run; the Labs-side
  identity-continuity guarantees this tool depends on were already proven
  live in Phases 4D/4E and are unchanged here.
- "Phase 4E tests" as a named file do not exist — Phase 4E's proof was a
  live DEV dataset + manual verification scripts (`p8_*.py`, scratchpad-only,
  never a committed test file), not a pytest suite. Not applicable to
  re-run; no gap introduced by omitting it.

## I. Final validation (Step 14 — larger synthetic dataset, live)

Fresh disposable Postgres 16 + Redis 7 containers (no shared state with
any prior phase's infrastructure), torn down completely afterward.
Dataset: 168 source rows — 150 clean, 10 malformed UUIDs (scattered
throughout the file, not clustered, to prove per-row tolerance isn't an
artifact of ordering), 8 rows forming 4 duplicate pairs (2 of the 4
pairs differing only by case, proving normalization-driven duplicate
detection at scale).

- **Dry run**: reported 150 would-migrate, 8 duplicates, 10 invalid, exit
  code 1. No rows written.
- **Execute**: migrated exactly 150 rows; direct row-count query confirmed
  150 total rows in the database — zero partial writes, zero rows lost
  to the 8 excluded duplicates or 10 rejected malformed rows.
- **Idempotent re-run**: 0 migrated, 150 `already_exists`, identical
  duplicate/invalid reporting, exit code unchanged (1, since the same
  unresolved duplicates/invalids are still present in the source — correctly
  distinguishing "nothing new to do" from "no problems exist").
- **Orphan-detection pass**: a 5-entry Labs `core_user_id` list (3 real,
  2 fabricated) correctly flagged exactly the 2 fabricated ones as
  `ORPHAN_LABS_IDENTITY`, with no mutation of any kind — a second run
  confirmed the report is pure/repeatable.
- **Production safety**: both containers were created fresh for this
  step and destroyed immediately after (`docker rm -f`); at no point did
  the script's `DATABASE_URL`/`REDIS_URL` point anywhere but these
  disposable containers; the script has no code path capable of reaching
  Core's or Labs' databases at all (no connection string for either exists
  anywhere in this file).

## J. Facility-scope gap — reconfirmed only, not fixed

Reconfirmed unchanged at `app/api/v1/deps.py:30-79` in the Labs repo
(read-only; file not modified). The external-token branch (lines 52-67,
handling any Core- or Blumax-Auth-issued bearer token) never reads
`LabUserFacility` — only the native-Labs-token branch (line 51) does,
because `facility_ids` only ever arrives as a JWT claim from Labs' own
login endpoint (`_resolved_facility_ids`, `app/api/v1/auth.py`). Since
Blumax Auth's frozen JWT contract deliberately carries no facility claim
(by design — Section 1 of this engagement's architecture), every
external-token request falls through to line 72's "every active facility
in the organization" fallback, identical to Core-token behavior today.

**Classification: pre-existing, not introduced or worsened by this
phase or by the planned Blumax Auth cutover — a defect in Labs' own
authorization code, orthogonal to identity migration.**
**Blocker/non-blocker**: non-blocker for Phase 4F (tooling) and for a
staged DEV cutover; **should be classified as a blocker for any
production cutover of an organization where staff are legitimately
restricted to a subset of facilities**, since under Blumax Auth every
external-token user in such an org gets broader facility access than
their explicit `LabUserFacility` grants. Recommend a dedicated,
separately-scoped phase to add a facility-ids lookup (keyed off
`LabUser.id`, independent of token claims) to the external-token branch,
before that specific production cutover — not before DEV validation
continues.

## K. Security review

- No plaintext password was logged, printed, or persisted anywhere in
  this phase's code or test output — `hashed_password` values never
  appear in `_print_report`, and tests use clearly-fake hash-shaped
  strings (`"h"`, `"$2b$12$fakehash..."`), never real bcrypt output.
  (`test_K`'s `hashed_password=None` row is used only to trigger a NOT
  NULL violation, never logged as a value.)
- No token or secret was logged — this script has no concept of a token;
  it operates on raw password hashes and UUIDs only, by column, and the
  report never prints a `hashed_password` column value.
- No automatic password reset, identity merge, orphan deletion, or UUID
  replacement exists anywhere in the new code — duplicates, conflicts,
  and orphans are purely reported; `apply_plan` only ever inserts a row
  that `classify` placed in `to_insert`, never updates or deletes an
  existing row.
- No Core database access, no cross-database SQL, no production database
  access exists in this script — it reads only from a local JSON file
  (`--source-json`) and an optional local JSON file
  (`--labs-core-user-ids-json`), and writes only to whatever
  `DATABASE_URL` its own process environment points at.

## L. Idempotency and invariant checklist (all confirmed, Section I)

- One bad row does not kill the batch. ✔ (10 malformed rows, 150 still migrated)
- Valid rows still migrate even when the file contains anomalies. ✔
- Duplicates are never silently merged — both sides are held back. ✔
- Malformed UUIDs never create a replacement identity. ✔ (rejected before any UUID object exists)
- Orphans are reported but preserved — nothing is deleted or unlinked. ✔
- Normalization is deterministic and documented. ✔ (`normalize_identifier`, Section C.3)
- A re-run is idempotent. ✔ (Section I)
- Stable UUIDs remain stable — no row's `id` is ever rewritten. ✔ (`apply_plan` only inserts)
- No production system was touched. ✔ (disposable containers only, Section I)

## M. Git state

Before and after this phase, `git status --porcelain` in `blumax-labs`,
`blumax-pharm`, and `blumax-superadmin` is **byte-identical** to the
state recorded at the start of Phase 4F — zero files touched in any of
those three repos. `blumax-auth` itself has never been committed
(`?? auth-backend/`, a pre-existing fact from far earlier in this
engagement, unrelated to this phase); within it, only
`scripts/migrate_core_user.py` and `tests/test_migration_script.py` were
modified, plus this report added under `docs/`. No commit, push, or
deploy was performed.

## N. STOP conditions encountered

None. No condition requiring a change to production architecture,
production data, or the migration contract arose during this phase.

## O. Explicit non-production-cutover disclaimer

This phase hardens the migration **tool**, nothing else. It does not
constitute, authorize, or prepare an immediate Labs production
authentication cutover. Core remains the sole production authentication
authority. No Core authentication code was touched, removed, or
disabled. Phase 4G (if it proceeds at all) is a separate, explicitly
requested phase — it was not started here.

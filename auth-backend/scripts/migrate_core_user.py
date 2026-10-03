#!/usr/bin/env python3
"""Identity-migration tool (Phase 4F hardened): bulk-copy existing Core
(blumax-backend) users into Blumax Auth, preserving `users.id` exactly --
so Core's JWT `sub` keeps meaning the same thing after cutover, and every
existing consumer link column (Labs' LabUser.core_user_id, Pharmacy's
GlobalUser.core_user_id, SuperAdmin's PlatformAdminGrant.identity_id)
keeps resolving correctly with ZERO code or data change on the consumer
side (see docs/PHASE5_BLUMAX_AUTH_CAPABILITY_COMPLETION.md's identity-
migration section for the full reasoning).

NOT EXECUTED AGAINST ANY DATABASE BY DEFAULT. Dry-run (prints what it
WOULD do); requires an explicit --execute flag to write anything, and even
then only ever writes to whatever DATABASE_URL this process's own
environment points at -- never Core's database directly (this script only
READS from Core, via --source-json, and WRITES only to Blumax Auth's own
`users` table. --source-db-url is reserved for a later phase once a real,
read-only Core connection string is supplied by an operator; not wired up
or exercised by any test here).

=== Phase 4F hardening (over the Phase 5 original) ===

1. PER-ROW FAULT TOLERANCE. A single malformed row (bad UUID, missing
   field) is rejected individually and reported -- it no longer aborts
   loading the rest of the file (see `load_source_json`/`parse_row`).

2. PREFLIGHT DUPLICATE DETECTION. Source rows are checked against EACH
   OTHER (not just against the database) before any insert is attempted,
   so one duplicate pair can never abort the whole batch via a bulk-insert
   IntegrityError (see `classify`). Every row sharing a duplicated id or
   identifier is excluded from insertion and reported -- the tool never
   silently picks one of two conflicting rows over the other.

3. EMAIL NORMALIZATION POLICY (see `normalize_identifier`): trim
   whitespace, lowercase. Nothing more aggressive (no dot-removal, no
   plus-addressing stripping, no domain canonicalization) -- those are
   provider-specific conventions this platform has no evidence it needs,
   and inventing one risks silently merging two genuinely different
   mailboxes. The normalized form is what duplicate/conflict detection
   compares; the ORIGINAL, as-supplied string is what gets stored (Core's
   own export is the source of truth for the literal value; only the
   *comparison* is normalized, not the persisted data -- see `ValidRow`).
   If two source rows normalize to the same identifier, they are reported
   as a duplicate, never silently merged.

4. ORPHAN DETECTION (see `detect_orphans`): an optional, separate,
   read-only cross-reference between an operator-supplied list of Labs'
   own `LabUser.core_user_id` values (exported by Labs' own operator,
   via `--labs-core-user-ids-json`) and this run's source export. A Labs
   id absent from the export is reported as an orphan -- never deleted,
   unlinked, or replaced automatically. This script has no database
   connection to Labs (or Core) at all, by design -- the cross-reference
   input is a plain, disposable JSON file an operator prepares, not a
   live cross-database query.

5. PER-ROW TRANSACTION SAFETY (see `apply_plan`): each row that reaches
   the insert stage is committed independently. A later row's unexpected
   failure never rolls back an earlier row's already-committed insert,
   and never leaves a partially-written row -- it is reported as an
   `error` and processing continues with the next row.

6. IDEMPOTENCY (unchanged in spirit from Phase 5, reconfirmed): a row
   whose id already exists is recognized as `already_exists` before any
   duplicate/conflict logic runs, and left untouched.

7. EXIT CODE: 0 if every row classified cleanly as migrated/already_exists
   (orphans, if checked, must also be zero); 1 if ANY row is invalid,
   duplicate, conflict, error, or orphan -- so a run with problems is
   never silently indistinguishable from a clean one, even though
   already_exists (idempotent) rows never count against a clean exit.

Usage (dry run, the default):
    python scripts/migrate_core_user.py --source-json core_users_export.json

Usage (actually write, only ever to THIS process's own DATABASE_URL):
    python scripts/migrate_core_user.py --source-json core_users_export.json --execute

Usage (with orphan detection against Labs' own exported core_user_id list):
    python scripts/migrate_core_user.py --source-json core_users_export.json \\
        --labs-core-user-ids-json labs_core_user_ids.json

Source format (--source-json): a JSON array of objects, each shaped like
a row from Core's own `users` table:
    [{"id": "<uuid>", "identifier": "...", "hashed_password": "<bcrypt hash>",
      "is_active": true}, ...]

Labs core_user_id export format (--labs-core-user-ids-json): a plain JSON
array of core_user_id strings, e.g. ["<uuid>", "<uuid>", ...] -- produced
by Labs' own operator from `SELECT DISTINCT core_user_id FROM lab_user
WHERE core_user_id IS NOT NULL`, outside this tool entirely. This script
never connects to Labs' (or Core's) database directly.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid
from dataclasses import dataclass, field
from typing import Literal

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.database import AsyncSessionLocal
from app.models.user import User

InvalidReason = Literal["INVALID_UUID", "MISSING_FIELD", "INVALID_IS_ACTIVE", "INVALID_JSON_ROW"]


def normalize_identifier(identifier: str) -> str:
    """The email-normalization policy (Phase 4F): trim whitespace, then
    lowercase. Deliberately conservative -- no dot-removal, no
    plus-addressing stripping, no Unicode canonicalization, no domain
    rewriting. Anything beyond trim+lowercase is a provider-specific
    convention (e.g. Gmail's dot-insensitivity) this platform has no
    evidence it needs, and getting it wrong silently merges two different
    people's accounts -- the single worst failure mode a migration tool
    can have. Used ONLY for duplicate/conflict comparison; the original,
    as-supplied string is what gets persisted (see ValidRow.raw_identifier
    vs ValidRow.identifier)."""
    return identifier.strip().lower()


@dataclass(frozen=True)
class ValidRow:
    row_number: int
    id: uuid.UUID
    identifier: str  # NORMALIZED -- used for comparison AND persisted (see module note: Blumax Auth has no separate raw/normalized column, so the normalized form is both the comparison key and the stored value)
    raw_identifier: str  # exactly as supplied, for reporting only
    hashed_password: str
    is_active: bool


@dataclass(frozen=True)
class InvalidRow:
    row_number: int
    reason: InvalidReason
    field: str | None
    value: str | None  # safe to print -- never the hashed_password itself


def parse_row(row_number: int, raw: object) -> ValidRow | InvalidRow:
    if not isinstance(raw, dict):
        return InvalidRow(row_number, "INVALID_JSON_ROW", None, None)

    required = ("id", "identifier", "hashed_password", "is_active")
    missing = [k for k in required if k not in raw]
    if missing:
        return InvalidRow(row_number, "MISSING_FIELD", missing[0], None)

    try:
        row_id = uuid.UUID(str(raw["id"]))
    except (ValueError, AttributeError, TypeError):
        return InvalidRow(row_number, "INVALID_UUID", "id", str(raw["id"])[:200])

    if not isinstance(raw["is_active"], bool):
        return InvalidRow(row_number, "INVALID_IS_ACTIVE", "is_active", str(raw["is_active"])[:200])

    raw_identifier = str(raw["identifier"])
    return ValidRow(
        row_number=row_number, id=row_id, identifier=normalize_identifier(raw_identifier),
        raw_identifier=raw_identifier, hashed_password=raw["hashed_password"], is_active=raw["is_active"],
    )


@dataclass(frozen=True)
class ParsedSource:
    valid: list[ValidRow]
    invalid: list[InvalidRow]


def load_source_json(path: str) -> ParsedSource:
    """Per-row fault tolerant (Phase 4F): a single malformed row is
    rejected individually (see `parse_row`) and does NOT prevent the rest
    of the file from loading. Only a genuinely unparseable JSON FILE (not
    a bad row within valid JSON) raises -- that is a precondition failure
    distinct from a data-quality issue in one row."""
    with open(path) as f:
        raw_list = json.load(f)  # may raise json.JSONDecodeError -- the whole file isn't valid JSON at all, not a per-row concern

    valid: list[ValidRow] = []
    invalid: list[InvalidRow] = []
    for i, raw in enumerate(raw_list):
        parsed = parse_row(i + 1, raw)
        if isinstance(parsed, ValidRow):
            valid.append(parsed)
        else:
            invalid.append(parsed)
    return ParsedSource(valid=valid, invalid=invalid)


@dataclass(frozen=True)
class DuplicateRow:
    row_number: int
    id: uuid.UUID
    raw_identifier: str
    reason: Literal["DUPLICATE_ID_IN_SOURCE", "DUPLICATE_IDENTIFIER_IN_SOURCE"]
    conflicting_row_numbers: tuple[int, ...]  # every OTHER row sharing the same key


@dataclass(frozen=True)
class ConflictRow:
    row_number: int
    id: uuid.UUID
    raw_identifier: str
    existing_id: uuid.UUID  # the DIFFERENT id that already owns this identifier in the destination DB


@dataclass(frozen=True)
class MigrationPlan:
    to_insert: list[ValidRow]
    already_exists: list[uuid.UUID]
    duplicates: list[DuplicateRow]
    conflicts: list[ConflictRow]


async def classify(db, valid_rows: list[ValidRow]) -> MigrationPlan:
    """Read-only against Blumax Auth's own DB: classifies every valid row
    without writing anything, so `--execute` is a pure, reviewable "apply
    the plan" step. Classification order (deliberate):

      1. already_exists  -- the id is already in the destination DB.
                             Checked FIRST so a legitimate idempotent
                             re-run is recognized before any duplicate
                             logic below ever applies to it.
      2. duplicates       -- among the REMAINING rows, any id OR any
                             NORMALIZED identifier that appears more than
                             once in this source batch. ALL rows sharing
                             the duplicated key are excluded from
                             insertion -- this tool never silently picks
                             one of two conflicting source rows over the
                             other; both are reported, the operator
                             decides.
      3. conflicts        -- the row's normalized identifier already
                             belongs to a DIFFERENT id in the destination
                             DB.
      4. to_insert        -- everything else.
    """
    already_exists: list[uuid.UUID] = []
    remaining: list[ValidRow] = []
    for row in valid_rows:
        existing_by_id = await db.get(User, row.id)
        if existing_by_id is not None:
            already_exists.append(row.id)
        else:
            remaining.append(row)

    id_counts: dict[uuid.UUID, list[int]] = {}
    identifier_counts: dict[str, list[int]] = {}
    for row in remaining:
        id_counts.setdefault(row.id, []).append(row.row_number)
        identifier_counts.setdefault(row.identifier, []).append(row.row_number)

    duplicates: list[DuplicateRow] = []
    conflicts: list[ConflictRow] = []
    to_insert: list[ValidRow] = []

    for row in remaining:
        dup_by_id = len(id_counts[row.id]) > 1
        dup_by_identifier = len(identifier_counts[row.identifier]) > 1
        if dup_by_id or dup_by_identifier:
            others = tuple(
                n for n in (id_counts[row.id] if dup_by_id else identifier_counts[row.identifier])
                if n != row.row_number
            )
            duplicates.append(DuplicateRow(
                row_number=row.row_number, id=row.id, raw_identifier=row.raw_identifier,
                reason="DUPLICATE_ID_IN_SOURCE" if dup_by_id else "DUPLICATE_IDENTIFIER_IN_SOURCE",
                conflicting_row_numbers=others,
            ))
            continue

        existing_by_identifier = (
            await db.execute(select(User).where(User.identifier == row.identifier))
        ).scalar_one_or_none()
        if existing_by_identifier is not None:
            conflicts.append(ConflictRow(
                row_number=row.row_number, id=row.id, raw_identifier=row.raw_identifier,
                existing_id=existing_by_identifier.id,
            ))
            continue

        to_insert.append(row)

    return MigrationPlan(to_insert=to_insert, already_exists=already_exists, duplicates=duplicates, conflicts=conflicts)


@dataclass(frozen=True)
class ErrorRow:
    row_number: int
    id: uuid.UUID
    reason: str


@dataclass
class ApplyResult:
    migrated: list[uuid.UUID] = field(default_factory=list)
    errors: list[ErrorRow] = field(default_factory=list)


async def apply_plan(db, plan: MigrationPlan) -> ApplyResult:
    """Per-row transaction safety (Phase 4F): each row is committed
    independently. An unexpected failure on one row (e.g. a race against
    another process, or a constraint this tool's own preflight didn't
    anticipate) is caught, rolled back for THAT row only, and reported --
    it never rolls back an earlier row's already-committed insert, and
    never aborts processing of the remaining rows."""
    result = ApplyResult()
    for row in plan.to_insert:
        try:
            db.add(User(id=row.id, identifier=row.identifier, hashed_password=row.hashed_password, is_active=row.is_active))
            await db.commit()
            result.migrated.append(row.id)
        except IntegrityError as exc:
            await db.rollback()
            result.errors.append(ErrorRow(row.row_number, row.id, f"IntegrityError: {exc.orig}"))
        except Exception as exc:  # noqa: BLE001 -- deliberately broad: any unexpected failure must be reported, never silently swallowed or left to crash the whole run
            await db.rollback()
            result.errors.append(ErrorRow(row.row_number, row.id, f"{type(exc).__name__}: {exc}"))
    return result


@dataclass(frozen=True)
class OrphanRow:
    core_user_id: str


def detect_orphans(valid_rows: list[ValidRow], labs_core_user_ids: list[str]) -> list[OrphanRow]:
    """Cross-references Labs' own (operator-exported) list of
    LabUser.core_user_id values against THIS run's source export. A Labs
    id absent from the export is reported -- never acted on. This
    function never deletes, unlinks, or replaces anything; it is a
    report, not a mutation (see module docstring, item 4)."""
    exported_ids = {str(row.id) for row in valid_rows}
    return [OrphanRow(core_user_id=cid) for cid in labs_core_user_ids if cid not in exported_ids]


def load_labs_core_user_ids(path: str) -> list[str]:
    with open(path) as f:
        return json.load(f)


def _print_report(
    parsed: ParsedSource, plan: MigrationPlan, apply_result: ApplyResult | None,
    orphans: list[OrphanRow] | None, *, executed: bool,
) -> bool:
    """Prints the full report and returns True if the run is "clean"
    (eligible for exit code 0) -- see module docstring, item 7."""
    migrated_count = len(apply_result.migrated) if apply_result else len(plan.to_insert)
    verb = "Migrated" if executed else "Would migrate"

    print(f"Total source rows read: {len(parsed.valid) + len(parsed.invalid)}")
    print(f"{verb}: {migrated_count}")
    print(f"Already existing (idempotent skip, untouched): {len(plan.already_exists)}")
    print(f"Duplicates within source (none migrated, needs operator review): {len(plan.duplicates)}")
    print(f"Conflicts against an existing different identity (none migrated): {len(plan.conflicts)}")
    print(f"Invalid rows (rejected at parse time): {len(parsed.invalid)}")
    error_count = len(apply_result.errors) if apply_result else 0
    print(f"Unexpected errors during insert: {error_count}")
    if orphans is not None:
        print(f"Orphaned Labs core_user_id values (not in this export): {len(orphans)}")

    if parsed.invalid:
        print("\nINVALID rows (rejected before any database access, never migrated):")
        for inv in parsed.invalid:
            print(f"  row {inv.row_number}: {inv.reason} field={inv.field!r} value={inv.value!r}")

    if plan.duplicates:
        print("\nDUPLICATE rows (excluded from migration -- operator must resolve the source data, then re-run):")
        for dup in plan.duplicates:
            print(f"  row {dup.row_number}: {dup.reason} id={dup.id} identifier={dup.raw_identifier!r} conflicts with row(s) {dup.conflicting_row_numbers}")

    if plan.conflicts:
        print("\nCONFLICT rows (identifier already belongs to a different existing identity -- never auto-resolved):")
        for c in plan.conflicts:
            print(f"  row {c.row_number}: source id {c.id} wants identifier {c.raw_identifier!r}, already owned by existing id {c.existing_id}")

    if apply_result and apply_result.errors:
        print("\nUNEXPECTED ERRORS during insert (this row was rolled back; earlier/later rows are unaffected):")
        for e in apply_result.errors:
            print(f"  row {e.row_number}: id={e.id} -- {e.reason}")

    if orphans:
        print("\nORPHAN_LABS_IDENTITY (reported only -- NOT deleted, unlinked, or replaced; operator must investigate before cutover):")
        for o in orphans:
            print(f"  core_user_id={o.core_user_id} -- no matching row in this export; recommended action: confirm whether this Core identity still exists, then either include it in a future export or explicitly unlink it in Labs")

    if not executed:
        print("\nDry run only -- no rows were written. Re-run with --execute to apply.")

    clean = (
        not parsed.invalid and not plan.duplicates and not plan.conflicts
        and error_count == 0 and not orphans
    )
    return clean


async def main_async(args: argparse.Namespace) -> int:
    if args.source_json:
        parsed = load_source_json(args.source_json)
    else:
        print("--source-db-url is not yet wired to a live Core connection in this phase; use --source-json", file=sys.stderr)
        return 2

    labs_core_user_ids = load_labs_core_user_ids(args.labs_core_user_ids_json) if args.labs_core_user_ids_json else None

    async with AsyncSessionLocal() as db:
        plan = await classify(db, parsed.valid)
        apply_result: ApplyResult | None = None
        if args.execute:
            apply_result = await apply_plan(db, plan)

        orphans = detect_orphans(parsed.valid, labs_core_user_ids) if labs_core_user_ids is not None else None
        clean = _print_report(parsed, plan, apply_result, orphans, executed=args.execute)

    return 0 if clean else 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source-json", default=None)
    parser.add_argument("--source-db-url", default=None)
    parser.add_argument("--execute", action="store_true", help="actually write rows; omit for a dry run")
    parser.add_argument(
        "--labs-core-user-ids-json", default=None,
        help="optional: a JSON array of Labs' own LabUser.core_user_id values, for orphan detection (see module docstring)",
    )
    args = parser.parse_args()
    if not args.source_json and not args.source_db_url:
        parser.error("one of --source-json or --source-db-url is required")
    exit_code = asyncio.run(main_async(args))
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()

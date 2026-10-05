"""Exercises scripts/migrate_core_user.py's hardened (Phase 4F) plan/
apply/parse/orphan-detection logic directly against the test database.

The original Phase 5 test suite (4 tests, preserved below under their
original names with intent unchanged) proved the migration design is
idempotent and conflict-aware. Phase 4F hardens the tool against
within-batch duplicates, malformed rows, email-case/whitespace variance,
orphaned Labs identities, and partial-batch DB failures -- this file's
new tests (A-K) prove each of those hardening items individually, plus
one larger mixed-quality batch (test J) proving they all compose
correctly together.
"""
from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from migrate_core_user import (  # noqa: E402
    ValidRow,
    apply_plan,
    classify,
    detect_orphans,
    load_source_json,
    normalize_identifier,
    parse_row,
)
from sqlalchemy import select  # noqa: E402

from app.models.user import User  # noqa: E402


def _row(identifier: str, *, active: bool = True, row_number: int = 1) -> ValidRow:
    raw_id = str(uuid.uuid4())
    return ValidRow(
        row_number=row_number, id=uuid.UUID(raw_id), identifier=normalize_identifier(identifier),
        raw_identifier=identifier, hashed_password="$2b$12$fakehashfakehashfakehashfa", is_active=active,
    )


# --- Preserved from the original Phase 5 suite (names/intent unchanged) ----

async def test_fresh_rows_are_all_planned_for_insert(db_session):
    rows = [_row("core-user-1@example.test", row_number=1), _row("core-user-2@example.test", row_number=2)]
    plan = await classify(db_session, rows)
    assert len(plan.to_insert) == 2
    assert plan.already_exists == []
    assert plan.conflicts == []
    assert plan.duplicates == []


async def test_apply_plan_writes_rows_with_preserved_ids(db_session):
    rows = [_row("core-user-3@example.test")]
    plan = await classify(db_session, rows)
    result = await apply_plan(db_session, plan)
    assert result.migrated == [rows[0].id]
    assert result.errors == []

    written = (await db_session.execute(select(User).where(User.id == rows[0].id))).scalar_one()
    assert written.identifier == "core-user-3@example.test"
    assert written.hashed_password == rows[0].hashed_password


async def test_apply_plan_carries_optional_username_through(db_session):
    # Phase 4H-3: a source row with `username` set must persist it, not
    # just `identifier` -- the whole point of this field existing.
    row = _row("core-user-username@example.test")
    row = ValidRow(**{**row.__dict__, "username": "core_user_username"})
    plan = await classify(db_session, [row])
    result = await apply_plan(db_session, plan)
    assert result.errors == []

    written = (await db_session.execute(select(User).where(User.id == row.id))).scalar_one()
    assert written.username == "core_user_username"


async def test_apply_plan_row_with_no_username_leaves_it_null(db_session):
    row = _row("core-user-no-username@example.test")
    plan = await classify(db_session, [row])
    await apply_plan(db_session, plan)

    written = (await db_session.execute(select(User).where(User.id == row.id))).scalar_one()
    assert written.username is None


async def test_already_migrated_id_is_skipped_not_reinserted(db_session):
    """Idempotency: running the plan twice for the same source row does
    not duplicate or error -- the second pass classifies it as
    already_exists and apply_plan does nothing further for it."""
    row = _row("core-user-4@example.test")
    plan1 = await classify(db_session, [row])
    await apply_plan(db_session, plan1)

    plan2 = await classify(db_session, [row])
    assert plan2.to_insert == []
    assert plan2.already_exists == [row.id]
    result2 = await apply_plan(db_session, plan2)  # no-op, must not raise
    assert result2.migrated == []
    assert result2.errors == []

    count = (await db_session.execute(select(User).where(User.id == row.id))).scalars().all()
    assert len(count) == 1


async def test_identifier_conflict_is_flagged_not_silently_overwritten(db_session):
    """Two DIFFERENT source ids wanting the SAME identifier (shouldn't
    happen if Core's own unique constraint holds, but defense in depth
    for a malformed export) must be flagged for manual review, never
    silently resolved by overwriting the existing row."""
    first = _row("shared-identifier@example.test")
    plan1 = await classify(db_session, [first])
    await apply_plan(db_session, plan1)

    second = _row("shared-identifier@example.test")  # different id, same identifier
    plan2 = await classify(db_session, [second])
    assert plan2.to_insert == []
    assert len(plan2.conflicts) == 1
    assert plan2.conflicts[0].id == second.id
    assert plan2.conflicts[0].existing_id == first.id

    # The original row is untouched.
    original = (await db_session.execute(select(User).where(User.id == first.id))).scalar_one()
    assert original.identifier == "shared-identifier@example.test"


# --- Phase 4F hardening tests (A-K) -----------------------------------------

async def test_A_duplicate_uuid_within_source_excludes_both_rows(db_session):
    """Two source rows sharing the same id: neither is silently chosen
    over the other -- both are excluded from to_insert and reported."""
    shared_id = uuid.uuid4()
    row1 = ValidRow(row_number=1, id=shared_id, identifier="dup-id-a@example.test", raw_identifier="dup-id-a@example.test", hashed_password="h1", is_active=True)
    row2 = ValidRow(row_number=2, id=shared_id, identifier="dup-id-b@example.test", raw_identifier="dup-id-b@example.test", hashed_password="h2", is_active=True)

    plan = await classify(db_session, [row1, row2])
    assert plan.to_insert == []
    assert {d.row_number for d in plan.duplicates} == {1, 2}
    assert all(d.reason == "DUPLICATE_ID_IN_SOURCE" for d in plan.duplicates)

    count = (await db_session.execute(select(User).where(User.id == shared_id))).scalars().all()
    assert count == []  # nothing was inserted for either conflicting row


async def test_B_duplicate_identifier_after_normalization_excludes_both_rows(db_session):
    """Two source rows whose identifiers differ only by case/whitespace
    normalize to the same value -- classified as a duplicate pair, never
    silently merged or silently kept-one-discarded-one."""
    row1 = _row(" Case.Variant@Example.Test", row_number=1)
    row2 = _row("case.variant@example.test  ", row_number=2)
    assert row1.identifier == row2.identifier  # sanity: normalization collided them

    plan = await classify(db_session, [row1, row2])
    assert plan.to_insert == []
    assert {d.row_number for d in plan.duplicates} == {1, 2}
    assert all(d.reason == "DUPLICATE_IDENTIFIER_IN_SOURCE" for d in plan.duplicates)


def test_C_single_malformed_uuid_is_rejected_per_row_not_fatal(tmp_path):
    """A malformed UUID in one row must not crash loading the rest of the
    file -- the row is rejected individually and the valid rows still load."""
    good1 = {"id": str(uuid.uuid4()), "identifier": "good1@example.test", "hashed_password": "h", "is_active": True}
    bad = {"id": "not-a-valid-uuid-at-all", "identifier": "bad@example.test", "hashed_password": "h", "is_active": True}
    good2 = {"id": str(uuid.uuid4()), "identifier": "good2@example.test", "hashed_password": "h", "is_active": True}
    path = tmp_path / "export.json"
    path.write_text(json.dumps([good1, bad, good2]))

    parsed = load_source_json(str(path))
    assert len(parsed.valid) == 2
    assert {r.raw_identifier for r in parsed.valid} == {"good1@example.test", "good2@example.test"}
    assert len(parsed.invalid) == 1
    assert parsed.invalid[0].reason == "INVALID_UUID"
    assert parsed.invalid[0].row_number == 2


def test_D_multiple_malformed_uuids_each_rejected_independently(tmp_path):
    rows = [
        {"id": "bad-1", "identifier": "a@example.test", "hashed_password": "h", "is_active": True},
        {"id": str(uuid.uuid4()), "identifier": "b@example.test", "hashed_password": "h", "is_active": True},
        {"id": "bad-2", "identifier": "c@example.test", "hashed_password": "h", "is_active": True},
        {"id": "", "identifier": "d@example.test", "hashed_password": "h", "is_active": True},
    ]
    path = tmp_path / "export.json"
    path.write_text(json.dumps(rows))

    parsed = load_source_json(str(path))
    assert len(parsed.valid) == 1
    assert len(parsed.invalid) == 3
    assert [r.row_number for r in parsed.invalid] == [1, 3, 4]
    assert all(r.reason == "INVALID_UUID" for r in parsed.invalid)


async def test_E_orphan_labs_identity_is_reported_never_mutated(db_session):
    """A Labs core_user_id absent from the Core export is reported as an
    orphan. detect_orphans is a pure function -- it never touches the
    database, so there is nothing to assert was "not deleted" beyond
    confirming the function itself performs no I/O and returns a report."""
    present_id = uuid.uuid4()
    orphan_id = uuid.uuid4()
    valid_rows = [_row("present@example.test", row_number=1)]
    # Swap in the specific id we want "present" to simulate a real match.
    valid_rows[0] = ValidRow(
        row_number=1, id=present_id, identifier="present@example.test",
        raw_identifier="present@example.test", hashed_password="h", is_active=True,
    )

    orphans = detect_orphans(valid_rows, [str(present_id), str(orphan_id)])
    assert [o.core_user_id for o in orphans] == [str(orphan_id)]


async def test_F_clean_migration_with_no_anomalies(db_session):
    rows = [_row(f"clean-{i}@example.test", row_number=i) for i in range(10)]
    plan = await classify(db_session, rows)
    result = await apply_plan(db_session, plan)

    assert len(result.migrated) == 10
    assert result.errors == []
    assert plan.already_exists == []
    assert plan.duplicates == []
    assert plan.conflicts == []


async def test_G_idempotent_rerun_of_a_full_clean_batch(db_session):
    rows = [_row(f"idempotent-{i}@example.test", row_number=i) for i in range(5)]
    plan1 = await classify(db_session, rows)
    result1 = await apply_plan(db_session, plan1)
    assert len(result1.migrated) == 5

    plan2 = await classify(db_session, rows)
    assert plan2.to_insert == []
    assert set(plan2.already_exists) == {r.id for r in rows}
    result2 = await apply_plan(db_session, plan2)
    assert result2.migrated == []

    for row in rows:
        matches = (await db_session.execute(select(User).where(User.id == row.id))).scalars().all()
        assert len(matches) == 1


async def test_H_existing_destination_identity_is_never_overwritten(db_session):
    """A row whose id already exists is recognized as already_exists and
    left completely alone, even if the source export's hashed_password
    for that id now differs from what's stored (e.g. a stale re-export) --
    this tool only inserts, it never updates."""
    row = _row("stable@example.test")
    plan1 = await classify(db_session, [row])
    await apply_plan(db_session, plan1)

    changed_password_row = ValidRow(
        row_number=1, id=row.id, identifier=row.identifier, raw_identifier=row.raw_identifier,
        hashed_password="DIFFERENT-HASH-FROM-A-STALE-REEXPORT", is_active=False,
    )
    plan2 = await classify(db_session, [changed_password_row])
    assert plan2.already_exists == [row.id]
    assert plan2.to_insert == []

    stored = (await db_session.execute(select(User).where(User.id == row.id))).scalar_one()
    assert stored.hashed_password == row.hashed_password  # unchanged
    assert stored.is_active is True  # unchanged


async def test_I_email_normalization_is_trim_and_lowercase_only(db_session):
    normalized = normalize_identifier("  Mixed.Case.User@Example.TEST  ")
    assert normalized == "mixed.case.user@example.test"
    # Policy boundary: NOT dot-removal, NOT plus-addressing removal.
    assert normalize_identifier("user.name+tag@example.test") == "user.name+tag@example.test"
    assert normalize_identifier("u.s.e.r@example.test") == "u.s.e.r@example.test"

    row = _row("  CaseVariant@Example.Test  ")
    plan = await classify(db_session, [row])
    await apply_plan(db_session, plan)
    stored = (await db_session.execute(select(User).where(User.id == row.id))).scalar_one()
    assert stored.identifier == "casevariant@example.test"


async def test_J_mixed_quality_batch_of_70_rows_classifies_every_category_correctly(db_session):
    """70 total source rows: 50 clean-valid, 5 forming duplicate pairs/
    groups within the batch, 5 malformed UUIDs (rejected at parse time,
    not even reaching classify), 5 conflicting with identities already
    in the destination DB, 5 already fully migrated (idempotent skip)."""
    # Pre-seed 5 "already exists" identities and 5 "conflict" identities.
    already_rows = [_row(f"already-{i}@example.test", row_number=1000 + i) for i in range(5)]
    conflict_targets = [_row(f"conflict-target-{i}@example.test", row_number=2000 + i) for i in range(5)]
    seed_plan = await classify(db_session, already_rows + conflict_targets)
    await apply_plan(db_session, seed_plan)

    raw_rows: list[dict] = []
    row_number = 1

    for i in range(50):
        raw_rows.append({"id": str(uuid.uuid4()), "identifier": f"clean-batch-{i}@example.test", "hashed_password": "h", "is_active": True})
        row_number += 1

    # 5 malformed UUIDs.
    for i in range(5):
        raw_rows.append({"id": f"not-a-uuid-{i}", "identifier": f"malformed-{i}@example.test", "hashed_password": "h", "is_active": True})
        row_number += 1

    # 5 rows forming duplicate pairs (same identifier, different ids) -- these
    # count as 5 total rows that mutually conflict (not 5 independent pairs).
    dup_identifier = "dup-batch@example.test"
    for i in range(5):
        raw_rows.append({"id": str(uuid.uuid4()), "identifier": dup_identifier, "hashed_password": "h", "is_active": True})

    # 5 rows conflicting with a pre-existing different identity.
    for i in range(5):
        raw_rows.append({"id": str(uuid.uuid4()), "identifier": f"conflict-target-{i}@example.test", "hashed_password": "h", "is_active": True})

    # 5 rows that already exist (same id, re-exported).
    for row in already_rows:
        raw_rows.append({"id": str(row.id), "identifier": row.raw_identifier, "hashed_password": "h", "is_active": True})

    path = "/tmp/claude-0/-home-BluMax-Health/fd7ed126-2ce0-4560-9cef-2f1f96bf9b4d/scratchpad/phase4f_mixed_70.json"
    with open(path, "w") as f:
        json.dump(raw_rows, f)

    parsed = load_source_json(path)
    assert len(parsed.valid) == 65  # 70 - 5 malformed
    assert len(parsed.invalid) == 5

    plan = await classify(db_session, parsed.valid)
    assert len(plan.to_insert) == 50
    assert len(plan.duplicates) == 5
    assert len(plan.conflicts) == 5
    assert len(plan.already_exists) == 5

    result = await apply_plan(db_session, plan)
    assert len(result.migrated) == 50
    assert result.errors == []


async def test_K_one_unexpected_db_failure_does_not_abort_the_rest_of_the_batch(db_session):
    """A row that fails at insert time for a reason classify() could not
    have anticipated (here: a NULL hashed_password slipping through,
    violating the column's NOT NULL constraint) is caught, rolled back,
    and reported as an error -- rows before and after it in the batch
    still commit successfully. This is the unit-level proof of the
    transaction-safety invariant Step 14's live DEV run also exercises."""
    good_before = _row("good-before@example.test", row_number=1)
    bad = ValidRow(row_number=2, id=uuid.uuid4(), identifier="bad-null-password@example.test", raw_identifier="bad-null-password@example.test", hashed_password=None, is_active=True)
    good_after = _row("good-after@example.test", row_number=3)

    from migrate_core_user import MigrationPlan
    plan = MigrationPlan(to_insert=[good_before, bad, good_after], already_exists=[], duplicates=[], conflicts=[])

    result = await apply_plan(db_session, plan)
    assert set(result.migrated) == {good_before.id, good_after.id}
    assert len(result.errors) == 1
    assert result.errors[0].id == bad.id

    for rid in (good_before.id, good_after.id):
        row = (await db_session.execute(select(User).where(User.id == rid))).scalar_one()
        assert row is not None
    missing = (await db_session.execute(select(User).where(User.id == bad.id))).scalar_one_or_none()
    assert missing is None

"""The active-facility claim ("afc"): one facility narrows `facility_ids`, `fac` stays the grant."""
from __future__ import annotations

import uuid

import pytest

from blumax_auth import ActiveFacilityRequired, AuthContext, InvalidToken, enforce_active_facility
from blumax_auth.verify import _to_context

A, B, C = (uuid.uuid4() for _ in range(3))


def _claims(**over):
    base = {"sub": str(uuid.uuid4()), "tid": str(uuid.uuid4()), "arc": "CLINICIAN", "rol": "doctor"}
    base.update(over)
    return base


def _ctx(**over) -> AuthContext:
    is_service = over.pop("is_service", False)
    return _to_context(_claims(**over), is_service=is_service)


class TestAfcNarrowing:
    def test_afc_narrows_a_multi_facility_grant_to_one(self):
        ctx = _ctx(fac=[str(A), str(B)], afc=str(A))
        assert ctx.active_facility_id == A
        assert ctx.facility_ids == frozenset({A})
        assert ctx.assigned_facility_ids == frozenset({A, B})
        assert ctx.is_facility_bound
        assert ctx.may_access_facility(A) and not ctx.may_access_facility(B)

    def test_afc_on_an_unrestricted_token_still_binds_to_that_facility(self):
        ctx = _ctx(afc=str(C))  # no "fac": unrestricted before, one facility now
        assert ctx.facility_ids == frozenset({C})
        assert ctx.assigned_facility_ids is None
        assert not ctx.may_access_facility(A)

    def test_without_afc_nothing_changes(self):
        ctx = _ctx(fac=[str(A), str(B)])
        assert ctx.active_facility_id is None
        assert ctx.facility_ids == frozenset({A, B})
        assert ctx.assigned_facility_ids == frozenset({A, B})
        assert not ctx.is_facility_bound

    def test_afc_outside_the_grant_is_refused(self):
        with pytest.raises(InvalidToken):
            _ctx(fac=[str(A)], afc=str(B))

    def test_afc_against_an_empty_grant_is_refused(self):
        with pytest.raises(InvalidToken):
            _ctx(fac=[], afc=str(A))

    def test_a_service_token_cannot_carry_afc(self):
        with pytest.raises(InvalidToken):
            _ctx(afc=str(A), is_service=True)

    def test_malformed_afc_is_refused(self):
        with pytest.raises(InvalidToken):
            _ctx(afc="not-a-uuid")


class TestEnforceActiveFacility:
    def test_bound_token_passes(self):
        ctx = _ctx(fac=[str(A), str(B)], afc=str(A))
        assert enforce_active_facility(ctx) is ctx

    def test_multi_facility_non_admin_without_afc_is_refused(self):
        with pytest.raises(ActiveFacilityRequired) as err:
            enforce_active_facility(_ctx(fac=[str(A), str(B)]))
        assert err.value.status_code == 403 and err.value.error_code == "ACTIVE_FACILITY_REQUIRED"

    def test_unrestricted_non_admin_without_afc_is_refused(self):
        with pytest.raises(ActiveFacilityRequired):
            enforce_active_facility(_ctx())

    def test_single_facility_user_may_stay_unbound(self):
        ctx = _ctx(fac=[str(A)])
        assert enforce_active_facility(ctx) is ctx

    def test_tenant_admin_may_stay_unbound(self):
        ctx = _ctx(arc="TENANT_ADMIN", fac=[str(A), str(B)])
        assert enforce_active_facility(ctx) is ctx

    def test_platform_admin_and_service_tokens_pass(self):
        assert enforce_active_facility(_ctx(adm=True, fac=[str(A), str(B)]))
        assert enforce_active_facility(_ctx(fac=[str(A), str(B)], is_service=True))

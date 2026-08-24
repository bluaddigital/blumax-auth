"""The verified identity a request carries."""
from __future__ import annotations

import uuid
from dataclasses import dataclass


@dataclass(frozen=True)
class AuthContext:
    """Everything a service knows about the caller, taken from signed claims.

    Frozen: this is the authorization decision for the request, and a handler
    that could mutate it could quietly widen its own scope.

    No permission list. Core signs the ROLE and its ARCHETYPE; each service
    maps archetype to its own permissions, because `opd.consult` and
    `ipd.admit` are domain vocabulary Core has no reason to know. See each
    service's own permission map.

    Map `archetype`, never `role`. Hospitals name their own roles — "Senior
    Registrar", "Duty MO" — and a service that has never heard of a name must
    not lock its holder out of a module the hospital pays for. `role` is for
    logs, audit records and anything a human reads.
    """

    user_id: uuid.UUID
    tenant_id: uuid.UUID | None
    tenant_slug: str | None
    role: str | None
    # TENANT_ADMIN | CLINICIAN | VIEWER. Defaults to the most restrictive when
    # a token predates the claim: an unknown caller should get less, not more.
    archetype: str
    # None means unrestricted (a platform admin, or a role with no facility
    # scoping). An empty set means scoped to no facilities at all. Opposite
    # meanings, so they must never share a representation — conflating them is
    # the bug this package exists partly to avoid repeating.
    facility_ids: frozenset[uuid.UUID] | None
    person_id: uuid.UUID | None
    provider_id: uuid.UUID | None
    is_platform_admin: bool
    jti: str | None

    def may_access_facility(self, facility_id: uuid.UUID) -> bool:
        """Whether this caller's scope covers a facility.

        Provided so services share one interpretation of the None/empty
        distinction rather than each re-deriving it. Nothing calls this yet —
        facility-level gating is a later decision — but the semantics belong
        with the claim, not scattered across whichever service enforces first.
        """
        if self.facility_ids is None:
            return True
        return facility_id in self.facility_ids

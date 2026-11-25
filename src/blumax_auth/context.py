"""The verified identity a request carries."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Actor:
    """The party acting FOR the token's subject (0.6.4, G8): RFC 8693's `act` claim on a delegated token minted by
    Core's POST /auth/token-exchange. `user_id` (sub) is then the human; the actor is the service account that called.
    For audit only -- the delegated token's permissions are already the human's INTERSECT the service's scopes."""

    #: act.sub -- the Core service account id.
    service_account_id: uuid.UUID
    #: act.svc -- the service account's name ("platform-labs-lab-order-consumer"); None if Core did not say.
    service_name: str | None = None


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
    # Core mints two token shapes off the same claim set: "access" for a
    # human session, "service" for a service-account (client-credentials)
    # caller acting on a tenant's behalf — e.g. pharmacy's cross-service
    # calls into IPD/OPD. Both verify identically otherwise (same iss/aud/
    # tid/rol/arc shape), so a route that has no reason to distinguish them
    # (most don't) needs no change. One that does — anything that should be
    # human-only — can check this flag; nothing else in this package does
    # today. Defaults True for any AuthContext built by hand (e.g. test
    # fixtures written before this field existed) rather than silently
    # becoming ambiguous.
    is_service: bool = False
    # The token's own "iat" (issue time), decoded from the JWT's NumericDate
    # (RFC 7519 §2 — whole seconds since the epoch, sub-second precision
    # truncated away) as an aware UTC datetime. None only for a token that
    # somehow carries no iat at all (never true for anything Core mints).
    # Exists so an opt-in caller (see session_revocation.py) can compare a
    # token's own age against a per-user revocation marker without a second
    # trip through the raw claims — mirrors blumax-backend's own
    # AccessTokenClaims.issued_at (app/core/security.py) exactly, so both
    # sides decode "iat" the identical way.
    issued_at: datetime | None = None
    # The ONE facility the session works in (the token's "afc"), or None for a token that names none (admin portal,
    # direct API use, service tokens). When set, `facility_ids` is narrowed to {active_facility_id}, so every guard
    # that already reads `facility_ids` / `may_access_facility` enforces the single facility with no per-route change.
    active_facility_id: uuid.UUID | None = None
    # The full grant the token carried in "fac" before it was narrowed (None = unrestricted). Only for code that must
    # know what the user MAY switch to; never use it to authorize data access.
    assigned_facility_ids: frozenset[uuid.UUID] | None = None
    # The v2 `sid` claim: the Core refresh-token family (login session) this token belongs to; SSO child sessions share
    # their source session's sid. None for v1 tokens, service tokens and a malformed claim. Used only by
    # session_revocation.py to honour Core's per-session marker (Phase 5b); never an authorization input.
    session_id: uuid.UUID | None = None
    # 0.6.4 (G8): who is acting for `user_id` when the token is a delegated one (Core token exchange, `act` claim); None
    # for a user's own token and for a service token. Record it in audit rows ("via service X on behalf of user Y").
    actor: Actor | None = None

    @property
    def is_delegated(self) -> bool:
        """True for a token a service obtained by exchanging a user's token (the `act` claim)."""
        return self.actor is not None

    @property
    def is_facility_bound(self) -> bool:
        """True when the token names the one facility the session works in."""
        return self.active_facility_id is not None

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

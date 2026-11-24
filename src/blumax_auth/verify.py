"""Token verification. RS256 only — this package can read tokens, never mint them."""
from __future__ import annotations

import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from jose import JWTError, jwt

from blumax_auth.context import AuthContext
from blumax_auth.errors import InvalidToken
from blumax_auth.jwks import JwksCache
from blumax_auth.metrics import service_audience_missing as _count_audience_missing

ALGORITHM = "RS256"

_log = logging.getLogger("blumax_auth.verify")

#: At most one `token_service_audience_missing` log line per verifier per this many seconds (the counter counts all).
AUDIENCE_LOG_INTERVAL_SECONDS = 60.0


class TokenVerifier:
    """Verifies Core-issued access tokens against the published JWKS.

    RS256 is the only accepted algorithm, listed explicitly. Reading `alg` from
    the token header and trusting it is the classic JWT confusion attack: an
    attacker sets alg to HS256 and signs with the public key, which the
    verifier then happily treats as a shared secret.
    """

    def __init__(
        self,
        jwks: JwksCache,
        *,
        issuer: str,
        audience: str,
        leeway_seconds: int = 30,
        service_audience: str | None = None,
    ) -> None:
        self._jwks = jwks
        self._issuer = issuer
        self._audience = audience
        # 0.6.0, OBSERVE ONLY: this service's own v2 audience (e.g. "blumax-opd"). A v2 token (`ver: 2`) whose aud list
        # lacks it is still accepted -- `audience` above stays the only audience that is enforced -- but is counted
        # (blumax_token_service_audience_missing_total) and logged (`token_service_audience_missing`, at most once a
        # minute). G6 turns this into a refusal. None (default) = no check at all, exactly as before. v1 tokens (a single
        # "blumax" aud) are never checked.
        self._service_audience = service_audience
        self._audience_logged_at = float("-inf")
        # Small clock-skew tolerance. Services and Core run on different hosts,
        # and a few seconds of drift should not 401 a clinician mid-round.
        self._leeway = leeway_seconds

    async def verify(self, token: str) -> AuthContext:
        try:
            header = jwt.get_unverified_header(token)
        except JWTError as exc:
            raise InvalidToken("Malformed token") from exc

        if header.get("alg") != ALGORITHM:
            raise InvalidToken(f"Unsupported signing algorithm: {header.get('alg')!r}")

        key = await self._jwks.get_key(header.get("kid"))

        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=[ALGORITHM],
                audience=self._audience,
                issuer=self._issuer,
                options={
                    "leeway": self._leeway,
                    # A token with no exp never expires; with no aud / iat it
                    # escapes the audience check and the session-revocation
                    # comparison. jose only validates these claims WHEN
                    # PRESENT unless told to require them. Core always mints
                    # all three (app/core/security.py).
                    "require_exp": True,
                    "require_aud": True,
                    "require_iat": True,
                },
            )
        except JWTError as exc:
            raise InvalidToken() from exc

        token_type = claims.get("type")
        if token_type not in ("access", "service"):
            raise InvalidToken("Token type must be 'access' or 'service'")

        if self._service_audience is not None and claims.get("ver") == 2:
            self._observe_service_audience(claims)

        return _to_context(claims, is_service=token_type == "service")

    def _observe_service_audience(self, claims: dict[str, Any]) -> None:
        aud = claims.get("aud")
        audiences = aud if isinstance(aud, list) else [aud]
        if self._service_audience in audiences:
            return
        _count_audience_missing()
        now = time.monotonic()
        if now - self._audience_logged_at >= AUDIENCE_LOG_INTERVAL_SECONDS:
            self._audience_logged_at = now
            _log.warning(
                "token_service_audience_missing",
                extra={
                    "service_audience": self._service_audience, "token_audiences": [str(a) for a in audiences],
                    "tenant_id": claims.get("tid"), "user_id": claims.get("sub"), "enforced": False,
                },
            )

    @property
    def issuer(self) -> str:
        """Read-only -- MultiIssuerTokenVerifier routes on this; nothing
        else in this package needs to see a single verifier's own issuer."""
        return self._issuer


class MultiIssuerTokenVerifier:
    """Accepts a token from any of several trusted issuers, each with its
    own JWKS/audience/leeway -- a real dual-issuer trust anchor, for a
    service mid-migration between two token issuers (e.g. Core and Blumax
    Auth) that must keep accepting BOTH during the transition window.

    Found needed 2026-10-25: a single TokenVerifier can only ever trust one
    issuer, so a consumer's naive "swap configure()'s issuer/jwks_url"
    migration approach is a hard cutover, not a staged rollout -- it
    silently rejects a still-valid token from whichever issuer isn't
    currently selected. This class is what a genuine dual-issuer window
    actually requires.

    Routing is by the token's own (unverified) `iss` claim -- reading it
    before verification is a ROUTING decision only, never a trust one: the
    chosen TokenVerifier still independently re-checks signature, issuer,
    audience and expiry against that specific issuer's own JWKS, exactly
    as if it had been the only verifier configured. A token claiming an
    issuer it cannot actually prove (wrong signature, or an issuer absent
    from `verifiers`) is refused the same as today, never silently routed
    to the wrong key set.
    """

    def __init__(self, verifiers: list[TokenVerifier]) -> None:
        if not verifiers:
            raise ValueError("MultiIssuerTokenVerifier needs at least one TokenVerifier")
        self._by_issuer = {v.issuer: v for v in verifiers}

    async def verify(self, token: str) -> AuthContext:
        try:
            unverified = jwt.get_unverified_claims(token)
        except JWTError as exc:
            raise InvalidToken("Malformed token") from exc

        issuer = unverified.get("iss")
        verifier = self._by_issuer.get(issuer)
        if verifier is None:
            raise InvalidToken(f"Untrusted issuer: {issuer!r}")
        return await verifier.verify(token)


def _issued_at(claims: dict[str, Any]) -> datetime | None:
    """The token's "iat" claim as an aware UTC datetime.

    jose decodes a NumericDate claim back to a plain int (seconds since the
    epoch), never a datetime — RFC 7519 §2, the same reason `exp` is an int
    on this claims dict too. None only if a token somehow carries no iat at
    all (never true for anything Core mints). Mirrors
    blumax-backend's app/core/security.py::_issued_at exactly, so both sides
    of a session-revocation comparison agree on what "iat" means.
    """
    raw = claims.get("iat")
    if raw is None:
        return None
    return datetime.fromtimestamp(raw, tz=UTC)


def _uuid(claims: dict[str, Any], name: str) -> uuid.UUID | None:
    raw = claims.get(name)
    if raw in (None, ""):
        return None
    try:
        return uuid.UUID(str(raw))
    except ValueError as exc:
        raise InvalidToken(f"Token claim {name!r} is not a valid UUID") from exc


def _optional_uuid(claims: dict[str, Any], name: str) -> uuid.UUID | None:
    """Like _uuid, but a malformed value reads as absent instead of failing verification (for informational claims
    whose absence must never change whether a token verifies)."""
    try:
        return _uuid(claims, name)
    except InvalidToken:
        return None


def _to_context(claims: dict[str, Any], *, is_service: bool) -> AuthContext:
    user_id = _uuid(claims, "sub")
    if user_id is None:
        raise InvalidToken("Token missing subject claim")

    raw_fac = claims.get("fac")
    facility_ids: frozenset[uuid.UUID] | None = None
    if raw_fac is not None:
        try:
            facility_ids = frozenset(uuid.UUID(str(f)) for f in raw_fac)
        except (TypeError, ValueError) as exc:
            raise InvalidToken("Token claim 'fac' is malformed") from exc

    # "afc": the active facility. It must be one the token's own grant covers (a signed token that contradicts itself
    # is refused), and it NARROWS `facility_ids` to that single facility. `fac` stays available as assigned_facility_ids.
    assigned_facility_ids = facility_ids
    active_facility_id = _uuid(claims, "afc")
    if active_facility_id is not None:
        if is_service:
            raise InvalidToken("A service token cannot carry an active facility")
        if facility_ids is not None and active_facility_id not in facility_ids:
            raise InvalidToken("Token claim 'afc' is outside the token's facility grant")
        facility_ids = frozenset({active_facility_id})

    return AuthContext(
        user_id=user_id,
        tenant_id=_uuid(claims, "tid"),
        tenant_slug=claims.get("tsl"),
        role=claims.get("rol"),
        archetype=claims.get("arc") or "VIEWER",
        facility_ids=facility_ids,
        person_id=_uuid(claims, "pid"),
        provider_id=_uuid(claims, "prv"),
        is_platform_admin=bool(claims.get("adm", False)),
        jti=claims.get("jti"),
        is_service=is_service,
        issued_at=_issued_at(claims),
        active_facility_id=active_facility_id,
        assigned_facility_ids=assigned_facility_ids,
        session_id=_optional_uuid(claims, "sid"),
    )

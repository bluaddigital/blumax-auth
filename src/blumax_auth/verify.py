"""Token verification. RS256 only — this package can read tokens, never mint them."""
from __future__ import annotations

import uuid
from typing import Any

from jose import JWTError, jwt

from blumax_auth.context import AuthContext
from blumax_auth.errors import InvalidToken
from blumax_auth.jwks import JwksCache

ALGORITHM = "RS256"

# Token types that can authenticate a request, mapped to the actor they name.
# `refresh` is deliberately absent: it exists to mint access tokens, and letting
# one authenticate a request would turn a long-lived credential into a
# short-lived one's equivalent.
#
# `service` was added when Core gained service accounts. It is verified exactly
# like an access token — same issuer, same audience, same signature, same
# tenant-bound `tid` — and differs only in what it records about the caller.
ACTOR_BY_TOKEN_TYPE: dict[str, str] = {
    "access": "user",
    "service": "service",
}


class TokenVerifier:
    """Verifies Core-issued access and service tokens against the published JWKS.

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
    ) -> None:
        self._jwks = jwks
        self._issuer = issuer
        self._audience = audience
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
                options={"leeway": self._leeway},
            )
        except JWTError as exc:
            raise InvalidToken() from exc

        token_type = claims.get("type")
        if token_type not in ACTOR_BY_TOKEN_TYPE:
            raise InvalidToken(f"Token type {token_type!r} cannot authenticate a request")

        return _to_context(claims, actor_type=ACTOR_BY_TOKEN_TYPE[token_type])


def _uuid(claims: dict[str, Any], name: str) -> uuid.UUID | None:
    raw = claims.get(name)
    if raw in (None, ""):
        return None
    try:
        return uuid.UUID(str(raw))
    except ValueError as exc:
        raise InvalidToken(f"Token claim {name!r} is not a valid UUID") from exc


def _to_context(claims: dict[str, Any], *, actor_type: str = "user") -> AuthContext:
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
        actor_type=actor_type,  # type: ignore[arg-type]
        # `snm` is the service account name. Absent on human tokens, and not
        # required on service tokens — audit falls back to the subject id.
        service_name=claims.get("snm") if actor_type == "service" else None,
    )

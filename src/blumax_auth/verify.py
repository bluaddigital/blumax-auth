"""Token verification. RS256 only — this package can read tokens, never mint them."""
from __future__ import annotations

import uuid
from typing import Any

from jose import JWTError, jwt

from blumax_auth.context import AuthContext
from blumax_auth.errors import InvalidToken
from blumax_auth.jwks import JwksCache

ALGORITHM = "RS256"


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
        if token_type not in ("access", "service"):
            raise InvalidToken("Token type must be 'access' or 'service'")

        return _to_context(claims, is_service=token_type == "service")


def _uuid(claims: dict[str, Any], name: str) -> uuid.UUID | None:
    raw = claims.get(name)
    if raw in (None, ""):
        return None
    try:
        return uuid.UUID(str(raw))
    except ValueError as exc:
        raise InvalidToken(f"Token claim {name!r} is not a valid UUID") from exc


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
    )

"""Password hashing and JWT issuance/verification.

Password scheme (bcrypt via passlib) deliberately matches Core's own
app/core/security.py so an existing bcrypt hash verifies unchanged if/when
user rows are migrated later (see MIGRATION.md's password-migration
section) -- this service does not invent a new hashing scheme.

JWT claim set is intentionally THIN for Phase 1 -- see app/core/config.py's
module docstring. `iss`/`aud`/`sub`/`type`/`jti`/`iat`/`exp` only, no
tenant/role/facility claims. Header carries `kid` (see app/core/keys.py).
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings
from app.core.keys import ALGORITHM, signing_keys

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# A real-shaped (but not-for-anyone's-account) bcrypt hash, used ONLY to
# give a nonexistent-identifier login the same bcrypt computation cost as
# a real one -- see verify_password_constant_time's own docstring. This is
# not a secret: it verifies against no real password.
_DUMMY_HASH = _pwd_context.hash("not-a-real-password-just-for-constant-time-padding")


def hash_password(raw: str) -> str:
    return _pwd_context.hash(raw)


def verify_password(raw: str, hashed: str) -> bool:
    return _pwd_context.verify(raw, hashed)


def verify_password_constant_time(raw: str, hashed: str | None) -> bool:
    """Always performs exactly one bcrypt verify, whether or not `hashed`
    is a real user's hash.

    The prior Core audit found a timing side-channel: Python's `or`
    short-circuit meant a nonexistent user's login request skipped the
    (deliberately slow) bcrypt call entirely, making "no such user" and
    "wrong password" distinguishable by response time even though the
    error message is identical. This function removes that gap at the
    call site -- always pay the bcrypt cost, dummy hash or real -- and
    never reports a match against the dummy hash as success.
    """
    is_real_user = hashed is not None
    result = _pwd_context.verify(raw, hashed if is_real_user else _DUMMY_HASH)
    return result if is_real_user else False


TokenType = Literal["access", "refresh", "service"]


class TokenClaims:
    """The human-identity claim set: iss/aud/sub/type/jti/iat/exp, nothing
    else -- unchanged since Phase 1. `sub` is always a human `users.id`."""

    def __init__(self, *, sub: str, token_type: Literal["access", "refresh"], jti: str,
                 iat: datetime, exp: datetime) -> None:
        self.sub = sub
        self.type = token_type
        self.jti = jti
        self.iat = iat
        self.exp = exp

    def to_dict(self) -> dict[str, Any]:
        return {
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
            "sub": self.sub,
            "type": self.type,
            "jti": self.jti,
            "iat": self.iat,
            "exp": self.exp,
        }


class ServiceTokenClaims:
    """The service-identity claim set -- deliberately almost identical in
    shape to TokenClaims (same verification path, same decode_token
    function, same signature/issuer/audience/expiry checks), with exactly
    two differences, each justified on its own:

    type="service" (never "access"/"refresh")
        The structural discriminator. Every caller that needs to require a
        human vs a service presents `expected_type` to decode_token, which
        hard-rejects a mismatch -- not an optional flag a route might
        forget to check, but a parameter every decode call site must
        supply. This is why a single literal is sufficient and a second,
        separate boolean would add nothing: decode_token's own type
        checking already makes "service-ness" unforgeable and
        unskippable.

    snm (service account name, e.g. "blumax-labs")
        Identifies WHICH application this token speaks for, for logging/
        audit purposes only -- a relying party must never treat `snm` as
        authorization (it is exactly as trustworthy as any other claim on
        a token the relying party didn't itself verify against a live
        database row, i.e. not at all beyond "Blumax Auth attests this
        service account requested it"). No destination_app, scope, or
        permission list is embedded here -- those were already checked,
        server-side, against the ServiceAccount's own DB row at the moment
        this service minted or exchanged an SSO code (see app/core/
        sso_code.py); embedding them in the token would let a relying
        party trust a claim about authorization instead of asking the
        party that actually owns that decision, which is the opposite of
        this platform's "identity vs local authorization" principle
        applied to a service rather than a human.

    `sub` for a service token is the ServiceAccount's own `id` -- a
    completely separate UUID space from human `users.id` (a different
    table, a different sequence of values), so a service sub can never
    collide with or be confused for a human one even before `type` is
    checked.
    """

    def __init__(self, *, sub: str, name: str, jti: str, iat: datetime, exp: datetime) -> None:
        self.sub = sub
        self.name = name
        self.jti = jti
        self.iat = iat
        self.exp = exp

    def to_dict(self) -> dict[str, Any]:
        return {
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
            "sub": self.sub,
            "type": "service",
            "snm": self.name,
            "jti": self.jti,
            "iat": self.iat,
            "exp": self.exp,
        }


def create_access_token(*, user_id: uuid.UUID) -> tuple[str, str]:
    """Returns (token, jti). Thin claims only -- see module docstring."""
    now = datetime.now(UTC)
    jti = str(uuid.uuid4())
    claims = TokenClaims(
        sub=str(user_id), token_type="access", jti=jti, iat=now,
        exp=now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    keys = signing_keys()
    token = jwt.encode(
        claims.to_dict(), keys.private_pem(), algorithm=ALGORITHM,
        headers={"kid": keys.kid},
    )
    return token, jti


def create_refresh_token(*, user_id: uuid.UUID, token_id: uuid.UUID) -> str:
    """jti = the DB RefreshToken row's own id (same pattern Core uses) --
    the row is the revocation/expiry index, the JWT carries no secret of
    its own beyond the signature."""
    now = datetime.now(UTC)
    claims = TokenClaims(
        sub=str(user_id), token_type="refresh", jti=str(token_id), iat=now,
        exp=now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    keys = signing_keys()
    return jwt.encode(
        claims.to_dict(), keys.private_pem(), algorithm=ALGORITHM,
        headers={"kid": keys.kid},
    )


def create_service_token(*, service_account_id: uuid.UUID, name: str) -> tuple[str, str]:
    """Returns (token, jti). No refresh token exists for a service identity
    -- a service simply requests a new one (POST /auth/service-token) when
    its short-lived token expires, rather than holding a second, longer-
    lived credential that would widen the blast radius of a leak."""
    now = datetime.now(UTC)
    jti = str(uuid.uuid4())
    claims = ServiceTokenClaims(
        sub=str(service_account_id), name=name, jti=jti, iat=now,
        exp=now + timedelta(minutes=settings.SERVICE_TOKEN_EXPIRE_MINUTES),
    )
    keys = signing_keys()
    token = jwt.encode(
        claims.to_dict(), keys.private_pem(), algorithm=ALGORITHM,
        headers={"kid": keys.kid},
    )
    return token, jti


class InvalidToken(Exception):
    pass


def decode_token(token: str, *, expected_type: TokenType) -> dict[str, Any]:
    try:
        header = jwt.get_unverified_header(token)
    except JWTError as exc:
        raise InvalidToken("malformed token") from exc

    if header.get("alg") != ALGORITHM:
        raise InvalidToken(f"unsupported algorithm: {header.get('alg')!r}")

    kid = header.get("kid")
    if not kid:
        raise InvalidToken("missing kid")

    keys = signing_keys()
    public_key = keys.key_for_kid(kid)
    if public_key is None:
        raise InvalidToken(f"unknown kid: {kid!r}")

    try:
        claims = jwt.decode(
            token, public_key, algorithms=[ALGORITHM],
            audience=settings.JWT_AUDIENCE, issuer=settings.JWT_ISSUER,
            options={"leeway": 30},
        )
    except JWTError as exc:
        raise InvalidToken(str(exc)) from exc

    if claims.get("type") != expected_type:
        raise InvalidToken(f"expected token type {expected_type!r}, got {claims.get('type')!r}")

    return claims

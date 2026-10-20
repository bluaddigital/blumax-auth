"""Patient-token verification — a separate path from staff tokens (F2.0).

Core issues patient tokens for the BluMax patient app with their own audience
(`blumax-patient`) and type (`patient`). They describe a patient ACCOUNT, never a
hospital user: no tenant, role, archetype, facility, provider or admin claim.

Kept entirely apart from TokenVerifier / require_auth on purpose:

  * the staff verifier still accepts only `access` and `service` tokens for the
    staff audience, so every existing route keeps rejecting patient tokens;
  * this verifier accepts only `patient` tokens for the patient audience and
    refuses any token that carries a staff claim, so a staff token can never be
    read as a patient one either;
  * a valid signature is not enough: require_patient also asks the service's
    session checker whether the session (`sid`) is still active, and FAILS
    CLOSED when that cannot be answered. There is no way to configure the
    patient path without a session checker. Core's sessions are authoritative:
    services other than Core use core_session_checker(), which forwards the
    patient's own bearer to Core's session endpoint for re-validation.

Typical setup in a patient-facing service:

    from blumax_auth import configure_patients

    configure_patients(
        jwks_url=settings.CORE_API_URL + PATIENT_JWKS_PATH,   # patient keys only
        issuer=settings.JWT_ISSUER,
        audience="blumax-patient",
        session_checker=core_session_checker(settings.CORE_API_URL),
    )

and on routes:

    async def my_records(ctx: PatientAuth) -> ...:
        ...ctx.account_id, ctx.global_person_id...
"""
from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any

import httpx
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from blumax_auth.errors import (
    InvalidToken,
    MissingCredentials,
    PatientSessionInactive,
    SessionCheckUnavailable,
)
from blumax_auth.jwks import JwksCache
from blumax_auth.verify import ALGORITHM, _issued_at, _uuid

PATIENT_TOKEN_TYPE = "patient"

# Claims that only a staff/service token carries. A patient token holding any of
# them is refused outright rather than having the claim ignored.
_STAFF_ONLY_CLAIMS = ("tid", "tsl", "rol", "arc", "fac", "pid", "prv", "adm", "snm")


@dataclass(frozen=True)
class PatientAuthContext:
    """A verified patient-app caller. Frozen, like AuthContext."""

    account_id: uuid.UUID          # sub — a patient account, never a users.id
    global_person_id: uuid.UUID    # gpid
    session_id: uuid.UUID          # sid — checked live on every request
    jti: str
    issued_at: datetime | None = None


class PatientTokenVerifier:
    """Verifies Core-issued patient tokens. RS256 only, as TokenVerifier."""

    def __init__(
        self,
        jwks: JwksCache,
        *,
        issuer: str,
        audience: str,
        leeway_seconds: int = 30,
    ) -> None:
        if not audience:
            raise ValueError("PatientTokenVerifier needs an explicit audience")
        self._jwks = jwks
        self._issuer = issuer
        self._audience = audience
        self._leeway = leeway_seconds

    async def verify(self, token: str) -> PatientAuthContext:
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

        if claims.get("type") != PATIENT_TOKEN_TYPE:
            raise InvalidToken("Token type must be 'patient'")
        return _to_patient_context(claims)


def _to_patient_context(claims: dict[str, Any]) -> PatientAuthContext:
    present = [c for c in _STAFF_ONLY_CLAIMS if claims.get(c) not in (None, "", False)]
    if present:
        raise InvalidToken(f"Patient token carries staff-only claims: {present}")

    account_id = _uuid(claims, "sub")
    global_person_id = _uuid(claims, "gpid")
    session_id = _uuid(claims, "sid")
    jti = claims.get("jti")
    if account_id is None or global_person_id is None or session_id is None or not jti:
        raise InvalidToken("Patient token missing a required claim (sub, gpid, sid, jti)")

    return PatientAuthContext(
        account_id=account_id,
        global_person_id=global_person_id,
        session_id=session_id,
        jti=str(jti),
        issued_at=_issued_at(claims),
    )


# ─── FastAPI wiring ───────────────────────────────────────────────────────────

# (verified context, the raw bearer it was verified from) -> is the session active?
SessionChecker = Callable[[PatientAuthContext, str], Awaitable[bool]]

CORE_SESSION_PATH = "/api/v1/patient-auth/session"


def core_session_checker(
    core_api_url: str,
    *,
    path: str = CORE_SESSION_PATH,
    timeout_seconds: float = 3.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> SessionChecker:
    """A session checker that asks Core, the authority on patient sessions.

    Forwards the patient's own bearer (never logged) to Core's session endpoint,
    which re-verifies the token and checks the session and account itself:
    200 -> active; 401/403 -> not active; anything else (5xx, timeout,
    connection error, unexpected status) raises, so require_patient answers 503
    -- fail closed. No caching: a revoked session stops working on the next
    request. `transport` is for tests only.
    """
    url = core_api_url.rstrip("/") + path

    async def check(ctx: PatientAuthContext, token: str) -> bool:  # noqa: ARG001
        async with httpx.AsyncClient(timeout=timeout_seconds, transport=transport) as client:
            response = await client.get(url, headers={"Authorization": f"Bearer {token}"})
        if response.status_code == 200:
            return True
        if response.status_code in (401, 403):
            return False
        raise RuntimeError(f"Core session check returned HTTP {response.status_code}")

    return check

_bearer = HTTPBearer(auto_error=False)
_patient_verifier: PatientTokenVerifier | None = None
_patient_jwks: JwksCache | None = None
_session_checker: SessionChecker | None = None

# Core publishes the patient signing key ONLY here (K1), never in the staff
# /.well-known/jwks.json -- so a patient token's signature cannot verify against
# staff keys, and a patient-shaped token signed with a staff key cannot verify
# here.
PATIENT_JWKS_PATH = "/.well-known/patient-jwks.json"
_STAFF_JWKS_PATH = "/.well-known/jwks.json"


def configure_patients(
    *,
    jwks_url: str,
    issuer: str,
    audience: str,
    session_checker: SessionChecker,
    ttl_seconds: float = 3600.0,
    leeway_seconds: int = 30,
) -> None:
    """Enable the patient path. Independent of configure(): a service may use
    either, both or neither. `session_checker` is mandatory — a patient request
    is never authorised on a signature alone."""
    global _patient_verifier, _patient_jwks, _session_checker
    if session_checker is None or not callable(session_checker):
        raise ValueError("configure_patients requires a session_checker")
    if jwks_url.split("?", 1)[0].rstrip("/").endswith(_STAFF_JWKS_PATH):
        # The staff key set would let the staff signing key vouch for patient
        # tokens -- exactly what Core's separate patient key prevents.
        raise ValueError(
            f"configure_patients needs Core's patient key set ({PATIENT_JWKS_PATH}), "
            "not the staff JWKS"
        )
    _patient_jwks = JwksCache(jwks_url, ttl_seconds=ttl_seconds)
    _patient_verifier = PatientTokenVerifier(
        _patient_jwks, issuer=issuer, audience=audience, leeway_seconds=leeway_seconds
    )
    _session_checker = session_checker


def patient_jwks_cache() -> JwksCache:
    """The live patient-path cache — tests seed it to avoid a real Core."""
    if _patient_jwks is None:
        raise RuntimeError("blumax_auth.configure_patients() has not been called")
    return _patient_jwks


def reset_patients() -> None:
    """Drop patient-path configuration. Tests only."""
    global _patient_verifier, _patient_jwks, _session_checker
    _patient_verifier = None
    _patient_jwks = None
    _session_checker = None


async def require_patient(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None,
) -> PatientAuthContext:
    """A verified patient whose session is still active — fail closed."""
    if _patient_verifier is None or _session_checker is None:
        raise RuntimeError("blumax_auth.configure_patients() has not been called")
    if credentials is None:
        raise MissingCredentials()

    ctx = await _patient_verifier.verify(credentials.credentials)
    try:
        active = await _session_checker(ctx, credentials.credentials)
    except Exception as exc:  # noqa: BLE001 — any failure to answer is a refusal
        raise SessionCheckUnavailable() from exc
    if active is not True:
        raise PatientSessionInactive()

    request.state.patient_auth = ctx
    return ctx


PatientAuth = Annotated[PatientAuthContext, Depends(require_patient)]

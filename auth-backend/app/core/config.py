"""Settings for the standalone Blumax Auth service.

Phase 1 (see MIGRATION.md): this service issues THIN identity tokens only
-- sub/iss/aud/iat/exp/jti/type, never tenant_id/roles/facility_id/etc.
Those business claims stay Core's (or, later, something Core builds on
top of a Blumax Auth token) -- see MIGRATION.md's own "token scope"
decision for why, and ARCHITECTURE.md for the full identity-vs-
authorization boundary this service must never cross.

Deliberately mirrors blumax-backend's app/core/config.py field names
(JWT_PRIVATE_KEY, JWT_DEV_KEY_PATH, JWT_PREVIOUS_PUBLIC_KEY, JWT_ISSUER,
JWT_AUDIENCE) so a later side-by-side diff during the real cutover is
trivial, and so the signing-key rotation mechanism (see app/core/keys.py)
is byte-for-byte the same shape Core already uses in production -- not
reinvented.
"""
from __future__ import annotations

import json

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_NAME: str = "blumax-auth-backend"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False

    # Phase 4I-1 (Superadmin frontend integration): this service's first
    # browser-direct consumer. Every prior consumer (Labs, Pharmacy) only
    # ever called /auth/* server-to-server from its own backend, which
    # needs no CORS at all -- a browser calling this service's /auth/login
    # directly, the way Superadmin's console now does, is new. Mirrors
    # blumax-backend's own ALLOWED_ORIGINS field name/shape exactly (same
    # JSON-array-or-comma-list env parsing below) so a deployment already
    # configuring Core's CORS knows this one works the same way. Empty by
    # default: an operator must opt a browser origin in explicitly.
    ALLOWED_ORIGINS: list[str] = []

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def _parse_origins(cls, v: object) -> object:
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("["):
                return json.loads(v)
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    DATABASE_URL: str
    REDIS_URL: str

    # --- JWT / signing keys -------------------------------------------------
    # Same env var names and same rotation shape as blumax-backend's
    # app/core/keys.py, deliberately -- see that module's own docstring for
    # the rotation sequence this mirrors.
    JWT_PRIVATE_KEY: str = ""
    JWT_DEV_KEY_PATH: str = ".dev-keys/auth-jwt-private.pem"
    JWT_PREVIOUS_PUBLIC_KEY: str = ""
    JWT_ISSUER: str = "https://auth.blumax.health"
    JWT_AUDIENCE: str = "blumax"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 14

    # --- Rate limiting (login) ----------------------------------------------
    LOGIN_RATE_LIMIT_MAX_ATTEMPTS: int = 10
    LOGIN_RATE_LIMIT_WINDOW_SECONDS: int = 60

    # --- Session revocation fail-mode ---------------------------------------
    # The prior Core audit found session-revocation checks silently fail
    # OPEN if Redis is unreachable (a logged-out user's still-unexpired
    # access token would be honoured again). This service makes the choice
    # explicit and observable instead -- see app/core/session_revocation.py.
    # "closed" = treat "can't reach Redis" as "treat session as revoked"
    # (safer default); "open" exists only for an operator who has decided
    # availability matters more for a given deployment, logged loudly either
    # way.
    SESSION_REVOCATION_FAIL_MODE: str = "closed"  # "closed" | "open"
    # How long a revocation marker itself persists. Must outlive the longest
    # access token that could have been issued before the marker was
    # written, or a token minted just before revocation could start
    # verifying again once the marker expires. 26h mirrors Core's own
    # SESSION_REVOCATION_TTL_SECONDS margin above its ~24h access-token
    # lifetime; this service's own access tokens are far shorter-lived
    # (ACCESS_TOKEN_EXPIRE_MINUTES above), so this is a deliberately generous
    # upper bound, not a tight fit.
    SESSION_REVOCATION_TTL_SECONDS: int = 26 * 60 * 60

    # --- Service-to-service authentication (Phase 5) ------------------------
    # A service token is a DISTINCT claim type (type="service", never
    # "access"/"refresh") identifying an application, not a human -- see
    # app/core/security.py's ServiceTokenClaims and app/models/
    # service_account.py. Deliberately short-lived: a service re-requests one
    # whenever it needs it rather than holding a long-lived credential in
    # memory, bounding the blast radius of a leaked token. Matches Core's own
    # service-token TTL (10 minutes) -- not reinvented, just the one Core
    # parameter worth keeping as-is since nothing about Blumax Auth's design
    # argues for a different value.
    SERVICE_TOKEN_EXPIRE_MINUTES: int = 10

    # --- SSO code exchange (Phase 5) -----------------------------------------
    # Short-lived, single-use, Redis-backed authorization code -- see
    # app/core/sso_code.py. 60s mirrors Core's own SSO_CODE_TTL_SECONDS: long
    # enough for a browser redirect round-trip, short enough to bound replay
    # exposure if a code leaks (e.g. via a referrer header or browser
    # history) before it's consumed.
    SSO_CODE_TTL_SECONDS: int = 60
    # Destination apps a code may target via the PUBLIC, unauthenticated
    # consume endpoint (POST /auth/sso/code/consume) -- mirrors Core's
    # PUBLIC_CONSUME_DESTINATION_APPS. Every other destination may only be
    # redeemed by an authenticated service account via POST /auth/sso/
    # exchange. Empty by default: an operator must opt a destination into
    # the public, no-service-account path explicitly.
    SSO_PUBLIC_CONSUME_DESTINATION_APPS: list[str] = []

    # --- Password reset (Phase 5) --------------------------------------------
    # Same Redis-backed, single-use, GETDEL-consumed primitive as an SSO
    # code (see app/core/password_reset.py) -- reusing the mechanism rather
    # than inventing a second one. 15 minutes is long enough for someone to
    # receive and act on a reset link/code, short enough to bound exposure
    # if it leaks before use.
    PASSWORD_RESET_TTL_SECONDS: int = 15 * 60
    PASSWORD_MIN_LENGTH: int = 8

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"


settings = Settings()  # type: ignore[call-arg]

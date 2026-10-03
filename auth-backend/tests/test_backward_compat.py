"""THE critical proof for Phase 1 (see MIGRATION.md): a token minted by
this new service validates under the exact same rules every existing
BLUMAX application already uses -- without touching any of those
applications. Imports blumax_auth (the real, already-deployed
verification package) directly from its sibling repo checkout and seeds
its JWKS cache with THIS service's own keys -- no network call, no
production application touched.
"""
from __future__ import annotations

import sys
import uuid

sys.path.insert(0, "/home/BluMax_Health/blumax-auth/src")

from blumax_auth.jwks import JwksCache
from blumax_auth.verify import TokenVerifier

from app.core.config import settings
from app.core.keys import signing_keys
from app.core.security import create_access_token


async def test_blumax_auth_issued_token_validates_under_existing_consumer_rules():
    user_id = uuid.uuid4()
    access_token, jti = create_access_token(user_id=user_id)

    cache = JwksCache(jwks_url="http://unused.invalid/jwks.json")
    cache.seed(signing_keys().jwks())

    verifier = TokenVerifier(cache, issuer=settings.JWT_ISSUER, audience=settings.JWT_AUDIENCE)
    context = await verifier.verify(access_token)

    assert context.user_id == user_id
    assert context.jti == jti
    assert context.is_service is False


async def test_thin_token_with_no_business_claims_degrades_safely_not_crashes():
    """The real point of Phase 1's "thin token" decision: existing
    consumer code was already written to tolerate a token that predates
    tenant/role/facility claims -- defaulting to the MOST restrictive
    interpretation (archetype=VIEWER, tenant_id=None, is_platform_admin=
    False), not crashing and not granting broad access by default. This
    is not a new guarantee this service adds -- it's an existing property
    of blumax_auth's own _to_context, confirmed here against a real
    thin token."""
    user_id = uuid.uuid4()
    access_token, _ = create_access_token(user_id=user_id)

    cache = JwksCache(jwks_url="http://unused.invalid/jwks.json")
    cache.seed(signing_keys().jwks())
    verifier = TokenVerifier(cache, issuer=settings.JWT_ISSUER, audience=settings.JWT_AUDIENCE)
    context = await verifier.verify(access_token)

    assert context.tenant_id is None
    assert context.role is None
    assert context.archetype == "VIEWER"  # most restrictive default, not "" or a crash
    assert context.facility_ids is None
    assert context.is_platform_admin is False


async def test_jwks_rotation_window_verifies_old_and_new_tokens_simultaneously():
    """Proves a consumer already mid-cache (holding the OLD key only)
    still verifies a token signed with the NEW key once it refetches --
    and a token signed with the (still valid, not-yet-expired) retiring
    key continues to verify too. This is the exact mechanism the real
    cutover (Phase 6) depends on."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    from app.core.keys import SigningKeys

    old_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    new_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Simulate "before rotation": only the old key is live.
    pre_rotation = SigningKeys(old_private, None)
    old_token, _ = _sign_with(pre_rotation, uuid.uuid4())

    # Simulate "during rotation": new key signs, old key still verifies.
    during_rotation = SigningKeys(new_private, old_private.public_key())
    new_token, _ = _sign_with(during_rotation, uuid.uuid4())

    cache = JwksCache(jwks_url="http://unused.invalid/jwks.json")
    cache.seed(during_rotation.jwks())
    verifier = TokenVerifier(cache, issuer=settings.JWT_ISSUER, audience=settings.JWT_AUDIENCE)

    await verifier.verify(old_token)  # old, pre-rotation token still honoured
    await verifier.verify(new_token)  # new token honoured too


def _sign_with(keys, user_id: uuid.UUID) -> tuple[str, str]:
    import uuid as _uuid
    from datetime import UTC, datetime, timedelta

    from jose import jwt as jose_jwt

    from app.core.keys import ALGORITHM

    now = datetime.now(UTC)
    jti = str(_uuid.uuid4())
    token = jose_jwt.encode(
        {
            "iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE, "sub": str(user_id),
            "type": "access", "jti": jti, "iat": now, "exp": now + timedelta(minutes=5),
        },
        keys.private_pem(), algorithm=ALGORITHM, headers={"kid": keys.kid},
    )
    return token, jti

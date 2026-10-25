"""blumax_auth.verifier() -- exposes the live, fully-configured verifier
(single- or multi-issuer) for a service's own code that re-verifies a
token outside this package's require_auth/TenantAuth dependencies. See
its own docstring in blumax_auth/fastapi.py for why this exists: a
service calling configure(also_trust=[...]) but then hand-building its
own single-issuer TokenVerifier elsewhere silently loses the dual-trust
window.
"""
from __future__ import annotations

import pytest

import blumax_auth
from blumax_auth import JwksCache, MultiIssuerTokenVerifier, TokenVerifier, TrustAnchor

ISSUER = "https://core.blumax.test"
AUDIENCE = "blumax"


def test_raises_before_configure():
    blumax_auth.reset()
    with pytest.raises(RuntimeError):
        blumax_auth.verifier()


def test_returns_the_single_issuer_verifier_by_default():
    blumax_auth.reset()
    blumax_auth.configure(jwks_url="http://unused.invalid/jwks.json", issuer=ISSUER, audience=AUDIENCE)
    v = blumax_auth.verifier()
    assert isinstance(v, TokenVerifier)
    blumax_auth.reset()


def test_returns_the_multi_issuer_verifier_when_also_trust_is_set():
    blumax_auth.reset()
    blumax_auth.configure(
        jwks_url="http://unused.invalid/core/jwks.json", issuer=ISSUER, audience=AUDIENCE,
        also_trust=[TrustAnchor(
            jwks_url="http://unused.invalid/auth/jwks.json",
            issuer="https://auth.blumax.test", audience=AUDIENCE,
        )],
    )
    v = blumax_auth.verifier()
    assert isinstance(v, MultiIssuerTokenVerifier)
    blumax_auth.reset()

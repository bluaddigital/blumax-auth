"""RS256 signing-key management -- the same shape as blumax-backend's
app/core/keys.py (not reinvented), so the eventual real cutover (Phase 6:
transplant Core's actual production private key into this service, same
`kid`, zero consumer-visible change) is a key-material swap, not a code
rewrite.

Rotation sequence (same as Core's own):
  1. Generate a new private key.
  2. Move the old public key into JWT_PREVIOUS_PUBLIC_KEY.
  3. Deploy.
  4. Wait one access-token lifetime + margin.
  5. Drop JWT_PREVIOUS_PUBLIC_KEY.

`kid` is never configured -- it is the first 16 hex characters of the
SHA-256 hash of the public key's DER-encoded SubjectPublicKeyInfo, so the
same key material always yields the same kid deterministically, and two
different services loaded with the same key (e.g. during the real
cutover) publish the same kid without coordination.
"""
from __future__ import annotations

import base64
import hashlib
import os
from functools import lru_cache

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from app.core.config import settings

ALGORITHM = "RS256"


def _thumbprint(public_key: RSAPublicKey) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()[:16]


def _b64url_uint(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode("ascii")


def _load_or_create_dev_key() -> RSAPrivateKey:
    path = settings.JWT_DEV_KEY_PATH
    if os.path.isfile(path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)  # type: ignore[return-value]
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    return key


class SigningKeys:
    def __init__(self, private_key: RSAPrivateKey, previous_public_key: RSAPublicKey | None) -> None:
        self.private_key = private_key
        self.public_key: RSAPublicKey = private_key.public_key()
        self.kid = _thumbprint(self.public_key)
        self.previous_public_key = previous_public_key
        self._previous_kid = _thumbprint(previous_public_key) if previous_public_key else None

    def private_pem(self) -> str:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")

    def _jwk(self, key_id: str, public_key: RSAPublicKey) -> dict:
        numbers = public_key.public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": ALGORITHM,
            "kid": key_id,
            "n": _b64url_uint(numbers.n),
            "e": _b64url_uint(numbers.e),
        }

    def jwks(self) -> dict:
        keys = [self._jwk(self.kid, self.public_key)]
        if self.previous_public_key is not None and self._previous_kid is not None:
            keys.append(self._jwk(self._previous_kid, self.previous_public_key))
        return {"keys": keys}

    def key_for_kid(self, kid: str) -> RSAPublicKey | None:
        if kid == self.kid:
            return self.public_key
        if kid == self._previous_kid:
            return self.previous_public_key
        return None


def _build() -> SigningKeys:
    if settings.JWT_PRIVATE_KEY:
        private_key = serialization.load_pem_private_key(
            settings.JWT_PRIVATE_KEY.encode(), password=None
        )
    elif settings.is_production:
        raise RuntimeError(
            "REFUSED: JWT_PRIVATE_KEY must be set in production -- "
            "refusing to sign tokens with a generated/throwaway key."
        )
    else:
        private_key = _load_or_create_dev_key()

    previous_public_key = None
    if settings.JWT_PREVIOUS_PUBLIC_KEY:
        previous_public_key = serialization.load_pem_public_key(
            settings.JWT_PREVIOUS_PUBLIC_KEY.encode()
        )

    return SigningKeys(private_key, previous_public_key)  # type: ignore[arg-type]


@lru_cache(maxsize=1)
def signing_keys() -> SigningKeys:
    return _build()

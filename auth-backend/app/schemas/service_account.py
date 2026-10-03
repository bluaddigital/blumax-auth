from __future__ import annotations

from pydantic import BaseModel


class ServiceTokenRequest(BaseModel):
    client_id: str
    client_secret: str


class ServiceTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

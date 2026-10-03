from __future__ import annotations

from pydantic import BaseModel


class LoginRequest(BaseModel):
    identifier: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str
    all_devices: bool = False


class MeResponse(BaseModel):
    sub: str
    iss: str
    aud: str
    type: str

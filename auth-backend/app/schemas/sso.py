from __future__ import annotations

from pydantic import BaseModel


class SsoCodeRequest(BaseModel):
    destination_app: str


class SsoCodeResponse(BaseModel):
    code: str
    expires_in: int


class SsoMintOnBehalfRequest(BaseModel):
    user_id: str
    destination_app: str


class SsoExchangeRequest(BaseModel):
    code: str


class SsoExchangeResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class SsoConsumeRequest(BaseModel):
    code: str


class SsoConsumeResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

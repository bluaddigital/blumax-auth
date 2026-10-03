from __future__ import annotations
from datetime import datetime

from pydantic import BaseModel


class CreateIdentityRequest(BaseModel):
    identifier: str
    password: str | None = None  # omitted -> a random temp password is generated and returned once


class CreateIdentityResponse(BaseModel):
    id: str
    identifier: str
    is_active: bool
    temporary_password: str | None = None  # only present when `password` was omitted


class IdentityResponse(BaseModel):
    id: str
    identifier: str
    is_active: bool
    created_at: datetime


class SetPasswordRequest(BaseModel):
    new_password: str

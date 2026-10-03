from __future__ import annotations

from pydantic import BaseModel


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class PasswordResetRequest(BaseModel):
    identifier: str


class PasswordResetConfirmRequest(BaseModel):
    reset_code: str
    new_password: str

from __future__ import annotations

from pydantic import BaseModel


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class PasswordResetRequest(BaseModel):
    identifier: str
    # Same meaning as LoginRequest.tenant (honoured only with
    # TENANT_SCOPED_IDENTITY_MODE=on): resolves the account inside that
    # tenant only.
    tenant: str | None = None


class PasswordResetConfirmRequest(BaseModel):
    reset_code: str
    new_password: str

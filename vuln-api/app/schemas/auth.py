# app/schemas/auth.py
from pydantic import BaseModel


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str
    confirm_password: str

# app/schemas/users.py
from pydantic import BaseModel


class NewUserRequest(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str


class CurrentUserResponse(BaseModel):
    id: int
    username: str
    is_active: bool
    is_default_password: bool

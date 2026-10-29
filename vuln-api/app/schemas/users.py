# app/schemas/users.py
from typing import Optional
from pydantic import BaseModel


class NewUserRequest(BaseModel):
    username: str
    password: str
    role: str = "group_reader" # Por defecto entra como lector
    group_id: Optional[int] = None # El grupo al que pertenece


class UserResponse(BaseModel):
    id: int
    username: str


class CurrentUserResponse(BaseModel):
    id: int
    username: str
    is_active: bool
    is_default_password: bool

# app/routers/users.py
from typing import List, Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import User
from app.auth import get_current_system_admin, get_current_user
from app.schemas.users import NewUserRequest, CurrentUserResponse, UserResponse
from app.services.user_service import (
    create_user as create_user_service,
    list_users as list_users_service,
    delete_user as delete_user_service,
)

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=CurrentUserResponse)
def get_user_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "is_active": current_user.is_active,
        "is_default_password": current_user.is_default_password,
    }


@router.post("")
def create_user(
    request: NewUserRequest,
    current_user: User = Depends(get_current_system_admin),
    db: Session = Depends(get_db),
):
    return create_user_service(db, request)


@router.get("", response_model=List[UserResponse])
def list_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return list_users_service(db)


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_system_admin),
    db: Session = Depends(get_db),
):
    return delete_user_service(db, current_user, user_id)

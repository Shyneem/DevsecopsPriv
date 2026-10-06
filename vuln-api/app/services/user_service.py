# app/services/user_service.py
import re
from typing import List, Dict, Any
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app.models import User
from app.db import SessionLocal
from app.auth import hash_password, verify_password
from app.schemas.auth import ChangePasswordRequest
from app.schemas.users import NewUserRequest


def validate_strong_password(password: str) -> None:
    """Valida que la contraseña sea robusta. Lanza HTTPException si no cumple."""
    errors = []
    if len(password) < 8:
        errors.append("mínimo 8 caracteres")
    if not re.search(r"[A-Z]", password):
        errors.append("al menos una letra mayúscula")
    if not re.search(r"[a-z]", password):
        errors.append("al menos una letra minúscula")
    if not re.search(r"\d", password):
        errors.append("al menos un número")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-]", password):
        errors.append("al menos un carácter especial (!@#$%^&*...)")
    if errors:
        raise HTTPException(
            status_code=400,
            detail=f"La contraseña no es suficientemente robusta: {', '.join(errors)}",
        )


def create_default_admin(session_factory=SessionLocal) -> None:
    """Inicializa el usuario administrador por defecto si no existe."""
    db = session_factory()
    try:
        admin_exists = db.query(User).filter(User.username == "admin").first()
        if not admin_exists:
            print("Creando usuario admin default...")
            default_admin = User(
                username="admin",
                password_hash=hash_password("admin"),
                is_active=True,
                is_default_password=True,
            )
            db.add(default_admin)
            db.commit()
    finally:
        db.close()


def change_user_password(db: Session, current_user: User, request: ChangePasswordRequest) -> Dict[str, str]:
    if not verify_password(request.old_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="La contraseña antigua es incorrecta")

    if request.old_password == request.new_password:
        raise HTTPException(
            status_code=400,
            detail="La nueva contraseña debe ser diferente a la anterior",
        )

    if request.new_password != request.confirm_password:
        raise HTTPException(
            status_code=400,
            detail="Las contraseñas nuevas no coinciden",
        )

    validate_strong_password(request.new_password)

    current_user.password_hash = hash_password(request.new_password)
    current_user.is_active = True
    current_user.is_default_password = False

    db.add(current_user)
    db.commit()

    return {"message": "Contraseña actualizada exitosamente"}


def create_user(db: Session, request: NewUserRequest) -> Dict[str, str]:
    existing = db.query(User).filter(User.username == request.username).first()
    if existing:
        raise HTTPException(
            status_code=400,
            detail="El nombre de usuario ya esta ocupado. Elige otro.",
        )

    new_user = User(
        username=request.username,
        password_hash=hash_password(request.password),
        is_default_password=True,
    )
    db.add(new_user)
    db.commit()
    return {"message": "Usuario creado"}


def list_users(db: Session) -> List[Dict[str, Any]]:
    users = db.query(User).all()
    return [{"id": u.id, "username": u.username} for u in users]


def delete_user(db: Session, current_user: User, user_id: int) -> Dict[str, str]:
    if current_user.id == user_id:
        raise HTTPException(status_code=400, detail="No puedes eliminarte a ti mismo")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    db.delete(user)
    db.commit()
    return {"message": "Usuario eliminado"}

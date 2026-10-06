# app/services/connection_service.py
import sys
import os
from typing import List, Dict, Any
from urllib.parse import urlparse
from fastapi import HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from app.models import WazuhConnection
from app.crypto import encrypt, decrypt
from app.wazuh_client import test_connection as default_test_connection
from app.schemas.connections import WazuhConnectionRequest
from typing import cast

CONNECTION_NOT_FOUND = "Conexión no encontrada"


def get_domains_allowlist() -> List[str]:
    """Obtiene la lista de dominios permitidos, priorizando app.main si fue modificado en tests."""
    main_mod = sys.modules.get("app.main")
    if main_mod and hasattr(main_mod, "DOMAINS_ALLOWLIST"):
        return getattr(main_mod, "DOMAINS_ALLOWLIST")
    return os.getenv("DOMAINS_ALLOWLIST", "localhost").split(",")


def get_test_connection_fn():
    """Obtiene la función test_connection, priorizando app.main si fue parcheada con @patch."""
    main_mod = sys.modules.get("app.main")
    if main_mod and hasattr(main_mod, "test_connection"):
        return getattr(main_mod, "test_connection")
    return default_test_connection


def list_connections(db: Session) -> List[Dict[str, Any]]:
    conns = db.query(WazuhConnection).all()
    return [
        {
            "id": c.id,
            "name": c.name,
            "indexer_url": c.indexer_url,
            "wazuh_user": c.wazuh_user,
            "is_active": c.is_active,
            "tested": c.tested,
            "last_tested_at": c.last_tested_at,
            "last_test_ok": c.last_test_ok,
        }
        for c in conns
    ]


def create_connection(db: Session, request: WazuhConnectionRequest) -> Dict[str, Any]:
    # Verificar nombre único
    if db.query(WazuhConnection).filter(WazuhConnection.name == request.name).first():
        raise HTTPException(
            status_code=400, detail="Ya existe una conexión con ese nombre"
        )

    # Verificar SSRF
    hostname = urlparse(request.indexer_url).hostname
    if hostname not in get_domains_allowlist():
        raise HTTPException(
            status_code=400,
            detail="El dominio del indexador no está en la lista de permitidos",
        )

    # Intentar conexión antes de persistir
    test_conn_fn = get_test_connection_fn()
    ok = test_conn_fn(request.indexer_url, request.wazuh_user, request.wazuh_password)
    if not ok:
        raise HTTPException(
            status_code=400,
            detail="No se pudo establecer conexión con el indexador Wazuh",
        )

    conn = WazuhConnection(
        name=request.name,
        indexer_url=request.indexer_url,
        wazuh_user=request.wazuh_user,
        wazuh_password=encrypt(request.wazuh_password),
        tested=True,
        last_tested_at=func.now(),
        last_test_ok=True,
    )
    db.add(conn)
    db.commit()
    db.refresh(conn)
    return {"message": "Conexión creada", "id": conn.id}


def update_connection(db: Session, conn_id: int, request: WazuhConnectionRequest) -> Dict[str, str]:
    conn = db.query(WazuhConnection).filter(WazuhConnection.id == conn_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail=CONNECTION_NOT_FOUND)

    hostname = urlparse(request.indexer_url).hostname
    if hostname not in get_domains_allowlist():
        raise HTTPException(
            status_code=400,
            detail="El dominio del indexador no está en la lista de permitidos",
        )

    conn.name = request.name
    conn.indexer_url = request.indexer_url
    conn.wazuh_user = request.wazuh_user
    if request.wazuh_password:
        conn.wazuh_password = encrypt(request.wazuh_password)
    db.commit()
    return {"message": "Conexión actualizada"}


def delete_connection(db: Session, conn_id: int) -> Dict[str, str]:
    conn = db.query(WazuhConnection).filter(WazuhConnection.id == conn_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail=CONNECTION_NOT_FOUND)
    db.delete(conn)
    db.commit()
    return {"message": "Conexión eliminada"}


def test_wazuh_connection_by_id(db: Session, conn_id: int) -> Dict[str, Any]:
    conn=( db.query(WazuhConnection).filter(WazuhConnection.id == conn_id).first())

    if not conn:
        raise HTTPException(status_code=404, detail=CONNECTION_NOT_FOUND)

    test_conn_fn = get_test_connection_fn()
    ok = test_conn_fn(
        cast(str, conn.indexer_url), cast(str, conn.wazuh_user), decrypt(cast(str,conn.wazuh_password))
    )

    conn.tested = True
    conn.last_tested_at = func.now()
    conn.last_test_ok = ok
    db.commit()

    return {"ok": ok, "message": "Conexión exitosa" if ok else "No se pudo conectar"}

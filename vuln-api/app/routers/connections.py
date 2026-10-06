# app/routers/connections.py
from typing import List, Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import User
from app.auth import get_current_user
from app.schemas.connections import WazuhConnectionRequest, WazuhConnectionResponse
from app.services.connection_service import (
    list_connections as list_connections_service,
    create_connection as create_connection_service,
    update_connection as update_connection_service,
    delete_connection as delete_connection_service,
    test_wazuh_connection_by_id,
)
from app.services.vuln_service import sync_connection as sync_connection_service

router = APIRouter(prefix="/wazuh-connections", tags=["wazuh-connections"])


@router.get("", response_model=List[WazuhConnectionResponse])
def list_connections(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return list_connections_service(db)


@router.post("", status_code=201)
def create_connection(
    request: WazuhConnectionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return create_connection_service(db, request)


@router.put("/{conn_id}")
def update_connection(
    conn_id: int,
    request: WazuhConnectionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return update_connection_service(db, conn_id, request)


@router.delete("/{conn_id}")
def delete_connection(
    conn_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return delete_connection_service(db, conn_id)


@router.post("/{conn_id}/test")
def test_wazuh_connection(
    conn_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return test_wazuh_connection_by_id(db, conn_id)


@router.post("/{conn_id}/sync")
def sync_connection(
    conn_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return sync_connection_service(db, conn_id)

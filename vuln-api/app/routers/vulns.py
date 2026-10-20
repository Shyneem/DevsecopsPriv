# app/routers/vulns.py
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import User
from app.auth import get_current_user
from app.schemas.vulns import VulnerabilityResponse
from app.services.vuln_service import (
    sync_all_connections as sync_all_connections_service,
    list_vulns as list_vulns_service,
)

router = APIRouter(prefix="/vulns", tags=["vulnerabilities"])


@router.post("/sync-all")
def sync_all_connections(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return sync_all_connections_service(db)


@router.get("", response_model=List[VulnerabilityResponse])
def list_vulns(
    limit: Optional[int] = None,
    connection_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return list_vulns_service(db, connection_id=connection_id, limit=limit)

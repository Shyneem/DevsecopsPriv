# app/routers/vulns.py
from typing import List, Optional, Union
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import User
from app.auth import get_current_user
from app.schemas.vulns import VulnerabilityResponse, PaginatedVulnerabilitiesResponse
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


@router.get("", response_model=Union[PaginatedVulnerabilitiesResponse, List[VulnerabilityResponse]])
def list_vulns(
    page: Optional[int] = Query(default=None, ge=1, description="Número de página (1-indexado). Si no se pasa, retorna lista sin paginar."),
    page_size: int = Query(default=25, ge=1, le=500, description="Cantidad de elementos por página"),
    connection_id: Optional[int] = Query(default=None, description="Filtrar por ID de conexión Wazuh"),
    severity: Optional[str] = Query(default=None, description="Filtrar por severidad (CRITICAL, HIGH, MEDIUM, LOW)"),
    status: Optional[str] = Query(default=None, description="Filtrar por estado (ACTIVE, RESOLVED)"),
    agent_id: Optional[str] = Query(default=None, description="Filtrar por ID de agente"),
    agent_name: Optional[str] = Query(default=None, description="Filtrar por nombre de agente"),
    cve_id: Optional[str] = Query(default=None, description="Filtrar por CVE ID"),
    package_name: Optional[str] = Query(default=None, description="Filtrar por paquete afectado"),
    search: Optional[str] = Query(default=None, description="Búsqueda de texto libre en CVE, paquete, agente o descripción"),
    sort_by: Optional[str] = Query(default="detected_at", description="Campo por el cual ordenar"),
    sort_order: Optional[str] = Query(default="desc", pattern="^(asc|desc)$", description="Dirección de ordenamiento (asc o desc)"),
    limit: Optional[int] = Query(default=None, description="Límite máximo de resultados (usado para compatibilidad hacia atrás)"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return list_vulns_service(
        db,
        connection_id=connection_id,
        limit=limit,
        page=page,
        page_size=page_size,
        severity=severity,
        status=status,
        agent_id=agent_id,
        agent_name=agent_name,
        cve_id=cve_id,
        package_name=package_name,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,
    )

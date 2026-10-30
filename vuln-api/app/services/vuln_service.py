# app/services/vuln_service.py
import sys
import math
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set, Tuple, Union, cast
from fastapi import HTTPException
from sqlalchemy import or_, desc, asc, case
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from app.models import WazuhVulnerability, WazuhConnection, VulnerabilityHistory
from app.crypto import decrypt
from app.wazuh_client import fetch_all_vulns as default_fetch_all_vulns
from app.services.connection_service import CONNECTION_NOT_FOUND


def get_fetch_all_vulns_fn():
    """Obtiene la función fetch_all_vulns, priorizando app.main si fue parcheada con @patch."""
    main_mod = sys.modules.get("app.main")
    if main_mod and hasattr(main_mod, "fetch_all_vulns"):
        return getattr(main_mod, "fetch_all_vulns")
    return default_fetch_all_vulns


def _handle_existing_vuln(
    db: Session,
    existing: WazuhVulnerability,
    vuln: dict,
    now: Optional[datetime] = None,
) -> None:
    current_time = now or datetime.now(timezone.utc)
    if existing.status == "RESOLVED":
        existing.status = cast(Any, "ACTIVE")
        db.add(
            VulnerabilityHistory(
                vulnerability_id=existing.id,
                action="REOPENED",
                details="La vulnerabilidad fue detectada nuevamente por Wazuh",
            )
        )
    new_severity: str | None = vuln.get("severity")

    if existing.severity != new_severity:
        db.add(
            VulnerabilityHistory(
                vulnerability_id=existing.id,
                action="SEVERITY_CHANGED",
                details=f"Severidad cambió de {existing.severity} a {vuln.get('severity')}",
            )
        )
        existing.severity = vuln.get("severity")

    existing.score_base = (vuln.get("score") or {}).get("base")
    existing.last_seen = current_time


def _resolve_missing_vulns(
    db: Session,
    active_vuln_dict: Dict[int, WazuhVulnerability],
    seen_vuln_ids: Set[int],
) -> None:
    history_records = []
    for vuln_id, db_vuln in active_vuln_dict.items():
        if vuln_id not in seen_vuln_ids:
            db_vuln.status = "RESOLVED"
            history_records.append(
                VulnerabilityHistory(
                    vulnerability_id=vuln_id,
                    action="RESOLVED",
                    details="Ya no es reportada por el agente (Probablemente parcheada)",
                )
            )
    if history_records:
        db.add_all(history_records)


def process_wazuh_vulnerabilities(db: Session, conn_id: int, raw_vulns: list) -> int:
    """Procesa e inserta/actualiza masivamente las vulnerabilidades de Wazuh, eliminando el problema N+1.
    
    1. Precarga en memoria todas las vulnerabilidades de la conexión en una sola consulta SQL.
    2. Realiza comparaciones O(1) usando diccionarios indexados por clave compuesta.
    3. Inserta y genera historial en lotes para minimizar viajes de ida y vuelta a la BD.
    """
    now = datetime.now(timezone.utc)
    seen_vuln_ids: Set[int] = set()

    # 1. Precarga única de todas las vulnerabilidades de la conexión
    existing_vulns = (
        db.query(WazuhVulnerability)
        .filter_by(connection_id=conn_id)
        .all()
    )
    existing_map: Dict[Tuple[str, str, str, str], WazuhVulnerability] = {
        (v.agent_id, v.package_name, v.package_version, v.cve_id): v
        for v in existing_vulns
    }
    active_vuln_dict: Dict[int, WazuhVulnerability] = {
        v.id: v for v in existing_vulns if v.status == "ACTIVE"
    }

    pending_new_vulns: List[WazuhVulnerability] = []
    count = 0
    BATCH_SIZE = 500

    def _flush_pending_new_vulns():
        if not pending_new_vulns:
            return
        db.flush()
        history_records = [
            VulnerabilityHistory(
                vulnerability_id=nv.id,
                action="DETECTED",
                details="Vulnerabilidad identificada por primera vez",
            )
            for nv in pending_new_vulns
        ]
        db.add_all(history_records)
        for nv in pending_new_vulns:
            seen_vuln_ids.add(nv.id)
        pending_new_vulns.clear()

    for v in raw_vulns:
        agent = v.get("agent", {})
        osinfo = (v.get("host") or {}).get("os") or {}
        pkg = v.get("package", {})
        vuln = v.get("vulnerability", {})

        cve_id = vuln.get("id")
        if not cve_id:
            continue

        agent_id = agent.get("id")
        pkg_name = pkg.get("name")
        pkg_version = pkg.get("version")
        key = (agent_id, pkg_name, pkg_version, cve_id)

        existing = existing_map.get(key)

        if existing:
            if existing.id is None:
                _flush_pending_new_vulns()
            seen_vuln_ids.add(existing.id)
            _handle_existing_vuln(db, existing, vuln, now=now)
        else:
            detected_at = vuln.get("detected_at") or now
            first_seen = detected_at
            new_vuln = WazuhVulnerability(
                connection_id=conn_id,
                status="ACTIVE",
                agent_id=agent_id,
                agent_name=agent.get("name"),
                os_full=osinfo.get("full"),
                os_platform=osinfo.get("platform"),
                os_version=osinfo.get("version"),
                package_name=pkg_name,
                package_version=pkg_version,
                package_type=pkg.get("type"),
                package_arch=pkg.get("architecture"),
                cve_id=cve_id,
                severity=vuln.get("severity"),
                score_base=(vuln.get("score") or {}).get("base"),
                score_version=(vuln.get("score") or {}).get("version"),
                detected_at=detected_at,
                published_at=vuln.get("published_at"),
                description=vuln.get("description"),
                reference=vuln.get("reference"),
                scanner_vendor=(vuln.get("scanner") or {}).get("vendor"),
                first_seen=first_seen,
                last_seen=first_seen,
            )
            db.add(new_vuln)
            existing_map[key] = new_vuln
            pending_new_vulns.append(new_vuln)

            if len(pending_new_vulns) >= BATCH_SIZE:
                _flush_pending_new_vulns()

        count += 1

    # Asegurar flush de los últimos elementos acumulados
    _flush_pending_new_vulns()

    # Resolver las vulnerabilidades activas previas que ya no vinieron en el scan
    _resolve_missing_vulns(db, active_vuln_dict, seen_vuln_ids)
    return count


def sync_connection(db: Session, conn_id: int) -> Dict[str, Any]:
    conn = (
        db.query(WazuhConnection).filter(WazuhConnection.id == conn_id).first()
    )
    if not conn:
        raise HTTPException(status_code=404, detail=CONNECTION_NOT_FOUND)
    if not conn.is_active:
        raise HTTPException(status_code=400, detail="La conexión está inactiva")

    fetch_fn = get_fetch_all_vulns_fn()
    raw_vulns = fetch_fn(
        cast(str, conn.indexer_url),
        cast(str, conn.wazuh_user),
        decrypt(cast(str, conn.wazuh_password)),
    )

    count = process_wazuh_vulnerabilities(db, cast(int, conn.id), raw_vulns)
    db.commit()

    return {"synced": count, "connection": conn.name}


def sync_all_connections(db: Session) -> List[Dict[str, Any]]:
    conns = db.query(WazuhConnection).filter(WazuhConnection.is_active == True).all()
    results = []

    fetch_fn = get_fetch_all_vulns_fn()
    for conn in conns:
        try:
            raw_vulns = fetch_fn(
                cast(str, conn.indexer_url),
                cast(str, conn.wazuh_user),
                decrypt(cast(str, conn.wazuh_password)),
            )

            count = process_wazuh_vulnerabilities(db, cast(int, conn.id), raw_vulns)
            db.commit()

            results.append({"connection": conn.name, "synced": count, "ok": True})
        except Exception as e:
            db.rollback()
            results.append({"connection": conn.name, "ok": False, "error": str(e)})

    return results


def list_vulns(
    db: Session,
    connection_id: Optional[int] = None,
    limit: Optional[int] = None,
    page: Optional[int] = None,
    page_size: int = 25,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    agent_id: Optional[str] = None,
    agent_name: Optional[str] = None,
    cve_id: Optional[str] = None,
    package_name: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: Optional[str] = "detected_at",
    sort_order: Optional[str] = "desc",
) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    # 1. Columnas calculadas en la base de datos
    dwell_expr = func.calculate_dwell_time(
        WazuhVulnerability.first_seen,
        WazuhVulnerability.last_seen,
    ).label("dwell_time_days")
    age_expr = func.calculate_vuln_age(
        WazuhVulnerability.first_seen,
    ).label("total_age_days")

    query = db.query(
        WazuhVulnerability,
        dwell_expr,
        age_expr,
    )

    # 2. Aplicación de filtros
    if connection_id is not None:
        query = query.filter(WazuhVulnerability.connection_id == connection_id)
    if severity:
        sev_list = [s.strip().upper() for s in severity.split(",") if s.strip()]
        if len(sev_list) == 1:
            query = query.filter(func.upper(WazuhVulnerability.severity) == sev_list[0])
        elif len(sev_list) > 1:
            query = query.filter(func.upper(WazuhVulnerability.severity).in_(sev_list))
    if status:
        stat_list = [s.strip().upper() for s in status.split(",") if s.strip()]
        if len(stat_list) == 1:
            query = query.filter(func.upper(WazuhVulnerability.status) == stat_list[0])
        elif len(stat_list) > 1:
            query = query.filter(func.upper(WazuhVulnerability.status).in_(stat_list))
    if agent_id:
        query = query.filter(WazuhVulnerability.agent_id == agent_id)
    if agent_name:
        query = query.filter(WazuhVulnerability.agent_name.ilike(f"%{agent_name}%"))
    if cve_id:
        query = query.filter(WazuhVulnerability.cve_id.ilike(f"%{cve_id}%"))
    if package_name:
        query = query.filter(WazuhVulnerability.package_name.ilike(f"%{package_name}%"))

    # 3. Búsqueda libre multi-columna
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                WazuhVulnerability.cve_id.ilike(search_term),
                WazuhVulnerability.package_name.ilike(search_term),
                WazuhVulnerability.agent_name.ilike(search_term),
                WazuhVulnerability.agent_id.ilike(search_term),
                WazuhVulnerability.description.ilike(search_term),
            )
        )

    # 4. Conteo total si se solicita paginación
    total_count = None
    if page is not None:
        total_count = query.count()

    # 5. Ordenamiento configurable
    sort_column_map = {
        "id": WazuhVulnerability.id,
        "detected_at": WazuhVulnerability.detected_at,
        "first_seen": WazuhVulnerability.first_seen,
        "last_seen": WazuhVulnerability.last_seen,
        "cve_id": WazuhVulnerability.cve_id,
        "package_name": WazuhVulnerability.package_name,
        "agent_name": WazuhVulnerability.agent_name,
        "agent_id": WazuhVulnerability.agent_id,
        "score_base": WazuhVulnerability.score_base,
        "status": WazuhVulnerability.status,
        "dwell_time_days": dwell_expr,
        "total_age_days": age_expr,
    }

    if sort_by == "severity":
        sort_col = case(
            (func.upper(WazuhVulnerability.severity) == "CRITICAL", 4),
            (func.upper(WazuhVulnerability.severity) == "HIGH", 3),
            (func.upper(WazuhVulnerability.severity) == "MEDIUM", 2),
            (func.upper(WazuhVulnerability.severity) == "LOW", 1),
            else_=0,
        )
    else:
        sort_col = sort_column_map.get(sort_by, WazuhVulnerability.detected_at)

    if (sort_order or "desc").lower() == "asc":
        query = query.order_by(asc(sort_col))
    else:
        query = query.order_by(desc(sort_col))

    # 6. Paginación con LIMIT y OFFSET
    if page is not None:
        safe_page = max(1, page)
        safe_page_size = max(1, min(page_size, 500))
        offset = (safe_page - 1) * safe_page_size
        query = query.offset(offset).limit(safe_page_size)
    elif limit is not None:
        query = query.limit(limit)

    results = query.all()

    items = [
        {
            "id": v.id,
            "connection_id": v.connection_id,
            "connection_name": v.connection.name if v.connection else None,
            "status": v.status,
            "agent_id": v.agent_id,
            "agent_name": v.agent_name,
            "os_full": v.os_full,
            "os_platform": v.os_platform,
            "os_version": v.os_version,
            "package_name": v.package_name,
            "package_version": v.package_version,
            "package_type": v.package_type,
            "package_arch": v.package_arch,
            "cve_id": v.cve_id,
            "severity": v.severity,
            "score_base": float(v.score_base) if v.score_base is not None else None,
            "score_version": v.score_version,
            "detected_at": v.detected_at,
            "published_at": v.published_at,
            "description": v.description,
            "reference": v.reference,
            "scanner_vendor": v.scanner_vendor,
            "first_seen": v.first_seen,
            "last_seen": v.last_seen,
            "dwell_time_days": dwell,
            "total_age_days": age,
            "history": [
                {
                    "id": h.id,
                    "action": h.action,
                    "details": h.details,
                    "timestamp": h.timestamp,
                }
                for h in sorted(v.history, key=lambda h: h.timestamp)
            ],
        }
        for v, dwell, age in results
    ]

    if page is not None:
        total = total_count if total_count is not None else len(items)
        safe_page_size = max(1, min(page_size, 500))
        total_pages = math.ceil(total / safe_page_size) if total > 0 else 0
        return {
            "items": items,
            "total": total,
            "page": max(1, page),
            "page_size": safe_page_size,
            "total_pages": total_pages,
        }

    return items

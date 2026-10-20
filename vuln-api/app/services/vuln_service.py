# app/services/vuln_service.py
import sys
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from fastapi import HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from app.models import WazuhVulnerability, WazuhConnection, VulnerabilityHistory
from app.crypto import decrypt
from app.wazuh_client import fetch_all_vulns as default_fetch_all_vulns
from app.services.connection_service import CONNECTION_NOT_FOUND
from typing import Any, cast


def _handle_existing_vuln(
    db: Session, existing: WazuhVulnerability, vuln: dict
) -> None:
    if existing.status == "RESOLVED":
        # 💡 cast fuerza a Pyrefly a ignorar el tipo inferido 'Never'
        existing.status = cast(Any, "ACTIVE")

        db.add(
            VulnerabilityHistory(
                vulnerability_id=existing.id,
                action="REOPENED",
                details="La vulnerabilidad fue detectada nuevamente por Wazuh",
            )
        )

def get_fetch_all_vulns_fn():
    """Obtiene la función fetch_all_vulns, priorizando app.main si fue parcheada con @patch."""
    main_mod = sys.modules.get("app.main")
    if main_mod and hasattr(main_mod, "fetch_all_vulns"):
        return getattr(main_mod, "fetch_all_vulns")
    return default_fetch_all_vulns


def _handle_existing_vuln(db: Session, existing: WazuhVulnerability, vuln: dict) -> None:
    if existing.status == "RESOLVED":
        existing.status = cast(Any,"ACTIVE")
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
    existing.last_seen = datetime.now(timezone.utc)


def _resolve_missing_vulns(db: Session, active_vuln_dict: dict, seen_vuln_ids: set) -> None:
    for vuln_id, db_vuln in active_vuln_dict.items():
        if vuln_id not in seen_vuln_ids:
            db_vuln.status = "RESOLVED"
            db.add(
                VulnerabilityHistory(
                    vulnerability_id=vuln_id,
                    action="RESOLVED",
                    details="Ya no es reportada por el agente (Probablemente parcheada)",
                )
            )


def process_wazuh_vulnerabilities(db: Session, conn_id: int, raw_vulns: list) -> int:
    count = 0
    seen_vuln_ids = set()

    active_vulns_in_db = (
        db.query(WazuhVulnerability)
        .filter_by(connection_id=conn_id, status="ACTIVE")
        .all()
    )
    active_vuln_dict = {v.id: v for v in active_vulns_in_db}

    for v in raw_vulns:
        agent = v.get("agent", {})
        osinfo = (v.get("host") or {}).get("os") or {}
        pkg = v.get("package", {})
        vuln = v.get("vulnerability", {})

        if not vuln.get("id"):
            continue

        existing = (
            db.query(WazuhVulnerability)
            .filter_by(
                connection_id=conn_id,
                agent_id=agent.get("id"),
                package_name=pkg.get("name"),
                package_version=pkg.get("version"),
                cve_id=vuln.get("id"),
            )
            .first()
        )

        if existing:
            seen_vuln_ids.add(existing.id)
            existing.last_seen = datetime.now(timezone.utc)
            _handle_existing_vuln(db, existing, vuln)
        else:
            detected_at = vuln.get("detected_at") or datetime.now(timezone.utc)
            first_seen = detected_at
            new_vuln = WazuhVulnerability(
                connection_id=conn_id,
                status="ACTIVE",
                agent_id=agent.get("id"),
                agent_name=agent.get("name"),
                os_full=osinfo.get("full"),
                os_platform=osinfo.get("platform"),
                os_version=osinfo.get("version"),
                package_name=pkg.get("name"),
                package_version=pkg.get("version"),
                package_type=pkg.get("type"),
                package_arch=pkg.get("architecture"),
                cve_id=vuln.get("id"),
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
            db.flush()
            db.add(
                VulnerabilityHistory(
                    vulnerability_id=new_vuln.id,
                    action="DETECTED",
                    details="Vulnerabilidad identificada por primera vez",
                )
            )
            seen_vuln_ids.add(new_vuln.id)

        count += 1

    _resolve_missing_vulns(db, active_vuln_dict, seen_vuln_ids)
    return count

from typing import cast


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
                cast(str,conn.indexer_url),
                cast(str,conn.wazuh_user),
                decrypt(cast(str,conn.wazuh_password)),
            )

            count = process_wazuh_vulnerabilities(db, cast(int,conn.id), raw_vulns)
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
) -> List[Dict[str, Any]]:
    query = db.query(
        WazuhVulnerability,
        (
            func.extract(
                "epoch",
                WazuhVulnerability.last_seen - WazuhVulnerability.first_seen,
            )
            / 86400.0
        ).label("dwell_time_days"),
        (
            func.extract("epoch", func.now() - WazuhVulnerability.first_seen)
            / 86400.0
        ).label("total_age_days"),
    )
    if connection_id:
        query = query.filter(WazuhVulnerability.connection_id == connection_id)
    if limit is not None:
        query = query.limit(limit)
    results = query.all()
    return [
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
            "score_base": float(v.score_base) if v.score_base else None,
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

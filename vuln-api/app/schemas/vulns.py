# app/schemas/vulns.py
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel


class VulnerabilityHistoryItem(BaseModel):
    id: int
    action: str
    details: Optional[str] = None
    timestamp: Optional[datetime] = None


class VulnerabilityResponse(BaseModel):
    id: int
    connection_id: int
    connection_name: Optional[str] = None
    status: Optional[str] = None
    agent_id: str
    agent_name: Optional[str] = None
    os_full: Optional[str] = None
    os_platform: Optional[str] = None
    os_version: Optional[str] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    package_type: Optional[str] = None
    package_arch: Optional[str] = None
    cve_id: str
    severity: Optional[str] = None
    score_base: Optional[float] = None
    score_version: Optional[str] = None
    detected_at: Optional[datetime] = None
    published_at: Optional[datetime] = None
    description: Optional[str] = None
    reference: Optional[str] = None
    scanner_vendor: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    dwell_time_days: Optional[float] = None
    total_age_days: Optional[float] = None
    history: List[VulnerabilityHistoryItem] = []


class SyncResult(BaseModel):
    connection: str
    synced: Optional[int] = None
    ok: bool
    error: Optional[str] = None

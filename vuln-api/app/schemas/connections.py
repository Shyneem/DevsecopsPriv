# app/schemas/connections.py
from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class WazuhConnectionRequest(BaseModel):
    name: str
    indexer_url: str
    wazuh_user: str
    wazuh_password: str


class WazuhConnectionResponse(BaseModel):
    id: int
    name: str
    indexer_url: str
    wazuh_user: str
    is_active: bool
    tested: Optional[bool] = None
    last_tested_at: Optional[datetime] = None
    last_test_ok: Optional[bool] = None

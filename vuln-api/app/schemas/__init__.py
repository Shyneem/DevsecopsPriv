# app/schemas/__init__.py
from .auth import TokenResponse, ChangePasswordRequest
from .users import NewUserRequest, UserResponse, CurrentUserResponse
from .connections import WazuhConnectionRequest, WazuhConnectionResponse
from .vulns import VulnerabilityResponse, VulnerabilityHistoryItem, SyncResult

__all__ = [
    "TokenResponse",
    "ChangePasswordRequest",
    "NewUserRequest",
    "UserResponse",
    "CurrentUserResponse",
    "WazuhConnectionRequest",
    "WazuhConnectionResponse",
    "VulnerabilityResponse",
    "VulnerabilityHistoryItem",
    "SyncResult",
]

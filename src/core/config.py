"""Data schemas and types for Zero-Standing-Privilege Dynamic Access & Honeytoken Defense Mesh."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class HoneytokenType(str, Enum):
    IAM_ACCESS_KEY = "IAM_ACCESS_KEY"
    SECRETS_MANAGER_SECRET = "SECRETS_MANAGER_SECRET"
    STS_CANARY_ROLE = "STS_CANARY_ROLE"


class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RevocationStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PENDING = "PENDING"
    FAILED = "FAILED"


class SessionState(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class JITSessionRequest(BaseModel):
    """Request payload submitted by engineer for just-in-time privileged access."""

    user_arn: str = Field(..., description="IAM Identity Center user ARN or SSO user identity")
    target_role_arn: str = Field(..., description="Target privileged IAM role ARN requested")
    duration_minutes: int = Field(default=15, ge=15, le=60, description="Session TTL in minutes (max 60)")
    justification: str = Field(..., min_length=5, description="Business rationale for elevated privilege")
    ticket_id: str = Field(..., description="Approved Jira / ServiceNow change management ticket ID")
    mfa_authenticated: bool = Field(default=True, description="Enforced multi-factor authentication check")


class EphemeralSessionToken(BaseModel):
    """STS AssumeRole credential bundle with cryptographic expiry timestamp."""

    session_id: str
    target_role_arn: str
    access_key_id: str
    expiration: datetime
    ttl_seconds: int
    session_state: SessionState = SessionState.ACTIVE


class Honeytoken(BaseModel):
    """Decoy canary asset planted in enterprise environment to trap threat actors."""

    token_id: str
    honey_type: HoneytokenType
    canary_principal_arn: str
    decoy_access_key_id: str
    deployed_location: str
    is_active: bool = True
    created_at: datetime = Field(default_factory=utc_now)


class HoneytokenAlert(BaseModel):
    """CloudTrail alert triggered upon unauthorized interaction with honeytoken."""

    event_id: str
    honeytoken_id: str
    source_ip: str
    caller_arn: str
    event_name: str
    user_agent: str
    timestamp: datetime = Field(default_factory=utc_now)
    severity: IncidentSeverity = IncidentSeverity.CRITICAL


class RevocationAction(BaseModel):
    """Automated containment action terminating active sessions and blocking attacker."""

    action_id: str
    target_principal_arn: str
    status: RevocationStatus
    sessions_terminated: int
    inline_deny_applied: bool
    containment_duration_ms: float
    timestamp: datetime = Field(default_factory=utc_now)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ForensicReport(BaseModel):
    """Tamper-evident forensic incident manifest for SOC investigations."""

    report_id: str
    generated_at: str
    honeytoken_alerts: List[HoneytokenAlert]
    containment_actions: List[RevocationAction]
    sha256_checksum: Optional[str] = None

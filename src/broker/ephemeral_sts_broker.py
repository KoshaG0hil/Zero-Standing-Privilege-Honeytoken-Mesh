"""Ephemeral STS Token Broker: Just-In-Time Zero-Standing-Privilege Access Engine."""

import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from ..core.config import EphemeralSessionToken, JITSessionRequest, SessionState


class EphemeralSTSBroker:
    """Brokers short-lived, just-in-time STS credentials with strict governance controls."""

    MAX_SESSION_MINUTES = 60
    MIN_SESSION_MINUTES = 15
    VALID_TICKET_PATTERN = re.compile(r"^(INC|SEC|CHG|PR|JIRA)-\d+$")

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        # In-memory registry of active ephemeral sessions: session_id -> EphemeralSessionToken
        self._active_sessions: Dict[str, EphemeralSessionToken] = {}

    def request_access(self, request: JITSessionRequest) -> EphemeralSessionToken:
        """Validates approval policies and issues an ephemeral STS assumed-role token."""
        # 1. Enforce Mandatory MFA
        if not request.mfa_authenticated:
            raise PermissionError("Access Denied: JIT privileged elevation requires multi-factor authentication (MFA).")

        # 2. Enforce Approved Ticket Format
        if not self.VALID_TICKET_PATTERN.match(request.ticket_id):
            raise ValueError(
                f"Invalid Ticket ID: '{request.ticket_id}' must match format 'INC-1234', 'SEC-5678', or 'CHG-9999'."
            )

        # 3. Enforce Session TTL Boundary
        if request.duration_minutes > self.MAX_SESSION_MINUTES:
            raise ValueError(
                f"Session duration {request.duration_minutes}m exceeds maximum "
                f"Zero-Standing-Privilege limit ({self.MAX_SESSION_MINUTES}m)."
            )

        now = datetime.now(timezone.utc)
        duration = timedelta(minutes=request.duration_minutes)
        expiration = now + duration
        session_id = f"zsp-sts-{uuid.uuid4().hex[:12]}"

        # Simulated or live STS AssumeRole
        access_key_id = f"ASIA{uuid.uuid4().hex[:16].upper()}"

        token = EphemeralSessionToken(
            session_id=session_id,
            target_role_arn=request.target_role_arn,
            access_key_id=access_key_id,
            expiration=expiration,
            ttl_seconds=int(duration.total_seconds()),
            session_state=SessionState.ACTIVE,
        )

        self._active_sessions[session_id] = token
        return token

    def list_active_sessions(self) -> List[EphemeralSessionToken]:
        """Returns all currently active ephemeral sessions."""
        now = datetime.now(timezone.utc)
        # Purge naturally expired sessions
        active = []
        for s in self._active_sessions.values():
            if s.session_state == SessionState.ACTIVE and s.expiration > now:
                active.append(s)
            elif s.expiration <= now:
                s.session_state = SessionState.EXPIRED
        return active

    def revoke_session(self, session_id: str) -> bool:
        """Explicitly revokes an active session."""
        session = self._active_sessions.get(session_id)
        if session and session.session_state == SessionState.ACTIVE:
            session.session_state = SessionState.REVOKED
            return True
        return False

    def revoke_all_for_role(self, target_role_arn: str) -> int:
        """Revokes all active ephemeral sessions associated with a target role."""
        revoked_count = 0
        for session in self._active_sessions.values():
            if session.target_role_arn == target_role_arn and session.session_state == SessionState.ACTIVE:
                session.session_state = SessionState.REVOKED
                revoked_count += 1
        return revoked_count

    def get_session(self, session_id: str) -> Optional[EphemeralSessionToken]:
        return self._active_sessions.get(session_id)

"""Tests for Ephemeral STS Token Broker."""

import pytest

from src.core.config import JITSessionRequest, SessionState


def test_valid_jit_request_issues_token(broker, sample_jit_request):
    token = broker.request_access(sample_jit_request)
    assert token.session_id.startswith("zsp-sts-")
    assert token.target_role_arn == sample_jit_request.target_role_arn
    assert token.session_state == SessionState.ACTIVE
    assert token.ttl_seconds == 30 * 60


def test_mfa_requirement_enforcement(broker, sample_jit_request):
    sample_jit_request.mfa_authenticated = False
    with pytest.raises(PermissionError, match="multi-factor authentication"):
        broker.request_access(sample_jit_request)


def test_invalid_ticket_id_rejected(broker, sample_jit_request):
    sample_jit_request.ticket_id = "INVALID-TICKET"
    with pytest.raises(ValueError, match="Invalid Ticket ID"):
        broker.request_access(sample_jit_request)


def test_exceeding_max_session_minutes_rejected(broker):
    with pytest.raises(ValueError):
        JITSessionRequest(
            user_arn="arn:aws:iam::123:user/test",
            target_role_arn="arn:aws:iam::123:role/test",
            duration_minutes=120,
            justification="Needs access",
            ticket_id="CHG-100",
            mfa_authenticated=True,
        )


def test_list_and_revoke_active_sessions(broker, sample_jit_request):
    token = broker.request_access(sample_jit_request)
    active = broker.list_active_sessions()
    assert len(active) == 1
    assert active[0].session_id == token.session_id

    revoked = broker.revoke_session(token.session_id)
    assert revoked is True
    assert len(broker.list_active_sessions()) == 0


def test_revoke_all_for_role(broker, sample_jit_request):
    broker.request_access(sample_jit_request)
    count = broker.revoke_all_for_role(sample_jit_request.target_role_arn)
    assert count == 1
    assert len(broker.list_active_sessions()) == 0

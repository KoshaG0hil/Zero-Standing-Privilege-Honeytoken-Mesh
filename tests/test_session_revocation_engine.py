"""Tests for Honeytoken Revocation Engine & Attacker Neutralization."""

from src.core.config import HoneytokenAlert, IncidentSeverity, RevocationStatus


def test_remediate_breach_drops_sessions(remediator, broker, sample_jit_request):
    # Issue active session
    token = broker.request_access(sample_jit_request)
    assert len(broker.list_active_sessions()) == 1

    alert = HoneytokenAlert(
        event_id="alert-test-01",
        honeytoken_id="honey-1234",
        source_ip="192.0.2.1",
        caller_arn="arn:aws:iam::123:user/attacker",
        event_name="GetCallerIdentity",
        user_agent="aws-cli/2.0",
        severity=IncidentSeverity.CRITICAL,
    )

    action = remediator.remediate_breach(alert, target_role_arn=token.target_role_arn)

    assert action.status == RevocationStatus.SUCCESS
    assert action.sessions_terminated == 1
    assert action.inline_deny_applied is True
    assert len(broker.list_active_sessions()) == 0
    assert "EmergencyQuarantineDenyAll" in str(action.metadata["inline_deny_policy"])

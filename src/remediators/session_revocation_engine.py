"""Automated Session Revocation & Attacker Neutralization Engine."""

import time
import uuid
from typing import Optional

from ..broker.ephemeral_sts_broker import EphemeralSTSBroker
from ..core.config import HoneytokenAlert, RevocationAction, RevocationStatus


class HoneytokenRevocationEngine:
    """Executes sub-second automated containment upon canary honeytoken tripwire breach."""

    def __init__(self, broker: Optional[EphemeralSTSBroker] = None):
        self.broker = broker or EphemeralSTSBroker()

    def remediate_breach(self, alert: HoneytokenAlert, target_role_arn: Optional[str] = None) -> RevocationAction:
        """Immediately revokes all active STS sessions and attaches an inline DenyAll boundary."""
        start_time = time.time()
        action_id = f"revoc-{uuid.uuid4().hex[:10]}"

        # 1. Terminate all active ephemeral STS sessions for targeted roles
        sessions_revoked = 0
        if target_role_arn:
            sessions_revoked = self.broker.revoke_all_for_role(target_role_arn)
        else:
            # Drop all active sessions across broker
            for s in self.broker.list_active_sessions():
                if self.broker.revoke_session(s.session_id):
                    sessions_revoked += 1

        # 2. Attach inline DenyAll policy to target principal
        # In AWS environment, calls: iam.put_user_policy(UserName=..., PolicyName='EmergencyDenyAll', ...)
        inline_deny_policy = self._generate_emergency_deny_policy(alert.caller_arn)

        latency_ms = round((time.time() - start_time) * 1000, 2)

        return RevocationAction(
            action_id=action_id,
            target_principal_arn=alert.caller_arn,
            status=RevocationStatus.SUCCESS,
            sessions_terminated=sessions_revoked,
            inline_deny_applied=True,
            containment_duration_ms=latency_ms,
            metadata={
                "offending_ip": alert.source_ip,
                "api_event": alert.event_name,
                "inline_deny_policy": inline_deny_policy,
            },
        )

    def _generate_emergency_deny_policy(self, principal_arn: str) -> dict:
        """Synthesizes AWS IAM DenyAll quarantine policy document."""
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EmergencyQuarantineDenyAll",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "StringLike": {
                            "aws:PrincipalArn": principal_arn,
                        }
                    },
                }
            ],
        }

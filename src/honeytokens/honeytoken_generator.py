"""Canary Honeytoken Generator & Detection Engine."""

import uuid
from typing import Dict, List, Optional

from ..core.config import Honeytoken, HoneytokenAlert, HoneytokenType, IncidentSeverity


class HoneytokenManager:
    """Manages the creation, placement, and tripwire matching for decoy canary credentials."""

    def __init__(self):
        # Registry of deployed honeytokens: token_id -> Honeytoken
        self._registry: Dict[str, Honeytoken] = {}
        # Key ID to token_id mapping for O(1) CloudTrail lookup
        self._key_map: Dict[str, str] = {}

    def deploy_honeytoken(
        self,
        honey_type: HoneytokenType,
        deployed_location: str,
        canary_principal_arn: Optional[str] = None,
    ) -> Honeytoken:
        """Deploys and registers a high-fidelity decoy canary token."""
        token_id = f"honey-{uuid.uuid4().hex[:8]}"
        decoy_key = f"AKIA{uuid.uuid4().hex[:16].upper()}"

        if not canary_principal_arn:
            canary_principal_arn = f"arn:aws:iam::123456789012:user/canary-decoy-{token_id}"

        honeytoken = Honeytoken(
            token_id=token_id,
            honey_type=honey_type,
            canary_principal_arn=canary_principal_arn,
            decoy_access_key_id=decoy_key,
            deployed_location=deployed_location,
            is_active=True,
        )

        self._registry[token_id] = honeytoken
        self._key_map[decoy_key] = token_id
        return honeytoken

    def evaluate_cloudtrail_event(self, event: Dict[str, any]) -> Optional[HoneytokenAlert]:
        """Inspects an AWS CloudTrail event and generates an alert if a honeytoken was accessed."""
        # Check userIdentity or requestParameters
        user_identity = event.get("userIdentity", {})
        access_key_id = user_identity.get("accessKeyId", "")

        token_id = self._key_map.get(access_key_id)
        if not token_id:
            return None

        honeytoken = self._registry.get(token_id)
        if not honeytoken or not honeytoken.is_active:
            return None

        event_name = event.get("eventName", "UnknownAPI")
        source_ip = event.get("sourceIPAddress", "0.0.0.0")
        caller_arn = user_identity.get("arn", honeytoken.canary_principal_arn)
        user_agent = event.get("userAgent", "aws-cli/2.0")

        return HoneytokenAlert(
            event_id=f"alert-{uuid.uuid4().hex[:10]}",
            honeytoken_id=token_id,
            source_ip=source_ip,
            caller_arn=caller_arn,
            event_name=event_name,
            user_agent=user_agent,
            severity=IncidentSeverity.CRITICAL,
        )

    def list_honeytokens(self) -> List[Honeytoken]:
        return list(self._registry.values())

    def get_honeytoken(self, token_id: str) -> Optional[Honeytoken]:
        return self._registry.get(token_id)

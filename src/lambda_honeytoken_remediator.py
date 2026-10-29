"""AWS Lambda Function: Automated Honeytoken Remediator & Session Revoker."""

import json
import logging
from typing import Any, Dict

from src.broker.ephemeral_sts_broker import EphemeralSTSBroker
from src.honeytokens.honeytoken_generator import HoneytokenManager
from src.remediators.session_revocation_engine import HoneytokenRevocationEngine

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Global persistent instances
broker = EphemeralSTSBroker(dry_run=True)
manager = HoneytokenManager()
engine = HoneytokenRevocationEngine(broker=broker)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Handles EventBridge CloudTrail events, verifies honeytoken tripwire, and triggers instant containment."""
    logger.info("EventBridge honeytoken event received: %s", json.dumps(event))

    detail = event.get("detail", {})
    alert = manager.evaluate_cloudtrail_event(detail)

    if not alert:
        logger.info("Event did not match any active canary honeytoken. No action required.")
        return {
            "statusCode": 200,
            "body": json.dumps({"status": "IGNORED", "message": "No honeytoken breached."}),
        }

    logger.warning("CANARY HONEYTOKEN BREACHED! Offending IP: %s | Caller: %s", alert.source_ip, alert.caller_arn)

    action = engine.remediate_breach(alert)

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "status": "CONTAINED",
                "action_id": action.action_id,
                "sessions_terminated": action.sessions_terminated,
                "containment_duration_ms": action.containment_duration_ms,
            }
        ),
    }

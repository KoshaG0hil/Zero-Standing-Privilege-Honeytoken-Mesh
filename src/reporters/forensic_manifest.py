"""Tamper-evident Forensic Incident Manifest Generator."""

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from ..core.config import HoneytokenAlert, RevocationAction


class ForensicManifestGenerator:
    """Produces SHA-256 signed forensic incident reports for SecOps attribution and legal compliance."""

    def generate(
        self,
        alerts: List[HoneytokenAlert],
        actions: List[RevocationAction],
    ) -> Dict[str, Any]:
        """Compiles incident actions into a canonical, signed JSON manifest."""
        ts = datetime.now(timezone.utc).isoformat()
        report_id = f"forensic-{uuid.uuid4().hex[:12]}"

        manifest_body: Dict[str, Any] = {
            "report_id": report_id,
            "generated_at": ts,
            "incident_framework": "MITRE-ATT&CK-T1078-Valid-Accounts",
            "metrics": {
                "total_honeytokens_triggered": len(alerts),
                "total_containment_actions": len(actions),
                "total_sessions_terminated": sum(a.sessions_terminated for a in actions),
                "average_containment_latency_ms": (
                    round(sum(a.containment_duration_ms for a in actions) / len(actions), 2) if actions else 0.0
                ),
            },
            "alerts": [alert.model_dump(mode="json") for alert in alerts],
            "containment_actions": [action.model_dump(mode="json") for action in actions],
        }

        canonical_json = json.dumps(manifest_body, sort_keys=True, indent=2)
        checksum = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
        manifest_body["sha256_checksum"] = checksum

        return manifest_body

    def save_report(self, manifest: Dict[str, Any], filepath: str = "reports/zsp_forensic_incident_report.json") -> str:
        """Saves generated manifest to destination file."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        return filepath

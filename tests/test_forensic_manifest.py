"""Tests for Tamper-evident Forensic Manifest Generator."""

from src.core.config import HoneytokenAlert, IncidentSeverity, RevocationAction, RevocationStatus
from src.reporters.forensic_manifest import ForensicManifestGenerator


def test_forensic_manifest_generation(tmp_path):
    alert = HoneytokenAlert(
        event_id="alert-001",
        honeytoken_id="honey-abc",
        source_ip="198.51.100.99",
        caller_arn="arn:aws:iam::123:user/decoy",
        event_name="GetObject",
        user_agent="Python-urllib/3.11",
        severity=IncidentSeverity.CRITICAL,
    )

    action = RevocationAction(
        action_id="revoc-001",
        target_principal_arn="arn:aws:iam::123:user/decoy",
        status=RevocationStatus.SUCCESS,
        sessions_terminated=2,
        inline_deny_applied=True,
        containment_duration_ms=2.45,
    )

    generator = ForensicManifestGenerator()
    manifest = generator.generate([alert], [action])

    assert "sha256_checksum" in manifest
    assert len(manifest["sha256_checksum"]) == 64
    assert manifest["metrics"]["total_honeytokens_triggered"] == 1
    assert manifest["metrics"]["total_sessions_terminated"] == 2

    out_file = str(tmp_path / "forensic.json")
    saved = generator.save_report(manifest, out_file)
    assert saved == out_file

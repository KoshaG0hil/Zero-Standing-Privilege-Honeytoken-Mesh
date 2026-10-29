"""Tests for Honeytoken Generator and CloudTrail Tripwire Detection."""

from src.core.config import HoneytokenType, IncidentSeverity


def test_deploy_honeytoken(honey_manager):
    ht = honey_manager.deploy_honeytoken(
        honey_type=HoneytokenType.SECRETS_MANAGER_SECRET,
        deployed_location="k8s-configmap:db-secret",
    )
    assert ht.token_id.startswith("honey-")
    assert ht.decoy_access_key_id.startswith("AKIA")
    assert ht.is_active is True
    assert len(honey_manager.list_honeytokens()) == 1


def test_cloudtrail_event_matches_honeytoken(honey_manager, sample_honeytoken):
    ct_event = {
        "userIdentity": {
            "type": "IAMUser",
            "accessKeyId": sample_honeytoken.decoy_access_key_id,
            "arn": sample_honeytoken.canary_principal_arn,
        },
        "eventName": "ListBuckets",
        "sourceIPAddress": "203.0.113.195",
        "userAgent": "Boto3/1.28.0",
    }
    alert = honey_manager.evaluate_cloudtrail_event(ct_event)
    assert alert is not None
    assert alert.honeytoken_id == sample_honeytoken.token_id
    assert alert.source_ip == "203.0.113.195"
    assert alert.event_name == "ListBuckets"
    assert alert.severity == IncidentSeverity.CRITICAL


def test_unrelated_cloudtrail_event_ignored(honey_manager):
    ct_event = {
        "userIdentity": {
            "accessKeyId": "AKIAUNRELATEDKEYEXAMPLE",
        },
        "eventName": "DescribeInstances",
    }
    alert = honey_manager.evaluate_cloudtrail_event(ct_event)
    assert alert is None

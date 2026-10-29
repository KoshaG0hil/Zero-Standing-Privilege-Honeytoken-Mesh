"""Tests for Lambda Honeytoken Remediator EventBridge Handler."""

import json

from src.lambda_honeytoken_remediator import lambda_handler, manager


def test_lambda_handler_unmatched_event():
    event = {
        "detail": {
            "userIdentity": {"accessKeyId": "AKIANONEXISTENTKEY"},
            "eventName": "DescribeInstances",
        }
    }
    resp = lambda_handler(event, None)
    assert resp["statusCode"] == 200
    body = json.loads(resp["body"])
    assert body["status"] == "IGNORED"


def test_lambda_handler_matched_honeytoken():
    # Deploy a token to manager
    ht = manager.deploy_honeytoken(
        honey_type="IAM_ACCESS_KEY",
        deployed_location="git-repo:infra-mesh",
    )

    event = {
        "detail": {
            "userIdentity": {
                "type": "IAMUser",
                "accessKeyId": ht.decoy_access_key_id,
                "arn": ht.canary_principal_arn,
            },
            "eventName": "GetCallerIdentity",
            "sourceIPAddress": "198.51.100.5",
        }
    }
    resp = lambda_handler(event, None)
    assert resp["statusCode"] == 200
    body = json.loads(resp["body"])
    assert body["status"] == "CONTAINED"
    assert "action_id" in body

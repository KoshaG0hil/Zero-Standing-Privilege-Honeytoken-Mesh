"""Shared test fixtures for Zero-Standing-Privilege Honeytoken Mesh tests."""

import pytest

from src.broker.ephemeral_sts_broker import EphemeralSTSBroker
from src.core.config import HoneytokenType, JITSessionRequest
from src.honeytokens.honeytoken_generator import HoneytokenManager
from src.remediators.session_revocation_engine import HoneytokenRevocationEngine


@pytest.fixture
def broker():
    return EphemeralSTSBroker(dry_run=True)


@pytest.fixture
def honey_manager():
    return HoneytokenManager()


@pytest.fixture
def remediator(broker):
    return HoneytokenRevocationEngine(broker=broker)


@pytest.fixture
def sample_jit_request():
    return JITSessionRequest(
        user_arn="arn:aws:identitystore:::user/alice-dev",
        target_role_arn="arn:aws:iam::123456789012:role/DevOpsAdmin",
        duration_minutes=30,
        justification="Hotfix deployment for security advisory SEC-8890",
        ticket_id="SEC-8890",
        mfa_authenticated=True,
    )


@pytest.fixture
def sample_honeytoken(honey_manager):
    return honey_manager.deploy_honeytoken(
        honey_type=HoneytokenType.IAM_ACCESS_KEY,
        deployed_location="s3://backup-secrets/dev-keys.env",
    )

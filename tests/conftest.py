"""Test fixtures for aumos-govdef-overlay."""

import uuid
from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock

import pytest

from aumos_common.auth import TenantContext

from aumos_govdef_overlay.adapters.kafka import GovDefEventPublisher


@pytest.fixture()
def tenant_context() -> TenantContext:
    """Provide a mock tenant context for tests."""
    return TenantContext(
        tenant_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        correlation_id=uuid.uuid4(),
        privilege_level=3,
    )


@pytest.fixture()
def mock_event_publisher() -> GovDefEventPublisher:
    """Provide a mock GovDefEventPublisher with all methods as AsyncMock."""
    publisher = MagicMock(spec=GovDefEventPublisher)
    publisher.publish_fedramp_assessed = AsyncMock()
    publisher.publish_nist_controls_mapped = AsyncMock()
    publisher.publish_cmmc_assessed = AsyncMock()
    publisher.publish_sovereign_deployment_initiated = AsyncMock()
    publisher.publish_classified_env_configured = AsyncMock()
    return publisher

"""Kafka event publishing for aumos-govdef-overlay.

This module defines the domain events published by this service and
provides a typed publisher wrapper.

Events must:
  - Include tenant_id and correlation_id fields
  - Be published via EventPublisher from aumos-common
  - Use Topics.* constants for topic names

After publishing, log at INFO level with event details for traceability.
"""

import uuid

from aumos_common.events import EventPublisher, Topics
from aumos_common.observability import get_logger

logger = get_logger(__name__)


class GovDefEventPublisher:
    """Publisher for aumos-govdef-overlay domain events.

    Wraps EventPublisher with typed methods for each event type
    produced by this service.

    Args:
        publisher: The underlying EventPublisher from aumos-common.
    """

    def __init__(self, publisher: EventPublisher) -> None:
        """Initialize with the shared event publisher.

        Args:
            publisher: Configured EventPublisher instance.
        """
        self._publisher = publisher

    async def publish_fedramp_assessed(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
        agency_id: str,
        readiness_score: float,
        correlation_id: str,
    ) -> None:
        """Publish a FedRAMPAssessmentCompleted event to Kafka.

        Args:
            tenant_id: The tenant that owns the assessment.
            assessment_id: The newly created assessment ID.
            agency_id: Federal agency identifier.
            readiness_score: Computed FedRAMP readiness score (0-100).
            correlation_id: Request correlation ID for tracing.
        """
        event = {
            "event_type": "fedramp.assessment.completed",
            "tenant_id": str(tenant_id),
            "assessment_id": str(assessment_id),
            "agency_id": agency_id,
            "readiness_score": readiness_score,
            "correlation_id": correlation_id,
        }
        await self._publisher.publish(Topics.COMPLIANCE_EVENTS, event)
        logger.info(
            "Published FedRAMPAssessmentCompleted event",
            tenant_id=str(tenant_id),
            assessment_id=str(assessment_id),
            readiness_score=readiness_score,
        )

    async def publish_nist_controls_mapped(
        self,
        tenant_id: uuid.UUID,
        controls_count: int,
        baseline: str,
        correlation_id: str,
    ) -> None:
        """Publish a NISTControlsMapped event to Kafka.

        Args:
            tenant_id: The tenant that owns the controls.
            controls_count: Number of controls mapped.
            baseline: NIST baseline (low/moderate/high).
            correlation_id: Request correlation ID for tracing.
        """
        event = {
            "event_type": "nist.controls.mapped",
            "tenant_id": str(tenant_id),
            "controls_count": controls_count,
            "baseline": baseline,
            "correlation_id": correlation_id,
        }
        await self._publisher.publish(Topics.COMPLIANCE_EVENTS, event)
        logger.info(
            "Published NISTControlsMapped event",
            tenant_id=str(tenant_id),
            controls_count=controls_count,
            baseline=baseline,
        )

    async def publish_cmmc_assessed(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
        target_level: int,
        score: float,
        correlation_id: str,
    ) -> None:
        """Publish a CMMCAssessmentCompleted event to Kafka.

        Args:
            tenant_id: The tenant that owns the assessment.
            assessment_id: The newly created assessment ID.
            target_level: CMMC target level (1, 2, or 3).
            score: Computed CMMC score.
            correlation_id: Request correlation ID for tracing.
        """
        event = {
            "event_type": "cmmc.assessment.completed",
            "tenant_id": str(tenant_id),
            "assessment_id": str(assessment_id),
            "target_level": target_level,
            "score": score,
            "correlation_id": correlation_id,
        }
        await self._publisher.publish(Topics.COMPLIANCE_EVENTS, event)
        logger.info(
            "Published CMMCAssessmentCompleted event",
            tenant_id=str(tenant_id),
            assessment_id=str(assessment_id),
            target_level=target_level,
            score=score,
        )

    async def publish_sovereign_deployment_initiated(
        self,
        tenant_id: uuid.UUID,
        deployment_id: uuid.UUID,
        cloud_provider: str,
        region: str,
        correlation_id: str,
    ) -> None:
        """Publish a SovereignDeploymentInitiated event to Kafka.

        Args:
            tenant_id: The tenant that owns the deployment.
            deployment_id: The newly created deployment ID.
            cloud_provider: Target sovereign cloud provider.
            region: Deployment region.
            correlation_id: Request correlation ID for tracing.
        """
        event = {
            "event_type": "sovereign.deployment.initiated",
            "tenant_id": str(tenant_id),
            "deployment_id": str(deployment_id),
            "cloud_provider": cloud_provider,
            "region": region,
            "correlation_id": correlation_id,
        }
        await self._publisher.publish(Topics.DEPLOYMENT_EVENTS, event)
        logger.info(
            "Published SovereignDeploymentInitiated event",
            tenant_id=str(tenant_id),
            deployment_id=str(deployment_id),
            cloud_provider=cloud_provider,
            region=region,
        )

    async def publish_classified_env_configured(
        self,
        tenant_id: uuid.UUID,
        env_id: uuid.UUID,
        environment_name: str,
        impact_level: int,
        correlation_id: str,
    ) -> None:
        """Publish a ClassifiedEnvConfigured event to Kafka.

        Args:
            tenant_id: The tenant that owns the environment.
            env_id: The newly created environment ID.
            environment_name: Human-readable environment name.
            impact_level: DoD Impact Level (4 or 5).
            correlation_id: Request correlation ID for tracing.
        """
        event = {
            "event_type": "classified_env.configured",
            "tenant_id": str(tenant_id),
            "env_id": str(env_id),
            "environment_name": environment_name,
            "impact_level": impact_level,
            "correlation_id": correlation_id,
        }
        await self._publisher.publish(Topics.COMPLIANCE_EVENTS, event)
        logger.info(
            "Published ClassifiedEnvConfigured event",
            tenant_id=str(tenant_id),
            env_id=str(env_id),
            environment_name=environment_name,
            impact_level=impact_level,
        )

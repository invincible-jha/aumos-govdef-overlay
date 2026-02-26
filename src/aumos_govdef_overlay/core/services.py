"""Business logic services for aumos-govdef-overlay.

Services contain all domain logic. They:
  - Accept dependencies via constructor injection (repositories, publishers)
  - Orchestrate repository calls and event publishing
  - Raise domain errors using aumos_common.errors
  - Are framework-agnostic (no FastAPI, no direct DB access)

After any state-changing operation, publish a Kafka event via EventPublisher.
"""

import uuid

from aumos_common.auth import TenantContext
from aumos_common.errors import NotFoundError
from aumos_common.observability import get_logger

from aumos_govdef_overlay.adapters.kafka import GovDefEventPublisher
from aumos_govdef_overlay.core.interfaces import (
    ICMMCRepository,
    IClassifiedEnvRepository,
    IFedRAMPRepository,
    INISTControlRepository,
    ISovereignCloudRepository,
)
from aumos_govdef_overlay.core.models import (
    CMMCAssessment,
    CMMCAssessmentStatus,
    ClassifiedEnvironment,
    ClassifiedEnvStatus,
    FedRAMPAssessment,
    FedRAMPAuthorizationStatus,
    FedRAMPImpactLevel,
    NISTControl,
    NISTControlStatus,
    SovereignDeployment,
    SovereignDeploymentStatus,
)

logger = get_logger(__name__)

# NIST 800-53 Rev 5 control counts per baseline
_NIST_CONTROL_COUNTS: dict[str, int] = {
    "low": 125,
    "moderate": 325,
    "high": 421,
}

# CMMC practice counts per level
_CMMC_PRACTICE_COUNTS: dict[int, int] = {
    1: 17,
    2: 110,
    3: 134,
}

# CMMC domain names
_CMMC_DOMAINS = [
    "Access Control",
    "Asset Management",
    "Audit and Accountability",
    "Awareness and Training",
    "Configuration Management",
    "Identification and Authentication",
    "Incident Response",
    "Maintenance",
    "Media Protection",
    "Personnel Security",
    "Physical Protection",
    "Recovery",
    "Risk Management",
    "Security Assessment",
    "Situational Awareness",
    "System and Communications Protection",
    "System and Information Integrity",
]


class FedRAMPService:
    """Service for FedRAMP authorization readiness assessments.

    Orchestrates readiness assessments, control gap analysis,
    and authorization workflow progression for FedRAMP compliance.

    Args:
        repository: FedRAMP assessment data access layer.
        publisher: Domain event publisher for compliance events.
    """

    def __init__(
        self,
        repository: IFedRAMPRepository,
        publisher: GovDefEventPublisher,
    ) -> None:
        """Initialize service with injected dependencies.

        Args:
            repository: Repository implementing IFedRAMPRepository.
            publisher: Event publisher for FedRAMP domain events.
        """
        self._repository = repository
        self._publisher = publisher

    async def assess_readiness(
        self,
        agency_id: str,
        service_name: str,
        impact_level: str,
        current_controls_implemented: int,
        tenant: TenantContext,
    ) -> FedRAMPAssessment:
        """Perform a FedRAMP readiness assessment.

        Calculates a readiness score based on the ratio of implemented
        controls to total required controls for the specified impact level.

        Args:
            agency_id: Federal agency identifier.
            service_name: Cloud service offering name.
            impact_level: FedRAMP impact level (low/moderate/high).
            current_controls_implemented: Number of controls currently implemented.
            tenant: Tenant context for RLS isolation.

        Returns:
            The created FedRAMPAssessment record with readiness score.
        """
        if impact_level not in [level.value for level in FedRAMPImpactLevel]:
            impact_level = FedRAMPImpactLevel.MODERATE.value

        controls_total = _NIST_CONTROL_COUNTS.get(impact_level, 325)
        readiness_score = min(
            100.0,
            round((current_controls_implemented / controls_total) * 100, 2),
        )

        assessment = await self._repository.create(
            agency_id=agency_id,
            service_name=service_name,
            impact_level=impact_level,
            tenant=tenant,
        )

        updates: dict = {
            "controls_total": controls_total,
            "controls_implemented": current_controls_implemented,
            "readiness_score": readiness_score,
            "authorization_status": FedRAMPAuthorizationStatus.READINESS_ASSESSMENT.value,
        }
        assessment = await self._repository.update(assessment.id, updates, tenant)  # type: ignore[assignment]

        logger.info(
            "FedRAMP readiness assessment completed",
            tenant_id=str(tenant.tenant_id),
            assessment_id=str(assessment.id),
            agency_id=agency_id,
            impact_level=impact_level,
            readiness_score=readiness_score,
        )

        await self._publisher.publish_fedramp_assessed(
            tenant_id=tenant.tenant_id,
            assessment_id=assessment.id,
            agency_id=agency_id,
            readiness_score=readiness_score,
            correlation_id=str(tenant.correlation_id),
        )

        return assessment

    async def get_authorization_status(
        self,
        agency_id: str,
        tenant: TenantContext,
    ) -> FedRAMPAssessment:
        """Retrieve the latest FedRAMP authorization status for an agency.

        Args:
            agency_id: Federal agency identifier.
            tenant: Tenant context for RLS isolation.

        Returns:
            The most recent FedRAMPAssessment for the agency.

        Raises:
            NotFoundError: If no assessment exists for the given agency.
        """
        assessment = await self._repository.get_latest_by_agency(agency_id, tenant)
        if assessment is None:
            raise NotFoundError(
                resource_type="FedRAMPAssessment",
                resource_id=agency_id,
            )

        logger.info(
            "Retrieved FedRAMP authorization status",
            tenant_id=str(tenant.tenant_id),
            agency_id=agency_id,
            status=assessment.authorization_status,
        )
        return assessment

    async def list_assessments(
        self, tenant: TenantContext
    ) -> list[FedRAMPAssessment]:
        """List all FedRAMP assessments for the tenant.

        Args:
            tenant: Tenant context for RLS isolation.

        Returns:
            List of all FedRAMPAssessment records for the tenant.
        """
        return await self._repository.list_all(tenant)


class NISTService:
    """Service for NIST 800-53 control mapping and compliance tracking.

    Manages control implementation status, evidence tracking, and
    compliance reporting against NIST SP 800-53 baselines.

    Args:
        repository: NIST control data access layer.
        publisher: Domain event publisher for compliance events.
    """

    def __init__(
        self,
        repository: INISTControlRepository,
        publisher: GovDefEventPublisher,
    ) -> None:
        """Initialize service with injected dependencies.

        Args:
            repository: Repository implementing INISTControlRepository.
            publisher: Event publisher for NIST domain events.
        """
        self._repository = repository
        self._publisher = publisher

    async def map_controls(
        self,
        controls: list[dict],
        baseline: str,
        revision: str,
        tenant: TenantContext,
    ) -> list[NISTControl]:
        """Bulk map and upsert NIST 800-53 control implementation status.

        Args:
            controls: List of control mapping dictionaries with control_id,
                      control_family, control_name, implementation_status, etc.
            baseline: NIST baseline (low/moderate/high).
            revision: NIST revision (rev4/rev5).
            tenant: Tenant context for RLS isolation.

        Returns:
            List of created/updated NISTControl records.
        """
        enriched_controls = [
            {**control, "baseline": baseline, "revision": revision}
            for control in controls
        ]

        mapped_controls = await self._repository.bulk_upsert(enriched_controls, tenant)

        logger.info(
            "NIST 800-53 controls mapped",
            tenant_id=str(tenant.tenant_id),
            controls_mapped=len(mapped_controls),
            baseline=baseline,
            revision=revision,
        )

        await self._publisher.publish_nist_controls_mapped(
            tenant_id=tenant.tenant_id,
            controls_count=len(mapped_controls),
            baseline=baseline,
            correlation_id=str(tenant.correlation_id),
        )

        return mapped_controls

    async def get_controls_status(
        self, tenant: TenantContext
    ) -> dict:
        """Get a summary of NIST 800-53 control implementation status.

        Args:
            tenant: Tenant context for RLS isolation.

        Returns:
            Dictionary with implementation status counts and completion percentage.
        """
        summary = await self._repository.get_completion_summary(tenant)

        logger.info(
            "Retrieved NIST control status summary",
            tenant_id=str(tenant.tenant_id),
        )
        return summary

    async def list_controls_by_family(
        self, control_family: str, tenant: TenantContext
    ) -> list[NISTControl]:
        """List all controls in a specific NIST control family.

        Args:
            control_family: NIST control family identifier (e.g., "AC", "AU").
            tenant: Tenant context for RLS isolation.

        Returns:
            List of NISTControl records for the specified family.
        """
        return await self._repository.list_by_family(control_family, tenant)

    async def update_control_status(
        self,
        record_id: uuid.UUID,
        implementation_status: str,
        implementation_narrative: str | None,
        evidence_references: list | None,
        tenant: TenantContext,
    ) -> NISTControl:
        """Update the implementation status of a NIST control.

        Args:
            record_id: UUID of the NISTControl record.
            implementation_status: New implementation status value.
            implementation_narrative: Description of how the control is implemented.
            evidence_references: List of evidence reference URLs or identifiers.
            tenant: Tenant context for RLS isolation.

        Returns:
            Updated NISTControl record.

        Raises:
            NotFoundError: If the control record does not exist.
        """
        if implementation_status not in [s.value for s in NISTControlStatus]:
            implementation_status = NISTControlStatus.NOT_IMPLEMENTED.value

        updates: dict = {"implementation_status": implementation_status}
        if implementation_narrative is not None:
            updates["implementation_narrative"] = implementation_narrative
        if evidence_references is not None:
            updates["evidence_references"] = evidence_references

        control = await self._repository.update(record_id, updates, tenant)
        if control is None:
            raise NotFoundError(
                resource_type="NISTControl",
                resource_id=str(record_id),
            )

        logger.info(
            "NIST control status updated",
            tenant_id=str(tenant.tenant_id),
            record_id=str(record_id),
            implementation_status=implementation_status,
        )
        return control


class CMMCService:
    """Service for CMMC (Cybersecurity Maturity Model Certification) assessments.

    Manages CMMC practice gap analysis, scoring, and certification
    workflow for DoD contractors handling CUI data.

    Args:
        repository: CMMC assessment data access layer.
        publisher: Domain event publisher for compliance events.
    """

    def __init__(
        self,
        repository: ICMMCRepository,
        publisher: GovDefEventPublisher,
    ) -> None:
        """Initialize service with injected dependencies.

        Args:
            repository: Repository implementing ICMMCRepository.
            publisher: Event publisher for CMMC domain events.
        """
        self._repository = repository
        self._publisher = publisher

    async def assess(
        self,
        target_level: int,
        practices_met: int,
        domain_scores: dict | None,
        c3pao_id: str | None,
        tenant: TenantContext,
    ) -> CMMCAssessment:
        """Perform a CMMC compliance assessment.

        Calculates CMMC score based on practices met vs. total required
        for the target level and initializes domain-level scoring.

        Args:
            target_level: CMMC target level (1, 2, or 3).
            practices_met: Number of CMMC practices currently met.
            domain_scores: Optional per-domain practice scores.
            c3pao_id: Certified Third-Party Assessment Organization ID (Level 2+).
            tenant: Tenant context for RLS isolation.

        Returns:
            The created CMMCAssessment with calculated score.
        """
        if target_level not in _CMMC_PRACTICE_COUNTS:
            target_level = 3

        practices_total = _CMMC_PRACTICE_COUNTS[target_level]
        practices_not_met = practices_total - min(practices_met, practices_total)
        score = round((practices_met / practices_total) * 110, 2)  # SPRS-like scoring

        # Initialize domain scores if not provided
        if domain_scores is None:
            domain_scores = {domain: 0 for domain in _CMMC_DOMAINS}

        assessment = await self._repository.create(
            target_level=target_level,
            tenant=tenant,
        )

        status = (
            CMMCAssessmentStatus.C3PAO_ASSESSMENT.value
            if c3pao_id
            else CMMCAssessmentStatus.SELF_ASSESSMENT.value
        )

        updates: dict = {
            "practices_total": practices_total,
            "practices_met": practices_met,
            "practices_not_met": practices_not_met,
            "score": score,
            "domain_scores": domain_scores,
            "assessment_status": status,
        }
        if c3pao_id:
            updates["c3pao_id"] = c3pao_id

        assessment = await self._repository.update(assessment.id, updates, tenant)  # type: ignore[assignment]

        logger.info(
            "CMMC assessment completed",
            tenant_id=str(tenant.tenant_id),
            assessment_id=str(assessment.id),
            target_level=target_level,
            score=score,
            practices_met=practices_met,
            practices_total=practices_total,
        )

        await self._publisher.publish_cmmc_assessed(
            tenant_id=tenant.tenant_id,
            assessment_id=assessment.id,
            target_level=target_level,
            score=score,
            correlation_id=str(tenant.correlation_id),
        )

        return assessment

    async def get_level_status(
        self, level: int, tenant: TenantContext
    ) -> CMMCAssessment:
        """Retrieve the latest CMMC compliance status for a given level.

        Args:
            level: CMMC level to query (1, 2, or 3).
            tenant: Tenant context for RLS isolation.

        Returns:
            The most recent CMMCAssessment for the specified level.

        Raises:
            NotFoundError: If no assessment exists for the given level.
        """
        assessment = await self._repository.get_latest_by_level(level, tenant)
        if assessment is None:
            raise NotFoundError(
                resource_type="CMMCAssessment",
                resource_id=str(level),
            )

        logger.info(
            "Retrieved CMMC level status",
            tenant_id=str(tenant.tenant_id),
            level=level,
            status=assessment.assessment_status,
        )
        return assessment

    async def list_assessments(self, tenant: TenantContext) -> list[CMMCAssessment]:
        """List all CMMC assessments for the tenant.

        Args:
            tenant: Tenant context for RLS isolation.

        Returns:
            List of all CMMCAssessment records for the tenant.
        """
        return await self._repository.list_all(tenant)


class SovereignCloudService:
    """Service for sovereign cloud deployment management.

    Orchestrates deployments to government sovereign cloud environments
    with appropriate network isolation, encryption, and compliance controls.

    Args:
        repository: Sovereign deployment data access layer.
        publisher: Domain event publisher for deployment events.
    """

    def __init__(
        self,
        repository: ISovereignCloudRepository,
        publisher: GovDefEventPublisher,
    ) -> None:
        """Initialize service with injected dependencies.

        Args:
            repository: Repository implementing ISovereignCloudRepository.
            publisher: Event publisher for sovereign cloud domain events.
        """
        self._repository = repository
        self._publisher = publisher

    async def deploy(
        self,
        deployment_name: str,
        cloud_provider: str,
        region: str,
        compliance_frameworks: list[str],
        encryption_config: dict | None,
        network_isolation_config: dict | None,
        is_air_gapped: bool,
        tenant: TenantContext,
    ) -> SovereignDeployment:
        """Initiate a sovereign cloud deployment.

        Creates a deployment configuration record and triggers provisioning
        for the specified government sovereign cloud environment.

        Args:
            deployment_name: Human-readable deployment identifier.
            cloud_provider: Target provider (aws-govcloud/azure-government/gcc-high).
            region: Deployment region identifier.
            compliance_frameworks: List of compliance frameworks to enforce.
            encryption_config: Encryption settings for data at rest and in transit.
            network_isolation_config: VPC/VNet isolation configuration.
            is_air_gapped: Whether the deployment is network-isolated.
            tenant: Tenant context for RLS isolation.

        Returns:
            Created SovereignDeployment record with PROVISIONING status.
        """
        deployment = await self._repository.create(
            deployment_name=deployment_name,
            cloud_provider=cloud_provider,
            region=region,
            tenant=tenant,
        )

        updates: dict = {
            "deployment_status": SovereignDeploymentStatus.PROVISIONING.value,
            "compliance_frameworks": compliance_frameworks,
            "is_air_gapped": is_air_gapped,
        }
        if encryption_config:
            updates["encryption_config"] = encryption_config
        if network_isolation_config:
            updates["network_isolation_config"] = network_isolation_config

        deployment = await self._repository.update(deployment.id, updates, tenant)  # type: ignore[assignment]

        logger.info(
            "Sovereign cloud deployment initiated",
            tenant_id=str(tenant.tenant_id),
            deployment_id=str(deployment.id),
            cloud_provider=cloud_provider,
            region=region,
            is_air_gapped=is_air_gapped,
        )

        await self._publisher.publish_sovereign_deployment_initiated(
            tenant_id=tenant.tenant_id,
            deployment_id=deployment.id,
            cloud_provider=cloud_provider,
            region=region,
            correlation_id=str(tenant.correlation_id),
        )

        return deployment

    async def get_il_level_status(
        self, il_level: int, tenant: TenantContext
    ) -> list[SovereignDeployment]:
        """Get sovereign deployments supporting a specific Impact Level.

        Args:
            il_level: DoD Impact Level (4 or 5).
            tenant: Tenant context for RLS isolation.

        Returns:
            List of SovereignDeployment records supporting the IL level.
        """
        all_deployments = await self._repository.list_all(tenant)
        # Filter by compliance frameworks that include the IL level marker
        il_marker = f"IL{il_level}"
        return [
            d for d in all_deployments
            if d.compliance_frameworks and il_marker in (d.compliance_frameworks or [])
        ]

    async def list_deployments(self, tenant: TenantContext) -> list[SovereignDeployment]:
        """List all sovereign cloud deployments for the tenant.

        Args:
            tenant: Tenant context for RLS isolation.

        Returns:
            List of all SovereignDeployment records for the tenant.
        """
        return await self._repository.list_all(tenant)


class ClassifiedEnvService:
    """Service for air-gapped classified environment management.

    Manages configuration and operational status for IL4/IL5 classified
    environments, enforcing strict access controls and audit requirements.

    Args:
        repository: Classified environment data access layer.
        publisher: Domain event publisher for classified env events.
    """

    def __init__(
        self,
        repository: IClassifiedEnvRepository,
        publisher: GovDefEventPublisher,
    ) -> None:
        """Initialize service with injected dependencies.

        Args:
            repository: Repository implementing IClassifiedEnvRepository.
            publisher: Event publisher for classified environment domain events.
        """
        self._repository = repository
        self._publisher = publisher

    async def configure_environment(
        self,
        environment_name: str,
        impact_level: int,
        classification_level: str,
        encryption_key_arn: str | None,
        network_segment: str | None,
        personnel_requirements: dict | None,
        physical_security_config: dict | None,
        tenant: TenantContext,
    ) -> ClassifiedEnvironment:
        """Configure an air-gapped classified environment.

        Creates an environment configuration record with strict IL4/IL5
        security controls, encryption, and audit requirements.

        Args:
            environment_name: Human-readable environment identifier.
            impact_level: DoD Impact Level (4 or 5).
            classification_level: Data classification (CUI, SECRET, etc.).
            encryption_key_arn: ARN of KMS key for data encryption.
            network_segment: Network segment identifier for isolation.
            personnel_requirements: Clearance and access requirements.
            physical_security_config: Physical security control settings.
            tenant: Tenant context for RLS isolation.

        Returns:
            Created ClassifiedEnvironment record.
        """
        env = await self._repository.create(
            environment_name=environment_name,
            impact_level=impact_level,
            classification_level=classification_level,
            tenant=tenant,
        )

        updates: dict = {
            "environment_status": ClassifiedEnvStatus.INITIALIZING.value,
            "is_air_gapped": True,
        }
        if encryption_key_arn:
            updates["encryption_key_arn"] = encryption_key_arn
        if network_segment:
            updates["network_segment"] = network_segment
        if personnel_requirements:
            updates["personnel_security_requirements"] = personnel_requirements
        if physical_security_config:
            updates["physical_security_config"] = physical_security_config

        env = await self._repository.update(env.id, updates, tenant)  # type: ignore[assignment]

        logger.info(
            "Classified environment configured",
            tenant_id=str(tenant.tenant_id),
            env_id=str(env.id),
            environment_name=environment_name,
            impact_level=impact_level,
            classification_level=classification_level,
        )

        await self._publisher.publish_classified_env_configured(
            tenant_id=tenant.tenant_id,
            env_id=env.id,
            environment_name=environment_name,
            impact_level=impact_level,
            correlation_id=str(tenant.correlation_id),
        )

        return env

    async def get_il_level_status(
        self, il_level: int, tenant: TenantContext
    ) -> list[ClassifiedEnvironment]:
        """Get all classified environments at a specific Impact Level.

        Args:
            il_level: DoD Impact Level (4 or 5).
            tenant: Tenant context for RLS isolation.

        Returns:
            List of ClassifiedEnvironment records at the specified IL.
        """
        return await self._repository.list_by_il_level(il_level, tenant)

    async def list_environments(
        self, tenant: TenantContext
    ) -> list[ClassifiedEnvironment]:
        """List all classified environments for the tenant.

        Args:
            tenant: Tenant context for RLS isolation.

        Returns:
            List of all ClassifiedEnvironment records for the tenant.
        """
        return await self._repository.list_all(tenant)


__all__ = [
    "FedRAMPService",
    "NISTService",
    "CMMCService",
    "SovereignCloudService",
    "ClassifiedEnvService",
]

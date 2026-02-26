"""Unit tests for aumos-govdef-overlay service layer."""

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from aumos_common.auth import TenantContext
from aumos_common.errors import NotFoundError

from aumos_govdef_overlay.adapters.kafka import GovDefEventPublisher
from aumos_govdef_overlay.core.models import (
    CMMCAssessment,
    CMMCAssessmentStatus,
    FedRAMPAssessment,
    FedRAMPAuthorizationStatus,
    NISTControl,
    NISTControlStatus,
    SovereignDeployment,
    SovereignDeploymentStatus,
)
from aumos_govdef_overlay.core.services import (
    CMMCService,
    FedRAMPService,
    NISTService,
    SovereignCloudService,
)


def _make_fedramp_assessment(
    tenant_id: uuid.UUID,
    agency_id: str = "DOD-001",
    authorization_status: str = FedRAMPAuthorizationStatus.READINESS_ASSESSMENT.value,
) -> FedRAMPAssessment:
    assessment = MagicMock(spec=FedRAMPAssessment)
    assessment.id = uuid.uuid4()
    assessment.tenant_id = tenant_id
    assessment.agency_id = agency_id
    assessment.service_name = "TestCSP"
    assessment.impact_level = "moderate"
    assessment.authorization_status = authorization_status
    assessment.readiness_score = 72.5
    assessment.controls_implemented = 236
    assessment.controls_total = 325
    assessment.pmo_contact = None
    assessment.ato_expiry_date = None
    assessment.notes = None
    return assessment


def _make_nist_control(tenant_id: uuid.UUID, control_id: str = "AC-1") -> NISTControl:
    control = MagicMock(spec=NISTControl)
    control.id = uuid.uuid4()
    control.tenant_id = tenant_id
    control.control_id = control_id
    control.control_family = "AC"
    control.control_name = "Access Control Policy and Procedures"
    control.baseline = "moderate"
    control.revision = "rev5"
    control.implementation_status = NISTControlStatus.IMPLEMENTED.value
    control.implementation_narrative = None
    control.responsible_role = None
    control.evidence_references = None
    control.inheritable = False
    control.inherited_from = None
    return control


def _make_cmmc_assessment(tenant_id: uuid.UUID, level: int = 3) -> CMMCAssessment:
    assessment = MagicMock(spec=CMMCAssessment)
    assessment.id = uuid.uuid4()
    assessment.tenant_id = tenant_id
    assessment.target_level = level
    assessment.assessment_status = CMMCAssessmentStatus.SELF_ASSESSMENT.value
    assessment.practices_total = 134
    assessment.practices_met = 100
    assessment.practices_not_met = 34
    assessment.score = 82.09
    assessment.domain_scores = {}
    assessment.c3pao_id = None
    assessment.certification_date = None
    assessment.expiry_date = None
    assessment.notes = None
    return assessment


def _make_sovereign_deployment(tenant_id: uuid.UUID) -> SovereignDeployment:
    deployment = MagicMock(spec=SovereignDeployment)
    deployment.id = uuid.uuid4()
    deployment.tenant_id = tenant_id
    deployment.deployment_name = "govcloud-prod"
    deployment.cloud_provider = "aws-govcloud"
    deployment.region = "us-gov-west-1"
    deployment.deployment_status = SovereignDeploymentStatus.PROVISIONING.value
    deployment.compliance_frameworks = ["FedRAMP-High", "IL4"]
    deployment.is_air_gapped = False
    deployment.endpoint_url = None
    deployment.data_residency_region = None
    deployment.notes = None
    return deployment


class TestFedRAMPService:
    """Tests for FedRAMPService."""

    @pytest.mark.asyncio()
    async def test_assess_readiness_creates_assessment(
        self,
        tenant_context: TenantContext,
        mock_event_publisher: GovDefEventPublisher,
    ) -> None:
        """assess_readiness should create an assessment and publish an event."""
        repo = MagicMock()
        tenant_id = tenant_context.tenant_id

        initial_assessment = _make_fedramp_assessment(tenant_id)
        updated_assessment = _make_fedramp_assessment(tenant_id)

        repo.create = AsyncMock(return_value=initial_assessment)
        repo.update = AsyncMock(return_value=updated_assessment)

        service = FedRAMPService(repo, mock_event_publisher)
        result = await service.assess_readiness(
            agency_id="DOD-001",
            service_name="TestCSP",
            impact_level="moderate",
            current_controls_implemented=236,
            tenant=tenant_context,
        )

        assert result is not None
        repo.create.assert_called_once()
        repo.update.assert_called_once()
        mock_event_publisher.publish_fedramp_assessed.assert_called_once()

    @pytest.mark.asyncio()
    async def test_assess_readiness_normalizes_invalid_impact_level(
        self,
        tenant_context: TenantContext,
        mock_event_publisher: GovDefEventPublisher,
    ) -> None:
        """assess_readiness should default to 'moderate' for invalid impact levels."""
        repo = MagicMock()
        initial = _make_fedramp_assessment(tenant_context.tenant_id)
        updated = _make_fedramp_assessment(tenant_context.tenant_id)
        repo.create = AsyncMock(return_value=initial)
        repo.update = AsyncMock(return_value=updated)

        service = FedRAMPService(repo, mock_event_publisher)
        await service.assess_readiness(
            agency_id="DOD-001",
            service_name="TestCSP",
            impact_level="ultra-classified",  # invalid
            current_controls_implemented=100,
            tenant=tenant_context,
        )

        # Should normalize to moderate (325 controls_total)
        call_kwargs = repo.update.call_args[0][1]
        assert call_kwargs["controls_total"] == 325

    @pytest.mark.asyncio()
    async def test_get_authorization_status_raises_not_found(
        self,
        tenant_context: TenantContext,
        mock_event_publisher: GovDefEventPublisher,
    ) -> None:
        """get_authorization_status should raise NotFoundError when no assessment exists."""
        repo = MagicMock()
        repo.get_latest_by_agency = AsyncMock(return_value=None)

        service = FedRAMPService(repo, mock_event_publisher)
        with pytest.raises(NotFoundError):
            await service.get_authorization_status("UNKNOWN-AGENCY", tenant_context)

    @pytest.mark.asyncio()
    async def test_get_authorization_status_returns_latest(
        self,
        tenant_context: TenantContext,
        mock_event_publisher: GovDefEventPublisher,
    ) -> None:
        """get_authorization_status should return the latest assessment."""
        repo = MagicMock()
        assessment = _make_fedramp_assessment(tenant_context.tenant_id)
        repo.get_latest_by_agency = AsyncMock(return_value=assessment)

        service = FedRAMPService(repo, mock_event_publisher)
        result = await service.get_authorization_status("DOD-001", tenant_context)

        assert result.agency_id == "DOD-001"


class TestNISTService:
    """Tests for NISTService."""

    @pytest.mark.asyncio()
    async def test_map_controls_bulk_upserts(
        self,
        tenant_context: TenantContext,
        mock_event_publisher: GovDefEventPublisher,
    ) -> None:
        """map_controls should call bulk_upsert and publish an event."""
        repo = MagicMock()
        controls = [_make_nist_control(tenant_context.tenant_id)]
        repo.bulk_upsert = AsyncMock(return_value=controls)

        service = NISTService(repo, mock_event_publisher)
        result = await service.map_controls(
            controls=[{"control_id": "AC-1", "control_family": "AC", "control_name": "AC Policy"}],
            baseline="moderate",
            revision="rev5",
            tenant=tenant_context,
        )

        assert len(result) == 1
        repo.bulk_upsert.assert_called_once()
        mock_event_publisher.publish_nist_controls_mapped.assert_called_once()

    @pytest.mark.asyncio()
    async def test_update_control_status_raises_not_found(
        self,
        tenant_context: TenantContext,
        mock_event_publisher: GovDefEventPublisher,
    ) -> None:
        """update_control_status should raise NotFoundError when record not found."""
        repo = MagicMock()
        repo.update = AsyncMock(return_value=None)

        service = NISTService(repo, mock_event_publisher)
        with pytest.raises(NotFoundError):
            await service.update_control_status(
                record_id=uuid.uuid4(),
                implementation_status="implemented",
                implementation_narrative=None,
                evidence_references=None,
                tenant=tenant_context,
            )


class TestCMMCService:
    """Tests for CMMCService."""

    @pytest.mark.asyncio()
    async def test_assess_calculates_score(
        self,
        tenant_context: TenantContext,
        mock_event_publisher: GovDefEventPublisher,
    ) -> None:
        """assess should calculate CMMC score and total practices for level 3."""
        repo = MagicMock()
        initial = _make_cmmc_assessment(tenant_context.tenant_id)
        updated = _make_cmmc_assessment(tenant_context.tenant_id)
        repo.create = AsyncMock(return_value=initial)
        repo.update = AsyncMock(return_value=updated)

        service = CMMCService(repo, mock_event_publisher)
        result = await service.assess(
            target_level=3,
            practices_met=100,
            domain_scores=None,
            c3pao_id=None,
            tenant=tenant_context,
        )

        assert result is not None
        call_kwargs = repo.update.call_args[0][1]
        assert call_kwargs["practices_total"] == 134
        assert call_kwargs["practices_not_met"] == 34
        mock_event_publisher.publish_cmmc_assessed.assert_called_once()

    @pytest.mark.asyncio()
    async def test_assess_sets_c3pao_status_when_provided(
        self,
        tenant_context: TenantContext,
        mock_event_publisher: GovDefEventPublisher,
    ) -> None:
        """assess should set C3PAO assessment status when c3pao_id is provided."""
        repo = MagicMock()
        initial = _make_cmmc_assessment(tenant_context.tenant_id)
        updated = _make_cmmc_assessment(tenant_context.tenant_id)
        repo.create = AsyncMock(return_value=initial)
        repo.update = AsyncMock(return_value=updated)

        service = CMMCService(repo, mock_event_publisher)
        await service.assess(
            target_level=2,
            practices_met=90,
            domain_scores=None,
            c3pao_id="C3PAO-XYZ-123",
            tenant=tenant_context,
        )

        call_kwargs = repo.update.call_args[0][1]
        assert call_kwargs["assessment_status"] == CMMCAssessmentStatus.C3PAO_ASSESSMENT.value
        assert call_kwargs["c3pao_id"] == "C3PAO-XYZ-123"

    @pytest.mark.asyncio()
    async def test_get_level_status_raises_not_found(
        self,
        tenant_context: TenantContext,
        mock_event_publisher: GovDefEventPublisher,
    ) -> None:
        """get_level_status should raise NotFoundError when no assessment at level."""
        repo = MagicMock()
        repo.get_latest_by_level = AsyncMock(return_value=None)

        service = CMMCService(repo, mock_event_publisher)
        with pytest.raises(NotFoundError):
            await service.get_level_status(3, tenant_context)


class TestSovereignCloudService:
    """Tests for SovereignCloudService."""

    @pytest.mark.asyncio()
    async def test_deploy_creates_provisioning_record(
        self,
        tenant_context: TenantContext,
        mock_event_publisher: GovDefEventPublisher,
    ) -> None:
        """deploy should create a deployment and publish an event."""
        repo = MagicMock()
        deployment = _make_sovereign_deployment(tenant_context.tenant_id)
        repo.create = AsyncMock(return_value=deployment)
        repo.update = AsyncMock(return_value=deployment)

        service = SovereignCloudService(repo, mock_event_publisher)
        result = await service.deploy(
            deployment_name="govcloud-prod",
            cloud_provider="aws-govcloud",
            region="us-gov-west-1",
            compliance_frameworks=["FedRAMP-High", "IL4"],
            encryption_config=None,
            network_isolation_config=None,
            is_air_gapped=False,
            tenant=tenant_context,
        )

        assert result is not None
        call_kwargs = repo.update.call_args[0][1]
        assert call_kwargs["deployment_status"] == SovereignDeploymentStatus.PROVISIONING.value
        mock_event_publisher.publish_sovereign_deployment_initiated.assert_called_once()

    @pytest.mark.asyncio()
    async def test_get_il_level_status_filters_by_framework(
        self,
        tenant_context: TenantContext,
        mock_event_publisher: GovDefEventPublisher,
    ) -> None:
        """get_il_level_status should filter deployments by IL compliance framework."""
        repo = MagicMock()
        il4_deployment = _make_sovereign_deployment(tenant_context.tenant_id)
        il4_deployment.compliance_frameworks = ["FedRAMP-High", "IL4"]
        il5_deployment = _make_sovereign_deployment(tenant_context.tenant_id)
        il5_deployment.compliance_frameworks = ["FedRAMP-High", "IL5"]
        no_il_deployment = _make_sovereign_deployment(tenant_context.tenant_id)
        no_il_deployment.compliance_frameworks = ["FedRAMP-Moderate"]

        repo.list_all = AsyncMock(return_value=[il4_deployment, il5_deployment, no_il_deployment])

        service = SovereignCloudService(repo, mock_event_publisher)
        result = await service.get_il_level_status(4, tenant_context)

        assert len(result) == 1
        assert result[0].compliance_frameworks is not None
        assert "IL4" in result[0].compliance_frameworks

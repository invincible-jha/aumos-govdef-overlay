"""API router for aumos-govdef-overlay.

All endpoints are registered here and included in main.py under /api/v1.
Routes delegate all logic to service layer — no business logic in routes.

Endpoints:
  POST   /govdef/fedramp/assess           — FedRAMP readiness assessment
  GET    /govdef/fedramp/status           — Authorization status by agency
  POST   /govdef/nist/map                 — NIST 800-53 control mapping
  GET    /govdef/nist/controls            — Control status summary
  POST   /govdef/cmmc/assess              — CMMC assessment
  GET    /govdef/cmmc/level/{level}       — Level compliance status
  POST   /govdef/sovereign/deploy         — Sovereign cloud deployment
  GET    /govdef/il-level/{level}/status  — IL4/IL5 status
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_common.auth import TenantContext, get_current_user
from aumos_common.database import get_db_session
from aumos_common.events import EventPublisher, get_event_publisher

from aumos_govdef_overlay.adapters.kafka import GovDefEventPublisher
from aumos_govdef_overlay.adapters.repositories import (
    CMMCRepository,
    ClassifiedEnvRepository,
    FedRAMPRepository,
    NISTControlRepository,
    SovereignCloudRepository,
)
from aumos_govdef_overlay.api.schemas import (
    CMMCAssessmentResponse,
    CMMCAssessRequest,
    FedRAMPAssessmentResponse,
    FedRAMPAssessRequest,
    ILLevelStatusResponse,
    NISTControlResponse,
    NISTControlsStatusResponse,
    NISTMapRequest,
    NISTMapResponse,
    SovereignDeploymentResponse,
    SovereignDeployRequest,
)
from aumos_govdef_overlay.core.models import (
    CMMCAssessment,
    ClassifiedEnvironment,
    FedRAMPAssessment,
    NISTControl,
    SovereignDeployment,
)
from aumos_govdef_overlay.core.services import (
    CMMCService,
    ClassifiedEnvService,
    FedRAMPService,
    NISTService,
    SovereignCloudService,
)

router = APIRouter(prefix="/govdef", tags=["govdef"])


# ─── Dependency factories ────────────────────────────────────────────────────

def _make_event_publisher(raw: EventPublisher = Depends(get_event_publisher)) -> GovDefEventPublisher:
    """Create a typed GovDef event publisher.

    Args:
        raw: The underlying EventPublisher from aumos-common.

    Returns:
        Typed GovDefEventPublisher wrapping the raw publisher.
    """
    return GovDefEventPublisher(raw)


def _fedramp_service(
    session: AsyncSession = Depends(get_db_session),
    publisher: GovDefEventPublisher = Depends(_make_event_publisher),
) -> FedRAMPService:
    """Construct FedRAMPService with injected dependencies.

    Args:
        session: Async database session.
        publisher: Typed event publisher.

    Returns:
        Configured FedRAMPService instance.
    """
    return FedRAMPService(FedRAMPRepository(session), publisher)


def _nist_service(
    session: AsyncSession = Depends(get_db_session),
    publisher: GovDefEventPublisher = Depends(_make_event_publisher),
) -> NISTService:
    """Construct NISTService with injected dependencies.

    Args:
        session: Async database session.
        publisher: Typed event publisher.

    Returns:
        Configured NISTService instance.
    """
    return NISTService(NISTControlRepository(session), publisher)


def _cmmc_service(
    session: AsyncSession = Depends(get_db_session),
    publisher: GovDefEventPublisher = Depends(_make_event_publisher),
) -> CMMCService:
    """Construct CMMCService with injected dependencies.

    Args:
        session: Async database session.
        publisher: Typed event publisher.

    Returns:
        Configured CMMCService instance.
    """
    return CMMCService(CMMCRepository(session), publisher)


def _sovereign_service(
    session: AsyncSession = Depends(get_db_session),
    publisher: GovDefEventPublisher = Depends(_make_event_publisher),
) -> SovereignCloudService:
    """Construct SovereignCloudService with injected dependencies.

    Args:
        session: Async database session.
        publisher: Typed event publisher.

    Returns:
        Configured SovereignCloudService instance.
    """
    return SovereignCloudService(SovereignCloudRepository(session), publisher)


def _classified_env_service(
    session: AsyncSession = Depends(get_db_session),
    publisher: GovDefEventPublisher = Depends(_make_event_publisher),
) -> ClassifiedEnvService:
    """Construct ClassifiedEnvService with injected dependencies.

    Args:
        session: Async database session.
        publisher: Typed event publisher.

    Returns:
        Configured ClassifiedEnvService instance.
    """
    return ClassifiedEnvService(ClassifiedEnvRepository(session), publisher)


# ─── Helper converters ────────────────────────────────────────────────────────

def _fedramp_to_response(assessment: FedRAMPAssessment) -> FedRAMPAssessmentResponse:
    return FedRAMPAssessmentResponse(
        id=assessment.id,
        tenant_id=assessment.tenant_id,
        agency_id=assessment.agency_id,
        service_name=assessment.service_name,
        impact_level=assessment.impact_level,
        authorization_status=assessment.authorization_status,
        readiness_score=assessment.readiness_score,
        controls_implemented=assessment.controls_implemented,
        controls_total=assessment.controls_total,
        pmo_contact=assessment.pmo_contact,
        ato_expiry_date=assessment.ato_expiry_date,
        notes=assessment.notes,
        created_at=assessment.created_at,
        updated_at=assessment.updated_at,
    )


def _nist_to_response(control: NISTControl) -> NISTControlResponse:
    return NISTControlResponse(
        id=control.id,
        tenant_id=control.tenant_id,
        control_id=control.control_id,
        control_family=control.control_family,
        control_name=control.control_name,
        baseline=control.baseline,
        revision=control.revision,
        implementation_status=control.implementation_status,
        implementation_narrative=control.implementation_narrative,
        responsible_role=control.responsible_role,
        evidence_references=control.evidence_references,
        inheritable=control.inheritable,
        inherited_from=control.inherited_from,
        created_at=control.created_at,
        updated_at=control.updated_at,
    )


def _cmmc_to_response(assessment: CMMCAssessment) -> CMMCAssessmentResponse:
    return CMMCAssessmentResponse(
        id=assessment.id,
        tenant_id=assessment.tenant_id,
        target_level=assessment.target_level,
        assessment_status=assessment.assessment_status,
        practices_total=assessment.practices_total,
        practices_met=assessment.practices_met,
        practices_not_met=assessment.practices_not_met,
        score=assessment.score,
        domain_scores=assessment.domain_scores,
        c3pao_id=assessment.c3pao_id,
        certification_date=assessment.certification_date,
        expiry_date=assessment.expiry_date,
        notes=assessment.notes,
        created_at=assessment.created_at,
        updated_at=assessment.updated_at,
    )


def _sovereign_to_response(deployment: SovereignDeployment) -> SovereignDeploymentResponse:
    return SovereignDeploymentResponse(
        id=deployment.id,
        tenant_id=deployment.tenant_id,
        deployment_name=deployment.deployment_name,
        cloud_provider=deployment.cloud_provider,
        region=deployment.region,
        deployment_status=deployment.deployment_status,
        compliance_frameworks=deployment.compliance_frameworks,
        is_air_gapped=deployment.is_air_gapped,
        endpoint_url=deployment.endpoint_url,
        data_residency_region=deployment.data_residency_region,
        notes=deployment.notes,
        created_at=deployment.created_at,
        updated_at=deployment.updated_at,
    )


# ─── FedRAMP Endpoints ────────────────────────────────────────────────────────

@router.post("/fedramp/assess", response_model=FedRAMPAssessmentResponse, status_code=201)
async def fedramp_assess(
    request: FedRAMPAssessRequest,
    tenant: TenantContext = Depends(get_current_user),
    service: FedRAMPService = Depends(_fedramp_service),
) -> FedRAMPAssessmentResponse:
    """Perform a FedRAMP readiness assessment.

    Args:
        request: FedRAMP assessment request parameters.
        tenant: Current tenant context from auth middleware.
        service: Injected FedRAMPService.

    Returns:
        Created FedRAMP assessment with readiness score.
    """
    assessment = await service.assess_readiness(
        agency_id=request.agency_id,
        service_name=request.service_name,
        impact_level=request.impact_level,
        current_controls_implemented=request.controls_implemented,
        tenant=tenant,
    )
    return _fedramp_to_response(assessment)


@router.get("/fedramp/status", response_model=FedRAMPAssessmentResponse)
async def fedramp_status(
    agency_id: str,
    tenant: TenantContext = Depends(get_current_user),
    service: FedRAMPService = Depends(_fedramp_service),
) -> FedRAMPAssessmentResponse:
    """Retrieve the latest FedRAMP authorization status for an agency.

    Args:
        agency_id: Federal agency identifier to query.
        tenant: Current tenant context from auth middleware.
        service: Injected FedRAMPService.

    Returns:
        Latest FedRAMP assessment record for the agency.
    """
    assessment = await service.get_authorization_status(agency_id, tenant)
    return _fedramp_to_response(assessment)


# ─── NIST 800-53 Endpoints ────────────────────────────────────────────────────

@router.post("/nist/map", response_model=NISTMapResponse, status_code=201)
async def nist_map(
    request: NISTMapRequest,
    tenant: TenantContext = Depends(get_current_user),
    service: NISTService = Depends(_nist_service),
) -> NISTMapResponse:
    """Bulk map NIST 800-53 control implementation status.

    Args:
        request: NIST control mapping request with controls list.
        tenant: Current tenant context from auth middleware.
        service: Injected NISTService.

    Returns:
        Mapping result with all created/updated control records.
    """
    controls_data = [control.model_dump() for control in request.controls]
    mapped_controls = await service.map_controls(
        controls=controls_data,
        baseline=request.baseline,
        revision=request.revision,
        tenant=tenant,
    )
    return NISTMapResponse(
        controls_mapped=len(mapped_controls),
        baseline=request.baseline,
        revision=request.revision,
        controls=[_nist_to_response(c) for c in mapped_controls],
    )


@router.get("/nist/controls", response_model=NISTControlsStatusResponse)
async def nist_controls_status(
    tenant: TenantContext = Depends(get_current_user),
    service: NISTService = Depends(_nist_service),
) -> NISTControlsStatusResponse:
    """Get NIST 800-53 control implementation status summary.

    Args:
        tenant: Current tenant context from auth middleware.
        service: Injected NISTService.

    Returns:
        Summary of all NIST control implementation statuses.
    """
    summary = await service.get_controls_status(tenant)
    all_controls = await service._repository.list_all(tenant)  # noqa: SLF001
    return NISTControlsStatusResponse(
        total=summary["total"],
        completion_percentage=summary["completion_percentage"],
        by_status=summary["by_status"],
        controls=[_nist_to_response(c) for c in all_controls],
    )


# ─── CMMC Endpoints ───────────────────────────────────────────────────────────

@router.post("/cmmc/assess", response_model=CMMCAssessmentResponse, status_code=201)
async def cmmc_assess(
    request: CMMCAssessRequest,
    tenant: TenantContext = Depends(get_current_user),
    service: CMMCService = Depends(_cmmc_service),
) -> CMMCAssessmentResponse:
    """Perform a CMMC compliance assessment.

    Args:
        request: CMMC assessment request with target level and practices data.
        tenant: Current tenant context from auth middleware.
        service: Injected CMMCService.

    Returns:
        Created CMMC assessment with score and domain breakdown.
    """
    assessment = await service.assess(
        target_level=request.target_level,
        practices_met=request.practices_met,
        domain_scores=request.domain_scores,
        c3pao_id=request.c3pao_id,
        tenant=tenant,
    )
    return _cmmc_to_response(assessment)


@router.get("/cmmc/level/{level}", response_model=CMMCAssessmentResponse)
async def cmmc_level_status(
    level: int,
    tenant: TenantContext = Depends(get_current_user),
    service: CMMCService = Depends(_cmmc_service),
) -> CMMCAssessmentResponse:
    """Get the latest CMMC compliance status for a given level.

    Args:
        level: CMMC certification level to query (1, 2, or 3).
        tenant: Current tenant context from auth middleware.
        service: Injected CMMCService.

    Returns:
        Latest CMMC assessment for the specified level.
    """
    assessment = await service.get_level_status(level, tenant)
    return _cmmc_to_response(assessment)


# ─── Sovereign Cloud Endpoints ────────────────────────────────────────────────

@router.post("/sovereign/deploy", response_model=SovereignDeploymentResponse, status_code=201)
async def sovereign_deploy(
    request: SovereignDeployRequest,
    tenant: TenantContext = Depends(get_current_user),
    service: SovereignCloudService = Depends(_sovereign_service),
) -> SovereignDeploymentResponse:
    """Initiate a sovereign cloud deployment.

    Args:
        request: Sovereign deployment configuration request.
        tenant: Current tenant context from auth middleware.
        service: Injected SovereignCloudService.

    Returns:
        Created deployment record with PROVISIONING status.
    """
    deployment = await service.deploy(
        deployment_name=request.deployment_name,
        cloud_provider=request.cloud_provider,
        region=request.region,
        compliance_frameworks=request.compliance_frameworks,
        encryption_config=request.encryption_config,
        network_isolation_config=request.network_isolation_config,
        is_air_gapped=request.is_air_gapped,
        tenant=tenant,
    )
    return _sovereign_to_response(deployment)


@router.get("/il-level/{level}/status", response_model=ILLevelStatusResponse)
async def il_level_status(
    level: int,
    tenant: TenantContext = Depends(get_current_user),
    sovereign_service: SovereignCloudService = Depends(_sovereign_service),
    classified_service: ClassifiedEnvService = Depends(_classified_env_service),
) -> ILLevelStatusResponse:
    """Get compliance status for a DoD Impact Level.

    Returns both sovereign cloud deployments and classified environments
    operating at the specified Impact Level.

    Args:
        level: DoD Impact Level to query (4 or 5).
        tenant: Current tenant context from auth middleware.
        sovereign_service: Injected SovereignCloudService.
        classified_service: Injected ClassifiedEnvService.

    Returns:
        Combined IL-level status across deployments and environments.
    """
    deployments = await sovereign_service.get_il_level_status(level, tenant)
    environments = await classified_service.get_il_level_status(level, tenant)

    return ILLevelStatusResponse(
        il_level=level,
        deployments_count=len(deployments),
        deployments=[_sovereign_to_response(d) for d in deployments],
        environments_count=len(environments),
    )

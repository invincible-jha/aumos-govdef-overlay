"""SQLAlchemy repository implementations for aumos-govdef-overlay.

Repositories extend BaseRepository from aumos-common which provides:
  - Automatic RLS tenant isolation (set_tenant_context)
  - Standard CRUD operations (get, list, create, update, delete)
  - Pagination support via paginate()
  - Soft delete support

Implement only the methods that differ from BaseRepository defaults.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_common.auth import TenantContext
from aumos_common.database import BaseRepository

from aumos_govdef_overlay.core.interfaces import (
    ICMMCRepository,
    IClassifiedEnvRepository,
    IFedRAMPRepository,
    INISTControlRepository,
    ISovereignCloudRepository,
)
from aumos_govdef_overlay.core.models import (
    CMMCAssessment,
    ClassifiedEnvironment,
    FedRAMPAssessment,
    NISTControl,
    SovereignDeployment,
)


class FedRAMPRepository(BaseRepository, IFedRAMPRepository):
    """Repository for FedRAMPAssessment records.

    Args:
        session: The async SQLAlchemy session (injected by FastAPI dependency).
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize repository with database session.

        Args:
            session: Async SQLAlchemy session.
        """
        super().__init__(session)

    async def get_by_id(
        self, assessment_id: uuid.UUID, tenant: TenantContext
    ) -> FedRAMPAssessment | None:
        """Get a FedRAMP assessment by ID within the tenant scope.

        Args:
            assessment_id: UUID of the assessment record.
            tenant: Tenant context for RLS isolation.

        Returns:
            The FedRAMPAssessment record or None if not found.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(FedRAMPAssessment).where(FedRAMPAssessment.id == assessment_id)
        )
        return result.scalar_one_or_none()

    async def list_all(self, tenant: TenantContext) -> list[FedRAMPAssessment]:
        """List all FedRAMP assessments for the tenant.

        Args:
            tenant: Tenant context for RLS isolation.

        Returns:
            List of FedRAMPAssessment records.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(FedRAMPAssessment).order_by(FedRAMPAssessment.created_at.desc())
        )
        return list(result.scalars().all())

    async def create(
        self,
        agency_id: str,
        service_name: str,
        impact_level: str,
        tenant: TenantContext,
    ) -> FedRAMPAssessment:
        """Create a new FedRAMP assessment record.

        Args:
            agency_id: Federal agency identifier.
            service_name: Cloud service offering name.
            impact_level: FedRAMP impact level (low/moderate/high).
            tenant: Tenant context for RLS isolation.

        Returns:
            Newly created FedRAMPAssessment record.
        """
        await self.set_tenant_context(tenant)
        assessment = FedRAMPAssessment(
            tenant_id=tenant.tenant_id,
            agency_id=agency_id,
            service_name=service_name,
            impact_level=impact_level,
        )
        self.session.add(assessment)
        await self.session.flush()
        await self.session.refresh(assessment)
        return assessment

    async def update(
        self,
        assessment_id: uuid.UUID,
        updates: dict,
        tenant: TenantContext,
    ) -> FedRAMPAssessment | None:
        """Update a FedRAMP assessment record.

        Args:
            assessment_id: UUID of the assessment to update.
            updates: Dictionary of field updates to apply.
            tenant: Tenant context for RLS isolation.

        Returns:
            Updated FedRAMPAssessment or None if not found.
        """
        await self.set_tenant_context(tenant)
        assessment = await self.get_by_id(assessment_id, tenant)
        if assessment is None:
            return None
        for field, value in updates.items():
            setattr(assessment, field, value)
        await self.session.flush()
        await self.session.refresh(assessment)
        return assessment

    async def get_latest_by_agency(
        self, agency_id: str, tenant: TenantContext
    ) -> FedRAMPAssessment | None:
        """Get the most recent FedRAMP assessment for a given agency.

        Args:
            agency_id: Federal agency identifier.
            tenant: Tenant context for RLS isolation.

        Returns:
            Most recent FedRAMPAssessment or None if not found.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(FedRAMPAssessment)
            .where(FedRAMPAssessment.agency_id == agency_id)
            .order_by(FedRAMPAssessment.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()


class NISTControlRepository(BaseRepository, INISTControlRepository):
    """Repository for NISTControl records.

    Args:
        session: The async SQLAlchemy session (injected by FastAPI dependency).
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize repository with database session.

        Args:
            session: Async SQLAlchemy session.
        """
        super().__init__(session)

    async def get_by_id(
        self, control_id: uuid.UUID, tenant: TenantContext
    ) -> NISTControl | None:
        """Get a NIST control record by UUID.

        Args:
            control_id: UUID of the NISTControl record.
            tenant: Tenant context for RLS isolation.

        Returns:
            The NISTControl record or None if not found.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(NISTControl).where(NISTControl.id == control_id)
        )
        return result.scalar_one_or_none()

    async def list_all(self, tenant: TenantContext) -> list[NISTControl]:
        """List all NIST controls for the tenant.

        Args:
            tenant: Tenant context for RLS isolation.

        Returns:
            List of all NISTControl records.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(NISTControl).order_by(NISTControl.control_family, NISTControl.control_id)
        )
        return list(result.scalars().all())

    async def list_by_family(
        self, control_family: str, tenant: TenantContext
    ) -> list[NISTControl]:
        """List NIST controls filtered by control family.

        Args:
            control_family: Control family code (e.g., "AC", "AU", "IA").
            tenant: Tenant context for RLS isolation.

        Returns:
            List of NISTControl records in the specified family.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(NISTControl)
            .where(NISTControl.control_family == control_family)
            .order_by(NISTControl.control_id)
        )
        return list(result.scalars().all())

    async def list_by_status(
        self, status: str, tenant: TenantContext
    ) -> list[NISTControl]:
        """List NIST controls filtered by implementation status.

        Args:
            status: Implementation status to filter by.
            tenant: Tenant context for RLS isolation.

        Returns:
            List of NISTControl records with the specified status.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(NISTControl)
            .where(NISTControl.implementation_status == status)
            .order_by(NISTControl.control_family, NISTControl.control_id)
        )
        return list(result.scalars().all())

    async def create(
        self,
        control_id: str,
        control_family: str,
        control_name: str,
        baseline: str,
        tenant: TenantContext,
    ) -> NISTControl:
        """Create a new NIST control mapping record.

        Args:
            control_id: NIST control identifier (e.g., "AC-1").
            control_family: Control family code (e.g., "AC").
            control_name: Human-readable control name.
            baseline: NIST baseline (low/moderate/high).
            tenant: Tenant context for RLS isolation.

        Returns:
            Newly created NISTControl record.
        """
        await self.set_tenant_context(tenant)
        control = NISTControl(
            tenant_id=tenant.tenant_id,
            control_id=control_id,
            control_family=control_family,
            control_name=control_name,
            baseline=baseline,
        )
        self.session.add(control)
        await self.session.flush()
        await self.session.refresh(control)
        return control

    async def bulk_upsert(
        self,
        controls: list[dict],
        tenant: TenantContext,
    ) -> list[NISTControl]:
        """Bulk create or update NIST control mapping records.

        Args:
            controls: List of control dictionaries with control data.
            tenant: Tenant context for RLS isolation.

        Returns:
            List of created/updated NISTControl records.
        """
        await self.set_tenant_context(tenant)
        result_controls: list[NISTControl] = []
        for control_data in controls:
            # Check if control already exists by control_id + tenant_id
            existing_result = await self.session.execute(
                select(NISTControl).where(
                    NISTControl.control_id == control_data.get("control_id", ""),
                    NISTControl.tenant_id == tenant.tenant_id,
                )
            )
            existing = existing_result.scalar_one_or_none()

            if existing:
                for field, value in control_data.items():
                    if hasattr(existing, field):
                        setattr(existing, field, value)
                await self.session.flush()
                await self.session.refresh(existing)
                result_controls.append(existing)
            else:
                control = NISTControl(
                    tenant_id=tenant.tenant_id,
                    **{k: v for k, v in control_data.items() if hasattr(NISTControl, k)},
                )
                self.session.add(control)
                await self.session.flush()
                await self.session.refresh(control)
                result_controls.append(control)

        return result_controls

    async def update(
        self,
        record_id: uuid.UUID,
        updates: dict,
        tenant: TenantContext,
    ) -> NISTControl | None:
        """Update a NIST control record.

        Args:
            record_id: UUID of the NISTControl record.
            updates: Dictionary of field updates to apply.
            tenant: Tenant context for RLS isolation.

        Returns:
            Updated NISTControl or None if not found.
        """
        await self.set_tenant_context(tenant)
        control = await self.get_by_id(record_id, tenant)
        if control is None:
            return None
        for field, value in updates.items():
            setattr(control, field, value)
        await self.session.flush()
        await self.session.refresh(control)
        return control

    async def get_completion_summary(
        self, tenant: TenantContext
    ) -> dict:
        """Get a summary of NIST control implementation completion.

        Args:
            tenant: Tenant context for RLS isolation.

        Returns:
            Dictionary with status counts and completion percentages.
        """
        await self.set_tenant_context(tenant)
        all_controls = await self.list_all(tenant)
        total = len(all_controls)
        if total == 0:
            return {"total": 0, "by_status": {}, "completion_percentage": 0.0}

        status_counts: dict[str, int] = {}
        for control in all_controls:
            status = control.implementation_status
            status_counts[status] = status_counts.get(status, 0) + 1

        implemented = status_counts.get("implemented", 0)
        not_applicable = status_counts.get("not_applicable", 0)
        effective_total = total - not_applicable
        completion_pct = (
            round((implemented / effective_total) * 100, 2)
            if effective_total > 0
            else 0.0
        )

        return {
            "total": total,
            "by_status": status_counts,
            "completion_percentage": completion_pct,
        }


class CMMCRepository(BaseRepository, ICMMCRepository):
    """Repository for CMMCAssessment records.

    Args:
        session: The async SQLAlchemy session (injected by FastAPI dependency).
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize repository with database session.

        Args:
            session: Async SQLAlchemy session.
        """
        super().__init__(session)

    async def get_by_id(
        self, assessment_id: uuid.UUID, tenant: TenantContext
    ) -> CMMCAssessment | None:
        """Get a CMMC assessment by ID.

        Args:
            assessment_id: UUID of the CMMCAssessment record.
            tenant: Tenant context for RLS isolation.

        Returns:
            The CMMCAssessment record or None if not found.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(CMMCAssessment).where(CMMCAssessment.id == assessment_id)
        )
        return result.scalar_one_or_none()

    async def list_all(self, tenant: TenantContext) -> list[CMMCAssessment]:
        """List all CMMC assessments for the tenant.

        Args:
            tenant: Tenant context for RLS isolation.

        Returns:
            List of all CMMCAssessment records.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(CMMCAssessment).order_by(CMMCAssessment.created_at.desc())
        )
        return list(result.scalars().all())

    async def list_by_level(
        self, level: int, tenant: TenantContext
    ) -> list[CMMCAssessment]:
        """List CMMC assessments filtered by target level.

        Args:
            level: CMMC target level (1, 2, or 3).
            tenant: Tenant context for RLS isolation.

        Returns:
            List of CMMCAssessment records for the specified level.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(CMMCAssessment)
            .where(CMMCAssessment.target_level == level)
            .order_by(CMMCAssessment.created_at.desc())
        )
        return list(result.scalars().all())

    async def create(
        self,
        target_level: int,
        tenant: TenantContext,
    ) -> CMMCAssessment:
        """Create a new CMMC assessment record.

        Args:
            target_level: CMMC certification target level (1, 2, or 3).
            tenant: Tenant context for RLS isolation.

        Returns:
            Newly created CMMCAssessment record.
        """
        await self.set_tenant_context(tenant)
        assessment = CMMCAssessment(
            tenant_id=tenant.tenant_id,
            target_level=target_level,
        )
        self.session.add(assessment)
        await self.session.flush()
        await self.session.refresh(assessment)
        return assessment

    async def update(
        self,
        assessment_id: uuid.UUID,
        updates: dict,
        tenant: TenantContext,
    ) -> CMMCAssessment | None:
        """Update a CMMC assessment record.

        Args:
            assessment_id: UUID of the assessment to update.
            updates: Dictionary of field updates.
            tenant: Tenant context for RLS isolation.

        Returns:
            Updated CMMCAssessment or None if not found.
        """
        await self.set_tenant_context(tenant)
        assessment = await self.get_by_id(assessment_id, tenant)
        if assessment is None:
            return None
        for field, value in updates.items():
            setattr(assessment, field, value)
        await self.session.flush()
        await self.session.refresh(assessment)
        return assessment

    async def get_latest_by_level(
        self, level: int, tenant: TenantContext
    ) -> CMMCAssessment | None:
        """Get the most recent CMMC assessment for a given level.

        Args:
            level: CMMC level to query.
            tenant: Tenant context for RLS isolation.

        Returns:
            Most recent CMMCAssessment for the level or None.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(CMMCAssessment)
            .where(CMMCAssessment.target_level == level)
            .order_by(CMMCAssessment.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()


class SovereignCloudRepository(BaseRepository, ISovereignCloudRepository):
    """Repository for SovereignDeployment records.

    Args:
        session: The async SQLAlchemy session (injected by FastAPI dependency).
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize repository with database session.

        Args:
            session: Async SQLAlchemy session.
        """
        super().__init__(session)

    async def get_by_id(
        self, deployment_id: uuid.UUID, tenant: TenantContext
    ) -> SovereignDeployment | None:
        """Get a sovereign deployment by ID.

        Args:
            deployment_id: UUID of the SovereignDeployment record.
            tenant: Tenant context for RLS isolation.

        Returns:
            The SovereignDeployment record or None if not found.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(SovereignDeployment).where(SovereignDeployment.id == deployment_id)
        )
        return result.scalar_one_or_none()

    async def list_all(self, tenant: TenantContext) -> list[SovereignDeployment]:
        """List all sovereign deployments for the tenant.

        Args:
            tenant: Tenant context for RLS isolation.

        Returns:
            List of all SovereignDeployment records.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(SovereignDeployment).order_by(SovereignDeployment.created_at.desc())
        )
        return list(result.scalars().all())

    async def list_by_provider(
        self, provider: str, tenant: TenantContext
    ) -> list[SovereignDeployment]:
        """List sovereign deployments filtered by cloud provider.

        Args:
            provider: Cloud provider identifier (e.g., "aws-govcloud").
            tenant: Tenant context for RLS isolation.

        Returns:
            List of SovereignDeployment records for the provider.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(SovereignDeployment)
            .where(SovereignDeployment.cloud_provider == provider)
            .order_by(SovereignDeployment.created_at.desc())
        )
        return list(result.scalars().all())

    async def create(
        self,
        deployment_name: str,
        cloud_provider: str,
        region: str,
        tenant: TenantContext,
    ) -> SovereignDeployment:
        """Create a new sovereign cloud deployment record.

        Args:
            deployment_name: Human-readable deployment name.
            cloud_provider: Target sovereign cloud provider.
            region: Deployment region identifier.
            tenant: Tenant context for RLS isolation.

        Returns:
            Newly created SovereignDeployment record.
        """
        await self.set_tenant_context(tenant)
        deployment = SovereignDeployment(
            tenant_id=tenant.tenant_id,
            deployment_name=deployment_name,
            cloud_provider=cloud_provider,
            region=region,
        )
        self.session.add(deployment)
        await self.session.flush()
        await self.session.refresh(deployment)
        return deployment

    async def update(
        self,
        deployment_id: uuid.UUID,
        updates: dict,
        tenant: TenantContext,
    ) -> SovereignDeployment | None:
        """Update a sovereign deployment record.

        Args:
            deployment_id: UUID of the deployment to update.
            updates: Dictionary of field updates.
            tenant: Tenant context for RLS isolation.

        Returns:
            Updated SovereignDeployment or None if not found.
        """
        await self.set_tenant_context(tenant)
        deployment = await self.get_by_id(deployment_id, tenant)
        if deployment is None:
            return None
        for field, value in updates.items():
            setattr(deployment, field, value)
        await self.session.flush()
        await self.session.refresh(deployment)
        return deployment


class ClassifiedEnvRepository(BaseRepository, IClassifiedEnvRepository):
    """Repository for ClassifiedEnvironment records.

    Args:
        session: The async SQLAlchemy session (injected by FastAPI dependency).
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize repository with database session.

        Args:
            session: Async SQLAlchemy session.
        """
        super().__init__(session)

    async def get_by_id(
        self, env_id: uuid.UUID, tenant: TenantContext
    ) -> ClassifiedEnvironment | None:
        """Get a classified environment by ID.

        Args:
            env_id: UUID of the ClassifiedEnvironment record.
            tenant: Tenant context for RLS isolation.

        Returns:
            The ClassifiedEnvironment record or None if not found.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(ClassifiedEnvironment).where(ClassifiedEnvironment.id == env_id)
        )
        return result.scalar_one_or_none()

    async def list_all(self, tenant: TenantContext) -> list[ClassifiedEnvironment]:
        """List all classified environments for the tenant.

        Args:
            tenant: Tenant context for RLS isolation.

        Returns:
            List of all ClassifiedEnvironment records.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(ClassifiedEnvironment).order_by(ClassifiedEnvironment.created_at.desc())
        )
        return list(result.scalars().all())

    async def list_by_il_level(
        self, il_level: int, tenant: TenantContext
    ) -> list[ClassifiedEnvironment]:
        """List classified environments at a specific Impact Level.

        Args:
            il_level: DoD Impact Level to filter by (4 or 5).
            tenant: Tenant context for RLS isolation.

        Returns:
            List of ClassifiedEnvironment records at the specified IL.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(ClassifiedEnvironment)
            .where(ClassifiedEnvironment.impact_level == il_level)
            .order_by(ClassifiedEnvironment.created_at.desc())
        )
        return list(result.scalars().all())

    async def create(
        self,
        environment_name: str,
        impact_level: int,
        classification_level: str,
        tenant: TenantContext,
    ) -> ClassifiedEnvironment:
        """Create a new classified environment configuration record.

        Args:
            environment_name: Human-readable environment name.
            impact_level: DoD Impact Level (4 or 5).
            classification_level: Data classification (CUI, SECRET, etc.).
            tenant: Tenant context for RLS isolation.

        Returns:
            Newly created ClassifiedEnvironment record.
        """
        await self.set_tenant_context(tenant)
        env = ClassifiedEnvironment(
            tenant_id=tenant.tenant_id,
            environment_name=environment_name,
            impact_level=impact_level,
            classification_level=classification_level,
        )
        self.session.add(env)
        await self.session.flush()
        await self.session.refresh(env)
        return env

    async def update(
        self,
        env_id: uuid.UUID,
        updates: dict,
        tenant: TenantContext,
    ) -> ClassifiedEnvironment | None:
        """Update a classified environment record.

        Args:
            env_id: UUID of the environment to update.
            updates: Dictionary of field updates.
            tenant: Tenant context for RLS isolation.

        Returns:
            Updated ClassifiedEnvironment or None if not found.
        """
        await self.set_tenant_context(tenant)
        env = await self.get_by_id(env_id, tenant)
        if env is None:
            return None
        for field, value in updates.items():
            setattr(env, field, value)
        await self.session.flush()
        await self.session.refresh(env)
        return env


__all__ = [
    "FedRAMPRepository",
    "NISTControlRepository",
    "CMMCRepository",
    "SovereignCloudRepository",
    "ClassifiedEnvRepository",
]

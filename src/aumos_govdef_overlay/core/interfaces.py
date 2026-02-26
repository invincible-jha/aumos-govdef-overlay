"""Abstract interfaces (Protocol classes) for aumos-govdef-overlay.

Defining interfaces as Protocol classes enables:
  - Dependency injection in services
  - Easy mocking in tests
  - Clear contracts between layers

Services depend on interfaces, not concrete implementations.
"""

import uuid
from typing import Protocol, runtime_checkable

from aumos_common.auth import TenantContext

from aumos_govdef_overlay.core.models import (
    CMMCAssessment,
    ClassifiedEnvironment,
    FedRAMPAssessment,
    NISTControl,
    SovereignDeployment,
)


@runtime_checkable
class IFedRAMPRepository(Protocol):
    """Repository interface for FedRAMPAssessment records."""

    async def get_by_id(
        self, assessment_id: uuid.UUID, tenant: TenantContext
    ) -> FedRAMPAssessment | None: ...

    async def list_all(self, tenant: TenantContext) -> list[FedRAMPAssessment]: ...

    async def create(
        self,
        agency_id: str,
        service_name: str,
        impact_level: str,
        tenant: TenantContext,
    ) -> FedRAMPAssessment: ...

    async def update(
        self,
        assessment_id: uuid.UUID,
        updates: dict,
        tenant: TenantContext,
    ) -> FedRAMPAssessment | None: ...

    async def get_latest_by_agency(
        self, agency_id: str, tenant: TenantContext
    ) -> FedRAMPAssessment | None: ...


@runtime_checkable
class INISTControlRepository(Protocol):
    """Repository interface for NISTControl records."""

    async def get_by_id(
        self, control_id: uuid.UUID, tenant: TenantContext
    ) -> NISTControl | None: ...

    async def list_all(self, tenant: TenantContext) -> list[NISTControl]: ...

    async def list_by_family(
        self, control_family: str, tenant: TenantContext
    ) -> list[NISTControl]: ...

    async def list_by_status(
        self, status: str, tenant: TenantContext
    ) -> list[NISTControl]: ...

    async def create(
        self,
        control_id: str,
        control_family: str,
        control_name: str,
        baseline: str,
        tenant: TenantContext,
    ) -> NISTControl: ...

    async def bulk_upsert(
        self,
        controls: list[dict],
        tenant: TenantContext,
    ) -> list[NISTControl]: ...

    async def update(
        self,
        record_id: uuid.UUID,
        updates: dict,
        tenant: TenantContext,
    ) -> NISTControl | None: ...

    async def get_completion_summary(
        self, tenant: TenantContext
    ) -> dict: ...


@runtime_checkable
class ICMMCRepository(Protocol):
    """Repository interface for CMMCAssessment records."""

    async def get_by_id(
        self, assessment_id: uuid.UUID, tenant: TenantContext
    ) -> CMMCAssessment | None: ...

    async def list_all(self, tenant: TenantContext) -> list[CMMCAssessment]: ...

    async def list_by_level(
        self, level: int, tenant: TenantContext
    ) -> list[CMMCAssessment]: ...

    async def create(
        self,
        target_level: int,
        tenant: TenantContext,
    ) -> CMMCAssessment: ...

    async def update(
        self,
        assessment_id: uuid.UUID,
        updates: dict,
        tenant: TenantContext,
    ) -> CMMCAssessment | None: ...

    async def get_latest_by_level(
        self, level: int, tenant: TenantContext
    ) -> CMMCAssessment | None: ...


@runtime_checkable
class ISovereignCloudRepository(Protocol):
    """Repository interface for SovereignDeployment records."""

    async def get_by_id(
        self, deployment_id: uuid.UUID, tenant: TenantContext
    ) -> SovereignDeployment | None: ...

    async def list_all(self, tenant: TenantContext) -> list[SovereignDeployment]: ...

    async def list_by_provider(
        self, provider: str, tenant: TenantContext
    ) -> list[SovereignDeployment]: ...

    async def create(
        self,
        deployment_name: str,
        cloud_provider: str,
        region: str,
        tenant: TenantContext,
    ) -> SovereignDeployment: ...

    async def update(
        self,
        deployment_id: uuid.UUID,
        updates: dict,
        tenant: TenantContext,
    ) -> SovereignDeployment | None: ...


@runtime_checkable
class IClassifiedEnvRepository(Protocol):
    """Repository interface for ClassifiedEnvironment records."""

    async def get_by_id(
        self, env_id: uuid.UUID, tenant: TenantContext
    ) -> ClassifiedEnvironment | None: ...

    async def list_all(self, tenant: TenantContext) -> list[ClassifiedEnvironment]: ...

    async def list_by_il_level(
        self, il_level: int, tenant: TenantContext
    ) -> list[ClassifiedEnvironment]: ...

    async def create(
        self,
        environment_name: str,
        impact_level: int,
        classification_level: str,
        tenant: TenantContext,
    ) -> ClassifiedEnvironment: ...

    async def update(
        self,
        env_id: uuid.UUID,
        updates: dict,
        tenant: TenantContext,
    ) -> ClassifiedEnvironment | None: ...


__all__ = [
    "IFedRAMPRepository",
    "INISTControlRepository",
    "ICMMCRepository",
    "ISovereignCloudRepository",
    "IClassifiedEnvRepository",
]

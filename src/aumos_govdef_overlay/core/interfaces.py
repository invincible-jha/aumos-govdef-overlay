"""Abstract interfaces (Protocol classes) for aumos-govdef-overlay.

Defining interfaces as Protocol classes enables:
  - Dependency injection in services
  - Easy mocking in tests
  - Clear contracts between layers

Services depend on interfaces, not concrete implementations.
"""

import uuid
from typing import Any, Protocol, runtime_checkable

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


@runtime_checkable
class IFedRAMPToolkitProtocol(Protocol):
    """Protocol for FedRAMP toolkit operations.

    Implementations provide FedRAMP authorization lifecycle support including
    baseline control mapping, SSP generation, POA&M tracking, and 3PAO scoping.
    """

    def map_baseline_controls(self, impact_level: str) -> dict: ...

    def generate_ssp_outline(
        self,
        system_name: str,
        impact_level: str,
        system_type: str,
        services: list[str],
    ) -> dict: ...

    def track_poam(self, poam_items: list[dict]) -> dict: ...

    def generate_continuous_monitoring_plan(
        self,
        impact_level: str,
        system_components: list[str],
    ) -> dict: ...

    def scope_3pao_assessment(
        self,
        impact_level: str,
        system_boundary: dict,
    ) -> dict: ...

    def map_control_inheritance(
        self,
        inherited_controls: list[str],
        provider: str,
        impact_level: str,
    ) -> dict: ...


@runtime_checkable
class INIST80053MapperProtocol(Protocol):
    """Protocol for NIST SP 800-53 Rev 5 control catalog operations.

    Implementations provide control catalog access, family organization,
    assessment procedures, cross-framework mapping, and gap analysis.
    """

    def get_control_catalog(
        self,
        baseline: str,
        control_families: list[str] | None,
    ) -> dict: ...

    def organize_by_family(self, baseline: str) -> dict: ...

    def get_assessment_procedures(self, control_id: str) -> dict: ...

    def map_cross_framework(
        self,
        source_framework: str,
        target_framework: str,
        control_ids: list[str],
    ) -> dict: ...

    def perform_gap_analysis(
        self,
        implemented_controls: list[str],
        target_baseline: str,
    ) -> dict: ...


@runtime_checkable
class ICMMCCheckerProtocol(Protocol):
    """Protocol for CMMC 2.0 practice assessment operations.

    Implementations assess CMMC domains, compute SPRS scores, identify
    gaps, and determine evidence requirements per DoD assessment guides.
    """

    def assess_domain(
        self,
        domain_name: str,
        target_level: int,
        implemented_practices: list[str],
    ) -> dict: ...

    def compute_sprs_score(
        self,
        domain_assessments: list[dict],
        target_level: int,
    ) -> dict: ...

    def identify_gaps(
        self,
        domain_assessments: list[dict],
        target_level: int,
    ) -> dict: ...

    def get_evidence_requirements(
        self,
        domain_name: str,
        target_level: int,
    ) -> dict: ...

    def score_assessment_readiness(
        self,
        domain_assessments: list[dict],
        target_level: int,
        assessment_date: str,
    ) -> dict: ...


@runtime_checkable
class ICUIHandlerProtocol(Protocol):
    """Protocol for CUI (Controlled Unclassified Information) handling.

    Implementations provide CUI category identification, marking requirements,
    storage validation, destruction procedures, and NIST 800-171 control mapping.
    """

    def identify_category(self, content_description: str, keywords: list[str]) -> dict: ...

    def get_marking_requirements(self, cui_category: str, document_type: str) -> dict: ...

    def validate_storage(
        self,
        storage_config: dict,
        cui_category: str,
    ) -> dict: ...

    def get_destruction_procedures(
        self,
        media_type: str,
        cui_category: str,
    ) -> dict: ...

    def map_nist_800_171(self, cui_category: str) -> dict: ...


@runtime_checkable
class IFIPSEnforcerProtocol(Protocol):
    """Protocol for FIPS 140-2 cryptographic compliance enforcement.

    Implementations enforce FIPS algorithm policies, plan migrations,
    validate key management, and track remediation progress.
    """

    def enforce_policy(
        self,
        system_algorithms: list[str],
        key_configs: list[dict],
        fips_level: int,
    ) -> dict: ...

    def plan_migration(
        self,
        non_compliant_algorithms: list[str],
        migration_deadline: str,
        system_criticality: str,
    ) -> dict: ...

    def validate_key_management(self, key_management_config: dict) -> dict: ...

    def inventory_modules(self, deployed_modules: list[dict]) -> dict: ...

    def track_remediation(
        self,
        remediation_id: str,
        status_update: str,
        progress_percent: int,
        notes: str | None,
    ) -> dict: ...


@runtime_checkable
class IDataResidencyCheckerProtocol(Protocol):
    """Protocol for US data sovereignty verification.

    Implementations verify data location compliance, detect cross-border
    transfers, validate cloud regions, and map jurisdictional requirements.
    """

    def verify_data_location(
        self,
        cloud_provider: str,
        region: str,
        data_category: str,
        impact_level: str,
    ) -> dict: ...

    def detect_cross_border_transfers(
        self,
        transfer_manifest: list[dict],
        data_category: str,
    ) -> dict: ...

    def validate_cloud_regions(self, deployment_config: dict) -> dict: ...

    def map_jurisdictional_requirements(
        self,
        data_categories: list[str],
        deployment_countries: list[str],
    ) -> dict: ...

    def get_approved_regions_catalog(self) -> dict: ...


@runtime_checkable
class IGovIncidentReporterProtocol(Protocol):
    """Protocol for government cybersecurity incident reporting.

    Implementations classify incidents per FISMA/DISA taxonomies, generate
    US-CERT reports, produce POA&Ms, and check reporting timeline compliance.
    """

    def classify_incident(self, incident_data: dict) -> dict: ...

    def generate_us_cert_report(
        self,
        incident_id: str,
        classification_result: dict,
        incident_details: dict,
        reporter_info: dict,
    ) -> dict: ...

    def generate_poam(
        self,
        incident_id: str,
        classification_result: dict,
        affected_controls: list[str],
        remediation_owner: str,
    ) -> dict: ...

    def generate_after_action_report(
        self,
        incident_id: str,
        classification_result: dict,
        incident_timeline: list[dict],
        lessons_learned: list[str],
        root_cause: str,
    ) -> dict: ...

    def check_reporting_timeline_compliance(
        self,
        incident_detected_utc: str,
        fisma_category: str,
        report_submitted_utc: str | None,
    ) -> dict: ...


@runtime_checkable
class IGovAuditLoggerProtocol(Protocol):
    """Protocol for NIST 800-92 compliant audit logging.

    Implementations generate tamper-evident audit events, validate log
    integrity via hash chains, enforce retention policies, and produce
    audit summary reports.
    """

    def generate_audit_event(
        self,
        event_type: str,
        subject_id: str,
        object_id: str,
        outcome: str,
        source_ip: str,
        component_id: str,
        session_id: str,
        additional_fields: dict[str, Any] | None,
        classification: str,
    ) -> dict: ...

    def validate_log_integrity(self, audit_records: list[dict]) -> dict: ...

    def enforce_retention_policy(
        self,
        log_metadata: list[dict],
        retention_framework: str,
    ) -> dict: ...

    def get_required_events_catalog(self, impact_level: str) -> dict: ...

    def generate_audit_summary_report(
        self,
        audit_records: list[dict],
        reporting_period_start: str,
        reporting_period_end: str,
        system_name: str,
    ) -> dict: ...


@runtime_checkable
class ISovereignCloudConfigProtocol(Protocol):
    """Protocol for sovereign cloud configuration generation.

    Implementations produce provider-specific deployment configurations,
    blueprints, provider comparisons, and compliance checklists for
    US government sovereign cloud environments.
    """

    def get_govcloud_region_config(
        self,
        provider: str,
        region: str,
        impact_level: str,
    ) -> dict: ...

    def generate_deployment_blueprint(
        self,
        deployment_name: str,
        provider: str,
        region: str,
        impact_level: str,
        services_required: list[str],
        compliance_frameworks: list[str],
    ) -> dict: ...

    def compare_providers(
        self,
        impact_level: str,
        required_services: list[str],
    ) -> dict: ...

    def get_encryption_templates(self) -> dict: ...

    def get_network_isolation_templates(self) -> dict: ...

    def get_compliance_checklist(self, impact_level: str) -> dict: ...


__all__ = [
    "IFedRAMPRepository",
    "INISTControlRepository",
    "ICMMCRepository",
    "ISovereignCloudRepository",
    "IClassifiedEnvRepository",
    "IFedRAMPToolkitProtocol",
    "INIST80053MapperProtocol",
    "ICMMCCheckerProtocol",
    "ICUIHandlerProtocol",
    "IFIPSEnforcerProtocol",
    "IDataResidencyCheckerProtocol",
    "IGovIncidentReporterProtocol",
    "IGovAuditLoggerProtocol",
    "ISovereignCloudConfigProtocol",
]

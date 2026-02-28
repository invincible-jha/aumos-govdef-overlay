"""SQLAlchemy ORM models for aumos-govdef-overlay.

All tenant-scoped tables extend AumOSModel which provides:
  - id: UUID primary key
  - tenant_id: UUID (RLS-enforced)
  - created_at: datetime
  - updated_at: datetime

Table naming convention: gdf_{table_name}
"""

import enum

from sqlalchemy import JSON, Boolean, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from aumos_common.database import AumOSModel


class FedRAMPImpactLevel(str, enum.Enum):
    """FedRAMP authorization impact levels."""

    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


class FedRAMPAuthorizationStatus(str, enum.Enum):
    """FedRAMP authorization workflow status."""

    NOT_STARTED = "not_started"
    READINESS_ASSESSMENT = "readiness_assessment"
    AUTHORIZATION_IN_PROCESS = "authorization_in_process"
    AUTHORIZED = "authorized"
    REVOKED = "revoked"


class NISTControlStatus(str, enum.Enum):
    """NIST 800-53 control implementation status."""

    NOT_IMPLEMENTED = "not_implemented"
    PLANNED = "planned"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    IMPLEMENTED = "implemented"
    NOT_APPLICABLE = "not_applicable"


class CMMCLevel(int, enum.Enum):
    """CMMC certification levels."""

    FOUNDATIONAL = 1
    ADVANCED = 2
    EXPERT = 3


class CMMCAssessmentStatus(str, enum.Enum):
    """CMMC assessment workflow status."""

    NOT_STARTED = "not_started"
    SELF_ASSESSMENT = "self_assessment"
    C3PAO_ASSESSMENT = "c3pao_assessment"
    CERTIFIED = "certified"
    CONDITIONAL = "conditional"
    NOT_MET = "not_met"


class SovereignDeploymentStatus(str, enum.Enum):
    """Sovereign cloud deployment status."""

    PENDING = "pending"
    PROVISIONING = "provisioning"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DECOMMISSIONED = "decommissioned"


class ImpactLevel(int, enum.Enum):
    """DoD Impact Level classification."""

    IL4 = 4
    IL5 = 5


class ClassifiedEnvStatus(str, enum.Enum):
    """Air-gapped classified environment status."""

    INITIALIZING = "initializing"
    ACTIVE = "active"
    MAINTENANCE = "maintenance"
    ISOLATED = "isolated"
    DECOMMISSIONED = "decommissioned"


class FedRAMPAssessment(AumOSModel):
    """FedRAMP readiness assessment record.

    Tracks the full FedRAMP authorization lifecycle for a tenant's
    cloud service offering, from initial readiness through ATO.

    Table: gdf_fedramp_assessments
    """

    __tablename__ = "gdf_fedramp_assessments"

    agency_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    service_name: Mapped[str] = mapped_column(String(255), nullable=False)
    impact_level: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=FedRAMPImpactLevel.MODERATE.value,
    )
    authorization_status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=FedRAMPAuthorizationStatus.NOT_STARTED.value,
        index=True,
    )
    readiness_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    control_families_assessed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    controls_implemented: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    controls_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    pmo_contact: Mapped[str | None] = mapped_column(String(255), nullable=True)
    authorization_package_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    ato_expiry_date: Mapped[str | None] = mapped_column(String(50), nullable=True)
    findings: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    remediation_plan: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class NISTControl(AumOSModel):
    """NIST 800-53 control mapping status record.

    Represents the implementation status and evidence for a single
    NIST SP 800-53 security or privacy control within a tenant's environment.

    Table: gdf_nist_controls
    """

    __tablename__ = "gdf_nist_controls"

    control_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    control_family: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    control_name: Mapped[str] = mapped_column(String(255), nullable=False)
    baseline: Mapped[str] = mapped_column(String(50), nullable=False, default="moderate")
    revision: Mapped[str] = mapped_column(String(10), nullable=False, default="rev5")
    implementation_status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=NISTControlStatus.NOT_IMPLEMENTED.value,
        index=True,
    )
    implementation_narrative: Mapped[str | None] = mapped_column(Text, nullable=True)
    responsible_role: Mapped[str | None] = mapped_column(String(255), nullable=True)
    evidence_references: Mapped[list | None] = mapped_column(JSON, nullable=True)
    related_fedramp_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    inheritable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    inherited_from: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_reviewed: Mapped[str | None] = mapped_column(String(50), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class CMMCAssessment(AumOSModel):
    """CMMC (Cybersecurity Maturity Model Certification) assessment record.

    Tracks CMMC assessment progress, practice compliance, and certification
    status for DoD contractor environments handling CUI.

    Table: gdf_cmmc_assessments
    """

    __tablename__ = "gdf_cmmc_assessments"

    target_level: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    assessment_status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=CMMCAssessmentStatus.NOT_STARTED.value,
        index=True,
    )
    c3pao_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    practices_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    practices_met: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    practices_not_met: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    domain_scores: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    poam_items: Mapped[list | None] = mapped_column(JSON, nullable=True)
    certification_date: Mapped[str | None] = mapped_column(String(50), nullable=True)
    expiry_date: Mapped[str | None] = mapped_column(String(50), nullable=True)
    contract_numbers: Mapped[list | None] = mapped_column(JSON, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class SovereignDeployment(AumOSModel):
    """Sovereign cloud deployment configuration record.

    Manages deployment configurations for government sovereign cloud
    environments including AWS GovCloud, Azure Government, and GCC High.

    Table: gdf_sovereign_deployments
    """

    __tablename__ = "gdf_sovereign_deployments"

    deployment_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    cloud_provider: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    region: Mapped[str] = mapped_column(String(100), nullable=False)
    deployment_status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=SovereignDeploymentStatus.PENDING.value,
        index=True,
    )
    compliance_frameworks: Mapped[list | None] = mapped_column(JSON, nullable=True)
    network_isolation_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    encryption_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    access_control_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    audit_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    endpoint_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    data_residency_region: Mapped[str | None] = mapped_column(String(100), nullable=True)
    is_air_gapped: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class ClassifiedEnvironment(AumOSModel):
    """Air-gapped classified environment configuration record.

    Tracks configuration and operational status for classified,
    air-gapped deployment environments at IL4 and IL5 impact levels.

    Table: gdf_classified_environments
    """

    __tablename__ = "gdf_classified_environments"

    environment_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    impact_level: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    environment_status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=ClassifiedEnvStatus.INITIALIZING.value,
        index=True,
    )
    classification_level: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="CUI",
    )
    is_air_gapped: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    network_segment: Mapped[str | None] = mapped_column(String(255), nullable=True)
    encryption_key_arn: Mapped[str | None] = mapped_column(String(512), nullable=True)
    personnel_security_requirements: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    physical_security_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    data_transfer_controls: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    audit_logging_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    authorized_users: Mapped[list | None] = mapped_column(JSON, nullable=True)
    last_security_review: Mapped[str | None] = mapped_column(String(50), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class SSPDocument(AumOSModel):
    """System Security Plan document record.

    Stores generated FedRAMP SSP in OSCAL JSON format.
    Tenant-scoped because each deployment may serve a different agency.

    Table: gdf_ssp_documents
    """

    __tablename__ = "gdf_ssp_documents"

    system_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    impact_level: Mapped[str] = mapped_column(String(10), nullable=False)
    oscal_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    version: Mapped[str] = mapped_column(String(20), nullable=False, default="1.0")
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="draft",
        comment="draft | in_review | approved | submitted"
    )
    ato_submission_date: Mapped[str | None] = mapped_column(String(20), nullable=True)
    ato_authorization_date: Mapped[str | None] = mapped_column(String(20), nullable=True)
    authorizing_agency: Mapped[str | None] = mapped_column(String(100), nullable=True)


class ConMonReport(AumOSModel):
    """FedRAMP Continuous Monitoring report per NIST SP 800-137.

    One report per monitoring cycle (default daily at 2am UTC).
    Controls compliance rate tracked over time for trend analysis.

    Table: gdf_conmon_reports
    """

    __tablename__ = "gdf_conmon_reports"

    cycle_date: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    impact_level: Mapped[str] = mapped_column(String(10), nullable=False)
    controls_checked: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    controls_compliant: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    compliance_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    degraded_controls: Mapped[list | None] = mapped_column(JSON, nullable=True, default=list)
    report_metadata: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class POAMItem(AumOSModel):
    """Plan of Action and Milestones remediation item.

    FedRAMP remediation timelines: Critical=30d, High=90d, Moderate=180d, Low=365d.
    Status lifecycle: OPEN -> IN_REMEDIATION -> CLOSED (no skipping).

    Table: gdf_poam_items
    """

    __tablename__ = "gdf_poam_items"

    finding_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    control_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    risk_level: Mapped[str] = mapped_column(
        String(20), nullable=False,
        comment="critical | high | moderate | low"
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_steps: Mapped[list | None] = mapped_column(JSON, nullable=True)
    due_date: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="OPEN",
        comment="OPEN | IN_REMEDIATION | CLOSED"
    )
    closed_at: Mapped[str | None] = mapped_column(String(30), nullable=True)
    closure_evidence: Mapped[str | None] = mapped_column(Text, nullable=True)


class STIGScanResult(AumOSModel):
    """DISA STIG compliance scan result record.

    Stores scan outcomes from bundled STIG profiles (Ubuntu, Docker, Kubernetes).
    CAT I findings must be remediated before ATO.

    Table: gdf_stig_results
    """

    __tablename__ = "gdf_stig_results"

    stig_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    target_system: Mapped[str] = mapped_column(String(255), nullable=False)
    cat1_open: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cat2_open: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cat3_open: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_rules: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    compliance_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    findings: Mapped[list | None] = mapped_column(JSON, nullable=True)
    scan_hash: Mapped[str | None] = mapped_column(String(32), nullable=True)


class StateComplianceRecord(AumOSModel):
    """StateRAMP / TX-RAMP compliance assessment record.

    Table: gdf_state_compliance
    """

    __tablename__ = "gdf_state_compliance"

    framework: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    authorization_level: Mapped[str] = mapped_column(String(50), nullable=False)
    controls_total: Mapped[int] = mapped_column(Integer, nullable=False)
    controls_met: Mapped[int] = mapped_column(Integer, nullable=False)
    compliance_score: Mapped[float] = mapped_column(Float, nullable=False)
    authorized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    gaps: Mapped[list | None] = mapped_column(JSON, nullable=True)


class EMASSSyncPackageRecord(AumOSModel):
    """eMASS control synchronization package record.

    Table: gdf_emass_packages
    """

    __tablename__ = "gdf_emass_packages"

    system_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    control_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sync_status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    controls: Mapped[list | None] = mapped_column(JSON, nullable=True)
    synced_at: Mapped[str | None] = mapped_column(String(30), nullable=True)


class ITARRecord(AumOSModel):
    """ITAR compliance record for controlled articles.

    Table: gdf_itar_records
    """

    __tablename__ = "gdf_itar_records"

    article_description: Mapped[str] = mapped_column(Text, nullable=False)
    usml_categories: Mapped[list | None] = mapped_column(JSON, nullable=True)
    is_controlled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    export_license_status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="not_required"
    )
    license_number: Mapped[str | None] = mapped_column(String(100), nullable=True)
    foreign_national_access_restricted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


__all__ = [
    "FedRAMPImpactLevel",
    "FedRAMPAuthorizationStatus",
    "NISTControlStatus",
    "CMMCLevel",
    "CMMCAssessmentStatus",
    "SovereignDeploymentStatus",
    "ImpactLevel",
    "ClassifiedEnvStatus",
    "FedRAMPAssessment",
    "NISTControl",
    "CMMCAssessment",
    "SovereignDeployment",
    "ClassifiedEnvironment",
    "SSPDocument",
    "ConMonReport",
    "POAMItem",
    "STIGScanResult",
    "StateComplianceRecord",
    "EMASSSyncPackageRecord",
    "ITARRecord",
]

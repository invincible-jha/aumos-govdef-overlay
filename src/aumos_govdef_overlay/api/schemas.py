"""Pydantic request and response schemas for aumos-govdef-overlay API.

All API inputs and outputs use Pydantic models — never return raw dicts.
Schemas are grouped by compliance domain resource.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


# ─── FedRAMP Schemas ────────────────────────────────────────────────────────

class FedRAMPAssessRequest(BaseModel):
    """Request body for POST /govdef/fedramp/assess."""

    agency_id: str = Field(description="Federal agency identifier")
    service_name: str = Field(description="Cloud service offering name")
    impact_level: str = Field(
        default="moderate",
        description="FedRAMP impact level: low, moderate, or high",
    )
    controls_implemented: int = Field(
        default=0,
        ge=0,
        description="Number of NIST controls currently implemented",
    )


class FedRAMPAssessmentResponse(BaseModel):
    """Response for FedRAMP assessment operations."""

    id: uuid.UUID = Field(description="Assessment record UUID")
    tenant_id: uuid.UUID = Field(description="Owning tenant UUID")
    agency_id: str = Field(description="Federal agency identifier")
    service_name: str = Field(description="Cloud service offering name")
    impact_level: str = Field(description="FedRAMP impact level")
    authorization_status: str = Field(description="Current authorization workflow status")
    readiness_score: float | None = Field(
        default=None,
        description="FedRAMP readiness score (0-100)",
    )
    controls_implemented: int = Field(description="Controls currently implemented")
    controls_total: int = Field(description="Total controls required for impact level")
    pmo_contact: str | None = Field(default=None, description="FedRAMP PMO contact email")
    ato_expiry_date: str | None = Field(
        default=None, description="Authority to Operate expiry date"
    )
    notes: str | None = Field(default=None, description="Assessment notes")
    created_at: datetime = Field(description="Record creation timestamp")
    updated_at: datetime = Field(description="Record last update timestamp")


# ─── NIST 800-53 Schemas ────────────────────────────────────────────────────

class NISTControlMappingItem(BaseModel):
    """A single NIST 800-53 control mapping entry."""

    control_id: str = Field(description="NIST control ID (e.g., AC-1)")
    control_family: str = Field(description="Control family code (e.g., AC)")
    control_name: str = Field(description="Human-readable control name")
    implementation_status: str = Field(
        default="not_implemented",
        description="Implementation status: not_implemented, planned, partially_implemented, implemented, not_applicable",
    )
    implementation_narrative: str | None = Field(
        default=None,
        description="Description of how the control is implemented",
    )
    responsible_role: str | None = Field(
        default=None,
        description="Role responsible for control implementation",
    )
    evidence_references: list[str] | None = Field(
        default=None,
        description="List of evidence reference URLs or identifiers",
    )
    inheritable: bool = Field(
        default=False,
        description="Whether this control can be inherited by child systems",
    )


class NISTMapRequest(BaseModel):
    """Request body for POST /govdef/nist/map."""

    controls: list[NISTControlMappingItem] = Field(
        description="List of NIST controls to map"
    )
    baseline: str = Field(
        default="moderate",
        description="NIST 800-53 baseline: low, moderate, or high",
    )
    revision: str = Field(
        default="rev5",
        description="NIST SP 800-53 revision: rev4 or rev5",
    )


class NISTControlResponse(BaseModel):
    """Response for a single NIST control record."""

    id: uuid.UUID = Field(description="Control record UUID")
    tenant_id: uuid.UUID = Field(description="Owning tenant UUID")
    control_id: str = Field(description="NIST control ID")
    control_family: str = Field(description="Control family code")
    control_name: str = Field(description="Human-readable control name")
    baseline: str = Field(description="NIST baseline")
    revision: str = Field(description="NIST revision")
    implementation_status: str = Field(description="Implementation status")
    implementation_narrative: str | None = Field(default=None)
    responsible_role: str | None = Field(default=None)
    evidence_references: list | None = Field(default=None)
    inheritable: bool = Field(description="Whether control is inheritable")
    inherited_from: str | None = Field(default=None)
    created_at: datetime = Field(description="Record creation timestamp")
    updated_at: datetime = Field(description="Record last update timestamp")


class NISTMapResponse(BaseModel):
    """Response for POST /govdef/nist/map."""

    controls_mapped: int = Field(description="Number of controls mapped")
    baseline: str = Field(description="NIST baseline applied")
    revision: str = Field(description="NIST revision applied")
    controls: list[NISTControlResponse] = Field(description="Mapped control records")


class NISTControlsStatusResponse(BaseModel):
    """Response for GET /govdef/nist/controls."""

    total: int = Field(description="Total controls tracked")
    completion_percentage: float = Field(description="Implementation completion percentage")
    by_status: dict = Field(description="Control counts by implementation status")
    controls: list[NISTControlResponse] = Field(description="All control records")


# ─── CMMC Schemas ───────────────────────────────────────────────────────────

class CMMCAssessRequest(BaseModel):
    """Request body for POST /govdef/cmmc/assess."""

    target_level: int = Field(
        ge=1,
        le=3,
        description="CMMC target certification level: 1, 2, or 3",
    )
    practices_met: int = Field(
        default=0,
        ge=0,
        description="Number of CMMC practices currently met",
    )
    domain_scores: dict | None = Field(
        default=None,
        description="Per-domain practice scores (domain name -> score)",
    )
    c3pao_id: str | None = Field(
        default=None,
        description="Certified Third-Party Assessment Organization ID (required for Level 2+)",
    )


class CMMCAssessmentResponse(BaseModel):
    """Response for CMMC assessment operations."""

    id: uuid.UUID = Field(description="Assessment record UUID")
    tenant_id: uuid.UUID = Field(description="Owning tenant UUID")
    target_level: int = Field(description="CMMC target certification level")
    assessment_status: str = Field(description="Assessment workflow status")
    practices_total: int = Field(description="Total practices required for target level")
    practices_met: int = Field(description="Practices currently met")
    practices_not_met: int = Field(description="Practices not yet met")
    score: float | None = Field(default=None, description="CMMC score (SPRS-style)")
    domain_scores: dict | None = Field(default=None, description="Per-domain scores")
    c3pao_id: str | None = Field(default=None, description="C3PAO identifier")
    certification_date: str | None = Field(default=None, description="Certification date")
    expiry_date: str | None = Field(default=None, description="Certification expiry date")
    notes: str | None = Field(default=None)
    created_at: datetime = Field(description="Record creation timestamp")
    updated_at: datetime = Field(description="Record last update timestamp")


# ─── Sovereign Cloud Schemas ─────────────────────────────────────────────────

class SovereignDeployRequest(BaseModel):
    """Request body for POST /govdef/sovereign/deploy."""

    deployment_name: str = Field(description="Human-readable deployment identifier")
    cloud_provider: str = Field(
        description="Target provider: aws-govcloud, azure-government, or gcc-high",
    )
    region: str = Field(description="Deployment region identifier")
    compliance_frameworks: list[str] = Field(
        description="Compliance frameworks to enforce (e.g., ['FedRAMP-High', 'IL5'])",
    )
    encryption_config: dict | None = Field(
        default=None,
        description="Encryption settings for data at rest and in transit",
    )
    network_isolation_config: dict | None = Field(
        default=None,
        description="VPC/VNet network isolation configuration",
    )
    is_air_gapped: bool = Field(
        default=False,
        description="Whether the deployment is network-isolated (air-gapped)",
    )


class SovereignDeploymentResponse(BaseModel):
    """Response for sovereign cloud deployment operations."""

    id: uuid.UUID = Field(description="Deployment record UUID")
    tenant_id: uuid.UUID = Field(description="Owning tenant UUID")
    deployment_name: str = Field(description="Deployment name")
    cloud_provider: str = Field(description="Cloud provider")
    region: str = Field(description="Deployment region")
    deployment_status: str = Field(description="Deployment status")
    compliance_frameworks: list | None = Field(default=None)
    is_air_gapped: bool = Field(description="Whether deployment is air-gapped")
    endpoint_url: str | None = Field(default=None)
    data_residency_region: str | None = Field(default=None)
    notes: str | None = Field(default=None)
    created_at: datetime = Field(description="Record creation timestamp")
    updated_at: datetime = Field(description="Record last update timestamp")


class ILLevelStatusResponse(BaseModel):
    """Response for GET /govdef/il-level/{level}/status."""

    il_level: int = Field(description="DoD Impact Level queried")
    deployments_count: int = Field(description="Number of deployments at this IL level")
    deployments: list[SovereignDeploymentResponse] = Field(
        description="Deployments supporting this IL level"
    )
    environments_count: int = Field(
        description="Number of classified environments at this IL level"
    )


__all__ = [
    "FedRAMPAssessRequest",
    "FedRAMPAssessmentResponse",
    "NISTControlMappingItem",
    "NISTMapRequest",
    "NISTControlResponse",
    "NISTMapResponse",
    "NISTControlsStatusResponse",
    "CMMCAssessRequest",
    "CMMCAssessmentResponse",
    "SovereignDeployRequest",
    "SovereignDeploymentResponse",
    "ILLevelStatusResponse",
]

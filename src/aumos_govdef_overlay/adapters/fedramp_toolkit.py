"""FedRAMP authorization toolkit adapter for aumos-govdef-overlay.

Implements FedRAMP baseline mapping (Low/Moderate/High), SSP document
generation support, POA&M tracking, continuous monitoring requirements,
3PAO assessment support, and control inheritance mapping.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# FedRAMP control counts per baseline (NIST 800-53 Rev 5)
_FEDRAMP_CONTROL_COUNTS: dict[str, int] = {
    "low": 125,
    "moderate": 325,
    "high": 421,
}

# FedRAMP control families with impact level applicability
_FEDRAMP_CONTROL_FAMILIES: dict[str, dict[str, Any]] = {
    "AC": {"name": "Access Control", "applicable_baselines": ["low", "moderate", "high"], "low_count": 2, "moderate_count": 15, "high_count": 22},
    "AT": {"name": "Awareness and Training", "applicable_baselines": ["low", "moderate", "high"], "low_count": 2, "moderate_count": 3, "high_count": 3},
    "AU": {"name": "Audit and Accountability", "applicable_baselines": ["low", "moderate", "high"], "low_count": 5, "moderate_count": 11, "high_count": 14},
    "CA": {"name": "Assessment, Authorization, and Monitoring", "applicable_baselines": ["low", "moderate", "high"], "low_count": 4, "moderate_count": 6, "high_count": 7},
    "CM": {"name": "Configuration Management", "applicable_baselines": ["low", "moderate", "high"], "low_count": 5, "moderate_count": 12, "high_count": 12},
    "CP": {"name": "Contingency Planning", "applicable_baselines": ["low", "moderate", "high"], "low_count": 4, "moderate_count": 7, "high_count": 10},
    "IA": {"name": "Identification and Authentication", "applicable_baselines": ["low", "moderate", "high"], "low_count": 4, "moderate_count": 8, "high_count": 9},
    "IR": {"name": "Incident Response", "applicable_baselines": ["low", "moderate", "high"], "low_count": 4, "moderate_count": 7, "high_count": 8},
    "MA": {"name": "Maintenance", "applicable_baselines": ["low", "moderate", "high"], "low_count": 2, "moderate_count": 5, "high_count": 5},
    "MP": {"name": "Media Protection", "applicable_baselines": ["low", "moderate", "high"], "low_count": 3, "moderate_count": 7, "high_count": 7},
    "PE": {"name": "Physical and Environmental Protection", "applicable_baselines": ["low", "moderate", "high"], "low_count": 8, "moderate_count": 12, "high_count": 14},
    "PL": {"name": "Planning", "applicable_baselines": ["low", "moderate", "high"], "low_count": 2, "moderate_count": 4, "high_count": 4},
    "PS": {"name": "Personnel Security", "applicable_baselines": ["low", "moderate", "high"], "low_count": 6, "moderate_count": 7, "high_count": 7},
    "RA": {"name": "Risk Assessment", "applicable_baselines": ["low", "moderate", "high"], "low_count": 3, "moderate_count": 5, "high_count": 5},
    "SA": {"name": "System and Services Acquisition", "applicable_baselines": ["low", "moderate", "high"], "low_count": 9, "moderate_count": 14, "high_count": 16},
    "SC": {"name": "System and Communications Protection", "applicable_baselines": ["low", "moderate", "high"], "low_count": 6, "moderate_count": 18, "high_count": 26},
    "SI": {"name": "System and Information Integrity", "applicable_baselines": ["low", "moderate", "high"], "low_count": 6, "moderate_count": 12, "high_count": 13},
    "SR": {"name": "Supply Chain Risk Management", "applicable_baselines": ["moderate", "high"], "low_count": 0, "moderate_count": 5, "high_count": 5},
}

# FedRAMP authorization workflow stages
_AUTHORIZATION_STAGES = [
    "Readiness Assessment",
    "Authorization",
    "Full Authorization Package",
    "ATO Granted",
    "Continuous Monitoring",
]

# FedRAMP continuous monitoring requirements
_CONTINUOUS_MONITORING_REQUIREMENTS: dict[str, list[str]] = {
    "monthly": [
        "Vulnerability scanning (OS and web applications)",
        "Security control review — high-priority controls",
        "Incident reporting",
        "POA&M updates",
    ],
    "quarterly": [
        "Privileged user access review",
        "Contingency plan testing",
        "Media sanitization and disposal review",
    ],
    "annually": [
        "Security assessment (subset of controls)",
        "Penetration testing",
        "POA&M full review",
        "Privacy Threshold Analysis (PTA) if applicable",
        "Privacy Impact Assessment (PIA) update if applicable",
    ],
    "as_needed": [
        "Significant change notification to JAB/AO",
        "Incident reporting to US-CERT",
        "Plan of Action and Milestones submission",
    ],
}

# 3PAO assessment scope by authorization type
_3PAO_SCOPE: dict[str, list[str]] = {
    "new_authorization": [
        "100% control assessment for JAB authorization",
        "Penetration testing of system boundary",
        "Vulnerability scanning",
        "Privacy controls assessment",
    ],
    "agency_authorization": [
        "Representative sample of controls (typically 25-30%)",
        "All High-impact controls",
        "Penetration testing",
        "Vulnerability scanning",
    ],
    "annual_assessment": [
        "One-third of controls not assessed in prior two years",
        "All corrected POA&M items",
        "New controls added since last assessment",
    ],
}


class FedRAMPToolkit:
    """Provides FedRAMP authorization lifecycle management tools.

    Implements FedRAMP baseline control mapping, SSP generation support,
    POA&M tracking, continuous monitoring schedule generation, 3PAO
    assessment scoping, and authorization package preparation guidance.
    """

    def __init__(self) -> None:
        """Initialize FedRAMP toolkit."""
        pass

    def map_baseline_controls(
        self,
        impact_level: str,
        implemented_families: list[str] | None = None,
    ) -> dict[str, Any]:
        """Map FedRAMP control requirements for a given impact level.

        Generates a complete control mapping showing all applicable control
        families and their control counts for the specified FedRAMP baseline
        (Low, Moderate, or High).

        Args:
            impact_level: FedRAMP impact level ('low', 'moderate', or 'high').
            implemented_families: Optional list of control families already implemented.

        Returns:
            FedRAMP control baseline mapping dict.
        """
        impact_level = impact_level.lower()
        if impact_level not in _FEDRAMP_CONTROL_COUNTS:
            impact_level = "moderate"

        count_key = f"{impact_level}_count"
        applicable_families: dict[str, Any] = {}
        total_controls = 0

        for family_code, family_info in _FEDRAMP_CONTROL_FAMILIES.items():
            if impact_level in family_info.get("applicable_baselines", []):
                family_count = family_info.get(count_key, 0)
                implemented = family_code in (implemented_families or [])
                applicable_families[family_code] = {
                    "family_name": family_info["name"],
                    "control_count": family_count,
                    "implemented": implemented,
                    "status": "Implemented" if implemented else "Not Implemented",
                }
                total_controls += family_count

        implemented_count = sum(
            f["control_count"] for f in applicable_families.values() if f["implemented"]
        )
        readiness_pct = round((implemented_count / total_controls * 100) if total_controls > 0 else 0.0, 2)

        mapping = {
            "impact_level": impact_level.upper(),
            "total_controls_required": total_controls,
            "control_families": applicable_families,
            "implemented_controls_estimated": implemented_count,
            "readiness_percentage": readiness_pct,
            "fedramp_version": "FedRAMP Rev 5 (NIST SP 800-53 Rev 5)",
            "authorization_path": "JAB P-ATO" if impact_level == "high" else "Agency ATO",
            "mapped_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "FedRAMP baseline controls mapped",
            impact_level=impact_level,
            total_controls=total_controls,
            readiness_pct=readiness_pct,
        )

        return mapping

    def generate_ssp_outline(
        self,
        system_name: str,
        system_owner: str,
        impact_level: str,
        agency_id: str,
        cloud_service_model: str,
        deployment_model: str,
        authorization_boundary_description: str,
    ) -> dict[str, Any]:
        """Generate a System Security Plan (SSP) document outline.

        Creates a structured SSP outline compliant with FedRAMP SSP template
        requirements, ready for population with system-specific control
        implementation descriptions.

        Args:
            system_name: Cloud service offering name.
            system_owner: Organization owning the system.
            impact_level: FedRAMP impact level.
            agency_id: Sponsoring agency identifier.
            cloud_service_model: IaaS, PaaS, or SaaS.
            deployment_model: Public, Private, Hybrid, or Government Community Cloud.
            authorization_boundary_description: Description of system boundary.

        Returns:
            SSP outline dict with all required sections.
        """
        impact_level = impact_level.lower()
        control_count = _FEDRAMP_CONTROL_COUNTS.get(impact_level, 325)

        ssp_outline = {
            "document_title": f"FedRAMP System Security Plan — {system_name}",
            "revision": "1.0",
            "impact_level": impact_level.upper(),
            "system_name": system_name,
            "system_owner": system_owner,
            "agency_id": agency_id,
            "cloud_service_model": cloud_service_model,
            "deployment_model": deployment_model,
            "authorization_boundary": authorization_boundary_description,
            "required_sections": [
                {
                    "section": "1",
                    "title": "Information System Categorization",
                    "description": "FIPS 199 security categorization for C/I/A objectives",
                    "required": True,
                },
                {
                    "section": "2",
                    "title": "Information System Owner",
                    "description": "System owner name, title, organization, and contact",
                    "required": True,
                },
                {
                    "section": "3",
                    "title": "Assignment of Security Responsibility",
                    "description": "ISSO designation and responsibilities",
                    "required": True,
                },
                {
                    "section": "4",
                    "title": "Authorized Users",
                    "description": "User roles and access levels",
                    "required": True,
                },
                {
                    "section": "5",
                    "title": "System Environment",
                    "description": "Architecture diagram, network topology, data flows",
                    "required": True,
                },
                {
                    "section": "6",
                    "title": "System Interconnections",
                    "description": "ISAs and MOUs for connected systems",
                    "required": True,
                },
                {
                    "section": "7",
                    "title": "Laws, Regulations, Standards and Guidance",
                    "description": "Applicable regulatory requirements",
                    "required": True,
                },
                {
                    "section": "13",
                    "title": "Security Control Implementation",
                    "description": f"All {control_count} required controls for {impact_level.upper()} baseline",
                    "required": True,
                    "control_count": control_count,
                },
            ],
            "required_attachments": [
                "Attachment 1 — Separation of Duties Matrix",
                "Attachment 2 — User Guide",
                "Attachment 3 — Privacy Threshold Analysis (PTA)",
                "Attachment 4 — Rules of Behavior",
                "Attachment 5 — Information Security Policies and Procedures",
                "Attachment 6 — Configuration Management Plan",
                "Attachment 7 — Incident Response Plan",
                "Attachment 8 — Contingency Plan",
                "Attachment 9 — Control Summary",
                "Attachment 10 — FedRAMP Applicable Laws and Regulations",
                "Attachment 11 — Acronyms and Definitions",
                "Attachment 12 — System Interconnections",
            ],
            "fedramp_template_version": "2023-06-30",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "FedRAMP SSP outline generated",
            system_name=system_name,
            impact_level=impact_level,
            control_count=control_count,
        )

        return ssp_outline

    def track_poam(
        self,
        poam_items: list[dict[str, Any]],
        system_name: str,
        report_date: datetime,
    ) -> dict[str, Any]:
        """Track and analyze Plan of Action and Milestones (POA&M) items.

        Provides POA&M status analysis, overdue item identification, and
        risk-prioritized remediation recommendations per FedRAMP requirements.

        Args:
            poam_items: List of POA&M item dicts with 'control_id', 'weakness',
                'risk_level', 'scheduled_completion', 'status' keys.
            system_name: Cloud service offering name.
            report_date: Date of this POA&M report.

        Returns:
            POA&M tracking report dict with status summary.
        """
        open_items = [i for i in poam_items if i.get("status", "") in ("open", "delayed")]
        closed_items = [i for i in poam_items if i.get("status", "") == "closed"]
        high_risk_open = [i for i in open_items if i.get("risk_level", "") in ("high", "critical")]

        overdue_items: list[dict[str, Any]] = []
        for item in open_items:
            scheduled_str = item.get("scheduled_completion")
            if scheduled_str:
                try:
                    scheduled = datetime.fromisoformat(scheduled_str)
                    if scheduled.replace(tzinfo=timezone.utc) < report_date.replace(tzinfo=timezone.utc):
                        overdue_days = (report_date.replace(tzinfo=timezone.utc) - scheduled.replace(tzinfo=timezone.utc)).days
                        overdue_items.append({
                            **item,
                            "overdue_days": overdue_days,
                        })
                except (ValueError, TypeError):
                    pass

        # FedRAMP risk rating thresholds for escalation
        critical_overdue = [i for i in overdue_items if i.get("risk_level") in ("high", "critical")]
        ato_at_risk = len(critical_overdue) > 0 or len(high_risk_open) >= 5

        tracking_report = {
            "system_name": system_name,
            "report_date": report_date.isoformat(),
            "total_poam_items": len(poam_items),
            "open_items": len(open_items),
            "closed_items": len(closed_items),
            "overdue_items": len(overdue_items),
            "high_risk_open_items": len(high_risk_open),
            "ato_at_risk": ato_at_risk,
            "overdue_item_details": overdue_items,
            "critical_overdue_items": critical_overdue,
            "remediation_priority": [
                i for i in sorted(open_items, key=lambda x: x.get("risk_level", "low"))
            ],
            "fedramp_poam_template": "FedRAMP POA&M Template Rev 5",
            "submission_due": (report_date + timedelta(days=30)).isoformat(),
            "tracked_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "FedRAMP POA&M tracked",
            system_name=system_name,
            open_items=len(open_items),
            overdue_items=len(overdue_items),
            ato_at_risk=ato_at_risk,
        )

        return tracking_report

    def generate_continuous_monitoring_plan(
        self,
        system_name: str,
        impact_level: str,
        authorization_date: datetime,
    ) -> dict[str, Any]:
        """Generate a FedRAMP Continuous Monitoring (ConMon) plan.

        Creates a structured continuous monitoring plan with scheduled
        activities, deliverable due dates, and reporting requirements
        aligned with FedRAMP JAB and agency authorization requirements.

        Args:
            system_name: Cloud service offering name.
            impact_level: FedRAMP impact level.
            authorization_date: Date ATO was granted.

        Returns:
            Continuous monitoring plan dict with activity schedule.
        """
        next_monthly = datetime.now(timezone.utc).replace(day=1) + timedelta(days=32)
        next_monthly = next_monthly.replace(day=1)

        next_annual = authorization_date.replace(year=authorization_date.year + 1)

        conmon_plan = {
            "system_name": system_name,
            "impact_level": impact_level.upper(),
            "authorization_date": authorization_date.isoformat(),
            "conmon_activities": _CONTINUOUS_MONITORING_REQUIREMENTS,
            "scheduled_deliverables": {
                "monthly": {
                    "next_due": next_monthly.isoformat(),
                    "deliverables": [
                        "Vulnerability scan results (OS and web app)",
                        "POA&M monthly update",
                        "Inventory update",
                    ],
                },
                "quarterly": {
                    "next_due": (datetime.now(timezone.utc) + timedelta(days=90)).isoformat(),
                    "deliverables": [
                        "Control implementation update",
                        "Privileged user review",
                    ],
                },
                "annually": {
                    "next_due": next_annual.isoformat(),
                    "deliverables": [
                        "Annual security assessment report (SAR)",
                        "Updated SSP",
                        "POA&M annual review",
                        "Penetration test results",
                    ],
                },
            },
            "significant_change_procedures": [
                "Notify AO/JAB of any significant change before implementation",
                "Document change in SSP and update affected controls",
                "Submit change notification form within 5 business days",
            ],
            "fedramp_conmon_reference": "FedRAMP Continuous Monitoring Performance Management Guide",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "FedRAMP continuous monitoring plan generated",
            system_name=system_name,
            impact_level=impact_level,
        )

        return conmon_plan

    def scope_3pao_assessment(
        self,
        authorization_type: str,
        system_name: str,
        total_controls: int,
        previous_assessment_date: datetime | None,
        high_impact_controls: list[str],
    ) -> dict[str, Any]:
        """Scope a 3PAO assessment for FedRAMP authorization.

        Generates assessment scope documentation for Third-Party Assessment
        Organizations (3PAOs) including control sampling methodology,
        testing requirements, and deliverable expectations.

        Args:
            authorization_type: 'new_authorization', 'agency_authorization', or 'annual_assessment'.
            system_name: Cloud service offering name.
            total_controls: Total controls in scope.
            previous_assessment_date: Date of previous 3PAO assessment if applicable.
            high_impact_controls: List of high-impact control IDs.

        Returns:
            3PAO assessment scope dict.
        """
        scope_requirements = _3PAO_SCOPE.get(
            authorization_type, _3PAO_SCOPE["agency_authorization"]
        )

        if authorization_type == "new_authorization":
            sample_size = total_controls
            sample_description = "100% — all controls assessed"
        elif authorization_type == "annual_assessment":
            sample_size = max(20, total_controls // 3)
            sample_description = "One-third of controls plus all corrections"
        else:
            sample_size = max(30, int(total_controls * 0.28))
            sample_description = "~28% sample plus all High controls"

        assessment_scope = {
            "system_name": system_name,
            "authorization_type": authorization_type,
            "assessment_scope_requirements": scope_requirements,
            "control_sample_size": sample_size,
            "control_sample_description": sample_description,
            "total_controls_in_system": total_controls,
            "high_impact_controls_to_assess": high_impact_controls,
            "mandatory_testing": [
                "Penetration testing (external and internal)",
                "Vulnerability scanning (OS, web app, database)",
                "Social engineering assessment",
            ],
            "deliverables_expected": [
                "Security Assessment Plan (SAP)",
                "Security Assessment Report (SAR)",
                "Penetration Test Report",
                "Vulnerability Scan Reports",
            ],
            "previous_assessment_date": previous_assessment_date.isoformat() if previous_assessment_date else None,
            "fedramp_3pao_reference": "FedRAMP 3PAO Obligations and Performance Standards",
            "scoped_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "FedRAMP 3PAO assessment scoped",
            system_name=system_name,
            authorization_type=authorization_type,
            sample_size=sample_size,
        )

        return assessment_scope

    def map_control_inheritance(
        self,
        system_name: str,
        cloud_provider: str,
        inherited_controls: list[dict[str, Any]],
        leveraged_authorizations: list[str],
    ) -> dict[str, Any]:
        """Map control inheritance from cloud provider and leveraged authorizations.

        Documents which FedRAMP controls are inherited from the underlying
        cloud service provider (IaaS/PaaS), customer-responsible, or hybrid,
        reducing the assessment burden for inherited controls.

        Args:
            system_name: Cloud service offering name.
            cloud_provider: Underlying cloud provider name.
            inherited_controls: List of inherited control dicts with 'control_id',
                'inheritance_type' ('inherited'/'hybrid'/'customer') keys.
            leveraged_authorizations: List of leveraged ATO package identifiers.

        Returns:
            Control inheritance mapping dict.
        """
        inherited = [c for c in inherited_controls if c.get("inheritance_type") == "inherited"]
        hybrid = [c for c in inherited_controls if c.get("inheritance_type") == "hybrid"]
        customer = [c for c in inherited_controls if c.get("inheritance_type") == "customer"]

        inheritance_summary: dict[str, Any] = {
            "system_name": system_name,
            "cloud_provider": cloud_provider,
            "leveraged_authorizations": leveraged_authorizations,
            "total_controls_mapped": len(inherited_controls),
            "inherited_count": len(inherited),
            "hybrid_count": len(hybrid),
            "customer_responsible_count": len(customer),
            "inheritance_breakdown": {
                "inherited": [c.get("control_id") for c in inherited],
                "hybrid": [c.get("control_id") for c in hybrid],
                "customer": [c.get("control_id") for c in customer],
            },
            "assessment_burden_reduction_pct": round(
                (len(inherited) / len(inherited_controls) * 100)
                if inherited_controls
                else 0.0,
                2,
            ),
            "note": "Inherited controls must be validated through leveraged authorization packages",
            "fedramp_inheritance_guidance": "FedRAMP Control Implementation Summary (CIS) Workbook",
            "mapped_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "FedRAMP control inheritance mapped",
            system_name=system_name,
            inherited_count=len(inherited),
            hybrid_count=len(hybrid),
            customer_count=len(customer),
        )

        return inheritance_summary


__all__ = ["FedRAMPToolkit"]

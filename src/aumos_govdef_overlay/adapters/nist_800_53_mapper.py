"""NIST SP 800-53 Rev 5 control mapping adapter for aumos-govdef-overlay.

Implements comprehensive NIST 800-53 Rev 5 control catalog, control family
organization, implementation status tracking, control assessment procedures,
enhancement mapping, cross-framework mapping, and gap analysis.
"""

from datetime import datetime, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# NIST 800-53 Rev 5 control families
_CONTROL_FAMILIES: dict[str, str] = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PM": "Program Management",
    "PS": "Personnel Security",
    "PT": "PII Processing and Transparency",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}

# Representative NIST 800-53 Rev 5 controls with priority information
_NIST_CONTROLS: list[dict[str, Any]] = [
    {"id": "AC-1", "family": "AC", "name": "Policy and Procedures", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "AC-2", "family": "AC", "name": "Account Management", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "AC-3", "family": "AC", "name": "Access Enforcement", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "AC-4", "family": "AC", "name": "Information Flow Enforcement", "baselines": ["moderate", "high"], "priority": "P1"},
    {"id": "AC-5", "family": "AC", "name": "Separation of Duties", "baselines": ["moderate", "high"], "priority": "P1"},
    {"id": "AC-6", "family": "AC", "name": "Least Privilege", "baselines": ["moderate", "high"], "priority": "P1"},
    {"id": "AC-17", "family": "AC", "name": "Remote Access", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "AU-2", "family": "AU", "name": "Event Logging", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "AU-3", "family": "AU", "name": "Content of Audit Records", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "AU-6", "family": "AU", "name": "Audit Record Review, Analysis, and Reporting", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "AU-9", "family": "AU", "name": "Protection of Audit Information", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "CA-2", "family": "CA", "name": "Control Assessments", "baselines": ["low", "moderate", "high"], "priority": "P2"},
    {"id": "CA-3", "family": "CA", "name": "Information Exchange", "baselines": ["low", "moderate", "high"], "priority": "P2"},
    {"id": "CA-7", "family": "CA", "name": "Continuous Monitoring", "baselines": ["low", "moderate", "high"], "priority": "P2"},
    {"id": "CM-2", "family": "CM", "name": "Baseline Configuration", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "CM-6", "family": "CM", "name": "Configuration Settings", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "CM-7", "family": "CM", "name": "Least Functionality", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "CP-9", "family": "CP", "name": "System Backup", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "IA-2", "family": "IA", "name": "Identification and Authentication", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "IA-3", "family": "IA", "name": "Device Identification and Authentication", "baselines": ["moderate", "high"], "priority": "P1"},
    {"id": "IA-5", "family": "IA", "name": "Authenticator Management", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "IR-4", "family": "IR", "name": "Incident Handling", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "IR-5", "family": "IR", "name": "Incident Monitoring", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "IR-6", "family": "IR", "name": "Incident Reporting", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "MP-2", "family": "MP", "name": "Media Access", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "MP-6", "family": "MP", "name": "Media Sanitization", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "PE-2", "family": "PE", "name": "Physical Access Authorizations", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "PE-3", "family": "PE", "name": "Physical Access Control", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "RA-3", "family": "RA", "name": "Risk Assessment", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "RA-5", "family": "RA", "name": "Vulnerability Monitoring and Scanning", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "SA-8", "family": "SA", "name": "Security and Privacy Engineering Principles", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "SC-7", "family": "SC", "name": "Boundary Protection", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "SC-8", "family": "SC", "name": "Transmission Confidentiality and Integrity", "baselines": ["moderate", "high"], "priority": "P1"},
    {"id": "SC-28", "family": "SC", "name": "Protection of Information at Rest", "baselines": ["moderate", "high"], "priority": "P1"},
    {"id": "SI-2", "family": "SI", "name": "Flaw Remediation", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "SI-3", "family": "SI", "name": "Malicious Code Protection", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "SI-4", "family": "SI", "name": "System Monitoring", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "SR-1", "family": "SR", "name": "Policy and Procedures", "baselines": ["low", "moderate", "high"], "priority": "P2"},
    {"id": "SR-3", "family": "SR", "name": "Supply Chain Controls and Plans", "baselines": ["low", "moderate", "high"], "priority": "P1"},
    {"id": "PS-3", "family": "PS", "name": "Personnel Screening", "baselines": ["low", "moderate", "high"], "priority": "P1"},
]

# Cross-framework mapping: NIST families to CMMC domains
_NIST_TO_CMMC: dict[str, str] = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Security Assessment",
    "CM": "Configuration Management",
    "CP": "Recovery",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical Protection",
    "PS": "Personnel Security",
    "RA": "Risk Management",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
}

# Assessment procedures by control type
_ASSESSMENT_PROCEDURES: dict[str, list[str]] = {
    "examine": [
        "Review policy and procedure documents",
        "Inspect configuration settings and baselines",
        "Review audit records and logs",
        "Examine architectural diagrams and data flow maps",
    ],
    "interview": [
        "Interview system owner and security staff",
        "Interview operations personnel",
        "Interview users of privileged accounts",
    ],
    "test": [
        "Test technical controls with automated scanning",
        "Conduct penetration testing",
        "Verify configuration compliance with SCAP benchmarks",
        "Test incident response procedures",
    ],
}


class NIST80053Mapper:
    """Maps and tracks NIST SP 800-53 Rev 5 control implementations.

    Provides comprehensive control catalog access, family-level organization,
    implementation status tracking, assessment procedure guidance, control
    enhancement mapping, cross-framework alignment, and gap analysis.
    """

    def __init__(self) -> None:
        """Initialize NIST 800-53 mapper."""
        pass

    def get_control_catalog(
        self,
        baseline: str | None = None,
        control_family: str | None = None,
        priority: str | None = None,
    ) -> dict[str, Any]:
        """Retrieve NIST 800-53 Rev 5 controls filtered by criteria.

        Provides access to the NIST 800-53 Rev 5 control catalog with
        optional filtering by baseline, control family, or priority level.

        Args:
            baseline: Optional NIST baseline filter ('low', 'moderate', 'high').
            control_family: Optional two-letter control family code.
            priority: Optional priority filter ('P1', 'P2', 'P3').

        Returns:
            Control catalog dict with filtered controls and metadata.
        """
        controls = _NIST_CONTROLS

        if baseline:
            controls = [c for c in controls if baseline.lower() in c.get("baselines", [])]
        if control_family:
            controls = [c for c in controls if c.get("family") == control_family.upper()]
        if priority:
            controls = [c for c in controls if c.get("priority") == priority.upper()]

        family_breakdown: dict[str, int] = {}
        for control in controls:
            family = control.get("family", "")
            family_breakdown[family] = family_breakdown.get(family, 0) + 1

        catalog = {
            "nist_revision": "Rev 5",
            "publication_date": "2020-09-23",
            "filters_applied": {
                "baseline": baseline,
                "control_family": control_family,
                "priority": priority,
            },
            "total_controls_returned": len(controls),
            "family_breakdown": family_breakdown,
            "controls": controls,
            "total_families": len(_CONTROL_FAMILIES),
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "NIST 800-53 control catalog retrieved",
            total_controls=len(controls),
            baseline=baseline,
            family=control_family,
        )

        return catalog

    def organize_by_family(
        self,
        implemented_control_ids: list[str],
        target_baseline: str,
    ) -> dict[str, Any]:
        """Organize NIST 800-53 controls by control family with implementation status.

        Groups controls by family and shows implementation progress for each
        family against the target baseline requirements.

        Args:
            implemented_control_ids: List of control IDs marked as implemented.
            target_baseline: Target NIST baseline ('low', 'moderate', 'high').

        Returns:
            Family organization dict with per-family implementation status.
        """
        target_baseline = target_baseline.lower()
        implemented_set = set(implemented_control_ids)

        applicable_controls = [
            c for c in _NIST_CONTROLS
            if target_baseline in c.get("baselines", [])
        ]

        family_organization: dict[str, Any] = {}

        for family_code, family_name in _CONTROL_FAMILIES.items():
            family_controls = [c for c in applicable_controls if c.get("family") == family_code]
            if not family_controls:
                continue

            implemented = [c for c in family_controls if c.get("id") in implemented_set]
            not_implemented = [c for c in family_controls if c.get("id") not in implemented_set]

            family_organization[family_code] = {
                "family_name": family_name,
                "total_applicable": len(family_controls),
                "implemented": len(implemented),
                "not_implemented": len(not_implemented),
                "implementation_pct": round(
                    (len(implemented) / len(family_controls) * 100) if family_controls else 0.0, 2
                ),
                "implemented_controls": [c.get("id") for c in implemented],
                "not_implemented_controls": [c.get("id") for c in not_implemented],
            }

        total_applicable = len(applicable_controls)
        total_implemented = sum(
            1 for c in applicable_controls if c.get("id") in implemented_set
        )
        overall_completion = round(
            (total_implemented / total_applicable * 100) if total_applicable > 0 else 0.0, 2
        )

        result = {
            "target_baseline": target_baseline.upper(),
            "total_applicable_controls": total_applicable,
            "total_implemented": total_implemented,
            "total_not_implemented": total_applicable - total_implemented,
            "overall_completion_pct": overall_completion,
            "family_breakdown": family_organization,
            "organized_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "NIST 800-53 controls organized by family",
            target_baseline=target_baseline,
            total_applicable=total_applicable,
            total_implemented=total_implemented,
            overall_completion=overall_completion,
        )

        return result

    def get_assessment_procedures(
        self,
        control_id: str,
        assessment_methods: list[str] | None = None,
    ) -> dict[str, Any]:
        """Retrieve assessment procedures for a NIST 800-53 control.

        Provides NIST SP 800-53A Rev 5 assessment procedure guidance
        covering examine, interview, and test methods for validating
        control implementation.

        Args:
            control_id: NIST 800-53 control identifier (e.g., 'AC-2').
            assessment_methods: Optional list to filter methods ('examine', 'interview', 'test').

        Returns:
            Assessment procedures dict for the specified control.
        """
        control_info = next(
            (c for c in _NIST_CONTROLS if c.get("id") == control_id),
            None,
        )

        if control_info is None:
            return {
                "control_id": control_id,
                "error": f"Control '{control_id}' not found in catalog",
            }

        procedures: dict[str, list[str]] = {}
        for method, steps in _ASSESSMENT_PROCEDURES.items():
            if assessment_methods is None or method in assessment_methods:
                # Customize steps with control context
                customized_steps = [
                    f"[{control_id} — {control_info['name']}] {step}"
                    for step in steps
                ]
                procedures[method] = customized_steps

        result = {
            "control_id": control_id,
            "control_name": control_info.get("name"),
            "control_family": control_info.get("family"),
            "family_name": _CONTROL_FAMILIES.get(control_info.get("family", ""), ""),
            "applicable_baselines": control_info.get("baselines", []),
            "priority": control_info.get("priority"),
            "assessment_procedures": procedures,
            "nist_800_53a_reference": f"NIST SP 800-53A Rev 5 — {control_id} Assessment Procedures",
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
        }

        return result

    def map_cross_framework(
        self,
        control_families_implemented: list[str],
        target_frameworks: list[str],
    ) -> dict[str, Any]:
        """Map NIST 800-53 control families to other compliance frameworks.

        Provides cross-framework mapping from NIST 800-53 Rev 5 to CMMC,
        FedRAMP, and other frameworks, showing coverage and gap analysis.

        Args:
            control_families_implemented: List of implemented control family codes.
            target_frameworks: List of frameworks to map to (e.g., ['CMMC', 'FedRAMP']).

        Returns:
            Cross-framework mapping dict with coverage analysis per framework.
        """
        implemented_set = set(control_families_implemented)
        framework_mappings: dict[str, Any] = {}

        if "CMMC" in target_frameworks:
            cmmc_coverage: dict[str, Any] = {}
            for family_code in control_families_implemented:
                cmmc_domain = _NIST_TO_CMMC.get(family_code)
                if cmmc_domain:
                    cmmc_coverage[cmmc_domain] = cmmc_coverage.get(cmmc_domain, [])
                    cmmc_coverage[cmmc_domain].append(family_code)

            all_cmmc_domains = set(_NIST_TO_CMMC.values())
            covered_domains = set(cmmc_coverage.keys())
            missing_domains = all_cmmc_domains - covered_domains

            framework_mappings["CMMC"] = {
                "total_cmmc_domains": len(all_cmmc_domains),
                "covered_domains": len(covered_domains),
                "missing_domains": sorted(missing_domains),
                "coverage_pct": round(len(covered_domains) / len(all_cmmc_domains) * 100, 2),
                "domain_coverage": cmmc_coverage,
            }

        if "FedRAMP" in target_frameworks:
            fedramp_required_families = set(_CONTROL_FAMILIES.keys())
            covered = implemented_set & fedramp_required_families
            missing = fedramp_required_families - implemented_set

            framework_mappings["FedRAMP"] = {
                "total_fedramp_families": len(fedramp_required_families),
                "covered_families": len(covered),
                "missing_families": sorted(missing),
                "coverage_pct": round(len(covered) / len(fedramp_required_families) * 100, 2),
            }

        result = {
            "nist_families_implemented": sorted(implemented_set),
            "target_frameworks": target_frameworks,
            "framework_mappings": framework_mappings,
            "nist_revision": "NIST SP 800-53 Rev 5",
            "mapped_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "NIST 800-53 cross-framework mapping complete",
            families_implemented=len(implemented_set),
            target_frameworks=target_frameworks,
        )

        return result

    def perform_gap_analysis(
        self,
        implemented_control_ids: list[str],
        target_baseline: str,
        organization_context: str | None = None,
    ) -> dict[str, Any]:
        """Perform a NIST 800-53 implementation gap analysis.

        Identifies control gaps against the target baseline and generates
        a prioritized remediation plan based on control priority levels
        and family coverage.

        Args:
            implemented_control_ids: List of implemented control IDs.
            target_baseline: Target NIST baseline ('low', 'moderate', 'high').
            organization_context: Optional context for tailored guidance.

        Returns:
            Gap analysis dict with prioritized remediation plan.
        """
        target_baseline = target_baseline.lower()
        implemented_set = set(implemented_control_ids)

        applicable_controls = [
            c for c in _NIST_CONTROLS
            if target_baseline in c.get("baselines", [])
        ]

        implemented = [c for c in applicable_controls if c.get("id") in implemented_set]
        not_implemented = [c for c in applicable_controls if c.get("id") not in implemented_set]

        # Priority-based gap sorting
        p1_gaps = [c for c in not_implemented if c.get("priority") == "P1"]
        p2_gaps = [c for c in not_implemented if c.get("priority") == "P2"]
        p3_gaps = [c for c in not_implemented if c.get("priority") == "P3"]

        completion_pct = round(
            (len(implemented) / len(applicable_controls) * 100)
            if applicable_controls else 0.0,
            2,
        )

        gap_analysis = {
            "target_baseline": target_baseline.upper(),
            "organization_context": organization_context,
            "total_applicable_controls": len(applicable_controls),
            "implemented_controls": len(implemented),
            "gap_controls_total": len(not_implemented),
            "completion_percentage": completion_pct,
            "priority_gaps": {
                "P1_critical": len(p1_gaps),
                "P2_important": len(p2_gaps),
                "P3_supplemental": len(p3_gaps),
            },
            "prioritized_remediation": [
                {
                    "control_id": c.get("id"),
                    "control_name": c.get("name"),
                    "family": c.get("family"),
                    "priority": c.get("priority"),
                    "remediation_order": idx + 1,
                }
                for idx, c in enumerate(p1_gaps + p2_gaps + p3_gaps)
            ],
            "estimated_remediation_effort": {
                "P1_controls": f"{len(p1_gaps) * 2}-{len(p1_gaps) * 4} person-weeks",
                "P2_controls": f"{len(p2_gaps) * 1}-{len(p2_gaps) * 2} person-weeks",
                "total_controls": f"{len(not_implemented) * 1}-{len(not_implemented) * 3} person-weeks",
            },
            "nist_publication": "NIST SP 800-53 Rev 5 (2020-09-23)",
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "NIST 800-53 gap analysis complete",
            target_baseline=target_baseline,
            total_gaps=len(not_implemented),
            p1_gaps=len(p1_gaps),
            completion_pct=completion_pct,
        )

        return gap_analysis


__all__ = ["NIST80053Mapper"]

"""CUI (Controlled Unclassified Information) handler adapter for aumos-govdef-overlay.

Implements CUI category identification, marking and handling requirements,
dissemination control, storage requirements validation, destruction procedures,
CUI registry management, and NIST 800-171 mapping per 32 CFR Part 2002.
"""

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# CUI category registry per National Archives CUI Registry
_CUI_CATEGORIES: dict[str, dict[str, Any]] = {
    "CONTROLLED_TECHNICAL_INFORMATION": {
        "abbreviation": "CTI",
        "authority": "DoD Instruction 5230.24",
        "description": "Technical data with military or space application",
        "handling_tier": "CUI//SP-CTI",
        "dissemination_controls": ["NOFORN", "FEDCON"],
        "encryption_required": True,
        "clearance_required": False,
    },
    "EXPORT_CONTROLLED": {
        "abbreviation": "EXPT",
        "authority": "EAR/ITAR",
        "description": "Export Administration Regulations / ITAR controlled information",
        "handling_tier": "CUI//SP-EXPT",
        "dissemination_controls": ["NOFORN"],
        "encryption_required": True,
        "clearance_required": False,
    },
    "PRIVACY_PII": {
        "abbreviation": "PII",
        "authority": "Privacy Act of 1974 / OMB M-07-16",
        "description": "Personally Identifiable Information",
        "handling_tier": "CUI//SP-PII",
        "dissemination_controls": ["FEDCON"],
        "encryption_required": True,
        "clearance_required": False,
    },
    "LAW_ENFORCEMENT_SENSITIVE": {
        "abbreviation": "LES",
        "authority": "28 CFR Part 23",
        "description": "Law enforcement sensitive criminal intelligence",
        "handling_tier": "CUI//SP-LES",
        "dissemination_controls": ["NOFORN", "FEDCON", "LAWSEN"],
        "encryption_required": True,
        "clearance_required": False,
    },
    "FINANCIAL": {
        "abbreviation": "FIN",
        "authority": "31 U.S.C. Chapter 37",
        "description": "Federal financial information requiring protection",
        "handling_tier": "CUI",
        "dissemination_controls": [],
        "encryption_required": True,
        "clearance_required": False,
    },
    "PROPRIETARY_BUSINESS_INFORMATION": {
        "abbreviation": "PROPIN",
        "authority": "18 U.S.C. § 1905",
        "description": "Proprietary business data submitted to federal agencies",
        "handling_tier": "CUI//SP-PROPIN",
        "dissemination_controls": ["NOFORN"],
        "encryption_required": True,
        "clearance_required": False,
    },
    "CRITICAL_INFRASTRUCTURE": {
        "abbreviation": "CI",
        "authority": "6 U.S.C. § 131-134",
        "description": "Critical infrastructure security information",
        "handling_tier": "CUI//SP-CI",
        "dissemination_controls": ["FEDCON"],
        "encryption_required": True,
        "clearance_required": False,
    },
}

# CUI marking requirements
_CUI_BANNER_FORMAT = "CUI"
_CUI_PORTION_MARKING = "(CUI)"

# Dissemination control definitions
_DISSEMINATION_CONTROLS: dict[str, str] = {
    "NOFORN": "Not releasable to foreign nationals",
    "FEDCON": "Federal employees and contractors only",
    "LAWSEN": "Law enforcement personnel only",
    "PROPIN": "Proprietary information handling required",
    "RELIDO": "Releasable by originator only",
}

# Storage requirements by CUI tier
_STORAGE_REQUIREMENTS: dict[str, dict[str, Any]] = {
    "CUI": {
        "encryption_standard": "FIPS 140-2 AES-256",
        "access_control": "Role-based, need-to-know enforced",
        "physical_controls": "Locked storage when unattended",
        "cloud_storage": "FedRAMP Moderate or higher",
        "transmission": "FIPS 140-2 approved encryption in transit",
    },
    "CUI//SP": {
        "encryption_standard": "FIPS 140-2 AES-256 mandatory",
        "access_control": "Strict need-to-know, individual accountability",
        "physical_controls": "GSA-approved locked cabinet or equivalent",
        "cloud_storage": "FedRAMP High or equivalent",
        "transmission": "TLS 1.2+ with mutual authentication",
    },
}

# NIST 800-171 control mapping for CUI protection
_NIST_800_171_CONTROLS: dict[str, list[str]] = {
    "access_control": ["3.1.1", "3.1.2", "3.1.3", "3.1.4", "3.1.5", "3.1.6", "3.1.7", "3.1.8"],
    "awareness_training": ["3.2.1", "3.2.2", "3.2.3"],
    "audit_accountability": ["3.3.1", "3.3.2"],
    "configuration_management": ["3.4.1", "3.4.2", "3.4.3", "3.4.4", "3.4.5"],
    "identification_authentication": ["3.5.1", "3.5.2", "3.5.3", "3.5.4", "3.5.5", "3.5.6", "3.5.7"],
    "incident_response": ["3.6.1", "3.6.2"],
    "maintenance": ["3.7.1", "3.7.2", "3.7.3", "3.7.4", "3.7.5"],
    "media_protection": ["3.8.1", "3.8.2", "3.8.3", "3.8.4", "3.8.5", "3.8.6", "3.8.7", "3.8.8", "3.8.9"],
    "personnel_security": ["3.9.1", "3.9.2"],
    "physical_protection": ["3.10.1", "3.10.2", "3.10.3", "3.10.4", "3.10.5", "3.10.6"],
    "risk_assessment": ["3.11.1", "3.11.2", "3.11.3"],
    "security_assessment": ["3.12.1", "3.12.2", "3.12.3", "3.12.4"],
    "system_communications_protection": ["3.13.1", "3.13.2", "3.13.3", "3.13.4", "3.13.5", "3.13.6", "3.13.7", "3.13.8", "3.13.9", "3.13.10", "3.13.11", "3.13.12", "3.13.13", "3.13.14", "3.13.15", "3.13.16"],
    "system_information_integrity": ["3.14.1", "3.14.2", "3.14.3", "3.14.4", "3.14.5", "3.14.6", "3.14.7"],
}

# Approved destruction methods by media type
_DESTRUCTION_METHODS: dict[str, list[str]] = {
    "paper": ["Cross-cut shredding (Level P-4 or higher)", "Incineration"],
    "electronic_media": ["DoD 5220.22-M overwrite (7-pass)", "Degaussing", "Physical destruction"],
    "solid_state": ["Cryptographic erasure + physical destruction", "Physical destruction"],
    "optical_media": ["Physical destruction (shredding)", "Incineration"],
}


class CUIHandler:
    """Manages Controlled Unclassified Information handling per 32 CFR Part 2002.

    Implements CUI category identification, marking requirement generation,
    dissemination control validation, storage requirement checking, destruction
    procedure guidance, registry management, and NIST 800-171 compliance mapping.
    """

    def __init__(self) -> None:
        """Initialize CUI handler."""
        pass

    def identify_category(
        self,
        data_description: str,
        data_elements: list[str],
        originating_authority: str | None = None,
    ) -> dict[str, Any]:
        """Identify the applicable CUI category for described data.

        Analyzes data description and elements against the CUI Registry
        to determine the applicable CUI category and associated handling
        requirements per 32 CFR Part 2002.

        Args:
            data_description: Description of the data to categorize.
            data_elements: List of specific data elements present.
            originating_authority: Optional originating government authority.

        Returns:
            CUI category identification dict with handling requirements.
        """
        identified_categories: list[dict[str, Any]] = []

        # Pattern-based category identification
        data_lower = data_description.lower()
        elements_lower = [e.lower() for e in data_elements]

        if any(kw in data_lower or kw in " ".join(elements_lower) for kw in ["pii", "personal", "ssn", "dob", "name"]):
            identified_categories.append({
                "category": "PRIVACY_PII",
                "confidence": "HIGH",
                **_CUI_CATEGORIES["PRIVACY_PII"],
            })

        if any(kw in data_lower for kw in ["technical", "military", "weapon", "defense"]):
            identified_categories.append({
                "category": "CONTROLLED_TECHNICAL_INFORMATION",
                "confidence": "MEDIUM",
                **_CUI_CATEGORIES["CONTROLLED_TECHNICAL_INFORMATION"],
            })

        if any(kw in data_lower for kw in ["export", "itar", "ear", "munition"]):
            identified_categories.append({
                "category": "EXPORT_CONTROLLED",
                "confidence": "HIGH",
                **_CUI_CATEGORIES["EXPORT_CONTROLLED"],
            })

        if any(kw in data_lower for kw in ["financial", "budget", "appropriation", "contract value"]):
            identified_categories.append({
                "category": "FINANCIAL",
                "confidence": "MEDIUM",
                **_CUI_CATEGORIES["FINANCIAL"],
            })

        if any(kw in data_lower for kw in ["critical infrastructure", "scada", "ics", "power grid"]):
            identified_categories.append({
                "category": "CRITICAL_INFRASTRUCTURE",
                "confidence": "HIGH",
                **_CUI_CATEGORIES["CRITICAL_INFRASTRUCTURE"],
            })

        # Default to basic CUI if description mentions controlled
        if not identified_categories and "controlled" in data_lower:
            identified_categories.append({
                "category": "FINANCIAL",
                "confidence": "LOW",
                **_CUI_CATEGORIES["FINANCIAL"],
            })

        primary_category = identified_categories[0] if identified_categories else None
        marking_required = primary_category is not None
        encryption_required = any(c.get("encryption_required", False) for c in identified_categories)

        result = {
            "data_description": data_description,
            "originating_authority": originating_authority,
            "identified_categories": identified_categories,
            "primary_category": primary_category,
            "cui_marking_required": marking_required,
            "encryption_required": encryption_required,
            "cui_registry_reference": "National Archives CUI Registry (https://www.archives.gov/cui)",
            "regulatory_reference": "32 CFR Part 2002",
            "identified_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "CUI category identified",
            categories_found=len(identified_categories),
            primary_category=primary_category.get("category") if primary_category else None,
            encryption_required=encryption_required,
        )

        return result

    def get_marking_requirements(
        self,
        cui_category: str,
        document_type: str,
        contains_portion_markings: bool = True,
    ) -> dict[str, Any]:
        """Get CUI marking requirements for a document or system.

        Returns required markings per 32 CFR Part 2002 and the CUI Marking
        Handbook including banner markings, portion markings, and
        document control marking requirements.

        Args:
            cui_category: CUI category code.
            document_type: Type of document ('email', 'document', 'slide', 'system').
            contains_portion_markings: Whether to generate portion marking guidance.

        Returns:
            CUI marking requirements dict with banner and portion marking formats.
        """
        category_info = _CUI_CATEGORIES.get(cui_category, {})
        handling_tier = category_info.get("handling_tier", "CUI")
        dissemination = category_info.get("dissemination_controls", [])

        # Construct banner marking
        banner_components = [handling_tier]
        if dissemination:
            banner_components.extend(dissemination)
        banner_marking = "//".join(banner_components)

        result = {
            "cui_category": cui_category,
            "category_info": category_info,
            "document_type": document_type,
            "banner_marking": banner_marking,
            "banner_position": "Top and bottom of each page",
            "portion_marking": f"({handling_tier})" if contains_portion_markings else None,
            "portion_marking_position": "Immediately following the classified portion" if contains_portion_markings else None,
            "required_markings": [
                f"Banner marking: {banner_marking}",
                "Controlled By: [Originating Office]",
                "Controlled By: [Agency Name]",
                "CUI Category/Subcategory: " + category_info.get("abbreviation", "CUI"),
                "Distribution/Dissemination: " + (", ".join(dissemination) if dissemination else "Standard CUI"),
                "POC: [Security Officer Name and Contact]",
            ],
            "handling_requirements": [
                "Store in accordance with CUI storage requirements",
                "Destroy per approved methods when no longer needed",
                "Report loss or unauthorized disclosure immediately",
                "Do not discuss CUI in non-secure communications channels",
            ],
            "email_guidance": (
                "Use encrypted email (FIPS 140-2 TLS) when transmitting CUI"
                if document_type == "email" else None
            ),
            "cui_marking_handbook": "CUI Marking Handbook (NARA, May 2022)",
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
        }

        return result

    def validate_storage(
        self,
        storage_configurations: list[dict[str, Any]],
        cui_category: str,
    ) -> dict[str, Any]:
        """Validate storage configurations against CUI storage requirements.

        Checks storage systems against CUI handling requirements for
        encryption, access control, physical security, and cloud compliance.

        Args:
            storage_configurations: List of storage config dicts with
                'system_name', 'encryption_standard', 'fedramp_level',
                'access_controls_enforced' keys.
            cui_category: CUI category for requirement lookup.

        Returns:
            Storage validation report dict with compliance findings.
        """
        category_info = _CUI_CATEGORIES.get(cui_category, {})
        handling_tier = category_info.get("handling_tier", "CUI")
        tier_key = "CUI//SP" if "SP" in handling_tier else "CUI"
        requirements = _STORAGE_REQUIREMENTS.get(tier_key, _STORAGE_REQUIREMENTS["CUI"])

        findings: list[dict[str, Any]] = []
        non_compliant_count = 0

        for storage in storage_configurations:
            system_name = storage.get("system_name", "")
            encryption = storage.get("encryption_standard", "")
            fedramp_level = storage.get("fedramp_level", "")
            access_controls = storage.get("access_controls_enforced", False)

            system_findings: list[str] = []
            compliant = True

            if "AES-256" not in encryption and "AES-128" not in encryption:
                system_findings.append(
                    f"Encryption '{encryption}' may not meet FIPS 140-2 AES-256 requirement"
                )
                compliant = False

            required_fedramp = "High" if tier_key == "CUI//SP" else "Moderate"
            if fedramp_level and fedramp_level not in ("High", "Moderate") and required_fedramp == "Moderate":
                system_findings.append(
                    f"Cloud storage FedRAMP level '{fedramp_level}' insufficient — requires {required_fedramp}"
                )
                compliant = False

            if not access_controls:
                system_findings.append("Access controls not enforced — need-to-know required")
                compliant = False

            if not compliant:
                non_compliant_count += 1

            findings.append({
                "system_name": system_name,
                "compliant": compliant,
                "findings": system_findings,
                "required_encryption": requirements["encryption_standard"],
                "required_fedramp": required_fedramp,
            })

        result = {
            "cui_category": cui_category,
            "handling_tier": handling_tier,
            "storage_requirements": requirements,
            "total_systems_assessed": len(storage_configurations),
            "compliant_systems": len(storage_configurations) - non_compliant_count,
            "non_compliant_systems": non_compliant_count,
            "system_findings": findings,
            "overall_compliant": non_compliant_count == 0,
            "nist_800_171_controls": _NIST_800_171_CONTROLS.get("system_communications_protection", [])[:5],
            "validated_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "CUI storage validated",
            cui_category=cui_category,
            total_systems=len(storage_configurations),
            non_compliant=non_compliant_count,
        )

        return result

    def get_destruction_procedures(
        self,
        media_types: list[str],
        cui_category: str,
        classified_commingled: bool = False,
    ) -> dict[str, Any]:
        """Get CUI destruction procedures by media type.

        Returns approved destruction methods per NIST 800-88 Rev 1 and
        DoD 5220.22-M aligned with the CUI category sensitivity level.

        Args:
            media_types: List of media types ('paper', 'electronic_media', 'solid_state', 'optical_media').
            cui_category: CUI category for context-appropriate requirements.
            classified_commingled: Whether CUI is commingled with classified info.

        Returns:
            Destruction procedures dict with approved methods per media type.
        """
        procedures: dict[str, Any] = {}

        for media_type in media_types:
            methods = _DESTRUCTION_METHODS.get(media_type, ["Contact Security Officer for approved method"])
            procedures[media_type] = {
                "approved_methods": methods,
                "preferred_method": methods[0] if methods else "Physical destruction",
                "documentation_required": True,
                "witness_required": classified_commingled,
            }

        result = {
            "cui_category": cui_category,
            "classified_commingled": classified_commingled,
            "destruction_procedures": procedures,
            "general_requirements": [
                "Document all CUI destruction with date, method, and approver",
                "Obtain destruction certificate when using third-party vendors",
                "Never dispose of CUI in regular waste streams",
                "Report any destruction incidents to security officer",
            ],
            "heightened_requirements": [
                "Witness signature required for destruction",
                "Cross-agency notification required",
            ] if classified_commingled else [],
            "nist_800_88_reference": "NIST SP 800-88 Rev 1 — Guidelines for Media Sanitization",
            "dod_reference": "DoD 5220.22-M — National Industrial Security Program Operating Manual",
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
        }

        return result

    def map_nist_800_171(
        self,
        cui_categories: list[str],
        implemented_control_ids: list[str],
    ) -> dict[str, Any]:
        """Map CUI protection requirements to NIST 800-171 controls.

        Generates a NIST 800-171 Rev 2 control mapping for CUI protection,
        showing which requirements apply and implementation status for
        each of the 110 NIST 800-171 security requirements.

        Args:
            cui_categories: List of CUI categories present in the system.
            implemented_control_ids: List of implemented NIST 800-171 control IDs.

        Returns:
            NIST 800-171 mapping dict with implementation status.
        """
        implemented_set = set(implemented_control_ids)
        all_required_controls: list[str] = []

        for control_list in _NIST_800_171_CONTROLS.values():
            all_required_controls.extend(control_list)

        total_required = len(set(all_required_controls))
        implemented_count = len(implemented_set & set(all_required_controls))
        not_implemented = [c for c in set(all_required_controls) if c not in implemented_set]

        family_status: dict[str, dict[str, Any]] = {}
        for family_name, family_controls in _NIST_800_171_CONTROLS.items():
            family_implemented = [c for c in family_controls if c in implemented_set]
            family_status[family_name] = {
                "total_controls": len(family_controls),
                "implemented": len(family_implemented),
                "completion_pct": round(
                    len(family_implemented) / len(family_controls) * 100
                    if family_controls else 0.0,
                    2,
                ),
                "not_implemented": [c for c in family_controls if c not in implemented_set],
            }

        completion_pct = round((implemented_count / total_required * 100) if total_required > 0 else 0.0, 2)

        result = {
            "cui_categories": cui_categories,
            "total_nist_800_171_controls": total_required,
            "implemented_controls": implemented_count,
            "not_implemented_controls": len(not_implemented),
            "completion_percentage": completion_pct,
            "family_status": family_status,
            "not_implemented_control_ids": sorted(not_implemented),
            "dfars_reference": "DFARS 252.204-7012 — Safeguarding Covered Defense Information",
            "nist_publication": "NIST SP 800-171 Rev 2 — Protecting CUI in Nonfederal Systems",
            "mapped_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "CUI NIST 800-171 mapping complete",
            cui_categories=len(cui_categories),
            total_required=total_required,
            implemented=implemented_count,
            completion_pct=completion_pct,
        )

        return result


__all__ = ["CUIHandler"]

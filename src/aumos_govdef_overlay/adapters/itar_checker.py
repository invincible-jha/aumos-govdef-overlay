"""ITAR (International Traffic in Arms Regulations) compliance checker.

GAP-311: ITAR Compliance Tracking.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


class USMLCategory(str, Enum):
    """United States Munitions List (USML) categories under ITAR (22 CFR 121)."""

    CAT_I = "I"         # Firearms, Close Assault Weapons
    CAT_II = "II"       # Artillery Projectors
    CAT_III = "III"     # Ammunition / Ordnance
    CAT_IV = "IV"       # Launch Vehicles, Guided Missiles
    CAT_V = "V"         # Explosives and Energetic Materials
    CAT_VI = "VI"       # Vessels of War
    CAT_VII = "VII"     # Tanks and Military Vehicles
    CAT_VIII = "VIII"   # Aircraft and Related Articles
    CAT_IX = "IX"       # Military Training Equipment
    CAT_X = "X"         # Personal Protective Equipment
    CAT_XI = "XI"       # Military Electronics
    CAT_XII = "XII"     # Fire Control / Imaging
    CAT_XIII = "XIII"   # Auxiliary Military Equipment
    CAT_XIV = "XIV"     # Toxicological Agents
    CAT_XV = "XV"       # Spacecraft Systems
    CAT_XVI = "XVI"     # Nuclear Weapons
    CAT_XVII = "XVII"   # Classified Articles
    CAT_XVIII = "XVIII" # Directed Energy Weapons
    CAT_XIX = "XIX"     # Gas Turbine Engines
    CAT_XX = "XX"       # Submersible Vessels
    CAT_XXI = "XXI"     # Miscellaneous Articles


class ExportLicenseStatus(str, Enum):
    """Export license status per DDTC authorization."""

    NOT_REQUIRED = "not_required"
    LICENSE_REQUIRED = "license_required"
    LICENSE_GRANTED = "license_granted"
    LICENSE_PENDING = "license_pending"
    LICENSE_DENIED = "license_denied"
    EXEMPTION_APPLIES = "exemption_applies"


@dataclass
class ITARRecord:
    """ITAR compliance record for a controlled article or technology."""

    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    article_description: str = ""
    usml_categories: list[str] = field(default_factory=list)
    export_license_status: ExportLicenseStatus = ExportLicenseStatus.NOT_REQUIRED
    license_number: str | None = None
    authorized_recipients: list[str] = field(default_factory=list)
    foreign_national_access_restricted: bool = True
    us_person_access_only: bool = False
    technical_data_controlled: bool = False
    notes: str = ""


@dataclass
class ForeignNationalAccessRecord:
    """Foreign national access control record per ITAR 22 CFR 120.39."""

    person_id: str
    nationality: str
    employer: str
    access_level: str
    requires_export_license: bool
    license_status: ExportLicenseStatus
    itar_exemption: str | None = None  # e.g., ITAR 126.5, 126.18


class ITARChecker:
    """ITAR compliance checker for controlled articles and technology.

    Implements USML category mapping, foreign national access controls,
    and export license tracking per 22 CFR Parts 120-130.

    Key principles:
    - Technical data under ITAR cannot be shared with foreign nationals without license
    - "Deemed exports" apply even within the US to foreign national employees
    - US persons include citizens, LPRs, asylees, and refugees (22 CFR 120.15)
    """

    # Countries currently embargoed under ITAR (22 CFR 126.1)
    EMBARGOED_COUNTRIES: frozenset[str] = frozenset([
        "Cuba", "Iran", "North Korea", "Sudan", "Syria",
        "Russia", "Belarus",  # Added post-2022
    ])

    # ITAR exemptions frequently applied to defense contractors
    COMMON_EXEMPTIONS: dict[str, str] = {
        "ITAR_126_5": "Canadian exemption — bilateral defense cooperation",
        "ITAR_126_7": "NATO / Australia / Japan / South Korea exemption",
        "ITAR_126_18": "Foreign affiliate exemption — wholly owned US subsidiary",
        "ITAR_125_4_b_1": "Published information exemption",
        "ITAR_125_4_b_11": "Fundamental research exemption",
    }

    def check_article(
        self,
        article_description: str,
        technical_data_keywords: list[str],
    ) -> dict[str, Any]:
        """Determine if an article or technology is ITAR-controlled.

        Args:
            article_description: Description of the article or technology.
            technical_data_keywords: Keywords to check against USML categories.

        Returns:
            Dict with is_controlled, usml_categories, and recommendations.
        """
        description_lower = article_description.lower()
        matched_categories: list[str] = []

        # Keyword-based USML classification heuristics
        _usml_keywords: dict[str, list[str]] = {
            USMLCategory.CAT_VIII.value: ["aircraft", "uav", "drone", "avionics", "flight control"],
            USMLCategory.CAT_XI.value: ["radar", "sonar", "iff", "electronic warfare", "jamming"],
            USMLCategory.CAT_XII.value: ["infrared", "thermal imaging", "fire control", "targeting"],
            USMLCategory.CAT_XV.value: ["satellite", "spacecraft", "launch vehicle", "telemetry"],
            USMLCategory.CAT_XVI.value: ["nuclear", "radiological", "fissile"],
        }

        for category, keywords in _usml_keywords.items():
            if any(kw in description_lower for kw in keywords):
                matched_categories.append(category)
            if any(kw.lower() in description_lower for kw in technical_data_keywords):
                if category not in matched_categories:
                    matched_categories.append(category)

        is_controlled = len(matched_categories) > 0

        return {
            "is_controlled": is_controlled,
            "usml_categories": matched_categories,
            "export_license_required": is_controlled,
            "recommendations": (
                [f"File DDTC license application for USML categories: {matched_categories}"]
                if is_controlled
                else ["Article appears to be EAR99 or not ITAR-controlled. Confirm with legal."]
            ),
        }

    def assess_foreign_national_access(
        self,
        nationality: str,
        access_to_categories: list[str],
    ) -> ForeignNationalAccessRecord:
        """Assess ITAR requirements for a foreign national's system access.

        Deemed exports apply to controlled technical data shared with foreign
        nationals even within the US (22 CFR 120.17).

        Args:
            nationality: Country of nationality/citizenship.
            access_to_categories: USML categories the person would access.

        Returns:
            ForeignNationalAccessRecord with license status.
        """
        is_embargoed = nationality in self.EMBARGOED_COUNTRIES
        has_controlled_access = len(access_to_categories) > 0

        if is_embargoed:
            license_status = ExportLicenseStatus.LICENSE_REQUIRED
        elif has_controlled_access:
            license_status = ExportLicenseStatus.LICENSE_REQUIRED
        else:
            license_status = ExportLicenseStatus.NOT_REQUIRED

        record = ForeignNationalAccessRecord(
            person_id=str(uuid.uuid4()),
            nationality=nationality,
            employer="AumOS Customer",
            access_level="read" if has_controlled_access else "none",
            requires_export_license=license_status == ExportLicenseStatus.LICENSE_REQUIRED,
            license_status=license_status,
            itar_exemption="ITAR_126_18" if not is_embargoed and has_controlled_access else None,
        )

        logger.info(
            "itar_foreign_national_assessed",
            nationality=nationality,
            license_required=record.requires_export_license,
            embargoed=is_embargoed,
        )
        return record

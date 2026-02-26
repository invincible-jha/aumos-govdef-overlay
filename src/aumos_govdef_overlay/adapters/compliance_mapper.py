"""Compliance framework cross-mapping adapter for aumos-govdef-overlay.

Provides mappings between FedRAMP, NIST 800-53, CMMC, and DoD IL levels
to enable cross-framework compliance tracking and gap analysis.
"""

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# NIST 800-53 Rev 5 control families
NIST_CONTROL_FAMILIES: dict[str, str] = {
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

# NIST 800-53 Rev 5 to CMMC 2.0 domain mapping
NIST_TO_CMMC_DOMAIN: dict[str, str] = {
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

# FedRAMP High controls that map to IL5 requirements
IL5_REQUIRED_CONTROL_FAMILIES = {"AC", "AU", "CA", "CM", "IA", "IR", "SC", "SI"}

# FedRAMP Moderate controls that map to IL4 requirements
IL4_REQUIRED_CONTROL_FAMILIES = {"AC", "AT", "AU", "CA", "CM", "CP", "IA", "IR", "MA", "MP", "PE", "PS", "RA", "SA", "SC", "SI"}


class ComplianceMapper:
    """Maps controls and requirements across compliance frameworks.

    Provides cross-framework analysis to identify control overlaps,
    gaps, and inheritance opportunities between FedRAMP, NIST 800-53,
    CMMC, and DoD Impact Levels.
    """

    def get_cmmc_domain_for_nist_family(self, nist_family: str) -> str | None:
        """Map a NIST 800-53 control family to its CMMC 2.0 domain.

        Args:
            nist_family: NIST control family code (e.g., "AC", "AU").

        Returns:
            Corresponding CMMC domain name or None if no mapping exists.
        """
        return NIST_TO_CMMC_DOMAIN.get(nist_family)

    def get_nist_families_for_il_level(self, il_level: int) -> set[str]:
        """Get the NIST control families required for a DoD Impact Level.

        Args:
            il_level: DoD Impact Level (4 or 5).

        Returns:
            Set of NIST control family codes required for the IL level.
        """
        if il_level >= 5:
            return IL5_REQUIRED_CONTROL_FAMILIES
        return IL4_REQUIRED_CONTROL_FAMILIES

    def get_fedramp_baseline_for_il_level(self, il_level: int) -> str:
        """Map a DoD Impact Level to the equivalent FedRAMP baseline.

        Args:
            il_level: DoD Impact Level (4 or 5).

        Returns:
            FedRAMP baseline name (moderate or high).
        """
        if il_level >= 5:
            return "high"
        return "moderate"

    def get_cmmc_level_for_fedramp_impact(self, fedramp_impact: str) -> int:
        """Map a FedRAMP impact level to the minimum required CMMC level.

        Args:
            fedramp_impact: FedRAMP impact level (low/moderate/high).

        Returns:
            Minimum CMMC level required (1, 2, or 3).
        """
        mapping = {
            "low": 1,
            "moderate": 2,
            "high": 3,
        }
        return mapping.get(fedramp_impact, 2)

    def analyze_cross_framework_gaps(
        self,
        implemented_nist_families: list[str],
        target_fedramp_level: str,
        target_cmmc_level: int,
        target_il_level: int,
    ) -> dict:
        """Analyze compliance gaps across all frameworks simultaneously.

        Args:
            implemented_nist_families: List of NIST control families with
                at least partial implementation.
            target_fedramp_level: Target FedRAMP impact level.
            target_cmmc_level: Target CMMC certification level.
            target_il_level: Target DoD Impact Level.

        Returns:
            Dictionary containing gap analysis across all frameworks.
        """
        implemented_set = set(implemented_nist_families)
        il_required = self.get_nist_families_for_il_level(target_il_level)
        il_gaps = il_required - implemented_set

        # CMMC domains covered by implemented NIST families
        covered_cmmc_domains = {
            self.get_cmmc_domain_for_nist_family(family)
            for family in implemented_set
            if self.get_cmmc_domain_for_nist_family(family) is not None
        }

        logger.info(
            "Cross-framework gap analysis completed",
            implemented_families=len(implemented_set),
            il_level=target_il_level,
            il_gaps=len(il_gaps),
            cmmc_level=target_cmmc_level,
        )

        return {
            "fedramp": {
                "target_level": target_fedramp_level,
                "required_cmmc_level": self.get_cmmc_level_for_fedramp_impact(target_fedramp_level),
            },
            "nist": {
                "implemented_families": sorted(implemented_set),
                "total_families": len(NIST_CONTROL_FAMILIES),
                "coverage_percentage": round(
                    (len(implemented_set) / len(NIST_CONTROL_FAMILIES)) * 100, 2
                ),
            },
            "cmmc": {
                "target_level": target_cmmc_level,
                "covered_domains": sorted(covered_cmmc_domains),
            },
            "il_level": {
                "target": target_il_level,
                "required_families": sorted(il_required),
                "gap_families": sorted(il_gaps),
                "gap_count": len(il_gaps),
                "readiness_percentage": round(
                    ((len(il_required) - len(il_gaps)) / max(len(il_required), 1)) * 100, 2
                ),
            },
        }


__all__ = [
    "ComplianceMapper",
    "NIST_CONTROL_FAMILIES",
    "NIST_TO_CMMC_DOMAIN",
]

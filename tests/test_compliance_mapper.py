"""Unit tests for the ComplianceMapper adapter."""

import pytest

from aumos_govdef_overlay.adapters.compliance_mapper import ComplianceMapper


class TestComplianceMapper:
    """Tests for ComplianceMapper cross-framework analysis."""

    def test_get_cmmc_domain_for_nist_family_known(self) -> None:
        """Should return the CMMC domain for a known NIST family."""
        mapper = ComplianceMapper()
        domain = mapper.get_cmmc_domain_for_nist_family("AC")
        assert domain == "Access Control"

    def test_get_cmmc_domain_for_nist_family_unknown(self) -> None:
        """Should return None for an unknown NIST family."""
        mapper = ComplianceMapper()
        domain = mapper.get_cmmc_domain_for_nist_family("XX")
        assert domain is None

    def test_get_nist_families_for_il5_is_subset_of_il4(self) -> None:
        """IL5 required families should be a strict subset of IL4 required families."""
        mapper = ComplianceMapper()
        il4_families = mapper.get_nist_families_for_il_level(4)
        il5_families = mapper.get_nist_families_for_il_level(5)
        assert il5_families.issubset(il4_families)

    def test_get_fedramp_baseline_for_il4(self) -> None:
        """IL4 should map to FedRAMP moderate baseline."""
        mapper = ComplianceMapper()
        assert mapper.get_fedramp_baseline_for_il_level(4) == "moderate"

    def test_get_fedramp_baseline_for_il5(self) -> None:
        """IL5 should map to FedRAMP high baseline."""
        mapper = ComplianceMapper()
        assert mapper.get_fedramp_baseline_for_il_level(5) == "high"

    def test_get_cmmc_level_for_fedramp_impact_high(self) -> None:
        """FedRAMP High should require CMMC Level 3."""
        mapper = ComplianceMapper()
        assert mapper.get_cmmc_level_for_fedramp_impact("high") == 3

    def test_get_cmmc_level_for_fedramp_impact_low(self) -> None:
        """FedRAMP Low should require CMMC Level 1."""
        mapper = ComplianceMapper()
        assert mapper.get_cmmc_level_for_fedramp_impact("low") == 1

    def test_analyze_cross_framework_gaps_all_implemented(self) -> None:
        """Gap analysis with all IL4 families implemented should show 0 gaps."""
        mapper = ComplianceMapper()
        il4_families = list(mapper.get_nist_families_for_il_level(4))
        result = mapper.analyze_cross_framework_gaps(
            implemented_nist_families=il4_families,
            target_fedramp_level="moderate",
            target_cmmc_level=2,
            target_il_level=4,
        )
        assert result["il_level"]["gap_count"] == 0
        assert result["il_level"]["readiness_percentage"] == 100.0

    def test_analyze_cross_framework_gaps_partial_implementation(self) -> None:
        """Gap analysis with partial implementation should report gaps."""
        mapper = ComplianceMapper()
        result = mapper.analyze_cross_framework_gaps(
            implemented_nist_families=["AC", "AU"],
            target_fedramp_level="high",
            target_cmmc_level=3,
            target_il_level=5,
        )
        assert result["il_level"]["gap_count"] > 0
        assert result["fedramp"]["required_cmmc_level"] == 3
        assert "AC" in result["nist"]["implemented_families"]

    def test_analyze_cross_framework_gaps_empty_implementation(self) -> None:
        """Gap analysis with no implementation should show full gap."""
        mapper = ComplianceMapper()
        result = mapper.analyze_cross_framework_gaps(
            implemented_nist_families=[],
            target_fedramp_level="moderate",
            target_cmmc_level=2,
            target_il_level=4,
        )
        il4_required = len(mapper.get_nist_families_for_il_level(4))
        assert result["il_level"]["gap_count"] == il4_required
        assert result["il_level"]["readiness_percentage"] == 0.0

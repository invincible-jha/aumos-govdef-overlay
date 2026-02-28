"""State-level compliance adapter for StateRAMP and TX-RAMP.

GAP-308: StateRAMP/TX-RAMP Support.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


class StateRampLevel(str, Enum):
    """StateRAMP authorization levels."""

    LOW_PLUS = "low_plus"
    MODERATE = "moderate"
    HIGH = "high"


class TXRampCategory(str, Enum):
    """TX-RAMP authorization categories per Texas DIR rule 202."""

    CATEGORY_1 = "category_1"  # Confidential data, non-sensitive
    CATEGORY_2 = "category_2"  # Sensitive personal information
    CATEGORY_3 = "category_3"  # Sensitive critical infrastructure


# StateRAMP control counts per authorization level
STATE_RAMP_CONTROL_COUNTS: dict[StateRampLevel, int] = {
    StateRampLevel.LOW_PLUS: 125,
    StateRampLevel.MODERATE: 275,
    StateRampLevel.HIGH: 421,
}

# TX-RAMP specific additional requirements per category
TX_RAMP_ADDITIONAL_REQUIREMENTS: dict[TXRampCategory, list[str]] = {
    TXRampCategory.CATEGORY_1: [
        "texas_dir_202_registered",
        "data_breach_notification_72h",
    ],
    TXRampCategory.CATEGORY_2: [
        "texas_dir_202_registered",
        "data_breach_notification_72h",
        "texas_privacy_act_compliant",
        "sensitive_data_encrypted",
        "employee_background_checks",
    ],
    TXRampCategory.CATEGORY_3: [
        "texas_dir_202_registered",
        "data_breach_notification_72h",
        "texas_privacy_act_compliant",
        "sensitive_data_encrypted",
        "employee_background_checks",
        "critical_infrastructure_security_plan",
        "annual_penetration_testing",
        "incident_response_24h",
    ],
}


@dataclass
class StateComplianceGap:
    """Single compliance gap identified during assessment."""

    control_id: str
    control_name: str
    gap_description: str
    remediation_guidance: str
    priority: str  # critical | high | medium | low


@dataclass
class StateComplianceResult:
    """State compliance assessment result."""

    framework: str
    authorization_level: str
    controls_total: int
    controls_met: int
    controls_not_met: int
    compliance_score: float
    gaps: list[StateComplianceGap] = field(default_factory=list)
    authorized: bool = False
    authorization_conditions: list[str] = field(default_factory=list)


class StateComplianceAdapter:
    """Compliance assessment for StateRAMP and TX-RAMP frameworks.

    StateRAMP provides government cloud security standards for US state agencies.
    TX-RAMP is the Texas-specific framework per Texas DIR rule 202.
    Both use NIST 800-53 as the underlying control baseline.
    """

    def assess_stateramp(
        self,
        target_level: StateRampLevel,
        implemented_controls: list[str],
        environment_config: dict[str, Any],
    ) -> StateComplianceResult:
        """Assess StateRAMP compliance for a given authorization level.

        Args:
            target_level: Requested StateRAMP authorization level.
            implemented_controls: List of implemented NIST 800-53 control IDs.
            environment_config: Deployment configuration assertions.

        Returns:
            StateComplianceResult with gap analysis.
        """
        required_count = STATE_RAMP_CONTROL_COUNTS[target_level]
        met = min(len(implemented_controls), required_count)
        not_met = max(required_count - met, 0)
        score = met / required_count if required_count > 0 else 0.0

        # StateRAMP requires 100% mandatory control coverage for authorization
        authorized = score >= 1.0
        conditions: list[str] = []
        if not authorized:
            conditions.append(
                f"Implement {not_met} additional NIST 800-53 controls required for {target_level.value}"
            )

        logger.info(
            "stateramp_assessment",
            level=target_level.value,
            controls_met=met,
            controls_total=required_count,
            authorized=authorized,
        )
        return StateComplianceResult(
            framework="StateRAMP",
            authorization_level=target_level.value,
            controls_total=required_count,
            controls_met=met,
            controls_not_met=not_met,
            compliance_score=score,
            authorized=authorized,
            authorization_conditions=conditions,
        )

    def assess_txramp(
        self,
        target_category: TXRampCategory,
        environment_config: dict[str, Any],
    ) -> StateComplianceResult:
        """Assess TX-RAMP compliance for a given category.

        TX-RAMP inherits StateRAMP requirements plus Texas-specific requirements
        defined in Texas DIR rule 202.

        Args:
            target_category: Requested TX-RAMP category.
            environment_config: Deployment configuration assertions.

        Returns:
            StateComplianceResult with TX-RAMP specific gap analysis.
        """
        required = TX_RAMP_ADDITIONAL_REQUIREMENTS[target_category]
        gaps: list[StateComplianceGap] = []

        for req in required:
            if not environment_config.get(req, False):
                gaps.append(
                    StateComplianceGap(
                        control_id=req,
                        control_name=req.replace("_", " ").title(),
                        gap_description=f"TX-RAMP {target_category.value} requires: {req}",
                        remediation_guidance=f"Implement {req} per Texas DIR Rule 202",
                        priority="high" if "critical" in req or "breach" in req else "medium",
                    )
                )

        met = len(required) - len(gaps)
        score = met / len(required) if required else 1.0
        authorized = len(gaps) == 0

        logger.info(
            "txramp_assessment",
            category=target_category.value,
            requirements_met=met,
            requirements_total=len(required),
            authorized=authorized,
        )
        return StateComplianceResult(
            framework="TX-RAMP",
            authorization_level=target_category.value,
            controls_total=len(required),
            controls_met=met,
            controls_not_met=len(gaps),
            compliance_score=score,
            gaps=gaps,
            authorized=authorized,
        )

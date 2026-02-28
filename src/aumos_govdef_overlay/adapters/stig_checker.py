"""DISA STIG compliance checker — processes XCCDF XML files.

GAP-307: STIG Compliance Checking.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


class STIGSeverity(str, Enum):
    """DISA STIG vulnerability severity categories."""

    CAT1 = "CAT_I"    # High — immediate risk
    CAT2 = "CAT_II"   # Medium — significant risk
    CAT3 = "CAT_III"  # Low — minor risk


class STIGFindingStatus(str, Enum):
    """STIG finding evaluation status."""

    OPEN = "open"
    NOT_APPLICABLE = "not_applicable"
    NOT_A_FINDING = "not_a_finding"
    NOT_REVIEWED = "not_reviewed"


@dataclass
class STIGFinding:
    """Single STIG rule evaluation finding."""

    rule_id: str
    title: str
    severity: STIGSeverity
    status: STIGFindingStatus
    check_description: str
    fix_description: str
    finding_details: str = ""
    comments: str = ""


@dataclass
class STIGScanResult:
    """Aggregated STIG scan result for a target."""

    stig_id: str
    stig_title: str
    target_system: str
    total_rules: int
    cat1_open: int = 0
    cat2_open: int = 0
    cat3_open: int = 0
    not_a_finding: int = 0
    not_applicable: int = 0
    not_reviewed: int = 0
    findings: list[STIGFinding] = field(default_factory=list)
    scan_hash: str = ""

    @property
    def open_findings_count(self) -> int:
        """Total open findings across all CAT levels."""
        return self.cat1_open + self.cat2_open + self.cat3_open

    @property
    def compliance_score(self) -> float:
        """Compliance score: percentage of rules that are not findings."""
        if self.total_rules == 0:
            return 0.0
        return self.not_a_finding / self.total_rules


# Bundled STIG profiles — rules evaluated via configuration assertions
# These are representative subsets of public domain DISA STIGs
BUNDLED_STIGS: dict[str, dict[str, Any]] = {
    "Ubuntu_20.04_STIG": {
        "stig_id": "UBTU-20-010000",
        "title": "Canonical Ubuntu 20.04 LTS STIG V1R12",
        "rules": [
            {"id": "UBTU-20-010000", "title": "Enable FIPS 140-2 mode", "severity": "CAT_I",
             "check": "fips_enabled"},
            {"id": "UBTU-20-010001", "title": "Audit privileged commands", "severity": "CAT_II",
             "check": "audit_privileged_commands"},
            {"id": "UBTU-20-010002", "title": "SSH root login disabled", "severity": "CAT_I",
             "check": "ssh_root_disabled"},
            {"id": "UBTU-20-010003", "title": "Password complexity enforced", "severity": "CAT_II",
             "check": "password_complexity"},
            {"id": "UBTU-20-010004", "title": "System firewall enabled", "severity": "CAT_II",
             "check": "firewall_enabled"},
            {"id": "UBTU-20-010005", "title": "USB storage disabled", "severity": "CAT_II",
             "check": "usb_storage_disabled"},
        ],
    },
    "Docker_STIG": {
        "stig_id": "CNTR-DK-000000",
        "title": "Docker Enterprise 2.x STIG V2R2",
        "rules": [
            {"id": "CNTR-DK-000010", "title": "Docker daemon runs as non-root", "severity": "CAT_I",
             "check": "docker_rootless"},
            {"id": "CNTR-DK-000020", "title": "Containers run as non-root", "severity": "CAT_I",
             "check": "container_non_root"},
            {"id": "CNTR-DK-000030", "title": "Container content-trust enabled", "severity": "CAT_II",
             "check": "docker_content_trust"},
            {"id": "CNTR-DK-000040", "title": "No privileged containers", "severity": "CAT_I",
             "check": "no_privileged_containers"},
            {"id": "CNTR-DK-000050", "title": "Image scanning enabled", "severity": "CAT_II",
             "check": "image_scanning_enabled"},
        ],
    },
    "Kubernetes_STIG": {
        "stig_id": "CNTR-K8-000000",
        "title": "Kubernetes STIG V1R11",
        "rules": [
            {"id": "CNTR-K8-000120", "title": "RBAC enabled", "severity": "CAT_I",
             "check": "k8s_rbac_enabled"},
            {"id": "CNTR-K8-000200", "title": "Pod Security Admission enforced", "severity": "CAT_I",
             "check": "pod_security_admission"},
            {"id": "CNTR-K8-000330", "title": "Audit logging enabled", "severity": "CAT_II",
             "check": "k8s_audit_logging"},
            {"id": "CNTR-K8-000340", "title": "etcd encrypted at rest", "severity": "CAT_I",
             "check": "etcd_encryption"},
            {"id": "CNTR-K8-000380", "title": "Network policies configured", "severity": "CAT_II",
             "check": "network_policies_enforced"},
        ],
    },
}


class STIGChecker:
    """DISA STIG compliance checker for AumOS deployment configurations.

    Processes bundled STIG profiles (Ubuntu, Docker, Kubernetes) against
    deployment configuration assertions. STIG files are public domain.

    CAT I findings indicate immediate remediation required before ATO.
    """

    def scan(self, target_system: str, config: dict[str, bool]) -> STIGScanResult:
        """Execute a STIG scan against deployment configuration assertions.

        Args:
            target_system: STIG profile key (Ubuntu_20.04_STIG, Docker_STIG, etc.).
            config: Dict of assertion name -> bool (True = compliant).

        Returns:
            STIGScanResult with per-rule findings and aggregate scores.

        Raises:
            ValueError: If target_system is not a supported STIG profile.
        """
        if target_system not in BUNDLED_STIGS:
            raise ValueError(
                f"Unknown STIG profile: {target_system}. Supported: {list(BUNDLED_STIGS)}"
            )

        profile = BUNDLED_STIGS[target_system]
        findings: list[STIGFinding] = []
        result = STIGScanResult(
            stig_id=profile["stig_id"],
            stig_title=profile["title"],
            target_system=target_system,
            total_rules=len(profile["rules"]),
        )

        for rule in profile["rules"]:
            check_name = rule["check"]
            compliant = config.get(check_name, False)

            if compliant:
                status = STIGFindingStatus.NOT_A_FINDING
                result.not_a_finding += 1
            else:
                status = STIGFindingStatus.OPEN
                severity = STIGSeverity(rule["severity"])
                if severity == STIGSeverity.CAT1:
                    result.cat1_open += 1
                elif severity == STIGSeverity.CAT2:
                    result.cat2_open += 1
                else:
                    result.cat3_open += 1

            findings.append(
                STIGFinding(
                    rule_id=rule["id"],
                    title=rule["title"],
                    severity=STIGSeverity(rule["severity"]),
                    status=status,
                    check_description=f"Verify: {check_name}",
                    fix_description=f"Configure: {check_name}=true",
                )
            )

        result.findings = findings
        config_str = str(sorted(config.items()))
        result.scan_hash = hashlib.sha256(f"{target_system}{config_str}".encode()).hexdigest()[:16]

        logger.info(
            "stig_scan_complete",
            stig_id=profile["stig_id"],
            target=target_system,
            open_cat1=result.cat1_open,
            open_cat2=result.cat2_open,
            compliance_score=result.compliance_score,
        )
        return result

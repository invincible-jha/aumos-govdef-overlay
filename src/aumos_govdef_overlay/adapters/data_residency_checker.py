"""Data residency verification adapter for aumos-govdef-overlay.

Enforces US data sovereignty requirements for government cloud environments.
Verifies data location, detects cross-border transfers, validates cloud
region compliance, and maps jurisdictional requirements to agency mandates.

Covers:
  - FedRAMP data residency requirements (Moderate/High)
  - DoD IL4/IL5 data location mandates
  - Executive Order 13556 CUI handling geography
  - ITAR/EAR technical data location controls
  - Cloud provider sovereign region validation
"""

from __future__ import annotations

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# US-only sovereign cloud regions approved for FedRAMP and DoD workloads
_APPROVED_GOVCLOUD_REGIONS: dict[str, list[str]] = {
    "aws-govcloud": [
        "us-gov-west-1",
        "us-gov-east-1",
    ],
    "azure-government": [
        "usgovarizona",
        "usgoviowa",
        "usgovtexas",
        "usgovvirginia",
        "usdodcentral",
        "usdodeast",
    ],
    "gcc-high": [
        "usgov-north",
        "usgov-east",
        "usgov-west",
        "usgov-south",
    ],
    "google-govcloud": [
        "us-gov-central1",
        "us-gov-east1",
        "us-gov-west1",
    ],
    "oracle-govcloud": [
        "us-gov-ashburn-1",
        "us-gov-chicago-1",
        "us-gov-phoenix-1",
    ],
}

# Regions that are categorically non-compliant for government CUI
_NON_COMPLIANT_REGIONS: set[str] = {
    "eu-west-1",
    "eu-central-1",
    "ap-northeast-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "cn-north-1",
    "cn-northwest-1",
    "me-south-1",
    "af-south-1",
    "sa-east-1",
    "us-east-1",     # Commercial, not GovCloud
    "us-west-2",     # Commercial, not GovCloud
    "eastus",        # Azure commercial, not Government
    "westus2",       # Azure commercial, not Government
    "northeurope",
    "westeurope",
}

# Jurisdictional requirements by data category
_JURISDICTIONAL_REQUIREMENTS: dict[str, dict] = {
    "cui": {
        "allowed_countries": ["US"],
        "allowed_territories": ["US territories with SCA coverage"],
        "prohibited_transfer": True,
        "legal_basis": "32 CFR Part 2002",
        "eo_reference": "EO 13556",
        "minimum_impact_level": "IL2",
    },
    "itar_technical_data": {
        "allowed_countries": ["US"],
        "allowed_territories": [],
        "prohibited_transfer": True,
        "legal_basis": "22 CFR Parts 120-130",
        "eo_reference": "EO 13637",
        "minimum_impact_level": "IL4",
    },
    "classified": {
        "allowed_countries": ["US"],
        "allowed_territories": [],
        "prohibited_transfer": True,
        "legal_basis": "32 CFR Part 2001 (EO 13526)",
        "eo_reference": "EO 13526",
        "minimum_impact_level": "IL5",
    },
    "pii_federal": {
        "allowed_countries": ["US"],
        "allowed_territories": ["US territories"],
        "prohibited_transfer": False,
        "legal_basis": "Privacy Act of 1974 / FISMA",
        "eo_reference": "OMB M-17-12",
        "minimum_impact_level": "IL2",
    },
    "dod_controlled": {
        "allowed_countries": ["US"],
        "allowed_territories": [],
        "prohibited_transfer": True,
        "legal_basis": "DFARS 252.204-7012",
        "eo_reference": "DoD Instruction 8582.01",
        "minimum_impact_level": "IL4",
    },
}

# Data transfer protocol acceptability by classification
_TRANSFER_PROTOCOL_ACCEPTABILITY: dict[str, dict[str, bool]] = {
    "cui": {
        "tls_1_3": True,
        "tls_1_2": True,
        "tls_1_0": False,
        "sftp": True,
        "ftps": True,
        "http_plain": False,
        "ftp_plain": False,
        "smtp_plain": False,
    },
    "classified": {
        "tls_1_3": False,  # Must use NSA Type 1 crypto for classified
        "nsa_type_1": True,
        "cross_domain_solution": True,
    },
    "itar_technical_data": {
        "tls_1_3": True,
        "tls_1_2": True,
        "encrypted_vpn": True,
        "http_plain": False,
    },
    "pii_federal": {
        "tls_1_3": True,
        "tls_1_2": True,
        "tls_1_0": False,
        "http_plain": False,
    },
}

# FedRAMP baseline data residency thresholds
_FEDRAMP_RESIDENCY_REQUIREMENTS: dict[str, dict] = {
    "low": {
        "us_only": True,
        "govcloud_required": False,
        "approved_commercial_clouds": ["AWS", "Azure", "Google", "Oracle"],
        "air_gap_required": False,
    },
    "moderate": {
        "us_only": True,
        "govcloud_required": True,
        "approved_commercial_clouds": [],
        "air_gap_required": False,
    },
    "high": {
        "us_only": True,
        "govcloud_required": True,
        "approved_commercial_clouds": [],
        "air_gap_required": False,
    },
    "il4": {
        "us_only": True,
        "govcloud_required": True,
        "approved_commercial_clouds": [],
        "air_gap_required": False,
    },
    "il5": {
        "us_only": True,
        "govcloud_required": True,
        "approved_commercial_clouds": [],
        "air_gap_required": True,
    },
}


class DataResidencyChecker:
    """Verifies US data sovereignty requirements for government cloud workloads.

    Checks data location compliance against FedRAMP, DoD IL, ITAR/EAR,
    and CUI handling requirements. Detects non-compliant cross-border
    transfers and validates cloud provider region configurations.
    """

    def __init__(self) -> None:
        """Initialize the DataResidencyChecker."""

    def verify_data_location(
        self,
        cloud_provider: str,
        region: str,
        data_category: str,
        impact_level: str,
    ) -> dict:
        """Verify that a storage location meets sovereignty requirements.

        Validates the combination of cloud provider, region, data classification,
        and impact level against approved US government sovereign cloud configurations.

        Args:
            cloud_provider: Cloud provider identifier (aws-govcloud, azure-government, etc.).
            region: Cloud region identifier to check.
            data_category: Data classification category (cui, itar_technical_data, etc.).
            impact_level: FedRAMP/DoD impact level (low, moderate, high, il4, il5).

        Returns:
            Dictionary with compliant flag, violations list, and recommended regions.
        """
        violations: list[str] = []
        warnings: list[str] = []

        # Check if provider is a recognized sovereign cloud
        approved_providers = list(_APPROVED_GOVCLOUD_REGIONS.keys())
        is_sovereign_provider = cloud_provider in approved_providers

        if not is_sovereign_provider:
            violations.append(
                f"Cloud provider '{cloud_provider}' is not a recognized US government "
                f"sovereign cloud. Approved providers: {', '.join(approved_providers)}"
            )

        # Check if region is explicitly non-compliant
        if region in _NON_COMPLIANT_REGIONS:
            violations.append(
                f"Region '{region}' is a commercial (non-sovereign) region and is "
                f"categorically non-compliant for government CUI and IL workloads."
            )

        # Check if region is in the approved set for this provider
        approved_regions_for_provider = _APPROVED_GOVCLOUD_REGIONS.get(cloud_provider, [])
        if is_sovereign_provider and region not in approved_regions_for_provider:
            violations.append(
                f"Region '{region}' is not in the approved region list for "
                f"'{cloud_provider}'. Approved: {', '.join(approved_regions_for_provider)}"
            )

        # Check impact level requirements
        fedramp_req = _FEDRAMP_RESIDENCY_REQUIREMENTS.get(impact_level.lower())
        if fedramp_req is None:
            warnings.append(
                f"Unknown impact level '{impact_level}'. Applying most restrictive "
                f"(IL5) requirements."
            )
            fedramp_req = _FEDRAMP_RESIDENCY_REQUIREMENTS["il5"]

        if fedramp_req.get("govcloud_required") and not is_sovereign_provider:
            violations.append(
                f"Impact level '{impact_level}' requires a US GovCloud provider, "
                f"but '{cloud_provider}' is a commercial provider."
            )

        if fedramp_req.get("air_gap_required"):
            warnings.append(
                f"Impact level '{impact_level}' (IL5) requires air-gapped deployment. "
                f"Verify that region '{region}' supports DoD-dedicated air-gap configurations."
            )

        # Check jurisdictional requirements for data category
        jurisdictional_req = _JURISDICTIONAL_REQUIREMENTS.get(data_category)
        if jurisdictional_req is None:
            warnings.append(
                f"Unknown data category '{data_category}'. Defaulting to CUI requirements."
            )
        else:
            allowed_countries = jurisdictional_req.get("allowed_countries", ["US"])
            if "US" not in allowed_countries:
                violations.append(
                    f"Data category '{data_category}' has unexpected country restrictions: "
                    f"{allowed_countries}"
                )

        # Recommend approved regions for this provider
        recommended_regions = approved_regions_for_provider or _APPROVED_GOVCLOUD_REGIONS.get(
            "aws-govcloud", []
        )

        compliant = len(violations) == 0

        logger.info(
            "Data location verification completed",
            cloud_provider=cloud_provider,
            region=region,
            data_category=data_category,
            impact_level=impact_level,
            compliant=compliant,
            violations_count=len(violations),
        )

        return {
            "compliant": compliant,
            "cloud_provider": cloud_provider,
            "region": region,
            "data_category": data_category,
            "impact_level": impact_level,
            "violations": violations,
            "warnings": warnings,
            "recommended_regions": recommended_regions,
            "is_sovereign_provider": is_sovereign_provider,
        }

    def detect_cross_border_transfers(
        self,
        transfer_manifest: list[dict],
        data_category: str,
    ) -> dict:
        """Detect and classify cross-border data transfers in a transfer manifest.

        Analyzes a list of data transfer records to identify transfers that
        originate or terminate outside US jurisdiction, flagging violations
        for CUI, ITAR, and classified data categories.

        Args:
            transfer_manifest: List of transfer records, each with keys:
                source_region, destination_region, protocol, data_size_bytes,
                transfer_timestamp, and optional metadata dict.
            data_category: Data classification category driving enforcement rules.

        Returns:
            Dictionary with violation list, transfer analysis, and remediation steps.
        """
        violations: list[dict] = []
        approved_transfers: list[dict] = []
        total_bytes_at_risk: int = 0

        jurisdictional_req = _JURISDICTIONAL_REQUIREMENTS.get(
            data_category,
            _JURISDICTIONAL_REQUIREMENTS["cui"],
        )
        prohibited_transfer = jurisdictional_req.get("prohibited_transfer", True)
        legal_basis = jurisdictional_req.get("legal_basis", "32 CFR Part 2002")

        protocol_rules = _TRANSFER_PROTOCOL_ACCEPTABILITY.get(
            data_category,
            _TRANSFER_PROTOCOL_ACCEPTABILITY.get("pii_federal", {}),
        )

        for transfer in transfer_manifest:
            source = transfer.get("source_region", "")
            destination = transfer.get("destination_region", "")
            protocol = transfer.get("protocol", "unknown")
            data_size = transfer.get("data_size_bytes", 0)
            timestamp = transfer.get("transfer_timestamp", "unknown")

            transfer_violations: list[str] = []

            # Check if source or destination is non-compliant
            if source in _NON_COMPLIANT_REGIONS:
                transfer_violations.append(
                    f"Source region '{source}' is a non-US sovereign region. "
                    f"Data originated outside US jurisdiction."
                )
                total_bytes_at_risk += data_size

            if destination in _NON_COMPLIANT_REGIONS:
                transfer_violations.append(
                    f"Destination region '{destination}' is outside US jurisdiction. "
                    f"This constitutes a cross-border transfer of {data_category} data, "
                    f"violating {legal_basis}."
                )
                total_bytes_at_risk += data_size

            # Check for cross-border between approved regions (allowed)
            source_is_approved = source not in _NON_COMPLIANT_REGIONS
            dest_is_approved = destination not in _NON_COMPLIANT_REGIONS

            # Check protocol acceptability
            protocol_allowed = protocol_rules.get(protocol)
            if protocol_allowed is False:
                transfer_violations.append(
                    f"Transfer protocol '{protocol}' is not approved for {data_category} "
                    f"data. Use TLS 1.2+ or stronger."
                )

            if transfer_violations:
                violations.append({
                    "source_region": source,
                    "destination_region": destination,
                    "protocol": protocol,
                    "data_size_bytes": data_size,
                    "transfer_timestamp": timestamp,
                    "violations": transfer_violations,
                    "severity": "critical" if prohibited_transfer else "high",
                })
            else:
                approved_transfers.append({
                    "source_region": source,
                    "destination_region": destination,
                    "protocol": protocol,
                    "data_size_bytes": data_size,
                    "transfer_timestamp": timestamp,
                })

        remediation_steps: list[str] = []
        if violations:
            remediation_steps.extend([
                f"Immediately halt cross-border transfers of {data_category} data.",
                f"Review and enforce {legal_basis} compliance controls.",
                "Reconfigure data paths to US-only sovereign cloud regions.",
                "Conduct forensic analysis to determine scope of data exposure.",
                "Notify ISSO/ISSM within 1 hour of confirmed cross-border transfer.",
            ])
            if data_category in ("itar_technical_data", "classified"):
                remediation_steps.append(
                    "Notify DoD/State Department within 24 hours per ITAR reporting requirements."
                )

        logger.info(
            "Cross-border transfer detection completed",
            data_category=data_category,
            total_transfers=len(transfer_manifest),
            violations_found=len(violations),
            bytes_at_risk=total_bytes_at_risk,
        )

        return {
            "data_category": data_category,
            "total_transfers_analyzed": len(transfer_manifest),
            "violations_found": len(violations),
            "approved_transfers": len(approved_transfers),
            "total_bytes_at_risk": total_bytes_at_risk,
            "violation_details": violations,
            "approved_transfer_details": approved_transfers,
            "remediation_steps": remediation_steps,
            "legal_basis": legal_basis,
            "prohibited_transfer": prohibited_transfer,
        }

    def validate_cloud_regions(
        self,
        deployment_config: dict,
    ) -> dict:
        """Validate a full cloud deployment configuration for residency compliance.

        Checks that all specified regions, replication targets, and backup
        locations are within the approved US sovereign cloud footprint.

        Args:
            deployment_config: Deployment configuration dictionary with keys:
                primary_provider, primary_region, backup_regions (list),
                replication_regions (list), cdn_regions (list, optional),
                impact_level, data_categories (list).

        Returns:
            Dictionary with overall compliance status and per-region findings.
        """
        primary_provider = deployment_config.get("primary_provider", "")
        primary_region = deployment_config.get("primary_region", "")
        backup_regions = deployment_config.get("backup_regions", [])
        replication_regions = deployment_config.get("replication_regions", [])
        cdn_regions = deployment_config.get("cdn_regions", [])
        impact_level = deployment_config.get("impact_level", "moderate")
        data_categories = deployment_config.get("data_categories", ["cui"])

        all_regions = (
            [primary_region]
            + backup_regions
            + replication_regions
            + cdn_regions
        )

        per_region_results: list[dict] = []
        global_violations: list[str] = []

        for region in all_regions:
            region_type = (
                "primary" if region == primary_region
                else "backup" if region in backup_regions
                else "replication" if region in replication_regions
                else "cdn"
            )

            is_non_compliant = region in _NON_COMPLIANT_REGIONS
            is_approved = any(
                region in regions
                for regions in _APPROVED_GOVCLOUD_REGIONS.values()
            )

            region_violations: list[str] = []
            if is_non_compliant:
                region_violations.append(
                    f"Region '{region}' ({region_type}) is categorically non-compliant "
                    f"for government data at impact level '{impact_level}'."
                )
                global_violations.append(region)

            if cdn_regions and region in cdn_regions and data_categories:
                for data_cat in data_categories:
                    if data_cat in ("classified", "itar_technical_data", "cui"):
                        region_violations.append(
                            f"CDN distribution to region '{region}' is not permitted for "
                            f"'{data_cat}' data. CDNs must not cache classified or CUI content."
                        )

            per_region_results.append({
                "region": region,
                "region_type": region_type,
                "is_approved_sovereign": is_approved,
                "is_non_compliant": is_non_compliant,
                "violations": region_violations,
            })

        # Check HA/DR requirements for IL5
        if impact_level == "il5" and len(backup_regions) < 1:
            global_violations.append("il5_dr_deficit")
            per_region_results.append({
                "region": "N/A",
                "region_type": "configuration",
                "is_approved_sovereign": False,
                "is_non_compliant": True,
                "violations": [
                    "IL5 deployments require at least one dedicated backup region "
                    "within the US DoD sovereign cloud footprint."
                ],
            })

        overall_compliant = len(global_violations) == 0

        logger.info(
            "Cloud region validation completed",
            primary_provider=primary_provider,
            primary_region=primary_region,
            total_regions=len(all_regions),
            overall_compliant=overall_compliant,
            non_compliant_regions=len(global_violations),
        )

        return {
            "overall_compliant": overall_compliant,
            "primary_provider": primary_provider,
            "impact_level": impact_level,
            "data_categories": data_categories,
            "regions_evaluated": len(all_regions),
            "non_compliant_regions": global_violations,
            "per_region_results": per_region_results,
            "approved_govcloud_regions": _APPROVED_GOVCLOUD_REGIONS,
        }

    def map_jurisdictional_requirements(
        self,
        data_categories: list[str],
        deployment_countries: list[str],
    ) -> dict:
        """Map jurisdictional requirements for a multi-category deployment.

        Produces the most restrictive combined requirement set when multiple
        data categories and deployment locations are involved.

        Args:
            data_categories: List of data classification categories present.
            deployment_countries: List of country codes where data will be processed.

        Returns:
            Dictionary with combined requirements, conflicting policies, and
            compliance recommendations.
        """
        combined_requirements: dict = {
            "allowed_countries": ["US"],
            "prohibited_transfer": False,
            "minimum_impact_level": "low",
            "air_gap_required": False,
            "govcloud_required": False,
            "legal_bases": [],
            "eo_references": [],
        }

        impact_level_rank = {"low": 0, "moderate": 1, "high": 2, "il4": 3, "il5": 4}
        conflicts: list[str] = []
        current_min_il = "low"

        for data_cat in data_categories:
            req = _JURISDICTIONAL_REQUIREMENTS.get(data_cat)
            if req is None:
                conflicts.append(
                    f"Unknown data category '{data_cat}' — treating as CUI for safety."
                )
                req = _JURISDICTIONAL_REQUIREMENTS["cui"]

            # Apply most restrictive transfer prohibition
            if req.get("prohibited_transfer"):
                combined_requirements["prohibited_transfer"] = True

            # Apply most restrictive impact level
            req_il = req.get("minimum_impact_level", "low")
            if impact_level_rank.get(req_il, 0) > impact_level_rank.get(current_min_il, 0):
                current_min_il = req_il
                combined_requirements["minimum_impact_level"] = req_il

            # Collect legal bases
            legal_basis = req.get("legal_basis")
            if legal_basis and legal_basis not in combined_requirements["legal_bases"]:
                combined_requirements["legal_bases"].append(legal_basis)

            eo_ref = req.get("eo_reference")
            if eo_ref and eo_ref not in combined_requirements["eo_references"]:
                combined_requirements["eo_references"].append(eo_ref)

        # Check deployment countries for non-US locations
        non_us_countries = [c for c in deployment_countries if c != "US"]
        if non_us_countries and combined_requirements["prohibited_transfer"]:
            conflicts.append(
                f"Deployment countries include non-US locations {non_us_countries}, "
                f"but data categories require US-only processing: "
                f"{[c for c in data_categories if _JURISDICTIONAL_REQUIREMENTS.get(c, {}).get('prohibited_transfer')]}"
            )

        # Set govcloud_required based on minimum IL
        if current_min_il in ("moderate", "high", "il4", "il5"):
            combined_requirements["govcloud_required"] = True
        if current_min_il == "il5":
            combined_requirements["air_gap_required"] = True

        recommendations: list[str] = []
        recommendations.append(
            f"Deploy at minimum impact level: {current_min_il.upper()}."
        )
        if combined_requirements["govcloud_required"]:
            recommendations.append(
                "Use a US GovCloud provider (AWS GovCloud, Azure Government, GCC High)."
            )
        if combined_requirements["prohibited_transfer"]:
            recommendations.append(
                "All data transfers must remain within US jurisdiction. "
                "Implement network-level controls to prevent cross-border routing."
            )
        if non_us_countries:
            recommendations.append(
                f"Remove non-US deployment targets {non_us_countries} or "
                f"segregate non-restricted data categories."
            )

        logger.info(
            "Jurisdictional requirements mapped",
            data_categories=data_categories,
            deployment_countries=deployment_countries,
            minimum_impact_level=current_min_il,
            prohibited_transfer=combined_requirements["prohibited_transfer"],
            conflicts_found=len(conflicts),
        )

        return {
            "combined_requirements": combined_requirements,
            "data_categories": data_categories,
            "deployment_countries": deployment_countries,
            "policy_conflicts": conflicts,
            "recommendations": recommendations,
        }

    def get_approved_regions_catalog(self) -> dict:
        """Return the full catalog of approved US sovereign cloud regions.

        Returns:
            Dictionary mapping provider name to list of approved region identifiers
            and metadata about their certification level.
        """
        catalog: dict = {}
        for provider, regions in _APPROVED_GOVCLOUD_REGIONS.items():
            certification = (
                "DoD IL5" if provider in ("azure-government",) and any("dod" in r for r in regions)
                else "FedRAMP High + IL4"
            )
            catalog[provider] = {
                "regions": regions,
                "certification": certification,
                "us_only": True,
                "fedramp_authorized": True,
            }

        logger.info(
            "Approved regions catalog retrieved",
            provider_count=len(catalog),
        )
        return catalog


__all__ = ["DataResidencyChecker"]

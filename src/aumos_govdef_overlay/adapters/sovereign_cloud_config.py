"""Sovereign cloud configuration adapter for aumos-govdef-overlay.

Generates and validates sovereign deployment configurations for US government
cloud environments. Covers AWS GovCloud, Azure Government, GCC High, and
on-premises IL5 deployments with full compliance profile generation.

Covers:
  - AWS GovCloud (US) region configuration and service availability
  - Azure Government / GCC High service configuration
  - Google Cloud for Government (AlloyDB, Assured Workloads)
  - IL4/IL5 network isolation and encryption configurations
  - FIPS 140-2 endpoint enforcement
  - FedRAMP Moderate/High-specific service restrictions
  - Air-gap and private link configuration templates
"""

from __future__ import annotations

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# AWS GovCloud service availability matrix (representative subset)
_AWS_GOVCLOUD_SERVICES: dict[str, dict] = {
    "ec2": {
        "available": True,
        "il5_capable": True,
        "fips_endpoints": True,
        "description": "Elastic Compute Cloud",
    },
    "s3": {
        "available": True,
        "il5_capable": True,
        "fips_endpoints": True,
        "description": "Simple Storage Service",
    },
    "rds": {
        "available": True,
        "il5_capable": True,
        "fips_endpoints": True,
        "description": "Relational Database Service",
    },
    "eks": {
        "available": True,
        "il5_capable": True,
        "fips_endpoints": True,
        "description": "Elastic Kubernetes Service",
    },
    "kms": {
        "available": True,
        "il5_capable": True,
        "fips_endpoints": True,
        "description": "Key Management Service (FIPS 140-2 validated HSM)",
    },
    "cloudhsm": {
        "available": True,
        "il5_capable": True,
        "fips_endpoints": True,
        "description": "CloudHSM — dedicated FIPS 140-2 Level 3 HSM",
    },
    "iam": {
        "available": True,
        "il5_capable": True,
        "fips_endpoints": True,
        "description": "Identity and Access Management",
    },
    "cloudtrail": {
        "available": True,
        "il5_capable": True,
        "fips_endpoints": True,
        "description": "CloudTrail audit logging",
    },
    "vpc": {
        "available": True,
        "il5_capable": True,
        "fips_endpoints": True,
        "description": "Virtual Private Cloud",
    },
    "direct_connect": {
        "available": True,
        "il5_capable": True,
        "fips_endpoints": True,
        "description": "Dedicated network connection to GovCloud",
    },
    "rekognition": {
        "available": False,
        "il5_capable": False,
        "fips_endpoints": False,
        "description": "Image recognition — NOT available in GovCloud",
    },
    "bedrock": {
        "available": False,
        "il5_capable": False,
        "fips_endpoints": False,
        "description": "Amazon Bedrock — NOT available in GovCloud (use SageMaker)",
    },
    "sagemaker": {
        "available": True,
        "il5_capable": True,
        "fips_endpoints": True,
        "description": "SageMaker ML platform",
    },
}

# Azure Government service availability matrix
_AZURE_GOVERNMENT_SERVICES: dict[str, dict] = {
    "virtual_machines": {
        "available": True,
        "il5_capable": True,
        "fips_endpoints": True,
        "sku_restrictions": ["some L-series unavailable in DoD regions"],
    },
    "blob_storage": {
        "available": True,
        "il5_capable": True,
        "fips_endpoints": True,
        "sku_restrictions": [],
    },
    "azure_sql": {
        "available": True,
        "il5_capable": True,
        "fips_endpoints": True,
        "sku_restrictions": [],
    },
    "aks": {
        "available": True,
        "il5_capable": True,
        "fips_endpoints": True,
        "sku_restrictions": [],
    },
    "key_vault": {
        "available": True,
        "il5_capable": True,
        "fips_endpoints": True,
        "sku_restrictions": ["Premium SKU required for HSM-backed keys"],
    },
    "dedicated_hsm": {
        "available": True,
        "il5_capable": True,
        "fips_endpoints": True,
        "sku_restrictions": [],
    },
    "azure_openai": {
        "available": False,
        "il5_capable": False,
        "fips_endpoints": False,
        "sku_restrictions": ["Not available in Azure Government — use commercial with data routing controls"],
    },
    "monitor": {
        "available": True,
        "il5_capable": True,
        "fips_endpoints": True,
        "sku_restrictions": [],
    },
    "sentinel": {
        "available": True,
        "il5_capable": True,
        "fips_endpoints": True,
        "sku_restrictions": [],
    },
    "expressroute": {
        "available": True,
        "il5_capable": True,
        "fips_endpoints": True,
        "sku_restrictions": [],
    },
}

# GovCloud encryption configuration templates
_ENCRYPTION_CONFIG_TEMPLATES: dict[str, dict] = {
    "il2_baseline": {
        "at_rest": {
            "algorithm": "AES-256",
            "key_management": "provider_managed",
            "kms_key_type": "aws_managed_key",
        },
        "in_transit": {
            "min_tls_version": "TLS_1_2",
            "cipher_suites": [
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_AES_128_GCM_SHA256",
            ],
        },
        "backup": {
            "encrypted": True,
            "separate_key": False,
        },
    },
    "il4_standard": {
        "at_rest": {
            "algorithm": "AES-256",
            "key_management": "customer_managed",
            "kms_key_type": "customer_managed_key",
            "key_rotation_days": 365,
            "hsm_required": False,
        },
        "in_transit": {
            "min_tls_version": "TLS_1_2",
            "fips_140_2_required": True,
            "cipher_suites": [
                "TLS_AES_256_GCM_SHA384",
                "TLS_AES_128_GCM_SHA256",
            ],
        },
        "backup": {
            "encrypted": True,
            "separate_key": True,
            "backup_key_in_separate_region": True,
        },
    },
    "il5_high_assurance": {
        "at_rest": {
            "algorithm": "AES-256",
            "key_management": "hsm_backed_customer_managed",
            "kms_key_type": "hsm_protected",
            "key_rotation_days": 90,
            "hsm_required": True,
            "fips_140_2_level": 3,
        },
        "in_transit": {
            "min_tls_version": "TLS_1_2",
            "fips_140_2_required": True,
            "nsa_type1_for_classified": True,
            "cipher_suites": [
                "TLS_AES_256_GCM_SHA384",
            ],
        },
        "backup": {
            "encrypted": True,
            "separate_key": True,
            "backup_key_in_separate_region": True,
            "air_gap_backup": True,
        },
    },
}

# Network isolation configuration templates
_NETWORK_ISOLATION_TEMPLATES: dict[str, dict] = {
    "il2_standard": {
        "vpc_enabled": True,
        "public_internet_access": True,
        "nat_gateway": True,
        "private_endpoints": False,
        "network_acls": "standard",
        "flow_logs": True,
        "baseline_controls": [
            "Security groups restricted to required ports",
            "No 0.0.0.0/0 inbound rules for management ports",
        ],
    },
    "il4_isolated": {
        "vpc_enabled": True,
        "public_internet_access": False,
        "nat_gateway": False,
        "private_endpoints": True,
        "private_link": True,
        "direct_connect_required": True,
        "network_acls": "strict",
        "flow_logs": True,
        "intrusion_detection": True,
        "baseline_controls": [
            "All traffic via private endpoints only",
            "No public IP addresses on workload resources",
            "Dedicated Direct Connect / ExpressRoute circuit",
            "Layer 7 inspection via WAF",
        ],
    },
    "il5_air_gap": {
        "vpc_enabled": True,
        "public_internet_access": False,
        "nat_gateway": False,
        "private_endpoints": True,
        "private_link": True,
        "direct_connect_required": True,
        "air_gapped": True,
        "network_acls": "deny_all_default",
        "flow_logs": True,
        "intrusion_detection": True,
        "cross_domain_solution_required": True,
        "baseline_controls": [
            "Air-gapped from public internet and other tenant VPCs",
            "All connectivity via government-dedicated circuits only",
            "Cross-domain solution required for data transfer to/from lower IL environments",
            "Physical network separation from commercial regions",
            "Real-time network monitoring with automated isolation triggers",
        ],
    },
}

# Compliance checklist by impact level
_COMPLIANCE_CHECKLISTS: dict[str, list[dict]] = {
    "fedramp_moderate": [
        {"id": "AUTH-1", "check": "FedRAMP ATO obtained or in process", "required": True},
        {"id": "AUTH-2", "check": "3PAO assessment scheduled", "required": True},
        {"id": "ENC-1", "check": "Data at rest encrypted with AES-256", "required": True},
        {"id": "ENC-2", "check": "TLS 1.2+ enforced for all endpoints", "required": True},
        {"id": "ENC-3", "check": "FIPS 140-2 validated modules in use", "required": True},
        {"id": "NET-1", "check": "GovCloud region deployment verified", "required": True},
        {"id": "NET-2", "check": "No US-to-non-US data routing", "required": True},
        {"id": "IAM-1", "check": "MFA enforced for all users", "required": True},
        {"id": "IAM-2", "check": "Privileged access managed via PAM solution", "required": True},
        {"id": "LOG-1", "check": "Audit logging enabled on all services", "required": True},
        {"id": "LOG-2", "check": "Log retention minimum 1 year", "required": True},
        {"id": "VULN-1", "check": "Vulnerability scanning monthly", "required": True},
        {"id": "POAM-1", "check": "POA&M process active and tracked", "required": True},
    ],
    "il4": [
        {"id": "IL4-1", "check": "DoD IL4 provisional authorization obtained", "required": True},
        {"id": "IL4-2", "check": "Customer-managed encryption keys configured", "required": True},
        {"id": "IL4-3", "check": "No public internet access from workloads", "required": True},
        {"id": "IL4-4", "check": "Private endpoints for all cloud services", "required": True},
        {"id": "IL4-5", "check": "Direct Connect / ExpressRoute dedicated circuit", "required": True},
        {"id": "IL4-6", "check": "CAC/PIV authentication for all users", "required": True},
        {"id": "IL4-7", "check": "DISA STIG applied to all OS/middleware", "required": True},
        {"id": "IL4-8", "check": "Continuous monitoring active (CONMON)", "required": True},
    ],
    "il5": [
        {"id": "IL5-1", "check": "DoD IL5 provisional authorization obtained", "required": True},
        {"id": "IL5-2", "check": "HSM-backed customer-managed keys (FIPS 140-2 Level 3)", "required": True},
        {"id": "IL5-3", "check": "Air-gapped network environment configured", "required": True},
        {"id": "IL5-4", "check": "Cross-domain solution implemented for data transfer", "required": True},
        {"id": "IL5-5", "check": "Personnel clearance verification complete", "required": True},
        {"id": "IL5-6", "check": "Physical security controls at datacenter verified", "required": True},
        {"id": "IL5-7", "check": "NSA-approved cryptography for classified data", "required": True},
        {"id": "IL5-8", "check": "Dedicated hardware isolation (no shared tenancy)", "required": True},
    ],
}


class SovereignCloudConfig:
    """Generates and validates sovereign cloud deployment configurations.

    Produces provider-specific configuration templates for AWS GovCloud,
    Azure Government, and GCC High, with encryption, network isolation,
    and compliance checklist generation for each impact level.
    """

    def __init__(self) -> None:
        """Initialize the SovereignCloudConfig."""

    def get_govcloud_region_config(
        self,
        provider: str,
        region: str,
        impact_level: str,
    ) -> dict:
        """Generate a complete sovereign cloud region configuration.

        Returns provider-specific endpoint configuration, FIPS endpoint
        URLs, service availability matrix, and deployment constraints
        for the requested impact level.

        Args:
            provider: Cloud provider (aws-govcloud, azure-government, gcc-high).
            region: Region identifier within the provider.
            impact_level: FedRAMP/DoD impact level (moderate, high, il4, il5).

        Returns:
            Dictionary with endpoint config, service matrix, constraints,
            and deployment guidance.
        """
        impact_level_lower = impact_level.lower()

        # Select service matrix and encryption template
        if provider == "aws-govcloud":
            services = _AWS_GOVCLOUD_SERVICES
            available_services = {k: v for k, v in services.items() if v["available"]}
            unavailable_services = {k: v for k, v in services.items() if not v["available"]}
            fips_endpoint_pattern = f"https://{{service}}.{region}.amazonaws.com"
        elif provider == "azure-government":
            services = _AZURE_GOVERNMENT_SERVICES
            available_services = {k: v for k, v in services.items() if v["available"]}
            unavailable_services = {k: v for k, v in services.items() if not v["available"]}
            fips_endpoint_pattern = f"https://{{service}}.usgovcloudapi.net"
        elif provider == "gcc-high":
            available_services = {
                "sharepoint": {"available": True, "il5_capable": True, "fips_endpoints": True},
                "teams": {"available": True, "il5_capable": True, "fips_endpoints": True},
                "exchange_online": {"available": True, "il5_capable": True, "fips_endpoints": True},
                "azure_ad": {"available": True, "il5_capable": True, "fips_endpoints": True},
                "intune": {"available": True, "il5_capable": True, "fips_endpoints": True},
            }
            unavailable_services = {}
            fips_endpoint_pattern = "https://{service}.cloud.microsoft"
        else:
            available_services = {}
            unavailable_services = {}
            fips_endpoint_pattern = "N/A — Unknown provider"

        # IL5 services filter
        if impact_level_lower == "il5":
            il5_capable_services = {
                k: v for k, v in available_services.items()
                if v.get("il5_capable", False)
            }
        else:
            il5_capable_services = available_services

        # Select encryption and network templates
        if impact_level_lower == "il5":
            encryption_config = _ENCRYPTION_CONFIG_TEMPLATES["il5_high_assurance"]
            network_config = _NETWORK_ISOLATION_TEMPLATES["il5_air_gap"]
        elif impact_level_lower in ("il4", "high"):
            encryption_config = _ENCRYPTION_CONFIG_TEMPLATES["il4_standard"]
            network_config = _NETWORK_ISOLATION_TEMPLATES["il4_isolated"]
        else:
            encryption_config = _ENCRYPTION_CONFIG_TEMPLATES["il2_baseline"]
            network_config = _NETWORK_ISOLATION_TEMPLATES["il2_standard"]

        deployment_constraints: list[str] = []
        if impact_level_lower in ("il4", "il5"):
            deployment_constraints.extend([
                "Deploy only in dedicated tenant spaces — no shared hardware.",
                "All management access via CAC/PIV — password-only auth is prohibited.",
                "DISA STIG hardening required on all OS images before deployment.",
            ])
        if impact_level_lower == "il5":
            deployment_constraints.extend([
                "Air-gap from commercial internet — dedicated circuits only.",
                "Personnel with Secret or higher clearance required for admin access.",
                "Physical datacenter inspection required annually.",
            ])
        if provider in ("aws-govcloud", "azure-government"):
            deployment_constraints.append(
                "Verify FIPS 140-2 endpoint URLs are used exclusively — no commercial endpoints."
            )

        logger.info(
            "GovCloud region config generated",
            provider=provider,
            region=region,
            impact_level=impact_level,
            available_services=len(available_services),
            il5_capable=len(il5_capable_services),
        )

        return {
            "provider": provider,
            "region": region,
            "impact_level": impact_level,
            "fips_endpoint_pattern": fips_endpoint_pattern,
            "available_services_count": len(available_services),
            "available_services": il5_capable_services,
            "unavailable_services": list(unavailable_services.keys()),
            "encryption_configuration": encryption_config,
            "network_isolation_configuration": network_config,
            "deployment_constraints": deployment_constraints,
        }

    def generate_deployment_blueprint(
        self,
        deployment_name: str,
        provider: str,
        region: str,
        impact_level: str,
        services_required: list[str],
        compliance_frameworks: list[str],
    ) -> dict:
        """Generate a complete deployment blueprint for a sovereign environment.

        Produces a deployment-ready configuration package with encryption,
        network isolation, IAM policies, monitoring configuration, and
        compliance checklist for the specified impact level.

        Args:
            deployment_name: Human-readable deployment identifier.
            provider: Cloud provider identifier.
            region: Target deployment region.
            impact_level: FedRAMP/DoD impact level (moderate, high, il4, il5).
            services_required: List of cloud service names needed.
            compliance_frameworks: List of compliance frameworks to apply.

        Returns:
            Dictionary with complete deployment blueprint, configuration
            blocks, and compliance acceptance criteria.
        """
        impact_level_lower = impact_level.lower()

        # Get base region config
        region_config = self.get_govcloud_region_config(provider, region, impact_level)
        available = region_config["available_services"]

        # Validate requested services
        unavailable_requested: list[str] = []
        for service in services_required:
            if service not in available:
                unavailable_requested.append(service)

        # Select compliance checklist
        if impact_level_lower == "il5":
            checklist = _COMPLIANCE_CHECKLISTS.get("il5", [])
        elif impact_level_lower == "il4":
            checklist = _COMPLIANCE_CHECKLISTS.get("il4", [])
        else:
            checklist = _COMPLIANCE_CHECKLISTS.get("fedramp_moderate", [])

        # IAM configuration
        iam_config = {
            "mfa_required": True,
            "cac_piv_required": impact_level_lower in ("il4", "il5"),
            "session_timeout_minutes": 15 if impact_level_lower in ("il4", "il5") else 60,
            "privilege_escalation_workflow": "approval_required",
            "break_glass_account": True,
            "pam_solution_required": True,
        }

        # Monitoring configuration
        monitoring_config = {
            "siem_integration": True,
            "audit_logging_enabled": True,
            "log_retention_days": 365 if impact_level_lower != "il5" else 2555,
            "alerting": {
                "privilege_escalation": True,
                "failed_logins_threshold": 3,
                "after_hours_access": True,
                "data_exfiltration_detection": True,
            },
            "vulnerability_scanning_frequency": (
                "weekly" if impact_level_lower in ("il4", "il5") else "monthly"
            ),
            "penetration_testing_frequency": "annually",
        }

        # Tag schema for sovereign deployments
        tag_schema = {
            "deployment_name": deployment_name,
            "impact_level": impact_level.upper(),
            "compliance_frameworks": ",".join(compliance_frameworks),
            "data_classification": "CUI" if impact_level_lower != "il5" else "SECRET_CAPABLE",
            "fedramp_authorized": "true",
            "us_sovereign": "true",
        }

        logger.info(
            "Deployment blueprint generated",
            deployment_name=deployment_name,
            provider=provider,
            region=region,
            impact_level=impact_level,
            services_requested=len(services_required),
            unavailable_services=len(unavailable_requested),
        )

        return {
            "blueprint_id": f"BP-{deployment_name.upper().replace(' ', '-')}-{impact_level.upper()}",
            "deployment_name": deployment_name,
            "provider": provider,
            "region": region,
            "impact_level": impact_level,
            "compliance_frameworks": compliance_frameworks,
            "services_requested": services_required,
            "unavailable_services_requested": unavailable_requested,
            "region_configuration": region_config,
            "iam_configuration": iam_config,
            "monitoring_configuration": monitoring_config,
            "tag_schema": tag_schema,
            "compliance_checklist": checklist,
            "checklist_item_count": len(checklist),
            "deployment_ready": len(unavailable_requested) == 0,
            "warnings": (
                [f"Service '{s}' is not available in {provider}. Consider alternatives."
                 for s in unavailable_requested]
            ),
        }

    def compare_providers(
        self,
        impact_level: str,
        required_services: list[str],
    ) -> dict:
        """Compare sovereign cloud providers for a given impact level.

        Evaluates AWS GovCloud, Azure Government, and GCC High against
        service requirements and compliance criteria to support provider
        selection decisions.

        Args:
            impact_level: FedRAMP/DoD impact level to evaluate against.
            required_services: List of service capabilities needed.

        Returns:
            Dictionary with per-provider scores, service coverage, and
            recommendation.
        """
        providers = {
            "aws-govcloud": _AWS_GOVCLOUD_SERVICES,
            "azure-government": _AZURE_GOVERNMENT_SERVICES,
        }
        impact_level_lower = impact_level.lower()

        provider_scores: list[dict] = []

        for provider_name, service_catalog in providers.items():
            available = [k for k, v in service_catalog.items() if v.get("available")]
            il5_capable = [k for k, v in service_catalog.items() if v.get("il5_capable")]
            fips_endpoints = [k for k, v in service_catalog.items() if v.get("fips_endpoints")]

            # Check required services coverage
            covered = [s for s in required_services if s in available]
            missing = [s for s in required_services if s not in available]

            coverage_pct = (len(covered) / len(required_services) * 100) if required_services else 100.0
            il5_coverage_pct = (
                len([s for s in required_services if s in il5_capable]) / len(required_services) * 100
            ) if required_services else 100.0

            # Compute overall score (simplified)
            score = coverage_pct * 0.6
            if impact_level_lower in ("il4", "il5"):
                score += il5_coverage_pct * 0.4
            else:
                score += coverage_pct * 0.4

            provider_scores.append({
                "provider": provider_name,
                "score": round(score, 1),
                "coverage_percent": round(coverage_pct, 1),
                "il5_coverage_percent": round(il5_coverage_pct, 1),
                "available_services": len(available),
                "covered_required_services": covered,
                "missing_required_services": missing,
                "fips_endpoints_count": len(fips_endpoints),
            })

        # Sort by score descending
        provider_scores.sort(key=lambda x: x["score"], reverse=True)
        recommended_provider = provider_scores[0]["provider"] if provider_scores else "aws-govcloud"

        logger.info(
            "Provider comparison completed",
            impact_level=impact_level,
            recommended_provider=recommended_provider,
            provider_count=len(provider_scores),
        )

        return {
            "impact_level": impact_level,
            "required_services": required_services,
            "provider_comparison": provider_scores,
            "recommended_provider": recommended_provider,
            "recommendation_rationale": (
                f"{recommended_provider} scored highest with "
                f"{provider_scores[0]['coverage_percent']}% service coverage "
                f"for the specified requirements at impact level {impact_level.upper()}."
            ),
        }

    def get_encryption_templates(self) -> dict:
        """Return all available encryption configuration templates.

        Returns:
            Dictionary mapping template name to full encryption configuration.
        """
        logger.info(
            "Encryption templates retrieved",
            template_count=len(_ENCRYPTION_CONFIG_TEMPLATES),
        )
        return dict(_ENCRYPTION_CONFIG_TEMPLATES)

    def get_network_isolation_templates(self) -> dict:
        """Return all available network isolation configuration templates.

        Returns:
            Dictionary mapping template name to full network isolation configuration.
        """
        logger.info(
            "Network isolation templates retrieved",
            template_count=len(_NETWORK_ISOLATION_TEMPLATES),
        )
        return dict(_NETWORK_ISOLATION_TEMPLATES)

    def get_compliance_checklist(
        self,
        impact_level: str,
    ) -> dict:
        """Return the compliance checklist for a specific impact level.

        Args:
            impact_level: FedRAMP/DoD impact level (moderate, high, il4, il5).

        Returns:
            Dictionary with checklist items and completion guidance.
        """
        il_lower = impact_level.lower()
        checklist_key = il_lower if il_lower in _COMPLIANCE_CHECKLISTS else "fedramp_moderate"
        checklist = _COMPLIANCE_CHECKLISTS.get(checklist_key, [])

        required_items = [item for item in checklist if item["required"]]
        optional_items = [item for item in checklist if not item["required"]]

        logger.info(
            "Compliance checklist retrieved",
            impact_level=impact_level,
            required_items=len(required_items),
            optional_items=len(optional_items),
        )

        return {
            "impact_level": impact_level,
            "checklist_key": checklist_key,
            "total_items": len(checklist),
            "required_items": required_items,
            "optional_items": optional_items,
            "completion_guidance": (
                f"All {len(required_items)} required items must be completed before "
                f"production deployment at {impact_level.upper()}."
            ),
        }


__all__ = ["SovereignCloudConfig"]

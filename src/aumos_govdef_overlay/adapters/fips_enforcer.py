"""FIPS 140-2 enforcement adapter for aumos-govdef-overlay.

Implements approved algorithm enforcement, non-compliant algorithm detection,
algorithm migration planning, key management validation, cryptographic module
inventory, compliance enforcement policy, and remediation tracking for
government systems subject to FIPS 140-2 requirements.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# FIPS 140-2 approved algorithms per NIST CMVP
_APPROVED_ALGORITHMS: set[str] = {
    # Symmetric
    "AES-128-CBC", "AES-192-CBC", "AES-256-CBC",
    "AES-128-GCM", "AES-192-GCM", "AES-256-GCM",
    "AES-128-CCM", "AES-256-CCM",
    "3DES-168",
    # Asymmetric
    "RSA-2048", "RSA-3072", "RSA-4096",
    "ECDSA-P256", "ECDSA-P384", "ECDSA-P521",
    "ECDH-P256", "ECDH-P384", "ECDH-P521",
    # Hash / MAC
    "SHA-256", "SHA-384", "SHA-512",
    "SHA-3-256", "SHA-3-512",
    "HMAC-SHA-256", "HMAC-SHA-384", "HMAC-SHA-512",
    # DRBG
    "CTR-DRBG-AES-256", "HMAC-DRBG-SHA-256", "HASH-DRBG-SHA-512",
    # Key derivation
    "SP800-108-KDF", "SP800-56C-KDF",
}

# Explicitly non-compliant algorithms requiring immediate remediation
_NON_COMPLIANT_ALGORITHMS: dict[str, dict[str, Any]] = {
    "DES": {"severity": "CRITICAL", "reason": "56-bit key insufficient, withdrawn from FIPS", "replacement": "AES-256-CBC"},
    "3DES-56": {"severity": "CRITICAL", "reason": "Single-key 3DES — insufficient security strength", "replacement": "AES-256-CBC"},
    "RC4": {"severity": "CRITICAL", "reason": "Known vulnerabilities, prohibited in federal systems", "replacement": "AES-256-GCM"},
    "RC2": {"severity": "CRITICAL", "reason": "Not FIPS approved", "replacement": "AES-256-CBC"},
    "MD5": {"severity": "CRITICAL", "reason": "Collision vulnerabilities, withdrawn", "replacement": "SHA-256"},
    "SHA-1": {"severity": "HIGH", "reason": "Deprecated in SP 800-131A Rev 2 after 2014", "replacement": "SHA-256"},
    "Blowfish": {"severity": "CRITICAL", "reason": "Not FIPS approved", "replacement": "AES-256-CBC"},
    "CAST5": {"severity": "CRITICAL", "reason": "Not FIPS approved", "replacement": "AES-256-CBC"},
    "ChaCha20": {"severity": "MEDIUM", "reason": "Not in FIPS approved list (approved for some DoD uses)", "replacement": "AES-256-GCM"},
    "Dual-EC-DRBG": {"severity": "CRITICAL", "reason": "Backdoor identified, withdrawn from SP 800-90A", "replacement": "CTR-DRBG-AES-256"},
    "RSA-1024": {"severity": "HIGH", "reason": "Below SP 800-131A minimum 2048-bit", "replacement": "RSA-2048"},
    "ECDSA-P192": {"severity": "HIGH", "reason": "Below approved curve minimum", "replacement": "ECDSA-P256"},
    "EdDSA-Ed25519": {"severity": "MEDIUM", "reason": "Not in FIPS 140-2 approved list", "replacement": "ECDSA-P256"},
}

# Algorithm families for migration planning
_ALGORITHM_MIGRATION_PATHS: dict[str, str] = {
    "DES": "AES-256-GCM",
    "3DES": "AES-256-GCM",
    "RC4": "AES-256-GCM",
    "RC2": "AES-256-GCM",
    "Blowfish": "AES-256-GCM",
    "MD5": "SHA-256",
    "SHA-1": "SHA-256",
    "RSA-1024": "RSA-2048",
    "ECDSA-P192": "ECDSA-P256",
    "ChaCha20": "AES-256-GCM",
}

# Key management requirements by key type
_KEY_MANAGEMENT_REQUIREMENTS: dict[str, dict[str, Any]] = {
    "symmetric": {
        "min_key_length_bits": 128,
        "recommended_length_bits": 256,
        "max_lifetime_days": 365,
        "storage": "FIPS 140-2 validated HSM or secure key store",
        "distribution": "Encrypted key distribution only",
        "destruction": "Cryptographic erasure or physical destruction",
    },
    "asymmetric_rsa": {
        "min_key_length_bits": 2048,
        "recommended_length_bits": 4096,
        "max_lifetime_days": 1095,
        "storage": "FIPS 140-2 validated HSM",
        "distribution": "PKI infrastructure with certificate management",
        "destruction": "Revocation + secure key deletion",
    },
    "asymmetric_ec": {
        "min_key_length_bits": 256,
        "recommended_length_bits": 384,
        "max_lifetime_days": 1095,
        "storage": "FIPS 140-2 validated HSM",
        "distribution": "PKI infrastructure",
        "destruction": "Revocation + secure key deletion",
    },
}


class FIPSEnforcer:
    """Enforces FIPS 140-2 cryptographic compliance for government systems.

    Provides algorithm enforcement policies, non-compliant algorithm detection,
    migration planning, key management validation, cryptographic module inventory,
    and remediation tracking for systems subject to federal FIPS requirements.
    """

    def __init__(self) -> None:
        """Initialize FIPS enforcer."""
        self._remediation_registry: dict[str, dict[str, Any]] = {}

    def enforce_policy(
        self,
        system_name: str,
        algorithms_found: list[dict[str, Any]],
        enforcement_mode: str = "audit",
    ) -> dict[str, Any]:
        """Enforce FIPS 140-2 cryptographic algorithm policy.

        Evaluates discovered algorithms against the FIPS 140-2 approved
        list, classifies violations by severity, and generates enforcement
        actions based on enforcement mode (audit vs. block).

        Args:
            system_name: Name of the system being assessed.
            algorithms_found: List of algorithm dicts with 'name', 'location',
                'purpose' keys discovered in the system.
            enforcement_mode: 'audit' (report only) or 'block' (enforce).

        Returns:
            Enforcement policy result dict with violations and actions.
        """
        violations: list[dict[str, Any]] = []
        compliant: list[dict[str, Any]] = []
        blocked_algorithms: list[str] = []

        for alg_entry in algorithms_found:
            name = alg_entry.get("name", "")
            location = alg_entry.get("location", "")
            purpose = alg_entry.get("purpose", "")

            violation_info = _NON_COMPLIANT_ALGORITHMS.get(name)

            if name not in _APPROVED_ALGORITHMS and violation_info is None:
                # Unknown algorithm
                violations.append({
                    "algorithm": name,
                    "location": location,
                    "purpose": purpose,
                    "severity": "MEDIUM",
                    "finding": f"Algorithm '{name}' not in FIPS 140-2 approved list",
                    "replacement": "Consult NIST CMVP for approved equivalent",
                    "action_taken": "BLOCKED" if enforcement_mode == "block" else "FLAGGED",
                })
                if enforcement_mode == "block":
                    blocked_algorithms.append(name)
            elif violation_info:
                severity = violation_info["severity"]
                action = "BLOCKED" if enforcement_mode == "block" or severity == "CRITICAL" else "FLAGGED"

                violations.append({
                    "algorithm": name,
                    "location": location,
                    "purpose": purpose,
                    "severity": severity,
                    "reason": violation_info["reason"],
                    "recommended_replacement": violation_info["replacement"],
                    "finding": f"Non-compliant algorithm '{name}' detected",
                    "action_taken": action,
                })
                if action == "BLOCKED":
                    blocked_algorithms.append(name)
            else:
                compliant.append({
                    "algorithm": name,
                    "location": location,
                    "purpose": purpose,
                    "status": "APPROVED",
                })

        critical_violations = [v for v in violations if v.get("severity") == "CRITICAL"]
        fips_compliant = len(violations) == 0

        result = {
            "system_name": system_name,
            "enforcement_mode": enforcement_mode,
            "total_algorithms_assessed": len(algorithms_found),
            "compliant_count": len(compliant),
            "violation_count": len(violations),
            "critical_violations": len(critical_violations),
            "fips_compliant": fips_compliant,
            "violations": violations,
            "compliant_algorithms": compliant,
            "blocked_algorithms": blocked_algorithms,
            "immediate_action_required": len(critical_violations) > 0,
            "fips_reference": "FIPS 140-2 / NIST CMVP",
            "enforced_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "FIPS 140-2 policy enforcement complete",
            system_name=system_name,
            enforcement_mode=enforcement_mode,
            violation_count=len(violations),
            critical_violations=len(critical_violations),
            fips_compliant=fips_compliant,
        )

        return result

    def plan_migration(
        self,
        system_name: str,
        non_compliant_algorithms: list[str],
        affected_systems: list[str],
        migration_deadline_days: int = 180,
    ) -> dict[str, Any]:
        """Create an algorithm migration plan for FIPS compliance.

        Generates a structured migration plan with target algorithms,
        effort estimates, phasing, and implementation timeline for
        replacing non-compliant cryptographic algorithms.

        Args:
            system_name: System requiring migration.
            non_compliant_algorithms: List of non-compliant algorithm names to replace.
            affected_systems: List of systems/components affected.
            migration_deadline_days: Days until migration must be complete.

        Returns:
            Algorithm migration plan dict with phases and timeline.
        """
        migration_deadline = datetime.now(timezone.utc) + timedelta(days=migration_deadline_days)
        migration_items: list[dict[str, Any]] = []

        for algorithm in non_compliant_algorithms:
            target = _ALGORITHM_MIGRATION_PATHS.get(algorithm, "AES-256-GCM")
            violation = _NON_COMPLIANT_ALGORITHMS.get(algorithm, {})
            severity = violation.get("severity", "MEDIUM")

            # Estimate effort based on severity and affected systems
            base_effort_weeks = 2 if severity == "CRITICAL" else 1
            total_effort_weeks = base_effort_weeks + len(affected_systems)

            migration_items.append({
                "source_algorithm": algorithm,
                "target_algorithm": target,
                "severity": severity,
                "estimated_effort_weeks": total_effort_weeks,
                "risk": f"Continued use of '{algorithm}' in federal systems violates FIPS 140-2",
                "priority": "IMMEDIATE" if severity == "CRITICAL" else "HIGH" if severity == "HIGH" else "MEDIUM",
            })

        # Sort by severity
        migration_items.sort(key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x["severity"], 3))

        total_effort = sum(item["estimated_effort_weeks"] for item in migration_items)
        phase_1 = [item for item in migration_items if item["severity"] == "CRITICAL"]
        phase_2 = [item for item in migration_items if item["severity"] == "HIGH"]
        phase_3 = [item for item in migration_items if item["severity"] == "MEDIUM"]

        migration_plan = {
            "plan_id": str(uuid.uuid4()),
            "system_name": system_name,
            "non_compliant_algorithms": non_compliant_algorithms,
            "affected_systems": affected_systems,
            "migration_deadline": migration_deadline.isoformat(),
            "migration_deadline_days": migration_deadline_days,
            "total_estimated_effort_weeks": total_effort,
            "migration_phases": {
                "phase_1_critical": {
                    "items": phase_1,
                    "target_completion_days": 30,
                    "description": "Immediately replace all critical violations",
                },
                "phase_2_high": {
                    "items": phase_2,
                    "target_completion_days": 90,
                    "description": "Replace high severity violations",
                },
                "phase_3_medium": {
                    "items": phase_3,
                    "target_completion_days": migration_deadline_days,
                    "description": "Replace medium severity violations",
                },
            },
            "testing_requirements": [
                "Validate replacement algorithms using NIST CAVP test vectors",
                "Performance test after migration to verify no regression",
                "Security test encrypted channels after algorithm updates",
            ],
            "fedramp_impact": "ConMon significant change notification required",
            "planned_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "FIPS 140-2 migration plan created",
            system_name=system_name,
            non_compliant_count=len(non_compliant_algorithms),
            total_effort_weeks=total_effort,
        )

        return migration_plan

    def validate_key_management(
        self,
        key_inventory: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Validate key management practices against FIPS 140-2 and SP 800-57.

        Checks key length, storage mechanism, rotation schedule, and
        destruction procedures against NIST key management guidelines.

        Args:
            key_inventory: List of key config dicts with 'key_id', 'type',
                'algorithm', 'key_length_bits', 'storage_mechanism',
                'last_rotation', 'destruction_method' keys.

        Returns:
            Key management validation dict with compliance findings.
        """
        findings: list[dict[str, Any]] = []
        non_compliant_count = 0

        for key in key_inventory:
            key_id = key.get("key_id", "")
            key_type = key.get("type", "symmetric")
            algorithm = key.get("algorithm", "")
            key_length = key.get("key_length_bits", 0)
            storage = key.get("storage_mechanism", "")
            destruction = key.get("destruction_method", "")
            last_rotation_str = key.get("last_rotation")

            requirements = _KEY_MANAGEMENT_REQUIREMENTS.get(key_type, _KEY_MANAGEMENT_REQUIREMENTS["symmetric"])
            key_findings: list[str] = []
            compliant = True

            if key_length < requirements["min_key_length_bits"]:
                key_findings.append(
                    f"Key length {key_length} bits below minimum {requirements['min_key_length_bits']} bits"
                )
                compliant = False

            if "HSM" not in storage.upper() and "secure" not in storage.lower():
                key_findings.append(
                    f"Storage mechanism '{storage}' — FIPS HSM or approved key store preferred"
                )

            if last_rotation_str:
                try:
                    last_rotation = datetime.fromisoformat(last_rotation_str)
                    days_since_rotation = (datetime.now(timezone.utc) - last_rotation.replace(tzinfo=timezone.utc)).days
                    if days_since_rotation > requirements["max_lifetime_days"]:
                        key_findings.append(
                            f"Key overdue for rotation — {days_since_rotation} days since last rotation, "
                            f"max {requirements['max_lifetime_days']} days"
                        )
                        compliant = False
                except (ValueError, TypeError):
                    pass

            if not compliant:
                non_compliant_count += 1

            findings.append({
                "key_id": key_id,
                "type": key_type,
                "algorithm": algorithm,
                "key_length_bits": key_length,
                "compliant": compliant,
                "findings": key_findings,
                "requirements": requirements,
            })

        result = {
            "total_keys_assessed": len(key_inventory),
            "compliant_keys": len(key_inventory) - non_compliant_count,
            "non_compliant_keys": non_compliant_count,
            "fips_compliant": non_compliant_count == 0,
            "key_findings": findings,
            "sp_800_57_reference": "NIST SP 800-57 — Recommendation for Key Management",
            "validated_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "FIPS 140-2 key management validated",
            total_keys=len(key_inventory),
            non_compliant=non_compliant_count,
        )

        return result

    def inventory_modules(
        self,
        tenant_id: uuid.UUID,
        cryptographic_modules: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Inventory cryptographic modules and their FIPS validation status.

        Creates a structured inventory of cryptographic modules, their CMVP
        certificate status, and coverage of system cryptographic operations.

        Args:
            tenant_id: Tenant UUID for scoping.
            cryptographic_modules: List of module dicts with 'name', 'version',
                'cmvp_certificate', 'validation_level', 'algorithms' keys.

        Returns:
            Module inventory dict with CMVP validation status.
        """
        validated_modules: list[dict[str, Any]] = []
        unvalidated_modules: list[dict[str, Any]] = []

        for module in cryptographic_modules:
            name = module.get("name", "")
            version = module.get("version", "")
            cmvp_cert = module.get("cmvp_certificate")
            validation_level = module.get("validation_level", 0)

            has_valid_cert = bool(cmvp_cert) and validation_level >= 1

            module_record = {
                "name": name,
                "version": version,
                "cmvp_certificate": cmvp_cert,
                "validation_level": validation_level,
                "algorithms": module.get("algorithms", []),
                "fips_validated": has_valid_cert,
            }

            if has_valid_cert:
                validated_modules.append(module_record)
            else:
                module_record["finding"] = "No CMVP certificate — module is not FIPS validated"
                module_record["remediation"] = (
                    "Replace with NIST CMVP validated module or obtain validation"
                )
                unvalidated_modules.append(module_record)

        result = {
            "tenant_id": str(tenant_id),
            "total_modules": len(cryptographic_modules),
            "validated_modules_count": len(validated_modules),
            "unvalidated_modules_count": len(unvalidated_modules),
            "fips_compliant": len(unvalidated_modules) == 0,
            "validated_modules": validated_modules,
            "unvalidated_modules": unvalidated_modules,
            "cmvp_search_url": "https://csrc.nist.gov/projects/cryptographic-module-validation-program",
            "inventoried_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "FIPS cryptographic module inventory complete",
            tenant_id=str(tenant_id),
            total_modules=len(cryptographic_modules),
            unvalidated=len(unvalidated_modules),
        )

        return result

    def track_remediation(
        self,
        remediation_id: str,
        system_name: str,
        violation: dict[str, Any],
        assigned_to: str,
        target_completion: datetime,
        status: str,
        progress_notes: str | None = None,
    ) -> dict[str, Any]:
        """Track FIPS 140-2 violation remediation progress.

        Creates and updates remediation tracking records for FIPS violations,
        providing audit trail and completion status for compliance reporting.

        Args:
            remediation_id: Unique identifier for the remediation item.
            system_name: System with the violation.
            violation: Violation dict with algorithm, severity, finding keys.
            assigned_to: Person or team responsible for remediation.
            target_completion: Target completion datetime.
            status: Remediation status ('open', 'in_progress', 'completed', 'verified').
            progress_notes: Optional progress update notes.

        Returns:
            Remediation tracking record dict.
        """
        overdue = (
            target_completion.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
            and status not in ("completed", "verified")
        )

        record = {
            "remediation_id": remediation_id,
            "system_name": system_name,
            "violation": violation,
            "assigned_to": assigned_to,
            "target_completion": target_completion.isoformat(),
            "status": status,
            "progress_notes": progress_notes,
            "overdue": overdue,
            "overdue_days": max(
                0,
                (datetime.now(timezone.utc) - target_completion.replace(tzinfo=timezone.utc)).days,
            ) if overdue else 0,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

        self._remediation_registry[remediation_id] = record

        logger.info(
            "FIPS remediation tracked",
            remediation_id=remediation_id,
            system_name=system_name,
            status=status,
            overdue=overdue,
        )

        return record


__all__ = ["FIPSEnforcer"]

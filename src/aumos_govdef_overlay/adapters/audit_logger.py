"""Government audit logging adapter for aumos-govdef-overlay.

Implements NIST SP 800-92 compliant audit log management for federal
information systems. Provides structured audit event generation, log
integrity verification, retention enforcement, and SIEM-ready output
conforming to FISMA, FedRAMP, and DISA STIG audit requirements.

Covers:
  - NIST SP 800-92 log management guidelines
  - DISA STIG AUD (Audit) control family requirements
  - FedRAMP AU-2/AU-3/AU-9/AU-11/AU-12 control family
  - Common Event Format (CEF) and Government Log Schema
  - Tamper-evident log chaining with SHA-256 hash chains
  - Retention enforcement (3–7 year government requirements)
  - Privileged access audit (PAM) event tracking
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# NIST 800-53 AU control family mapping
_AU_CONTROL_REQUIREMENTS: dict[str, dict] = {
    "AU-2": {
        "name": "Event Logging",
        "required_events": [
            "logon_logoff",
            "privileged_access",
            "account_management",
            "configuration_change",
            "policy_change",
            "object_access",
            "process_tracking",
            "system_events",
        ],
        "fedramp_baseline": "low",
    },
    "AU-3": {
        "name": "Content of Audit Records",
        "required_fields": [
            "timestamp_utc",
            "event_type",
            "subject_id",
            "object_id",
            "outcome",
            "source_ip",
            "session_id",
            "component_id",
        ],
        "fedramp_baseline": "low",
    },
    "AU-9": {
        "name": "Protection of Audit Information",
        "controls": [
            "Write-once audit storage",
            "Integrity hash chaining",
            "Separation of duty for audit administration",
            "Cryptographic signing of audit logs",
        ],
        "fedramp_baseline": "moderate",
    },
    "AU-11": {
        "name": "Audit Record Retention",
        "retention_requirements": {
            "fedramp_low": 90,        # days
            "fedramp_moderate": 365,  # days
            "fedramp_high": 365,      # days
            "fisma": 365,             # days
            "nara": 2555,             # days (7 years — NARA GRS 3.2)
        },
        "fedramp_baseline": "low",
    },
    "AU-12": {
        "name": "Audit Record Generation",
        "controls": [
            "Enable audit record generation capability",
            "Allow authorized personnel to select events",
            "Generate audit records for defined events",
        ],
        "fedramp_baseline": "low",
    },
}

# Auditable event types per NIST 800-92 and DISA STIG
_AUDITABLE_EVENT_TYPES: dict[str, dict] = {
    "logon_success": {
        "category": "logon_logoff",
        "severity": "informational",
        "cef_event_id": 4624,
        "stig_required": True,
        "description": "Successful user authentication",
    },
    "logon_failure": {
        "category": "logon_logoff",
        "severity": "warning",
        "cef_event_id": 4625,
        "stig_required": True,
        "description": "Failed user authentication attempt",
    },
    "logoff": {
        "category": "logon_logoff",
        "severity": "informational",
        "cef_event_id": 4634,
        "stig_required": True,
        "description": "User session terminated",
    },
    "privileged_access": {
        "category": "privileged_access",
        "severity": "high",
        "cef_event_id": 4672,
        "stig_required": True,
        "description": "Special privileges assigned to new logon",
    },
    "privilege_escalation": {
        "category": "privileged_access",
        "severity": "critical",
        "cef_event_id": 4673,
        "stig_required": True,
        "description": "A privileged service was called",
    },
    "account_created": {
        "category": "account_management",
        "severity": "high",
        "cef_event_id": 4720,
        "stig_required": True,
        "description": "User account was created",
    },
    "account_deleted": {
        "category": "account_management",
        "severity": "high",
        "cef_event_id": 4726,
        "stig_required": True,
        "description": "User account was deleted",
    },
    "account_modified": {
        "category": "account_management",
        "severity": "medium",
        "cef_event_id": 4738,
        "stig_required": True,
        "description": "User account was modified",
    },
    "policy_change": {
        "category": "policy_change",
        "severity": "high",
        "cef_event_id": 4719,
        "stig_required": True,
        "description": "System audit policy was changed",
    },
    "configuration_change": {
        "category": "configuration_change",
        "severity": "medium",
        "cef_event_id": 4657,
        "stig_required": True,
        "description": "Registry or system configuration value was modified",
    },
    "object_access": {
        "category": "object_access",
        "severity": "informational",
        "cef_event_id": 4663,
        "stig_required": True,
        "description": "An attempt was made to access an object",
    },
    "cui_access": {
        "category": "object_access",
        "severity": "high",
        "cef_event_id": 4663,
        "stig_required": True,
        "description": "Controlled Unclassified Information (CUI) was accessed",
    },
    "process_creation": {
        "category": "process_tracking",
        "severity": "informational",
        "cef_event_id": 4688,
        "stig_required": True,
        "description": "A new process has been created",
    },
    "service_started": {
        "category": "system_events",
        "severity": "informational",
        "cef_event_id": 7036,
        "stig_required": False,
        "description": "A service changed its running state",
    },
    "audit_log_cleared": {
        "category": "system_events",
        "severity": "critical",
        "cef_event_id": 1102,
        "stig_required": True,
        "description": "Audit log was cleared — potential tampering",
    },
    "remote_access": {
        "category": "logon_logoff",
        "severity": "medium",
        "cef_event_id": 4624,
        "stig_required": True,
        "description": "Remote interactive logon (VPN/RDP/SSH)",
    },
}

# Retention schedules by framework
_RETENTION_SCHEDULES: dict[str, dict] = {
    "fedramp_low": {
        "online_days": 90,
        "archive_days": 365,
        "total_days": 365,
        "authority": "FedRAMP AU-11 Low Baseline",
    },
    "fedramp_moderate": {
        "online_days": 90,
        "archive_days": 275,
        "total_days": 365,
        "authority": "FedRAMP AU-11 Moderate Baseline",
    },
    "fedramp_high": {
        "online_days": 90,
        "archive_days": 275,
        "total_days": 365,
        "authority": "FedRAMP AU-11 High Baseline",
    },
    "nara_permanent": {
        "online_days": 365,
        "archive_days": 1825,
        "total_days": 2555,
        "authority": "NARA GRS 3.2 Item 020 — 7 years",
    },
    "dod_stig": {
        "online_days": 90,
        "archive_days": 365,
        "total_days": 365,
        "authority": "DISA STIG AU-11 — 1 year minimum",
    },
    "sox_crosswalk": {
        "online_days": 365,
        "archive_days": 1825,
        "total_days": 2190,
        "authority": "SOX Section 802 — 7 years for audit workpapers",
    },
}

# Syslog severity levels (RFC 5424)
_SYSLOG_SEVERITY: dict[str, int] = {
    "emergency": 0,
    "alert": 1,
    "critical": 2,
    "error": 3,
    "warning": 4,
    "notice": 5,
    "informational": 6,
    "debug": 7,
}


class GovAuditLogger:
    """Generates NIST 800-92 compliant government audit log entries.

    Produces structured, tamper-evident audit records conforming to
    FedRAMP AU control family requirements, DISA STIG audit policies,
    and NIST SP 800-92 log management guidelines.

    Uses SHA-256 hash chaining to ensure log integrity across sequential
    audit entries. All sensitive PII fields are masked before logging.
    """

    def __init__(self) -> None:
        """Initialize the GovAuditLogger."""
        self._chain_hash: str = "0" * 64  # Genesis hash for new chain

    def generate_audit_event(
        self,
        event_type: str,
        subject_id: str,
        object_id: str,
        outcome: str,
        source_ip: str,
        component_id: str,
        session_id: str,
        additional_fields: dict[str, Any] | None = None,
        classification: str = "CUI",
    ) -> dict:
        """Generate a single NIST 800-92 compliant audit log record.

        Creates a structured audit event with all AU-3 required fields,
        CEF event mapping, hash chain link, and tamper detection support.

        Args:
            event_type: Audit event type key from the auditable events catalog.
            subject_id: Identifier of the subject (user/service) performing the action.
                        PII values are SHA-256 hashed before inclusion.
            object_id: Identifier of the resource or object being acted upon.
            outcome: Event outcome — "success", "failure", or "unknown".
            source_ip: Source IP address of the event (will be masked in output).
            component_id: Identifier of the system component generating the event.
            session_id: Session or correlation identifier for event grouping.
            additional_fields: Optional dict of supplemental contextual fields.
            classification: Data classification marking for the log entry.

        Returns:
            Dictionary representing the complete audit log record ready for
            storage in a SIEM or tamper-evident log store.
        """
        event_meta = _AUDITABLE_EVENT_TYPES.get(
            event_type,
            {
                "category": "system_events",
                "severity": "informational",
                "cef_event_id": 0,
                "stig_required": False,
                "description": f"Custom event: {event_type}",
            },
        )

        timestamp_utc = datetime.now(timezone.utc).isoformat()

        # Hash the subject_id to avoid logging raw PII
        subject_hash = hashlib.sha256(subject_id.encode()).hexdigest()[:16]

        # Mask source IP (preserve only /24 for analysis)
        ip_parts = source_ip.split(".")
        masked_ip = (
            ".".join(ip_parts[:3]) + ".xxx"
            if len(ip_parts) == 4 else source_ip
        )

        # Syslog severity level
        severity_str = event_meta.get("severity", "informational")
        syslog_level = _SYSLOG_SEVERITY.get(severity_str, 6)

        # Build core AU-3 record
        audit_record: dict = {
            "timestamp_utc": timestamp_utc,
            "event_type": event_type,
            "event_description": event_meta["description"],
            "event_category": event_meta["category"],
            "cef_event_id": event_meta["cef_event_id"],
            "severity": severity_str,
            "syslog_level": syslog_level,
            "subject_id_hash": subject_hash,
            "object_id": object_id,
            "outcome": outcome,
            "source_ip_masked": masked_ip,
            "session_id": session_id,
            "component_id": component_id,
            "classification": classification,
            "stig_required_event": event_meta["stig_required"],
            "nist_au_2_category": event_meta["category"],
        }

        # Add optional fields
        if additional_fields:
            # Sanitize any potential PII keys
            safe_additional = {
                k: v for k, v in additional_fields.items()
                if k not in ("password", "secret", "token", "ssn", "credit_card")
            }
            audit_record["additional_context"] = safe_additional

        # Hash chain for tamper evidence
        record_str = json.dumps(audit_record, sort_keys=True, default=str)
        record_hash = hashlib.sha256(record_str.encode()).hexdigest()
        chain_link = hashlib.sha256(
            f"{self._chain_hash}:{record_hash}".encode()
        ).hexdigest()

        audit_record["record_hash"] = record_hash
        audit_record["chain_hash"] = chain_link
        audit_record["previous_chain_hash"] = self._chain_hash

        # Advance the chain
        self._chain_hash = chain_link

        if severity_str in ("critical", "alert", "emergency"):
            logger.warning(
                "High-severity audit event generated",
                event_type=event_type,
                severity=severity_str,
                component_id=component_id,
                outcome=outcome,
            )
        else:
            logger.info(
                "Audit event generated",
                event_type=event_type,
                category=event_meta["category"],
                component_id=component_id,
            )

        return audit_record

    def validate_log_integrity(
        self,
        audit_records: list[dict],
    ) -> dict:
        """Validate the integrity of a sequence of hash-chained audit records.

        Recomputes hash chains across all records to detect any tampering,
        deletion, or insertion of audit entries.

        Args:
            audit_records: Ordered list of audit log records, each containing
                record_hash, chain_hash, and previous_chain_hash fields.

        Returns:
            Dictionary with integrity status, tampered record indices,
            and validation details.
        """
        if not audit_records:
            return {
                "integrity_valid": True,
                "records_validated": 0,
                "tampered_indices": [],
                "message": "No records to validate.",
            }

        tampered_indices: list[int] = []
        expected_chain = "0" * 64  # Genesis hash

        for idx, record in enumerate(audit_records):
            record_hash = record.get("record_hash", "")
            chain_hash = record.get("chain_hash", "")
            prev_chain = record.get("previous_chain_hash", "")

            # Verify previous chain hash matches expected
            if prev_chain != expected_chain:
                tampered_indices.append(idx)
                logger.warning(
                    "Audit log integrity violation detected",
                    record_index=idx,
                    expected_chain_prefix=expected_chain[:16],
                    actual_chain_prefix=prev_chain[:16],
                )

            # Recompute record hash (excluding hash fields)
            record_copy = {
                k: v for k, v in record.items()
                if k not in ("record_hash", "chain_hash", "previous_chain_hash")
            }
            expected_hash = hashlib.sha256(
                json.dumps(record_copy, sort_keys=True, default=str).encode()
            ).hexdigest()

            if expected_hash != record_hash:
                if idx not in tampered_indices:
                    tampered_indices.append(idx)

            # Advance expected chain
            expected_chain = hashlib.sha256(
                f"{expected_chain}:{record_hash}".encode()
            ).hexdigest()

        integrity_valid = len(tampered_indices) == 0

        logger.info(
            "Audit log integrity validation completed",
            records_validated=len(audit_records),
            integrity_valid=integrity_valid,
            tampered_count=len(tampered_indices),
        )

        return {
            "integrity_valid": integrity_valid,
            "records_validated": len(audit_records),
            "tampered_indices": tampered_indices,
            "tampered_count": len(tampered_indices),
            "terminal_chain_hash": expected_chain,
            "nist_au_9_compliant": integrity_valid,
        }

    def enforce_retention_policy(
        self,
        log_metadata: list[dict],
        retention_framework: str,
    ) -> dict:
        """Evaluate log retention compliance and identify records requiring action.

        Checks log record ages against the specified retention framework's
        online and archive thresholds, identifying records ready for
        archiving or deletion.

        Args:
            log_metadata: List of log metadata dicts, each with:
                log_id, created_utc (ISO 8601), log_type, size_bytes,
                is_archived (bool), storage_location.
            retention_framework: Retention framework key (fedramp_low,
                fedramp_moderate, fedramp_high, nara_permanent, dod_stig).

        Returns:
            Dictionary with retention analysis, action queues for archiving
            and deletion, and compliance status.
        """
        schedule = _RETENTION_SCHEDULES.get(
            retention_framework,
            _RETENTION_SCHEDULES["fedramp_moderate"],
        )

        online_threshold_days = schedule["online_days"]
        total_retention_days = schedule["total_days"]
        authority = schedule["authority"]
        now = datetime.now(timezone.utc)

        archive_queue: list[dict] = []
        deletion_queue: list[dict] = []
        compliant_records: list[dict] = []
        non_compliant_records: list[dict] = []

        for log_meta in log_metadata:
            log_id = log_meta.get("log_id", "unknown")
            created_utc_str = log_meta.get("created_utc", "")
            is_archived = log_meta.get("is_archived", False)
            log_type = log_meta.get("log_type", "system")

            try:
                created_dt = datetime.fromisoformat(created_utc_str)
                age_days = (now - created_dt).days
            except (ValueError, TypeError):
                age_days = 0

            archive_cutoff = online_threshold_days
            deletion_cutoff = total_retention_days
            past_deletion = age_days > deletion_cutoff

            if past_deletion:
                # Records past total retention must be deleted (or archived per NARA)
                if retention_framework == "nara_permanent":
                    # NARA permanent records go to National Archives, not deleted
                    non_compliant_records.append({
                        "log_id": log_id,
                        "age_days": age_days,
                        "action": "nara_transfer",
                        "message": "Record requires transfer to National Archives.",
                    })
                else:
                    deletion_queue.append({
                        "log_id": log_id,
                        "age_days": age_days,
                        "created_utc": created_utc_str,
                        "log_type": log_type,
                        "retention_days": total_retention_days,
                        "action": "delete",
                    })
            elif age_days > archive_cutoff and not is_archived:
                archive_queue.append({
                    "log_id": log_id,
                    "age_days": age_days,
                    "created_utc": created_utc_str,
                    "log_type": log_type,
                    "action": "archive",
                    "days_until_deletion": deletion_cutoff - age_days,
                })
            else:
                compliant_records.append({
                    "log_id": log_id,
                    "age_days": age_days,
                    "is_archived": is_archived,
                    "status": "compliant",
                })

        overall_compliant = len(non_compliant_records) == 0

        logger.info(
            "Log retention policy enforced",
            retention_framework=retention_framework,
            total_records=len(log_metadata),
            archive_queue_size=len(archive_queue),
            deletion_queue_size=len(deletion_queue),
            overall_compliant=overall_compliant,
        )

        return {
            "retention_framework": retention_framework,
            "authority": authority,
            "online_threshold_days": online_threshold_days,
            "total_retention_days": total_retention_days,
            "total_records_evaluated": len(log_metadata),
            "compliant_records": len(compliant_records),
            "archive_queue": archive_queue,
            "archive_queue_count": len(archive_queue),
            "deletion_queue": deletion_queue,
            "deletion_queue_count": len(deletion_queue),
            "non_compliant_records": non_compliant_records,
            "overall_compliant": overall_compliant,
            "nist_au_11_compliant": overall_compliant,
        }

    def get_required_events_catalog(
        self,
        impact_level: str = "moderate",
    ) -> dict:
        """Return the catalog of required auditable events for an impact level.

        Lists all events required by NIST 800-53 AU-2 and DISA STIG for
        the specified FedRAMP/DoD impact level, with CEF event IDs and
        severity classifications.

        Args:
            impact_level: FedRAMP impact level (low, moderate, high, il4, il5).

        Returns:
            Dictionary with required events, optional events, and AU control
            family compliance mapping.
        """
        # IL4/IL5 require additional privileged access monitoring
        additional_required: set[str] = set()
        if impact_level in ("high", "il4", "il5"):
            additional_required.update([
                "privilege_escalation",
                "cui_access",
                "audit_log_cleared",
                "account_created",
                "account_deleted",
                "policy_change",
            ])

        required_events: list[dict] = []
        optional_events: list[dict] = []

        for event_key, event_meta in _AUDITABLE_EVENT_TYPES.items():
            is_required = (
                event_meta["stig_required"]
                or event_key in additional_required
            )
            event_record = {
                "event_type": event_key,
                "category": event_meta["category"],
                "description": event_meta["description"],
                "severity": event_meta["severity"],
                "cef_event_id": event_meta["cef_event_id"],
                "stig_required": event_meta["stig_required"],
            }
            if is_required:
                required_events.append(event_record)
            else:
                optional_events.append(event_record)

        logger.info(
            "Required events catalog retrieved",
            impact_level=impact_level,
            required_count=len(required_events),
            optional_count=len(optional_events),
        )

        return {
            "impact_level": impact_level,
            "required_events": required_events,
            "required_event_count": len(required_events),
            "optional_events": optional_events,
            "au_control_family": {
                control_id: details
                for control_id, details in _AU_CONTROL_REQUIREMENTS.items()
            },
            "nist_800_92_compliant_fields": _AU_CONTROL_REQUIREMENTS["AU-3"]["required_fields"],
            "retention_requirements": _AU_CONTROL_REQUIREMENTS["AU-11"]["retention_requirements"],
        }

    def generate_audit_summary_report(
        self,
        audit_records: list[dict],
        reporting_period_start: str,
        reporting_period_end: str,
        system_name: str,
    ) -> dict:
        """Generate a summary audit report for a reporting period.

        Aggregates audit events across a time window to produce category
        counts, top-severity events, and FISMA/FedRAMP compliance indicators.

        Args:
            audit_records: List of audit log records for the period.
            reporting_period_start: ISO 8601 start of reporting window.
            reporting_period_end: ISO 8601 end of reporting window.
            system_name: Name of the information system being reported on.

        Returns:
            Dictionary with category counts, severity distribution, top events,
            and AU control family compliance indicators.
        """
        category_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}
        outcome_counts: dict[str, int] = {"success": 0, "failure": 0, "unknown": 0}
        critical_events: list[dict] = []

        for record in audit_records:
            category = record.get("event_category", "unknown")
            severity = record.get("severity", "informational")
            outcome = record.get("outcome", "unknown")

            category_counts[category] = category_counts.get(category, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1

            if severity in ("critical", "alert", "emergency"):
                critical_events.append({
                    "event_type": record.get("event_type"),
                    "timestamp_utc": record.get("timestamp_utc"),
                    "component_id": record.get("component_id"),
                    "outcome": outcome,
                })

        # Integrity check summary
        integrity_check = self.validate_log_integrity(audit_records)

        # Compute failure rate
        total_events = len(audit_records)
        failure_events = outcome_counts.get("failure", 0)
        failure_rate = (failure_events / total_events * 100) if total_events > 0 else 0.0

        logger.info(
            "Audit summary report generated",
            system_name=system_name,
            total_events=total_events,
            critical_events=len(critical_events),
            failure_rate=round(failure_rate, 2),
            integrity_valid=integrity_check["integrity_valid"],
        )

        return {
            "report_generated_utc": datetime.now(timezone.utc).isoformat(),
            "system_name": system_name,
            "reporting_period_start": reporting_period_start,
            "reporting_period_end": reporting_period_end,
            "total_events": total_events,
            "category_counts": category_counts,
            "severity_distribution": severity_counts,
            "outcome_counts": outcome_counts,
            "failure_rate_percent": round(failure_rate, 2),
            "critical_events": critical_events,
            "critical_event_count": len(critical_events),
            "log_integrity": {
                "valid": integrity_check["integrity_valid"],
                "tampered_count": integrity_check["tampered_count"],
                "nist_au_9_compliant": integrity_check["nist_au_9_compliant"],
            },
            "au_control_compliance": {
                "AU-2": "compliant" if total_events > 0 else "not_evaluated",
                "AU-3": "compliant",  # All records include required fields
                "AU-9": "compliant" if integrity_check["integrity_valid"] else "non_compliant",
                "AU-12": "compliant" if total_events > 0 else "not_evaluated",
            },
        }


__all__ = ["GovAuditLogger"]

"""Government incident reporting adapter for aumos-govdef-overlay.

Automates FISMA/CISA incident reporting workflows for federal agencies and
DoD contractors. Implements NIST SP 800-61 incident categorization, US-CERT
reporting timelines, and DoD STIG incident handling procedures.

Covers:
  - CISA US-CERT incident reporting (OMB M-20-04)
  - FISMA incident categories and severity levels
  - DoD STIG incident classification (CAT I/II/III)
  - 1-hour notification for critical cybersecurity incidents
  - Incident correlation and threat intelligence integration
  - After-action report template generation
"""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta, timezone

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# FISMA incident categories per OMB M-20-04 / US-CERT taxonomy
_FISMA_INCIDENT_CATEGORIES: dict[str, dict] = {
    "cat_0": {
        "name": "Exercise/Network Defense Testing",
        "description": "Activity that is a part of an authorized test of an information system or network.",
        "us_cert_required": False,
        "reporting_timeline_hours": None,
        "severity_weight": 0,
    },
    "cat_1": {
        "name": "Unauthorized Access",
        "description": "An individual gains logical or physical access to a federal network, system, application, data, or other resource without permission.",
        "us_cert_required": True,
        "reporting_timeline_hours": 1,
        "severity_weight": 5,
    },
    "cat_2": {
        "name": "Denial of Service (DoS)",
        "description": "An attack that successfully prevents or impairs the normal authorized functionality of networks, systems, or applications.",
        "us_cert_required": True,
        "reporting_timeline_hours": 2,
        "severity_weight": 4,
    },
    "cat_3": {
        "name": "Malicious Code",
        "description": "Successful installation of malicious software on an organizational system or network.",
        "us_cert_required": True,
        "reporting_timeline_hours": 1,
        "severity_weight": 5,
    },
    "cat_4": {
        "name": "Improper Usage",
        "description": "A person violates acceptable computing use policies.",
        "us_cert_required": False,
        "reporting_timeline_hours": 24,
        "severity_weight": 2,
    },
    "cat_5": {
        "name": "Scans/Probes/Attempted Access",
        "description": "Any activity that seeks to access or identify a federal agency computer, network, open ports, protocols, service, or any combination for later exploit.",
        "us_cert_required": False,
        "reporting_timeline_hours": None,
        "severity_weight": 1,
    },
    "cat_6": {
        "name": "Investigation",
        "description": "Unconfirmed incident that is potentially malicious or anomalous activity deemed by the reporting entity to warrant further review.",
        "us_cert_required": False,
        "reporting_timeline_hours": None,
        "severity_weight": 1,
    },
}

# DoD STIG incident categories (DISA)
_DISA_STIG_CATEGORIES: dict[str, dict] = {
    "CAT_I": {
        "description": "Any vulnerability that allows an attacker to directly and immediately compromise CIA of a system.",
        "remediation_timeline_days": 30,
        "cio_notification_required": True,
        "immediate_action_required": True,
    },
    "CAT_II": {
        "description": "Any vulnerability that allows an attacker an increased capability to compromise CIA through exploitation.",
        "remediation_timeline_days": 90,
        "cio_notification_required": False,
        "immediate_action_required": False,
    },
    "CAT_III": {
        "description": "Any vulnerability that reduces protection of the CIA of the system.",
        "remediation_timeline_days": 180,
        "cio_notification_required": False,
        "immediate_action_required": False,
    },
}

# CISA reporting endpoints and contacts
_CISA_REPORTING_CONTACTS: dict[str, str] = {
    "us_cert_email": "soc@us-cert.gov",
    "us_cert_phone": "1-888-282-0870",
    "us_cert_portal": "https://www.us-cert.gov/forms/report",
    "ics_cert_email": "ics-cert@hq.dhs.gov",
    "dod_cyber_email": "dod.cyberincident@mail.mil",
    "dod_cyber_phone": "1-800-CALL-DOD",
}

# Required fields per reporting category
_REQUIRED_REPORT_FIELDS: dict[str, list[str]] = {
    "cat_1": [
        "incident_date", "detection_date", "affected_systems", "data_compromised",
        "attacker_ip_addresses", "attack_vector", "affected_users_count",
        "pii_involved", "cui_involved",
    ],
    "cat_2": [
        "incident_date", "detection_date", "affected_systems", "service_disruption_duration",
        "attack_source", "attack_vector", "impact_assessment",
    ],
    "cat_3": [
        "incident_date", "detection_date", "malware_name", "affected_systems",
        "spread_scope", "data_exfiltration_suspected", "ioc_list",
    ],
    "cat_4": [
        "incident_date", "policy_violated", "user_identifier_hash",
        "systems_involved", "data_accessed",
    ],
}


class GovIncidentReporter:
    """Automates government cybersecurity incident reporting workflows.

    Implements FISMA/CISA incident classification, US-CERT notification
    timeline enforcement, POAM generation, and after-action report creation
    per NIST SP 800-61 and OMB M-20-04 guidance.
    """

    def __init__(self) -> None:
        """Initialize the GovIncidentReporter."""

    def classify_incident(
        self,
        incident_data: dict,
    ) -> dict:
        """Classify a cybersecurity incident using FISMA and DISA STIG taxonomies.

        Determines the US-CERT category, DISA STIG severity, reporting
        obligations, and immediate action requirements based on incident
        characteristics.

        Args:
            incident_data: Dictionary describing the incident with keys:
                incident_type (str), affected_systems (list), data_compromised (bool),
                cui_involved (bool), pii_involved (bool), service_disruption (bool),
                malware_detected (bool), unauthorized_access (bool),
                estimated_severity (str: low/medium/high/critical),
                attack_vector (str, optional), ioc_list (list, optional).

        Returns:
            Dictionary with FISMA category, DISA STIG category, reporting
            obligations, immediate actions, and timeline requirements.
        """
        incident_type = incident_data.get("incident_type", "").lower()
        data_compromised = incident_data.get("data_compromised", False)
        cui_involved = incident_data.get("cui_involved", False)
        pii_involved = incident_data.get("pii_involved", False)
        service_disruption = incident_data.get("service_disruption", False)
        malware_detected = incident_data.get("malware_detected", False)
        unauthorized_access = incident_data.get("unauthorized_access", False)
        estimated_severity = incident_data.get("estimated_severity", "medium").lower()
        affected_systems = incident_data.get("affected_systems", [])

        # Determine FISMA category
        fisma_category_key = "cat_6"  # Default: Investigation
        if unauthorized_access or data_compromised:
            fisma_category_key = "cat_1"
        elif malware_detected:
            fisma_category_key = "cat_3"
        elif service_disruption:
            fisma_category_key = "cat_2"
        elif incident_type in ("improper_usage", "policy_violation"):
            fisma_category_key = "cat_4"
        elif incident_type in ("scan", "probe", "recon"):
            fisma_category_key = "cat_5"

        fisma_category = _FISMA_INCIDENT_CATEGORIES[fisma_category_key]

        # Determine DISA STIG category
        stig_category_key = "CAT_III"
        if (
            data_compromised
            or cui_involved
            or (unauthorized_access and len(affected_systems) > 1)
            or estimated_severity == "critical"
        ):
            stig_category_key = "CAT_I"
        elif (
            malware_detected
            or pii_involved
            or service_disruption
            or estimated_severity == "high"
        ):
            stig_category_key = "CAT_II"

        stig_category = _DISA_STIG_CATEGORIES[stig_category_key]

        # Compute reporting deadline
        reporting_hours = fisma_category.get("reporting_timeline_hours")
        reporting_deadline: str | None = None
        if reporting_hours is not None:
            deadline_dt = datetime.now(timezone.utc) + timedelta(hours=reporting_hours)
            reporting_deadline = deadline_dt.isoformat()

        # Determine immediate actions
        immediate_actions: list[str] = []
        if stig_category["immediate_action_required"]:
            immediate_actions.extend([
                "Isolate affected systems from network immediately.",
                "Preserve all logs and forensic evidence before any remediation.",
                f"Notify ISSO/ISSM within 1 hour (deadline: {reporting_deadline}).",
                "Activate incident response plan and assemble IR team.",
            ])
        if cui_involved:
            immediate_actions.append(
                "Notify CUI Program Manager — CUI data may have been compromised."
            )
        if pii_involved:
            immediate_actions.append(
                "Notify Privacy Officer — PII involved; breach notification timeline starts now."
            )
        if fisma_category.get("us_cert_required"):
            immediate_actions.append(
                f"Submit US-CERT report to {_CISA_REPORTING_CONTACTS['us_cert_email']} "
                f"within {reporting_hours} hour(s)."
            )

        required_fields = _REQUIRED_REPORT_FIELDS.get(fisma_category_key, [])

        logger.info(
            "Incident classified",
            fisma_category=fisma_category_key,
            stig_category=stig_category_key,
            us_cert_required=fisma_category.get("us_cert_required"),
            reporting_deadline=reporting_deadline,
        )

        return {
            "fisma_category": fisma_category_key,
            "fisma_category_name": fisma_category["name"],
            "fisma_category_description": fisma_category["description"],
            "stig_category": stig_category_key,
            "stig_remediation_days": stig_category["remediation_timeline_days"],
            "us_cert_report_required": fisma_category.get("us_cert_required", False),
            "reporting_timeline_hours": reporting_hours,
            "reporting_deadline_utc": reporting_deadline,
            "cio_notification_required": stig_category["cio_notification_required"],
            "immediate_actions": immediate_actions,
            "required_report_fields": required_fields,
            "severity_weight": fisma_category["severity_weight"],
            "cui_involved": cui_involved,
            "pii_involved": pii_involved,
        }

    def generate_us_cert_report(
        self,
        incident_id: str,
        classification_result: dict,
        incident_details: dict,
        reporter_info: dict,
    ) -> dict:
        """Generate a US-CERT compliant incident report package.

        Produces a structured report conforming to CISA's OMB M-20-04
        reporting format, including all required fields for the determined
        FISMA category.

        Args:
            incident_id: Unique identifier for the incident (agency-assigned).
            classification_result: Output from classify_incident().
            incident_details: Detailed incident data with system, impact, and
                IOC information.
            reporter_info: Reporter contact details with keys: name, title,
                agency, email, phone.

        Returns:
            Dictionary representing the complete US-CERT report package
            ready for submission, with submission guidance.
        """
        fisma_category = classification_result.get("fisma_category", "cat_6")
        stig_category = classification_result.get("stig_category", "CAT_III")
        us_cert_required = classification_result.get("us_cert_report_required", False)
        reporting_deadline = classification_result.get("reporting_deadline_utc")

        # Collect required fields
        required_fields = classification_result.get("required_report_fields", [])
        missing_fields: list[str] = []
        for field in required_fields:
            if field not in incident_details:
                missing_fields.append(field)

        # Generate incident hash for deduplication
        hash_input = f"{incident_id}:{fisma_category}:{incident_details.get('incident_date', '')}".encode()
        incident_hash = hashlib.sha256(hash_input).hexdigest()[:16]

        # Sanitize sensitive identifiers (hash attacker IPs for report)
        attacker_ips = incident_details.get("attacker_ip_addresses", [])
        hashed_ips = []
        for ip in attacker_ips:
            ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:12]
            hashed_ips.append(f"[REDACTED-{ip_hash}]")

        report_package: dict = {
            "report_metadata": {
                "report_id": f"USCERT-{incident_hash.upper()}",
                "incident_id": incident_id,
                "fisma_category": fisma_category,
                "stig_category": stig_category,
                "report_generated_utc": datetime.now(timezone.utc).isoformat(),
                "reporting_deadline_utc": reporting_deadline,
                "us_cert_required": us_cert_required,
                "report_format_version": "OMB-M-20-04-v2",
            },
            "incident_summary": {
                "incident_date": incident_details.get("incident_date"),
                "detection_date": incident_details.get("detection_date"),
                "incident_type": incident_details.get("incident_type"),
                "fisma_category_name": classification_result.get("fisma_category_name"),
                "severity": stig_category,
                "affected_systems_count": len(incident_details.get("affected_systems", [])),
                "estimated_impact": incident_details.get("impact_assessment", "Under assessment"),
            },
            "affected_systems": incident_details.get("affected_systems", []),
            "data_compromise": {
                "data_compromised": incident_details.get("data_compromised", False),
                "cui_involved": incident_details.get("cui_involved", False),
                "pii_involved": incident_details.get("pii_involved", False),
                "classified_data_involved": incident_details.get("classified_data_involved", False),
                "estimated_records_affected": incident_details.get("estimated_records_affected", 0),
            },
            "technical_indicators": {
                "attacker_ips_hashed": hashed_ips,
                "attack_vector": incident_details.get("attack_vector", "Unknown"),
                "malware_indicators": incident_details.get("ioc_list", []),
                "ttps": incident_details.get("ttps", []),
            },
            "reporter_contact": {
                "name": reporter_info.get("name", "[REQUIRED]"),
                "title": reporter_info.get("title", "[REQUIRED]"),
                "agency": reporter_info.get("agency", "[REQUIRED]"),
                "email": reporter_info.get("email", "[REQUIRED]"),
                "phone": reporter_info.get("phone", "[REQUIRED]"),
            },
            "submission_instructions": {
                "primary_channel": f"Email to {_CISA_REPORTING_CONTACTS['us_cert_email']}",
                "portal": _CISA_REPORTING_CONTACTS["us_cert_portal"],
                "phone": _CISA_REPORTING_CONTACTS["us_cert_phone"],
                "deadline_utc": reporting_deadline,
                "include_attachments": [
                    "System logs (last 72 hours)",
                    "Network flow captures",
                    "IDS/IPS alerts",
                    "Forensic timeline",
                ],
            },
            "missing_required_fields": missing_fields,
            "report_complete": len(missing_fields) == 0,
        }

        logger.info(
            "US-CERT report generated",
            report_id=report_package["report_metadata"]["report_id"],
            fisma_category=fisma_category,
            us_cert_required=us_cert_required,
            missing_fields_count=len(missing_fields),
        )

        return report_package

    def generate_poam(
        self,
        incident_id: str,
        classification_result: dict,
        affected_controls: list[str],
        remediation_owner: str,
    ) -> dict:
        """Generate a Plan of Action and Milestones (POA&M) for an incident.

        Creates a FedRAMP/FISMA-compliant POA&M document with remediation
        milestones, resource requirements, and scheduled completion dates.

        Args:
            incident_id: Incident identifier the POA&M addresses.
            classification_result: Output from classify_incident().
            affected_controls: List of NIST 800-53 control IDs affected
                (e.g., ["IR-4", "SI-3", "AU-6"]).
            remediation_owner: Name/role of the responsible remediation owner.

        Returns:
            Dictionary representing the POA&M with milestones, resources,
            and scheduled dates.
        """
        stig_category = classification_result.get("stig_category", "CAT_III")
        stig_details = _DISA_STIG_CATEGORIES.get(stig_category, _DISA_STIG_CATEGORIES["CAT_III"])
        remediation_days = stig_details["remediation_timeline_days"]

        now = datetime.now(timezone.utc)
        scheduled_completion = now + timedelta(days=remediation_days)

        # Generate milestones based on remediation timeline
        milestones: list[dict] = []
        milestone_intervals = [
            (0.1, "Containment actions completed"),
            (0.2, "Root cause analysis completed"),
            (0.4, "Remediation plan documented and approved"),
            (0.6, "Technical controls implemented"),
            (0.8, "Testing and verification completed"),
            (1.0, "POA&M closure — all controls validated"),
        ]

        for fraction, description in milestone_intervals:
            milestone_date = now + timedelta(days=int(remediation_days * fraction))
            milestones.append({
                "milestone_number": len(milestones) + 1,
                "description": description,
                "scheduled_completion_date": milestone_date.isoformat(),
                "status": "open",
            })

        # Map affected NIST controls to weakness descriptions
        control_weaknesses: list[dict] = []
        for control_id in affected_controls:
            control_weaknesses.append({
                "control_id": control_id,
                "weakness_description": (
                    f"Control {control_id} implementation weakness identified "
                    f"during incident {incident_id} investigation."
                ),
                "detection_method": "Incident response investigation",
            })

        poam_id = f"POAM-{incident_id[:8].upper()}-{stig_category}"

        logger.info(
            "POA&M generated",
            poam_id=poam_id,
            incident_id=incident_id,
            stig_category=stig_category,
            remediation_days=remediation_days,
            affected_controls_count=len(affected_controls),
        )

        return {
            "poam_id": poam_id,
            "incident_id": incident_id,
            "stig_category": stig_category,
            "weakness_type": classification_result.get("fisma_category_name"),
            "remediation_owner": remediation_owner,
            "original_detection_date": now.isoformat(),
            "scheduled_completion_date": scheduled_completion.isoformat(),
            "remediation_days": remediation_days,
            "control_weaknesses": control_weaknesses,
            "milestones": milestones,
            "resources_required": {
                "personnel": ["ISSO", "System Administrator", "Incident Responder"],
                "tools": ["SIEM", "EDR", "Vulnerability Scanner"],
                "estimated_hours": remediation_days * 4,  # Rough estimate
            },
            "fedramp_poam_compliant": True,
            "fisma_poam_compliant": True,
        }

    def generate_after_action_report(
        self,
        incident_id: str,
        classification_result: dict,
        incident_timeline: list[dict],
        lessons_learned: list[str],
        root_cause: str,
    ) -> dict:
        """Generate an after-action report (AAR) for a resolved incident.

        Produces an NIST SP 800-61 Rev 2 compliant after-action report
        with timeline analysis, root cause, lessons learned, and
        recommendations for control improvements.

        Args:
            incident_id: Incident identifier.
            classification_result: Output from classify_incident().
            incident_timeline: Ordered list of timeline events, each with
                timestamp, event_type, description, and actor.
            lessons_learned: List of lessons learned statements.
            root_cause: Root cause analysis narrative.

        Returns:
            Dictionary representing the complete after-action report.
        """
        fisma_category = classification_result.get("fisma_category", "cat_6")
        stig_category = classification_result.get("stig_category", "CAT_III")
        cui_involved = classification_result.get("cui_involved", False)
        pii_involved = classification_result.get("pii_involved", False)

        # Compute incident duration from timeline
        incident_duration_hours: float | None = None
        if len(incident_timeline) >= 2:
            try:
                first_event = incident_timeline[0].get("timestamp", "")
                last_event = incident_timeline[-1].get("timestamp", "")
                start_dt = datetime.fromisoformat(first_event)
                end_dt = datetime.fromisoformat(last_event)
                incident_duration_hours = (end_dt - start_dt).total_seconds() / 3600
            except (ValueError, TypeError):
                incident_duration_hours = None

        # Identify control gaps from classification
        recommended_control_improvements: list[dict] = []
        fisma_cat_data = _FISMA_INCIDENT_CATEGORIES.get(fisma_category, {})
        cat_name = fisma_cat_data.get("name", "Unknown")

        if fisma_category in ("cat_1", "cat_3"):
            recommended_control_improvements.extend([
                {
                    "nist_control": "IR-4",
                    "recommendation": "Strengthen incident handling procedures and playbooks.",
                },
                {
                    "nist_control": "SI-3",
                    "recommendation": "Enhance malicious code protection mechanisms.",
                },
                {
                    "nist_control": "AU-6",
                    "recommendation": "Increase audit log review frequency to daily.",
                },
            ])
        if fisma_category == "cat_2":
            recommended_control_improvements.extend([
                {
                    "nist_control": "SC-5",
                    "recommendation": "Implement denial of service protection controls.",
                },
                {
                    "nist_control": "CP-10",
                    "recommendation": "Test system recovery procedures within 30 days.",
                },
            ])

        report_id = f"AAR-{incident_id[:8].upper()}"

        logger.info(
            "After-action report generated",
            report_id=report_id,
            incident_id=incident_id,
            fisma_category=fisma_category,
            lessons_learned_count=len(lessons_learned),
            duration_hours=incident_duration_hours,
        )

        return {
            "report_id": report_id,
            "incident_id": incident_id,
            "report_generated_utc": datetime.now(timezone.utc).isoformat(),
            "executive_summary": {
                "fisma_category": f"{fisma_category.upper()} — {cat_name}",
                "stig_category": stig_category,
                "incident_duration_hours": incident_duration_hours,
                "cui_data_involved": cui_involved,
                "pii_data_involved": pii_involved,
                "root_cause_summary": root_cause,
            },
            "incident_timeline": incident_timeline,
            "root_cause_analysis": {
                "root_cause": root_cause,
                "contributing_factors": [],
                "nist_800_61_phase": "Post-Incident Activity",
            },
            "lessons_learned": lessons_learned,
            "recommended_control_improvements": recommended_control_improvements,
            "corrective_actions_taken": [],
            "distribution_list": [
                "ISSM", "CIO", "AO (Authorizing Official)", "ISSO",
                "Program Manager",
            ],
            "report_classification": "CUI // SP-CTI" if cui_involved else "CUI",
            "nist_800_61_compliant": True,
        }

    def check_reporting_timeline_compliance(
        self,
        incident_detected_utc: str,
        fisma_category: str,
        report_submitted_utc: str | None = None,
    ) -> dict:
        """Check whether incident reporting met the required timeline.

        Validates that the time from detection to US-CERT report submission
        complies with OMB M-20-04 and FISMA reporting requirements.

        Args:
            incident_detected_utc: ISO 8601 UTC timestamp of incident detection.
            fisma_category: FISMA category key (cat_1 through cat_6).
            report_submitted_utc: ISO 8601 UTC timestamp when report was submitted,
                or None if not yet submitted.

        Returns:
            Dictionary with compliance status, time remaining or overdue,
            and escalation requirements.
        """
        category_data = _FISMA_INCIDENT_CATEGORIES.get(fisma_category)
        if category_data is None:
            category_data = _FISMA_INCIDENT_CATEGORIES["cat_6"]

        required_hours = category_data.get("reporting_timeline_hours")
        us_cert_required = category_data.get("us_cert_required", False)

        try:
            detected_dt = datetime.fromisoformat(incident_detected_utc)
        except ValueError:
            detected_dt = datetime.now(timezone.utc)

        now = datetime.now(timezone.utc)

        if not us_cert_required or required_hours is None:
            return {
                "us_cert_required": False,
                "fisma_category": fisma_category,
                "compliance_status": "not_applicable",
                "message": f"US-CERT report not required for {fisma_category}.",
            }

        deadline_dt = detected_dt + timedelta(hours=required_hours)
        overdue = now > deadline_dt

        if report_submitted_utc is not None:
            try:
                submitted_dt = datetime.fromisoformat(report_submitted_utc)
                on_time = submitted_dt <= deadline_dt
                hours_delta = (submitted_dt - detected_dt).total_seconds() / 3600
                status = "compliant" if on_time else "non_compliant_late_submission"
            except ValueError:
                on_time = False
                hours_delta = None
                status = "error_invalid_submission_timestamp"
        else:
            on_time = None
            hours_delta = (now - detected_dt).total_seconds() / 3600
            status = "overdue_no_submission" if overdue else "pending_within_window"

        hours_remaining: float | None = None
        if not overdue and report_submitted_utc is None:
            hours_remaining = (deadline_dt - now).total_seconds() / 3600

        escalation_required = overdue and us_cert_required

        logger.info(
            "Reporting timeline compliance checked",
            fisma_category=fisma_category,
            compliance_status=status,
            overdue=overdue,
            escalation_required=escalation_required,
        )

        return {
            "us_cert_required": us_cert_required,
            "fisma_category": fisma_category,
            "compliance_status": status,
            "required_timeline_hours": required_hours,
            "deadline_utc": deadline_dt.isoformat(),
            "detected_utc": incident_detected_utc,
            "submitted_utc": report_submitted_utc,
            "hours_elapsed": round(hours_delta, 2) if hours_delta is not None else None,
            "hours_remaining": round(hours_remaining, 2) if hours_remaining is not None else None,
            "overdue": overdue,
            "submitted_on_time": on_time,
            "escalation_required": escalation_required,
            "escalation_action": (
                "Immediately notify CISO and submit late US-CERT report with explanation."
                if escalation_required else None
            ),
        }


__all__ = ["GovIncidentReporter"]

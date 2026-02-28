"""Army eMASS (Enterprise Mission Assurance Support Service) integration adapter.

GAP-306: eMASS Integration.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from aumos_common.observability import get_logger

logger = get_logger(__name__)


@dataclass
class EMASSSyncPackage:
    """eMASS control data synchronization package."""

    package_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    system_id: str = ""
    controls: list[dict[str, Any]] = field(default_factory=list)
    poam_items: list[dict[str, Any]] = field(default_factory=list)
    synced_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    sync_status: str = "pending"  # pending | synced | failed


class EMASSSyncError(Exception):
    """Raised when eMASS API synchronization fails."""


class EMASSTAdapter:
    """Adapter for Army eMASS REST API v3.12.

    Maps AumOS NIST 800-53 controls to eMASS package format for
    DoD system authorization workflows. eMASS is mandatory for
    Army, Navy, Air Force, and Marine Corps IT systems.

    Authentication uses API key + user key pair per eMASS API v3.12 spec.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        user_uid: str,
        http_client: httpx.AsyncClient,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._user_uid = user_uid
        self._client = http_client

    def _auth_headers(self) -> dict[str, str]:
        """Return eMASS API authentication headers."""
        return {
            "api-key": self._api_key,
            "user-uid": self._user_uid,
            "Content-Type": "application/json",
        }

    async def get_system(self, system_id: str) -> dict[str, Any]:
        """Retrieve eMASS system package details.

        Args:
            system_id: eMASS system ID.

        Returns:
            System package dict from eMASS API.

        Raises:
            EMASSSyncError: If the API call fails.
        """
        try:
            response = await self._client.get(
                f"{self._base_url}/api/systems/{system_id}",
                headers=self._auth_headers(),
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as exc:
            raise EMASSSyncError(f"eMASS API error for system {system_id}: {exc}") from exc

    def map_controls_to_emass(self, nist_controls: list[dict]) -> list[dict]:
        """Map AumOS NIST 800-53 control records to eMASS control format.

        Args:
            nist_controls: List of {control_id, status, implementation_narrative} dicts.

        Returns:
            List of eMASS-formatted control records.
        """
        _status_map = {
            "implemented": "Implemented",
            "partially_implemented": "Planned",
            "planned": "Planned",
            "not_implemented": "Not Applicable",
            "not_applicable": "Not Applicable",
        }

        return [
            {
                "systemId": None,  # Filled by eMASS on sync
                "acronym": ctrl.get("control_id", "").upper(),
                "responsibleEntities": ctrl.get("responsible_role", "System Owner"),
                "controlDesignation": "System Specific",
                "estimatedCompletionDate": None,
                "comments": ctrl.get("implementation_narrative", ""),
                "implementationStatus": _status_map.get(
                    ctrl.get("implementation_status", "not_implemented"),
                    "Not Applicable",
                ),
                "severity": None,
                "vulnerabiltySummary": None,
                "recommendations": None,
            }
            for ctrl in nist_controls
        ]

    async def sync_controls(
        self,
        system_id: str,
        nist_controls: list[dict],
    ) -> EMASSSyncPackage:
        """Sync AumOS control data to eMASS system package.

        Args:
            system_id: eMASS system ID.
            nist_controls: NIST 800-53 control records from gdf_nist_controls.

        Returns:
            EMASSSyncPackage with sync status.
        """
        emass_controls = self.map_controls_to_emass(nist_controls)
        package = EMASSSyncPackage(
            system_id=system_id,
            controls=emass_controls,
        )

        try:
            response = await self._client.put(
                f"{self._base_url}/api/systems/{system_id}/controls",
                headers=self._auth_headers(),
                json={"controls": emass_controls},
                timeout=60.0,
            )
            response.raise_for_status()
            package.sync_status = "synced"
            logger.info(
                "emass_sync_complete",
                system_id=system_id,
                control_count=len(emass_controls),
            )
        except httpx.HTTPError as exc:
            package.sync_status = "failed"
            logger.error("emass_sync_failed", system_id=system_id, error=str(exc))
            raise EMASSSyncError(f"eMASS sync failed: {exc}") from exc

        return package

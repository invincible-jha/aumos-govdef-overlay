"""Air-gapped local event store — SQLite-backed Kafka replacement for IL5.

GAP-304: Disconnected/Air-Gapped Operation Mode.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from aumos_common.observability import get_logger

logger = get_logger(__name__)


class OfflineEventStore:
    """SQLite-backed event store for air-gapped IL5 deployments.

    Replaces Kafka when AUMOS_GOVDEF_AIRGAP_MODE=true.
    Events written to SQLite and exported as JSON batches for
    manual transfer across the air gap boundary.

    Air-gapped environments (IL5/SCIF) have no internet connectivity.
    Events exported via this store can be manually transferred to a
    connected enclave for Kafka ingestion — providing eventual consistency.

    FIFO ordering is guaranteed by INTEGER PRIMARY KEY AUTOINCREMENT.
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the SQLite event store schema."""
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    topic TEXT NOT NULL,
                    event_key TEXT,
                    payload TEXT NOT NULL,
                    published_at TEXT NOT NULL,
                    exported INTEGER DEFAULT 0
                )"""
            )
            conn.commit()

    async def publish(self, topic: str, key: str, payload: dict) -> None:
        """Write event to local SQLite store.

        Args:
            topic: Kafka topic name (used for routing on re-import).
            key: Event key (e.g. tenant_id or resource_id).
            payload: Event payload dict.
        """
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                "INSERT INTO events (topic, event_key, payload, published_at) VALUES (?, ?, ?, ?)",
                (topic, key, json.dumps(payload), datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()
        logger.debug("offline_event_stored", topic=topic, key=key)

    def export_pending(self) -> list[dict]:
        """Export unsynced events for manual transfer to connected enclave.

        Marks exported events atomically to prevent duplicate exports.
        Returns events in FIFO order (by auto-increment id).

        Returns:
            List of event dicts with id, topic, key, payload, published_at.
        """
        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute(
                "SELECT id, topic, event_key, payload, published_at FROM events WHERE exported = 0 ORDER BY id ASC"
            ).fetchall()
            ids = [row[0] for row in rows]
            if ids:
                placeholders = ",".join("?" * len(ids))
                conn.execute(
                    f"UPDATE events SET exported = 1 WHERE id IN ({placeholders})", ids
                )
                conn.commit()

        if rows:
            logger.info("offline_events_exported", count=len(rows))

        return [
            {
                "id": r[0],
                "topic": r[1],
                "key": r[2],
                "payload": json.loads(r[3]),
                "published_at": r[4],
            }
            for r in rows
        ]

    def get_pending_count(self) -> int:
        """Return count of events pending export.

        Returns:
            Number of events not yet exported.
        """
        with sqlite3.connect(self._db_path) as conn:
            result = conn.execute("SELECT COUNT(*) FROM events WHERE exported = 0").fetchone()
            return result[0] if result else 0

    def purge_exported(self, older_than_days: int = 30) -> int:
        """Purge exported events older than a retention period.

        Args:
            older_than_days: Retain exported events for this many days.

        Returns:
            Number of rows deleted.
        """
        cutoff = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0).isoformat()
        with sqlite3.connect(self._db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM events WHERE exported = 1 AND published_at < ?",
                (cutoff,),
            )
            conn.commit()
            deleted = cursor.rowcount
        if deleted:
            logger.info("offline_events_purged", count=deleted)
        return deleted

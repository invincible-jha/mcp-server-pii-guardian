# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
PIIAuditLog — thread-safe, in-memory ring buffer for PII detection events.

Design notes
------------
* Uses collections.deque with a fixed maxlen so memory is bounded.
* A threading.Lock guards all writes and reads so the log can be used
  safely from concurrent MCP request handlers.
* No PII text is stored — only entity types, counts, and metadata.
* The ``export_jsonl`` helper produces newline-delimited JSON for shipping
  to an external SIEM or object store.
"""

from __future__ import annotations

import json
import logging
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Iterator

from pii_guardian.types import PIIAction, PIIAuditEntry, PIIDetection

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public class --------------------------------------------------------------
# ---------------------------------------------------------------------------


class PIIAuditLog:
    """In-memory audit log for PII detection events.

    Parameters
    ----------
    max_entries:
        Maximum number of entries retained.  Once the buffer is full the
        oldest entry is silently evicted (ring-buffer semantics via
        ``collections.deque(maxlen=...)``)

    Example
    -------
    >>> log = PIIAuditLog(max_entries=500)
    >>> log.log("search_tool", "input", detections, "redact")
    >>> entries = log.query(tool_name="search_tool")
    """

    def __init__(self, max_entries: int = 10_000) -> None:
        if max_entries < 1:
            raise ValueError(
                f"max_entries must be >= 1, got {max_entries!r}"
            )
        self._max_entries = max_entries
        self._buffer: deque[PIIAuditEntry] = deque(maxlen=max_entries)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Write -------------------------------------------------------------
    # ------------------------------------------------------------------

    def log(
        self,
        tool_name: str,
        direction: str,
        detections: list[PIIDetection],
        action: str | PIIAction,
    ) -> None:
        """Append a detection event to the audit log.

        Parameters
        ----------
        tool_name:
            The MCP tool name that triggered the guard call.
        direction:
            ``"input"`` or ``"output"``.
        detections:
            All PIIDetection instances from the guard call.
        action:
            The PIIAction (or its string value) that was applied.
        """
        if isinstance(action, PIIAction):
            action_str = action.value
        else:
            action_str = str(action)

        entity_types = list(dict.fromkeys(d.entity_type for d in detections))
        timestamp = datetime.now(tz=timezone.utc).isoformat()

        entry = PIIAuditEntry(
            tool_name=tool_name,
            direction=direction,
            action=action_str,
            entity_types=entity_types,
            detection_count=len(detections),
            timestamp=timestamp,
        )

        with self._lock:
            self._buffer.append(entry)

        logger.debug(
            "audit: tool=%s direction=%s action=%s entities=%s count=%d",
            tool_name,
            direction,
            action_str,
            entity_types,
            len(detections),
        )

    # ------------------------------------------------------------------
    # Read --------------------------------------------------------------
    # ------------------------------------------------------------------

    def query(
        self,
        tool_name: str | None = None,
        entity_type: str | None = None,
        direction: str | None = None,
        action: str | PIIAction | None = None,
    ) -> list[PIIAuditEntry]:
        """Return matching entries from the audit log.

        All supplied parameters are combined with AND logic.  Omitting a
        parameter means "no filter on that dimension".

        Parameters
        ----------
        tool_name:
            Filter by exact MCP tool name.
        entity_type:
            Filter by presence of this entity type label.
        direction:
            Filter by ``"input"`` or ``"output"``.
        action:
            Filter by action string or PIIAction enum value.

        Returns
        -------
        list[PIIAuditEntry]:
            Matching entries in chronological order (oldest first).
        """
        if isinstance(action, PIIAction):
            action_filter: str | None = action.value
        elif action is not None:
            action_filter = str(action)
        else:
            action_filter = None

        with self._lock:
            snapshot = list(self._buffer)

        results: list[PIIAuditEntry] = []
        for entry in snapshot:
            if tool_name is not None and entry.tool_name != tool_name:
                continue
            if entity_type is not None and entity_type not in entry.entity_types:
                continue
            if direction is not None and entry.direction != direction:
                continue
            if action_filter is not None and entry.action != action_filter:
                continue
            results.append(entry)

        return results

    def all_entries(self) -> list[PIIAuditEntry]:
        """Return a snapshot of all entries in chronological order."""
        with self._lock:
            return list(self._buffer)

    def clear(self) -> None:
        """Remove all entries from the audit log."""
        with self._lock:
            self._buffer.clear()

    # ------------------------------------------------------------------
    # Export ------------------------------------------------------------
    # ------------------------------------------------------------------

    def export_jsonl(
        self,
        tool_name: str | None = None,
        entity_type: str | None = None,
    ) -> str:
        """Serialise matching entries as newline-delimited JSON.

        Each line is a JSON object with the same fields as PIIAuditEntry.
        This format is directly ingestible by most log aggregation platforms
        (Splunk, Datadog, CloudWatch Logs, etc.).
        """
        entries = self.query(tool_name=tool_name, entity_type=entity_type)
        lines = [
            json.dumps(
                {
                    "tool_name": e.tool_name,
                    "direction": e.direction,
                    "action": e.action,
                    "entity_types": e.entity_types,
                    "detection_count": e.detection_count,
                    "timestamp": e.timestamp,
                }
            )
            for e in entries
        ]
        return "\n".join(lines)

    def iter_entries(self) -> Iterator[PIIAuditEntry]:
        """Yield entries one by one without materialising a full list."""
        with self._lock:
            snapshot = list(self._buffer)
        yield from snapshot

    # ------------------------------------------------------------------
    # Stats -------------------------------------------------------------
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, int | dict[str, int]]:
        """Return summary statistics over all buffered entries.

        Returns a dict with keys:
        - ``total_events``: total number of audit entries.
        - ``by_action``: counts keyed by action string.
        - ``by_entity_type``: counts keyed by entity type label.
        - ``by_direction``: counts keyed by ``"input"``/``"output"``.
        """
        with self._lock:
            snapshot = list(self._buffer)

        by_action: dict[str, int] = {}
        by_entity_type: dict[str, int] = {}
        by_direction: dict[str, int] = {}

        for entry in snapshot:
            by_action[entry.action] = by_action.get(entry.action, 0) + 1
            by_direction[entry.direction] = by_direction.get(entry.direction, 0) + 1
            for entity_type in entry.entity_types:
                by_entity_type[entity_type] = by_entity_type.get(entity_type, 0) + 1

        return {
            "total_events": len(snapshot),
            "by_action": by_action,
            "by_entity_type": by_entity_type,
            "by_direction": by_direction,
        }

    def __len__(self) -> int:
        with self._lock:
            return len(self._buffer)

    def __repr__(self) -> str:
        return (
            f"PIIAuditLog(max_entries={self._max_entries}, "
            f"current_size={len(self)})"
        )

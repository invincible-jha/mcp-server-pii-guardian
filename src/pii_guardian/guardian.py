# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
PIIGuardian — main middleware class for MCP server integration.

Usage pattern
-------------
1. Construct a PIIGuardian (once, at application startup).
2. Call ``guard_input`` before forwarding tool arguments to the underlying
   tool implementation.
3. Call ``guard_output`` before returning tool results to the caller.
4. Inspect ``GuardResult.blocked`` and raise or return an error response
   as appropriate for your MCP server framework.

The guardian is intentionally framework-agnostic — it receives and returns
plain Python dicts so it can be dropped into any MCP server regardless of
the transport layer.

Thread safety
-------------
PIIGuardian is safe to share across concurrent request handlers.
PIIDetector and PIIRedactor are stateless after initialisation.
PIIAuditLog uses an internal lock for all writes.
"""

from __future__ import annotations

import logging
from typing import Any

from pii_guardian.audit import PIIAuditLog
from pii_guardian.config import GuardianConfig
from pii_guardian.detector import PIIDetector
from pii_guardian.redactor import PIIRedactor
from pii_guardian.types import GuardResult, PIIAction, PIIDetection

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Custom exceptions ---------------------------------------------------------
# ---------------------------------------------------------------------------


class PIIBlockedError(Exception):
    """Raised when a guard call resolves to PIIAction.BLOCK.

    Attributes
    ----------
    tool_name:  The MCP tool that was blocked.
    direction:  ``"input"`` or ``"output"``.
    detections: All PIIDetection instances that triggered the block.
    """

    def __init__(
        self,
        tool_name: str,
        direction: str,
        detections: list[PIIDetection],
    ) -> None:
        entity_types = list(dict.fromkeys(d.entity_type for d in detections))
        super().__init__(
            f"PII blocked on {direction} for tool {tool_name!r}. "
            f"Detected entity types: {entity_types}"
        )
        self.tool_name = tool_name
        self.direction = direction
        self.detections = detections


# ---------------------------------------------------------------------------
# Main class ----------------------------------------------------------------
# ---------------------------------------------------------------------------


class PIIGuardian:
    """PII detection and redaction middleware for MCP servers.

    Parameters
    ----------
    config:
        GuardianConfig instance.  Defaults to ``GuardianConfig.default()``
        if omitted.
    raise_on_block:
        When True, ``guard`` raises ``PIIBlockedError`` instead of returning
        a GuardResult with ``blocked=True``.  Defaults to False so callers
        always receive a result and can handle the error in their own way.

    Example
    -------
    >>> guardian = PIIGuardian()
    >>> result = guardian.guard_input("send_email", {"to": "bob@example.com"})
    >>> result.clean
    False
    >>> result.redacted
    True
    """

    def __init__(
        self,
        config: GuardianConfig | None = None,
        raise_on_block: bool = False,
    ) -> None:
        self._config = config or GuardianConfig.default()
        self._raise_on_block = raise_on_block
        self._detector = PIIDetector(
            entities=self._config.entities,
            threshold=self._config.threshold,
        )
        self._redactor = PIIRedactor(
            strategy=self._config.redaction_strategy,
        )
        self._audit = PIIAuditLog(
            max_entries=self._config.max_audit_entries,
        )
        logger.info(
            "PIIGuardian ready — entities=%d threshold=%.2f strategy=%s",
            len(self._config.entities),
            self._config.threshold,
            self._config.redaction_strategy.value,
        )

    # ------------------------------------------------------------------
    # Public interface --------------------------------------------------
    # ------------------------------------------------------------------

    @property
    def config(self) -> GuardianConfig:
        """The active GuardianConfig (read-only)."""
        return self._config

    @property
    def audit_log(self) -> PIIAuditLog:
        """The internal PIIAuditLog instance."""
        return self._audit

    def guard_input(
        self,
        tool_name: str,
        input_data: dict[str, Any],
    ) -> GuardResult:
        """Guard incoming tool arguments before execution.

        Parameters
        ----------
        tool_name:
            The MCP tool identifier being invoked.
        input_data:
            The raw arguments dict from the MCP caller.

        Returns
        -------
        GuardResult:
            Use ``result.data`` as the (possibly redacted) arguments.
            Check ``result.blocked`` before proceeding.
        """
        return self.guard(tool_name, input_data, direction="input")

    def guard_output(
        self,
        tool_name: str,
        output_data: dict[str, Any],
    ) -> GuardResult:
        """Guard outgoing tool results before they reach the caller.

        Parameters
        ----------
        tool_name:
            The MCP tool identifier whose result is being guarded.
        output_data:
            The raw result dict produced by the tool.

        Returns
        -------
        GuardResult:
            Use ``result.data`` as the (possibly redacted) result.
        """
        return self.guard(tool_name, output_data, direction="output")

    def guard(
        self,
        tool_name: str,
        data: dict[str, Any],
        direction: str = "input",
    ) -> GuardResult:
        """Core guard implementation used by guard_input and guard_output.

        Detects PII in all string values of ``data``, resolves the
        appropriate PIIAction, applies it, logs the event, and returns a
        GuardResult.

        Parameters
        ----------
        tool_name:
            The MCP tool identifier.
        data:
            The dict payload to inspect.
        direction:
            ``"input"`` or ``"output"``.  Used for audit logging and
            human-readable error messages only.

        Returns
        -------
        GuardResult

        Raises
        ------
        PIIBlockedError:
            Only when ``raise_on_block=True`` and the resolved action is BLOCK.
        """
        # 1. Detect PII in all string leaf values.
        path_detections = self._detector.detect_in_values(data)
        all_detections: list[PIIDetection] = [
            detection
            for _, detections in path_detections
            for detection in detections
        ]

        # 2. Clean pass — no PII found.
        if not all_detections:
            if self._config.audit_enabled:
                self._audit.log(tool_name, direction, [], PIIAction.ALLOW.value)
            return GuardResult(clean=True, data=data)

        # 3. Resolve the action.
        action = self._resolve_action(tool_name, all_detections)

        # 4. Log before acting so the event is captured even on BLOCK.
        if self._config.audit_enabled:
            self._audit.log(tool_name, direction, all_detections, action)

        logger.info(
            "PII detected: tool=%s direction=%s action=%s entities=%s",
            tool_name,
            direction,
            action.value,
            [d.entity_type for d in all_detections],
        )

        # 5. Apply the action.
        match action:
            case PIIAction.BLOCK:
                return self._handle_block(tool_name, direction, data, all_detections)
            case PIIAction.REDACT:
                redacted_data = self._redactor.redact(data, path_detections)
                return GuardResult(
                    clean=False,
                    data=redacted_data,
                    redacted=True,
                    detections=all_detections,
                )
            case PIIAction.FLAG:
                return GuardResult(
                    clean=False,
                    data=data,
                    flagged=True,
                    detections=all_detections,
                )
            case PIIAction.ALLOW:
                return GuardResult(
                    clean=False,
                    data=data,
                    detections=all_detections,
                )
            case _:
                # Defensive: treat unknown actions as REDACT.
                redacted_data = self._redactor.redact(data, path_detections)
                return GuardResult(
                    clean=False,
                    data=redacted_data,
                    redacted=True,
                    detections=all_detections,
                )

    # ------------------------------------------------------------------
    # Action resolution -------------------------------------------------
    # ------------------------------------------------------------------

    def _resolve_action(
        self,
        tool_name: str,
        detections: list[PIIDetection],
    ) -> PIIAction:
        """Determine the PIIAction to apply for this tool + detection set.

        Priority order (highest to lowest):
        1. If any detected entity type is in ``blocked_entities`` → BLOCK.
        2. Per-tool action from ``tool_actions``.
        3. ``default_action``.
        """
        for detection in detections:
            if self._config.is_blocked_entity(detection.entity_type):
                logger.debug(
                    "Entity type %r is in blocked_entities — forcing BLOCK",
                    detection.entity_type,
                )
                return PIIAction.BLOCK

        return self._config.action_for_tool(tool_name)

    # ------------------------------------------------------------------
    # Block handling ----------------------------------------------------
    # ------------------------------------------------------------------

    def _handle_block(
        self,
        tool_name: str,
        direction: str,
        data: dict[str, Any],
        detections: list[PIIDetection],
    ) -> GuardResult:
        """Return a blocked GuardResult or raise PIIBlockedError."""
        result = GuardResult(
            clean=False,
            data=data,
            blocked=True,
            detections=detections,
        )
        if self._raise_on_block:
            raise PIIBlockedError(tool_name, direction, detections)
        return result

    # ------------------------------------------------------------------
    # Convenience -------------------------------------------------------
    # ------------------------------------------------------------------

    def audit_stats(self) -> dict[str, Any]:
        """Return summary statistics from the internal audit log."""
        return self._audit.stats()

    def export_audit_jsonl(self) -> str:
        """Export the entire audit log as newline-delimited JSON."""
        return self._audit.export_jsonl()

    def __repr__(self) -> str:
        return (
            f"PIIGuardian("
            f"entities={len(self._config.entities)}, "
            f"threshold={self._config.threshold:.2f}, "
            f"strategy={self._config.redaction_strategy.value!r}, "
            f"default_action={self._config.default_action.value!r}"
            f")"
        )

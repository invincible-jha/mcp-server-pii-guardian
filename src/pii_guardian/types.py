# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
Core types for mcp-server-pii-guardian.

All domain types are defined here as frozen dataclasses and enums
to keep them immutable, serialisable, and free of third-party runtime
dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RedactionStrategy(Enum):
    """Strategy used when rewriting PII found in a payload.

    MASK    — replace characters with asterisks, preserving first/last:
              ``john@example.com`` → ``j***@e******.com``
    HASH    — replace the detected span with its SHA-256 hex digest
              (useful for pseudonymisation that needs to be reversible
              with the key)
    REMOVE  — replace with the literal string ``[REDACTED]``
    REPLACE — replace with the entity-type label in brackets:
              ``john@example.com`` → ``[EMAIL_ADDRESS]``
    """

    MASK = "mask"
    HASH = "hash"
    REMOVE = "remove"
    REPLACE = "replace"


class PIIAction(Enum):
    """Action taken when PII is detected for a given tool or entity type.

    BLOCK   — reject the request/response entirely (raises PIIBlockedError)
    REDACT  — rewrite the payload using the configured RedactionStrategy
    FLAG    — leave the payload unchanged but mark GuardResult.flagged = True
    ALLOW   — pass through with no modification and no flag
    """

    BLOCK = "block"
    REDACT = "redact"
    FLAG = "flag"
    ALLOW = "allow"


@dataclass(frozen=True)
class PIIDetection:
    """A single PII span identified within a text string.

    Attributes:
        entity_type: Presidio entity label, e.g. ``EMAIL_ADDRESS``.
        text:        The exact substring that was flagged.
        start:       Zero-based start index within the source string.
        end:         Zero-based exclusive end index within the source string.
        score:       Presidio confidence score in the range ``[0.0, 1.0]``.
    """

    entity_type: str
    text: str
    start: int
    end: int
    score: float

    def __post_init__(self) -> None:
        if not (0.0 <= self.score <= 1.0):
            raise ValueError(
                f"PIIDetection.score must be between 0.0 and 1.0, got {self.score!r}"
            )
        if self.start < 0:
            raise ValueError(
                f"PIIDetection.start must be >= 0, got {self.start!r}"
            )
        if self.end < self.start:
            raise ValueError(
                f"PIIDetection.end ({self.end}) must be >= start ({self.start})"
            )


@dataclass(frozen=True)
class GuardResult:
    """The outcome of a single guard_input / guard_output call.

    Attributes:
        clean:      True when no PII was detected above the threshold.
        data:       The (potentially redacted) payload to use downstream.
        blocked:    True when the action resolved to BLOCK.
        redacted:   True when at least one redaction was applied.
        flagged:    True when the action resolved to FLAG.
        detections: All PIIDetection instances found in this call.
    """

    clean: bool
    data: dict[str, Any]
    blocked: bool = False
    redacted: bool = False
    flagged: bool = False
    detections: list[PIIDetection] = field(default_factory=list)

    @property
    def entity_types_found(self) -> list[str]:
        """Deduplicated list of entity types present in detections."""
        return list(dict.fromkeys(d.entity_type for d in self.detections))


@dataclass(frozen=True)
class PIIAuditEntry:
    """Immutable record written to the PIIAuditLog for each guard call.

    Attributes:
        tool_name:  MCP tool identifier that triggered the guard.
        direction:  ``"input"`` or ``"output"``.
        action:     The PIIAction that was applied (as its string value).
        entity_types: Deduplicated list of entity type labels detected.
        detection_count: Total number of detections in this call.
        timestamp:  ISO-8601 UTC timestamp string.
    """

    tool_name: str
    direction: str
    action: str
    entity_types: list[str]
    detection_count: int
    timestamp: str

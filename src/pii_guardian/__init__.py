# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
mcp-server-pii-guardian
=======================

PII detection and redaction middleware for MCP servers.

Wraps Microsoft Presidio to provide a clean, type-safe API for guarding
tool inputs and outputs against accidental PII exposure.

Quickstart
----------
>>> from pii_guardian import PIIGuardian
>>> guardian = PIIGuardian()
>>> result = guardian.guard_input("my_tool", {"message": "Email me at bob@example.com"})
>>> result.redacted
True
>>> result.data
{'message': 'Email me at b*b@e******.com'}

Public API
----------
The following names are part of the stable public surface and will not
change without a major version bump:

Classes
    PIIGuardian          Main middleware — construct once, call guard_* per request.
    PIIDetector          Presidio wrapper — detect PII in plain text.
    PIIRedactor          Apply a redaction strategy to text or dicts.
    PIIAuditLog          Thread-safe in-memory audit ring buffer.
    GuardianConfig       Configuration dataclass with factory helpers.
    PIIBlockedError      Raised when guard resolves to BLOCK + raise_on_block=True.

Enums
    RedactionStrategy    MASK | HASH | REMOVE | REPLACE
    PIIAction            BLOCK | REDACT | FLAG | ALLOW

Types
    PIIDetection         Frozen dataclass — a single detected PII span.
    GuardResult          Frozen dataclass — the outcome of a guard call.
    PIIAuditEntry        Frozen dataclass — a single audit log record.
"""

from pii_guardian.audit import PIIAuditLog
from pii_guardian.config import DEFAULT_ENTITIES, HIGH_RISK_ENTITIES, GuardianConfig
from pii_guardian.detector import PIIDetector
from pii_guardian.guardian import PIIBlockedError, PIIGuardian
from pii_guardian.redactor import PIIRedactor
from pii_guardian.types import (
    GuardResult,
    PIIAction,
    PIIAuditEntry,
    PIIDetection,
    RedactionStrategy,
)

__version__ = "0.1.0"
__all__ = [
    # Main classes
    "PIIGuardian",
    "PIIDetector",
    "PIIRedactor",
    "PIIAuditLog",
    "GuardianConfig",
    # Exceptions
    "PIIBlockedError",
    # Enums
    "RedactionStrategy",
    "PIIAction",
    # Types / dataclasses
    "PIIDetection",
    "GuardResult",
    "PIIAuditEntry",
    # Constants
    "DEFAULT_ENTITIES",
    "HIGH_RISK_ENTITIES",
]

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
GuardianConfig — runtime configuration for PIIGuardian.

All validation is performed in __post_init__ so the dataclass is
safe to construct from arbitrary user-supplied dictionaries without
a Pydantic dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pii_guardian.types import PIIAction, RedactionStrategy

# ---------------------------------------------------------------------------
# Default entity list -------------------------------------------------------
# ---------------------------------------------------------------------------

DEFAULT_ENTITIES: list[str] = [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "US_SSN",
    "CREDIT_CARD",
    "PERSON",
    "LOCATION",
    "IP_ADDRESS",
]

# Entity types that are considered high-risk and blocked by default when
# GuardianConfig.default() is used with strict_mode=True.
HIGH_RISK_ENTITIES: list[str] = [
    "US_SSN",
    "CREDIT_CARD",
]


# ---------------------------------------------------------------------------
# Config dataclass ----------------------------------------------------------
# ---------------------------------------------------------------------------


@dataclass
class GuardianConfig:
    """Configuration container for PIIGuardian middleware.

    Attributes:
        entities:           PII entity types to detect.  Must be valid
                            Presidio entity labels.
        threshold:          Minimum Presidio confidence score ``[0.0, 1.0]``
                            required for a detection to be acted upon.
        redaction_strategy: How detected PII is rewritten when the action
                            is REDACT.
        default_action:     Action applied to any tool not listed in
                            ``tool_actions``.
        tool_actions:       Per-tool overrides, keyed by MCP tool name.
        blocked_entities:   Entity types that always trigger a BLOCK
                            regardless of ``default_action`` or
                            ``tool_actions``.
        audit_enabled:      Whether guard calls are written to the audit log.
        max_audit_entries:  Capacity of the in-memory audit ring buffer.
    """

    entities: list[str] = field(default_factory=lambda: list(DEFAULT_ENTITIES))
    threshold: float = 0.7
    redaction_strategy: RedactionStrategy = RedactionStrategy.MASK
    default_action: PIIAction = PIIAction.REDACT
    tool_actions: dict[str, PIIAction] = field(default_factory=dict)
    blocked_entities: list[str] = field(default_factory=list)
    audit_enabled: bool = True
    max_audit_entries: int = 10_000

    def __post_init__(self) -> None:
        self._validate()

    # ------------------------------------------------------------------
    # Validation --------------------------------------------------------
    # ------------------------------------------------------------------

    def _validate(self) -> None:
        if not (0.0 <= self.threshold <= 1.0):
            raise ValueError(
                f"GuardianConfig.threshold must be between 0.0 and 1.0, "
                f"got {self.threshold!r}"
            )
        if not self.entities:
            raise ValueError("GuardianConfig.entities must not be empty.")
        if self.max_audit_entries < 1:
            raise ValueError(
                f"GuardianConfig.max_audit_entries must be >= 1, "
                f"got {self.max_audit_entries!r}"
            )
        for tool_name, action in self.tool_actions.items():
            if not isinstance(action, PIIAction):
                raise TypeError(
                    f"tool_actions[{tool_name!r}] must be a PIIAction instance, "
                    f"got {type(action).__name__}"
                )

    # ------------------------------------------------------------------
    # Factory helpers ---------------------------------------------------
    # ------------------------------------------------------------------

    @classmethod
    def default(cls) -> GuardianConfig:
        """Return a sensible production-ready default configuration.

        - Detects all DEFAULT_ENTITIES.
        - Threshold 0.7 (Presidio recommendation).
        - MASK strategy (non-destructive, reversible with log).
        - REDACT for most tools; SSN/credit-card always BLOCK.
        """
        return cls(
            entities=list(DEFAULT_ENTITIES),
            threshold=0.7,
            redaction_strategy=RedactionStrategy.MASK,
            default_action=PIIAction.REDACT,
            blocked_entities=list(HIGH_RISK_ENTITIES),
        )

    @classmethod
    def strict(cls) -> GuardianConfig:
        """Maximum-protection configuration.

        All detected PII triggers a BLOCK.  Suitable for air-gapped or
        highly-regulated environments where no PII must flow through the
        MCP layer at all.
        """
        return cls(
            entities=list(DEFAULT_ENTITIES),
            threshold=0.5,
            redaction_strategy=RedactionStrategy.REMOVE,
            default_action=PIIAction.BLOCK,
        )

    @classmethod
    def permissive(cls) -> GuardianConfig:
        """Observation-only configuration.

        Detects PII and writes to the audit log but never modifies or
        blocks payloads.  Useful for baselining before enforcing policy.
        """
        return cls(
            entities=list(DEFAULT_ENTITIES),
            threshold=0.7,
            redaction_strategy=RedactionStrategy.MASK,
            default_action=PIIAction.FLAG,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GuardianConfig:
        """Construct a GuardianConfig from a plain dictionary.

        Supports string values for enum fields, e.g.::

            {
                "threshold": 0.8,
                "redaction_strategy": "hash",
                "default_action": "redact",
                "tool_actions": {"summarise": "allow"},
                "blocked_entities": ["US_SSN"]
            }
        """
        raw = dict(data)

        if "redaction_strategy" in raw and isinstance(
            raw["redaction_strategy"], str
        ):
            raw["redaction_strategy"] = RedactionStrategy(raw["redaction_strategy"])

        if "default_action" in raw and isinstance(raw["default_action"], str):
            raw["default_action"] = PIIAction(raw["default_action"])

        if "tool_actions" in raw and isinstance(raw["tool_actions"], dict):
            raw["tool_actions"] = {
                tool: (PIIAction(action) if isinstance(action, str) else action)
                for tool, action in raw["tool_actions"].items()
            }

        return cls(**raw)

    # ------------------------------------------------------------------
    # Helpers -----------------------------------------------------------
    # ------------------------------------------------------------------

    def action_for_tool(self, tool_name: str) -> PIIAction:
        """Return the configured PIIAction for ``tool_name``."""
        return self.tool_actions.get(tool_name, self.default_action)

    def is_blocked_entity(self, entity_type: str) -> bool:
        """Return True when ``entity_type`` is in the blocked_entities list."""
        return entity_type in self.blocked_entities

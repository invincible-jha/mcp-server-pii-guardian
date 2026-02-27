# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
CanaryPIIIntegration — bridge between PII Guardian and agent-canary-tokens.

Places canary tokens in text near detected PII positions so that if
PII-adjacent data is exfiltrated the canary token will appear in the
destination.  Detection of a canary token in external text is then a
reliable signal that data near a PII finding has left the system.

This module performs two functions only:
- Injection: embed canary tokens into text near PII finding positions.
- Detection: check whether a known canary token appears in external text.

No automatic response to a breach is performed.  All breach events are
recorded and returned for the caller to act on.

Usage:
    from pii_guardian.canary_integration import CanaryPIIIntegration, CanaryConfig
    from pii_guardian.local_detector import LocalPIIDetector

    detector = LocalPIIDetector()
    findings = detector.detect("Call me at 555-123-4567")

    config = CanaryConfig(token_density=1, token_format="<<CNRY-{token_id}>>")
    integration = CanaryPIIIntegration()
    annotated_text, placements = integration.inject_canary_tokens(
        text="Call me at 555-123-4567",
        findings=findings,
        canary_config=config,
    )
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Protocol — accepts both PIIFinding and PIIDetection
# ---------------------------------------------------------------------------


@runtime_checkable
class PIIFindingLike(Protocol):
    """Structural protocol matching PIIFinding and PIIDetection."""

    entity_type: str
    start: int
    end: int


# ---------------------------------------------------------------------------
# Canary dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CanaryConfig:
    """Configuration for canary token injection.

    Attributes:
        token_density:  Number of canary tokens to place per PII finding.
                        Operator-set integer; not modified at runtime.
        token_format:   Format string for the canary token text.  Must contain
                        the literal ``{token_id}`` which is replaced with the
                        unique token ID.  Example: ``"<<CNRY-{token_id}>>"``
    """

    token_density: int
    token_format: str

    def __post_init__(self) -> None:
        if self.token_density < 1:
            raise ValueError(
                f"CanaryConfig.token_density must be >= 1, got {self.token_density!r}"
            )
        if "{token_id}" not in self.token_format:
            raise ValueError(
                "CanaryConfig.token_format must contain the literal '{token_id}' "
                "so each injected token is uniquely identifiable."
            )

    @classmethod
    def default(cls) -> CanaryConfig:
        """Return a sensible default canary config (1 token per finding)."""
        return cls(token_density=1, token_format="<<CNRY-{token_id}>>")


@dataclass(frozen=True)
class CanaryPlacement:
    """Record of a single canary token injected into text.

    Attributes:
        position:       Character position in the annotated text where the
                        canary token begins.
        token_id:       The unique ID embedded in the canary token string.
        token_text:     The full canary token string as it appears in the text.
        near_pii_type:  The entity_type of the PII finding this token was
                        placed adjacent to.
    """

    position: int
    token_id: str
    token_text: str
    near_pii_type: str


@dataclass(frozen=True)
class CanaryBreachRecord:
    """Record of a canary token found in external text.

    Attributes:
        token_id:       The unique ID of the detected canary token.
        found_at_index: Character position within *external_text* where the
                        token was first found.
        match_count:    Total number of times the token appeared in the text.
    """

    token_id: str
    found_at_index: int
    match_count: int


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------


class CanaryPIIIntegration:
    """Bridges PII detection with canary token injection and breach checking.

    The integration is stateless with respect to detection.  Injection
    produces a new annotated string and a list of CanaryPlacement records
    which the caller is responsible for storing if they want to correlate
    future breach checks.

    Example
    -------
    >>> integration = CanaryPIIIntegration()
    >>> config = CanaryConfig(token_density=1, token_format="<<CNRY-{token_id}>>")
    >>> text, placements = integration.inject_canary_tokens(
    ...     text="Email: alice@example.com",
    ...     findings=[],  # empty — no placements made
    ...     canary_config=config,
    ... )
    >>> text
    'Email: alice@example.com'
    """

    def inject_canary_tokens(
        self,
        text: str,
        findings: list[Any],
        canary_config: CanaryConfig,
    ) -> tuple[str, list[CanaryPlacement]]:
        """Embed canary tokens into *text* adjacent to each PII finding.

        For each finding in *findings*, up to ``canary_config.token_density``
        canary tokens are inserted immediately after the PII span.  The
        insertion is performed right-to-left so that earlier span indices
        remain valid as tokens are appended.

        Parameters
        ----------
        text:
            The original text that was scanned for PII.
        findings:
            A list of PIIFinding or PIIDetection objects.  Objects must have
            ``entity_type``, ``start``, and ``end`` attributes.
        canary_config:
            The injection configuration controlling density and format.

        Returns
        -------
        tuple[str, list[CanaryPlacement]]:
            - The annotated text with canary tokens injected.
            - A list of CanaryPlacement records (one per injected token),
              ordered by original insertion position ascending.
        """
        if not findings:
            return text, []

        # Sort findings by end position descending for right-to-left insertion
        sorted_findings = sorted(findings, key=lambda f: f.end, reverse=True)

        annotated = text
        placements: list[CanaryPlacement] = []

        for finding in sorted_findings:
            for _ in range(canary_config.token_density):
                token_id = str(uuid.uuid4())
                token_text = canary_config.token_format.format(token_id=token_id)
                insertion_index = finding.end

                annotated = annotated[:insertion_index] + token_text + annotated[insertion_index:]

                placements.append(
                    CanaryPlacement(
                        position=insertion_index,
                        token_id=token_id,
                        token_text=token_text,
                        near_pii_type=finding.entity_type,
                    )
                )

        # Return placements in document order (ascending position)
        placements.sort(key=lambda p: p.position)
        return annotated, placements

    def check_canary_breach(
        self,
        token_id: str,
        token_format: str,
        external_text: str,
    ) -> bool:
        """Check whether a canary token appears in *external_text*.

        This is a pure scan — it records nothing and triggers no automated
        action.  The caller receives the result and decides how to respond.

        Parameters
        ----------
        token_id:
            The unique token ID to search for.
        token_format:
            The format string used during injection (must contain
            ``{token_id}``).  Used to reconstruct the exact token string.
        external_text:
            The text to scan (e.g. LLM output, log entry, network capture).

        Returns
        -------
        bool:
            True when the canary token is found in *external_text*.
        """
        expected_token = token_format.format(token_id=token_id)
        return expected_token in external_text

    def find_breached_tokens(
        self,
        placements: list[CanaryPlacement],
        token_format: str,
        external_text: str,
    ) -> list[CanaryBreachRecord]:
        """Scan *external_text* for all canary tokens from *placements*.

        Returns a breach record for each token found.  Tokens not present in
        the external text are silently omitted from the result.

        Parameters
        ----------
        placements:
            The list of CanaryPlacement records from a previous
            ``inject_canary_tokens`` call.
        token_format:
            The format string used during injection.
        external_text:
            The text to scan for canary tokens.

        Returns
        -------
        list[CanaryBreachRecord]:
            One record per breached canary token, ordered by their first
            occurrence in *external_text*.
        """
        breach_records: list[CanaryBreachRecord] = []

        for placement in placements:
            expected_token = token_format.format(token_id=placement.token_id)
            first_index = external_text.find(expected_token)
            if first_index == -1:
                continue

            # Count total occurrences
            match_count = len(re.findall(re.escape(expected_token), external_text))
            breach_records.append(
                CanaryBreachRecord(
                    token_id=placement.token_id,
                    found_at_index=first_index,
                    match_count=match_count,
                )
            )

        breach_records.sort(key=lambda r: r.found_at_index)
        return breach_records

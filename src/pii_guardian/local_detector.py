# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
LocalPIIDetector — pure regex-based PII detection with no external dependencies.

Provides pattern matching for common PII types without requiring presidio-analyzer
or any NLP model.  This is useful for:
- Minimal deployments where presidio is not available
- Fast pre-screening before sending text to the full Presidio engine
- Air-gapped environments with no network access

Detection is purely regex-based with checksum validation where the data format
allows it (e.g., Luhn check for credit card numbers).  The detector is
stateless, so all methods are thread-safe.

Supported patterns
------------------
- EMAIL_ADDRESS       — standard RFC 5322 local-part + domain
- PHONE_NUMBER        — US, UK, and common EU formats
- US_SSN              — ###-##-#### with format validation
- CREDIT_CARD         — 13-19 digit numbers passing Luhn check
- IP_ADDRESS          — IPv4 dotted-decimal
- DATE_OF_BIRTH       — common date formats (yyyy-mm-dd, dd/mm/yyyy, etc.)
- POSTAL_CODE         — US ZIP+4 and UK postcode formats

Usage:
    config = DetectorConfig(enabled_patterns={"email", "phone"}, min_confidence=0.8)
    detector = LocalPIIDetector(config)
    findings = detector.detect("Contact me at alice@example.com")
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# PIIFinding dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PIIFinding:
    """A single PII span identified by the local detector.

    Attributes:
        entity_type: Presidio-compatible entity label (e.g. ``EMAIL_ADDRESS``).
        text:        The exact substring that was flagged.
        start:       Zero-based start index within the source string.
        end:         Zero-based exclusive end index within the source string.
        confidence:  Detection confidence in the range ``[0.0, 1.0]``.
                     Regex matches without checksum validation are lower;
                     those with checksum validation are higher.
    """

    entity_type: str
    text: str
    start: int
    end: int
    confidence: float

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(
                f"PIIFinding.confidence must be between 0.0 and 1.0, "
                f"got {self.confidence!r}"
            )
        if self.start < 0:
            raise ValueError(f"PIIFinding.start must be >= 0, got {self.start!r}")
        if self.end < self.start:
            raise ValueError(
                f"PIIFinding.end ({self.end}) must be >= start ({self.start})"
            )


# ---------------------------------------------------------------------------
# DetectorConfig dataclass
# ---------------------------------------------------------------------------


@dataclass
class DetectorConfig:
    """Configuration for LocalPIIDetector.

    Attributes:
        enabled_patterns: Set of pattern names to activate.  If empty, all
                          patterns are enabled.  Valid names are the keys of
                          ``PATTERN_NAMES`` (email, phone, ssn, credit_card,
                          ip_address, date_of_birth, postal_code).
        min_confidence:   Minimum confidence score for a finding to be returned.
                          Set by the operator at configuration time; not adjusted
                          at runtime.
    """

    enabled_patterns: set[str] = field(default_factory=set)
    min_confidence: float = 0.7

    def __post_init__(self) -> None:
        if not (0.0 <= self.min_confidence <= 1.0):
            raise ValueError(
                f"DetectorConfig.min_confidence must be between 0.0 and 1.0, "
                f"got {self.min_confidence!r}"
            )

    @classmethod
    def all_patterns(cls, min_confidence: float = 0.7) -> DetectorConfig:
        """Return a config with all patterns enabled."""
        return cls(enabled_patterns=set(), min_confidence=min_confidence)


# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------

# Each entry: (compiled_regex, entity_type, base_confidence)
# base_confidence reflects pattern specificity before any checksum check.

_PATTERN_REGISTRY: dict[str, tuple[re.Pattern[str], str, float]] = {
    "email": (
        re.compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
            re.ASCII,
        ),
        "EMAIL_ADDRESS",
        0.85,
    ),
    "phone": (
        re.compile(
            r"""
            (?:
                # US: (555) 867-5309 | 555-867-5309 | +1 555 867 5309
                (?:\+1[\s\-]?)?\(?\d{3}\)?[\s\-]\d{3}[\s\-]\d{4}
                |
                # UK: +44 7911 123456 | 07911 123456
                (?:\+44\s?|0)\d{4}[\s\-]?\d{6}
                |
                # EU generic: +XX XXXXXXXXX (9-12 digits)
                \+\d{2}[\s\-]?\d{4,5}[\s\-]?\d{4,6}
            )
            """,
            re.VERBOSE | re.ASCII,
        ),
        "PHONE_NUMBER",
        0.75,
    ),
    "ssn": (
        re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        "US_SSN",
        0.9,
    ),
    "credit_card": (
        re.compile(r"\b(?:\d[ \-]?){13,19}\b"),
        "CREDIT_CARD",
        0.0,  # confidence set by Luhn check result
    ),
    "ip_address": (
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        "IP_ADDRESS",
        0.9,
    ),
    "date_of_birth": (
        re.compile(
            r"""
            (?:
                # yyyy-mm-dd or yyyy/mm/dd
                \b\d{4}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b
                |
                # dd/mm/yyyy or dd-mm-yyyy
                \b(?:0[1-9]|[12]\d|3[01])[-/](?:0[1-9]|1[0-2])[-/]\d{4}\b
                |
                # mm/dd/yyyy (US)
                \b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/\d{4}\b
            )
            """,
            re.VERBOSE,
        ),
        "DATE_OF_BIRTH",
        0.75,
    ),
    "postal_code": (
        re.compile(
            r"""
            (?:
                # US ZIP or ZIP+4
                \b\d{5}(?:-\d{4})?\b
                |
                # UK postcode: SW1A 2AA
                \b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b
            )
            """,
            re.VERBOSE | re.ASCII | re.IGNORECASE,
        ),
        "POSTAL_CODE",
        0.7,
    ),
}


# ---------------------------------------------------------------------------
# Luhn checksum validation
# ---------------------------------------------------------------------------


def _luhn_valid(number_str: str) -> bool:
    """Return True when *number_str* (digits only) passes the Luhn check.

    Parameters
    ----------
    number_str:
        A string containing only digit characters.

    Returns
    -------
    bool:
        True when the Luhn check digit is valid.
    """
    digits = [int(ch) for ch in number_str]
    digits.reverse()
    total = 0
    for position, digit in enumerate(digits):
        if position % 2 == 1:
            doubled = digit * 2
            total += doubled - 9 if doubled > 9 else doubled
        else:
            total += digit
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Public detector class
# ---------------------------------------------------------------------------


class LocalPIIDetector:
    """Pure regex-based PII detector requiring no external libraries.

    The detector is stateless — the same instance can be called from
    multiple threads simultaneously without synchronisation.

    Parameters
    ----------
    config:
        DetectorConfig controlling which patterns are active and the
        minimum confidence threshold.  Defaults to all patterns enabled
        with a confidence floor of 0.7.

    Example
    -------
    >>> detector = LocalPIIDetector()
    >>> findings = detector.detect("My SSN is 123-45-6789")
    >>> findings[0].entity_type
    'US_SSN'
    """

    def __init__(self, config: DetectorConfig | None = None) -> None:
        self._config = config if config is not None else DetectorConfig.all_patterns()
        self._active_patterns = self._resolve_active_patterns()

    def _resolve_active_patterns(self) -> dict[str, tuple[re.Pattern[str], str, float]]:
        """Filter the registry to only enabled patterns."""
        if not self._config.enabled_patterns:
            return dict(_PATTERN_REGISTRY)
        return {
            name: entry
            for name, entry in _PATTERN_REGISTRY.items()
            if name in self._config.enabled_patterns
        }

    @property
    def config(self) -> DetectorConfig:
        """Read-only access to the active configuration."""
        return self._config

    @property
    def active_pattern_names(self) -> list[str]:
        """Names of all patterns currently active in this detector."""
        return list(self._active_patterns.keys())

    def detect(self, text: str) -> list[PIIFinding]:
        """Scan *text* and return all PII findings above the confidence floor.

        The detection is:
        1. Run each active regex against the text.
        2. For credit card numbers, apply Luhn validation; skip if invalid.
        3. Deduplicate overlapping spans, keeping the highest-confidence finding.
        4. Filter out findings below min_confidence.
        5. Return sorted by start position.

        Parameters
        ----------
        text:
            The plain-text string to scan.

        Returns
        -------
        list[PIIFinding]:
            Sorted, deduplicated PII findings.  Empty when nothing is found
            above the confidence floor.
        """
        if not text or not text.strip():
            return []

        raw_findings: list[PIIFinding] = []

        for pattern_name, (regex, entity_type, base_confidence) in self._active_patterns.items():
            for match in regex.finditer(text):
                matched_text = match.group()
                confidence = base_confidence

                if pattern_name == "credit_card":
                    digits_only = re.sub(r"\D", "", matched_text)
                    if len(digits_only) < 13 or not _luhn_valid(digits_only):
                        continue
                    confidence = 0.9

                if confidence < self._config.min_confidence:
                    continue

                raw_findings.append(
                    PIIFinding(
                        entity_type=entity_type,
                        text=matched_text,
                        start=match.start(),
                        end=match.end(),
                        confidence=confidence,
                    )
                )

        return self._deduplicate(raw_findings)

    @staticmethod
    def _deduplicate(findings: list[PIIFinding]) -> list[PIIFinding]:
        """Remove overlapping findings, keeping the highest-confidence span.

        Parameters
        ----------
        findings:
            Unsorted list of raw findings.

        Returns
        -------
        list[PIIFinding]:
            Non-overlapping findings sorted by start position.
        """
        if not findings:
            return []

        sorted_by_confidence = sorted(findings, key=lambda f: (-f.confidence, f.start))
        kept: list[PIIFinding] = []

        for candidate in sorted_by_confidence:
            overlaps = any(
                candidate.start < kept_item.end and candidate.end > kept_item.start
                for kept_item in kept
            )
            if not overlaps:
                kept.append(candidate)

        return sorted(kept, key=lambda f: f.start)

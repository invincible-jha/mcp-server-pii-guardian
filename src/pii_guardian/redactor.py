# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
PIIRedactor — applies a chosen redaction strategy to a dict payload or
a plain-text string based on detected PIIDetection spans.

Strategies
----------
MASK    Preserve the first and last character of each word/token and
        replace the middle with asterisks.  For email addresses the local
        part and the domain label are masked separately so the structure
        of the address is still recognisable.

HASH    Replace each detected span with its SHA-256 hex digest (truncated
        to 16 hex chars for readability, still collision-resistant for
        pseudonymisation).

REMOVE  Replace each span with the literal string ``[REDACTED]``.

REPLACE Replace each span with the entity-type label enclosed in brackets,
        e.g. ``[EMAIL_ADDRESS]``.
"""

from __future__ import annotations

import copy
import hashlib
import logging
from typing import Any

from pii_guardian.types import PIIDetection, RedactionStrategy

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers -------------------------------------------------------------------
# ---------------------------------------------------------------------------

_MASK_CHAR = "*"


def _mask_token(token: str) -> str:
    """Mask a single word/token, preserving first and last characters.

    >>> _mask_token("john")
    'j**n'
    >>> _mask_token("ab")
    'a*'
    >>> _mask_token("a")
    '*'
    """
    if len(token) <= 1:
        return _MASK_CHAR * len(token)
    if len(token) == 2:  # noqa: PLR2004
        return token[0] + _MASK_CHAR
    return token[0] + _MASK_CHAR * (len(token) - 2) + token[-1]


def _mask_value(text: str, entity_type: str) -> str:
    """Apply mask strategy to ``text``, with entity-aware formatting.

    Email addresses receive per-component masking (local-part @ domain)
    so the overall shape of the address is preserved.
    """
    if entity_type == "EMAIL_ADDRESS" and "@" in text:
        local, _, domain = text.partition("@")
        domain_name, _, tld = domain.partition(".")
        masked_local = _mask_token(local)
        masked_domain = _mask_token(domain_name)
        masked_tld = tld if tld else ""
        return f"{masked_local}@{masked_domain}.{masked_tld}" if masked_tld else f"{masked_local}@{masked_domain}"

    # Generic masking: mask each whitespace-delimited token individually.
    tokens = text.split(" ")
    return " ".join(_mask_token(t) if t else t for t in tokens)


def _hash_value(text: str) -> str:
    """Return a 16-character hex SHA-256 digest of ``text``."""
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"[HASH:{digest[:16]}]"


# ---------------------------------------------------------------------------
# Public class --------------------------------------------------------------
# ---------------------------------------------------------------------------


class PIIRedactor:
    """Rewrites detected PII spans in text and nested dict payloads.

    Parameters
    ----------
    strategy:
        The RedactionStrategy to apply.  Defaults to MASK.

    Example
    -------
    >>> from pii_guardian.types import RedactionStrategy, PIIDetection
    >>> redactor = PIIRedactor(RedactionStrategy.REPLACE)
    >>> detection = PIIDetection("EMAIL_ADDRESS", "bob@example.com", 8, 23, 0.99)
    >>> redactor.redact_text("Contact bob@example.com today", [detection])
    'Contact [EMAIL_ADDRESS] today'
    """

    def __init__(
        self,
        strategy: RedactionStrategy = RedactionStrategy.MASK,
    ) -> None:
        self._strategy = strategy
        logger.debug("PIIRedactor initialised with strategy=%s", strategy)

    # ------------------------------------------------------------------
    # Public interface --------------------------------------------------
    # ------------------------------------------------------------------

    @property
    def strategy(self) -> RedactionStrategy:
        """The currently configured RedactionStrategy."""
        return self._strategy

    def redact_text(
        self,
        text: str,
        detections: list[PIIDetection],
    ) -> str:
        """Rewrite ``text`` by replacing each detected span.

        Detections are applied from right to left so that earlier span
        indices remain valid after each substitution.

        Parameters
        ----------
        text:
            The source string to redact.
        detections:
            Sorted list of PIIDetection instances for this string.

        Returns
        -------
        str:
            The redacted string.
        """
        if not detections:
            return text

        # Work right-to-left to preserve earlier indices.
        ordered = sorted(detections, key=lambda d: d.start, reverse=True)
        result = text
        for detection in ordered:
            replacement = self._replacement_for(detection)
            result = result[: detection.start] + replacement + result[detection.end :]
        return result

    def redact(
        self,
        data: dict[str, Any],
        detections_by_path: list[tuple[str, list[PIIDetection]]],
    ) -> dict[str, Any]:
        """Deep-copy ``data`` and apply redactions at each dotted path.

        Parameters
        ----------
        data:
            The original payload dict.
        detections_by_path:
            Pairs of ``(dot_path, detections)`` as returned by
            ``PIIDetector.detect_in_values()``.

        Returns
        -------
        dict[str, Any]:
            A new dict (deep-copy) with all detected PII rewritten.
        """
        if not detections_by_path:
            return data

        redacted = copy.deepcopy(data)
        for path, detections in detections_by_path:
            self._apply_at_path(redacted, path, detections)
        return redacted

    # ------------------------------------------------------------------
    # Internal helpers --------------------------------------------------
    # ------------------------------------------------------------------

    def _replacement_for(self, detection: PIIDetection) -> str:
        """Compute the replacement string for a single detection."""
        match self._strategy:
            case RedactionStrategy.MASK:
                return _mask_value(detection.text, detection.entity_type)
            case RedactionStrategy.HASH:
                return _hash_value(detection.text)
            case RedactionStrategy.REMOVE:
                return "[REDACTED]"
            case RedactionStrategy.REPLACE:
                return f"[{detection.entity_type}]"
            case _:
                # Unreachable unless the enum is extended without updating here.
                return "[REDACTED]"

    def _apply_at_path(
        self,
        data: dict[str, Any],
        path: str,
        detections: list[PIIDetection],
    ) -> None:
        """Mutate ``data`` in place, redacting the string at ``path``.

        Path syntax:
        - ``"key"``          — top-level key
        - ``"parent.child"`` — nested dict key
        - ``"list[0]"``      — list element
        - ``"parent.list[2].field"`` — mixed nesting
        """
        parts = _parse_path(path)
        node: Any = data
        try:
            for part in parts[:-1]:
                if isinstance(part, int):
                    node = node[part]
                else:
                    node = node[part]
            last = parts[-1]
            if isinstance(node, (dict, list)) and isinstance(node[last], str):
                node[last] = self.redact_text(node[last], detections)
        except (KeyError, IndexError, TypeError) as exc:
            logger.warning("Could not apply redaction at path %r: %s", path, exc)


def _parse_path(path: str) -> list[str | int]:
    """Parse a dot-separated path with optional bracket indices.

    Examples
    --------
    >>> _parse_path("foo.bar[0].baz")
    ['foo', 'bar', 0, 'baz']
    >>> _parse_path("items[2]")
    ['items', 2]
    """
    parts: list[str | int] = []
    for segment in path.split("."):
        if not segment:
            continue
        if "[" in segment:
            key_part, *index_parts = segment.split("[")
            if key_part:
                parts.append(key_part)
            for index_part in index_parts:
                index_str = index_part.rstrip("]")
                if index_str.isdigit():
                    parts.append(int(index_str))
                else:
                    parts.append(index_str)
        else:
            parts.append(segment)
    return parts

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
Streaming PII detection for incremental text processing.

Processes text chunks as they arrive, managing patterns that may span chunk
boundaries by maintaining an overlap buffer. Suitable for streaming LLM
output or chunked file processing.

Example
-------
>>> detector = StreamingPIIDetector()
>>> detections = detector.feed("My email is alice@")
>>> detections += detector.feed("example.com and SSN is 123-45-6789")
>>> remaining = detector.flush()
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from pii_guardian.config import DEFAULT_ENTITIES
from pii_guardian.types import PIIDetection

logger = logging.getLogger(__name__)

# Maximum number of characters to retain as overlap between chunks.
# This must be large enough to capture the longest PII pattern split
# across a chunk boundary (e.g., a full SSN or email address).
_OVERLAP_BUFFER_SIZE: int = 128

# ---------------------------------------------------------------------------
# Regex-based local patterns (no Presidio dependency for streaming path)
# ---------------------------------------------------------------------------

# Each entry: (entity_type, compiled_pattern, confidence)
_REGEX_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    (
        "EMAIL_ADDRESS",
        re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE),
        0.92,
    ),
    (
        "US_SSN",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        0.95,
    ),
    (
        "PHONE_NUMBER",
        re.compile(
            r"\b(?:\+1[\s\-]?)?(?:\(\d{3}\)[\s\-]?|\d{3}[\s\-])\d{3}[\s\-]\d{4}\b"
        ),
        0.90,
    ),
    (
        "CREDIT_CARD",
        re.compile(r"\b(?:\d{4}[\s\-]?){3}\d{4}\b"),
        0.88,
    ),
    (
        "IP_ADDRESS",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        0.91,
    ),
    (
        "US_PASSPORT",
        re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
        0.72,
    ),
    (
        "US_DRIVER_LICENSE",
        re.compile(r"\b[A-Z]\d{7}\b|\b[A-Z]{2}\d{6}\b"),
        0.65,
    ),
    (
        "URL",
        re.compile(
            r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+"
            r"(?:/[-\w%@!$&'()*+,;:=.~/?#]*)?",
            re.IGNORECASE,
        ),
        0.80,
    ),
]


@dataclass
class _ChunkResult:
    """Internal: detections found in a text segment with their absolute positions."""

    detections: list[PIIDetection] = field(default_factory=list)


class StreamingPIIDetector:
    """Incrementally detect PII in a stream of text chunks.

    Maintains an overlap buffer to catch PII patterns that are split across
    chunk boundaries. Uses local regex patterns (no Presidio) so it has zero
    startup latency and no network dependency.

    Confidence scores reflect detection method:
    - Regex detections: 0.88–0.95 (high, pattern-exact)
    - Heuristic detections: 0.50–0.80 (medium, context-dependent)

    Parameters
    ----------
    entities:
        PII entity types to detect. Defaults to ``DEFAULT_ENTITIES``.
    overlap_size:
        Number of characters to retain between chunks to catch cross-boundary
        patterns. Defaults to 128.

    Example
    -------
    >>> sdetector = StreamingPIIDetector()
    >>> chunks = ["Call me at ", "555-867-5309 or email me at", " alice@example.com"]
    >>> all_detections = []
    >>> for chunk in chunks:
    ...     all_detections.extend(sdetector.feed(chunk))
    >>> all_detections.extend(sdetector.flush())
    """

    def __init__(
        self,
        entities: list[str] | None = None,
        overlap_size: int = _OVERLAP_BUFFER_SIZE,
    ) -> None:
        self._entities: frozenset[str] = frozenset(
            entities if entities is not None else DEFAULT_ENTITIES
        )
        self._overlap_size: int = max(0, overlap_size)
        self._buffer: str = ""
        self._global_offset: int = 0  # tracks position in the full stream
        self._emitted_spans: set[tuple[int, int]] = set()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def feed(self, chunk: str) -> list[PIIDetection]:
        """Process a new chunk of text and return any complete PII detections.

        Patterns that may extend into the next chunk are held in the overlap
        buffer and will be returned on the next ``feed`` or ``flush`` call.

        Parameters
        ----------
        chunk:
            The next segment of text to analyse.

        Returns
        -------
        list[PIIDetection]:
            Detections that are fully contained within the already-processed
            text (not overlapping into the pending region).
        """
        if not chunk:
            return []

        # Combine leftover overlap with the new chunk
        window: str = self._buffer + chunk

        # Find all detections in the combined window
        raw_detections = self._scan_window(window)

        # Determine the safe zone: everything except the last overlap_size chars
        safe_end = max(0, len(window) - self._overlap_size)

        # Emit detections that are fully within the safe zone
        emitted: list[PIIDetection] = []
        for detection in raw_detections:
            # Adjust to global stream coordinates
            global_start = self._global_offset - len(self._buffer) + detection.start
            global_end = self._global_offset - len(self._buffer) + detection.end
            span = (global_start, global_end)

            if detection.end <= safe_end and span not in self._emitted_spans:
                self._emitted_spans.add(span)
                emitted.append(
                    PIIDetection(
                        entity_type=detection.entity_type,
                        text=detection.text,
                        start=global_start,
                        end=global_end,
                        score=detection.score,
                    )
                )

        # Update buffer and global offset
        self._buffer = window[safe_end:]
        self._global_offset += len(chunk)

        return sorted(emitted, key=lambda d: d.start)

    def flush(self) -> list[PIIDetection]:
        """Flush the remaining buffer and return any outstanding PII detections.

        Call this after the last chunk has been fed to ensure no detections
        are left in the overlap buffer.

        Returns
        -------
        list[PIIDetection]:
            Any remaining detections from the buffered text.
        """
        if not self._buffer:
            return []

        raw_detections = self._scan_window(self._buffer)
        buffer_base = self._global_offset - len(self._buffer)
        flushed: list[PIIDetection] = []

        for detection in raw_detections:
            global_start = buffer_base + detection.start
            global_end = buffer_base + detection.end
            span = (global_start, global_end)
            if span not in self._emitted_spans:
                self._emitted_spans.add(span)
                flushed.append(
                    PIIDetection(
                        entity_type=detection.entity_type,
                        text=detection.text,
                        start=global_start,
                        end=global_end,
                        score=detection.score,
                    )
                )

        self._buffer = ""
        return sorted(flushed, key=lambda d: d.start)

    def reset(self) -> None:
        """Reset internal state to process a new stream from scratch."""
        self._buffer = ""
        self._global_offset = 0
        self._emitted_spans = set()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _scan_window(self, window: str) -> list[PIIDetection]:
        """Run all enabled regex patterns against *window*.

        Returns a deduplicated, sorted list of non-overlapping detections.
        """
        raw: list[PIIDetection] = []

        for entity_type, pattern, confidence in _REGEX_PATTERNS:
            if entity_type not in self._entities:
                continue
            for match in pattern.finditer(window):
                raw.append(
                    PIIDetection(
                        entity_type=entity_type,
                        text=match.group(),
                        start=match.start(),
                        end=match.end(),
                        score=confidence,
                    )
                )

        return _deduplicate_detections(raw)


# ---------------------------------------------------------------------------
# Standalone helpers
# ---------------------------------------------------------------------------


def _deduplicate_detections(detections: list[PIIDetection]) -> list[PIIDetection]:
    """Remove overlapping detections, preferring the highest-confidence span."""
    if not detections:
        return []

    sorted_by_score = sorted(detections, key=lambda d: (-d.score, d.start))
    kept: list[PIIDetection] = []

    for candidate in sorted_by_score:
        overlaps = any(
            candidate.start < kept_det.end and candidate.end > kept_det.start
            for kept_det in kept
        )
        if not overlaps:
            kept.append(candidate)

    return sorted(kept, key=lambda d: d.start)

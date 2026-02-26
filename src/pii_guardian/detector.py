# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
PIIDetector — thin, type-safe wrapper around Presidio AnalyzerEngine.

Responsibilities
----------------
* Instantiate and cache a Presidio AnalyzerEngine at construction time.
* Expose a single ``detect(text)`` method that returns a sorted list of
  non-overlapping PIIDetection instances above the configured threshold.
* Handle Presidio's lazy-import behaviour gracefully with a clear error
  message when the package is not installed.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from pii_guardian.config import DEFAULT_ENTITIES
from pii_guardian.types import PIIDetection

if TYPE_CHECKING:
    # Avoid importing presidio at module-load time so the rest of the
    # library can be imported even in minimal environments.
    from presidio_analyzer import AnalyzerEngine, RecognizerResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sentinel / lazy import helper ---------------------------------------------
# ---------------------------------------------------------------------------


def _load_analyzer() -> "AnalyzerEngine":
    """Import and instantiate a Presidio AnalyzerEngine.

    Raises:
        ImportError: When presidio-analyzer is not installed.
    """
    try:
        from presidio_analyzer import AnalyzerEngine  # noqa: PLC0415
    except ImportError as exc:
        raise ImportError(
            "presidio-analyzer is required. "
            "Install it with:  pip install presidio-analyzer"
        ) from exc
    return AnalyzerEngine()


# ---------------------------------------------------------------------------
# Public class --------------------------------------------------------------
# ---------------------------------------------------------------------------


class PIIDetector:
    """Detects PII entities within a plain-text string.

    Parameters
    ----------
    entities:
        Presidio entity labels to scan for.  Defaults to the package-level
        DEFAULT_ENTITIES list (EMAIL_ADDRESS, PHONE_NUMBER, US_SSN, …).
    threshold:
        Minimum Presidio confidence score ``[0.0, 1.0]`` for a result to be
        included.  Detections below this value are discarded.
    language:
        NLP language model passed to Presidio.  Defaults to ``"en"``.

    Example
    -------
    >>> detector = PIIDetector()
    >>> detections = detector.detect("Call me at 555-867-5309")
    >>> detections[0].entity_type
    'PHONE_NUMBER'
    """

    def __init__(
        self,
        entities: list[str] | None = None,
        threshold: float = 0.7,
        language: str = "en",
    ) -> None:
        if not (0.0 <= threshold <= 1.0):
            raise ValueError(
                f"threshold must be between 0.0 and 1.0, got {threshold!r}"
            )
        self._entities: list[str] = entities if entities is not None else list(DEFAULT_ENTITIES)
        self._threshold: float = threshold
        self._language: str = language
        self._engine: AnalyzerEngine = _load_analyzer()
        logger.debug(
            "PIIDetector initialised — entities=%s threshold=%.2f language=%s",
            self._entities,
            self._threshold,
            self._language,
        )

    # ------------------------------------------------------------------
    # Public interface --------------------------------------------------
    # ------------------------------------------------------------------

    @property
    def entities(self) -> list[str]:
        """Read-only view of the configured entity labels."""
        return list(self._entities)

    @property
    def threshold(self) -> float:
        """Configured minimum confidence threshold."""
        return self._threshold

    def detect(self, text: str) -> list[PIIDetection]:
        """Analyse ``text`` and return all PII detections above threshold.

        Results are sorted by start position (ascending) and deduplicated
        so that overlapping spans from multiple recognisers are collapsed
        to the highest-scoring one.

        Parameters
        ----------
        text:
            The plain-text string to analyse.

        Returns
        -------
        list[PIIDetection]:
            Sorted, non-overlapping detections.  Empty when no PII is found.
        """
        if not text or not text.strip():
            return []

        try:
            raw_results: list[RecognizerResult] = self._engine.analyze(
                text=text,
                entities=self._entities,
                language=self._language,
                score_threshold=self._threshold,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Presidio AnalyzerEngine.analyze raised an exception: %s", exc)
            raise RuntimeError(
                f"PII detection failed for input of length {len(text)}: {exc}"
            ) from exc

        detections = [
            PIIDetection(
                entity_type=result.entity_type,
                text=text[result.start : result.end],
                start=result.start,
                end=result.end,
                score=result.score,
            )
            for result in raw_results
        ]

        return self._deduplicate(detections)

    def detect_in_values(self, data: dict) -> list[tuple[str, list[PIIDetection]]]:
        """Recursively scan all string values within a nested dict.

        Parameters
        ----------
        data:
            Arbitrary nested dict (JSON-compatible payload).

        Returns
        -------
        list[tuple[str, list[PIIDetection]]]:
            Pairs of ``(dot_path, detections)`` for every leaf string that
            contains at least one detection.  Only populated paths are
            returned.
        """
        results: list[tuple[str, list[PIIDetection]]] = []
        self._scan_dict(data, prefix="", results=results)
        return results

    # ------------------------------------------------------------------
    # Internal helpers --------------------------------------------------
    # ------------------------------------------------------------------

    def _scan_dict(
        self,
        node: object,
        prefix: str,
        results: list[tuple[str, list[PIIDetection]]],
    ) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                path = f"{prefix}.{key}" if prefix else key
                self._scan_dict(value, path, results)
        elif isinstance(node, list):
            for index, item in enumerate(node):
                path = f"{prefix}[{index}]"
                self._scan_dict(item, path, results)
        elif isinstance(node, str):
            detections = self.detect(node)
            if detections:
                results.append((prefix, detections))

    @staticmethod
    def _deduplicate(detections: list[PIIDetection]) -> list[PIIDetection]:
        """Remove overlapping detections, keeping the highest-confidence span.

        When two detections overlap (i.e. their character ranges intersect),
        the one with the higher score is retained.  Ties are broken by
        preferring the detection that appears earlier (lower start index).
        """
        if not detections:
            return []

        # Sort by score descending so we greedily keep the best detections.
        sorted_by_score = sorted(detections, key=lambda d: (-d.score, d.start))
        kept: list[PIIDetection] = []

        for candidate in sorted_by_score:
            overlaps = any(
                candidate.start < kept_det.end and candidate.end > kept_det.start
                for kept_det in kept
            )
            if not overlaps:
                kept.append(candidate)

        # Return in document order (by start position).
        return sorted(kept, key=lambda d: d.start)

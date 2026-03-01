# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
PII detection quality benchmark — precision, recall, and F1 per entity type.

Usage
-----
Run directly from the repository root:

    python benchmarks/run_benchmark.py

Or with verbose output:

    python benchmarks/run_benchmark.py --verbose

The benchmark uses the local ``pii_guardian`` package. It measures precision,
recall, and F1 per PII entity type using the ground-truth corpus in
``benchmark_data.py``.

Metrics
-------
- Precision = TP / (TP + FP)  — of all detections, how many were correct?
- Recall    = TP / (TP + FN)  — of all expected PII, how many were found?
- F1        = 2 * P * R / (P + R) — harmonic mean of precision and recall
"""

from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass, field

# Ensure the src directory is on the path when run directly
sys.path.insert(0, "src")

from benchmark_data import ALL_CORPUS, CORPUS_BY_ENTITY_TYPE, CorpusEntry
from pii_guardian.streaming import StreamingPIIDetector
from pii_guardian.types import PIIDetection


# ---------------------------------------------------------------------------
# Metric containers
# ---------------------------------------------------------------------------


@dataclass
class EntityMetrics:
    """Precision, recall, and F1 for a single entity type."""

    entity_type: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    total_samples: int = 0

    @property
    def precision(self) -> float:
        """Fraction of detections that were correct."""
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator > 0 else 0.0

    @property
    def recall(self) -> float:
        """Fraction of expected PII that was found."""
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator > 0 else 0.0

    @property
    def f1(self) -> float:
        """Harmonic mean of precision and recall."""
        precision = self.precision
        recall = self.recall
        denominator = precision + recall
        return 2 * precision * recall / denominator if denominator > 0 else 0.0


@dataclass
class BenchmarkReport:
    """Full benchmark result across all entity types."""

    entity_metrics: dict[str, EntityMetrics] = field(default_factory=dict)
    total_samples: int = 0
    elapsed_seconds: float = 0.0

    @property
    def macro_f1(self) -> float:
        """Average F1 across all entity types (macro average)."""
        scores = [m.f1 for m in self.entity_metrics.values()]
        return sum(scores) / len(scores) if scores else 0.0

    def format(self, verbose: bool = False) -> str:
        """Render the report as a human-readable table."""
        lines: list[str] = [
            "",
            "PII Guardian — Detection Quality Benchmark",
            "=" * 60,
            f"{'Entity Type':<25} {'Precision':>10} {'Recall':>10} {'F1':>10}",
            "-" * 60,
        ]

        for entity_type, metrics in sorted(self.entity_metrics.items()):
            lines.append(
                f"{entity_type:<25} "
                f"{metrics.precision:>10.3f} "
                f"{metrics.recall:>10.3f} "
                f"{metrics.f1:>10.3f}"
            )

        lines += [
            "-" * 60,
            f"{'Macro F1':<25} {'':>10} {'':>10} {self.macro_f1:>10.3f}",
            "=" * 60,
            f"Total samples: {self.total_samples}",
            f"Elapsed: {self.elapsed_seconds:.3f}s",
            "",
        ]

        if verbose:
            lines.append("Per-type detail:")
            for entity_type, metrics in sorted(self.entity_metrics.items()):
                lines.append(
                    f"  {entity_type}: "
                    f"TP={metrics.true_positives} "
                    f"FP={metrics.false_positives} "
                    f"FN={metrics.false_negatives}"
                )

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------


def _match_span(
    detections: list[PIIDetection],
    entity_type: str,
    span_text: str,
) -> bool:
    """Return True if any detection matches the expected entity type and text."""
    return any(
        d.entity_type == entity_type and d.text == span_text for d in detections
    )


def run_entity_benchmark(
    entity_type: str,
    corpus: list[CorpusEntry],
    detector: StreamingPIIDetector,
) -> EntityMetrics:
    """Measure precision, recall, and F1 for one entity type against its corpus."""
    metrics = EntityMetrics(entity_type=entity_type)

    for entry in corpus:
        metrics.total_samples += 1
        det = StreamingPIIDetector(entities=[entity_type])
        detections = det.feed(entry.text)
        detections += det.flush()

        detected_spans = set(
            (d.entity_type, d.text)
            for d in detections
            if d.entity_type == entity_type
        )
        expected_spans = set(
            (et, span)
            for et, span in entry.expected_spans
            if et == entity_type
        )

        # Count TP, FP, FN at span level
        for span in expected_spans:
            if span in detected_spans:
                metrics.true_positives += 1
            else:
                metrics.false_negatives += 1

        for span in detected_spans:
            if span not in expected_spans:
                metrics.false_positives += 1

    return metrics


def run_full_benchmark(verbose: bool = False) -> BenchmarkReport:
    """Run the complete benchmark across all entity types and return the report."""
    report = BenchmarkReport(total_samples=len(ALL_CORPUS))
    detector = StreamingPIIDetector()

    start = time.monotonic()

    for entity_type, corpus in CORPUS_BY_ENTITY_TYPE.items():
        metrics = run_entity_benchmark(entity_type, corpus, detector)
        report.entity_metrics[entity_type] = metrics

    report.elapsed_seconds = time.monotonic() - start
    return report


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the PII detection benchmark and print the results."""
    parser = argparse.ArgumentParser(
        description="Benchmark pii_guardian detection quality (precision, recall, F1)."
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-type TP/FP/FN detail alongside the summary table.",
    )
    args = parser.parse_args()

    report = run_full_benchmark(verbose=args.verbose)
    print(report.format(verbose=args.verbose))


if __name__ == "__main__":
    main()

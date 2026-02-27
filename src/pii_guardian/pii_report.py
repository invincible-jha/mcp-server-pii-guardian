# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
PIIReportGenerator — audit report generation for PII findings.

Produces structured reports from a list of PIIFinding objects
(from LocalPIIDetector) or PIIDetection objects (from PIIDetector).
Reports are exportable as JSON, CSV, or Markdown.

This module is a pure reporting layer — it records what was found.
It applies no heuristics and performs no anomaly detection.

Usage:
    from pii_guardian.local_detector import LocalPIIDetector
    from pii_guardian.pii_report import PIIReportGenerator

    detector = LocalPIIDetector()
    findings = detector.detect("Email: alice@example.com, SSN: 123-45-6789")
    generator = PIIReportGenerator()
    report = generator.generate_report(findings, profile="gdpr")
    print(generator.export_markdown(report))
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Protocol — compatible with both PIIFinding and PIIDetection
# ---------------------------------------------------------------------------


@runtime_checkable
class PIIFindingLike(Protocol):
    """Structural protocol for any PII detection result.

    Both ``PIIFinding`` (from local_detector) and ``PIIDetection``
    (from detector / types) satisfy this protocol.
    """

    entity_type: str
    text: str
    start: int
    end: int


def _get_confidence(finding: PIIFindingLike) -> float:
    """Extract the confidence/score from a finding regardless of attribute name."""
    if hasattr(finding, "confidence"):
        return float(finding.confidence)  # type: ignore[union-attr]
    if hasattr(finding, "score"):
        return float(finding.score)  # type: ignore[union-attr]
    return 0.0


# ---------------------------------------------------------------------------
# Report dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FindingSummary:
    """Aggregated statistics for a single entity type.

    Attributes:
        entity_type:  The Presidio entity label.
        count:        Total number of findings for this entity type.
        avg_confidence: Mean confidence across all findings of this type.
    """

    entity_type: str
    count: int
    avg_confidence: float


@dataclass(frozen=True)
class PIIReport:
    """A complete PII audit report.

    Attributes:
        profile_name:        The compliance profile used for classification
                             (e.g. ``"gdpr"``, ``"hipaa"``, ``"pci"``, ``"ccpa"``).
        total_findings:      Total number of PII findings across all categories.
        findings_by_category: Mapping of entity_type -> list of serialisable
                              finding dicts (entity_type, text_length, start, end,
                              confidence).  Raw PII text is NOT stored — only the
                              span length is recorded to avoid re-creating a PII
                              exposure in the report itself.
        category_summaries:  Aggregated statistics per entity type.
        compliance_status:   ``"clean"`` when total_findings == 0, else
                             ``"findings_present"``.
        generated_at:        ISO-8601 UTC timestamp string.
    """

    profile_name: str
    total_findings: int
    findings_by_category: dict[str, list[dict[str, Any]]]
    category_summaries: list[FindingSummary]
    compliance_status: str
    generated_at: str


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


@dataclass
class PIIReportGenerator:
    """Generates and exports PII audit reports from detection findings.

    The generator is stateless — each call to ``generate_report`` is
    independent and thread-safe.

    Parameters
    ----------
    redact_text_in_report:
        When True (the default), only the character-length of detected
        spans is stored in the report rather than the raw PII text.
        Set to False only in controlled environments where re-exposing
        the finding text is acceptable.
    """

    redact_text_in_report: bool = True

    def generate_report(
        self,
        findings: list[Any],
        profile: str,
    ) -> PIIReport:
        """Build a PIIReport from a list of detection findings.

        Parameters
        ----------
        findings:
            A list of PIIFinding or PIIDetection objects.  Any object that
            satisfies the PIIFindingLike protocol is accepted.
        profile:
            Human-readable compliance profile name for the report header
            (e.g. ``"gdpr"``, ``"hipaa"``, ``"pci"``, ``"ccpa"``).

        Returns
        -------
        PIIReport:
            A frozen report dataclass ready for export.
        """
        findings_by_category: dict[str, list[dict[str, Any]]] = {}
        confidence_accumulator: dict[str, list[float]] = {}

        for finding in findings:
            entity_type: str = finding.entity_type
            confidence: float = _get_confidence(finding)
            text_repr: str = (
                f"[{len(finding.text)} chars redacted]"
                if self.redact_text_in_report
                else finding.text
            )

            record: dict[str, Any] = {
                "entity_type": entity_type,
                "text": text_repr,
                "start": finding.start,
                "end": finding.end,
                "confidence": round(confidence, 4),
            }

            findings_by_category.setdefault(entity_type, []).append(record)
            confidence_accumulator.setdefault(entity_type, []).append(confidence)

        category_summaries: list[FindingSummary] = []
        for entity_type, records in findings_by_category.items():
            confidences = confidence_accumulator[entity_type]
            avg_confidence = sum(confidences) / len(confidences)
            category_summaries.append(
                FindingSummary(
                    entity_type=entity_type,
                    count=len(records),
                    avg_confidence=round(avg_confidence, 4),
                )
            )

        # Sort summaries by count descending for readability
        category_summaries.sort(key=lambda s: (-s.count, s.entity_type))

        total_findings = sum(s.count for s in category_summaries)
        compliance_status = "clean" if total_findings == 0 else "findings_present"

        return PIIReport(
            profile_name=profile,
            total_findings=total_findings,
            findings_by_category=findings_by_category,
            category_summaries=category_summaries,
            compliance_status=compliance_status,
            generated_at=datetime.now(tz=timezone.utc).isoformat(),
        )

    # ------------------------------------------------------------------
    # Export methods
    # ------------------------------------------------------------------

    def export_json(self, report: PIIReport) -> str:
        """Serialise *report* as a pretty-printed JSON string.

        Parameters
        ----------
        report:
            A PIIReport produced by ``generate_report``.

        Returns
        -------
        str:
            JSON-encoded report.
        """
        payload: dict[str, Any] = {
            "profile_name": report.profile_name,
            "generated_at": report.generated_at,
            "compliance_status": report.compliance_status,
            "total_findings": report.total_findings,
            "category_summaries": [
                {
                    "entity_type": summary.entity_type,
                    "count": summary.count,
                    "avg_confidence": summary.avg_confidence,
                }
                for summary in report.category_summaries
            ],
            "findings_by_category": report.findings_by_category,
        }
        return json.dumps(payload, indent=2)

    def export_csv(self, report: PIIReport) -> str:
        """Serialise *report* findings as a CSV string.

        The CSV has one row per finding with columns:
        entity_type, start, end, confidence, text

        Parameters
        ----------
        report:
            A PIIReport produced by ``generate_report``.

        Returns
        -------
        str:
            RFC 4180-compliant CSV content.
        """
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=["entity_type", "start", "end", "confidence", "text"],
            lineterminator="\n",
        )
        writer.writeheader()

        for records in report.findings_by_category.values():
            for record in records:
                writer.writerow(
                    {
                        "entity_type": record["entity_type"],
                        "start": record["start"],
                        "end": record["end"],
                        "confidence": record["confidence"],
                        "text": record["text"],
                    }
                )

        return output.getvalue()

    def export_markdown(self, report: PIIReport) -> str:
        """Render *report* as a human-readable Markdown document.

        Parameters
        ----------
        report:
            A PIIReport produced by ``generate_report``.

        Returns
        -------
        str:
            A Markdown-formatted string suitable for display in a PR comment,
            documentation page, or incident report.
        """
        lines: list[str] = []

        lines.append("# PII Detection Report")
        lines.append("")
        lines.append(f"**Profile:** {report.profile_name}")
        lines.append(f"**Generated:** {report.generated_at}")
        lines.append(f"**Status:** `{report.compliance_status}`")
        lines.append(f"**Total findings:** {report.total_findings}")
        lines.append("")

        if not report.category_summaries:
            lines.append("No PII findings detected.")
            return "\n".join(lines)

        lines.append("## Summary by Category")
        lines.append("")
        lines.append("| Entity Type | Count | Avg Confidence |")
        lines.append("|-------------|------:|---------------:|")
        for summary in report.category_summaries:
            lines.append(
                f"| `{summary.entity_type}` | {summary.count} "
                f"| {summary.avg_confidence:.4f} |"
            )

        lines.append("")
        lines.append("## Findings Detail")
        lines.append("")

        for entity_type, records in sorted(report.findings_by_category.items()):
            lines.append(f"### {entity_type}")
            lines.append("")
            lines.append("| # | Start | End | Confidence | Text |")
            lines.append("|---|------:|----:|-----------:|------|")
            for index, record in enumerate(records, start=1):
                lines.append(
                    f"| {index} | {record['start']} | {record['end']} "
                    f"| {record['confidence']:.4f} | `{record['text']}` |"
                )
            lines.append("")

        return "\n".join(lines)

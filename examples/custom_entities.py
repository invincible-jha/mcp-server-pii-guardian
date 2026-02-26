# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
custom_entities.py — demonstrates adding domain-specific PII recognisers
to the Presidio AnalyzerEngine used inside PIIDetector.

Presidio's recogniser registry allows you to plug in pattern-based or
ML-based recognisers for entity types that are not covered out of the box.

This example adds two custom recognisers:
  - EMPLOYEE_ID   Pattern: EMP-XXXXXX (6 digits)
  - API_KEY       Pattern: sk-live-... or sk-test-... (Stripe-style API key)

Run:
    pip install -e ".[dev]"
    python -m spacy download en_core_web_lg
    python examples/custom_entities.py
"""

from __future__ import annotations

import sys

from pii_guardian import (
    GuardianConfig,
    PIIAction,
    PIIDetection,
    PIIDetector,
    PIIGuardian,
    RedactionStrategy,
)


# ---------------------------------------------------------------------------
# Custom recogniser helpers -------------------------------------------------
# ---------------------------------------------------------------------------


def build_employee_id_recogniser():  # type: ignore[return]
    """Build a Presidio PatternRecognizer for EMPLOYEE_ID."""
    try:
        from presidio_analyzer import Pattern, PatternRecognizer  # noqa: PLC0415
    except ImportError as exc:
        raise ImportError("presidio-analyzer is required") from exc

    return PatternRecognizer(
        supported_entity="EMPLOYEE_ID",
        patterns=[
            Pattern(
                name="employee_id_pattern",
                regex=r"\bEMP-\d{6}\b",
                score=0.95,
            )
        ],
        context=["employee", "emp", "staff", "id"],
    )


def build_api_key_recogniser():  # type: ignore[return]
    """Build a Presidio PatternRecognizer for API_KEY (Stripe-style)."""
    try:
        from presidio_analyzer import Pattern, PatternRecognizer  # noqa: PLC0415
    except ImportError as exc:
        raise ImportError("presidio-analyzer is required") from exc

    return PatternRecognizer(
        supported_entity="API_KEY",
        patterns=[
            Pattern(
                name="stripe_api_key",
                regex=r"\bsk-(live|test)-[A-Za-z0-9]{24,}\b",
                score=0.99,
            )
        ],
        context=["key", "token", "secret", "api"],
    )


# ---------------------------------------------------------------------------
# Extended detector ---------------------------------------------------------
# ---------------------------------------------------------------------------


def build_extended_detector() -> PIIDetector:
    """Construct a PIIDetector with custom recognisers added to the engine."""
    entities = [
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "PERSON",
        "EMPLOYEE_ID",
        "API_KEY",
    ]
    detector = PIIDetector(entities=entities, threshold=0.7)

    # Access the internal Presidio engine and add our custom recognisers
    registry = detector._engine.registry  # type: ignore[attr-defined]
    registry.add_recognizer(build_employee_id_recogniser())
    registry.add_recognizer(build_api_key_recogniser())

    return detector


# ---------------------------------------------------------------------------
# Demo ----------------------------------------------------------------------
# ---------------------------------------------------------------------------


def _print_detections(label: str, detections: list[PIIDetection]) -> None:
    print(f"\n{label}")
    if not detections:
        print("  (no detections)")
        return
    for det in detections:
        print(f"  [{det.entity_type}] {det.text!r}  (score={det.score:.0%}, span={det.start}:{det.end})")


def demo_custom_detector() -> None:
    """Show raw detection results for custom entity types."""
    detector = build_extended_detector()

    test_cases = [
        "The employee EMP-004821 needs access revoked.",
        "Use sk-live-AbCdEfGhIjKlMnOpQrStUvWxYz for the Stripe integration.",
        "Contact john@acme.com or call EMP-991234 for HR matters.",
        "No sensitive data here.",
    ]
    print("\n--- Custom Detector Results ---")
    for text in test_cases:
        detections = detector.detect(text)
        _print_detections(f"Input: {text!r}", detections)


def demo_custom_guardian() -> None:
    """Show a PIIGuardian configured to block API keys and hash employee IDs."""
    detector = build_extended_detector()

    # We need to build the guardian manually to inject our custom detector.
    # PIIGuardian exposes its internal detector for this purpose.
    config = GuardianConfig(
        entities=["EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "EMPLOYEE_ID", "API_KEY"],
        threshold=0.7,
        redaction_strategy=RedactionStrategy.HASH,
        default_action=PIIAction.REDACT,
        blocked_entities=["API_KEY"],  # Never allow raw API keys through
    )
    guardian = PIIGuardian(config)

    # Replace the auto-built detector with our extended one so it knows
    # about EMPLOYEE_ID and API_KEY.
    guardian._detector = detector  # type: ignore[assignment]

    test_payloads: list[tuple[str, dict]] = [
        (
            "onboard_employee",
            {
                "user": "jane.doe@acme.com",
                "employee_id": "EMP-004821",
                "role": "engineer",
            },
        ),
        (
            "config_update",
            {
                "service": "payment_gateway",
                "api_key": "sk-live-AbCdEfGhIjKlMnOpQrStUvWxYz1234",
            },
        ),
        (
            "hr_report",
            {
                "report": "EMP-991234 (alice@corp.com) promoted to Senior Engineer.",
            },
        ),
    ]

    print("\n--- Custom PIIGuardian Results ---")
    for tool_name, payload in test_payloads:
        result = guardian.guard_input(tool_name, payload)
        status = (
            "BLOCKED"
            if result.blocked
            else ("REDACTED" if result.redacted else "CLEAN")
        )
        print(f"\nTool: {tool_name!r}  [{status}]")
        if result.detections:
            for det in result.detections:
                print(f"  Detected {det.entity_type}: {det.text!r}")
        print(f"  Guarded payload: {result.data}")


def main() -> int:
    print("mcp-server-pii-guardian — Custom Entities Demo")
    print("=" * 60)
    print("Adding EMPLOYEE_ID and API_KEY recognisers to Presidio.\n")

    try:
        demo_custom_detector()
        demo_custom_guardian()
    except ImportError as exc:
        print(f"\nImportError: {exc}", file=sys.stderr)
        print("Install: pip install presidio-analyzer && python -m spacy download en_core_web_lg", file=sys.stderr)
        return 1

    print("\n\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
basic_guardian.py — minimal end-to-end demonstration of PIIGuardian.

Run from the project root after installing the package:

    pip install -e ".[dev]"
    python -m spacy download en_core_web_lg   # Presidio NLP model
    python examples/basic_guardian.py
"""

from __future__ import annotations

import json
import sys

from pii_guardian import (
    GuardianConfig,
    PIIAction,
    PIIGuardian,
    RedactionStrategy,
)


# ---------------------------------------------------------------------------
# Example payloads ----------------------------------------------------------
# ---------------------------------------------------------------------------

TOOL_INPUTS: list[tuple[str, dict]] = [
    (
        "send_email",
        {
            "to": "alice@contoso.com",
            "subject": "Your invoice",
            "body": "Hi Alice, your card ending in 4242 has been charged. SSN 123-45-6789 on file.",
        },
    ),
    (
        "search_docs",
        {
            "query": "Q3 earnings",
            "requested_by": "John Smith",
        },
    ),
    (
        "log_event",
        {
            "event": "login",
            "ip": "192.168.1.50",
            "user": "bob",
            "phone": "555-867-5309",
        },
    ),
    (
        "public_api",
        {
            "endpoint": "/healthz",
            "method": "GET",
        },
    ),
]


def section(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print("=" * 60)


def demo_default_config() -> None:
    """Default config: MASK strategy, REDACT action, SSN/CC always blocked."""
    section("1. Default Configuration (MASK + REDACT)")
    guardian = PIIGuardian(GuardianConfig.default())

    for tool_name, payload in TOOL_INPUTS:
        result = guardian.guard_input(tool_name, payload)
        status = (
            "BLOCKED"
            if result.blocked
            else ("REDACTED" if result.redacted else ("FLAGGED" if result.flagged else "CLEAN"))
        )
        print(f"\nTool: {tool_name!r}  [{status}]")
        if result.detections:
            for det in result.detections:
                print(f"  Detected {det.entity_type} ({det.score:.0%}): {det.text!r}")
        print(f"  Output: {json.dumps(result.data, indent=4)}")


def demo_replace_strategy() -> None:
    """REPLACE strategy swaps detected spans with entity-type labels."""
    section("2. REPLACE Strategy")
    config = GuardianConfig(
        entities=["EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON"],
        threshold=0.6,
        redaction_strategy=RedactionStrategy.REPLACE,
        default_action=PIIAction.REDACT,
    )
    guardian = PIIGuardian(config)

    payload = {
        "message": "Please call John Smith at 555-123-4567 or email him at john@acme.com",
    }
    result = guardian.guard_input("crm_lookup", payload)
    print(f"\nInput : {payload['message']!r}")
    print(f"Output: {result.data['message']!r}")


def demo_flag_only() -> None:
    """FLAG action passes data through but marks the result for inspection."""
    section("3. FLAG Only (observation mode)")
    config = GuardianConfig.permissive()
    guardian = PIIGuardian(config)

    payload = {"note": "Customer Jane Doe called from 212-555-0100"}
    result = guardian.guard_input("crm_note", payload)
    print(f"\nflagged={result.flagged}  clean={result.clean}")
    print(f"Data unchanged: {result.data['note']!r}")
    print(f"Entity types found: {result.entity_types_found}")


def demo_per_tool_actions() -> None:
    """Per-tool actions override the default for specific tool names."""
    section("4. Per-Tool Actions")
    config = GuardianConfig(
        entities=["EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "US_SSN"],
        threshold=0.7,
        redaction_strategy=RedactionStrategy.HASH,
        default_action=PIIAction.REDACT,
        tool_actions={
            "internal_audit": PIIAction.ALLOW,
            "public_webhook": PIIAction.BLOCK,
        },
        blocked_entities=[],  # No global blocks for this demo
    )
    guardian = PIIGuardian(config)

    payload = {"email": "cfo@enterprise.com", "amount": "1000000"}

    for tool_name in ["internal_audit", "public_webhook", "crm_update"]:
        result = guardian.guard_input(tool_name, payload)
        status = (
            "BLOCKED"
            if result.blocked
            else ("ALLOWED" if result.clean or not result.redacted else "REDACTED/HASHED")
        )
        print(f"\nTool: {tool_name!r}  [{status}]")
        if not result.blocked:
            print(f"  email field: {result.data.get('email')!r}")


def demo_audit_stats() -> None:
    """Show audit statistics accumulated over multiple guard calls."""
    section("5. Audit Log Stats")
    guardian = PIIGuardian(GuardianConfig.default())

    payloads = [
        ("tool_a", {"text": "Email me at alpha@beta.com"}),
        ("tool_b", {"text": "Call 555-222-3333 for support"}),
        ("tool_a", {"text": "No PII here, just a query string"}),
        ("tool_c", {"ssn": "444-55-6666"}),  # Will be blocked (SSN)
    ]
    for tool_name, payload in payloads:
        guardian.guard_input(tool_name, payload)

    stats = guardian.audit_stats()
    print(f"\nTotal events logged: {stats['total_events']}")
    print(f"By action:           {stats['by_action']}")
    print(f"By entity type:      {stats['by_entity_type']}")
    print(f"By direction:        {stats['by_direction']}")


# ---------------------------------------------------------------------------
# Entry point ---------------------------------------------------------------
# ---------------------------------------------------------------------------


def main() -> int:
    print("mcp-server-pii-guardian — Basic Guardian Demo")
    print("Requires: pip install presidio-analyzer presidio-anonymizer")
    print("          python -m spacy download en_core_web_lg")

    try:
        demo_default_config()
        demo_replace_strategy()
        demo_flag_only()
        demo_per_tool_actions()
        demo_audit_stats()
    except ImportError as exc:
        print(f"\nImportError: {exc}", file=sys.stderr)
        print("Install dependencies and download the spaCy model first.", file=sys.stderr)
        return 1

    print("\n\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

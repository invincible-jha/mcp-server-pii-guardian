# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
mcp_middleware.py — demonstrates how to wrap any MCP tool handler with
PIIGuardian as a transparent middleware layer.

This example is framework-agnostic.  It defines a minimal ``MCPRequest`` /
``MCPResponse`` protocol and shows the guard-then-dispatch pattern that maps
directly to real MCP server implementations (FastMCP, mcp-python, etc.).

Run from the project root:

    pip install -e ".[dev]"
    python -m spacy download en_core_web_lg
    python examples/mcp_middleware.py
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass, field
from typing import Any, Callable

from pii_guardian import (
    GuardianConfig,
    PIIAction,
    PIIGuardian,
    RedactionStrategy,
)

logging.basicConfig(level=logging.WARNING, format="%(levelname)s  %(name)s  %(message)s")
logger = logging.getLogger("mcp_middleware_example")


# ---------------------------------------------------------------------------
# Minimal MCP-like request/response types -----------------------------------
# ---------------------------------------------------------------------------


@dataclass
class MCPRequest:
    tool_name: str
    arguments: dict[str, Any]
    request_id: str = "req-001"


@dataclass
class MCPResponse:
    request_id: str
    result: dict[str, Any] | None = None
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


# Type alias for a tool handler function
ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]


# ---------------------------------------------------------------------------
# Middleware wrapper ---------------------------------------------------------
# ---------------------------------------------------------------------------


class PIIGuardianMiddleware:
    """Wraps a registry of MCP tool handlers with PIIGuardian protection.

    The middleware intercepts each request/response cycle:
    1. guard_input  — inspect and potentially redact/block tool arguments.
    2. dispatch     — call the real tool handler with the (clean) arguments.
    3. guard_output — inspect and potentially redact/block tool results.

    Parameters
    ----------
    guardian:
        A configured PIIGuardian instance.
    """

    def __init__(self, guardian: PIIGuardian) -> None:
        self._guardian = guardian
        self._handlers: dict[str, ToolHandler] = {}

    def register(self, tool_name: str, handler: ToolHandler) -> None:
        """Register a tool handler under ``tool_name``."""
        self._handlers[tool_name] = handler
        logger.debug("Registered tool handler for %r", tool_name)

    def handle(self, request: MCPRequest) -> MCPResponse:
        """Process an MCPRequest through the full guard → dispatch → guard cycle."""
        tool_name = request.tool_name
        handler = self._handlers.get(tool_name)

        if handler is None:
            return MCPResponse(
                request_id=request.request_id,
                error=f"Unknown tool: {tool_name!r}",
            )

        # -- 1. Guard input -----------------------------------------------
        input_result = self._guardian.guard_input(tool_name, request.arguments)

        if input_result.blocked:
            return MCPResponse(
                request_id=request.request_id,
                error=(
                    f"Request blocked: PII detected in input for tool {tool_name!r}. "
                    f"Entities: {input_result.entity_types_found}"
                ),
                metadata={"blocked": True, "entities": input_result.entity_types_found},
            )

        guarded_arguments = input_result.data

        # -- 2. Dispatch --------------------------------------------------
        try:
            raw_output = handler(guarded_arguments)
        except Exception as exc:  # noqa: BLE001
            return MCPResponse(
                request_id=request.request_id,
                error=f"Tool handler raised an exception: {exc}",
            )

        # -- 3. Guard output ----------------------------------------------
        output_result = self._guardian.guard_output(tool_name, raw_output)

        if output_result.blocked:
            return MCPResponse(
                request_id=request.request_id,
                error=(
                    f"Response blocked: PII detected in output for tool {tool_name!r}. "
                    f"Entities: {output_result.entity_types_found}"
                ),
                metadata={"blocked": True, "entities": output_result.entity_types_found},
            )

        meta: dict[str, Any] = {}
        if input_result.redacted:
            meta["input_redacted"] = True
            meta["input_entities"] = input_result.entity_types_found
        if output_result.redacted:
            meta["output_redacted"] = True
            meta["output_entities"] = output_result.entity_types_found
        if input_result.flagged or output_result.flagged:
            meta["flagged"] = True

        return MCPResponse(
            request_id=request.request_id,
            result=output_result.data,
            metadata=meta,
        )


# ---------------------------------------------------------------------------
# Example tool handlers (simulate real tools) -------------------------------
# ---------------------------------------------------------------------------


def handle_user_lookup(arguments: dict[str, Any]) -> dict[str, Any]:
    """Simulates a CRM lookup that echoes back user data."""
    user_id = arguments.get("user_id", "unknown")
    return {
        "user_id": user_id,
        "name": "Alice Wonderland",
        "email": "alice@wonderland.io",
        "phone": "415-867-5309",
        "account_status": "active",
    }


def handle_document_search(arguments: dict[str, Any]) -> dict[str, Any]:
    """Simulates a document search — output contains no PII."""
    query = arguments.get("query", "")
    return {
        "results": [
            {"id": "doc-001", "title": "Q3 Earnings Report", "snippet": "Revenue grew 12% YoY."},
            {"id": "doc-002", "title": "Board Minutes", "snippet": f"Discussion re: {query}"},
        ],
        "total": 2,
    }


def handle_send_message(arguments: dict[str, Any]) -> dict[str, Any]:
    """Simulates sending a message — returns a delivery receipt."""
    return {"status": "delivered", "message_id": "msg-abc123"}


# ---------------------------------------------------------------------------
# Demo runner ---------------------------------------------------------------
# ---------------------------------------------------------------------------


def _print_response(label: str, response: MCPResponse) -> None:
    print(f"\n{label}")
    if response.error:
        print(f"  ERROR:    {response.error}")
    else:
        print(f"  Result:   {json.dumps(response.result, indent=10)}")
    if response.metadata:
        print(f"  Metadata: {response.metadata}")


def main() -> int:
    print("mcp-server-pii-guardian — MCP Middleware Demo")
    print("=" * 60)

    # Build a guardian: redact by default, block SSN/CC, allow public tools
    config = GuardianConfig(
        entities=["EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD", "PERSON"],
        threshold=0.7,
        redaction_strategy=RedactionStrategy.REPLACE,
        default_action=PIIAction.REDACT,
        tool_actions={
            "document_search": PIIAction.FLAG,  # Search queries: flag but don't redact
        },
        blocked_entities=["US_SSN", "CREDIT_CARD"],
    )

    try:
        guardian = PIIGuardian(config)
    except ImportError as exc:
        print(f"\nImportError: {exc}", file=sys.stderr)
        return 1

    # Build the middleware and register tool handlers
    middleware = PIIGuardianMiddleware(guardian)
    middleware.register("user_lookup", handle_user_lookup)
    middleware.register("document_search", handle_document_search)
    middleware.register("send_message", handle_send_message)

    # ---- Scenario 1: Input with no PII → result contains PII (redacted) -
    req1 = MCPRequest(
        tool_name="user_lookup",
        arguments={"user_id": "usr-42"},
        request_id="req-001",
    )
    _print_response("Scenario 1 — user_lookup (output contains PII)", middleware.handle(req1))

    # ---- Scenario 2: Input contains PII → redacted before dispatch -------
    req2 = MCPRequest(
        tool_name="send_message",
        arguments={
            "to": "bob@company.com",
            "body": "Hi, this is Bob Smith calling about the renewal.",
        },
        request_id="req-002",
    )
    _print_response("Scenario 2 — send_message (input PII redacted)", middleware.handle(req2))

    # ---- Scenario 3: SSN in input → BLOCK --------------------------------
    req3 = MCPRequest(
        tool_name="send_message",
        arguments={
            "to": "billing@corp.com",
            "body": "SSN: 123-45-6789 please process.",
        },
        request_id="req-003",
    )
    _print_response("Scenario 3 — blocked (SSN in input)", middleware.handle(req3))

    # ---- Scenario 4: Search query with email → FLAG only -----------------
    req4 = MCPRequest(
        tool_name="document_search",
        arguments={"query": "contracts for alice@contoso.com"},
        request_id="req-004",
    )
    _print_response("Scenario 4 — document_search (FLAG action)", middleware.handle(req4))

    # ---- Scenario 5: Clean request through a flagging tool ---------------
    req5 = MCPRequest(
        tool_name="document_search",
        arguments={"query": "Q4 budget planning"},
        request_id="req-005",
    )
    _print_response("Scenario 5 — document_search (no PII, clean)", middleware.handle(req5))

    # ---- Audit stats -------------------------------------------------------
    print("\n\nAudit Log Statistics")
    print("-" * 40)
    stats = guardian.audit_stats()
    print(f"Total events:  {stats['total_events']}")
    print(f"By action:     {stats['by_action']}")
    print(f"By entity:     {stats['by_entity_type']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

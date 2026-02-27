# mcp-server-pii-guardian

[![Governance Score](https://img.shields.io/badge/governance-self--assessed-blue)](https://github.com/aumos-ai/mcp-server-pii-guardian)

PII detection and redaction middleware for MCP servers.

Wraps [Microsoft Presidio](https://microsoft.github.io/presidio/) to give
any MCP tool server a clean, typed, zero-dependency guard layer that
detects, redacts, flags, or blocks personally identifiable information
before it leaks out of — or into — your tool calls.

---

## Features

- Four redaction strategies: **MASK**, **HASH**, **REMOVE**, **REPLACE**
- Seven default entity types (email, phone, SSN, credit card, person, location, IP)
- Per-tool action overrides (`BLOCK`, `REDACT`, `FLAG`, `ALLOW`)
- Hard-block list for high-risk entity types (`US_SSN`, `CREDIT_CARD` by default)
- Thread-safe in-memory audit log with JSONL export
- Three built-in config presets: `default()`, `strict()`, `permissive()`
- `py.typed` — full type hint coverage, mypy strict compatible
- Extensible: plug in custom Presidio `PatternRecognizer` instances
- Zero AumOS dependencies — works with any MCP server framework

---

## Installation

```bash
pip install mcp-pii-guardian
python -m spacy download en_core_web_lg
```

---

## Quickstart

```python
from pii_guardian import PIIGuardian

guardian = PIIGuardian()

# Guard incoming tool arguments
result = guardian.guard_input(
    tool_name="send_email",
    input_data={
        "to": "alice@example.com",
        "body": "Your SSN 123-45-6789 has been verified.",
    },
)

if result.blocked:
    raise ValueError("Request contains blocked PII")

# Use result.data — PII has been redacted
print(result.data)
# {"to": "a***e@e******.com", "body": "Your SSN [REDACTED] has been verified."}
#  ^^ email masked (MASK strategy)         ^^ SSN BLOCKED → request rejected above
```

---

## Configuration presets

```python
from pii_guardian import GuardianConfig, PIIGuardian

# Default: MASK + REDACT, SSN and credit card always blocked
guardian = PIIGuardian(GuardianConfig.default())

# Strict: everything BLOCKED at 0.5 confidence threshold
guardian = PIIGuardian(GuardianConfig.strict())

# Permissive: FLAG only, never modify payloads (baselining / observation)
guardian = PIIGuardian(GuardianConfig.permissive())
```

---

## Custom configuration

```python
from pii_guardian import GuardianConfig, PIIAction, PIIGuardian, RedactionStrategy

config = GuardianConfig(
    entities=["EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "US_SSN"],
    threshold=0.75,
    redaction_strategy=RedactionStrategy.REPLACE,   # → [EMAIL_ADDRESS]
    default_action=PIIAction.REDACT,
    tool_actions={
        "internal_audit_tool": PIIAction.ALLOW,     # fully trusted tool
        "public_webhook":      PIIAction.BLOCK,     # zero tolerance
    },
    blocked_entities=["US_SSN"],
)
guardian = PIIGuardian(config, raise_on_block=False)
```

---

## MCP middleware pattern

```python
from pii_guardian import PIIGuardian, GuardianConfig

guardian = PIIGuardian(GuardianConfig.default())

def call_tool(tool_name: str, arguments: dict) -> dict:
    # 1. Guard input
    input_result = guardian.guard_input(tool_name, arguments)
    if input_result.blocked:
        return {"error": "Blocked: PII detected in arguments"}

    # 2. Execute tool with (possibly redacted) arguments
    raw_output = execute_tool(tool_name, input_result.data)

    # 3. Guard output
    output_result = guardian.guard_output(tool_name, raw_output)
    if output_result.blocked:
        return {"error": "Blocked: PII detected in tool result"}

    return output_result.data
```

See `examples/mcp_middleware.py` for a complete framework-agnostic example.

---

## Redaction strategies

| Strategy  | Example output              | Use case                              |
|-----------|-----------------------------|---------------------------------------|
| `MASK`    | `a***e@e****e.com`          | Logs — preserve shape, hide value     |
| `HASH`    | `[HASH:3d7e2b1a9f805c24]`   | Pseudonymisation with reversibility   |
| `REMOVE`  | `[REDACTED]`                | Maximum anonymisation                 |
| `REPLACE` | `[EMAIL_ADDRESS]`           | NLP pipelines that need entity labels |

---

## Audit log

```python
# Statistics
stats = guardian.audit_stats()
# {"total_events": 42, "by_action": {"redact": 38, "block": 4}, ...}

# Export as JSONL for SIEM ingestion
jsonl = guardian.export_audit_jsonl()

# Query specific entries
entries = guardian.audit_log.query(
    tool_name="send_email",
    entity_type="EMAIL_ADDRESS",
)
```

---

## Custom entity types

```python
from presidio_analyzer import Pattern, PatternRecognizer
from pii_guardian import GuardianConfig, PIIDetector, PIIGuardian

# Register a custom recogniser (e.g. internal employee ID format)
detector = PIIDetector(entities=["EMAIL_ADDRESS", "EMPLOYEE_ID"])
detector._engine.registry.add_recognizer(
    PatternRecognizer(
        supported_entity="EMPLOYEE_ID",
        patterns=[Pattern("emp", r"\bEMP-\d{6}\b", score=0.95)],
    )
)

guardian = PIIGuardian(GuardianConfig(entities=["EMAIL_ADDRESS", "EMPLOYEE_ID"]))
guardian._detector = detector
```

See `examples/custom_entities.py` for a complete example.

---

## Documentation

- [Quickstart](docs/quickstart.md)
- [Entity types reference](docs/entity-types.md)
- [Redaction strategies](docs/redaction-strategies.md)

---

## Project boundaries (FIRE LINE)

This project is intentionally narrow in scope.  It will never include:

- AumOS or AMGP dependencies
- Consent-based redaction decisions (that is PWM territory)
- Role-based access control
- Persistent audit storage
- Cloud-provider SDK dependencies at runtime

See [FIRE_LINE.md](FIRE_LINE.md) for the full boundary definition.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

Copyright (c) 2026 MuVeraAI Corporation.

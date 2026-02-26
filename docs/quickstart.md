# Quickstart — mcp-server-pii-guardian

Get PII protection on your MCP server in under 10 minutes.

---

## Prerequisites

- Python 3.10 or later
- pip

---

## Installation

```bash
pip install mcp-pii-guardian
```

Presidio requires a spaCy NLP model.  Download it once after installing:

```bash
python -m spacy download en_core_web_lg
```

---

## Minimal example

```python
from pii_guardian import PIIGuardian

guardian = PIIGuardian()

result = guardian.guard_input(
    tool_name="send_email",
    input_data={
        "to": "alice@example.com",
        "body": "Your SSN 123-45-6789 has been verified.",
    },
)

if result.blocked:
    print("Request blocked — contains high-risk PII")
else:
    print(result.data)
    # {"to": "a***@e******.com", "body": "Your SSN [REDACTED] has been verified."}
    # (SSN is blocked by default config; email is masked)
```

The default `GuardianConfig` uses:
- `RedactionStrategy.MASK` — asterisk-masking that preserves structure.
- `PIIAction.REDACT` as the default action for all tools.
- `blocked_entities = ["US_SSN", "CREDIT_CARD"]` — these always BLOCK.

---

## Guarding tool outputs

```python
result = guardian.guard_output(
    tool_name="user_lookup",
    output_data={"name": "Bob Smith", "email": "bob@corp.com", "role": "admin"},
)
print(result.data)
# {"name": "B*b S***h", "email": "b*b@c***.com", "role": "admin"}
```

---

## Choosing a configuration preset

```python
from pii_guardian import GuardianConfig, PIIGuardian

# Default — MASK + REDACT, SSN/CC blocked
guardian = PIIGuardian(GuardianConfig.default())

# Strict — everything BLOCKED at threshold 0.5
guardian = PIIGuardian(GuardianConfig.strict())

# Permissive — FLAG only, never modify payloads (baselining mode)
guardian = PIIGuardian(GuardianConfig.permissive())
```

---

## Custom configuration

```python
from pii_guardian import GuardianConfig, PIIAction, PIIGuardian, RedactionStrategy

config = GuardianConfig(
    entities=["EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON"],
    threshold=0.75,
    redaction_strategy=RedactionStrategy.REPLACE,
    default_action=PIIAction.REDACT,
    tool_actions={
        "internal_audit": PIIAction.ALLOW,    # trust this tool completely
        "public_webhook": PIIAction.BLOCK,    # zero tolerance on this tool
    },
    blocked_entities=["US_SSN"],
)
guardian = PIIGuardian(config)
```

---

## Inspecting detections

```python
result = guardian.guard_input("my_tool", {"text": "Call Jane at 555-123-4567"})

for detection in result.detections:
    print(detection.entity_type, detection.text, detection.score)
# PHONE_NUMBER  555-123-4567  0.75

print(result.entity_types_found)  # ['PHONE_NUMBER']
```

---

## Audit log

```python
stats = guardian.audit_stats()
print(stats)
# {
#   "total_events": 42,
#   "by_action": {"redact": 38, "block": 3, "allow": 1},
#   "by_entity_type": {"EMAIL_ADDRESS": 20, "PHONE_NUMBER": 15, "US_SSN": 3},
#   "by_direction": {"input": 30, "output": 12}
# }

# Export as JSONL for shipping to a SIEM
jsonl = guardian.export_audit_jsonl()
```

---

## Raising on block

If you prefer exceptions over checking `result.blocked`:

```python
from pii_guardian import PIIBlockedError, PIIGuardian

guardian = PIIGuardian(raise_on_block=True)

try:
    result = guardian.guard_input("my_tool", {"ssn": "123-45-6789"})
except PIIBlockedError as exc:
    print(exc.tool_name, exc.detections)
```

---

## Next steps

- [Entity types reference](entity-types.md) — full list of supported Presidio entities.
- [Redaction strategies](redaction-strategies.md) — MASK, HASH, REMOVE, REPLACE in depth.
- `examples/mcp_middleware.py` — full middleware wrapper for an MCP server.
- `examples/custom_entities.py` — adding domain-specific recognisers.

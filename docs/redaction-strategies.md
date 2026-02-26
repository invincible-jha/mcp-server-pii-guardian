# Redaction Strategies

`PIIRedactor` supports four strategies for rewriting detected PII spans.
Choose the one that fits your privacy requirements and downstream system needs.

---

## MASK

**Value:** `RedactionStrategy.MASK`

Preserves the first and last character of each word token and replaces
interior characters with asterisks.  For email addresses the local part and
the domain label are masked separately to preserve the recognisable structure.

```python
from pii_guardian import PIIGuardian, GuardianConfig, RedactionStrategy

guardian = PIIGuardian(GuardianConfig(
    entities=["EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON"],
    redaction_strategy=RedactionStrategy.MASK,
))

result = guardian.guard_input("tool", {
    "email": "alice@example.com",
    "phone": "555-867-5309",
    "name": "John Smith",
})
print(result.data)
# {
#   "email": "a***e@e****e.com",
#   "phone": "5*******9",
#   "name": "J**n S***h"
# }
```

**Best for:** Logging and debugging where you need to see the approximate
shape of a value but must not expose the literal PII.

**Caution:** The masking is deterministic but not reversible.  Two different
values that share the same first/last characters will produce the same mask.

---

## HASH

**Value:** `RedactionStrategy.HASH`

Replaces each detected span with a bracketed 16-character hex prefix of its
SHA-256 digest.

Format: `[HASH:abcdef0123456789]`

```python
guardian = PIIGuardian(GuardianConfig(
    entities=["EMAIL_ADDRESS"],
    redaction_strategy=RedactionStrategy.HASH,
))

result = guardian.guard_input("tool", {"email": "alice@example.com"})
print(result.data)
# {"email": "[HASH:3d7e2b1a9f805c24]"}
```

**Best for:** Pseudonymisation — you can maintain a lookup table of
`original → hash` to re-identify when legally required, while the downstream
system sees only opaque identifiers.  Multiple occurrences of the same value
produce the same hash, enabling consistent pseudonymisation within a session.

**Note:** 16 hex characters (64 bits) is collision-resistant for
pseudonymisation purposes.  If you need the full 256-bit digest, modify
`_hash_value` in `redactor.py`.

---

## REMOVE

**Value:** `RedactionStrategy.REMOVE`

Replaces each detected span with the literal string `[REDACTED]`.

```python
guardian = PIIGuardian(GuardianConfig(
    entities=["EMAIL_ADDRESS", "PHONE_NUMBER"],
    redaction_strategy=RedactionStrategy.REMOVE,
))

result = guardian.guard_input("tool", {
    "message": "Contact alice@example.com or call 555-123-4567."
})
print(result.data["message"])
# "Contact [REDACTED] or call [REDACTED]."
```

**Best for:** Maximum anonymisation where no structural information about
the original value should be preserved.  Output is human-readable.

---

## REPLACE

**Value:** `RedactionStrategy.REPLACE`

Replaces each detected span with the entity-type label enclosed in brackets.

```python
guardian = PIIGuardian(GuardianConfig(
    entities=["EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON"],
    redaction_strategy=RedactionStrategy.REPLACE,
))

result = guardian.guard_input("tool", {
    "text": "Call John Smith at 555-123-4567 or email john@acme.com"
})
print(result.data["text"])
# "Call [PERSON] at [PHONE_NUMBER] or email [EMAIL_ADDRESS]"
```

**Best for:** Structured analysis — downstream NLP pipelines, LLM prompts,
or log analytics that benefit from knowing _what kind_ of PII was present
without seeing the value itself.

---

## Comparison table

| Strategy | Example output              | Reversible | Structure visible | Entity type visible |
|----------|-----------------------------|------------|-------------------|---------------------|
| MASK     | `a***e@e****e.com`          | No         | Yes               | No                  |
| HASH     | `[HASH:3d7e2b1a9f805c24]`   | With key   | No                | No                  |
| REMOVE   | `[REDACTED]`                | No         | No                | No                  |
| REPLACE  | `[EMAIL_ADDRESS]`           | No         | No                | Yes                 |

---

## Choosing at runtime

You can switch strategies by constructing a new `GuardianConfig`:

```python
from pii_guardian import GuardianConfig, PIIGuardian, RedactionStrategy

for strategy in [
    RedactionStrategy.MASK,
    RedactionStrategy.HASH,
    RedactionStrategy.REMOVE,
    RedactionStrategy.REPLACE,
]:
    config = GuardianConfig(
        entities=["EMAIL_ADDRESS"],
        redaction_strategy=strategy,
    )
    guardian = PIIGuardian(config)
    result = guardian.guard_input("demo", {"email": "bob@company.com"})
    print(f"{strategy.value:8}  →  {result.data['email']}")
```

---

## Custom strategies

The `RedactionStrategy` enum and `PIIRedactor._replacement_for` method are
designed for extension.  To add a new strategy:

1. Add a new value to `RedactionStrategy` in `src/pii_guardian/types.py`.
2. Add a matching `case` branch in `PIIRedactor._replacement_for` in
   `src/pii_guardian/redactor.py`.
3. Update this document and `CHANGELOG.md`.

```python
# types.py
class RedactionStrategy(Enum):
    MASK = "mask"
    HASH = "hash"
    REMOVE = "remove"
    REPLACE = "replace"
    TOKENIZE = "tokenize"   # your new strategy

# redactor.py — inside _replacement_for
case RedactionStrategy.TOKENIZE:
    return _tokenize(detection.text)   # your implementation
```

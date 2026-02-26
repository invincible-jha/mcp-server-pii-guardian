# Entity Types Reference

`mcp-server-pii-guardian` exposes the full entity catalogue of
[Microsoft Presidio](https://microsoft.github.io/presidio/supported_entities/).
This page documents the defaults, the full catalogue, and how to add your own.

---

## Default entities

These seven entity types are scanned when you use `GuardianConfig.default()`
or construct a `PIIDetector` with no explicit entity list.

| Entity type      | Example match              | Notes                                              |
|------------------|----------------------------|----------------------------------------------------|
| `EMAIL_ADDRESS`  | `alice@example.com`        | RFC-5321 compliant pattern + context recogniser.   |
| `PHONE_NUMBER`   | `555-867-5309`             | US and international formats.                      |
| `US_SSN`         | `123-45-6789`              | **Blocked by default** in `GuardianConfig.default()`. |
| `CREDIT_CARD`    | `4111 1111 1111 1111`      | Luhn-validated. **Blocked by default**.            |
| `PERSON`         | `John Smith`               | NLP-based (spaCy NER). Lower precision than patterns. |
| `LOCATION`       | `New York`, `10 Downing St`| NLP-based. May have false positives on common words. |
| `IP_ADDRESS`     | `192.168.1.1`              | IPv4 and IPv6.                                     |

---

## Full Presidio entity catalogue

Pass any of these strings in `GuardianConfig.entities` or `PIIDetector(entities=[...])`.

### Personal identifiers
| Entity type               | Description                              |
|---------------------------|------------------------------------------|
| `PERSON`                  | Full names (NLP)                         |
| `EMAIL_ADDRESS`           | Email addresses                          |
| `PHONE_NUMBER`            | Phone numbers (US + international)       |
| `US_SSN`                  | US Social Security Numbers               |
| `US_DRIVER_LICENSE`       | US driver's licence numbers              |
| `US_PASSPORT`             | US passport numbers                      |
| `US_ITIN`                 | US Individual Taxpayer ID Numbers        |
| `UK_NHS`                  | UK National Health Service numbers       |
| `UK_NINO`                 | UK National Insurance numbers            |
| `AU_ABN`                  | Australian Business Numbers              |
| `AU_ACN`                  | Australian Company Numbers               |
| `AU_TFN`                  | Australian Tax File Numbers              |
| `AU_MEDICARE`             | Australian Medicare numbers              |
| `SG_NRIC_FIN`             | Singapore NRIC / FIN numbers             |
| `IN_PAN`                  | Indian Permanent Account Numbers         |
| `IN_AADHAAR`              | Indian Aadhaar numbers                   |
| `IN_VEHICLE_REGISTRATION` | Indian vehicle registration numbers      |
| `IN_VOTER`                | Indian voter ID numbers                  |
| `IN_PASSPORT`             | Indian passport numbers                  |

### Financial identifiers
| Entity type        | Description                                          |
|--------------------|------------------------------------------------------|
| `CREDIT_CARD`      | Credit and debit card numbers (Luhn-validated)       |
| `IBAN_CODE`        | International Bank Account Numbers                   |
| `US_BANK_NUMBER`   | US bank account numbers                              |

### Network / technical
| Entity type        | Description                              |
|--------------------|------------------------------------------|
| `IP_ADDRESS`       | IPv4 and IPv6 addresses                  |
| `URL`              | Web URLs                                 |
| `DOMAIN_NAME`      | Domain name patterns                     |

### Location
| Entity type        | Description                              |
|--------------------|------------------------------------------|
| `LOCATION`         | Cities, countries, addresses (NLP)       |
| `US_BANK_NUMBER`   | —                                        |

### Medical / biometric
| Entity type            | Description                          |
|------------------------|--------------------------------------|
| `MEDICAL_LICENSE`      | US medical licence numbers           |

### Cryptographic / secrets
These are **not** in the Presidio built-in catalogue.  Use a custom
`PatternRecognizer` (see `examples/custom_entities.py`) for:
- API keys (`sk-live-...`)
- JWT tokens
- AWS access key IDs (`AKIA...`)
- Private key PEM blocks

---

## NLP-based vs. pattern-based entities

Presidio uses two detection mechanisms:

**Pattern-based** (`PatternRecognizer`) — uses regex + optional checksum
validation.  High precision, minimal false positives.  Examples:
`EMAIL_ADDRESS`, `CREDIT_CARD`, `US_SSN`, `IP_ADDRESS`.

**NLP-based** (`SpacyRecognizer`) — uses spaCy Named Entity Recognition.
Broader coverage but lower precision.  Examples: `PERSON`, `LOCATION`.

For high-precision environments, consider omitting `PERSON` and `LOCATION`
from your entity list and using pattern-based recognisers for your specific
name/location formats.

---

## High-risk entities

`GuardianConfig.default()` places these entity types in `blocked_entities`,
meaning any detection always triggers `PIIAction.BLOCK` regardless of the
per-tool action:

```python
HIGH_RISK_ENTITIES = ["US_SSN", "CREDIT_CARD"]
```

Override by constructing `GuardianConfig` directly:

```python
config = GuardianConfig(
    entities=["EMAIL_ADDRESS", "US_SSN"],
    blocked_entities=[],          # No automatic blocks
    default_action=PIIAction.REDACT,
)
```

---

## Adding custom entity types

```python
from presidio_analyzer import Pattern, PatternRecognizer
from pii_guardian import GuardianConfig, PIIDetector, PIIGuardian

# 1. Build a recogniser
employee_recogniser = PatternRecognizer(
    supported_entity="EMPLOYEE_ID",
    patterns=[Pattern("emp_id", r"\bEMP-\d{6}\b", score=0.95)],
)

# 2. Build a detector with your custom entity included
detector = PIIDetector(entities=["EMAIL_ADDRESS", "EMPLOYEE_ID"])
detector._engine.registry.add_recognizer(employee_recogniser)

# 3. Build a guardian and swap in the custom detector
guardian = PIIGuardian(GuardianConfig(entities=["EMAIL_ADDRESS", "EMPLOYEE_ID"]))
guardian._detector = detector

result = guardian.guard_input("hr_tool", {"id": "EMP-004821"})
print(result.detections[0].entity_type)  # EMPLOYEE_ID
```

See `examples/custom_entities.py` for a full working example.

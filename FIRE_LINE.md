# Fire Line — mcp-server-pii-guardian

> The fire line defines what this project IS and IS NOT.
> Crossing it means the PR is rejected, no exceptions.

---

## This project IS

- A standalone PII detection and redaction middleware for MCP servers.
- A clean, typed wrapper around Microsoft Presidio.
- A drop-in guard layer compatible with ANY MCP server framework.
- Apache 2.0 licensed and free of proprietary dependencies.

---

## This project IS NOT

- An AumOS component. Zero imports from `aumos`, `amgp`, or any
  MuVeraAI internal package.
- A consent management layer. Consent and privacy preference logic
  belongs in PWM (Privacy Wallet Manager) — a separate project.
- A context-aware redactor. Decisions based on user context, roles,
  or session state are out of scope.
- An AMGP protocol implementation. No message-bus or event-stream
  integration here.
- A replacement for your compliance programme. This library aids
  technical PII hygiene but does not constitute legal advice.

---

## Dependency constraints

| Allowed                        | Forbidden                          |
|--------------------------------|------------------------------------|
| `presidio-analyzer`            | `aumos-*`                          |
| `presidio-anonymizer`          | `amgp`                             |
| Python standard library        | `pydantic` (use dataclasses)       |
| `spacy` (NLP model, optional)  | Any AumOS SDK package              |
| Dev: `pytest`, `ruff`, `mypy`  | Any cloud-provider SDK at runtime  |

---

## Scope boundaries

| Feature                            | In scope | Out of scope |
|------------------------------------|----------|--------------|
| Detect PII in dict/text payloads   | Yes      |              |
| Redact using MASK/HASH/REMOVE/REPLACE | Yes   |              |
| Per-tool action configuration      | Yes      |              |
| In-memory audit log                | Yes      |              |
| Custom Presidio recognisers        | Yes      |              |
| Consent-based redaction decisions  |          | No (PWM)     |
| Role-based access control          |          | No           |
| Persistent audit storage           |          | No           |
| AMGP message bus integration       |          | No           |
| AumOS trust scoring                |          | No           |

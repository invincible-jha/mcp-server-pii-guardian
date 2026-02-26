# CLAUDE.md — mcp-server-pii-guardian

Project-level instructions for Claude Code working in this repository.

---

## Project identity

Standalone PII detection and redaction middleware for MCP servers.
Wraps Microsoft Presidio.  Apache 2.0.  No AumOS dependencies.

**Location:** `M:/Project Quasar/aumos-oss/mcp-server-pii-guardian/`

---

## Hard constraints (FIRE LINE)

1. **Zero AumOS imports.** Never import `aumos`, `amgp`, or any MuVeraAI
   internal package.  This is a fully standalone OSS library.
2. **No Pydantic.** Use dataclasses + manual `__post_init__` validation.
3. **No test files** — tests live outside this project.
4. **Apache 2.0 license header** in every `.py` file:
   ```python
   # SPDX-License-Identifier: Apache-2.0
   # Copyright (c) 2026 MuVeraAI Corporation
   ```

---

## Code conventions

- Python 3.10+ — use `match`/`case`, `X | Y` unions, `from __future__ import annotations`.
- Type hints required on all function signatures.
- Docstrings on all public classes and methods (Google or NumPy style).
- `ruff` for linting and formatting (line length 100).
- `mypy --strict` must pass with zero errors.
- Conventional commits: `feat:`, `fix:`, `refactor:`, `docs:`, `chore:`.

---

## Architecture map

```
src/pii_guardian/
  types.py        — frozen dataclasses + enums (no imports from this package)
  config.py       — GuardianConfig (imports types.py only)
  detector.py     — PIIDetector wrapping presidio_analyzer
  redactor.py     — PIIRedactor (mask/hash/remove/replace)
  audit.py        — PIIAuditLog (thread-safe ring buffer)
  guardian.py     — PIIGuardian (orchestrates detector + redactor + audit)
  __init__.py     — public API surface
```

Dependency direction: `guardian → detector, redactor, audit, config, types`.
No circular imports.  `types.py` has no intra-package imports.

---

## Key design decisions

- **Dataclasses over Pydantic** — keeps the package lightweight and avoids
  a Pydantic version conflict in user environments.
- **Lazy Presidio import** — `_load_analyzer()` in `detector.py` defers the
  import so the rest of the library can be imported in minimal environments.
- **Frozen dataclasses** for `PIIDetection`, `GuardResult`, `PIIAuditEntry`
  — immutability makes results safe to cache and share across threads.
- **Right-to-left redaction** in `PIIRedactor.redact_text` — preserves
  earlier span indices when multiple spans are replaced in a single pass.
- **Overlap deduplication** in `PIIDetector._deduplicate` — Presidio can
  return overlapping results from multiple recognisers; we keep the
  highest-confidence non-overlapping set.

---

## Common tasks

### Add a new redaction strategy
1. Add the enum value to `RedactionStrategy` in `types.py`.
2. Add a `case` branch in `PIIRedactor._replacement_for` in `redactor.py`.
3. Update `docs/redaction-strategies.md`.
4. Update `CHANGELOG.md`.

### Add a new default entity type
1. Append to `DEFAULT_ENTITIES` in `config.py`.
2. Update `docs/entity-types.md`.

### Add a custom Presidio recogniser
See `examples/custom_entities.py` — access `guardian._detector._engine.registry`
and call `registry.add_recognizer(...)`.

---

## Do not

- Add a `conftest.py` or any test file — tests are not part of this project.
- Import from `aumos`, `amgp`, or any other AumOS package.
- Add Pydantic as a dependency.
- Store raw PII text in the audit log.
- Hard-code model names or cloud endpoints.

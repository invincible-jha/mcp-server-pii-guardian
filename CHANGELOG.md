# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [0.1.0] — 2026-02-26

### Added
- `PIIGuardian` — main middleware class with `guard_input` / `guard_output` / `guard` methods.
- `PIIDetector` — thin wrapper around Presidio `AnalyzerEngine` with overlap-deduplication and nested-dict scanning.
- `PIIRedactor` — four redaction strategies: MASK, HASH, REMOVE, REPLACE.
- `GuardianConfig` — dataclass configuration with `default()`, `strict()`, `permissive()`, and `from_dict()` factory helpers.
- `PIIAuditLog` — thread-safe in-memory ring buffer with query, stats, and JSONL export.
- `PIIBlockedError` — raised when `raise_on_block=True` and a BLOCK action is triggered.
- Per-tool action overrides via `GuardianConfig.tool_actions`.
- `blocked_entities` list — entity types that always trigger BLOCK regardless of tool action.
- `py.typed` marker for PEP 561 type-checking support.
- Apache 2.0 license.
- Examples: `basic_guardian.py`, `mcp_middleware.py`, `custom_entities.py`.
- Docs: quickstart, entity-types reference, redaction-strategies reference.

# Contributing to mcp-server-pii-guardian

Thank you for considering a contribution. This project follows the
[MuVeraAI open-source contribution guidelines](https://github.com/muveraai).

---

## Ground rules

- **Zero AumOS dependencies.** This package must remain completely standalone.
  Any PR that introduces an import of `aumos`, `amgp`, or any other AumOS
  package will be rejected.
- **No Pydantic.** Runtime validation must use dataclasses and manual
  `__post_init__` checks only.
- **Python 3.10+.** Use `match`/`case`, `X | Y` union types, and
  `from __future__ import annotations` in every file.
- **Type hints required** on every function signature (enforced by mypy strict).
- **Apache 2.0 license header** in every `.py` file.

---

## Development setup

```bash
git clone https://github.com/muveraai/mcp-server-pii-guardian
cd mcp-server-pii-guardian

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -e ".[dev]"
python -m spacy download en_core_web_lg
```

---

## Linting and type checking

```bash
# Lint and auto-fix
ruff check src/ examples/ --fix
ruff format src/ examples/

# Static type checking
mypy src/pii_guardian
```

---

## Running tests

```bash
pytest
pytest --cov=pii_guardian --cov-report=term-missing
```

Aim for 90%+ coverage.  Integration tests that require a spaCy model should
be marked with `@pytest.mark.integration`.

---

## Commit style

Follow conventional commits:

```
feat: add LOCATION entity to default config
fix: handle empty string input in PIIDetector.detect
refactor: extract _deduplicate into a static method
docs: add custom recogniser example
test: cover PIIAuditLog.export_jsonl edge case
chore: bump presidio-analyzer to 2.2.354
```

---

## Pull request checklist

- [ ] All new `.py` files have the Apache 2.0 license header.
- [ ] All public functions have type hints and docstrings.
- [ ] `ruff check` passes with zero warnings.
- [ ] `mypy src/pii_guardian` passes with zero errors.
- [ ] New behaviour is covered by tests.
- [ ] `CHANGELOG.md` `[Unreleased]` section is updated.
- [ ] No AumOS package imports anywhere.

---

## Reporting issues

Open a GitHub issue with:
1. Python version and OS.
2. `presidio-analyzer` version (`pip show presidio-analyzer`).
3. A minimal reproducible example.
4. The full traceback.

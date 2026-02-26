# Contributing to aumos-govdef-overlay

## Development Setup

```bash
git clone <repo>
cd aumos-govdef-overlay
pip install -e ".[dev]"
cp .env.example .env
```

## Standards

- Type hints on all function signatures
- Google-style docstrings on public classes and functions
- `ruff` for linting and formatting (120 char line length)
- `mypy` strict mode
- Conventional commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`

## Testing

```bash
make test        # full suite with coverage
make test-quick  # fast run, stop on first failure
```

Minimum coverage: 80% for core modules, 60% for adapters.

## Compliance Domain Knowledge

Changes to compliance thresholds (NIST control counts, CMMC practice counts, IL level
requirements) must be backed by official NIST/DoD/FedRAMP publications. Include
the publication reference in the commit message.

## Security

- Never log CUI or classified data values
- Encryption key ARNs should be stored as references, never as values
- All new endpoints require authentication via `get_current_user`

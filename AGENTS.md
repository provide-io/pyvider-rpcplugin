# Repository Guidelines

## Project Structure & Module Organization
- `src/pyvider/rpcplugin/` holds the runtime, handshake helpers, and transport adapters; keep new packages under this namespace to preserve the PyPI import path.
- `tests/` mirrors the package layout; place reusable fixtures in `tests/conftest.py` and longer flows under `tests/integration/`.
- `docs/` contains the mkdocs-driven guide, including the contribution chapter linked from the README.
- `examples/` hosts runnable plugins and clients that should track public API changes.

## Build, Test, and Development Commands
- `uv sync --group dev` installs the toolchain pinned in `uv.lock`.
- `uv run pytest -n auto` runs the full suite with xdist; append `-m "not slow"` for fast feedback.
- `uv run pytest --cov=pyvider.rpcplugin --cov-report=term-missing` verifies coverage before publishing.
- `uv run ruff check src tests` enforces lint rules; pair with `uv run ruff format src tests` to auto-format.
- `uv run pyre check` (or `uv run mypy src`) keeps type hints sound; run `uv run bandit -r src` after security-sensitive edits.

## Coding Style & Naming Conventions
Use 4-space indents, target Python 3.11 features, and respect the 111-character line limit enforced by Ruff. Keep modules and files in snake_case, classes in PascalCase, and constants in UPPER_SNAKE. Prefer attrs/dataclasses for structured data, add return type hints on public APIs, and document handshake semantics with concise docstrings.

## Testing Guidelines
Pytest drives all tests; name files `test_*.py` and align fixtures with the package they exercise. Mark long jobs with `@pytest.mark.slow` or `@pytest.mark.long_running` so CI can filter them. Prioritize async unit coverage, and add regression demos under `examples/` when debugging transport edge cases. Aim to keep branch coverage high; open HTML reports (`uv run coverage html`) when diagnosing gaps.

## Commit & Pull Request Guidelines
Automation uses the `🔼⚙️ [skip ci] auto-commit` prefix for dependency bumps; write human commits as a single present-tense sentence and include `[skip ci]` only when skipping pipelines is intentional. Reference issue IDs in the body, summarize validation steps, and update docs or changelog entries when behavior shifts. PRs should outline the change intent and list verification commands or relevant gRPC traces.

## Security & Configuration Tips
Sample certificates in `keys/` are for local demos only—never ship them. Load secrets via environment variables or OS key stores, and scrub them from logs by default. When adding transports or auth flows, ensure both client and server negotiation paths enforce the magic cookie and protocol version checks.

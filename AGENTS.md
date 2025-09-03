# Repository Guidelines

## Project Structure & Module Organization
- src/: application/library code (create per language needs).
- tests/: unit/integration tests mirroring src/ layout.
- scripts/: developer utilities (lint, test, build, dev).
- docs/: design notes, ADRs, and API references.
- assets/ or examples/: static files and runnable examples.

Example: `mkdir -p src tests scripts` and keep modules small and cohesive.

## Build, Test, and Development Commands
- `./scripts/dev.sh`: start a local dev workflow (watch, reload, or sandbox).
- `./scripts/test.sh`: run the full test suite with coverage.
- `./scripts/lint.sh`: run linters and auto-formatters.
- `make <target>`: optional; if a Makefile exists, mirror the above targets.

Ensure scripts are executable (`chmod +x scripts/*.sh`) and CI calls them.

## Coding Style & Naming Conventions
- Indentation: 2 or 4 spaces (match language defaults consistently).
- Line length: aim for ≤ 100 chars; wrap thoughtfully.
- Naming: snake_case for files/dirs; PascalCase for types/classes; lowerCamelCase for vars.
- Formatting: use a language-appropriate formatter (e.g., Prettier, Black, gofmt). Run `./scripts/lint.sh` before pushing.

## Testing Guidelines
- Co-locate tests under `tests/` mirroring `src/` (e.g., `tests/<module>/test_<unit>.…`).
- Focus on core logic and edge cases; add regression tests for bugs.
- Target ≥ 80% line coverage; fail CI below threshold.
- Prefer fast, deterministic tests; use fixtures/fakes over live services.

## Commit & Pull Request Guidelines
- Use Conventional Commits: `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`, `ci:`.
- Branch names: `user/short-topic` (e.g., `alice/feat-wallet-endpoint`).
- PRs: concise description, linked issues (`Closes #123`), testing notes, and screenshots if UI.
- Keep PRs small and focused; update docs and scripts when behavior changes.

## Security & Configuration Tips
- Never commit secrets; provide `.env.example` and add real `.env` to `.gitignore`.
- Pin dependencies and scan in CI; review third-party code carefully.
- Document sensitive config in `docs/` and restrict credentials to least privilege.

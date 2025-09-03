use context7

# CLAUDE.md - Algorand Attestation Service (AAS)

This file provides personalized guidance for Claude Code when working on the Algorand Attestation Service project.

## Project Overview

Building a minimal, production-grade Algorand Attestation Service (AAS) inspired by EAS: a Schema Registry + Attestation Writer on Algorand AVM with Python SDK and CLI.

## Development Environment & Stack

- **Python**: 3.12+ (leverage modern language features and typing improvements)
- **Smart Contracts**: PyTeal + Beaker Router (Algorand AVM, Boxes, ARC-4)
- **SDK/CLI/Tests**: Python 3.12+, pytest, mypy, pynacl (ed25519), algosdk, beaker
- **Local Chain**: AlgoKit LocalNet (docker)
- **Package Manager**: uv (primary choice for this project)
- **Code Quality**: ruff, pre-commit, mypy

## AlgoKit LocalNet Setup

```bash
# Start LocalNet
algokit localnet start

# Environment variables for development
export ALGOD_URL=http://localhost:4001
export ALGOD_TOKEN=aLKsd...    # from localnet output
export DEPLOYER_MNEMONIC="25 words ..."
```

## Common Development Commands

```bash
# Install dependencies and setup
uv pip install -e .[dev]

# Run tests (all)
pytest -q

# Run only unit tests (skip LocalNet requirements)
pytest -q -m "not localnet"

# Run LocalNet integration tests
pytest -q -m localnet

# Code quality checks
mypy .
ruff check .

# Run with PYTHONPATH for tests
PYTHONPATH=$(pwd) uv run pytest -q
```

## Project Structure (Enforced)

```
aas/
  contracts/aas.py          # Beaker Router
  sdk/aas.py                # Python SDK (hashing, signing, compose calls)
  cli/aas_cli.py            # Click/Typer CLI
  scripts/deploy.py         # Beaker deploy script
  tests/
    test_contract_compile.py
    test_sdk_hashing.py
    test_flow_localnet.py   # marked @pytest.mark.localnet
  pyproject.toml / uv.lock
  .pre-commit-config.yaml
  README.md
```

## Code Style Rules (STRICT - Hard Requirements)

### Clean Code Principles
- Write self-documenting code with clear, descriptive variable and function names
- Define small functions focused on a single responsibility
- Prefer explicit and straightforward code over clever or implicit constructs
- Names should reveal intent clearly

### KISS Principle (Keep It Simple, Stupid)
- **Before implementing ANY solution, ask: "Does this violate KISS? If not, simplify!"**
- Choose the simplest approach that works
- Avoid over-engineering and unnecessary abstractions
- Prefer straightforward solutions over clever ones
- If you can solve it with fewer lines, fewer classes, or fewer dependencies - do it
- Question every layer of abstraction - is it really needed?

### Function Length & Structure
- **EVERY public function MUST be ≤10 lines maximum**
- Use helper functions for packing/unpacking boxes
- Guard-first: fail fast on invalid input
- Flat structure with guard clauses; avoid deep nesting
- Short functions (≤10 lines)

### DRY (Don't Repeat Yourself)
- Identify common functionality and extract it into reusable functions, classes, or modules
- Use constants for repeated literals or magic values
- Avoid duplicated logic; centralize common behavior

### Type Hints (Python 3.12+ Style)
- Fully annotated code - no exceptions
- Use built-in generics without importing from typing where possible:
  - `list[str]` instead of `List[str]`
  - `dict[str, int]` instead of `Dict[str, int]`
  - `set[int]` instead of `Set[int]`
  - `tuple[str, ...]` instead of `Tuple[str, ...]`
  - Use union with `|`, e.g., `str | None` instead of `Optional[str]`
- Only import from typing when necessary (Protocol, TypeVar, Generic)
- **Never relax type hints to use `Any`** - create proper types even if just Literals
- You may fallback to `Any` if the alternative would be `object` though
- Never put type hints in exclamation marks if prevented by `from __future__ import annotations`

### Control Flow & Nesting
- Use guard clauses and early returns to reduce nesting
- Avoid multiple nested conditionals by extracting complex boolean expressions into well-named functions
- Keep nesting shallow (max 2-3 levels)
- Prefer flat code structure over deeply nested code blocks
- Use early returns and function extraction to reduce indentation levels

### Loop Handling
- Extract complex loop logic into separate helper functions for clarity and testing
- Use list/dict comprehensions where appropriate for concise looping
- Prefer comprehensions over loops

### Import Practices
- **Never do local imports** unless absolutely necessary
- **Never do relative imports** - always use absolute imports and run with explicit PYTHONPATH
- **NEVER use star imports** like `from libsdk import *` - always import specific items
- **ALWAYS** import specific items: `from algosdk import account, mnemonic`

### Error Handling
- Avoid over-catching exceptions; let unexpected exceptions propagate for debugging
- Catch exceptions only when recovery or meaningful fallback is possible

### Comments and Documentation
- Favor clear code over comments; add comments sparingly when intent is not obvious
- Document public interfaces, classes, and functions with concise docstrings

## TDD Workflow (MANDATORY)

Each step MUST follow this exact sequence:
1. **Write failing tests first**
2. **Implement minimal code to make tests pass**
3. **Ensure all tests green before moving to next step**
4. **Commit only when tests pass**

### Test Organization
- Unit tests: Fast, no network dependencies
- Integration tests: Mark with `@pytest.mark.localnet` 
- If LocalNet unavailable: Skip localnet tests with clear message

## Algorand-Specific Best Practices

### Smart Contract Design
- Store minimal PII on-chain: only hashes/addresses
- Use Boxes efficiently: `schema:<schema_id_bytes>`, `att:<att_id_bytes>`
- Emit logs for every state transition: `SchemaCreated`, `Attested`, `Revoked`
- Deterministic ID generation:
  - `schema_id = sha256(canonical_schema_json)`
  - `claim_hash = sha256(canonical_claim_json)`
  - `attestation_id = sha256(schema_id|subject|claim_hash|nonce)`

### SDK Development
- Canonical JSON serialization for hashing
- Ed25519 signature verification
- Clean algosdk client wrapper patterns
- Clear separation of on-chain vs off-chain logic

### Error Handling
- Guard clauses for contract validation
- Clear error messages for CLI users
- Fail fast on invalid signatures or unauthorized operations

## Testing Strategy

### Test Types
- `test_contract_compile.py`: Assert Beaker builds approval/clear TEAL
- `test_sdk_hashing.py`: Assert canonical JSON hashing is stable
- `test_flow_localnet.py`: Full E2E flow on LocalNet

### LocalNet Test Pattern
```python
import pytest

@pytest.mark.localnet
def test_full_attestation_flow():
    # This test requires AlgoKit LocalNet running
    pass
```

### Test Runners
- Whenever running tests set `PYTHONPATH=$(pwd) uv run ...`

## Git Workflow (CRITICAL RULES)

### CRITICAL RULES - NEVER BREAK THESE:
- **NEVER** use `git add -A` or `git add .` - these are dangerous and can add unintended files
- **ALWAYS** add files explicitly by name: `git add aas/contracts/aas.py`
- **ALWAYS** check `git status` and `git diff --staged` before committing
- **NEVER** commit without reviewing exactly what is being staged

### Safe Git Workflow:
```bash
# Check what's changed
git status

# Add specific files only
git add aas/contracts/aas.py
git add aas/sdk/aas.py

# Review what will be committed
git diff --staged

# Commit with descriptive message
git commit -m "feat: add schema creation functionality"
```

## Development Practices

### Package Management
- Always use `uv run python` for script execution
- `uv pip install -e .[dev]` for development setup
- Keep dependencies minimal and well-documented

### Code Quality Gates
- All code must pass `mypy .` with no errors
- All code must pass `ruff check .` with no violations  
- All tests must pass before any commit
- Pre-commit hooks enforce quality automatically

## Architecture Patterns

### Box Storage Design
```python
# schema:<schema_id_bytes> → owner addr (32B), flags (u64), uri slice
# att:<att_id_bytes> → status (OK/RV), subject addr, schema id, optional cid slice
```

### Method Signatures
- `create_schema(schema_id, owner, uri, flags)`
- `grant_attester(schema_id, attester_pk_32)`
- `attest(schema_id, subject_addr, claim_hash_32, nonce_32, sig_64, cid)`
- `revoke(att_id, reason_u64)`

## Important Reminders

- **KISS First**: Before any implementation, ask "Does this violate KISS? If not, simplify!"
- Every function ≤10 lines (use helpers for complex operations)
- TDD: tests first, implementation second, commit only when green
- Guard clauses: validate input early, fail fast
- Minimal on-chain storage: hashes and addresses only
- Clear logs for all state transitions
- Deterministic ID generation using canonical JSON + sha256
- Never use star imports - always import specific items
- Use Python 3.12+ features for modern, idiomatic code
- Prioritize readability and maintainability over micro-optimizations
- Choose simplest solution that works

use context7
- never mention Claude in commit messages or anywhere else
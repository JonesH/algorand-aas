# Algorand Attestation Service (AAS)

A minimal, production-grade Algorand Attestation Service inspired by EAS: a Schema Registry + Attestation Writer on Algorand AVM with Python SDK and CLI.

## Features

- **Schema Registry**: Create and manage attestation schemas
- **Attestation Writing**: Create, verify, and revoke attestations
- **AI Provenance**: Attest AI model inference runs with verifiable metadata
- **Ed25519 Signatures**: Cryptographic verification of attestations
- **Minimal On-chain PII**: Only hashes and addresses stored on-chain
- **Type-safe SDK**: Pydantic models with full type safety
- **CLI Interface**: Rich command-line interface with Typer

## Quick Start

### Prerequisites

- Python 3.12+
- AlgoKit LocalNet (for development)

### Installation

```bash
# Install in development mode
uv pip install -e .

# Install with development dependencies
uv pip install -e .[dev]

# Install pre-commit if not installed yet (pipx is recommended for global installation of python cli tools)
pipx install pre-commit
# Install pre-commit hooks for code quality
pre-commit install
```

### Development Setup

```bash
# Start LocalNet
algokit localnet start

# Set environment variables
export ALGOD_URL=http://localhost:4001
export ALGOD_TOKEN=<token-from-localnet>
export DEPLOYER_MNEMONIC="25 words ..."

# Run fast unit tests only (0.4s - recommended for development)
uv run pytest -m "not localnet" -q

# Run all tests (including slow LocalNet tests - 15-20s) 
uv run pytest

# Run LocalNet integration tests in parallel (faster)
uv run pytest -m localnet -n 2

# Run full test suite in parallel  
uv run pytest -n auto

# Run type checking
uv run mypy .

# Run linting
uv run ruff check .
```

### CLI Usage

```bash
# Set environment variables
export AAS_ALGOD_URL=http://localhost:4001
export AAS_ALGOD_TOKEN=your_token_here
export AAS_APP_ID=123456
export AAS_MNEMONIC="your 25 word mnemonic phrase here"

# Show help
aas --help

# Create a schema from JSON file
aas create-schema schema.json --uri "https://example.com/schema" --flags 1

# Grant attester permissions
aas grant-attester schema_id_here attester_public_key_64_char_hex

# Create an attestation (requires pre-signed message)
aas attest schema_id subject_address claim.json nonce_64_hex signature_128_hex attester_pk_64_hex --cid QmHash

# Revoke an attestation
aas revoke attestation_id_here --reason 42

# Get attestation information
aas get attestation_id_here

# AI Attestation Commands
# Canonicalize AI inference run
aas ai canonicalize --prompt prompt.txt --params params.json --output output.txt --out claim.json

# Attest AI inference (demo mode with placeholder signature)
aas ai attest --schema ai.inference.v1 --claim claim.json

# Run complete AI attestation demo
aas ai demo-selfrun examples/selfrun_gemma270m/

# Run an LLM locally with LM Studio
# Ensure LM Studio local server is enabled (http://localhost:1234)
scripts/lmstudio_run.sh \
  --prompt examples/selfrun_gemma270m/prompt.txt \
  --params examples/selfrun_gemma270m/params.json \
  --out-dir examples/selfrun_gemma270m \
  --attester demo-user

# Or run the bundled example end-to-end
scripts/lmstudio_example.sh
```

## Application Specification Generation

AAS generates ARC-32/ARC-4/ARC-56 JSON application specifications for frontend integration and tooling compatibility.

### Generate Specs Standalone

```bash
# Generate ARC-32 specification file
uv run python aas/scripts/generate_spec.py

# Output files:
# - aas_arc32_spec.json        (main spec file)
# - artifacts/application.json  (complete artifacts)
# - artifacts/approval.teal     (approval program)
# - artifacts/clear.teal        (clear program)
# - artifacts/contract.json     (ABI contract)
```

### Generate Specs During Deployment

```bash
# Deploy and auto-generate specs with app ID
uv run python aas/scripts/deploy.py

# Output files include deployment info:
# - aas_app_<app_id>_spec.json (spec with network info)
# - application.json           (standard naming for tools)
# - artifacts/*               (all build artifacts)
```

### Use with Frontend Tools

```bash
# Generate typed client from spec (AlgoKit)
algokit generate client application.json --output clients/

# Use with block explorers, debugging tools, etc.
# Most Algorand tooling accepts ARC-32 JSON specifications
```

## Architecture

### Smart Contract (PyTeal + Beaker)
- `create_schema(schema_id, owner, uri, flags)`: Register new schema ✅
- `grant_attester(schema_id, attester_pk)`: Grant attestation permissions ✅
- `attest(schema_id, subject_addr, claim_hash_32, nonce_32, sig_64, cid, attester_pk)`: Create attestation with ed25519 signature verification ✅
- `revoke(att_id, reason)`: Revoke existing attestation ✅

### Box Storage Format
- `schema:<schema_id>` → owner(32B) + flags(8B) + uri(variable)
- `attesters:<schema_id>` → concatenated 32-byte attester public keys
- `att:<att_id>` → status(1B) + subject(32B) + schema_id_len(8B) + schema_id + cid

### Attestation ID Generation
Deterministic: `attestation_id = sha256(schema_id + subject_addr + claim_hash + nonce)`

### SDK (Python)
- Canonical JSON hashing for deterministic IDs ✅
- Ed25519 signing and verification helpers ✅
- Type-safe Pydantic models ✅
- High-level client interface ⏳

## Development

This project follows TDD (Test-Driven Development):

1. Write failing tests first
2. Implement minimal code to make tests pass
3. Ensure all tests green before moving to next step
4. Commit only when tests pass

### Fast Development Workflow

For rapid development feedback (TDD cycle):
```bash
# Lightning-fast unit tests (0.4s) - use during development
uv run pytest -m "not localnet" -q

# Full integration tests (15-20s) - use before commits
uv run pytest -m localnet -n 2
```

### Project Structure

```
aas/
  contracts/aas.py          # Beaker Router with PyTeal smart contract
  sdk/
     aas.py                # Core SDK client with real blockchain transaction submission
     models.py             # Pydantic models for type safety
     hashing.py            # Crypto utilities (JSON hashing, ed25519)
  cli/
     main.py               # Typer CLI with full blockchain transaction support
     ai_commands.py        # AI attestation commands (canonicalize, attest, demo)
     schemas/
       ai_inference_v1.json # AI inference attestation schema
  scripts/
     deploy.py             # Deployment script for LocalNet/TestNet/MainNet
     generate_spec.py      # ARC-32 application specification generator
examples/
  selfrun_gemma270m/       # Working AI attestation example
     prompt.txt            # Example prompt for Gemma 3 270M
     params.json           # Model parameters and configuration
     output.txt            # Model output
     claim.json            # Generated canonical claim
tests/
  test_contract_compile.py  # Contract compilation tests
  test_sdk_hashing.py       # SDK hashing and crypto tests
  test_flow_localnet.py     # LocalNet integration tests
  test_example_selfrun.py   # AI attestation flow tests
```

## Implementation Status

**✅ Steps 1-8 Complete**: Full attestation service with AI provenance and blockchain transaction support implemented

### Step 1: Schema Registry ✅
- [x] `create_schema` contract method with box storage
- [x] Schema ID generation and validation
- [x] Owner-only schema management
- [x] Comprehensive LocalNet integration tests

### Step 2: Attester Management ✅
- [x] `grant_attester` contract method with owner validation
- [x] Idempotent attester storage in concatenated format
- [x] 32-byte ed25519 public key validation
- [x] Authorization checks and error handling

### Step 3: Attestation Creation ✅
- [x] `attest` contract method with full ed25519 signature verification
- [x] OpUp integration for ed25519 operation budget (~1,900 ops)
- [x] Canonical message construction and deterministic ID generation
- [x] Attester authorization verification
- [x] Duplicate prevention and box storage
- [x] Comprehensive test coverage (happy path, unauthorized, duplicates, invalid signatures)

### Step 4: Attestation Revocation ✅
- [x] `revoke` contract method with validation and authorization
- [x] Revocation reason tracking in 8-byte suffix
- [x] Status updates from "A" to "R" in attestation boxes
- [x] Comprehensive test coverage (happy path, nonexistent, edge cases)

### Step 5: Python SDK ✅
- [x] Core hashing utilities (canonical JSON, deterministic IDs)
- [x] Ed25519 signing helpers (sign_message/verify_signature complete)
- [x] Pydantic models for type safety
- [x] High-level client wrapper for algod (AASClient with all methods)
- [x] verify_attestation() box reading (with box data parsing)
- [x] Unit tests for client methods and validation

### Step 6: CLI Interface ✅
- [x] Basic Typer CLI structure
- [x] Pydantic-settings configuration with environment variables
- [x] create-schema command (JSON schema file input, owner validation)
- [x] grant-attester command (schema ID + attester public key)
- [x] attest command (signature validation, claim data from JSON)
- [x] revoke command (attestation ID + optional reason)
- [x] get command (attestation lookup by ID)
- [x] Comprehensive CLI tests (argument parsing, validation, mocking)
- [x] Real blockchain transaction submission with ApplicationClient integration
- [x] Deployment script for LocalNet/TestNet/MainNet environments

### Step 8: AI Attestation Example ✅
- [x] AI inference schema (ai.inference.v1) for standardized AI provenance
- [x] `aas ai canonicalize` command for deterministic claim generation
- [x] `aas ai attest` command for AI-specific blockchain attestations
- [x] `aas ai demo-selfrun` helper for complete workflow demonstration
- [x] Working Gemma 3 270M example with prompt, parameters, and output
- [x] Comprehensive test coverage for AI attestation flow
- [x] Documentation and integration with existing CLI structure

## Test Results

**Optimized Performance** (function-scoped deployment, 2-round confirmations, enhanced funding, parallel execution):
```bash
# Unit tests only (development workflow)
uv run pytest -m "not localnet" -q
======================== 37 passed in 0.37s ========================

# Full test suite (pre-commit workflow)  
uv run pytest -n 2
======================== 73 passed, 1 skipped in ~20-25s ========================
```

**Current Focus**: All 8 steps complete! Production-ready AAS with AI provenance attestation, full blockchain transaction support, deployment script, and comprehensive CLI interface

## License

MIT

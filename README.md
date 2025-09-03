# Algorand Attestation Service (AAS)

A minimal, production-grade Algorand Attestation Service inspired by EAS: a Schema Registry + Attestation Writer on Algorand AVM with Python SDK and CLI.

## Features

- **Schema Registry**: Create and manage attestation schemas
- **Attestation Writing**: Create, verify, and revoke attestations
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
```

### Development Setup

```bash
# Start LocalNet
algokit localnet start

# Set environment variables
export ALGOD_URL=http://localhost:4001
export ALGOD_TOKEN=<token-from-localnet>
export DEPLOYER_MNEMONIC="25 words ..."

# Run all tests
uv run pytest

# Run only unit tests (skip LocalNet)
uv run pytest -m "not localnet"

# Run only LocalNet integration tests  
uv run pytest -m localnet

# Run type checking
uv run mypy .

# Run linting
uv run ruff check .
```

### CLI Usage

```bash
# Show help
aas --help

# Create a schema (TODO: CLI not implemented yet)
aas create-schema

# Grant attester permissions (TODO: CLI not implemented yet)  
aas grant-attester

# Create an attestation (TODO: CLI not implemented yet)
aas attest

# Revoke an attestation (TODO: CLI not implemented yet)
aas revoke

# Get information (TODO: CLI not implemented yet)
aas get
```

## Architecture

### Smart Contract (PyTeal + Beaker)
- `create_schema(schema_id, owner, uri, flags)`: Register new schema ✅ 
- `grant_attester(schema_id, attester_pk)`: Grant attestation permissions ✅
- `attest(schema_id, subject_addr, claim_hash_32, nonce_32, sig_64, cid, attester_pk)`: Create attestation with ed25519 signature verification ✅
- `revoke(att_id, reason)`: Revoke existing attestation ⏳

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

### Project Structure

```
aas/
  contracts/aas.py          # Beaker Router with PyTeal smart contract
  sdk/
     aas.py                # Core SDK (TODO: high-level client)
     models.py             # Pydantic models for type safety  
     hashing.py            # Crypto utilities (JSON hashing, ed25519)
  cli/
     main.py               # Typer CLI (TODO: implement commands)
  scripts/
     deploy.py             # Deployment script (TODO: implement)
tests/
  test_contract_compile.py  # Contract compilation tests
  test_sdk_hashing.py       # SDK hashing and crypto tests  
  test_flow_localnet.py     # LocalNet integration tests
```

## Implementation Status

**✅ Steps 1-4 Complete**: Core attestation functionality with revocation implemented

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

### Step 5: Python SDK ⏳
- [x] Core hashing utilities (canonical JSON, deterministic IDs)
- [x] Ed25519 signing helpers (sign_message function signatures)
- [x] Pydantic models for type safety
- [ ] High-level client wrapper for algod
- [ ] verify_attestation() box reading
- [ ] End-to-end SDK integration tests

### Step 6: CLI Interface ⏳
- [x] Basic Typer CLI structure
- [ ] create-schema command
- [ ] grant-attester command  
- [ ] attest command
- [ ] revoke command
- [ ] get/query commands

## Test Results
```
======================== 19 passed, 3 skipped in 20.53s ========================
```

**Current Focus**: Ready for Step 5 (SDK client wrapper) or Step 6 (CLI interface)

## License

MIT
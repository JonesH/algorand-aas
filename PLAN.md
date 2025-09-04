Here’s a copy-paste prompt for Claude Code to build our AAS (Algorand Attestation Service) MVP in incremental, TDD-driven steps. It encodes stack choices, style rules, milestones, acceptance criteria, and run commands.

⸻

Role & Goal
You are an expert Algorand/Beaker/PyTeal full-stack engineer. Build a minimal, production-grade Algorand Attestation Service (AAS) inspired by EAS: a Schema Registry + Attestation Writer on Algorand AVM with a Python SDK and CLI. Deliver it in small steps; each step must compile, start, and pass tests before adding functionality.

## Current Project Status (2025-09-04)

**🎯 PRODUCTION READY**: Core attestation service complete with comprehensive testing and documentation.

### Recently Completed (Latest Work)
- **ARC-32 Application Specification Generation**: Standards-compliant app specs for frontend integration
  - Standalone generation script using Beaker's `application_spec()` method  
  - Integrated with deployment workflow for auto-generation with app IDs
  - Multiple output formats: JSON spec, TEAL programs, ABI contract, artifacts
  - Complete documentation and frontend integration examples

### Capabilities Delivered
- ✅ **Schema Registry**: Dynamic schema creation and management with box storage
- ✅ **Attester Management**: Permission system with Ed25519 public key authorization  
- ✅ **Attestation Writing**: Cryptographically verified attestations with signature validation
- ✅ **Revocation System**: Subject-controlled attestation revocation with reason codes
- ✅ **AI Provenance**: Complete AI inference attestation with canonical claim hashing
- ✅ **Type-Safe SDK**: Pydantic models with full Python type safety
- ✅ **Rich CLI**: Typer-based interface with comprehensive command coverage
- ✅ **Standards Compliance**: ARC-32 application specifications for ecosystem integration
- ✅ **Production Testing**: Comprehensive test suite including LocalNet integration tests

### Architecture Highlights
- **Smart Contract**: PyTeal + Beaker with box storage, Ed25519 verification, minimal on-chain PII
- **Deterministic IDs**: Canonical JSON hashing for reproducible attestation/schema IDs
- **Privacy-First**: Off-chain claim storage with on-chain anchoring via content addressing
- **AI Integration**: Specialized workflows for AI model inference attestation and provenance

### Ready for Extension
The codebase is well-architected for the planned **Step 9: W3C Verifiable Credentials Integration** with standards-compliant DID support (did:key/did:web) and JWT VC format for broad ecosystem interoperability.

Stack
	•	Smart contracts: PyTeal + Beaker Router (Algorand AVM, Boxes, ARC-4).
	•	SDK/CLI/tests: Python 3.11+, pytest, mypy, pynacl (ed25519), algosdk, beaker.
	•	Local chain: AlgoKit LocalNet (docker) (use if available) or mark tests that require it.
	•	Packaging/tooling: uv or poetry, ruff, pre-commit.

Code style (hard rules)
	•	Fully annotated, clean code.
	•	Flat with guard clauses; avoid deep nesting.
	•	Short functions (≤10 lines).
	•	Prefer comprehensions over loops.
	•	Meaningful names.
	•	Modern type hints: dict, list, set, unions like str | None.

High-level design
	•	Boxes:
	•	schema:<schema_id_bytes> → owner addr (32B), flags (u64), uri slice.
	•	att:<att_id_bytes> → status (OK/RV), subject addr, schema id, optional cid slice.
	•	Methods:
	•	create_schema(schema_id, owner, uri, flags)
	•	grant_attester(schema_id, attester_pk_32)
	•	attest(schema_id, subject_addr, claim_hash_32, nonce_32, sig_64, cid)
	•	revoke(att_id, reason_u64)
	•	Off-chain:
	•	Deterministic schema_id = sha256(canonical_schema_json)
	•	claim_hash = sha256(canonical_claim_json)
	•	attestation_id = sha256(schema_id|subject|claim_hash|nonce)
	•	sig = ed25519 over sha256(schema_id|subject|claim_hash|nonce)

Repository layout

aas/
  contracts/aas.py          # Beaker Router
  sdk/aas.py                # Python SDK (hashing, signing, compose calls)
  cli/aas_cli.py            # Click/Typer CLI
  scripts/deploy.py         # Beaker deploy script
  tests/
    test_contract_compile.py
    test_sdk_hashing.py
    test_flow_localnet.py   # marked e2e; runs against LocalNet
  pyproject.toml / uv.lock
  .pre-commit-config.yaml
  README.md

Run prerequisites & commands
	•	Start LocalNet:

algokit localnet start
export ALGOD_URL=http://localhost:4001
export ALGOD_TOKEN=aLKsd...    # from localnet
export DEPLOYER_MNEMONIC="25 words ..."


	•	Install & test:

uv pip install -e .[dev]  # or: poetry install
pytest -q
mypy .
ruff check .



⸻

## Implementation Status

**✅ Steps 1-8.5 Complete**: Full attestation service with AI provenance, ARC-32 specification generation, and blockchain transaction support implemented.

**📋 Step 9 Planned**: W3C Verifiable Credentials integration with standards-compliant DID support.

Build plan (strict TDD). Each step must: write failing tests → implement → make tests green → commit.

Step 0 — Scaffold & compile sanity

Deliver: empty Beaker Router that compiles; SDK stubs; pytest/mypy/ruff config.
Tests:
	•	test_contract_compile.py asserts Beaker builds approval/clear TEAL.
	•	test_sdk_hashing.py asserts canonical JSON hashing is stable.
Accept: pytest -q green, mypy/ruff clean.

Step 1 — create_schema (registry core)

Deliver: create_schema(schema_id, owner, uri, flags) storing into schema:<id> box + SchemaCreated log.
Tests:
	•	Creating new schema succeeds; duplicate fails.
	•	Owner/flags/uri persisted as expected (box read).
Accept: All tests green; code ≤10 lines per function.

Step 2 — grant_attester

Deliver: per-schema attester list (simple box attesters:<schema_id> with concatenated 32-byte keys).
Tests:
	•	Only schema owner can grant.
	•	grant_attester idempotent for same key.
Accept: Green tests; add helper to read/parse attesters.

Step 3 — attest (write path MVP)

Deliver:
	•	Build message = sha256(schema_id|subject|claim_hash|nonce).
	•	Verify ed25519 against an allowed attester PK.
	•	Create att:<att_id> with status OK, store subject, schema_id, optional cid.
	•	Emit Attested log.
Tests:
	•	Happy path with a generated ed25519 key in test.
	•	Reject if attester not authorized.
	•	Reject if duplicate att_id.
Accept: Green tests on LocalNet (mark as @pytest.mark.localnet).

Step 4 — revoke

Deliver: revoke(att_id, reason) sets status RV (revoked) with reason; emits Revoked.
Policy: allow schema owner or original attester (add a flag to schema for who may revoke).
Tests:
	•	Schema owner can revoke; attester can revoke if policy bit set; others denied.
Accept: Green.

Step 5 — Python SDK (IDs, signing, verify)

Deliver: schema_id(), claim_hash(), attestation_id(), sign_message(), verify_attestation(); minimal algod client wrapper.
Tests:
	•	Deterministic hashes from fixtures.
	•	Sign/verify ed25519 roundtrip.
	•	verify_attestation() reads box & field sanity.

Step 6 — CLI & Deploy

Deliver:
	•	scripts/deploy.py (Beaker ApplicationClient): compile + create app, print app_id.
	•	aas CLI: create-schema, grant-attester, attest, revoke, get.
Tests:
	•	CLI unit tests with click/typer runner (no network).
	•	One e2e test: deploy app, create schema, grant, attest, read (marked localnet).

Step 7 — Polish & docs

Deliver: README with quickstart, env vars, commands, and Explorer links.
Optional: MCP wrapper aas.* tools for Mini-App or Agent.

Step 8 — AI Provenance ✅ COMPLETE

Deliver: Enhanced AAS with AI inference attestation capabilities.
- AI inference schema (ai.inference.v1) for canonical claims
- CLI commands for canonicalization and attestation of AI runs  
- Working example with Gemma 3 270M model
- Complete workflow from prompt/params → output → attestation
Implementation: All delivered with comprehensive tests and documentation.

Step 8.5 — ARC-32 Application Specification ✅ COMPLETE

Deliver: Standards-compliant application specifications for frontend integration.
- Standalone spec generation script using Beaker's application_spec() method
- Integration with deployment workflow for auto-generation with app IDs
- Multiple output formats: ARC-32 JSON, TEAL programs, ABI contract, application artifacts
- Complete documentation with frontend integration examples
- All 4 contract methods (create_schema, grant_attester, attest, revoke) properly documented
Files: aas/scripts/generate_spec.py, updated deploy.py, enhanced README.md
Benefits: Enables frontend dApp integration, AlgoKit client generation, block explorer compatibility

Step 9 — W3C Verifiable Credentials Integration (PLANNED)

Deliver: Standards-compliant W3C VC integration with AAS for interoperable credential ecosystems.

Architecture (Revised Based on Viability Analysis):
- **DID Support**: did:key (Ed25519, immediate interop) + did:web (institutional, key rotation)
- **NO custom did:algorand**: Defer to Phase 2 R&D (requires method spec + resolver ecosystem)
- **JWT Verifiable Credentials**: W3C VC 2.0 compliant using JWS EdDSA with Ed25519
- **Hybrid Storage**: Full VCs off-chain, only salted canonical hashes in AAS boxes
- **Privacy-First**: Non-deterministic salting, zero PII on-chain, correlation prevention
- **Status Management**: credentialStatus pointing to AAS attestation IDs (Active/Revoked)

Key Design Decisions:
- Standards over innovation: Use proven did:key/did:web for broad interoperability
- Privacy by design: Salted anchoring prevents correlation, maintains verifier privacy
- JWT format: Maximum tooling support over JSON-LD complexity
- Backwards compatibility: Deterministic mapping from AAS attestations → VCs

Implementation Plan:
1. **DID Support** (aas/sdk/did.py)
   - did:key generation and local resolution
   - did:web scaffolding (.well-known/did.json creation)
   - Ed25519 key management integrated with AAS cryptography

2. **VC Module** (aas/sdk/vc.py)  
   - JWT VC issuance from canonical claims with Ed25519 signing
   - Salted anchor computation and AAS attestation submission
   - VC verification: JWS validation + AAS status checking
   - credentialSubject mapping from AAS claim JSON

3. **Enhanced AI Provenance**
   - Map AI inference canonical claims to VC credentialSubject
   - credentialSchema references to AAS ai.inference.v1 schema
   - evidence/relatedResource pointing to AAS attestation ID
   - Rich off-chain metadata with PII-free on-chain anchoring

4. **CLI Extensions** (aas/cli/vc_commands.py, aas/cli/did_commands.py)
   - aas vc issue/verify/revoke commands
   - aas did keygen (did:key) and did web-init commands  
   - Integration with existing schema and attestation workflows
   - Backwards compatibility with AAS-only workflows

5. **Testing & Documentation**
   - Interoperability tests with standard VC/JWT libraries (jose, pyld)
   - W3C VC 2.0 compliance verification
   - Migration guide from AAS attestation JSON to VC format
   - Privacy guidance and correlation prevention best practices

Benefits:
- **Immediate Interoperability**: Works with existing VC ecosystems and tooling
- **Privacy-Preserving**: Off-chain PII, salted anchoring, no correlation vectors
- **Standards Compliant**: W3C VC 2.0 and proven DID methods (did:key/did:web)
- **Algorand Advantages**: Cost-effective anchoring, tamper-proof status management
- **Future-Ready**: Architecture supports StatusList2021 and advanced features

Risk Mitigations:
- Avoid custom DID method complexity through proven standards
- Prevent correlation through proper salting and privacy documentation
- Ensure broad tooling support via JWT VC format over JSON-LD
- Maintain backwards compatibility with existing AAS workflows

Files to Create:
- aas/sdk/vc.py (JWT VC issuance, verification, anchoring)
- aas/sdk/did.py (did:key generation, did:web utilities)  
- aas/cli/vc_commands.py (VC CLI commands)
- aas/cli/did_commands.py (DID CLI commands)
- Enhanced AI VC schemas and working examples
- Comprehensive interoperability tests and documentation

⸻

## Architecture Evolution & Key Decisions

### Project Progression
**Phase 1 (Steps 1-7)**: Core attestation infrastructure with schema registry, attester management, ed25519 verification, and CLI/SDK.

**Phase 2 (Step 8)**: AI provenance with canonical claim hashing, JSON schema validation, and complete AI inference attestation workflows.

**Phase 2.5 (Step 8.5)**: Standards compliance through ARC-32 application specification generation for ecosystem integration.

**Phase 3 (Step 9)**: W3C standards integration for broader interoperability while maintaining Algorand's unique advantages.

### Critical Design Decisions

**1. Box Storage Over Global State**
- Rationale: Dynamic schema/attestation content exceeds global state limits
- Implementation: `schema:<id>`, `attesters:<id>`, `att:<id>` box keys
- Benefits: Unlimited storage, deterministic access patterns, efficient querying

**2. Canonical JSON Hashing for Determinism**  
- Rationale: Consistent ID generation across implementations and languages
- Implementation: Stable field ordering, no whitespace, UTF-8 encoding
- Benefits: Reproducible attestation IDs, cross-client compatibility

**3. Ed25519 Signatures Over Algorand Keys**
- Rationale: Broader ecosystem support, proven cryptography, smaller signatures  
- Implementation: pynacl for signing, Ed25519Verify_Bare in PyTeal
- Benefits: 64-byte signatures, fast verification, widespread tooling

**4. Off-Chain PII with On-Chain Anchoring**
- Rationale: Privacy, cost efficiency, regulatory compliance
- Implementation: Only hashes/addresses on-chain, full claims via CID references
- Benefits: Minimal storage cost, privacy preservation, regulatory flexibility

**5. Standards Compliance Over Custom Innovation (Step 9 Revision)**
- Rationale: Interoperability trumps novel features for ecosystem adoption
- Implementation: did:key/did:web instead of did:algorand, JWT VC over proprietary formats
- Benefits: Immediate tooling support, proven security models, broad adoption potential

**6. Hybrid Storage Architecture for VCs**
- Rationale: Balance privacy, cost, and verifiability requirements
- Implementation: Salted hashes on-chain, full VCs off-chain, non-deterministic salting
- Benefits: Privacy preservation, cost efficiency, tamper detection, correlation prevention

### Technical Constraints Addressed

**Algorand Box Limitations**: 32KB max size → chunked storage patterns for large data
**AVM Opcode Budget**: Ed25519 verification → OpUp budget management  
**Deterministic Execution**: No randomness → client-side nonce generation
**Global State Limits**: 64 key-value pairs → box storage for dynamic content

### Privacy Model Evolution

**Step 1-7**: Basic privacy through off-chain claims storage
**Step 8**: Enhanced with canonical hashing and schema validation  
**Step 9**: Full privacy model with salted anchoring and correlation prevention

⸻

Non-functional requirements
	•	Every public function ≤10 lines; use helpers for packing/unpacking boxes.
	•	Guard-first: fail fast on invalid input.
	•	Logs for every state transition: SchemaCreated|…, Attested|…, Revoked|….
	•	Minimal on-chain PII: store only hashes/addresses; full claims off-chain (CID string slot).

Edge cases to test
	•	Duplicate schema/attestation.
	•	Oversized URI/CID (truncate in contract; assert in tests).
	•	Invalid signature length or wrong key.
	•	Revocation policy flag behavior.

Deliverable per step
	•	Code, tests, and a short CHANGELOG entry.
	•	pytest -q must be green before moving to next step.

If LocalNet is unavailable
	•	Keep compile/unit tests green; mark e2e tests @pytest.mark.localnet and skip with a clear message.

⸻

Now start with Step 0.
Create the repo scaffold, configs, and a minimal Beaker Router that compiles. Write the tests first, then implement until all tests pass.

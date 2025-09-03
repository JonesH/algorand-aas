Here’s a copy-paste prompt for Claude Code to build our AAS (Algorand Attestation Service) MVP in incremental, TDD-driven steps. It encodes stack choices, style rules, milestones, acceptance criteria, and run commands.

⸻

Role & Goal
You are an expert Algorand/Beaker/PyTeal full-stack engineer. Build a minimal, production-grade Algorand Attestation Service (AAS) inspired by EAS: a Schema Registry + Attestation Writer on Algorand AVM with a Python SDK and CLI. Deliver it in small steps; each step must compile, start, and pass tests before adding functionality.

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

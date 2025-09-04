"""Tests for AI self-run attestation example."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aas.cli.ai_commands import _create_canonical_claim, _validate_claim_against_schema
from aas.sdk.hashing import canonical_json_hash


def test_canonical_claim_creation() -> None:
    """Test creation of canonical AI inference claim."""
    prompt = "Test prompt"
    params = {"temperature": 0.0, "max_tokens": 100}
    output = "Test output"
    model_id = "test/model"
    model_version = "v1.0"
    
    claim = _create_canonical_claim(
        prompt=prompt,
        params=params,
        output=output,
        model_id=model_id,
        model_version=model_version,
    )
    
    assert claim["schema_version"] == "ai.inference.v1"
    assert claim["model"]["id"] == model_id
    assert claim["model"]["version"] == model_version
    assert claim["input"]["prompt"] == prompt
    assert claim["input"]["parameters"] == params
    assert claim["output"]["text"] == output
    assert claim["provenance"]["method"] == "self-run"


def test_claim_validation_success() -> None:
    """Test successful claim validation against schema."""
    claim = {
        "schema_version": "ai.inference.v1",
        "model": {"id": "test/model", "version": "v1.0"},
        "input": {
            "prompt": "test",
            "parameters": {"temperature": 0.0, "max_tokens": 100}
        },
        "output": {"text": "response"},
        "execution": {"timestamp": "2024-01-01T00:00:00Z"},
        "provenance": {"method": "self-run"}
    }
    
    # Should not raise an exception
    _validate_claim_against_schema(claim)


def test_claim_validation_missing_fields() -> None:
    """Test claim validation with missing required fields."""
    claim = {
        "schema_version": "ai.inference.v1",
        "model": {"id": "test/model", "version": "v1.0"}
        # Missing required fields: input, output, execution, provenance
    }
    
    with pytest.raises(ValueError, match="Missing required fields"):
        _validate_claim_against_schema(claim)


def test_claim_validation_wrong_schema_version() -> None:
    """Test claim validation with wrong schema version."""
    claim = {
        "schema_version": "wrong.version",
        "model": {"id": "test/model", "version": "v1.0"},
        "input": {
            "prompt": "test", 
            "parameters": {"temperature": 0.0, "max_tokens": 100}
        },
        "output": {"text": "response"},
        "execution": {"timestamp": "2024-01-01T00:00:00Z"},
        "provenance": {"method": "self-run"}
    }
    
    with pytest.raises(ValueError, match="Invalid schema version"):
        _validate_claim_against_schema(claim)


def test_hash_stability() -> None:
    """Test that identical claims produce identical hashes."""
    claim1 = _create_canonical_claim(
        prompt="test",
        params={"temperature": 0.0, "max_tokens": 100},
        output="response",
        model_id="model",
        model_version="v1.0",
    )
    
    claim2 = _create_canonical_claim(
        prompt="test",
        params={"temperature": 0.0, "max_tokens": 100}, 
        output="response",
        model_id="model",
        model_version="v1.0",
    )
    
    # Set same timestamp to ensure identical hashes
    claim2["execution"]["timestamp"] = claim1["execution"]["timestamp"]
    
    hash1 = canonical_json_hash(claim1)
    hash2 = canonical_json_hash(claim2)
    
    assert hash1 == hash2


def test_gemma270m_example_files_exist() -> None:
    """Test that Gemma 270M example files exist and are valid."""
    example_dir = Path("examples/selfrun_gemma270m")
    
    # Check required files exist
    assert (example_dir / "prompt.txt").exists()
    assert (example_dir / "params.json").exists()
    assert (example_dir / "output.txt").exists()
    
    # Validate params.json
    params = json.loads((example_dir / "params.json").read_text())
    assert "model_id" in params
    assert "model_version" in params
    assert "params" in params
    
    # Validate prompt is not empty
    prompt = (example_dir / "prompt.txt").read_text().strip()
    assert len(prompt) > 0
    
    # Validate output is not empty
    output = (example_dir / "output.txt").read_text().strip()
    assert len(output) > 0


def test_gemma270m_claim_validation() -> None:
    """Test that generated Gemma 270M claim validates against schema."""
    example_dir = Path("examples/selfrun_gemma270m")
    claim_file = example_dir / "claim.json"
    
    if not claim_file.exists():
        pytest.skip("claim.json not generated yet - run canonicalization first")
    
    claim = json.loads(claim_file.read_text())
    
    # Should validate without errors
    _validate_claim_against_schema(claim)
    
    # Check specific fields
    assert claim["schema_version"] == "ai.inference.v1"
    assert claim["model"]["id"] == "google/gemma-3-270m-it"
    assert claim["provenance"]["method"] == "self-run"


@pytest.mark.lmstudio
def test_live_lm_studio_integration() -> None:
    """Test integration with live LM Studio instance."""
    pytest.skip("Live LM Studio integration test - requires running LM Studio")
    
    # This test would:
    # 1. Check if LM Studio is running
    # 2. Send a request to local API
    # 3. Capture response and canonicalize
    # 4. Validate the resulting claim
    pass
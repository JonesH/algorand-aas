"""Test AI VC provenance integration.

Tests for AI inference VC integration with existing AI attestation system.
Following TDD: These tests should FAIL initially until implementation.
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

import pytest
from nacl.signing import SigningKey

from aas.sdk.ai_vc_integration import (
    map_ai_claim_to_vc_subject,
    issue_ai_inference_vc,
    verify_ai_inference_vc,
    anchor_ai_vc_to_aas,
    get_ai_vc_status
)
from aas.sdk.did import generate_ed25519_keypair
from aas.sdk.vc import parse_jwt_vc_payload


@pytest.fixture
def sample_ai_claim():
    """Sample AI inference canonical claim."""
    return {
        "schema_version": "ai.inference.v1",
        "model": {
            "id": "google/gemma-3-270m-it",
            "version": "gemma3-270m-it-qat-q4_0"
        },
        "input": {
            "prompt": "What is the capital of France?",
            "parameters": {
                "temperature": 0.7,
                "max_tokens": 100,
                "top_p": 0.9
            }
        },
        "output": {
            "text": "The capital of France is Paris.",
            "finish_reason": "stop"
        },
        "execution": {
            "timestamp": "2024-01-01T12:00:00Z",
            "environment": {
                "runtime": "LM Studio",
                "version": "0.2.0"
            }
        },
        "provenance": {
            "attester": "test-user",
            "method": "self-run"
        }
    }


@pytest.fixture
def ai_keypair():
    """AI inference keypair for testing."""
    return generate_ed25519_keypair()


def test_map_ai_claim_to_vc_subject(sample_ai_claim: dict):
    """Test mapping AI claim to VC credentialSubject format."""
    vc_subject = map_ai_claim_to_vc_subject(sample_ai_claim)
    
    # Should preserve original AI claim structure
    assert vc_subject["schema_version"] == "ai.inference.v1"
    assert vc_subject["model"]["id"] == "google/gemma-3-270m-it"
    assert vc_subject["input"]["prompt"] == "What is the capital of France?"
    assert vc_subject["output"]["text"] == "The capital of France is Paris."
    
    # Should add VC-specific metadata
    assert vc_subject["@type"] == ["AIInferenceCredential", "VerifiableCredential"]
    assert "id" in vc_subject  # Should have subject ID


def test_map_empty_claim_error():
    """Test error handling for empty AI claim."""
    with pytest.raises(ValueError, match="AI claim is required"):
        map_ai_claim_to_vc_subject({})


def test_map_invalid_schema_version_error():
    """Test error handling for invalid schema version."""
    invalid_claim = {"schema_version": "invalid.v1", "model": {}}
    
    with pytest.raises(ValueError, match="Invalid AI schema version"):
        map_ai_claim_to_vc_subject(invalid_claim)


def test_issue_ai_inference_vc(sample_ai_claim: dict, ai_keypair: tuple):
    """Test issuing AI inference VC from canonical claim."""
    signing_key, issuer_did = ai_keypair
    subject_did = "did:key:z6MkfrQREaHn7i6Rx1M4xr37KVnSuYDvtGbgqrJvd8j7NRgN"
    
    jwt_vc = issue_ai_inference_vc(
        sample_ai_claim,
        issuer_did,
        subject_did,
        signing_key
    )
    
    # Should return valid JWT format
    assert jwt_vc.count('.') == 2
    
    # Should contain AI inference data in VC
    payload = parse_jwt_vc_payload(jwt_vc)
    vc_data = payload["vc"]
    
    assert vc_data["type"] == ["VerifiableCredential", "AIInferenceCredential"]
    assert vc_data["credentialSubject"]["schema_version"] == "ai.inference.v1"
    assert vc_data["credentialSubject"]["model"]["id"] == "google/gemma-3-270m-it"


def test_issue_ai_vc_with_schema_id(sample_ai_claim: dict, ai_keypair: tuple):
    """Test issuing AI VC with AAS schema reference."""
    signing_key, issuer_did = ai_keypair
    subject_did = "did:key:z6MkfrQREaHn7i6Rx1M4xr37KVnSuYDvtGbgqrJvd8j7NRgN"
    schema_id = "ai.inference.v1.aas.schema"
    
    jwt_vc = issue_ai_inference_vc(
        sample_ai_claim,
        issuer_did,
        subject_did,
        signing_key,
        schema_id=schema_id
    )
    
    payload = parse_jwt_vc_payload(jwt_vc)
    vc_data = payload["vc"]
    
    # Should reference AAS schema
    assert vc_data["credentialSchema"]["id"] == schema_id


def test_issue_ai_vc_missing_parameters_error():
    """Test error handling for missing parameters."""
    with pytest.raises(ValueError, match="All parameters required"):
        issue_ai_inference_vc({}, "", "", None)


def test_verify_ai_inference_vc(sample_ai_claim: dict, ai_keypair: tuple):
    """Test verifying AI inference VC."""
    signing_key, issuer_did = ai_keypair
    subject_did = "did:key:z6MkfrQREaHn7i6Rx1M4xr37KVnSuYDvtGbgqrJvd8j7NRgN"
    
    # Issue VC first
    jwt_vc = issue_ai_inference_vc(
        sample_ai_claim,
        issuer_did,
        subject_did,
        signing_key
    )
    
    # Verify it
    is_valid = verify_ai_inference_vc(jwt_vc, issuer_did)
    assert is_valid is True


def test_verify_ai_vc_invalid_signature():
    """Test verification failure for invalid signature."""
    invalid_jwt = "invalid.jwt.token"
    issuer_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    
    is_valid = verify_ai_inference_vc(invalid_jwt, issuer_did)
    assert is_valid is False


def test_anchor_ai_vc_to_aas(sample_ai_claim: dict, ai_keypair: tuple):
    """Test anchoring AI VC to AAS attestation system."""
    signing_key, issuer_did = ai_keypair
    subject_did = "did:key:z6MkfrQREaHn7i6Rx1M4xr37KVnSuYDvtGbgqrJvd8j7NRgN"
    
    # Issue AI VC first  
    jwt_vc = issue_ai_inference_vc(
        sample_ai_claim,
        issuer_did,
        subject_did,
        signing_key
    )
    
    # Anchor to AAS
    schema_id = "ai.inference.v1"
    subject_addr = "ALGORAND_ADDRESS_32BYTES_TEST_ADDRESS"
    
    attestation_id = anchor_ai_vc_to_aas(
        jwt_vc,
        schema_id,
        subject_addr,
        signing_key
    )
    
    # Should return attestation ID
    assert len(attestation_id) > 0
    assert isinstance(attestation_id, str)


def test_anchor_ai_vc_invalid_parameters():
    """Test error handling for invalid anchoring parameters."""
    with pytest.raises(ValueError, match="All parameters required"):
        anchor_ai_vc_to_aas("", "", "", None)


def test_get_ai_vc_status():
    """Test checking AI VC status through AAS."""
    attestation_id = "test_ai_attestation_id_12345"
    
    status = get_ai_vc_status(attestation_id)
    
    # Should return valid status (using real AAS status format)
    assert status in ["Active", "Revoked", "Suspended"]


def test_ai_vc_roundtrip(sample_ai_claim: dict, ai_keypair: tuple):
    """Test complete AI VC roundtrip: claim → VC → verify → anchor → status."""
    signing_key, issuer_did = ai_keypair
    subject_did = "did:key:z6MkfrQREaHn7i6Rx1M4xr37KVnSuYDvtGbgqrJvd8j7NRgN"
    
    # 1. Issue AI VC
    jwt_vc = issue_ai_inference_vc(
        sample_ai_claim,
        issuer_did, 
        subject_did,
        signing_key,
        schema_id="ai.inference.v1"
    )
    
    # 2. Verify VC
    is_valid = verify_ai_inference_vc(jwt_vc, issuer_did)
    assert is_valid is True
    
    # 3. Anchor to AAS
    schema_id = "ai.inference.v1"
    subject_addr = "ALGORAND_ADDRESS_32BYTES_TEST_ADDRESS"
    
    attestation_id = anchor_ai_vc_to_aas(
        jwt_vc,
        schema_id,
        subject_addr,
        signing_key
    )
    
    # 4. Check status
    status = get_ai_vc_status(attestation_id)
    assert status == "Active"


def test_ai_claim_preservation_in_vc(sample_ai_claim: dict, ai_keypair: tuple):
    """Test that original AI claim is fully preserved in VC."""
    signing_key, issuer_did = ai_keypair
    subject_did = "did:key:z6MkfrQREaHn7i6Rx1M4xr37KVnSuYDvtGbgqrJvd8j7NRgN"
    
    jwt_vc = issue_ai_inference_vc(
        sample_ai_claim,
        issuer_did,
        subject_did,
        signing_key
    )
    
    payload = parse_jwt_vc_payload(jwt_vc)
    credential_subject = payload["vc"]["credentialSubject"]
    
    # Remove VC-specific fields for comparison
    ai_claim_from_vc = {k: v for k, v in credential_subject.items() 
                        if k not in ["@type", "id"]}
    
    # Should match original AI claim exactly
    assert ai_claim_from_vc == sample_ai_claim


def test_ai_vc_with_provenance_metadata(sample_ai_claim: dict, ai_keypair: tuple):
    """Test AI VC includes proper provenance metadata."""
    signing_key, issuer_did = ai_keypair
    subject_did = "did:key:z6MkfrQREaHn7i6Rx1M4xr37KVnSuYDvtGbgqrJvd8j7NRgN"
    
    jwt_vc = issue_ai_inference_vc(
        sample_ai_claim,
        issuer_did,
        subject_did,
        signing_key
    )
    
    payload = parse_jwt_vc_payload(jwt_vc)
    vc_data = payload["vc"]
    
    # Should have AI-specific VC type
    assert "AIInferenceCredential" in vc_data["type"]
    
    # Should preserve provenance information
    provenance = vc_data["credentialSubject"]["provenance"]
    assert provenance["attester"] == "test-user"
    assert provenance["method"] == "self-run"


def test_multiple_ai_models_in_vc(ai_keypair: tuple):
    """Test AI VC works with different model types."""
    signing_key, issuer_did = ai_keypair
    subject_did = "did:key:z6MkfrQREaHn7i6Rx1M4xr37KVnSuYDvtGbgqrJvd8j7NRgN"
    
    # Test with different model
    claude_claim = {
        "schema_version": "ai.inference.v1",
        "model": {
            "id": "anthropic/claude-3-sonnet",
            "version": "20240229"
        },
        "input": {
            "prompt": "Explain quantum computing",
            "parameters": {
                "temperature": 0.3,
                "max_tokens": 200
            }
        },
        "output": {
            "text": "Quantum computing uses quantum mechanics...",
            "finish_reason": "stop"
        },
        "execution": {
            "timestamp": "2024-01-01T12:00:00Z",
            "environment": {
                "runtime": "Claude API",
                "version": "v1.0"
            }
        },
        "provenance": {
            "attester": "api-user",
            "method": "delegated"
        }
    }
    
    jwt_vc = issue_ai_inference_vc(
        claude_claim,
        issuer_did,
        subject_did,
        signing_key
    )
    
    # Should work for different AI models
    assert jwt_vc.count('.') == 2
    
    payload = parse_jwt_vc_payload(jwt_vc)
    model_info = payload["vc"]["credentialSubject"]["model"]
    assert model_info["id"] == "anthropic/claude-3-sonnet"
    assert model_info["version"] == "20240229"
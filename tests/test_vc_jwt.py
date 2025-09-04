"""Test JWT Verifiable Credentials functionality.

Tests for W3C VC issuance, verification, and structure validation.
Following TDD: These tests should FAIL initially until implementation.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import pytest
from nacl.signing import SigningKey

# Import functions that don't exist yet - will cause ImportError initially
from aas.sdk.did import generate_did_key
from aas.sdk.vc import (
    issue_jwt_vc,
    verify_jwt_vc,
    extract_credentialsubject,
    generate_salted_anchor,
    parse_jwt_vc_payload,
    validate_vc_structure,
    create_vc_credentialstatus,
)


@pytest.fixture
def sample_claim() -> dict[str, Any]:
    """Sample AAS canonical claim for testing."""
    return {
        "name": "Alice Smith",
        "email": "alice@example.com", 
        "age": 30,
        "verified": True
    }


@pytest.fixture
def sample_issuer_keypair() -> tuple[SigningKey, str]:
    """Sample issuer keypair for testing."""
    signing_key = SigningKey.generate()
    did_key = generate_did_key(signing_key)
    return signing_key, did_key


def test_issue_jwt_vc_basic(sample_claim: dict[str, Any], sample_issuer_keypair: tuple[SigningKey, str]) -> None:
    """Test basic JWT VC issuance from AAS claim."""
    signing_key, issuer_did = sample_issuer_keypair
    subject_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    
    jwt_vc = issue_jwt_vc(
        claim=sample_claim,
        issuer_did=issuer_did,
        subject_did=subject_did,
        signing_key=signing_key,
        schema_id="test_schema_123"
    )
    
    assert isinstance(jwt_vc, str)
    assert jwt_vc.count('.') == 2  # JWT has 3 parts separated by dots
    
    # Should be decodable as JWT
    payload = parse_jwt_vc_payload(jwt_vc)
    assert payload["iss"] == issuer_did
    assert payload["sub"] == subject_did


def test_verify_jwt_vc_valid(sample_claim: dict[str, Any], sample_issuer_keypair: tuple[SigningKey, str]) -> None:
    """Test JWT VC verification with valid signature."""
    signing_key, issuer_did = sample_issuer_keypair
    subject_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    
    jwt_vc = issue_jwt_vc(
        claim=sample_claim,
        issuer_did=issuer_did,
        subject_did=subject_did,
        signing_key=signing_key
    )
    
    # Verification should succeed
    is_valid = verify_jwt_vc(jwt_vc, issuer_did)
    assert is_valid is True


def test_verify_jwt_vc_invalid_signature(sample_claim: dict[str, Any], sample_issuer_keypair: tuple[SigningKey, str]) -> None:
    """Test JWT VC verification with invalid signature."""
    signing_key, issuer_did = sample_issuer_keypair
    subject_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    
    jwt_vc = issue_jwt_vc(
        claim=sample_claim,
        issuer_did=issuer_did,
        subject_did=subject_did,
        signing_key=signing_key
    )
    
    # Verification with wrong issuer should fail
    wrong_signing_key = SigningKey.generate()
    wrong_issuer = generate_did_key(wrong_signing_key)
    is_valid = verify_jwt_vc(jwt_vc, wrong_issuer)
    assert is_valid is False


def test_extract_credentialsubject(sample_claim: dict[str, Any]) -> None:
    """Test mapping AAS claim to VC credentialSubject."""
    subject_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    
    credential_subject = extract_credentialsubject(sample_claim, subject_did)
    
    assert isinstance(credential_subject, dict)
    assert credential_subject["id"] == subject_did
    
    # Should contain original claim data
    assert credential_subject["name"] == sample_claim["name"]
    assert credential_subject["email"] == sample_claim["email"]
    assert credential_subject["age"] == sample_claim["age"]


def test_generate_salted_anchor() -> None:
    """Test privacy-preserving salted anchor generation."""
    claim = {"name": "Alice", "email": "alice@example.com"}
    
    # Generate multiple anchors for same claim
    anchor1 = generate_salted_anchor(claim)
    anchor2 = generate_salted_anchor(claim)
    
    assert isinstance(anchor1, str)
    assert isinstance(anchor2, str)
    assert len(anchor1) == 64  # SHA256 hex length
    assert len(anchor2) == 64
    
    # Should be different due to salting (non-deterministic)
    assert anchor1 != anchor2


def test_validate_vc_structure(sample_claim: dict[str, Any], sample_issuer_keypair: tuple[SigningKey, str]) -> None:
    """Test W3C VC 2.0 structure validation."""
    signing_key, issuer_did = sample_issuer_keypair
    subject_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    
    jwt_vc = issue_jwt_vc(
        claim=sample_claim,
        issuer_did=issuer_did,
        subject_did=subject_did,
        signing_key=signing_key
    )
    
    payload = parse_jwt_vc_payload(jwt_vc)
    vc_data = payload["vc"]
    
    # Should validate as proper W3C VC structure
    assert validate_vc_structure(vc_data) is True
    
    # Required fields should be present
    assert "@context" in vc_data
    assert "type" in vc_data
    assert "credentialSubject" in vc_data
    assert "issuer" in vc_data


def test_create_vc_credentialstatus() -> None:
    """Test credential status creation for AAS integration."""
    attestation_id = "test_attestation_123"
    
    credential_status = create_vc_credentialstatus(attestation_id)
    
    assert isinstance(credential_status, dict)
    assert credential_status["id"].endswith(attestation_id)
    assert credential_status["type"] == "AlgorandAttestationService2024"


def test_jwt_vc_expiration(sample_claim: dict[str, Any], sample_issuer_keypair: tuple[SigningKey, str]) -> None:
    """Test JWT VC with expiration time."""
    signing_key, issuer_did = sample_issuer_keypair
    subject_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    
    # Issue VC with explicit expiration
    exp_time = datetime.now(timezone.utc).timestamp() + 3600  # 1 hour from now
    
    jwt_vc = issue_jwt_vc(
        claim=sample_claim,
        issuer_did=issuer_did,
        subject_did=subject_did,
        signing_key=signing_key,
        exp=exp_time
    )
    
    payload = parse_jwt_vc_payload(jwt_vc)
    assert "exp" in payload
    assert payload["exp"] == exp_time


def test_jwt_vc_with_schema_reference(sample_claim: dict[str, Any], sample_issuer_keypair: tuple[SigningKey, str]) -> None:
    """Test JWT VC with credentialSchema reference."""
    signing_key, issuer_did = sample_issuer_keypair
    subject_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    schema_id = "test_schema_456"
    
    jwt_vc = issue_jwt_vc(
        claim=sample_claim,
        issuer_did=issuer_did,
        subject_did=subject_did,
        signing_key=signing_key,
        schema_id=schema_id
    )
    
    payload = parse_jwt_vc_payload(jwt_vc)
    vc_data = payload["vc"]
    
    assert "credentialSchema" in vc_data
    assert vc_data["credentialSchema"]["id"] == schema_id


def test_error_handling() -> None:
    """Test error handling for invalid inputs."""
    with pytest.raises(ValueError):
        issue_jwt_vc(
            claim={}, 
            issuer_did="invalid-did",
            subject_did="invalid-subject",
            signing_key=None  # type: ignore[arg-type]
        )
    
    with pytest.raises(ValueError):
        verify_jwt_vc("invalid.jwt.token", "did:key:validkey")
    
    with pytest.raises(ValueError):
        parse_jwt_vc_payload("not-a-jwt")


def test_jwt_algorithm_eddsa(sample_claim: dict[str, Any], sample_issuer_keypair: tuple[SigningKey, str]) -> None:
    """Test that JWT uses EdDSA algorithm as expected."""
    signing_key, issuer_did = sample_issuer_keypair
    subject_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    
    jwt_vc = issue_jwt_vc(
        claim=sample_claim,
        issuer_did=issuer_did,
        subject_did=subject_did,
        signing_key=signing_key
    )
    
    # Parse JWT header to check algorithm
    import jwt
    header = jwt.get_unverified_header(jwt_vc)
    assert header["alg"] == "EdDSA"
    assert header["typ"] == "JWT"


def test_vc_context_and_type(sample_claim: dict[str, Any], sample_issuer_keypair: tuple[SigningKey, str]) -> None:
    """Test W3C VC context and type fields are correctly set."""
    signing_key, issuer_did = sample_issuer_keypair
    subject_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    
    jwt_vc = issue_jwt_vc(
        claim=sample_claim,
        issuer_did=issuer_did,
        subject_did=subject_did,
        signing_key=signing_key
    )
    
    payload = parse_jwt_vc_payload(jwt_vc)
    vc_data = payload["vc"]
    
    # Check W3C VC context
    assert "https://www.w3.org/2018/credentials/v1" in vc_data["@context"]
    
    # Check type
    assert "VerifiableCredential" in vc_data["type"]
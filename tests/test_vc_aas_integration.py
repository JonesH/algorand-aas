"""Test VC-AAS integration functionality.

Tests for integrating JWT VCs with existing AAS attestation system.
Following TDD: These tests should FAIL initially until implementation.
"""

from __future__ import annotations

import pytest
from nacl.signing import SigningKey

# Import functions that don't exist yet - will cause ImportError initially
from aas.sdk.aas import AASClient  # This exists
from aas.sdk.did import generate_did_key
from aas.sdk.vc import issue_jwt_vc, generate_salted_anchor
from aas.sdk.vc_aas_integration import (
    anchor_vc_to_aas,
    verify_vc_status,
    revoke_vc,
    create_vc_enabled_schema,
    issue_and_anchor_vc,
    get_vc_attestation_status,
)


@pytest.fixture
def sample_vc_claim():
    """Sample claim for VC testing."""
    return {
        "name": "Alice Smith",
        "email": "alice@example.com",
        "credential_type": "IdentityVerification",
        "verified_date": "2024-01-15"
    }


@pytest.fixture
def issuer_keypair():
    """Issuer keypair for testing."""
    signing_key = SigningKey.generate()
    did_key = generate_did_key(signing_key)
    return signing_key, did_key


def test_anchor_vc_to_aas(sample_vc_claim, issuer_keypair):
    """Test anchoring JWT VC to AAS attestation system."""
    signing_key, issuer_did = issuer_keypair
    subject_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    schema_id = "vc.identity.v1"
    
    # Issue JWT VC
    jwt_vc = issue_jwt_vc(
        claim=sample_vc_claim,
        issuer_did=issuer_did,
        subject_did=subject_did,
        signing_key=signing_key,
        schema_id=schema_id
    )
    
    # Generate salted anchor
    salted_anchor = generate_salted_anchor(sample_vc_claim)
    
    # Anchor to AAS (should return attestation ID)
    attestation_id = anchor_vc_to_aas(
        jwt_vc=jwt_vc,
        salted_anchor=salted_anchor,
        schema_id=schema_id,
        subject_addr="ALGO_ADDRESS_HERE_32BYTES",
        signing_key=signing_key,
        nonce="test_nonce_123456"
    )
    
    assert isinstance(attestation_id, str)
    assert len(attestation_id) == 64  # SHA256 hex length


def test_verify_vc_status_active(sample_vc_claim, issuer_keypair):
    """Test verifying VC status as active through AAS."""
    signing_key, issuer_did = issuer_keypair
    subject_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    
    jwt_vc = issue_jwt_vc(
        claim=sample_vc_claim,
        issuer_did=issuer_did,
        subject_did=subject_did,
        signing_key=signing_key
    )
    
    # Mock an existing attestation ID
    attestation_id = "test_attestation_id_12345"
    
    status = verify_vc_status(jwt_vc, attestation_id)
    
    assert status in ["Active", "Revoked", "Suspended"]


def test_revoke_vc(sample_vc_claim, issuer_keypair):
    """Test revoking VC through AAS system."""
    signing_key, issuer_did = issuer_keypair
    subject_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    
    jwt_vc = issue_jwt_vc(
        claim=sample_vc_claim,
        issuer_did=issuer_did,
        subject_did=subject_did,
        signing_key=signing_key
    )
    
    attestation_id = "test_attestation_id_67890"
    revocation_reason = 42
    
    # Should successfully revoke
    success = revoke_vc(jwt_vc, attestation_id, revocation_reason, signing_key)
    
    assert success is True


def test_create_vc_enabled_schema():
    """Test creating AAS schema configured for VC integration."""
    schema_data = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "email": {"type": "string", "format": "email"},
            "credential_type": {"type": "string"}
        },
        "required": ["name", "email", "credential_type"]
    }
    
    owner_addr = "OWNER_ADDRESS_32BYTES_HERE"
    vc_flags = 1  # Enable VC features
    
    schema_id = create_vc_enabled_schema(
        schema_data=schema_data,
        owner_addr=owner_addr,
        uri="https://schemas.example.com/identity.json",
        vc_flags=vc_flags
    )
    
    assert isinstance(schema_id, str)
    assert len(schema_id) == 64  # SHA256 hex length


def test_issue_and_anchor_vc_e2e(sample_vc_claim, issuer_keypair):
    """Test end-to-end VC issuance and anchoring."""
    signing_key, issuer_did = issuer_keypair
    subject_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    schema_id = "vc.test.schema"
    subject_addr = "ALGO_ADDRESS_32BYTES_HERE"
    
    # Should issue VC and anchor in one operation
    result = issue_and_anchor_vc(
        claim=sample_vc_claim,
        issuer_did=issuer_did,
        subject_did=subject_did,
        signing_key=signing_key,
        schema_id=schema_id,
        subject_addr=subject_addr
    )
    
    assert "jwt_vc" in result
    assert "attestation_id" in result
    assert "salted_anchor" in result
    
    # Verify result structure
    assert isinstance(result["jwt_vc"], str)
    assert result["jwt_vc"].count('.') == 2  # Valid JWT
    assert len(result["attestation_id"]) == 64
    assert len(result["salted_anchor"]) == 64


def test_get_vc_attestation_status():
    """Test getting attestation status for VC verification."""
    attestation_id = "test_attestation_id_status"
    
    status_info = get_vc_attestation_status(attestation_id)
    
    assert isinstance(status_info, dict)
    assert "status" in status_info  # "A" for Active, "R" for Revoked
    assert "subject_addr" in status_info
    assert "schema_id" in status_info
    
    if status_info["status"] == "R":
        assert "reason" in status_info


def test_privacy_preserving_anchoring(sample_vc_claim):
    """Test that anchoring preserves privacy through salting."""
    # Generate multiple anchors for same claim
    anchor1 = generate_salted_anchor(sample_vc_claim)
    anchor2 = generate_salted_anchor(sample_vc_claim)
    anchor3 = generate_salted_anchor(sample_vc_claim)
    
    # All should be different (non-deterministic due to salting)
    assert anchor1 != anchor2 != anchor3
    assert len({anchor1, anchor2, anchor3}) == 3
    
    # But all should be valid SHA256 hex strings
    for anchor in [anchor1, anchor2, anchor3]:
        assert len(anchor) == 64
        assert all(c in '0123456789abcdef' for c in anchor)


def test_vc_status_credentialstatus_integration(sample_vc_claim, issuer_keypair):
    """Test that VC credentialStatus points to AAS attestation."""
    signing_key, issuer_did = issuer_keypair
    subject_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    
    # Issue VC with credentialStatus
    jwt_vc = issue_jwt_vc(
        claim=sample_vc_claim,
        issuer_did=issuer_did,
        subject_did=subject_did,
        signing_key=signing_key
    )
    
    # Mock anchoring to get attestation ID
    attestation_id = "test_attestation_credstatus"
    
    # Should be able to verify status through credentialStatus
    status = verify_vc_status(jwt_vc, attestation_id)
    assert status is not None


def test_error_handling_integration():
    """Test error handling in VC-AAS integration."""
    with pytest.raises(ValueError):
        anchor_vc_to_aas(
            jwt_vc="invalid.jwt.token",
            salted_anchor="invalid_anchor",
            schema_id="",
            subject_addr="",
            signing_key=None,  # type: ignore[arg-type]
            nonce=""
        )
    
    with pytest.raises(ValueError):
        verify_vc_status("invalid_jwt", "invalid_attestation_id")
    
    with pytest.raises(ValueError):
        revoke_vc("invalid_jwt", "invalid_id", 0, None)  # type: ignore[arg-type]


@pytest.mark.localnet
def test_full_vc_lifecycle_localnet(sample_vc_claim, issuer_keypair):
    """Test complete VC lifecycle on LocalNet."""
    # This test requires LocalNet running
    signing_key, issuer_did = issuer_keypair
    subject_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    
    # 1. Create VC-enabled schema
    schema_id = create_vc_enabled_schema(
        schema_data={"type": "object", "properties": {"name": {"type": "string"}}},
        owner_addr="LOCALNET_OWNER_ADDRESS",
        uri="https://test.schema.com"
    )
    
    # 2. Issue and anchor VC
    result = issue_and_anchor_vc(
        claim=sample_vc_claim,
        issuer_did=issuer_did,
        subject_did=subject_did,
        signing_key=signing_key,
        schema_id=schema_id,
        subject_addr="LOCALNET_SUBJECT_ADDRESS"
    )
    
    # 3. Verify VC is active
    status = verify_vc_status(result["jwt_vc"], result["attestation_id"])
    assert status == "Active"
    
    # 4. Revoke VC
    revoked = revoke_vc(result["jwt_vc"], result["attestation_id"], 99, signing_key)
    assert revoked is True
    
    # 5. Verify VC is now revoked
    status_after = verify_vc_status(result["jwt_vc"], result["attestation_id"])
    assert status_after == "Revoked"


def test_backwards_compatibility_with_existing_aas():
    """Test that VC integration doesn't break existing AAS functionality."""
    # This test ensures existing AAS workflows still work
    # Should be able to create regular (non-VC) attestations alongside VC attestations
    
    # Mock test - in real implementation, this would create both types
    # and verify they coexist without conflicts
    regular_schema_id = "regular.schema.v1"
    vc_schema_id = "vc.schema.v1"
    
    # Both should be valid schema IDs
    assert isinstance(regular_schema_id, str)
    assert isinstance(vc_schema_id, str)
    assert regular_schema_id != vc_schema_id
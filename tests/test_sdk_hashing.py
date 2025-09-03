"""Test SDK hashing functionality.

Ensures canonical JSON hashing is stable and deterministic.
Step 0 requirement: Assert canonical JSON hashing is stable.
"""

from __future__ import annotations

import pytest

from aas.sdk.hashing import (
    canonical_json_hash,
    generate_schema_id, 
    generate_claim_hash,
    generate_attestation_id,
    sign_message,
    verify_signature
)


def test_canonical_json_hash_deterministic() -> None:
    """Test that canonical JSON hashing is deterministic."""
    data1 = {"name": "test", "value": 42}
    data2 = {"value": 42, "name": "test"}  # Different order
    
    hash1 = canonical_json_hash(data1)
    hash2 = canonical_json_hash(data2)
    
    # Should be identical despite different input order
    assert hash1 == hash2
    assert len(hash1) == 64  # SHA256 hex length


def test_canonical_json_hash_stable() -> None:
    """Test that canonical JSON hashing produces stable results."""
    data = {"schema": "user", "fields": ["name", "email"]}
    
    expected_hash = canonical_json_hash(data)
    
    # Multiple calls should return same hash
    for _ in range(5):
        assert canonical_json_hash(data) == expected_hash


def test_generate_schema_id() -> None:
    """Test schema ID generation."""
    schema_data = {"type": "object", "properties": {"name": {"type": "string"}}}
    
    schema_id = generate_schema_id(schema_data)
    
    assert schema_id is not None
    assert len(schema_id) == 64
    assert schema_id == canonical_json_hash(schema_data)


def test_generate_claim_hash() -> None:
    """Test claim hash generation."""
    claim_data = {"name": "Alice", "email": "alice@example.com"}
    
    claim_hash = generate_claim_hash(claim_data)
    
    assert claim_hash is not None
    assert len(claim_hash) == 64
    assert claim_hash == canonical_json_hash(claim_data)


def test_generate_attestation_id() -> None:
    """Test attestation ID generation."""
    schema_id = "a1b2c3"
    subject = "ADDR123"
    claim_hash = "d4e5f6"
    nonce = "nonce123"
    
    att_id = generate_attestation_id(schema_id, subject, claim_hash, nonce)
    
    assert att_id is not None
    assert len(att_id) == 64
    
    # Should be deterministic
    att_id2 = generate_attestation_id(schema_id, subject, claim_hash, nonce)
    assert att_id == att_id2


def test_empty_data_raises_error() -> None:
    """Test that empty data raises ValueError."""
    with pytest.raises(ValueError, match="Data cannot be empty"):
        canonical_json_hash({})


def test_sign_message() -> None:
    """Test ed25519 message signing."""
    from nacl.signing import SigningKey
    
    # Generate signing key
    signing_key = SigningKey.generate()
    
    # Test data
    schema_id = "test_schema_123"
    subject = "ADDR" + "1" * 28  # 32-byte address format
    claim_hash = "a" * 64  # 32-byte hash as hex
    nonce = "n" * 64  # 32-byte nonce as hex
    
    # Sign message
    signature_hex = sign_message(signing_key, schema_id, subject, claim_hash, nonce)
    
    # Verify signature format
    assert signature_hex is not None
    assert len(signature_hex) == 128  # 64 bytes as hex
    assert all(c in '0123456789abcdef' for c in signature_hex)


def test_verify_signature() -> None:
    """Test ed25519 signature verification."""
    from nacl.signing import SigningKey
    
    # Generate key pair
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    
    # Test data
    schema_id = "test_schema_456" 
    subject = "ADDR" + "2" * 28
    claim_hash = "b" * 64
    nonce = "m" * 64
    
    # Sign message
    signature_hex = sign_message(signing_key, schema_id, subject, claim_hash, nonce)
    
    # Verify signature (should pass)
    is_valid = verify_signature(verify_key, signature_hex, schema_id, subject, claim_hash, nonce)
    assert is_valid is True
    
    # Verify with wrong data (should fail)
    is_valid_wrong = verify_signature(verify_key, signature_hex, "wrong_schema", subject, claim_hash, nonce)
    assert is_valid_wrong is False


def test_sign_verify_round_trip() -> None:
    """Test complete sign/verify round trip."""
    from nacl.signing import SigningKey
    
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    
    # Multiple test cases
    test_cases = [
        ("schema1", "ADDR111", "hash1", "nonce1"),
        ("schema2", "ADDR222", "hash2", "nonce2"),
        ("complex_schema_id", "LONG_ADDRESS_HERE_123456", "complex_hash_here", "complex_nonce")
    ]
    
    for schema_id, subject, claim_hash, nonce in test_cases:
        signature = sign_message(signing_key, schema_id, subject, claim_hash, nonce)
        is_valid = verify_signature(verify_key, signature, schema_id, subject, claim_hash, nonce)
        assert is_valid is True


def test_invalid_signature_format() -> None:
    """Test verification with invalid signature format."""
    from nacl.signing import SigningKey
    
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    
    # Test with invalid signature formats
    invalid_signatures = [
        "too_short",
        "x" * 130,  # Too long
        "g" * 128,  # Invalid hex character
    ]
    
    for invalid_sig in invalid_signatures:
        is_valid = verify_signature(verify_key, invalid_sig, "schema", "subject", "hash", "nonce")
        assert is_valid is False
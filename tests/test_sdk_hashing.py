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
    generate_attestation_id
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
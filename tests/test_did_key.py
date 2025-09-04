"""Test DID key functionality.

Tests for W3C DID did:key generation, parsing, and resolution.
Following TDD: These tests should FAIL initially until implementation.
"""

from __future__ import annotations

import pytest
from nacl.signing import SigningKey, VerifyKey

# Import functions that don't exist yet - will cause ImportError initially
from aas.sdk.did import (
    generate_did_key,
    did_key_to_public_key,
    resolve_did_document,
    generate_ed25519_keypair,
    validate_did_key_format,
)


def test_generate_ed25519_keypair() -> None:
    """Test Ed25519 keypair generation for DID keys."""
    signing_key, did_key = generate_ed25519_keypair()
    
    # Should return nacl SigningKey and did:key string
    assert isinstance(signing_key, SigningKey)
    assert isinstance(did_key, str)
    
    # DID key should have proper format
    assert did_key.startswith("did:key:z6Mk")
    assert len(did_key) > 50  # Reasonable length for base58 encoded key


def test_generate_did_key_from_signing_key() -> None:
    """Test generating did:key from existing SigningKey."""
    signing_key = SigningKey.generate()
    
    did_key = generate_did_key(signing_key)
    
    assert isinstance(did_key, str)
    assert did_key.startswith("did:key:z6Mk")
    
    # Should be deterministic - same key gives same DID
    did_key2 = generate_did_key(signing_key)
    assert did_key == did_key2


def test_did_key_to_public_key() -> None:
    """Test parsing did:key back to VerifyKey."""
    # Generate a keypair first
    signing_key, did_key = generate_ed25519_keypair()
    
    # Parse back to public key
    verify_key = did_key_to_public_key(did_key)
    
    assert isinstance(verify_key, VerifyKey)
    assert verify_key == signing_key.verify_key


def test_validate_did_key_format() -> None:
    """Test DID key format validation."""
    # Valid did:key
    signing_key, did_key = generate_ed25519_keypair()
    assert validate_did_key_format(did_key) is True
    
    # Invalid formats
    assert validate_did_key_format("not-a-did") is False
    assert validate_did_key_format("did:key:invalid") is False
    assert validate_did_key_format("did:web:example.com") is False
    assert validate_did_key_format("") is False


def test_resolve_did_document() -> None:
    """Test DID document generation from did:key."""
    signing_key, did_key = generate_ed25519_keypair()
    
    did_doc = resolve_did_document(did_key)
    
    # Should be a dictionary with W3C DID structure
    assert isinstance(did_doc, dict)
    
    # Required DID document fields
    assert did_doc["id"] == did_key
    assert "@context" in did_doc
    assert "verificationMethod" in did_doc
    assert "authentication" in did_doc
    
    # Verification method should contain Ed25519 key
    vm = did_doc["verificationMethod"][0]
    assert vm["id"] == f"{did_key}#{did_key.split(':')[-1]}"
    assert vm["type"] == "Ed25519VerificationKey2020"
    assert vm["controller"] == did_key
    assert "publicKeyMultibase" in vm


def test_multibase_encoding_correctness() -> None:
    """Test that multibase encoding follows did:key specification."""
    signing_key = SigningKey.generate()
    did_key = generate_did_key(signing_key)
    
    # Extract the multibase part (after 'did:key:')
    multibase_key = did_key[8:]  # Remove 'did:key:' prefix
    
    # Should start with 'z' (base58btc encoding)
    assert multibase_key.startswith('z6Mk')
    
    # Should be valid base58 characters
    base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    for char in multibase_key[1:]:  # Skip the 'z' prefix
        assert char in base58_chars


def test_round_trip_consistency() -> None:
    """Test that key -> did:key -> key round trip is consistent."""
    # Start with a known signing key
    signing_key = SigningKey.generate()
    original_public_key = bytes(signing_key.verify_key)
    
    # Convert to did:key
    did_key = generate_did_key(signing_key)
    
    # Parse back to public key
    recovered_verify_key = did_key_to_public_key(did_key)
    recovered_public_key = bytes(recovered_verify_key)
    
    # Should be identical
    assert original_public_key == recovered_public_key


def test_error_handling() -> None:
    """Test error handling for invalid inputs."""
    with pytest.raises(ValueError):
        generate_did_key(None)  # type: ignore[arg-type]
    
    with pytest.raises(ValueError):
        did_key_to_public_key("invalid-did-key")
    
    with pytest.raises(ValueError):
        resolve_did_document("not-a-did-key")


def test_deterministic_generation() -> None:
    """Test that DID generation is deterministic for same key."""
    # Create same key twice using same seed
    seed = b"x" * 32  # Fixed seed for deterministic key generation
    
    signing_key1 = SigningKey(seed)
    signing_key2 = SigningKey(seed)
    
    did_key1 = generate_did_key(signing_key1)
    did_key2 = generate_did_key(signing_key2)
    
    assert did_key1 == did_key2


def test_multiple_keys_different_dids() -> None:
    """Test that different keys produce different DIDs."""
    signing_key1 = SigningKey.generate()
    signing_key2 = SigningKey.generate()
    
    did_key1 = generate_did_key(signing_key1)
    did_key2 = generate_did_key(signing_key2)
    
    assert did_key1 != did_key2
    assert did_key1.startswith("did:key:z6Mk")
    assert did_key2.startswith("did:key:z6Mk")
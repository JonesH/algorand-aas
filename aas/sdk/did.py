"""DID key generation and resolution.

W3C DID did:key implementation for Ed25519 keys.
Follows KISS principle with functions ≤10 lines.
"""

from __future__ import annotations

from typing import Any

import multibase
from nacl.signing import SigningKey, VerifyKey


def generate_ed25519_keypair() -> tuple[SigningKey, str]:
    """Generate Ed25519 keypair and return signing key and did:key."""
    signing_key = SigningKey.generate()
    did_key = generate_did_key(signing_key)
    return signing_key, did_key


def generate_did_key(signing_key: SigningKey) -> str:
    """Generate did:key from Ed25519 SigningKey."""
    if not signing_key:
        raise ValueError("Signing key is required")
    
    public_key_bytes = bytes(signing_key.verify_key)
    multicodec_ed25519 = _build_multicodec_key(public_key_bytes)
    multibase_key = multibase.encode('base58btc', multicodec_ed25519)
    return f"did:key:{multibase_key.decode('utf-8')}"


def did_key_to_public_key(did_key: str) -> VerifyKey:
    """Parse did:key back to VerifyKey."""
    if not validate_did_key_format(did_key):
        raise ValueError(f"Invalid did:key format: {did_key}")
    
    multibase_key = did_key[8:]  # Remove 'did:key:' prefix
    multicodec_bytes = multibase.decode(multibase_key)
    public_key_bytes = _extract_public_key_from_multicodec(multicodec_bytes)
    return VerifyKey(public_key_bytes)


def validate_did_key_format(did_key: str) -> bool:
    """Validate did:key format."""
    if not isinstance(did_key, str) or not did_key:
        return False
    
    if not did_key.startswith("did:key:z6Mk"):
        return False
    
    try:
        multibase.decode(did_key[8:])
        return True
    except Exception:
        return False


def resolve_did_document(did_key: str) -> dict[str, Any]:
    """Generate DID document from did:key."""
    if not validate_did_key_format(did_key):
        raise ValueError(f"Invalid did:key: {did_key}")
    
    key_id = f"{did_key}#{did_key.split(':')[-1]}"
    multibase_key = did_key[8:]  # Remove 'did:key:' prefix
    
    return _build_did_document(did_key, key_id, multibase_key)


def _build_multicodec_key(public_key_bytes: bytes) -> bytes:
    """Build multicodec key with Ed25519 prefix."""
    ed25519_multicodec = b'\xed\x01'  # Ed25519 multicodec prefix
    return ed25519_multicodec + public_key_bytes


def _extract_public_key_from_multicodec(multicodec_bytes: bytes) -> bytes:
    """Extract public key bytes from multicodec format."""
    if len(multicodec_bytes) < 34 or multicodec_bytes[:2] != b'\xed\x01':
        raise ValueError("Invalid Ed25519 multicodec format")
    return multicodec_bytes[2:]  # Skip the 2-byte prefix


def _build_did_document(did_key: str, key_id: str, multibase_key: str) -> dict[str, Any]:
    """Build W3C DID document structure."""
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": did_key,
        "verificationMethod": [{
            "id": key_id,
            "type": "Ed25519VerificationKey2020", 
            "controller": did_key,
            "publicKeyMultibase": multibase_key
        }],
        "authentication": [key_id],
        "assertionMethod": [key_id]
    }
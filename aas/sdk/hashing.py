"""Canonical JSON hashing and cryptographic utilities.

Provides deterministic ID generation for schemas and attestations.
Implements ed25519 signing and verification.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from nacl.signing import SigningKey, VerifyKey


def canonical_json_hash(data: dict[str, Any]) -> str:
    """Generate deterministic SHA256 hash from canonical JSON.
    
    Args:
        data: Dictionary to hash
        
    Returns:
        Hex-encoded SHA256 hash
    """
    if not data:
        raise ValueError("Data cannot be empty")
    canonical_json = json.dumps(data, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()


def generate_schema_id(schema_data: dict[str, Any]) -> str:
    """Generate deterministic schema ID from schema JSON."""
    return canonical_json_hash(schema_data)


def generate_claim_hash(claim_data: dict[str, Any]) -> str:
    """Generate deterministic claim hash from claim JSON.""" 
    return canonical_json_hash(claim_data)


def generate_attestation_id(schema_id: str, subject: str, claim_hash: str, nonce: str) -> str:
    """Generate deterministic attestation ID."""
    message = _build_message(schema_id, subject, claim_hash, nonce)
    return hashlib.sha256(message).hexdigest()


def _build_message(schema_id: str, subject: str, claim_hash: str, nonce: str) -> bytes:
    """Build canonical message for signing and ID generation."""
    message = f"{schema_id}|{subject}|{claim_hash}|{nonce}"
    return message.encode('utf-8')


def sign_message(signing_key: SigningKey, schema_id: str, subject: str, claim_hash: str, nonce: str) -> str:
    """Sign attestation message with ed25519."""
    if not signing_key:
        raise ValueError("Signing key is required")
    
    message = _build_message(schema_id, subject, claim_hash, nonce)
    signed = signing_key.sign(message)
    return signed.signature.hex()


def verify_signature(verify_key: VerifyKey, signature_hex: str, schema_id: str, subject: str, claim_hash: str, nonce: str) -> bool:
    """Verify ed25519 signature."""
    if not verify_key or not signature_hex:
        return False
    
    try:
        signature_bytes = bytes.fromhex(signature_hex)
        message = _build_message(schema_id, subject, claim_hash, nonce)
        verify_key.verify(message, signature_bytes)
        return True
    except Exception:
        return False
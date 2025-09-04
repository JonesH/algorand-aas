"""JWT Verifiable Credentials implementation.

W3C VC 2.0 compliant JWT VC issuance and verification.
Follows KISS principle with functions ≤10 lines.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timezone
from typing import Any

import jwt
from nacl.signing import SigningKey

from aas.sdk.did import did_key_to_public_key


def issue_jwt_vc(
    claim: dict[str, Any],
    issuer_did: str,
    subject_did: str,
    signing_key: SigningKey,
    schema_id: str | None = None,
    exp: float | None = None
) -> str:
    """Issue JWT VC from AAS canonical claim."""
    if not claim or not issuer_did or not subject_did or not signing_key:
        raise ValueError("All parameters required for VC issuance")
    
    vc_data = _build_vc_data(claim, issuer_did, subject_did, schema_id)
    jwt_payload = _build_jwt_payload(vc_data, issuer_did, subject_did, exp)
    private_key_pem = _signing_key_to_pem(signing_key)
    return jwt.encode(jwt_payload, private_key_pem, algorithm="EdDSA")


def verify_jwt_vc(jwt_vc: str, expected_issuer_did: str) -> bool:
    """Verify JWT VC signature and structure."""
    if not isinstance(jwt_vc, str) or jwt_vc.count('.') != 2:
        raise ValueError("Invalid JWT format")
    
    try:
        public_key = did_key_to_public_key(expected_issuer_did)
        public_key_pem = _verify_key_to_pem(public_key)
        jwt.decode(jwt_vc, public_key_pem, algorithms=["EdDSA"])
        return True
    except ValueError:
        raise  # Re-raise ValueError from did_key_to_public_key or JWT parsing
    except Exception:
        return False


def parse_jwt_vc_payload(jwt_vc: str) -> dict[str, Any]:
    """Parse JWT VC payload without verification."""
    try:
        return jwt.decode(jwt_vc, options={"verify_signature": False})  # type: ignore[no-any-return]
    except Exception:
        raise ValueError("Invalid JWT format")


def extract_credentialsubject(claim: dict[str, Any], subject_did: str) -> dict[str, Any]:
    """Map AAS claim to W3C VC credentialSubject."""
    credential_subject = {"id": subject_did}
    credential_subject.update(claim)
    return credential_subject


def generate_salted_anchor(claim: dict[str, Any]) -> str:
    """Generate privacy-preserving salted anchor for AAS."""
    salt = secrets.token_bytes(32)
    canonical_json = json.dumps(claim, sort_keys=True, separators=(',', ':'))
    message = salt + canonical_json.encode('utf-8')
    return hashlib.sha256(message).hexdigest()


def validate_vc_structure(vc_data: dict[str, Any]) -> bool:
    """Validate W3C VC 2.0 structure."""
    required_fields = ["@context", "type", "credentialSubject", "issuer"]
    return all(field in vc_data for field in required_fields)


def create_vc_credentialstatus(attestation_id: str) -> dict[str, Any]:
    """Create credentialStatus for AAS integration."""
    return {
        "id": f"https://aas.example.com/status/{attestation_id}",
        "type": "AlgorandAttestationService2024"
    }


def _build_vc_data(
    claim: dict[str, Any], 
    issuer_did: str, 
    subject_did: str, 
    schema_id: str | None
) -> dict[str, Any]:
    """Build W3C VC data structure."""
    vc_data = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential"],
        "issuer": issuer_did,
        "credentialSubject": extract_credentialsubject(claim, subject_did)
    }
    
    if schema_id:
        vc_data["credentialSchema"] = {"id": schema_id, "type": "JsonSchemaValidator2018"}
    
    return vc_data


def _build_jwt_payload(
    vc_data: dict[str, Any], 
    issuer_did: str, 
    subject_did: str, 
    exp: float | None
) -> dict[str, Any]:
    """Build JWT payload with VC data."""
    now = datetime.now(timezone.utc)
    payload = {
        "vc": vc_data,
        "iss": issuer_did,
        "sub": subject_did,
        "iat": now.timestamp(),
        "jti": secrets.token_urlsafe(16)
    }
    
    if exp:
        payload["exp"] = exp
    
    return payload


def _signing_key_to_pem(signing_key: SigningKey) -> bytes:
    """Convert nacl SigningKey to PEM format for JWT."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    
    private_key_bytes = bytes(signing_key)
    crypto_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return crypto_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def _verify_key_to_pem(verify_key) -> bytes:  # type: ignore[no-untyped-def]
    """Convert nacl VerifyKey to PEM format for JWT."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    
    public_key_bytes = bytes(verify_key)
    crypto_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    return crypto_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
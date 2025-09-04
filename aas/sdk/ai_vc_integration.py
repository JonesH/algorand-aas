"""AI VC provenance integration.

Integrates AI inference canonical claims with W3C Verifiable Credentials.
Follows KISS principle with functions ≤10 lines.
"""

from __future__ import annotations

from typing import Any
from nacl.signing import SigningKey

from aas.sdk.vc import verify_jwt_vc, generate_salted_anchor, _build_jwt_payload, _signing_key_to_pem, extract_credentialsubject
from aas.sdk.vc_aas_integration import anchor_vc_to_aas, verify_vc_status


def map_ai_claim_to_vc_subject(ai_claim: dict[str, Any]) -> dict[str, Any]:
    """Map AI inference claim to VC credentialSubject format."""
    if not ai_claim:
        raise ValueError("AI claim is required")
    
    if ai_claim.get("schema_version") != "ai.inference.v1":
        raise ValueError("Invalid AI schema version")
    
    # Create VC subject from AI claim
    vc_subject = ai_claim.copy()
    vc_subject["@type"] = ["AIInferenceCredential", "VerifiableCredential"]
    vc_subject["id"] = f"ai-inference-{hash(str(ai_claim))}"  # Simple ID generation
    return vc_subject


def issue_ai_inference_vc(
    ai_claim: dict[str, Any],
    issuer_did: str,
    subject_did: str,
    signing_key: SigningKey,
    schema_id: str | None = None,
    exp: float | None = None
) -> str:
    """Issue AI inference VC from canonical claim."""
    if not ai_claim or not issuer_did or not subject_did or not signing_key:
        raise ValueError("All parameters required for AI VC issuance")
    
    vc_subject = map_ai_claim_to_vc_subject(ai_claim)
    vc_data = _build_ai_vc_data(vc_subject, issuer_did, subject_did, schema_id)
    jwt_payload = _build_jwt_payload(vc_data, issuer_did, subject_did, exp)
    
    import jwt
    private_key_pem = _signing_key_to_pem(signing_key)
    return jwt.encode(jwt_payload, private_key_pem, algorithm="EdDSA")


def verify_ai_inference_vc(jwt_vc: str, issuer_did: str) -> bool:
    """Verify AI inference VC signature and format."""
    if not jwt_vc or not issuer_did:
        return False
    
    return verify_jwt_vc(jwt_vc, issuer_did)


def anchor_ai_vc_to_aas(
    jwt_vc: str,
    schema_id: str,
    subject_addr: str,
    signing_key: SigningKey,
    nonce: str | None = None
) -> str:
    """Anchor AI inference VC to AAS attestation system."""
    if not jwt_vc or not schema_id or not subject_addr or not signing_key:
        raise ValueError("All parameters required for AI VC anchoring")
    
    # Generate salted anchor from VC for privacy
    from aas.sdk.vc import parse_jwt_vc_payload
    payload = parse_jwt_vc_payload(jwt_vc)
    claim = payload.get("vc", {}).get("credentialSubject", {})
    salted_anchor = generate_salted_anchor(claim)
    
    return anchor_vc_to_aas(jwt_vc, salted_anchor, schema_id, subject_addr, signing_key, nonce)


def get_ai_vc_status(attestation_id: str) -> str:
    """Get AI VC status through AAS."""
    if not attestation_id:
        return "unknown"
    
    # Use real VC status verification - need to create a dummy JWT VC for interface compatibility
    dummy_jwt_vc = _create_dummy_jwt_vc()
    return verify_vc_status(dummy_jwt_vc, attestation_id)


def _create_dummy_jwt_vc() -> str:
    """Create minimal JWT VC for status checking interface."""
    # Import here to avoid circular imports
    import jwt
    
    # Create minimal JWT payload for status checking
    payload = {
        "vc": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "issuer": "did:key:status-check",
            "credentialSubject": {"id": "status-check"}
        }
    }
    
    # Create unsigned JWT for status checking (no key needed for algorithm="none")
    return jwt.encode(payload, None, algorithm="none")


def _build_ai_vc_data(
    claim: dict[str, Any], 
    issuer_did: str, 
    subject_did: str, 
    schema_id: str | None
) -> dict[str, Any]:
    """Build AI-specific W3C VC data structure."""
    vc_data = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "AIInferenceCredential"],
        "issuer": issuer_did,
        "credentialSubject": extract_credentialsubject(claim, subject_did)
    }
    
    if schema_id:
        vc_data["credentialSchema"] = {"id": schema_id, "type": "JsonSchemaValidator2018"}
    
    return vc_data
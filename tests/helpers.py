"""Test helper functions for DRY code and simplified test patterns.

Provides reusable utilities for LocalNet integration tests to reduce duplication
and improve test clarity following KISS principles.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Generator

from algosdk import encoding
from algosdk.atomic_transaction_composer import AccountTransactionSigner
from algosdk.kmd import KMDClient
from algosdk.v2client.algod import AlgodClient
from beaker.client import ApplicationClient
from nacl.signing import SigningKey

from aas.contracts.aas import AASApplication


def build_attestation_message(schema_id: bytes, subject_addr: str, claim_hash: bytes, nonce: bytes) -> bytes:
    """Build canonical message for attestation signing and ID generation."""
    subject_bytes = encoding.decode_address(subject_addr)
    return schema_id + subject_bytes + claim_hash + nonce


def generate_attestation_id(schema_id: bytes, subject_addr: str, claim_hash: bytes, nonce: bytes) -> bytes:
    """Generate deterministic attestation ID from message components."""
    message = build_attestation_message(schema_id, subject_addr, claim_hash, nonce)
    return hashlib.sha256(message).digest()


def create_schema_helper(
    client: ApplicationClient, 
    signer: AccountTransactionSigner,
    schema_id: bytes, 
    owner: str, 
    uri: str = "test-schema",
    flags: int = 1
) -> None:
    """Create schema with standard parameters."""
    schema_box = (client.app_id, b"schema:" + schema_id)
    client.call(
        AASApplication.create_schema,
        schema_id=schema_id,
        owner=owner,
        uri=uri,
        flags=flags,
        boxes=[schema_box],
        signer=signer,
    )


def grant_attester_helper(
    client: ApplicationClient,
    signer: AccountTransactionSigner, 
    schema_id: bytes,
    attester_pk: bytes
) -> None:
    """Grant attester with standard box setup."""
    schema_box = (client.app_id, b"schema:" + schema_id)
    att_box = (client.app_id, b"attesters:" + schema_id)
    client.call(
        AASApplication.grant_attester,
        schema_id=schema_id,
        attester_pk=attester_pk,
        boxes=[schema_box, att_box],
        signer=signer,
    )


def create_attestation_helper(
    client: ApplicationClient,
    signer: AccountTransactionSigner,
    schema_id: bytes,
    subject_addr: str,
    claim_hash: bytes,
    nonce: bytes,
    attester_sk: SigningKey,
    cid: str = "QmTest"
) -> bytes:
    """Create attestation and return attestation ID."""
    # Sign message
    message = build_attestation_message(schema_id, subject_addr, claim_hash, nonce)
    signature = bytes(attester_sk.sign(message).signature)
    attester_pk = bytes(attester_sk.verify_key)
    
    # Generate attestation ID
    att_id = generate_attestation_id(schema_id, subject_addr, claim_hash, nonce)
    
    # Prepare boxes
    schema_box = (client.app_id, b"schema:" + schema_id)
    att_box = (client.app_id, b"attesters:" + schema_id)
    att_storage_box = (client.app_id, b"att:" + att_id)
    
    # Call attest
    client.call(
        AASApplication.attest,
        schema_id=schema_id,
        subject_addr=subject_addr,
        claim_hash_32=claim_hash,
        nonce_32=nonce,
        sig_64=signature,
        cid=cid,
        attester_pk=attester_pk,
        boxes=[schema_box, att_box, att_storage_box],
        signer=signer,
    )
    
    return att_id


def parse_attestation_box(algod_client: AlgodClient, app_id: int, att_id: bytes) -> dict:
    """Parse attestation box data into structured format."""
    box_value = algod_client.application_box_by_name(app_id, b"att:" + att_id)["value"]  # type: ignore[call-overload]
    data = base64.b64decode(box_value)
    
    # Parse format: status(1B) + subject(32B) + schema_id_len(8B) + schema_id + cid
    status = data[0:1].decode('utf-8')
    subject_bytes = data[1:33]
    subject_addr = encoding.encode_address(subject_bytes)
    schema_id_len = int.from_bytes(data[33:41], 'big')
    schema_id = data[41:41+schema_id_len]
    cid = data[41+schema_id_len:-8].decode('utf-8') if len(data) > 41+schema_id_len+8 else ""
    
    # Check for revocation reason (last 8 bytes if status is 'R')
    reason = None
    if status == 'R' and len(data) >= 8:
        reason = int.from_bytes(data[-8:], 'big')
    
    return {
        'status': status,
        'subject_addr': subject_addr,  
        'schema_id': schema_id,
        'cid': cid,
        'reason': reason
    }


def create_unauthorized_signer(
    algod_client: AlgodClient,
    exclude_addr: str | None = None
) -> Generator[tuple[AccountTransactionSigner, str], None, None]:
    """Create funded unauthorized signer from different LocalNet account."""
    kmd = KMDClient(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "http://localhost:4002",
    )
    wallets = kmd.list_wallets()
    wallet = next((w for w in wallets if w["name"] == "unencrypted-default-wallet"), None)
    if not wallet:
        raise Exception("LocalNet wallet not found")
    
    handle = kmd.init_wallet_handle(wallet["id"], "")
    try:
        addrs = kmd.list_keys(handle)
        # Pick different address than exclude_addr
        target_addr = next((a for a in addrs if a != exclude_addr), addrs[0])
        target_sk = kmd.export_key(handle, "", target_addr)
        yield AccountTransactionSigner(target_sk), target_addr
    finally:
        kmd.release_wallet_handle(handle)
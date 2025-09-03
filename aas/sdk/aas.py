"""Core AAS SDK functionality.

Provides high-level interface for interacting with Algorand AAS smart contract.
Handles schema creation, attestation writing, and verification.
"""

from __future__ import annotations

from algosdk.v2client import algod
from algosdk import encoding, transaction
from algosdk.atomic_transaction_composer import AccountTransactionSigner
from beaker.client import ApplicationClient
import base64
import hashlib

from aas.contracts.aas import AASApplication, get_app
from aas.sdk.hashing import generate_schema_id, generate_claim_hash
from aas.sdk.models import Attestation, AttestationStatus



class AASClient:
    """High-level client for Algorand Attestation Service."""
    
    def __init__(self, algod_client: algod.AlgodClient, app_id: int | None = None):
        """Initialize AAS client.
        
        Args:
            algod_client: Algorand client
            app_id: AAS application ID (if deployed)
        """
        if not algod_client:
            raise ValueError("Algod client is required")
            
        self.algod_client = algod_client
        self.app_id = app_id
        self.signer: AccountTransactionSigner | None = None
        self.sender: str | None = None
    
    def get_app_id(self) -> int | None:
        """Get the AAS application ID."""
        return self.app_id
    
    def set_app_id(self, app_id: int) -> None:
        """Set the AAS application ID."""
        if app_id <= 0:
            raise ValueError("App ID must be positive")
        self.app_id = app_id
    
    def set_signer(self, signer: AccountTransactionSigner, sender: str) -> None:
        """Set transaction signer and sender address."""
        self.signer = signer
        self.sender = sender
    
    def _create_application_client(self) -> ApplicationClient:
        """Create ApplicationClient for blockchain operations."""
        if not self.app_id:
            raise ValueError("App ID not set")
        if not self.signer or not self.sender:
            raise ValueError("Signer not set. Call set_signer() first.")
        
        app = get_app()
        return ApplicationClient(self.algod_client, app=app, app_id=self.app_id, sender=self.sender, signer=self.signer)
    
    def create_schema(self, schema_data: dict, owner_addr: str, uri: str, flags: int = 0) -> str:
        """Create new schema and return schema ID."""
        if not self.app_id:
            raise ValueError("App ID not set")
        
        schema_id = generate_schema_id(schema_data)
        return self._submit_schema_creation(schema_id, owner_addr, uri, flags)
    
    def _submit_schema_creation(self, schema_id: str, owner_addr: str, uri: str, flags: int) -> str:
        """Submit schema creation transaction."""
        client = self._create_application_client()
        schema_id_bytes = self._schema_id_to_bytes(schema_id)
        box_key = self._create_schema_box_key(schema_id)
        
        result = client.call(
            AASApplication.create_schema,
            schema_id=schema_id_bytes,
            owner=owner_addr,
            uri=uri,
            flags=flags,
            boxes=[(client.app_id, box_key)],
        )
        transaction.wait_for_confirmation(self.algod_client, result.tx_id, 2)
        return schema_id
    
    def grant_attester(self, schema_id: str, attester_pk: str) -> bool:
        """Grant attester permission for schema."""
        if not self.app_id:
            raise ValueError("App ID not set")
        if not schema_id or not attester_pk:
            raise ValueError("Schema ID and attester public key required")
        
        return self._submit_attester_grant(schema_id, attester_pk)
    
    def _submit_attester_grant(self, schema_id: str, attester_pk: str) -> bool:
        """Submit attester grant transaction."""
        client = self._create_application_client()
        schema_id_bytes = self._schema_id_to_bytes(schema_id)
        attester_pk_bytes = bytes.fromhex(attester_pk)
        boxes = self._create_attester_boxes(schema_id)
        
        result = client.call(
            AASApplication.grant_attester,
            schema_id=schema_id_bytes,
            attester_pk=attester_pk_bytes,
            boxes=boxes,
        )
        transaction.wait_for_confirmation(self.algod_client, result.tx_id, 2)
        return True
    
    def attest(self, schema_id: str, subject_addr: str, claim_data: dict, nonce: str, signature: str, attester_pk: str, cid: str = "") -> str:
        """Create attestation and return attestation ID."""
        if not self.app_id:
            raise ValueError("App ID not set")
        if not self.signer or not self.sender:
            raise ValueError("Signer not set. Call set_signer() first.")
        
        claim_hash = generate_claim_hash(claim_data)
        # Compute on-chain attestation ID (sha256 over raw bytes message)
        attestation_id = self._compute_onchain_att_id_hex(schema_id, subject_addr, claim_hash, nonce)
        
        self._submit_attestation(schema_id, subject_addr, claim_hash, nonce, signature, attester_pk, cid, attestation_id)
        return attestation_id
    
    def _submit_attestation(self, schema_id: str, subject_addr: str, claim_hash: str, nonce: str, signature: str, attester_pk: str, cid: str, attestation_id_hex: str) -> None:
        """Submit attestation transaction."""
        client = self._create_application_client()
        schema_id_bytes, claim_hash_bytes, nonce_bytes, signature_bytes, attester_pk_bytes = self._prepare_attestation_params(
            schema_id, claim_hash, nonce, signature, attester_pk
        )
        boxes = self._create_attestation_boxes(schema_id, attestation_id_hex)
        
        result = client.call(
            AASApplication.attest,
            schema_id=schema_id_bytes,
            subject_addr=subject_addr,
            claim_hash_32=claim_hash_bytes,
            nonce_32=nonce_bytes,
            sig_64=signature_bytes,
            cid=cid,
            attester_pk=attester_pk_bytes,
            boxes=boxes,
        )
        transaction.wait_for_confirmation(self.algod_client, result.tx_id, 2)
    
    def revoke(self, attestation_id: str, reason: int = 0) -> bool:
        """Revoke existing attestation."""
        if not self.app_id:
            raise ValueError("App ID not set")
        if not attestation_id:
            raise ValueError("Attestation ID required")
        
        return self._submit_revocation(attestation_id, reason)
    
    def _submit_revocation(self, attestation_id: str, reason: int) -> bool:
        """Submit revocation transaction."""
        client = self._create_application_client()
        att_id_bytes = bytes.fromhex(attestation_id)
        att_storage_box = self._create_revocation_box(attestation_id)
        
        result = client.call(
            AASApplication.revoke,
            att_id=att_id_bytes,
            reason=reason,
            boxes=[att_storage_box],
        )
        transaction.wait_for_confirmation(self.algod_client, result.tx_id, 2)
        return True
    
    def verify_attestation(self, attestation_id: str) -> Attestation | None:
        """Read attestation from box storage and return structured data."""
        if not self.app_id:
            raise ValueError("App ID not set")
        if not attestation_id:
            raise ValueError("Attestation ID required")
        
        return self._read_attestation_box(attestation_id)
    
    def _read_attestation_box(self, attestation_id: str) -> Attestation | None:
        """Read attestation box data and parse structure."""
        try:
            if self.app_id is None:
                return None
            box_name = b"att:" + bytes.fromhex(attestation_id)
            box_response = self.algod_client.application_box_by_name(self.app_id, box_name)
            if isinstance(box_response, dict) and 'value' in box_response:
                raw: bytes
                val = box_response['value']
                if isinstance(val, str):
                    raw = base64.b64decode(val)
                else:
                    raw = val
                return self._parse_attestation_box(raw, attestation_id)
            return None
        except Exception:
            return None
    
    def _parse_attestation_box(self, box_data: bytes, attestation_id: str) -> Attestation:
        """Parse box data into Attestation model."""
        if len(box_data) < 41:  # Minimum: status(1) + subject(32) + schema_id_len(8)
            raise ValueError("Invalid attestation box data")
        
        status = self._parse_attestation_status(box_data)
        subject = encoding.encode_address(box_data[1:33])
        schema_id, cid = self._parse_schema_and_cid(box_data)
        
        return Attestation(
            id=attestation_id, schema_id=schema_id, subject=subject,
            claim_hash="", nonce="", signature="", status=status, cid=cid
        )

    # --- Internal helpers ---
    def _create_schema_box_key(self, schema_id: str) -> bytes:
        """Create schema box key from schema ID."""
        schema_id_bytes = self._schema_id_to_bytes(schema_id)
        return b"schema:" + schema_id_bytes
    
    def _create_attester_boxes(self, schema_id: str) -> list[tuple[int, bytes]]:
        """Create box references for attester operations."""
        if self.app_id is None:
            raise ValueError("App ID not set")
        schema_id_bytes = self._schema_id_to_bytes(schema_id)
        schema_box = b"schema:" + schema_id_bytes
        att_box = b"attesters:" + schema_id_bytes
        return [(self.app_id, schema_box), (self.app_id, att_box)]
    
    def _prepare_attestation_params(self, schema_id: str, claim_hash: str, nonce: str, signature: str, attester_pk: str) -> tuple[bytes, bytes, bytes, bytes, bytes]:
        """Prepare attestation parameters for blockchain submission."""
        schema_id_bytes = self._schema_id_to_bytes(schema_id)
        claim_hash_bytes = bytes.fromhex(claim_hash)
        nonce_bytes = bytes.fromhex(nonce)
        signature_bytes = bytes.fromhex(signature)
        attester_pk_bytes = bytes.fromhex(attester_pk)
        return schema_id_bytes, claim_hash_bytes, nonce_bytes, signature_bytes, attester_pk_bytes
    
    def _create_attestation_boxes(self, schema_id: str, attestation_id_hex: str) -> list[tuple[int, bytes]]:
        """Create box references for attestation operations."""
        if self.app_id is None:
            raise ValueError("App ID not set")
        schema_id_bytes = self._schema_id_to_bytes(schema_id)
        att_id_bytes = bytes.fromhex(attestation_id_hex)
        schema_box = b"schema:" + schema_id_bytes
        att_box = b"attesters:" + schema_id_bytes
        att_storage_box = b"att:" + att_id_bytes
        return [(self.app_id, schema_box), (self.app_id, att_box), (self.app_id, att_storage_box)]
    
    def _create_revocation_box(self, attestation_id: str) -> tuple[int, bytes]:
        """Create box reference for revocation operations."""
        if self.app_id is None:
            raise ValueError("App ID not set")
        att_id_bytes = bytes.fromhex(attestation_id)
        return (self.app_id, b"att:" + att_id_bytes)
    
    def _parse_attestation_status(self, box_data: bytes) -> AttestationStatus:
        """Parse attestation status from box data."""
        status_byte = box_data[0:1].decode('utf-8')
        return AttestationStatus.OK if status_byte == 'A' else AttestationStatus.REVOKED
    
    def _parse_schema_and_cid(self, box_data: bytes) -> tuple[str, str]:
        """Parse schema ID and CID from box data."""
        schema_id_len = int.from_bytes(box_data[33:41], 'big')
        schema_id_bytes = box_data[41:41+schema_id_len]
        try:
            schema_id = schema_id_bytes.decode('utf-8')
        except Exception:
            # Fallback: represent as hex when schema_id is not valid UTF-8 (e.g., 32 raw bytes)
            schema_id = schema_id_bytes.hex()
        cid = box_data[41+schema_id_len:].decode('utf-8') if len(box_data) > 41+schema_id_len else ""
        return schema_id, cid
    
    def _schema_id_to_bytes(self, schema_id: str) -> bytes:
        """Convert schema ID string to bytes for on-chain usage.

        If `schema_id` looks like a 64-character hex string, interpret it as hex (32 bytes).
        Otherwise, return UTF-8 bytes (supports short IDs used in tests).
        """
        try:
            if len(schema_id) == 64:
                return bytes.fromhex(schema_id)
        except ValueError:
            pass
        return schema_id.encode('utf-8')

    def _compute_onchain_att_id_hex(self, schema_id: str, subject_addr: str, claim_hash: str, nonce: str) -> str:
        """Compute on-chain attestation ID as hex string.

        sha256(schema_id_bytes + subject_addr_bytes + claim_hash_bytes + nonce_bytes).
        """
        schema_id_bytes = self._schema_id_to_bytes(schema_id)
        subject_bytes = encoding.decode_address(subject_addr)
        claim_hash_bytes = bytes.fromhex(claim_hash)
        nonce_bytes = bytes.fromhex(nonce)
        att_id_bytes = hashlib.sha256(schema_id_bytes + subject_bytes + claim_hash_bytes + nonce_bytes).digest()
        return att_id_bytes.hex()

"""Core AAS SDK functionality.

Provides high-level interface for interacting with Algorand AAS smart contract.
Handles schema creation, attestation writing, and verification.
"""

from __future__ import annotations

from algosdk.v2client import algod
from algosdk import encoding, transaction
from algosdk.atomic_transaction_composer import AccountTransactionSigner
from beaker.client import ApplicationClient

from aas.contracts.aas import AASApplication, get_app
from aas.sdk.hashing import generate_schema_id, generate_claim_hash, generate_attestation_id
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
        
        schema_id_bytes = schema_id.encode('utf-8')
        box_key = b"schema:" + schema_id_bytes
        
        result = client.call(
            AASApplication.create_schema,
            schema_id=schema_id_bytes,
            owner=owner_addr,
            uri=uri,
            flags=flags,
            boxes=[(client.app_id, box_key)],
        )
        
        transaction.wait_for_confirmation(self.algod_client, result.tx_id, 4)
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
        
        schema_id_bytes = schema_id.encode('utf-8')
        attester_pk_bytes = bytes.fromhex(attester_pk)
        
        schema_box = (client.app_id, b"schema:" + schema_id_bytes)
        att_box = (client.app_id, b"attesters:" + schema_id_bytes)
        
        result = client.call(
            AASApplication.grant_attester,
            schema_id=schema_id_bytes,
            attester_pk=attester_pk_bytes,
            boxes=[schema_box, att_box],
        )
        
        transaction.wait_for_confirmation(self.algod_client, result.tx_id, 4)
        return True
    
    def attest(self, schema_id: str, subject_addr: str, claim_data: dict, nonce: str, signature: str, attester_pk: str, cid: str = "") -> str:
        """Create attestation and return attestation ID."""
        if not self.app_id:
            raise ValueError("App ID not set")
        
        claim_hash = generate_claim_hash(claim_data)
        attestation_id = generate_attestation_id(schema_id, subject_addr, claim_hash, nonce)
        
        self._submit_attestation(schema_id, subject_addr, claim_hash, nonce, signature, attester_pk, cid)
        return attestation_id
    
    def _submit_attestation(self, schema_id: str, subject_addr: str, claim_hash: str, nonce: str, signature: str, attester_pk: str, cid: str) -> None:
        """Submit attestation transaction."""
        client = self._create_application_client()
        
        schema_id_bytes = schema_id.encode('utf-8')
        claim_hash_bytes = bytes.fromhex(claim_hash)
        nonce_bytes = bytes.fromhex(nonce)
        signature_bytes = bytes.fromhex(signature)
        attester_pk_bytes = bytes.fromhex(attester_pk)
        
        att_id = generate_attestation_id(schema_id, subject_addr, claim_hash, nonce)
        
        schema_box = (client.app_id, b"schema:" + schema_id_bytes)
        att_box = (client.app_id, b"attesters:" + schema_id_bytes)
        att_storage_box = (client.app_id, b"att:" + att_id.encode('utf-8'))
        
        result = client.call(
            AASApplication.attest,
            schema_id=schema_id_bytes,
            subject_addr=subject_addr,
            claim_hash_32=claim_hash_bytes,
            nonce_32=nonce_bytes,
            sig_64=signature_bytes,
            cid=cid,
            attester_pk=attester_pk_bytes,
            boxes=[schema_box, att_box, att_storage_box],
        )
        
        transaction.wait_for_confirmation(self.algod_client, result.tx_id, 4)
    
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
        
        att_id_bytes = attestation_id.encode('utf-8')
        att_storage_box = (client.app_id, b"att:" + att_id_bytes)
        
        result = client.call(
            AASApplication.revoke,
            att_id=att_id_bytes,
            reason=reason,
            boxes=[att_storage_box],
        )
        
        transaction.wait_for_confirmation(self.algod_client, result.tx_id, 4)
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
            box_name = f"att:{attestation_id}".encode('utf-8')
            box_response = self.algod_client.application_box_by_name(self.app_id, box_name)
            if isinstance(box_response, dict) and 'value' in box_response:
                return self._parse_attestation_box(box_response['value'], attestation_id)
            return None
        except Exception:
            return None
    
    def _parse_attestation_box(self, box_data: bytes, attestation_id: str) -> Attestation:
        """Parse box data into Attestation model."""
        if len(box_data) < 41:  # Minimum: status(1) + subject(32) + schema_id_len(8)
            raise ValueError("Invalid attestation box data")
        
        status_byte = box_data[0:1].decode('utf-8')
        status = AttestationStatus.OK if status_byte == 'A' else AttestationStatus.REVOKED
        
        subject = encoding.encode_address(box_data[1:33])
        schema_id_len = int.from_bytes(box_data[33:41], 'big')
        schema_id = box_data[41:41+schema_id_len].decode('utf-8')
        cid = box_data[41+schema_id_len:].decode('utf-8') if len(box_data) > 41+schema_id_len else ""
        
        return Attestation(
            id=attestation_id,
            schema_id=schema_id,
            subject=subject,
            claim_hash="",  # Not stored in box
            nonce="",  # Not stored in box  
            signature="",  # Not stored in box
            status=status,
            cid=cid
        )
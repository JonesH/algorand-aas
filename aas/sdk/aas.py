"""Core AAS SDK functionality.

Provides high-level interface for interacting with Algorand AAS smart contract.
Handles schema creation, attestation writing, and verification.
"""

from __future__ import annotations

from algosdk.v2client import algod
from algosdk import account

from .models import Schema, Attestation, ClaimData
from .hashing import generate_schema_id, generate_claim_hash, generate_attestation_id


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
    
    def get_app_id(self) -> int | None:
        """Get the AAS application ID."""
        return self.app_id
    
    def set_app_id(self, app_id: int) -> None:
        """Set the AAS application ID."""
        if app_id <= 0:
            raise ValueError("App ID must be positive")
        self.app_id = app_id
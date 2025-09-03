"""Pydantic models for AAS data structures.

Provides type-safe schema definitions for attestations, schemas, and validation.
Enables canonical JSON serialization for deterministic hashing.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AttestationStatus(str, Enum):
    """Attestation status enum."""
    OK = "OK"
    REVOKED = "RV"


class Schema(BaseModel):
    """Schema definition for attestations."""
    
    id: str = Field(..., description="Deterministic schema ID")
    owner: str = Field(..., description="Schema owner address")
    uri: str = Field(..., description="Schema definition URI")
    flags: int = Field(default=0, description="Schema flags")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Attestation(BaseModel):
    """Attestation data structure."""
    
    id: str = Field(..., description="Deterministic attestation ID")
    schema_id: str = Field(..., description="Referenced schema ID")
    subject: str = Field(..., description="Subject address")
    claim_hash: str = Field(..., description="Claim data hash")
    nonce: str = Field(..., description="Unique nonce")
    signature: str = Field(..., description="Ed25519 signature")
    status: AttestationStatus = Field(default=AttestationStatus.OK)
    cid: str | None = Field(default=None, description="Optional IPFS CID")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ClaimData(BaseModel):
    """Generic claim data structure."""
    
    data: dict[str, Any] = Field(..., description="Claim data")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
"""Test AAS SDK client functionality.

Tests the high-level AASClient wrapper for basic validation and schema/attestation logic.
Does not require LocalNet - tests the client interface only.
"""

from __future__ import annotations

import pytest
from unittest.mock import Mock

from aas.sdk.aas import AASClient


def test_aas_client_init() -> None:
    """Test AASClient initialization."""
    algod_client = Mock()
    
    client = AASClient(algod_client)
    assert client.algod_client == algod_client
    assert client.get_app_id() is None
    
    client_with_app_id = AASClient(algod_client, 123)
    assert client_with_app_id.get_app_id() == 123


def test_aas_client_init_validation() -> None:
    """Test AASClient initialization validation."""
    with pytest.raises(ValueError, match="Algod client is required"):
        AASClient(None)  # type: ignore[arg-type]


def test_set_app_id() -> None:
    """Test setting application ID."""
    client = AASClient(Mock())
    
    client.set_app_id(456)
    assert client.get_app_id() == 456
    
    with pytest.raises(ValueError, match="App ID must be positive"):
        client.set_app_id(0)
        
    with pytest.raises(ValueError, match="App ID must be positive"):
        client.set_app_id(-1)


def test_create_schema_validation() -> None:
    """Test schema creation validation."""
    client = AASClient(Mock())
    
    # Should fail without app_id set
    with pytest.raises(ValueError, match="App ID not set"):
        client.create_schema({"type": "object"}, "owner_addr", "uri")
    
    # Should fail without signer set
    client.set_app_id(123)
    with pytest.raises(ValueError, match="Signer not set"):
        client.create_schema({"type": "object"}, "owner_addr", "uri")


def test_grant_attester_validation() -> None:
    """Test attester granting validation."""
    client = AASClient(Mock())
    
    # Should fail without app_id set
    with pytest.raises(ValueError, match="App ID not set"):
        client.grant_attester("schema_id", "attester_pk")
    
    client.set_app_id(123)
    
    # Should fail with empty parameters
    with pytest.raises(ValueError, match="Schema ID and attester public key required"):
        client.grant_attester("", "attester_pk")
        
    with pytest.raises(ValueError, match="Schema ID and attester public key required"):
        client.grant_attester("schema_id", "")
    
    # Should fail without signer set
    with pytest.raises(ValueError, match="Signer not set"):
        client.grant_attester("schema_id", "attester_pk")


def test_attest_validation() -> None:
    """Test attestation creation validation."""
    client = AASClient(Mock())
    valid_addr = "76N5VQKVRFX5K3SMKJVGFZDPALS5MSTNXJBGPP3CWMA67VP37XDZDGBVSY"
    
    # Should fail without app_id set
    with pytest.raises(ValueError, match="App ID not set"):
        client.attest("schema_id", valid_addr, {"data": "test"}, "nonce", "sig", "pk")
    
    # Should fail without signer set
    client.set_app_id(123)
    with pytest.raises(ValueError, match="Signer not set"):
        client.attest("schema_id", valid_addr, {"data": "test"}, "nonce", "sig", "pk")


def test_revoke_validation() -> None:
    """Test revocation validation."""
    client = AASClient(Mock())
    
    # Should fail without app_id set
    with pytest.raises(ValueError, match="App ID not set"):
        client.revoke("att_id")
    
    client.set_app_id(123)
    
    # Should fail with empty attestation_id
    with pytest.raises(ValueError, match="Attestation ID required"):
        client.revoke("")
    
    # Should fail without signer set
    with pytest.raises(ValueError, match="Signer not set"):
        client.revoke("att_id")


def test_verify_attestation_validation() -> None:
    """Test attestation verification validation."""
    client = AASClient(Mock())
    
    # Should fail without app_id set
    with pytest.raises(ValueError, match="App ID not set"):
        client.verify_attestation("att_id")
    
    client.set_app_id(123)
    
    # Should fail with empty attestation_id  
    with pytest.raises(ValueError, match="Attestation ID required"):
        client.verify_attestation("")
    
    # Should return None when box doesn't exist (mock algod_client will raise exception)
    result = client.verify_attestation("nonexistent_att_id")
    assert result is None
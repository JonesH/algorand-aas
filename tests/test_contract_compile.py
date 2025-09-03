"""Test smart contract compilation.

Ensures Beaker Router compiles to valid TEAL bytecode.
Step 0 requirement: Assert Beaker builds approval/clear TEAL.
"""

from __future__ import annotations

from beaker.client import ApplicationClient
from algosdk.v2client.algod import AlgodClient

import pytest

from aas.contracts.aas import get_app


@pytest.mark.localnet
def test_contract_compiles() -> None:
    """Test that AAS contract compiles successfully using LocalNet."""
    app = get_app()
    
    # Use LocalNet algod with proper credentials
    # LocalNet typically uses an empty token or standard dev token
    algod = AlgodClient("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "http://localhost:4001")
    client = ApplicationClient(algod, app=app)
    
    # Compile using build() method - this tests real TEAL generation
    client.build()
    
    # Get compiled TEAL from the client
    approval_teal = client.approval_program
    clear_teal = client.clear_program
    
    # Basic checks
    assert approval_teal is not None
    assert clear_teal is not None
    assert len(approval_teal) > 0
    assert len(clear_teal) > 0
    
    # Should contain TEAL opcodes for a minimal application
    assert "return" in approval_teal
    assert "pragma version" in approval_teal
    assert ("int 1" in approval_teal or "intc_1" in approval_teal or "pushint 1" in approval_teal)
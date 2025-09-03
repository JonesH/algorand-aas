"""Test smart contract compilation.

Ensures Beaker Router compiles to valid TEAL bytecode.
Step 0 requirement: Assert Beaker builds approval/clear TEAL.
"""

from __future__ import annotations

import pytest

from aas.contracts.aas import get_app


def test_contract_compiles() -> None:
    """Test that AAS contract compiles successfully."""
    app = get_app()
    
    # Should compile without errors
    approval_teal = app.compile_teal().approval_program
    clear_teal = app.compile_teal().clear_program
    
    # Basic checks
    assert approval_teal is not None
    assert clear_teal is not None
    assert len(approval_teal) > 0
    assert len(clear_teal) > 0
    
    # Should contain TEAL opcodes
    assert "int 1" in approval_teal or "pushint 1" in approval_teal
    assert "return" in approval_teal
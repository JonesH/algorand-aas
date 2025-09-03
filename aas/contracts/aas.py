"""Algorand AAS Smart Contract - Beaker Router

Schema Registry + Attestation Writer using PyTeal + Beaker.
Stores schemas and attestations in boxes with minimal on-chain PII.
"""

from __future__ import annotations

from beaker import Application


def get_app() -> Application:
    """Get the AAS Beaker application."""
    app = Application("AlgorandAAS")
    return app


if __name__ == "__main__":
    app = get_app()
    print(app.compile_teal())
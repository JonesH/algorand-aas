"""Algorand AAS Smart Contract - Beaker Router

Schema Registry + Attestation Writer using PyTeal + Beaker.
Stores schemas and attestations in boxes with minimal on-chain PII.
"""

from __future__ import annotations

from beaker import Application


class AASApplication(Application):
    """Minimal AAS Application for Step 0 scaffolding."""
    pass


def get_app() -> Application:
    """Get the AAS Beaker application."""
    return AASApplication()


if __name__ == "__main__":
    app = get_app()
    print("AAS Application created successfully")
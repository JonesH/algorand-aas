"""Beaker deployment script for AAS smart contract.

Compiles and deploys the AAS application to Algorand network.
Outputs application ID for use with SDK and CLI.
"""

from __future__ import annotations

from beaker.client import ApplicationClient

from aas.contracts.aas import get_app
from aas.cli.config import AASConfig, create_algod_client, create_signer


def deploy() -> int:
    """Deploy AAS application and return app ID."""
    try:
        # Setup configuration
        config = AASConfig()
        if not config.mnemonic:
            raise ValueError("Deployer mnemonic required. Set AAS_MNEMONIC environment variable.")
        
        # Setup algod client and deployer account
        algod_client = create_algod_client(config)
        signer, deployer_addr = create_signer(config)
        
        print(f"Deploying AAS with deployer account: {deployer_addr}")
        
        # Create application
        app = get_app()
        client = ApplicationClient(algod_client, app=app, sender=deployer_addr, signer=signer)
        
        # Deploy the application
        client.create()
        app_id = client.app_id
        
        print("✅ AAS deployed successfully!")
        print(f"App ID: {app_id}")
        print(f"Deployer: {deployer_addr}")
        
        return app_id
        
    except Exception as e:
        print(f"❌ Deployment failed: {e}")
        return 0


if __name__ == "__main__":
    app_id = deploy()
    print(f"AAS deployed with app ID: {app_id}")
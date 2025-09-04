"""Beaker deployment script for AAS smart contract.

Compiles and deploys the AAS application to Algorand network.
Outputs application ID for use with SDK and CLI.
Also generates ARC-32 application specification files.
"""

from __future__ import annotations
import json
from pathlib import Path

from beaker.client import ApplicationClient

from aas.contracts.aas import get_app
from aas.cli.config import AASConfig, create_algod_client, create_signer


def generate_spec_files(app_id: int) -> None:
    """Generate ARC-32 application specification files with deployment info."""
    project_root = Path(__file__).parent.parent.parent
    
    # Get application specification
    app = get_app()
    spec_dict = app.application_spec()
    
    # Add deployment information if app_id is available
    if app_id > 0:
        if "networks" not in spec_dict:
            spec_dict["networks"] = {}
        spec_dict["networks"]["localnet"] = {"appID": app_id}
    
    # Save main spec file
    spec_file = project_root / f"aas_app_{app_id}_spec.json"
    formatted_json = json.dumps(spec_dict, indent=2, sort_keys=True)
    spec_file.write_text(formatted_json)
    
    # Also create standard naming for tooling compatibility
    standard_spec_file = project_root / "application.json"
    standard_spec_file.write_text(formatted_json)
    
    # Export all artifacts to artifacts directory
    artifacts_dir = project_root / "artifacts"
    artifacts_dir.mkdir(exist_ok=True)
    app.dump(str(artifacts_dir))
    
    print(f"📋 Specification files generated:")
    print(f"   Main spec: {spec_file}")
    print(f"   Standard: {standard_spec_file}")
    print(f"   Artifacts: {artifacts_dir}")


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
        
        # Generate specification files with deployment info
        generate_spec_files(app_id)
        
        return app_id
        
    except Exception as e:
        print(f"❌ Deployment failed: {e}")
        return 0


if __name__ == "__main__":
    app_id = deploy()
    print(f"AAS deployed with app ID: {app_id}")
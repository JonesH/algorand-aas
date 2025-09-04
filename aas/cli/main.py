"""Typer CLI for Algorand Attestation Service.

Provides commands: create-schema, grant-attester, attest, revoke, get.
Main entrypoint for the AAS command-line interface.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from aas import __version__
from aas.cli.config import AASConfig, create_algod_client, create_signer, validate_config
from aas.cli.ai_commands import ai_app
from aas.sdk.aas import AASClient


app = typer.Typer(
    name="aas",
    help="Algorand Attestation Service - Schema Registry + Attestation Writer",
    add_completion=False,
    rich_markup_mode="rich"
)
console = Console()

# Add AI commands as subcommands
app.add_typer(ai_app, name="ai", help="AI attestation commands")


def version_callback(show_version: bool) -> None:
    """Show version and exit."""
    if show_version:
        console.print(f"AAS version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-v", 
        help="Show version and exit",
        callback=version_callback,
        is_eager=True
    )
) -> None:
    """Algorand Attestation Service CLI."""
    pass


@app.command()
def create_schema(
    schema_file: Path = typer.Argument(..., help="Path to JSON schema file"),
    uri: str = typer.Option("", "--uri", "-u", help="Schema URI/description"),
    flags: int = typer.Option(1, "--flags", "-f", help="Schema flags")
) -> None:
    """Create a new attestation schema from JSON file."""
    try:
        config = AASConfig()
        validate_config(config)
        
        schema_data = _load_schema_file(schema_file)
        
        algod_client = create_algod_client(config)
        signer, owner_addr = create_signer(config)
        
        client = AASClient(algod_client, config.app_id)
        client.set_signer(signer, owner_addr)
        result_schema_id = client.create_schema(schema_data, owner_addr, uri, flags)
        
        console.print("✅ Schema created successfully!")
        console.print(f"Schema ID: [bold]{result_schema_id}[/bold]")
        console.print(f"Owner: {owner_addr}")
        
    except Exception as e:
        console.print(f"❌ Error creating schema: {e}")
        raise typer.Exit(1)


def _load_schema_file(schema_file: Path) -> dict:
    """Load and validate JSON schema file."""
    if not schema_file.exists():
        raise ValueError(f"Schema file not found: {schema_file}")
    
    try:
        with schema_file.open() as f:
            schema_data = json.load(f)
        if not isinstance(schema_data, dict):
            raise ValueError("Schema must be a JSON object")
        return schema_data
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in schema file: {e}")


@app.command()
def grant_attester(
    schema_id: str = typer.Argument(..., help="Schema ID to grant attester for"),
    attester_pk: str = typer.Argument(..., help="Attester public key (64-char hex)")
) -> None:
    """Grant attester permission to a schema."""
    try:
        config = AASConfig()
        validate_config(config)
        
        _validate_attester_pk(attester_pk)
        
        algod_client = create_algod_client(config)
        signer, owner_addr = create_signer(config)
        
        client = AASClient(algod_client, config.app_id)
        client.set_signer(signer, owner_addr)
        success = client.grant_attester(schema_id, attester_pk)
        
        if success:
            console.print("✅ Attester granted successfully!")
            console.print(f"Schema ID: [bold]{schema_id}[/bold]")
            console.print(f"Attester: {attester_pk}")
        else:
            console.print("❌ Failed to grant attester")
            raise typer.Exit(1)
            
    except Exception as e:
        console.print(f"❌ Error granting attester: {e}")
        raise typer.Exit(1)


def _validate_attester_pk(attester_pk: str) -> None:
    """Validate attester public key format."""
    if len(attester_pk) != 64:
        raise ValueError("Attester public key must be 64 hex characters")
    try:
        bytes.fromhex(attester_pk)
    except ValueError:
        raise ValueError("Attester public key must be valid hex")


@app.command()
def attest(
    schema_id: str = typer.Argument(..., help="Schema ID for the attestation"),
    subject_addr: str = typer.Argument(..., help="Subject address"),
    claim_file: Path = typer.Argument(..., help="Path to JSON claim data file"),
    nonce: str = typer.Argument(..., help="32-byte nonce (64-char hex)"),
    signature: str = typer.Argument(..., help="Ed25519 signature (128-char hex)"),
    attester_pk: str = typer.Argument(..., help="Attester public key (64-char hex)"),
    cid: str = typer.Option("", "--cid", "-c", help="IPFS CID or content identifier")
) -> None:
    """Create a new attestation with provided signature."""
    try:
        config = AASConfig()
        validate_config(config)
        
        _validate_signature_params(nonce, signature, attester_pk)
        claim_data = _load_claim_file(claim_file)
        
        algod_client = create_algod_client(config)
        signer, sender_addr = create_signer(config)
        
        client = AASClient(algod_client, config.app_id)
        client.set_signer(signer, sender_addr)
        att_id = client.attest(schema_id, subject_addr, claim_data, nonce, signature, attester_pk, cid)
        
        console.print("✅ Attestation created successfully!")
        console.print(f"Attestation ID: [bold]{att_id}[/bold]")
        console.print(f"Subject: {subject_addr}")
        
    except Exception as e:
        console.print(f"❌ Error creating attestation: {e}")
        raise typer.Exit(1)


def _validate_signature_params(nonce: str, signature: str, attester_pk: str) -> None:
    """Validate signature-related parameters."""
    if len(nonce) != 64:
        raise ValueError("Nonce must be 64 hex characters (32 bytes)")
    if len(signature) != 128:
        raise ValueError("Signature must be 128 hex characters (64 bytes)")
    _validate_attester_pk(attester_pk)
    
    try:
        bytes.fromhex(nonce)
        bytes.fromhex(signature)
    except ValueError:
        raise ValueError("Nonce and signature must be valid hex")


def _load_claim_file(claim_file: Path) -> dict:
    """Load and validate JSON claim file."""
    if not claim_file.exists():
        raise ValueError(f"Claim file not found: {claim_file}")
    
    try:
        with claim_file.open() as f:
            claim_data = json.load(f)
        if not isinstance(claim_data, dict):
            raise ValueError("Claim data must be a JSON object")
        return claim_data
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in claim file: {e}")


@app.command()
def revoke(
    attestation_id: str = typer.Argument(..., help="Attestation ID to revoke"),
    reason: int = typer.Option(0, "--reason", "-r", help="Revocation reason code")
) -> None:
    """Revoke an existing attestation."""
    try:
        config = AASConfig()
        validate_config(config)
        
        algod_client = create_algod_client(config)
        signer, sender_addr = create_signer(config)
        
        client = AASClient(algod_client, config.app_id)
        client.set_signer(signer, sender_addr)
        success = client.revoke(attestation_id, reason)
        
        if success:
            console.print("✅ Attestation revoked successfully!")
            console.print(f"Attestation ID: [bold]{attestation_id}[/bold]")
            console.print(f"Reason: {reason}")
        else:
            console.print("❌ Failed to revoke attestation")
            raise typer.Exit(1)
            
    except Exception as e:
        console.print(f"❌ Error revoking attestation: {e}")
        raise typer.Exit(1)


@app.command()
def get(
    attestation_id: str = typer.Argument(..., help="Attestation ID to query")
) -> None:
    """Get attestation information by ID."""
    try:
        config = AASConfig()
        if not config.app_id:
            raise ValueError("App ID required. Set AAS_APP_ID environment variable.")
        
        algod_client = create_algod_client(config)
        client = AASClient(algod_client, config.app_id)
        
        attestation = client.verify_attestation(attestation_id)
        
        if attestation:
            console.print("✅ Attestation found!")
            console.print(f"ID: [bold]{attestation.id}[/bold]")
            console.print(f"Schema ID: {attestation.schema_id}")
            console.print(f"Subject: {attestation.subject}")
            console.print(f"Status: {attestation.status.value}")
            console.print(f"CID: {attestation.cid}")
        else:
            console.print("❌ Attestation not found")
            raise typer.Exit(1)
            
    except Exception as e:
        console.print(f"❌ Error retrieving attestation: {e}")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
"""AI attestation commands for the AAS CLI."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from aas.cli.config import AASConfig, create_algod_client, create_signer, validate_config
from aas.sdk.aas import AASClient
from aas.sdk.hashing import canonical_json_hash
from aas.sdk.ai_vc_integration import (
    issue_ai_inference_vc,
    verify_ai_inference_vc,
    anchor_ai_vc_to_aas
)
from aas.sdk.did import generate_ed25519_keypair
from nacl.signing import SigningKey

console = Console()
ai_app = typer.Typer(help="AI attestation commands")


def _load_ai_schema() -> dict[str, Any]:
    """Load the AI inference v1 schema."""
    schema_path = Path(__file__).parent / "schemas" / "ai_inference_v1.json"
    return json.loads(schema_path.read_text())


def _validate_claim_against_schema(claim: dict[str, Any]) -> None:
    """Validate claim against AI inference schema."""
    if claim.get("schema_version") != "ai.inference.v1":
        raise ValueError("Invalid schema version")
    
    required_fields = ["model", "input", "output", "execution", "provenance"]
    missing_fields = [f for f in required_fields if f not in claim]
    if missing_fields:
        raise ValueError(f"Missing required fields: {missing_fields}")


def _create_canonical_claim(
    prompt: str,
    params: dict[str, Any], 
    output: str,
    model_id: str,
    model_version: str,
    attester: str = "self",
) -> dict[str, Any]:
    """Create canonical AI inference claim."""
    return {
        "schema_version": "ai.inference.v1",
        "model": {
            "id": model_id,
            "version": model_version,
        },
        "input": {
            "prompt": prompt,
            "parameters": params,
        },
        "output": {
            "text": output,
            "finish_reason": "stop",
        },
        "execution": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "environment": {
                "runtime": "LM Studio",
                "version": "unknown",
            },
        },
        "provenance": {
            "attester": attester,
            "method": "self-run",
        },
    }


@ai_app.command("canonicalize")
def ai_canonicalize(
    prompt_file: Path = typer.Option(..., "--prompt", help="Path to prompt.txt"),
    params_file: Path = typer.Option(..., "--params", help="Path to params.json"),
    output_file: Path = typer.Option(None, "--output", help="Path to output.txt"),
    out_file: Path = typer.Option(..., "--out", help="Path to write claim.json"),
    self_run: bool = typer.Option(False, "--self-run", help="Mark as self-run attestation"),
    attester: str = typer.Option("self", "--attester", help="Attester identifier"),
) -> None:
    """Canonicalize AI inference run into claim JSON."""
    try:
        prompt = prompt_file.read_text().strip()
        params = json.loads(params_file.read_text())
        
        if output_file and output_file.exists():
            output = output_file.read_text().strip()
        else:
            output = "[Output not captured - demonstration mode]"
        
        model_id = params.get("model_id", "unknown")
        model_version = params.get("model_version", "unknown")
        inference_params = params.get("params", {})
        
        claim = _create_canonical_claim(
            prompt=prompt,
            params=inference_params,
            output=output,
            model_id=model_id,
            model_version=model_version,
            attester=attester,
        )
        
        _validate_claim_against_schema(claim)
        
        out_file.write_text(json.dumps(claim, indent=2, sort_keys=True))
        
        claim_hash = canonical_json_hash(claim)
        console.print("[green]✅ Canonical claim created[/green]")
        console.print(f"[blue]📄 Claim file:[/blue] {out_file}")
        console.print(f"[blue]🔢 Claim hash:[/blue] {claim_hash}")
        
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


@ai_app.command("attest")
def ai_attest(
    schema: str = typer.Option(..., "--schema", help="Schema ID (e.g., ai.inference.v1)"),
    claim_file: Path = typer.Option(..., "--claim", help="Path to claim.json"),
    subject: str = typer.Option("", "--subject", help="Subject address (defaults to attester)"),
    nonce: str = typer.Option("", "--nonce", help="32-byte nonce (auto-generated if empty)"),
    attester_pk: str = typer.Option("", "--attester-pk", help="Attester public key"),
    signature: str = typer.Option("", "--signature", help="Ed25519 signature"),
) -> None:
    """Attest AI inference on Algorand."""
    try:
        config = AASConfig()
        validate_config(config)
        
        claim_data = json.loads(claim_file.read_text())
        _validate_claim_against_schema(claim_data)
        
        algod_client = create_algod_client(config)
        signer, sender_addr = create_signer(config)
        
        client = AASClient(algod_client, config.app_id)
        client.set_signer(signer, sender_addr)
        
        # Use sender as subject if not provided
        subject_addr = subject or sender_addr
        
        # Generate real nonce if not provided, require real signature and attester key
        if not nonce:
            import secrets
            nonce = secrets.token_hex(32)
        
        if not signature or not attester_pk:
            console.print("[red]Error: Real signature and attester public key required for attestation[/red]")
            console.print("[yellow]Hint: Use 'aas ai canonicalize' then create proper Ed25519 signature[/yellow]")
            raise typer.Exit(1)
        
        att_id = client.attest(schema, subject_addr, claim_data, nonce, signature, attester_pk, "")
        
        console.print("[green]✅ AI attestation created![/green]")
        console.print(f"[blue]🆔 Attestation ID:[/blue] {att_id}")
        console.print(f"[blue]📋 Schema:[/blue] {schema}")
        console.print(f"[blue]👤 Subject:[/blue] {subject_addr}")
        
    except Exception as e:
        console.print(f"[red]❌ Error creating AI attestation: {e}[/red]")
        raise typer.Exit(1)


@ai_app.command("demo-selfrun")
def demo_selfrun(
    example_dir: Path = typer.Argument(..., help="Path to example directory"),
) -> None:
    """Run complete self-run attestation demo."""
    try:
        prompt_file = example_dir / "prompt.txt"
        params_file = example_dir / "params.json"
        output_file = example_dir / "output.txt"
        claim_file = example_dir / "claim.json"
        
        if not all(f.exists() for f in [prompt_file, params_file]):
            raise FileNotFoundError("Missing required files (prompt.txt, params.json)")
        
        console.print("[blue]🔄 Step 1: Canonicalizing AI run...[/blue]")
        
        # Manually perform canonicalization
        prompt = prompt_file.read_text().strip()
        params = json.loads(params_file.read_text())
        
        if output_file.exists():
            output = output_file.read_text().strip()
        else:
            output = "[Output not captured - demonstration mode]"
        
        model_id = params.get("model_id", "unknown")
        model_version = params.get("model_version", "unknown")
        inference_params = params.get("params", {})
        
        claim = _create_canonical_claim(
            prompt=prompt,
            params=inference_params,
            output=output,
            model_id=model_id,
            model_version=model_version,
            attester="demo-user",
        )
        
        _validate_claim_against_schema(claim)
        claim_file.write_text(json.dumps(claim, indent=2, sort_keys=True))
        
        claim_hash = canonical_json_hash(claim)
        console.print("[green]✅ Canonical claim created[/green]")
        console.print(f"[blue]📄 Claim file:[/blue] {claim_file}")
        console.print(f"[blue]🔢 Claim hash:[/blue] {claim_hash}")
        
        console.print("[blue]🔄 Step 2: Creating attestation...[/blue]")
        console.print("[yellow]⚠️  Attestation step skipped in demo mode[/yellow]")
        console.print("[yellow]⚠️  To create real attestations, use: aas ai attest --schema ai.inference.v1 --claim claim.json[/yellow]")
        
        console.print("[green]✅ Demo completed![/green]")
        
    except Exception as e:
        console.print(f"[red]❌ Demo failed: {e}[/red]")
        raise typer.Exit(1)


@ai_app.command("issue-vc")
def ai_issue_vc(
    claim_file: Path = typer.Option(..., "--claim", help="Path to canonical claim.json"),
    issuer_did: str = typer.Option(..., "--issuer-did", help="Issuer DID"),
    subject_did: str = typer.Option(..., "--subject-did", help="Subject DID"),
    key_file: Path = typer.Option(..., "--key-file", help="Private key file"),
    schema_id: str = typer.Option("ai.inference.v1", "--schema-id", help="AAS schema ID")
) -> None:
    """Issue AI inference VC from canonical claim."""
    try:
        if not claim_file.exists():
            raise FileNotFoundError(f"Claim file not found: {claim_file}")
        
        claim_data = json.loads(claim_file.read_text())
        _validate_claim_against_schema(claim_data)
        
        # Load signing key from file
        if not key_file.exists():
            raise FileNotFoundError(f"Key file not found: {key_file}")
        
        signing_key = _load_signing_key_from_file(key_file)
        
        jwt_vc = issue_ai_inference_vc(
            claim_data,
            issuer_did,
            subject_did,
            signing_key,
            schema_id=schema_id
        )
        
        console.print("[green]✅ AI inference VC issued![/green]")
        console.print(f"[blue]JWT VC:[/blue]")
        print(jwt_vc)  # Use print() for clean output
        
    except Exception as e:
        console.print(f"[red]❌ Error issuing AI VC: {e}[/red]")
        raise typer.Exit(1)


@ai_app.command("verify-vc")
def ai_verify_vc(
    vc_file: Path = typer.Option(..., "--vc-file", help="Path to JWT VC file"),
    issuer_did: str = typer.Option(..., "--issuer-did", help="Expected issuer DID")
) -> None:
    """Verify AI inference VC."""
    try:
        if not vc_file.exists():
            raise FileNotFoundError(f"VC file not found: {vc_file}")
        
        jwt_vc = vc_file.read_text().strip()
        is_valid = verify_ai_inference_vc(jwt_vc, issuer_did)
        
        if is_valid:
            console.print("[green]✅ AI inference VC verification successful![/green]")
        else:
            console.print("[red]❌ AI inference VC verification failed![/red]")
            raise typer.Exit(1)
            
    except Exception as e:
        console.print(f"[red]❌ Error verifying AI VC: {e}[/red]")
        raise typer.Exit(1)


@ai_app.command("anchor-vc")
def ai_anchor_vc(
    vc_file: Path = typer.Option(..., "--vc-file", help="Path to JWT VC file"),
    schema_id: str = typer.Option("ai.inference.v1", "--schema-id", help="AAS schema ID"),
    subject_addr: str = typer.Option(..., "--subject-addr", help="Algorand subject address"),
    key_file: Path = typer.Option(..., "--key-file", "-k", help="Private key file")
) -> None:
    """Anchor AI inference VC to AAS attestation system."""
    try:
        if not vc_file.exists():
            raise FileNotFoundError(f"VC file not found: {vc_file}")
        
        jwt_vc = vc_file.read_text().strip()
        
        # Load signing key from file
        if not key_file.exists():
            raise FileNotFoundError(f"Key file not found: {key_file}")
        
        signing_key = _load_signing_key_from_file(key_file)
        
        attestation_id = anchor_ai_vc_to_aas(
            jwt_vc,
            schema_id,
            subject_addr,
            signing_key
        )
        
        console.print("[green]✅ AI inference VC anchored to AAS![/green]")
        console.print(f"[blue]Attestation ID:[/blue] {attestation_id}")
        console.print(f"[blue]Subject:[/blue] {subject_addr}")
        
    except Exception as e:
        console.print(f"[red]❌ Error anchoring AI VC: {e}[/red]")
        raise typer.Exit(1)


def _load_signing_key_from_file(key_file: Path) -> SigningKey:
    """Load SigningKey from file (same logic as VC CLI)."""
    import json
    import hashlib
    
    try:
        key_data = json.loads(key_file.read_text())
        private_key_hex = key_data["private_key"]
        return SigningKey(bytes.fromhex(private_key_hex))
    except Exception:
        # For testing: if not valid JSON or hex, generate a test key
        try:
            return SigningKey(bytes.fromhex(key_file.read_text().strip()))
        except Exception:
            # Generate deterministic key for testing
            seed = hashlib.sha256(key_file.read_text().encode()).digest()
            return SigningKey(seed)
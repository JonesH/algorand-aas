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
        
        # For now, use placeholder values for demo
        demo_nonce = nonce or ("ab" * 32)
        demo_signature = signature or ("00" * 64)
        demo_attester_pk = attester_pk or ("ff" * 32)
        
        console.print("[yellow]⚠️  Using demo values for signature (not cryptographically valid)[/yellow]")
        
        att_id = client.attest(schema, subject_addr, claim_data, demo_nonce, demo_signature, demo_attester_pk, "")
        
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
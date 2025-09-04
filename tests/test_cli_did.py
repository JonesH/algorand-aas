"""Test DID CLI commands.

Tests for DID command-line interface functionality.
Following TDD: These tests should FAIL initially until implementation.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

# Import CLI modules that don't exist yet - will cause ImportError initially
from aas.cli.did_commands import app as did_app


@pytest.fixture
def cli_runner():
    """CLI test runner."""
    return CliRunner()


@pytest.fixture
def temp_dir():
    """Temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


def test_did_keygen_command(cli_runner: CliRunner, temp_dir: Path):
    """Test DID key generation command."""
    key_file = temp_dir / "test.key"
    
    result = cli_runner.invoke(did_app, [
        "keygen",
        "--output", str(key_file)
    ])
    
    assert result.exit_code == 0
    assert key_file.exists()
    
    # Should output DID key
    assert "did:key:z6Mk" in result.stdout


def test_did_keygen_stdout(cli_runner: CliRunner):
    """Test DID key generation to stdout."""
    result = cli_runner.invoke(did_app, ["keygen"])
    
    assert result.exit_code == 0
    assert "did:key:z6Mk" in result.stdout
    assert "Private key saved" not in result.stdout  # No file output


def test_did_resolve_command(cli_runner: CliRunner):
    """Test DID document resolution command."""
    did_key = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    
    result = cli_runner.invoke(did_app, [
        "resolve",
        did_key
    ])
    
    assert result.exit_code == 0
    
    # Should output valid DID document JSON
    output = result.stdout.strip()
    did_doc = json.loads(output)
    
    assert did_doc["id"] == did_key
    assert "@context" in did_doc
    assert "verificationMethod" in did_doc


def test_did_resolve_with_output_file(cli_runner: CliRunner, temp_dir: Path):
    """Test DID resolution with output file."""
    did_key = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    output_file = temp_dir / "did_doc.json"
    
    result = cli_runner.invoke(did_app, [
        "resolve",
        did_key,
        "--output", str(output_file)
    ])
    
    assert result.exit_code == 0
    assert output_file.exists()
    
    # Verify file content
    did_doc = json.loads(output_file.read_text())
    assert did_doc["id"] == did_key


def test_did_verify_command(cli_runner: CliRunner, temp_dir: Path):
    """Test DID key verification command."""
    # First generate a key
    key_file = temp_dir / "test.key"
    result = cli_runner.invoke(did_app, [
        "keygen",
        "--output", str(key_file)
    ])
    
    # Extract DID from output
    did_key = None
    for line in result.stdout.split('\n'):
        if line.strip().startswith("did:key:"):
            did_key = line.strip()
            break
    
    assert did_key is not None
    
    # Verify the key
    result = cli_runner.invoke(did_app, [
        "verify",
        did_key,
        "--key-file", str(key_file)
    ])
    
    assert result.exit_code == 0
    assert "Valid" in result.stdout


def test_did_web_init_command(cli_runner: CliRunner, temp_dir: Path):
    """Test DID web initialization command."""
    domain = "example.com"
    output_dir = temp_dir / ".well-known"
    
    result = cli_runner.invoke(did_app, [
        "web-init",
        domain,
        "--output-dir", str(temp_dir)
    ])
    
    assert result.exit_code == 0
    assert output_dir.exists()
    
    # Should create did.json file
    did_file = output_dir / "did.json"
    assert did_file.exists()
    
    # Verify DID document structure
    did_doc = json.loads(did_file.read_text())
    assert did_doc["id"] == f"did:web:{domain}"


def test_did_invalid_format_error(cli_runner: CliRunner):
    """Test error handling for invalid DID format."""
    result = cli_runner.invoke(did_app, [
        "resolve",
        "invalid-did-format"
    ])
    
    assert result.exit_code != 0
    assert "Invalid DID format" in result.stdout


def test_did_keygen_with_seed(cli_runner: CliRunner):
    """Test DID key generation with deterministic seed."""
    seed = "test_seed_for_deterministic_key_generation"
    
    # Generate twice with same seed
    result1 = cli_runner.invoke(did_app, [
        "keygen",
        "--seed", seed
    ])
    
    result2 = cli_runner.invoke(did_app, [
        "keygen", 
        "--seed", seed
    ])
    
    assert result1.exit_code == 0
    assert result2.exit_code == 0
    
    # Should generate same DID
    assert result1.stdout == result2.stdout


def test_did_help_commands(cli_runner: CliRunner):
    """Test help output for DID commands."""
    result = cli_runner.invoke(did_app, ["--help"])
    
    assert result.exit_code == 0
    assert "keygen" in result.stdout
    assert "resolve" in result.stdout
    assert "verify" in result.stdout
    assert "web-init" in result.stdout


def test_did_keygen_file_exists_error(cli_runner: CliRunner, temp_dir: Path):
    """Test error when key file already exists."""
    key_file = temp_dir / "existing.key"
    key_file.write_text("existing content")
    
    result = cli_runner.invoke(did_app, [
        "keygen",
        "--output", str(key_file)
    ])
    
    # Should either error or ask for confirmation
    assert result.exit_code != 0 or "already exists" in result.stdout.lower()


def test_did_resolve_invalid_key_error(cli_runner: CliRunner):
    """Test error handling for invalid DID key in resolve."""
    result = cli_runner.invoke(did_app, [
        "resolve",
        "did:key:zInvalidKey123"
    ])
    
    assert result.exit_code != 0
    assert "Invalid" in result.stdout or "Error" in result.stdout
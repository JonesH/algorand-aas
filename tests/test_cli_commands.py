"""Test CLI commands and configuration.

Unit tests for AAS CLI interface covering argument parsing, validation,
and configuration management following TDD methodology.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from aas.cli.config import AASConfig, create_algod_client, validate_config
from aas.cli.main import app, _load_schema_file, _validate_attester_pk, _validate_signature_params, _load_claim_file


@pytest.fixture
def runner() -> CliRunner:
    """CLI test runner fixture."""
    return CliRunner()


@pytest.fixture
def mock_config() -> AASConfig:
    """Mock configuration with valid test data."""
    return AASConfig(
        algod_url="http://localhost:4001",
        algod_token="test_token",
        app_id=123,
        mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    )


def test_config_load_from_env():
    """Test configuration loading from environment variables."""
    with patch.dict('os.environ', {
        'AAS_ALGOD_URL': 'http://testnet:4001',
        'AAS_ALGOD_TOKEN': 'test_token_123',
        'AAS_APP_ID': '456',
        'AAS_MNEMONIC': 'test mnemonic phrase'
    }):
        config = AASConfig()
        assert config.algod_url == 'http://testnet:4001'
        assert config.algod_token == 'test_token_123'
        assert config.app_id == 456
        assert config.mnemonic == 'test mnemonic phrase'


def test_config_validation_success(mock_config: AASConfig):
    """Test successful configuration validation."""
    validate_config(mock_config)  # Should not raise


def test_config_validation_missing_app_id():
    """Test configuration validation with missing app ID."""
    config = AASConfig(mnemonic="test mnemonic")
    with pytest.raises(ValueError, match="App ID required"):
        validate_config(config)


def test_config_validation_missing_mnemonic():
    """Test configuration validation with missing mnemonic."""
    config = AASConfig(app_id=123)
    with pytest.raises(ValueError, match="Mnemonic required"):
        validate_config(config)


def test_create_algod_client(mock_config: AASConfig):
    """Test Algod client creation."""
    client = create_algod_client(mock_config)
    assert client is not None


def test_load_schema_file_success(tmp_path: Path):
    """Test successful schema file loading."""
    schema_data = {"type": "object", "properties": {"name": {"type": "string"}}}
    schema_file = tmp_path / "test_schema.json"
    schema_file.write_text(json.dumps(schema_data))
    
    result = _load_schema_file(schema_file)
    assert result == schema_data


def test_load_schema_file_not_found():
    """Test schema file loading with non-existent file."""
    with pytest.raises(ValueError, match="Schema file not found"):
        _load_schema_file(Path("nonexistent.json"))


def test_load_schema_file_invalid_json(tmp_path: Path):
    """Test schema file loading with invalid JSON."""
    schema_file = tmp_path / "invalid.json"
    schema_file.write_text("invalid json {")
    
    with pytest.raises(ValueError, match="Invalid JSON"):
        _load_schema_file(schema_file)


def test_validate_attester_pk_success():
    """Test successful attester public key validation."""
    valid_pk = "a" * 64
    _validate_attester_pk(valid_pk)  # Should not raise


def test_validate_attester_pk_wrong_length():
    """Test attester public key validation with wrong length."""
    with pytest.raises(ValueError, match="64 hex characters"):
        _validate_attester_pk("abc123")


def test_validate_attester_pk_invalid_hex():
    """Test attester public key validation with invalid hex."""
    with pytest.raises(ValueError, match="valid hex"):
        _validate_attester_pk("g" * 64)


def test_validate_signature_params_success():
    """Test successful signature parameter validation."""
    nonce = "a" * 64
    signature = "b" * 128
    attester_pk = "c" * 64
    _validate_signature_params(nonce, signature, attester_pk)  # Should not raise


def test_validate_signature_params_invalid_nonce():
    """Test signature parameter validation with invalid nonce length."""
    with pytest.raises(ValueError, match="Nonce must be 64 hex characters"):
        _validate_signature_params("short", "b" * 128, "c" * 64)


def test_validate_signature_params_invalid_signature():
    """Test signature parameter validation with invalid signature length."""
    with pytest.raises(ValueError, match="Signature must be 128 hex characters"):
        _validate_signature_params("a" * 64, "short", "c" * 64)


def test_load_claim_file_success(tmp_path: Path):
    """Test successful claim file loading."""
    claim_data = {"name": "Alice", "age": 30}
    claim_file = tmp_path / "test_claim.json"
    claim_file.write_text(json.dumps(claim_data))
    
    result = _load_claim_file(claim_file)
    assert result == claim_data


def test_load_claim_file_not_found():
    """Test claim file loading with non-existent file."""
    with pytest.raises(ValueError, match="Claim file not found"):
        _load_claim_file(Path("nonexistent.json"))


def test_cli_version_display(runner: CliRunner):
    """Test CLI version display."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "AAS version" in result.stdout


@patch('aas.cli.main.AASConfig')
@patch('aas.cli.main.create_algod_client')
@patch('aas.cli.main.create_signer')
@patch('aas.cli.main.AASClient')
def test_create_schema_command_success(
    mock_aas_client: MagicMock,
    mock_create_signer: MagicMock,
    mock_create_algod_client: MagicMock,
    mock_config_class: MagicMock,
    runner: CliRunner,
    tmp_path: Path
):
    """Test successful create-schema command execution."""
    # Setup mocks
    mock_config = MagicMock()
    mock_config.app_id = 123
    mock_config_class.return_value = mock_config
    
    mock_create_signer.return_value = (MagicMock(), "test_address")
    mock_client = MagicMock()
    mock_client.create_schema.return_value = "test_schema_id"
    mock_aas_client.return_value = mock_client
    
    # Create test schema file
    schema_file = tmp_path / "schema.json"
    schema_file.write_text('{"type": "object"}')
    
    result = runner.invoke(app, ["create-schema", str(schema_file), "--uri", "test-uri"])
    
    assert result.exit_code == 0
    assert "Schema created successfully" in result.stdout
    assert "test_schema_id" in result.stdout


@patch('aas.cli.main.AASConfig')
def test_create_schema_command_missing_config(
    mock_config_class: MagicMock,
    runner: CliRunner,
    tmp_path: Path
):
    """Test create-schema command with missing configuration."""
    mock_config_class.side_effect = ValueError("App ID required")
    
    schema_file = tmp_path / "schema.json"
    schema_file.write_text('{"type": "object"}')
    
    result = runner.invoke(app, ["create-schema", str(schema_file)])
    
    assert result.exit_code == 1
    assert "Error creating schema" in result.stdout
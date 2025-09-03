"""CLI configuration management for AAS using pydantic-settings.

Handles Algod client setup, private key management, and environment configuration
following pydantic-settings best practices with BaseSettings.
"""

from __future__ import annotations

from algosdk import account, mnemonic
from algosdk.atomic_transaction_composer import AccountTransactionSigner
from algosdk.v2client.algod import AlgodClient
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AASConfig(BaseSettings):
    """AAS CLI configuration using pydantic-settings BaseSettings."""
    
    model_config = SettingsConfigDict(
        env_prefix='AAS_',
        env_file='.env',
        env_file_encoding='utf-8',
        secrets_dir='/run/secrets'
    )
    
    algod_url: str = Field(
        default="http://localhost:4001",
        description="Algorand node URL"
    )
    algod_token: str = Field(
        default="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        description="Algorand node API token"
    )
    app_id: int | None = Field(
        default=None,
        description="Deployed AAS application ID"
    )
    mnemonic: str | None = Field(
        default=None,
        description="Account mnemonic for transaction signing"
    )
    
    @field_validator('app_id')
    @classmethod
    def validate_app_id(cls, v: int | None) -> int | None:
        """Validate app ID is positive if provided."""
        if v is not None and v <= 0:
            raise ValueError("App ID must be positive")
        return v


def create_algod_client(config: AASConfig) -> AlgodClient:
    """Create Algod client from configuration."""
    return AlgodClient(config.algod_token, config.algod_url)


def create_signer(config: AASConfig) -> tuple[AccountTransactionSigner, str]:
    """Create transaction signer from mnemonic."""
    if not config.mnemonic:
        raise ValueError("Mnemonic required. Set AAS_MNEMONIC environment variable.")
    
    try:
        private_key = mnemonic.to_private_key(config.mnemonic)
        address = account.address_from_private_key(private_key)
        return AccountTransactionSigner(private_key), address
    except Exception as e:
        raise ValueError(f"Invalid mnemonic: {e}")


def validate_config(config: AASConfig) -> None:
    """Validate configuration completeness for CLI operations."""
    if not config.app_id:
        raise ValueError("App ID required. Set AAS_APP_ID environment variable.")
    if not config.mnemonic:
        raise ValueError("Mnemonic required. Set AAS_MNEMONIC environment variable.")
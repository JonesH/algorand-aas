"""Typer CLI for Algorand Attestation Service.

Provides commands: create-schema, grant-attester, attest, revoke, get.
Main entrypoint for the AAS command-line interface.
"""

from __future__ import annotations

import typer
from rich.console import Console

from aas import __version__


app = typer.Typer(
    name="aas",
    help="Algorand Attestation Service - Schema Registry + Attestation Writer",
    add_completion=False,
    rich_markup_mode="rich"
)
console = Console()


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
def create_schema() -> None:
    """Create a new attestation schema."""
    console.print("Creating schema... (not implemented yet)")


@app.command()
def grant_attester() -> None:
    """Grant attester permission to a schema."""
    console.print("Granting attester... (not implemented yet)")


@app.command()
def attest() -> None:
    """Create a new attestation.""" 
    console.print("Creating attestation... (not implemented yet)")


@app.command()
def revoke() -> None:
    """Revoke an existing attestation."""
    console.print("Revoking attestation... (not implemented yet)")


@app.command()
def get() -> None:
    """Get schema or attestation information."""
    console.print("Getting information... (not implemented yet)")


if __name__ == "__main__":
    app()
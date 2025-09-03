"""Algorand AAS Smart Contract - Beaker Router

Schema Registry + Attestation Writer using PyTeal + Beaker.
Stores schemas and attestations in boxes with minimal on-chain PII.
"""

from beaker import Application, external
from pyteal import (
    abi,
    Assert,
    Bytes,
    Concat,
    Itob,
    Log,
    BoxGet,
    BoxPut,
    Seq,
    Not,
    ScratchVar,
    TealType,
)


class AASApplication(Application):
    """AAS Application with Schema Registry functionality."""
    
    @external
    def create_schema(
        self,
        schema_id: abi.DynamicBytes,
        owner: abi.Address,
        uri: abi.String,
        flags: abi.Uint64,
    ):
        """Create new schema in registry."""
        key, val = ScratchVar(TealType.bytes), ScratchVar(TealType.bytes)
        return Seq(
            key.store(Concat(Bytes("schema:"), schema_id.get())),
            val.store(Concat(owner.get(), Itob(flags.get()), uri.get())),
            BoxPut(key.load(), val.load()),
            Log(Concat(Bytes("SchemaCreated:"), schema_id.get())),
        )


def get_app() -> Application:
    """Get the AAS Beaker application."""
    return AASApplication()


if __name__ == "__main__":
    app = get_app()
    print("AAS Application created successfully")
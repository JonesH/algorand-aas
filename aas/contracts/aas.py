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
    Txn,
    Extract,
    Len,
    Int,
    While,
    If,
    And,
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

    @external
    def grant_attester(
        self,
        schema_id: abi.DynamicBytes,
        attester_pk: abi.DynamicBytes,
    ):
        """Grant attester for a schema (idempotent).

        - Only schema owner may grant
        - Stores 32-byte attester keys concatenated in box: attesters:<schema_id>
        """
        skey, akey, cur, idx, found = (
            ScratchVar(TealType.bytes),
            ScratchVar(TealType.bytes),
            ScratchVar(TealType.bytes),
            ScratchVar(TealType.uint64),
            ScratchVar(TealType.uint64),
        )
        # Use single MaybeValue instances and include them in the Seq before reads
        schema_bg = BoxGet(skey.load())
        att_bg = BoxGet(akey.load())
        return Seq(
            # Load and check schema owner
            skey.store(Concat(Bytes("schema:"), schema_id.get())),
            schema_bg,
            Assert(schema_bg.hasValue()),
            cur.store(schema_bg.value()),
            Assert(Txn.sender() == Extract(cur.load(), Int(0), Int(32))),

            # Validate attester key length = 32
            Assert(Len(attester_pk.get()) == Int(32)),

            # Prepare attesters key and current list (if any)
            akey.store(Concat(Bytes("attesters:"), schema_id.get())),
            att_bg,
            If(att_bg.hasValue()).Then(
                cur.store(att_bg.value())
            ).Else(
                cur.store(Bytes(""))
            ),
            # Scan for existing key (idempotent)
            Assert((Len(cur.load()) % Int(32)) == Int(0)),
            idx.store(Int(0)),
            found.store(Int(0)),
            While(And(idx.load() < Len(cur.load()), found.load() == Int(0))).Do(
                Seq(
                    If(Extract(cur.load(), idx.load(), Int(32)) == attester_pk.get())
                    .Then(found.store(Int(1)))
                    .Else(idx.store(idx.load() + Int(32)))
                )
            ),
            # Append if not found
            If(found.load() == Int(0)).Then(
                BoxPut(akey.load(), Concat(cur.load(), attester_pk.get()))
            ),
            Log(Concat(Bytes("AttesterGranted:"), schema_id.get())),
        )


def get_app() -> Application:
    """Get the AAS Beaker application."""
    return AASApplication()


if __name__ == "__main__":
    app = get_app()
    print("AAS Application created successfully")

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
    Ed25519Verify_Bare,
    Sha256,
    OpUp,
    OpUpMode,
)


class AASApplication(Application):
    """AAS Application with Schema Registry functionality."""
    
    def _verify_attester_authorized(self, schema_id_bytes, sig_pk):
        """Check if attester public key is in authorized list."""
        akey, cur = (
            ScratchVar(TealType.bytes),
            ScratchVar(TealType.bytes)
        )
        att_bg = BoxGet(akey.load())
        return Seq(
            akey.store(Concat(Bytes("attesters:"), schema_id_bytes)),
            att_bg,
            Assert(att_bg.hasValue()),
            cur.store(att_bg.value()),
            self._find_attester_in_list(cur.load(), sig_pk)
        )
    
    def _find_attester_in_list(self, attesters_list, target_pk):
        """Search for attester public key in concatenated list."""
        idx, found = ScratchVar(TealType.uint64), ScratchVar(TealType.uint64)
        return Seq(
            idx.store(Int(0)),
            found.store(Int(0)),
            While(And(idx.load() < Len(attesters_list), found.load() == Int(0))).Do(
                Seq(
                    If(Extract(attesters_list, idx.load(), Int(32)) == target_pk)
                    .Then(found.store(Int(1)))
                    .Else(idx.store(idx.load() + Int(32)))
                )
            ),
            Assert(found.load() == Int(1))
        )
    
    def _verify_signature(self, message_bytes, signature_bytes, pk_bytes):
        """Verify ed25519 signature using Ed25519Verify_Bare."""
        opup = OpUp(OpUpMode.OnCall)
        return Seq(
            Assert(Len(signature_bytes) == Int(64)),
            Assert(Len(pk_bytes) == Int(32)),
            opup.ensure_budget(Int(2000)),  # Increase opcode budget for ed25519 verification
            Assert(Ed25519Verify_Bare(message_bytes, signature_bytes, pk_bytes))
        )
    
    def _check_attestation_unique(self, att_id_bytes):
        """Ensure attestation ID doesn't already exist."""
        existing = BoxGet(Concat(Bytes("att:"), att_id_bytes))
        return Seq(
            existing,
            Assert(Not(existing.hasValue()))
        )
    
    def _store_attestation(self, att_id_bytes, subject_addr_bytes, schema_id_bytes, cid_str):
        """Store attestation data in att:<att_id> box."""
        att_key, att_val = ScratchVar(TealType.bytes), ScratchVar(TealType.bytes)
        return Seq(
            att_key.store(Concat(Bytes("att:"), att_id_bytes)),
            att_val.store(Concat(
                Bytes("base64", "QQ=="),  # "A" = status OK (1 byte)
                subject_addr_bytes,       # subject (32 bytes)
                Itob(Len(schema_id_bytes)),  # schema_id length (8 bytes)
                schema_id_bytes,          # schema_id (variable)
                cid_str                   # cid string (variable)
            )),
            BoxPut(att_key.load(), att_val.load())
        )
    
    def _revoke_attestation(self, att_id_bytes, reason_u64):
        """Revoke attestation by updating status to 'R' in place."""
        att_key, cur_val, new_val = (
            ScratchVar(TealType.bytes),
            ScratchVar(TealType.bytes), 
            ScratchVar(TealType.bytes)
        )
        att_bg = BoxGet(att_key.load())
        return Seq(
            att_key.store(Concat(Bytes("att:"), att_id_bytes)),
            att_bg,
            Assert(att_bg.hasValue()),
            cur_val.store(att_bg.value()),
            Assert(Extract(cur_val.load(), Int(0), Int(1)) == Bytes("base64", "QQ==")),  # Must be "A" (active)
            # Replace status byte with "R" and keep same size by overwriting last 8 bytes with reason
            new_val.store(Concat(
                Bytes("base64", "Ug=="),  # "R" = status Revoked (1 byte)
                Extract(cur_val.load(), Int(1), Len(cur_val.load()) - Int(9)),  # Keep middle data 
                Itob(reason_u64)  # Replace last 8 bytes with revocation reason
            )),
            BoxPut(att_key.load(), new_val.load())
        )
    
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

    @external
    def attest(
        self,
        schema_id: abi.DynamicBytes,
        subject_addr: abi.Address,
        claim_hash_32: abi.DynamicBytes,
        nonce_32: abi.DynamicBytes,
        sig_64: abi.DynamicBytes,
        cid: abi.String,
        attester_pk: abi.DynamicBytes,
    ):
        """Create attestation with signature verification.
        
        Verifies ed25519 signature from authorized attester.
        Stores attestation in att:<att_id> box.
        """
        message, att_id = ScratchVar(TealType.bytes), ScratchVar(TealType.bytes)
        return Seq(
            # Validate input lengths
            Assert(Len(claim_hash_32.get()) == Int(32)),
            Assert(Len(nonce_32.get()) == Int(32)),
            
            # Build canonical message: schema_id + subject + claim_hash + nonce
            message.store(Concat(
                schema_id.get(),
                subject_addr.get(), 
                claim_hash_32.get(),
                nonce_32.get()
            )),
            # Generate attestation ID
            att_id.store(Sha256(message.load())),
            
            # Verify attester is authorized for this schema
            self._verify_attester_authorized(schema_id.get(), attester_pk.get()),
            
            # Verify signature
            self._verify_signature(message.load(), sig_64.get(), attester_pk.get()),
            
            # Ensure attestation is unique
            self._check_attestation_unique(att_id.load()),
            
            # Store attestation
            self._store_attestation(att_id.load(), subject_addr.get(), schema_id.get(), cid.get()),
            
            Log(Concat(Bytes("Attested:"), att_id.load())),
        )

    @external
    def revoke(
        self,
        att_id: abi.DynamicBytes,
        reason: abi.Uint64,
    ):
        """Revoke existing attestation.
        
        Authorization: only the attestation subject may revoke.
        Subject address is stored in the attestation box value.
        """
        att_key, cur_val = ScratchVar(TealType.bytes), ScratchVar(TealType.bytes)
        att_bg = BoxGet(att_key.load())
        return Seq(
            # Validate attestation ID length
            Assert(Len(att_id.get()) == Int(32)),
            # Load attestation to check status and subject authorization
            att_key.store(Concat(Bytes("att:"), att_id.get())),
            att_bg,
            Assert(att_bg.hasValue()),
            cur_val.store(att_bg.value()),
            # Must be active ("A") before revocation
            Assert(Extract(cur_val.load(), Int(0), Int(1)) == Bytes("base64", "QQ==")),
            # Authorize: sender must be the subject
            Assert(Txn.sender() == Extract(cur_val.load(), Int(1), Int(32))),
            
            # Revoke attestation
            self._revoke_attestation(att_id.get(), reason.get()),
            
            Log(Concat(Bytes("Revoked:"), att_id.get())),
        )


def get_app() -> Application:
    """Get the AAS Beaker application."""
    return AASApplication()


if __name__ == "__main__":
    app = get_app()
    print("AAS Application created successfully")

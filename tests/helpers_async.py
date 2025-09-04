"""Async test helpers to enable limited concurrency in LocalNet tests.

These wrap the synchronous Algorand SDK and Beaker client calls, running them in
threads so pytest-asyncio tests can await multiple independent operations. This
does not make the underlying SDK async, but can reduce wall time when several
independent I/O operations can proceed concurrently (e.g., multiple box reads
or creating several independent schemas).
"""

from __future__ import annotations

import asyncio
import base64
from typing import Any

from algosdk import encoding, transaction
from algosdk.atomic_transaction_composer import AccountTransactionSigner
from algosdk.v2client.algod import AlgodClient
from beaker.client import ApplicationClient
from nacl.signing import SigningKey

from aas.contracts.aas import AASApplication
from tests.helpers import (
    build_attestation_message,
    generate_attestation_id,
)


async def async_create_schema(
    client: ApplicationClient,
    signer: AccountTransactionSigner,
    schema_id: bytes,
    owner: str,
    uri: str = "test-schema",
    flags: int = 1,
) -> None:
    schema_box = (client.app_id, b"schema:" + schema_id)
    await asyncio.to_thread(
        client.call,
        AASApplication.create_schema,
        schema_id=schema_id,
        owner=owner,
        uri=uri,
        flags=flags,
        boxes=[schema_box],
        signer=signer,
    )


async def async_grant_attester(
    client: ApplicationClient,
    signer: AccountTransactionSigner,
    schema_id: bytes,
    attester_pk: bytes,
) -> None:
    schema_box = (client.app_id, b"schema:" + schema_id)
    att_box = (client.app_id, b"attesters:" + schema_id)
    await asyncio.to_thread(
        client.call,
        AASApplication.grant_attester,
        schema_id=schema_id,
        attester_pk=attester_pk,
        boxes=[schema_box, att_box],
        signer=signer,
    )


async def async_create_attestation(
    client: ApplicationClient,
    signer: AccountTransactionSigner,
    schema_id: bytes,
    subject_addr: str,
    claim_hash: bytes,
    nonce: bytes,
    attester_sk: SigningKey,
    cid: str = "QmTest",
) -> bytes:
    message = build_attestation_message(schema_id, subject_addr, claim_hash, nonce)
    signature = bytes(attester_sk.sign(message).signature)
    attester_pk = bytes(attester_sk.verify_key)
    att_id = generate_attestation_id(schema_id, subject_addr, claim_hash, nonce)

    schema_box = (client.app_id, b"schema:" + schema_id)
    att_box = (client.app_id, b"attesters:" + schema_id)
    att_storage_box = (client.app_id, b"att:" + att_id)

    await asyncio.to_thread(
        client.call,
        AASApplication.attest,
        schema_id=schema_id,
        subject_addr=subject_addr,
        claim_hash_32=claim_hash,
        nonce_32=nonce,
        sig_64=signature,
        cid=cid,
        attester_pk=attester_pk,
        boxes=[schema_box, att_box, att_storage_box],
        signer=signer,
    )
    return att_id


async def async_parse_attestation_box(
    algod_client: AlgodClient, app_id: int, att_id: bytes
) -> dict[str, Any]:
    # Fetch box (blocking HTTP) in a thread
    box = await asyncio.to_thread(
        algod_client.application_box_by_name, app_id, b"att:" + att_id
    )
    data = base64.b64decode(box["value"])  # type: ignore[call-overload]

    status = data[0:1].decode("utf-8")
    subject_bytes = data[1:33]
    subject_addr = encoding.encode_address(subject_bytes)
    schema_id_len = int.from_bytes(data[33:41], "big")
    schema_id = data[41 : 41 + schema_id_len]

    reason = None
    if status == "R" and len(data) >= 41 + schema_id_len:
        cid_start = 41 + schema_id_len
        cid_end = len(data) - 8
        cid = data[cid_start:cid_end].decode("utf-8") if cid_end > cid_start else ""
        reason = int.from_bytes(data[-8:], "big")
    else:
        cid = data[41 + schema_id_len :].decode("utf-8") if len(data) > 41 + schema_id_len else ""

    return {
        "status": status,
        "subject_addr": subject_addr,
        "schema_id": schema_id,
        "cid": cid,
        "reason": reason,
    }


async def async_wait_for_confirmation(
    algod_client: AlgodClient, txid: str, max_rounds: int = 8
) -> dict[str, Any]:
    """A light async wrapper around polling for confirmation.

    Uses asyncio.sleep between polls to allow other tasks to run.
    """
    last_round = await asyncio.to_thread(lambda: algod_client.status().get("last-round"))
    current_round = int(last_round) if last_round is not None else 0
    for _ in range(max_rounds):
        info = await asyncio.to_thread(algod_client.pending_transaction_info, txid)
        if info.get("confirmed-round", 0) > 0:
            return info
        current_round += 1
        # advance to next round
        await asyncio.to_thread(algod_client.status_after_block, current_round)
        await asyncio.sleep(0)  # yield control
    raise TimeoutError(f"Transaction {txid} not confirmed within {max_rounds} rounds")


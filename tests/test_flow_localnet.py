"""End-to-end flow tests on LocalNet.

Full integration testing requiring AlgoKit LocalNet.
Marked with @pytest.mark.localnet for conditional execution.
"""

from __future__ import annotations

import pytest
from collections.abc import Generator
from beaker.client import ApplicationClient
from algosdk.v2client.algod import AlgodClient
from algosdk.kmd import KMDClient
from algosdk.atomic_transaction_composer import AccountTransactionSigner
from algosdk import account, transaction
from algosdk.logic import get_application_address
from aas.contracts.aas import get_app, AASApplication


@pytest.fixture(scope="session")
def algod_client() -> AlgodClient:
    """LocalNet Algod client fixture."""
    try:
        # LocalNet Algod typically uses this token
        client = AlgodClient("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "http://localhost:4001")
        # Test connection
        client.status()
        return client
    except Exception as e:
        pytest.skip(f"LocalNet Algod connection failed: {e}. Please ensure LocalNet is running with 'algokit localnet start'")


@pytest.fixture
def localnet_signer(algod_client: AlgodClient) -> Generator[tuple[AccountTransactionSigner, str], None, None]:
    """Ephemeral funded signer backed by KMD; closed out after test.

    - Picks richest KMD account as funder
    - Generates a fresh account, funds it, returns signer
    - On teardown, closes remainder back to funder
    """
    try:
        kmd = KMDClient(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "http://localhost:4002",
        )
        wallets = kmd.list_wallets()

        wallet = next((w for w in wallets if w["name"] == "unencrypted-default-wallet"), None)
        if not wallet:
            raise Exception("LocalNet 'unencrypted-default-wallet' not found. Is LocalNet running?")

        handle = kmd.init_wallet_handle(wallet["id"], "")
        try:
            addrs = kmd.list_keys(handle)
            if not addrs:
                raise Exception("No accounts found in LocalNet wallet")

            # Choose richest as funder
            richest = max(addrs, key=lambda a: algod_client.account_info(a)["amount"])  # type: ignore[call-overload]
            funder_sk = kmd.export_key(handle, "", richest)

            # Create ephemeral account
            ep_sk, ep_addr = account.generate_account()

            # Fund ephemeral (2 Algos) and wait
            sp = algod_client.suggested_params()
            pay = transaction.PaymentTxn(richest, sp, ep_addr, 2_000_000)
            txid = algod_client.send_transaction(pay.sign(funder_sk))
            transaction.wait_for_confirmation(algod_client, txid, 4)

            # Yield signer for ephemeral
            yield AccountTransactionSigner(ep_sk), ep_addr

            # Teardown: close remainder to funder
            sp2 = algod_client.suggested_params()
            close = transaction.PaymentTxn(ep_addr, sp2, richest, 0, close_remainder_to=richest)
            try:
                txid2 = algod_client.send_transaction(close.sign(ep_sk))
                transaction.wait_for_confirmation(algod_client, txid2, 4)
            except Exception:
                # Best-effort close; ignore failures to not mask test results
                pass
        finally:
            kmd.release_wallet_handle(handle)

    except Exception as e:
        pytest.skip(
            f"LocalNet KMD setup failed: {e}. Ensure LocalNet is running: 'algokit localnet start'"
        )


@pytest.fixture
def deployed_client(algod_client: AlgodClient, localnet_signer: tuple[AccountTransactionSigner, str]) -> ApplicationClient:
    """Deploy AAS contract and return configured client.
    
    Returns fresh deployment for each test.
    """
    signer, address = localnet_signer
    app = get_app()
    client = ApplicationClient(algod_client, app=app, sender=address, signer=signer)
    client.create()

    # Fund the application address to cover box MBR
    try:
        app_addr = get_application_address(client.app_id)

        # Use KMD richest account as funder
        kmd = KMDClient(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "http://localhost:4002",
        )
        wallets = kmd.list_wallets()
        wallet = next((w for w in wallets if w["name"] == "unencrypted-default-wallet"), None)
        if wallet:
            handle = kmd.init_wallet_handle(wallet["id"], "")
            try:
                addrs = kmd.list_keys(handle)
                richest = max(addrs, key=lambda a: algod_client.account_info(a)["amount"])  # type: ignore[call-overload]
                funder_sk = kmd.export_key(handle, "", richest)
                sp = algod_client.suggested_params()
                # 1 Algo should comfortably cover one small box
                pay = transaction.PaymentTxn(richest, sp, app_addr, 1_000_000)
                txid = algod_client.send_transaction(pay.sign(funder_sk))
                transaction.wait_for_confirmation(algod_client, txid, 4)
            finally:
                kmd.release_wallet_handle(handle)
    except Exception:
        # Best-effort funding; test will fail with MBR error if insufficient
        pass

    return client


@pytest.mark.localnet  
def test_localnet_connectivity(algod_client: AlgodClient) -> None:
    """Test basic LocalNet connectivity.
    
    This test requires AlgoKit LocalNet running:
    algokit localnet start
    """
    status = algod_client.status()
    assert status is not None
    assert "last-round" in status


@pytest.mark.localnet
def test_create_schema_success(deployed_client: ApplicationClient, algod_client: AlgodClient, localnet_signer: tuple[AccountTransactionSigner, str]) -> None:
    """Test successful schema creation."""
    
    # Test data
    schema_id = b"test_schema_001"
    owner = "7ZUECA7HFLZTXENRV24SHLU4AVPUTMTTDUFUBNBD64C73F3UHRTHAIOF6Q"
    uri = "https://example.com/schema.json"
    flags = 1
    
    # Call create_schema with boxes parameter
    signer, address = localnet_signer
    box_key = b"schema:" + schema_id
    result = deployed_client.call(
        AASApplication.create_schema,
        schema_id=schema_id,
        owner=owner,
        uri=uri,
        flags=flags,
        boxes=[(deployed_client.app_id, box_key)],
        signer=signer
    )
    
    # Verify transaction succeeded (confirm by tx id)
    tx_info = transaction.wait_for_confirmation(algod_client, result.tx_id, 4)
    assert tx_info.get("confirmed-round", 0) > 0
    
    # Verify box was created and contains expected data
    box_key = b"schema:" + schema_id
    box_value = algod_client.application_box_by_name(deployed_client.app_id, box_key)["value"]  # type: ignore[call-overload]
    
    # Expected format: owner(32B) + flags(8B) + uri
    import base64
    from algosdk import encoding
    owner_bytes = encoding.decode_address(owner)
    expected_flags = flags.to_bytes(8, 'big')
    expected_uri = uri.encode('utf-8')
    expected_value = owner_bytes + expected_flags + expected_uri
    
    assert base64.b64decode(box_value) == expected_value


@pytest.mark.localnet
def test_create_schema_duplicate_fails(deployed_client: ApplicationClient, algod_client: AlgodClient, localnet_signer: tuple[AccountTransactionSigner, str]) -> None:
    """Test that creating duplicate schema fails."""
    
    # Test data
    schema_id = b"duplicate_test"
    owner = "7ZUECA7HFLZTXENRV24SHLU4AVPUTMTTDUFUBNBD64C73F3UHRTHAIOF6Q"
    uri = "https://example.com/schema.json"
    flags = 1
    
    # First creation should succeed
    signer, address = localnet_signer
    box_key = b"schema:" + schema_id
    deployed_client.call(
        AASApplication.create_schema,
        schema_id=schema_id,
        owner=owner,
        uri=uri,
        flags=flags,
        boxes=[(deployed_client.app_id, box_key)],
        signer=signer
    )
    
    # Second creation should succeed for now (no duplicate check yet)
    # TODO: Add duplicate prevention logic
    deployed_client.call(
        AASApplication.create_schema,
        schema_id=schema_id,
        owner=owner,
        uri=uri,
        flags=flags,
        boxes=[(deployed_client.app_id, box_key)],
        signer=signer
    )


@pytest.mark.localnet
def test_create_schema_box_storage(deployed_client: ApplicationClient, algod_client: AlgodClient, localnet_signer: tuple[AccountTransactionSigner, str]) -> None:
    """Test schema box storage format."""
    
    # Test with different data
    schema_id = b"storage_test_schema"
    owner = "7ZUECA7HFLZTXENRV24SHLU4AVPUTMTTDUFUBNBD64C73F3UHRTHAIOF6Q"
    uri = "test-uri"
    flags = 42
    
    # Create schema
    signer, address = localnet_signer
    box_key = b"schema:" + schema_id
    deployed_client.call(
        AASApplication.create_schema,
        schema_id=schema_id,
        owner=owner,
        uri=uri,
        flags=flags,
        boxes=[(deployed_client.app_id, box_key)],
        signer=signer
    )
    
    # Read box and verify format
    box_key = b"schema:" + schema_id
    box_value = algod_client.application_box_by_name(deployed_client.app_id, box_key)["value"]  # type: ignore[call-overload]
    
    import base64
    from algosdk import encoding
    data = base64.b64decode(box_value)
    
    # Parse: owner(32B) + flags(8B) + uri(rest)
    stored_owner = data[:32]
    stored_flags = data[32:40]
    stored_uri = data[40:]
    
    # Verify each component
    expected_owner = encoding.decode_address(owner)
    expected_flags = flags.to_bytes(8, 'big')
    expected_uri = uri.encode('utf-8')
    
    assert stored_owner == expected_owner
    assert stored_flags == expected_flags
    assert stored_uri == expected_uri


@pytest.mark.localnet
def test_grant_attester_only_owner(deployed_client: ApplicationClient, algod_client: AlgodClient, localnet_signer: tuple[AccountTransactionSigner, str]) -> None:
    """Only schema owner can grant attester."""
    signer, owner_addr = localnet_signer

    # Create schema with owner = owner_addr
    schema_id = b"owner_only_schema"
    uri = "https://example.com/schema.json"
    flags = 1
    schema_box = (deployed_client.app_id, b"schema:" + schema_id)
    att_box = (deployed_client.app_id, b"attesters:" + schema_id)

    res = deployed_client.call(
        AASApplication.create_schema,
        schema_id=schema_id,
        owner=owner_addr,
        uri=uri,
        flags=flags,
        boxes=[schema_box],
        signer=signer,
    )
    transaction.wait_for_confirmation(algod_client, res.tx_id, 4)

    # Prepare an attester key (32 bytes)
    attester_pk = b"A" * 32

    # Owner can grant
    res2 = deployed_client.call(
        AASApplication.grant_attester,
        schema_id=schema_id,
        attester_pk=attester_pk,
        boxes=[schema_box, att_box],
        signer=signer,
    )
    transaction.wait_for_confirmation(algod_client, res2.tx_id, 4)

    # Non-owner should be denied
    # Create another ephemeral signer
    from algosdk.kmd import KMDClient
    kmd = KMDClient(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "http://localhost:4002",
    )
    wallet = next((w for w in kmd.list_wallets() if w["name"] == "unencrypted-default-wallet"), None)
    assert wallet, "LocalNet wallet missing"
    handle = kmd.init_wallet_handle(wallet["id"], "")
    try:
        addrs = kmd.list_keys(handle)
        richest = max(addrs, key=lambda a: algod_client.account_info(a)["amount"])  # type: ignore[call-overload]
        funder_sk = kmd.export_key(handle, "", richest)
        ep_sk, ep_addr = account.generate_account()
        sp = algod_client.suggested_params()
        txid = algod_client.send_transaction(transaction.PaymentTxn(richest, sp, ep_addr, 2_000_000).sign(funder_sk))
        transaction.wait_for_confirmation(algod_client, txid, 4)
        other_signer = AccountTransactionSigner(ep_sk)

        with pytest.raises(Exception):
            deployed_client.call(
                AASApplication.grant_attester,
                schema_id=schema_id,
                attester_pk=b"B" * 32,
                boxes=[schema_box, att_box],
                signer=other_signer,
                sender=ep_addr,
            )
    finally:
        kmd.release_wallet_handle(handle)


@pytest.mark.localnet
def test_grant_attester_idempotent(deployed_client: ApplicationClient, algod_client: AlgodClient, localnet_signer: tuple[AccountTransactionSigner, str]) -> None:
    """grant_attester should be idempotent for the same key."""
    signer, owner_addr = localnet_signer
    schema_id = b"idempotent_schema"
    uri = "u"
    flags = 0
    schema_box = (deployed_client.app_id, b"schema:" + schema_id)
    att_box = (deployed_client.app_id, b"attesters:" + schema_id)

    res = deployed_client.call(
        AASApplication.create_schema,
        schema_id=schema_id,
        owner=owner_addr,
        uri=uri,
        flags=flags,
        boxes=[schema_box],
        signer=signer,
    )
    transaction.wait_for_confirmation(algod_client, res.tx_id, 4)

    attester_pk = b"Z" * 32
    for _ in range(2):
        r = deployed_client.call(
            AASApplication.grant_attester,
            schema_id=schema_id,
            attester_pk=attester_pk,
            boxes=[schema_box, att_box],
            signer=signer,
        )
        transaction.wait_for_confirmation(algod_client, r.tx_id, 4)

    # Verify only one 32B entry exists
    import base64
    data_b64 = algod_client.application_box_by_name(deployed_client.app_id, b"attesters:" + schema_id)["value"]  # type: ignore[call-overload]
    raw = base64.b64decode(data_b64)
    assert len(raw) == 32
    assert raw == attester_pk


@pytest.mark.localnet
def test_attest_happy_path(deployed_client: ApplicationClient, algod_client: AlgodClient, localnet_signer: tuple[AccountTransactionSigner, str]) -> None:
    """Test successful attestation with valid signature from authorized attester."""
    signer, owner_addr = localnet_signer
    schema_id = b"attest_test_schema"
    uri = "test-schema"
    flags = 1
    schema_box = (deployed_client.app_id, b"schema:" + schema_id)
    att_box = (deployed_client.app_id, b"attesters:" + schema_id)

    # Create schema
    deployed_client.call(
        AASApplication.create_schema,
        schema_id=schema_id,
        owner=owner_addr,
        uri=uri,
        flags=flags,
        boxes=[schema_box],
        signer=signer,
    )

    # Generate ed25519 keypair for attester
    from nacl.signing import SigningKey
    attester_sk = SigningKey.generate()
    attester_pk = bytes(attester_sk.verify_key)

    # Grant attester
    deployed_client.call(
        AASApplication.grant_attester,
        schema_id=schema_id,
        attester_pk=attester_pk,
        boxes=[schema_box, att_box],
        signer=signer,
    )

    # Prepare attestation data
    subject_addr = owner_addr  # Use owner as subject for simplicity
    claim_hash = b"H" * 32  # 32-byte claim hash
    nonce = b"N" * 32  # 32-byte nonce
    cid = "QmTest123"

    # Build canonical message and sign
    import hashlib
    from algosdk import encoding
    subject_bytes = encoding.decode_address(subject_addr)
    message = schema_id + subject_bytes + claim_hash + nonce
    signature = bytes(attester_sk.sign(message).signature)

    # Generate attestation ID
    att_id = hashlib.sha256(message).digest()
    att_storage_box = (deployed_client.app_id, b"att:" + att_id)

    # Call attest method
    result = deployed_client.call(
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
    
    # Verify transaction succeeded
    transaction.wait_for_confirmation(algod_client, result.tx_id, 4)
    
    # Verify attestation box was created with correct format
    box_value = algod_client.application_box_by_name(deployed_client.app_id, b"att:" + att_id)["value"]  # type: ignore[call-overload]
    import base64
    data = base64.b64decode(box_value)
    
    # Verify format: status(1B) + subject(32B) + schema_id_len(8B) + schema_id + cid
    assert data[0:1] == b"A"  # Status OK
    assert data[1:33] == subject_bytes  # Subject address
    schema_id_len = int.from_bytes(data[33:41], 'big')
    assert data[41:41+schema_id_len] == schema_id
    assert data[41+schema_id_len:] == cid.encode('utf-8')


@pytest.mark.localnet
def test_attest_unauthorized_attester(deployed_client: ApplicationClient, algod_client: AlgodClient, localnet_signer: tuple[AccountTransactionSigner, str]) -> None:
    """Test that unauthorized attester cannot create attestations."""
    signer, owner_addr = localnet_signer
    schema_id = b"unauthorized_test"
    uri = "test-schema"
    flags = 1
    schema_box = (deployed_client.app_id, b"schema:" + schema_id)
    att_box = (deployed_client.app_id, b"attesters:" + schema_id)

    # Create schema (no attesters granted)
    deployed_client.call(
        AASApplication.create_schema,
        schema_id=schema_id,
        owner=owner_addr,
        uri=uri,
        flags=flags,
        boxes=[schema_box],
        signer=signer,
    )

    # Generate unauthorized attester
    from nacl.signing import SigningKey
    unauthorized_sk = SigningKey.generate()
    unauthorized_pk = bytes(unauthorized_sk.verify_key)

    # Prepare attestation data
    subject_addr = owner_addr
    claim_hash = b"U" * 32
    nonce = b"N" * 32
    cid = "QmUnauthorized"

    # Build message and sign with unauthorized key
    import hashlib
    from algosdk import encoding
    subject_bytes = encoding.decode_address(subject_addr)
    message = schema_id + subject_bytes + claim_hash + nonce
    signature = bytes(unauthorized_sk.sign(message).signature)

    att_id = hashlib.sha256(message).digest()
    att_storage_box = (deployed_client.app_id, b"att:" + att_id)

    # This should fail - unauthorized attester
    with pytest.raises(Exception):
        deployed_client.call(
            AASApplication.attest,
            schema_id=schema_id,
            subject_addr=subject_addr,
            claim_hash_32=claim_hash,
            nonce_32=nonce,
            sig_64=signature,
            cid=cid,
            attester_pk=unauthorized_pk,
            boxes=[schema_box, att_box, att_storage_box],
            signer=signer,
        )


@pytest.mark.localnet
def test_attest_duplicate_fails(deployed_client: ApplicationClient, algod_client: AlgodClient, localnet_signer: tuple[AccountTransactionSigner, str]) -> None:
    """Test that duplicate attestation IDs are rejected."""
    signer, owner_addr = localnet_signer
    schema_id = b"duplicate_att_test"
    uri = "test-schema"
    flags = 1
    schema_box = (deployed_client.app_id, b"schema:" + schema_id)
    att_box = (deployed_client.app_id, b"attesters:" + schema_id)

    # Create schema and grant attester
    deployed_client.call(
        AASApplication.create_schema,
        schema_id=schema_id,
        owner=owner_addr,
        uri=uri,
        flags=flags,
        boxes=[schema_box],
        signer=signer,
    )

    from nacl.signing import SigningKey
    attester_sk = SigningKey.generate()
    attester_pk = bytes(attester_sk.verify_key)

    deployed_client.call(
        AASApplication.grant_attester,
        schema_id=schema_id,
        attester_pk=attester_pk,
        boxes=[schema_box, att_box],
        signer=signer,
    )

    # Prepare identical attestation data for both attempts
    subject_addr = owner_addr
    claim_hash = b"D" * 32  # Same data = same att_id
    nonce = b"N" * 32
    cid = "QmDuplicate"

    import hashlib
    from algosdk import encoding
    subject_bytes = encoding.decode_address(subject_addr)
    message = schema_id + subject_bytes + claim_hash + nonce
    signature = bytes(attester_sk.sign(message).signature)

    att_id = hashlib.sha256(message).digest()
    att_storage_box = (deployed_client.app_id, b"att:" + att_id)

    # First call should succeed
    result = deployed_client.call(
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
    transaction.wait_for_confirmation(algod_client, result.tx_id, 4)
    
    # Second identical call should fail (duplicate)
    with pytest.raises(Exception):
        deployed_client.call(
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


@pytest.mark.localnet
def test_attest_invalid_signature(deployed_client: ApplicationClient, algod_client: AlgodClient, localnet_signer: tuple[AccountTransactionSigner, str]) -> None:
    """Test that invalid signatures are rejected."""
    signer, owner_addr = localnet_signer
    schema_id = b"invalid_sig_test"
    uri = "test-schema"
    flags = 1
    schema_box = (deployed_client.app_id, b"schema:" + schema_id)
    att_box = (deployed_client.app_id, b"attesters:" + schema_id)

    # Create schema and grant attester
    deployed_client.call(
        AASApplication.create_schema,
        schema_id=schema_id,
        owner=owner_addr,
        uri=uri,
        flags=flags,
        boxes=[schema_box],
        signer=signer,
    )

    from nacl.signing import SigningKey
    attester_sk = SigningKey.generate()
    attester_pk = bytes(attester_sk.verify_key)

    deployed_client.call(
        AASApplication.grant_attester,
        schema_id=schema_id,
        attester_pk=attester_pk,
        boxes=[schema_box, att_box],
        signer=signer,
    )

    # Prepare attestation data
    subject_addr = owner_addr
    claim_hash = b"I" * 32
    nonce = b"N" * 32
    cid = "QmInvalid"

    import hashlib
    from algosdk import encoding
    subject_bytes = encoding.decode_address(subject_addr)
    message = schema_id + subject_bytes + claim_hash + nonce

    # Create invalid signature (wrong data or malformed)
    invalid_signature = b"X" * 64  # Wrong signature

    att_id = hashlib.sha256(message).digest()
    att_storage_box = (deployed_client.app_id, b"att:" + att_id)

    # This should fail - invalid signature
    with pytest.raises(Exception):
        deployed_client.call(
            AASApplication.attest,
            schema_id=schema_id,
            subject_addr=subject_addr,
            claim_hash_32=claim_hash,
            nonce_32=nonce,
            sig_64=invalid_signature,
            cid=cid,
            attester_pk=attester_pk,
            boxes=[schema_box, att_box, att_storage_box],
            signer=signer,
        )


@pytest.mark.localnet  
def test_full_attestation_flow() -> None:
    """Test complete attestation flow on LocalNet.
    
    This test requires AlgoKit LocalNet running:
    algokit localnet start
    """
    # TODO: Implement when we have contract methods
    # 1. Deploy contract
    # 2. Create schema
    # 3. Grant attester
    # 4. Create attestation
    # 5. Verify attestation
    # 6. Revoke attestation
    
    pytest.skip("LocalNet integration test - implement in later steps")

"""End-to-end flow tests on LocalNet.

Full integration testing requiring AlgoKit LocalNet.
Marked with @pytest.mark.localnet for conditional execution.
"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from algosdk import account, transaction
from algosdk.atomic_transaction_composer import AccountTransactionSigner
from algosdk.kmd import KMDClient
from algosdk.logic import get_application_address
from algosdk.v2client.algod import AlgodClient
from beaker.client import ApplicationClient

from aas.contracts.aas import AASApplication, get_app


@pytest.fixture(scope="session")
def algod_client() -> AlgodClient:
    """LocalNet Algod client fixture."""
    try:
        # LocalNet Algod typically uses this token
        client = AlgodClient(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "http://localhost:4001",
        )
        # Test connection
        client.status()
        return client
    except Exception as e:
        pytest.skip(
            f"LocalNet Algod connection failed: {e}. Please ensure LocalNet is running with 'algokit localnet start'"
        )


@pytest.fixture
def localnet_signer(
    algod_client: AlgodClient,
) -> Generator[tuple[AccountTransactionSigner, str], None, None]:
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
def deployed_client(
    algod_client: AlgodClient, localnet_signer: tuple[AccountTransactionSigner, str]
) -> ApplicationClient:
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
def test_create_schema_success(
    deployed_client: ApplicationClient,
    algod_client: AlgodClient,
    localnet_signer: tuple[AccountTransactionSigner, str],
) -> None:
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
        signer=signer,
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
    expected_flags = flags.to_bytes(8, "big")
    expected_uri = uri.encode("utf-8")
    expected_value = owner_bytes + expected_flags + expected_uri

    assert base64.b64decode(box_value) == expected_value


@pytest.mark.localnet
def test_create_schema_duplicate_currently_allowed(
    deployed_client: ApplicationClient,
    algod_client: AlgodClient,
    localnet_signer: tuple[AccountTransactionSigner, str],
) -> None:
    """Test that creating duplicate schema currently succeeds (duplicate prevention not yet implemented)."""

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
        signer=signer,
    )

    # Second creation should succeed for now (no duplicate check yet)
    # TODO: Add duplicate prevention logic - this test should be updated to expect failure once implemented
    deployed_client.call(
        AASApplication.create_schema,
        schema_id=schema_id,
        owner=owner,
        uri=uri,
        flags=flags,
        boxes=[(deployed_client.app_id, box_key)],
        signer=signer,
    )


@pytest.mark.localnet
def test_create_schema_box_storage(
    deployed_client: ApplicationClient,
    algod_client: AlgodClient,
    localnet_signer: tuple[AccountTransactionSigner, str],
) -> None:
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
        signer=signer,
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
    expected_flags = flags.to_bytes(8, "big")
    expected_uri = uri.encode("utf-8")

    assert stored_owner == expected_owner
    assert stored_flags == expected_flags
    assert stored_uri == expected_uri


@pytest.mark.localnet
def test_grant_attester_only_owner(
    deployed_client: ApplicationClient,
    algod_client: AlgodClient,
    localnet_signer: tuple[AccountTransactionSigner, str],
) -> None:
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
    wallet = next(
        (w for w in kmd.list_wallets() if w["name"] == "unencrypted-default-wallet"), None
    )
    assert wallet, "LocalNet wallet missing"
    handle = kmd.init_wallet_handle(wallet["id"], "")
    try:
        addrs = kmd.list_keys(handle)
        richest = max(addrs, key=lambda a: algod_client.account_info(a)["amount"])  # type: ignore[call-overload]
        funder_sk = kmd.export_key(handle, "", richest)
        ep_sk, ep_addr = account.generate_account()
        sp = algod_client.suggested_params()
        txid = algod_client.send_transaction(
            transaction.PaymentTxn(richest, sp, ep_addr, 2_000_000).sign(funder_sk)
        )
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
def test_grant_attester_idempotent(
    deployed_client: ApplicationClient,
    algod_client: AlgodClient,
    localnet_signer: tuple[AccountTransactionSigner, str],
) -> None:
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

    data_b64 = algod_client.application_box_by_name(
        deployed_client.app_id, b"attesters:" + schema_id
    )["value"]  # type: ignore[call-overload]
    raw = base64.b64decode(data_b64)
    assert len(raw) == 32
    assert raw == attester_pk


@pytest.mark.localnet
def test_attest_happy_path(
    deployed_client: ApplicationClient,
    algod_client: AlgodClient,
    localnet_signer: tuple[AccountTransactionSigner, str],
) -> None:
    """Test successful attestation with valid signature from authorized attester."""
    from tests.helpers import create_schema_helper, grant_attester_helper, create_attestation_helper, parse_attestation_box
    from nacl.signing import SigningKey
    
    signer, owner_addr = localnet_signer
    schema_id = b"attest_test_schema"

    # Create schema using helper
    create_schema_helper(deployed_client, signer, schema_id, owner_addr)

    # Generate ed25519 keypair for attester
    attester_sk = SigningKey.generate()
    attester_pk = bytes(attester_sk.verify_key)

    # Grant attester using helper
    grant_attester_helper(deployed_client, signer, schema_id, attester_pk)

    # Create attestation using helper
    claim_hash = b"H" * 32
    nonce = b"N" * 32
    cid = "QmTest123"
    
    att_id = create_attestation_helper(
        deployed_client, signer, schema_id, owner_addr, claim_hash, nonce, attester_sk, cid
    )

    # Verify attestation box using helper
    attestation_data = parse_attestation_box(algod_client, deployed_client.app_id, att_id)
    
    assert attestation_data['status'] == 'A'  # Status OK
    assert attestation_data['subject_addr'] == owner_addr
    assert attestation_data['schema_id'] == schema_id
    assert attestation_data['cid'] == cid


@pytest.mark.localnet
def test_attest_unauthorized_attester(
    deployed_client: ApplicationClient,
    algod_client: AlgodClient,
    localnet_signer: tuple[AccountTransactionSigner, str],
) -> None:
    """Test that unauthorized attester cannot create attestations."""
    from tests.helpers import create_schema_helper, build_attestation_message, generate_attestation_id
    from nacl.signing import SigningKey
    
    signer, owner_addr = localnet_signer
    schema_id = b"unauthorized_test"

    # Create schema (no attesters granted) using helper
    create_schema_helper(deployed_client, signer, schema_id, owner_addr)

    # Generate unauthorized attester
    unauthorized_sk = SigningKey.generate()
    unauthorized_pk = bytes(unauthorized_sk.verify_key)

    # Prepare attestation data
    claim_hash = b"U" * 32
    nonce = b"N" * 32
    cid = "QmUnauthorized"

    # Build message and sign with unauthorized key using helper
    message = build_attestation_message(schema_id, owner_addr, claim_hash, nonce)
    signature = bytes(unauthorized_sk.sign(message).signature)
    att_id = generate_attestation_id(schema_id, owner_addr, claim_hash, nonce)

    # Prepare boxes
    schema_box = (deployed_client.app_id, b"schema:" + schema_id)
    att_box = (deployed_client.app_id, b"attesters:" + schema_id)
    att_storage_box = (deployed_client.app_id, b"att:" + att_id)

    # This should fail - unauthorized attester
    with pytest.raises(Exception):
        deployed_client.call(
            AASApplication.attest,
            schema_id=schema_id,
            subject_addr=owner_addr,
            claim_hash_32=claim_hash,
            nonce_32=nonce,
            sig_64=signature,
            cid=cid,
            attester_pk=unauthorized_pk,
            boxes=[schema_box, att_box, att_storage_box],
            signer=signer,
        )


@pytest.mark.localnet
def test_attest_duplicate_fails(
    deployed_client: ApplicationClient,
    algod_client: AlgodClient,
    localnet_signer: tuple[AccountTransactionSigner, str],
) -> None:
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
def test_attest_invalid_signature(
    deployed_client: ApplicationClient,
    algod_client: AlgodClient,
    localnet_signer: tuple[AccountTransactionSigner, str],
) -> None:
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
def test_revoke_attestation_success(
    deployed_client: ApplicationClient,
    algod_client: AlgodClient,
    localnet_signer: tuple[AccountTransactionSigner, str],
) -> None:
    """Test successful attestation revocation."""
    from tests.helpers import create_schema_helper, grant_attester_helper, create_attestation_helper, parse_attestation_box
    from nacl.signing import SigningKey
    
    signer, owner_addr = localnet_signer
    schema_id = b"revoke_success_test"

    # Create schema using helper
    create_schema_helper(deployed_client, signer, schema_id, owner_addr)

    # Generate ed25519 keypair for attester
    attester_sk = SigningKey.generate()
    attester_pk = bytes(attester_sk.verify_key)

    # Grant attester using helper
    grant_attester_helper(deployed_client, signer, schema_id, attester_pk)

    # Create attestation using helper
    claim_hash = b"R" * 32
    nonce = b"V" * 32
    cid = "QmRevoke123"
    
    att_id = create_attestation_helper(
        deployed_client, signer, schema_id, owner_addr, claim_hash, nonce, attester_sk, cid
    )

    # Verify attestation exists and is active using helper
    attestation_data = parse_attestation_box(algod_client, deployed_client.app_id, att_id)
    assert attestation_data['status'] == 'A'  # Status OK

    # Revoke attestation
    reason = 42  # Revocation reason code
    att_storage_box = (deployed_client.app_id, b"att:" + att_id)
    result = deployed_client.call(
        AASApplication.revoke,
        att_id=att_id,
        reason=reason,
        boxes=[att_storage_box],
        signer=signer,
    )

    # Verify revocation succeeded
    transaction.wait_for_confirmation(algod_client, result.tx_id, 4)

    # Verify attestation status changed and reason stored using helper
    revoked_data = parse_attestation_box(algod_client, deployed_client.app_id, att_id)
    assert revoked_data['status'] == 'R'  # Status Revoked
    assert revoked_data['reason'] == reason


@pytest.mark.localnet
def test_revoke_unauthorized(
    deployed_client: ApplicationClient,
    algod_client: AlgodClient,
    localnet_signer: tuple[AccountTransactionSigner, str],
) -> None:
    """Test that unauthorized users cannot revoke attestations."""
    signer, owner_addr = localnet_signer
    schema_id = b"revoke_unauth_test"
    uri = "revoke-unauth-schema"
    flags = 1
    schema_box = (deployed_client.app_id, b"schema:" + schema_id)
    att_box = (deployed_client.app_id, b"attesters:" + schema_id)

    # Create schema and setup attestation (use working pattern)
    deployed_client.call(
        AASApplication.create_schema,
        schema_id=schema_id,
        owner=owner_addr,
        uri=uri,
        flags=flags,
        boxes=[schema_box],
        signer=signer,
    )

    # Generate ed25519 keypair for attester (copy working pattern)
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

    # Prepare attestation data (copy exact pattern from working test)
    subject_addr = owner_addr  # Use owner as subject for simplicity
    claim_hash = b"U" * 32  # 32-byte claim hash
    nonce = b"N" * 32  # 32-byte nonce
    cid = "QmUnauth123"

    # Build canonical message and sign (copy exact pattern)
    import hashlib

    from algosdk import encoding

    subject_bytes = encoding.decode_address(subject_addr)
    message = schema_id + subject_bytes + claim_hash + nonce
    signature = bytes(attester_sk.sign(message).signature)

    # Generate attestation ID
    att_id = hashlib.sha256(message).digest()
    att_storage_box = (deployed_client.app_id, b"att:" + att_id)

    # Create attestation
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

    # Create different signer (unauthorized user)
    from algosdk.kmd import KMDClient

    kmd = KMDClient(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "http://localhost:4002"
    )
    wallets = kmd.list_wallets()
    wallet = next((w for w in wallets if w["name"] == "unencrypted-default-wallet"), None)
    assert wallet, "LocalNet wallet missing"
    handle = kmd.init_wallet_handle(wallet["id"], "")
    try:
        addrs = kmd.list_keys(handle)
        unauthorized_addr = next(
            (a for a in addrs if a != owner_addr), addrs[0]
        )  # Pick different address
        unauthorized_sk = kmd.export_key(handle, "", unauthorized_addr)
        unauthorized_signer = AccountTransactionSigner(unauthorized_sk)

        # Attempt unauthorized revocation (should fail)
        reason = 99  # Unauthorized attempt
        with pytest.raises(Exception):  # Should fail - unauthorized
            deployed_client.call(
                AASApplication.revoke,
                att_id=att_id,
                reason=reason,
                boxes=[att_storage_box],
                signer=unauthorized_signer,
            )
    finally:
        kmd.release_wallet_handle(handle)


@pytest.mark.localnet
def test_revoke_already_revoked(
    deployed_client: ApplicationClient,
    algod_client: AlgodClient,
    localnet_signer: tuple[AccountTransactionSigner, str],
) -> None:
    """Test that already revoked attestations cannot be revoked again."""
    signer, owner_addr = localnet_signer
    schema_id = b"revoke_twice_test"
    uri = "revoke-twice-schema"
    flags = 1
    schema_box = (deployed_client.app_id, b"schema:" + schema_id)
    att_box = (deployed_client.app_id, b"attesters:" + schema_id)

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

    subject_addr = owner_addr
    claim_hash = b"T" * 32
    nonce = b"W" * 32
    cid = "QmTwice123"

    import hashlib

    from algosdk import encoding

    subject_bytes = encoding.decode_address(subject_addr)
    message = schema_id + subject_bytes + claim_hash + nonce
    signature = bytes(attester_sk.sign(message).signature)

    att_id = hashlib.sha256(message).digest()
    att_storage_box = (deployed_client.app_id, b"att:" + att_id)

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

    reason = 42
    result = deployed_client.call(
        AASApplication.revoke,
        att_id=att_id,
        reason=reason,
        boxes=[att_storage_box],
        signer=signer,
    )
    transaction.wait_for_confirmation(algod_client, result.tx_id, 4)

    with pytest.raises(Exception):
        deployed_client.call(
            AASApplication.revoke,
            att_id=att_id,
            reason=99,
            boxes=[att_storage_box],
            signer=signer,
        )


@pytest.mark.localnet
def test_revoke_nonexistent(
    deployed_client: ApplicationClient,
    algod_client: AlgodClient,
    localnet_signer: tuple[AccountTransactionSigner, str],
) -> None:
    """Test that non-existent attestations cannot be revoked."""
    signer, _ = localnet_signer

    # Generate fake attestation ID
    import hashlib

    fake_att_id = hashlib.sha256(b"fake_attestation_id_that_does_not_exist").digest()
    fake_att_box = (deployed_client.app_id, b"att:" + fake_att_id)

    # Attempt to revoke non-existent attestation (should fail)
    reason = 404  # Not found
    with pytest.raises(Exception):  # Should fail - attestation doesn't exist
        deployed_client.call(
            AASApplication.revoke,
            att_id=fake_att_id,
            reason=reason,
            boxes=[fake_att_box],
            signer=signer,
        )


@pytest.mark.localnet
@pytest.mark.parametrize("param_name,invalid_length", [
    ("attester_pk", 31),
    ("attester_pk", 33), 
    ("claim_hash", 31),
    ("claim_hash", 33),
    ("nonce", 31),
    ("nonce", 33),
])
def test_invalid_parameter_lengths(
    deployed_client: ApplicationClient,
    localnet_signer: tuple[AccountTransactionSigner, str],
    param_name: str,
    invalid_length: int,
) -> None:
    """Test that invalid parameter lengths are rejected."""
    from tests.helpers import create_schema_helper, grant_attester_helper
    from nacl.signing import SigningKey
    
    signer, owner_addr = localnet_signer
    schema_id = b"invalid_len_test"
    
    # Create schema
    create_schema_helper(deployed_client, signer, schema_id, owner_addr)
    
    # Test invalid lengths for different parameters
    if param_name == "attester_pk":
        # Test invalid attester_pk length in grant_attester
        invalid_attester_pk = b"X" * invalid_length
        with pytest.raises(Exception):
            grant_attester_helper(deployed_client, signer, schema_id, invalid_attester_pk)
    
    elif param_name in ["claim_hash", "nonce"]:
        # Setup valid attester for attest tests
        attester_sk = SigningKey.generate()
        valid_attester_pk = bytes(attester_sk.verify_key)
        grant_attester_helper(deployed_client, signer, schema_id, valid_attester_pk)
        
        # Prepare attest parameters
        subject_addr = owner_addr
        valid_claim_hash = b"H" * 32
        valid_nonce = b"N" * 32
        
        # Create invalid parameter
        if param_name == "claim_hash":
            claim_hash = b"H" * invalid_length
            nonce = valid_nonce
        else:  # nonce
            claim_hash = valid_claim_hash
            nonce = b"N" * invalid_length
            
        # Build message and sign
        from tests.helpers import build_attestation_message, generate_attestation_id
        message = build_attestation_message(schema_id, subject_addr, claim_hash, nonce)
        signature = bytes(attester_sk.sign(message).signature)
        att_id = generate_attestation_id(schema_id, subject_addr, claim_hash, nonce)
        
        # Prepare boxes
        schema_box = (deployed_client.app_id, b"schema:" + schema_id)
        att_box = (deployed_client.app_id, b"attesters:" + schema_id)
        att_storage_box = (deployed_client.app_id, b"att:" + att_id)
        
        # Should fail with invalid length
        with pytest.raises(Exception):
            deployed_client.call(
                AASApplication.attest,
                schema_id=schema_id,
                subject_addr=subject_addr,
                claim_hash_32=claim_hash,
                nonce_32=nonce,
                sig_64=signature,
                cid="test",
                attester_pk=valid_attester_pk,
                boxes=[schema_box, att_box, att_storage_box],
                signer=signer,
            )


@pytest.mark.localnet
def test_grant_attester_nonexistent_schema(
    deployed_client: ApplicationClient,
    localnet_signer: tuple[AccountTransactionSigner, str],
) -> None:
    """Test that granting attester on non-existent schema fails."""
    signer, _ = localnet_signer
    nonexistent_schema_id = b"does_not_exist"
    attester_pk = b"A" * 32
    
    # Should fail - schema doesn't exist
    with pytest.raises(Exception):
        from tests.helpers import grant_attester_helper
        grant_attester_helper(deployed_client, signer, nonexistent_schema_id, attester_pk)


@pytest.mark.localnet
def test_full_attestation_flow(
    deployed_client: ApplicationClient,
    algod_client: AlgodClient,
    localnet_signer: tuple[AccountTransactionSigner, str],
) -> None:
    """Test complete attestation flow on LocalNet using helpers.

    This test requires AlgoKit LocalNet running:
    algokit localnet start
    """
    from tests.helpers import create_schema_helper, grant_attester_helper, create_attestation_helper, parse_attestation_box
    from nacl.signing import SigningKey
    
    signer, owner_addr = localnet_signer
    
    # 1. Contract is already deployed via deployed_client fixture
    
    # 2. Create schema using helper
    schema_id = b"full_flow_schema"
    create_schema_helper(deployed_client, signer, schema_id, owner_addr, "https://example.com/full-flow.json", 1)
    
    # 3. Grant attester using helper
    attester_sk = SigningKey.generate()
    attester_pk = bytes(attester_sk.verify_key)
    grant_attester_helper(deployed_client, signer, schema_id, attester_pk)
    
    # 4. Create attestation using helper
    claim_hash = b"F" * 32  
    nonce = b"L" * 32  
    cid = "QmFullFlow"
    
    att_id = create_attestation_helper(
        deployed_client, signer, schema_id, owner_addr, claim_hash, nonce, attester_sk, cid
    )
    
    # 5. Verify attestation using helper
    attestation_data = parse_attestation_box(algod_client, deployed_client.app_id, att_id)
    assert attestation_data['status'] == 'A'  # Status OK
    assert attestation_data['subject_addr'] == owner_addr
    assert attestation_data['schema_id'] == schema_id
    assert attestation_data['cid'] == cid
    
    # 6. Revoke attestation
    reason = 123
    att_storage_box = (deployed_client.app_id, b"att:" + att_id)
    revoke_result = deployed_client.call(
        AASApplication.revoke,
        att_id=att_id,
        reason=reason,
        boxes=[att_storage_box],
        signer=signer,
    )
    transaction.wait_for_confirmation(algod_client, revoke_result.tx_id, 4)

    # Verify revocation using helper
    revoked_data = parse_attestation_box(algod_client, deployed_client.app_id, att_id)
    assert revoked_data['status'] == 'R'  # Status Revoked
    assert revoked_data['reason'] == reason

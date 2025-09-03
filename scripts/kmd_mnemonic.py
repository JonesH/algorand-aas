"""Fetch a funded LocalNet mnemonic from KMD.

Uses the 'unencrypted-default-wallet' and returns the richest account's mnemonic.
Prints the mnemonic to stdout.
"""

from __future__ import annotations

import sys

from algosdk.kmd import KMDClient
from algosdk import mnemonic
from algosdk.v2client.algod import AlgodClient


def main() -> int:
    try:
        kmd = KMDClient(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "http://localhost:4002",
        )
        algod = AlgodClient(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "http://localhost:4001",
        )
        wallets = kmd.list_wallets()
        wallet = next(w for w in wallets if w["name"] == "unencrypted-default-wallet")
        handle = kmd.init_wallet_handle(wallet["id"], "")
        try:
            addrs = kmd.list_keys(handle)
            richest = max(addrs, key=lambda a: algod.account_info(a)["amount"])  # type: ignore[call-overload]
            sk = kmd.export_key(handle, "", richest)
            print(mnemonic.from_private_key(sk))
            return 0
        finally:
            kmd.release_wallet_handle(handle)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


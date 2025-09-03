"""Derive Algorand address from env AAS_MNEMONIC and print it."""

from __future__ import annotations

import os

from algosdk import account, mnemonic


def main() -> int:
    priv = mnemonic.to_private_key(os.environ["AAS_MNEMONIC"])
    print(account.address_from_private_key(priv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


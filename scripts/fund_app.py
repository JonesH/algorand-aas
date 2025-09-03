"""Fund the application address to cover box MBR.

Usage: python scripts/fund_app.py <app_id> [amount_microalgos]
Defaults to funding 1_000_000 microAlgos.
Requires env: AAS_ALGOD_URL, AAS_ALGOD_TOKEN, AAS_MNEMONIC
"""

from __future__ import annotations

import os
import sys

from algosdk import account, mnemonic, transaction
from algosdk.logic import get_application_address
from algosdk.v2client.algod import AlgodClient


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: fund_app.py <app_id> [amount]", file=sys.stderr)
        return 2
    app_id = int(sys.argv[1])
    amount = int(sys.argv[2]) if len(sys.argv) > 2 else 1_000_000

    algod = AlgodClient(os.environ["AAS_ALGOD_TOKEN"], os.environ["AAS_ALGOD_URL"])

    priv = mnemonic.to_private_key(os.environ["AAS_MNEMONIC"])
    sender = account.address_from_private_key(priv)
    app_addr = get_application_address(app_id)

    sp = algod.suggested_params()
    pay = transaction.PaymentTxn(sender, sp, app_addr, amount)
    txid = algod.send_transaction(pay.sign(priv))
    transaction.wait_for_confirmation(algod, txid, 4)
    print(app_addr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


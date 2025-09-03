"""Read a box by name for debugging.

Usage: python scripts/read_box.py <app_id> <att_id_hex>
Prints the decoded bytes length and first few bytes.
"""

from __future__ import annotations

import base64
import binascii
import sys

from algosdk.v2client.algod import AlgodClient


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: read_box.py <app_id> <att_id_hex>", file=sys.stderr)
        return 2
    app_id = int(sys.argv[1])
    att_id_hex = sys.argv[2]

    algod = AlgodClient(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "http://localhost:4001",
    )
    name = b"att:" + binascii.unhexlify(att_id_hex)
    resp = algod.application_box_by_name(app_id, name)
    raw = base64.b64decode(resp["value"])  # type: ignore[index]
    print(f"len={len(raw)} first16={raw[:16].hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


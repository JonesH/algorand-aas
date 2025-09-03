"""Sign an AAS attestation message and compute attestation ID.

Args (positional):
  1) schema_id_hex: 64-hex schema id (represents 32 raw bytes on-chain)
  2) subject_addr: Algorand address
  3) claim_json_path: JSON file for claim; hashed canonically
  4) nonce_hex: 64-hex (32 bytes) nonce
  5) attester_sk_hex: ed25519 secret key (hex)

Prints two space-separated values: <signature_hex> <attestation_id_hex>
"""

from __future__ import annotations

import binascii
import hashlib
import json
import sys
from pathlib import Path

from nacl.signing import SigningKey
from algosdk import encoding

from aas.sdk.hashing import canonical_json_hash


def main() -> int:
    if len(sys.argv) < 6:
        print(
            "Usage: sign_attestation.py <schema_hex> <subject_addr> <claim.json> <nonce_hex> <attester_sk_hex>",
            file=sys.stderr,
        )
        return 2

    schema_hex, subject_addr, claim_path, nonce_hex, sk_hex = sys.argv[1:6]

    claim_hash_hex = canonical_json_hash(json.loads(Path(claim_path).read_text()))

    message = (
        binascii.unhexlify(schema_hex)
        + encoding.decode_address(subject_addr)
        + binascii.unhexlify(claim_hash_hex)
        + binascii.unhexlify(nonce_hex)
    )

    sk = SigningKey(binascii.unhexlify(sk_hex))
    sig_hex = sk.sign(message).signature.hex()
    att_id_hex = hashlib.sha256(message).hexdigest()
    print(f"{sig_hex} {att_id_hex}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


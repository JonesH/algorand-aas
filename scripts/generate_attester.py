"""Generate an ed25519 attester keypair.

Prints two space-separated values: <sk_hex> <pk_hex>
"""

from __future__ import annotations

from nacl.signing import SigningKey


def main() -> int:
    sk = SigningKey.generate()
    sk_hex = sk.encode().hex()
    pk_hex = bytes(sk.verify_key).hex()
    print(f"{sk_hex} {pk_hex}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


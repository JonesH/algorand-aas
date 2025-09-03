"""Deploy the AAS app using env-configured Algod + mnemonic.

Prints the new application ID to stdout.
Requires env: AAS_ALGOD_URL, AAS_ALGOD_TOKEN, AAS_MNEMONIC
"""

from __future__ import annotations

from beaker.client import ApplicationClient

from aas.contracts.aas import get_app
from aas.cli.config import AASConfig, create_algod_client, create_signer


def main() -> int:
    cfg = AASConfig()
    algod = create_algod_client(cfg)
    signer, addr = create_signer(cfg)
    client = ApplicationClient(algod, app=get_app(), sender=addr, signer=signer)
    client.create()
    print(client.app_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


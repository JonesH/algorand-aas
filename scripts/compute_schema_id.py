"""Compute canonical schema ID (sha256 of canonical JSON).

Usage: python scripts/compute_schema_id.py path/to/schema.json
Prints the 64-hex schema ID to stdout.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from aas.sdk.hashing import canonical_json_hash


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: compute_schema_id.py <schema_json_path>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    try:
        data = json.loads(path.read_text())
        print(canonical_json_hash(data))
        return 0
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


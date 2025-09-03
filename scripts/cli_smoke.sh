#!/usr/bin/env bash
set -euo pipefail

# Defaults for LocalNet; override via env if needed
: "${AAS_ALGOD_URL:=http://localhost:4001}"
: "${AAS_ALGOD_TOKEN:=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"

export AAS_ALGOD_URL AAS_ALGOD_TOKEN

echo "[smoke] Fetching funded LocalNet mnemonic from KMD"
AAS_MNEMONIC=$(uv run python scripts/kmd_mnemonic.py)
export AAS_MNEMONIC

echo "[smoke] Deploying AAS app"
AAS_APP_ID=$(uv run python scripts/deploy_app.py)
export AAS_APP_ID
echo "[smoke] Deployed app id: $AAS_APP_ID"

echo "[smoke] Funding app address for box MBR"
APP_ADDR=$(uv run python scripts/fund_app.py "$AAS_APP_ID" 1000000)
echo "[smoke] Funded app address: $APP_ADDR"

echo "[smoke] Deriving subject address from mnemonic"
SUBJECT_ADDR=$(uv run python scripts/derive_address.py)
export SUBJECT_ADDR
echo "[smoke] Subject: $SUBJECT_ADDR"

echo "[smoke] Creating sample schema.json and computing ID"
SCHEMA_JSON="schema.smoke.json"
cat > "$SCHEMA_JSON" <<'JSON'
{"type":"object","properties":{"name":{"type":"string"}}}
JSON
SCHEMA_ID=$(uv run python scripts/compute_schema_id.py "$SCHEMA_JSON")
export SCHEMA_ID
echo "[smoke] Schema ID: $SCHEMA_ID"

echo "[smoke] CLI create-schema"
uv run aas create-schema "$SCHEMA_JSON" --uri smoke-uri

echo "[smoke] Generating attester keypair and granting"
read -r ATT_SK_HEX ATT_PK_HEX < <(uv run python scripts/generate_attester.py)
export ATT_SK_HEX ATT_PK_HEX
uv run aas grant-attester "$SCHEMA_ID" "$ATT_PK_HEX"

echo "[smoke] Preparing claim + signing attestation"
CLAIM_JSON="claim.smoke.json"
echo '{"name":"Alice"}' > "$CLAIM_JSON"
NONCE_HEX=$(uv run python - <<'PY'
print('ab'*32)
PY
)
export NONCE_HEX
read -r SIGN_HEX ATT_ID_HEX < <(uv run python scripts/sign_attestation.py "$SCHEMA_ID" "$SUBJECT_ADDR" "$CLAIM_JSON" "$NONCE_HEX" "$ATT_SK_HEX")
export SIGN_HEX ATT_ID_HEX
echo "[smoke] Attestation ID: $ATT_ID_HEX"

echo "[smoke] CLI attest"
uv run aas attest "$SCHEMA_ID" "$SUBJECT_ADDR" "$CLAIM_JSON" "$NONCE_HEX" "$SIGN_HEX" "$ATT_PK_HEX" --cid smoke

echo "[smoke] CLI get"
uv run aas get "$ATT_ID_HEX" || true
echo "[smoke] Direct box read for debugging (should exist)"
uv run python scripts/read_box.py "$AAS_APP_ID" "$ATT_ID_HEX"

echo "[smoke] Done: APP_ID=$AAS_APP_ID SCHEMA_ID=$SCHEMA_ID ATT_ID=$ATT_ID_HEX SUBJECT=$SUBJECT_ADDR"

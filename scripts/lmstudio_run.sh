#!/usr/bin/env bash
set -euo pipefail

# Simple wrapper to run a local LM Studio model and emit output.txt + claim.json

usage() {
  cat <<'USAGE'
Usage:
  scripts/lmstudio_run.sh \
    --prompt <path/to/prompt.txt> \
    --params <path/to/params.json> \
    [--out-dir <dir>] \
    [--attester <id>]

Notes:
  - Ensure LM Studio local server is enabled (default: http://localhost:1234)
  - You can override with LMSTUDIO_BASE_URL env var
  - params.json may include "lmstudio_model" to map to the locally loaded model name
USAGE
}

PROMPT=""
PARAMS=""
OUT_DIR=""
ATTESTER="self"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prompt) PROMPT="$2"; shift 2;;
    --params) PARAMS="$2"; shift 2;;
    --out-dir) OUT_DIR="$2"; shift 2;;
    --attester) ATTESTER="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 1;;
  esac
done

if [[ -z "$PROMPT" || -z "$PARAMS" ]]; then
  usage; exit 1
fi

if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="$(dirname "$PROMPT")"
fi

uv run python scripts/run_llm.py \
  --provider lmstudio \
  --prompt "$PROMPT" \
  --params "$PARAMS" \
  --out-dir "$OUT_DIR" \
  --attester "$ATTESTER"


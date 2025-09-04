#!/usr/bin/env bash
set -euo pipefail

# Run the included Gemma 270M example via LM Studio locally

EX_DIR="examples/selfrun_gemma270m"

scripts/lmstudio_run.sh \
  --prompt "$EX_DIR/prompt.txt" \
  --params "$EX_DIR/params.json" \
  --out-dir "$EX_DIR" \
  --attester demo-user

echo "\nDone. Files written to: $EX_DIR"


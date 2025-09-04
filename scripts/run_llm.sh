#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} == "-h" || ${1:-} == "--help" || $# -eq 0 ]]; then
  cat <<'USAGE'
Run an LLM and produce output.txt + claim.json (ai.inference.v1)

Usage:
  scripts/run_llm.sh \
    --provider <lmstudio|ollama|openai|anthropic> \
    --prompt <path/to/prompt.txt> \
    --params <path/to/params.json> \
    --out-dir <dir> \
    [--attester <id>]

Example:
  scripts/run_llm.sh \
    --provider lmstudio \
    --prompt examples/selfrun_gemma270m/prompt.txt \
    --params examples/selfrun_gemma270m/params.json \
    --out-dir examples/selfrun_gemma270m \
    --attester demo-user
USAGE
  exit 0
fi

uv run python scripts/run_llm.py "$@"


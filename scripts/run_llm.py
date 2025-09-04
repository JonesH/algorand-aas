#!/usr/bin/env python3
"""
Provider-agnostic LLM runner that:
- Reads a prompt and params
- Calls the selected provider (LM Studio, Ollama, OpenAI, Anthropic)
- Writes output.txt and claim.json (ai.inference.v1)

Usage:
  uv run python scripts/run_llm.py \
    --provider lmstudio \
    --prompt examples/selfrun_gemma270m/prompt.txt \
    --params examples/selfrun_gemma270m/params.json \
    --out-dir examples/selfrun_gemma270m \
    --attester demo-user

Environment variables (as applicable):
  LMSTUDIO_BASE_URL (default: http://localhost:1234)
  OLLAMA_BASE_URL   (default: http://localhost:11434)
  OPENAI_API_KEY
  OPENAI_BASE_URL   (default: https://api.openai.com)
  ANTHROPIC_API_KEY
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Tuple


# Local import for canonical claim helper
try:
    from aas.cli.ai_commands import _create_canonical_claim  # type: ignore
except Exception as e:  # pragma: no cover
    print(f"Error: could not import AAS CLI helpers: {e}", file=sys.stderr)
    sys.exit(1)


@dataclass
class RunResult:
    text: str
    finish_reason: str


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _http_post(url: str, headers: Dict[str, str], body: Dict[str, Any]) -> Dict[str, Any]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            resp_data = resp.read().decode("utf-8")
            return json.loads(resp_data)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8") if hasattr(e, "read") else str(e)
        raise RuntimeError(f"HTTP {e.code} error from {url}: {detail}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Network error contacting {url}: {e}") from e


def run_lmstudio(prompt: str, model: str, params: Dict[str, Any]) -> RunResult:
    base = os.environ.get("LMSTUDIO_BASE_URL", "http://localhost:1234")
    url = f"{base.rstrip('/')}/v1/chat/completions"
    body: Dict[str, Any] = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": params.get("temperature"),
        "top_p": params.get("top_p"),
        "max_tokens": params.get("max_tokens"),
        # LM Studio supports deterministic seeds in some backends
        "seed": params.get("seed"),
    }
    # Remove None values
    body = {k: v for k, v in body.items() if v is not None}
    resp = _http_post(url, headers={}, body=body)
    # Prefer chat-style response
    try:
        text = resp["choices"][0]["message"]["content"]
        finish_reason = resp["choices"][0].get("finish_reason", "stop")
        return RunResult(text=text, finish_reason=finish_reason)
    except Exception:
        # Fallback to completion-style
        text = resp.get("choices", [{}])[0].get("text", "")
        finish_reason = resp.get("choices", [{}])[0].get("finish_reason", "stop")
        if not text:
            raise RuntimeError(f"Unexpected LM Studio response: {json.dumps(resp)[:500]}")
        return RunResult(text=text, finish_reason=finish_reason)


def run_ollama(prompt: str, model: str, params: Dict[str, Any]) -> RunResult:
    base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    url = f"{base.rstrip('/')}/api/generate"
    options: Dict[str, Any] = {}
    if "temperature" in params:
        options["temperature"] = params["temperature"]
    if "top_p" in params:
        options["top_p"] = params["top_p"]
    if "max_tokens" in params:
        options["num_predict"] = params["max_tokens"]
    body = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": options,
    }
    resp = _http_post(url, headers={}, body=body)
    text = resp.get("response", "").strip()
    finish_reason = resp.get("done_reason", "stop") or "stop"
    if not text:
        raise RuntimeError(f"Unexpected Ollama response: {json.dumps(resp)[:500]}")
    return RunResult(text=text, finish_reason=finish_reason)


def run_openai(prompt: str, model: str, params: Dict[str, Any]) -> RunResult:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is required for provider 'openai'")
    base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com")
    url = f"{base.rstrip('/')}/v1/chat/completions"
    body: Dict[str, Any] = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": params.get("temperature"),
        "top_p": params.get("top_p"),
        "max_tokens": params.get("max_tokens"),
    }
    body = {k: v for k, v in body.items() if v is not None}
    headers = {"Authorization": f"Bearer {api_key}"}
    resp = _http_post(url, headers=headers, body=body)
    text = resp["choices"][0]["message"]["content"].strip()
    finish_reason = resp["choices"][0].get("finish_reason", "stop")
    return RunResult(text=text, finish_reason=finish_reason)


def run_anthropic(prompt: str, model: str, params: Dict[str, Any]) -> RunResult:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is required for provider 'anthropic'")
    url = "https://api.anthropic.com/v1/messages"
    body: Dict[str, Any] = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": params.get("max_tokens", 256),
        "temperature": params.get("temperature"),
        "top_p": params.get("top_p"),
    }
    body = {k: v for k, v in body.items() if v is not None}
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }
    resp = _http_post(url, headers=headers, body=body)
    # Anthropic returns content as a list of blocks
    content = resp.get("content", [])
    if not content:
        raise RuntimeError(f"Unexpected Anthropic response: {json.dumps(resp)[:500]}")
    text = "".join(block.get("text", "") for block in content if block.get("type") == "text").strip()
    finish_reason = resp.get("stop_reason", "stop")
    return RunResult(text=text, finish_reason=finish_reason)


def provider_runtime(provider: str) -> Tuple[str, str]:
    # runtime, version
    if provider == "lmstudio":
        return ("LM Studio", os.environ.get("LMSTUDIO_VERSION", "unknown"))
    if provider == "ollama":
        return ("Ollama", os.environ.get("OLLAMA_VERSION", "unknown"))
    if provider == "openai":
        return ("OpenAI", os.environ.get("OPENAI_API_VERSION", "v1"))
    if provider == "anthropic":
        return ("Anthropic", os.environ.get("ANTHROPIC_API_VERSION", "v1"))
    return (provider, "unknown")


def main() -> None:
    ap = argparse.ArgumentParser(description="Run an LLM and produce canonical AI claim files")
    ap.add_argument("--provider", required=True, choices=["lmstudio", "ollama", "openai", "anthropic"], help="LLM provider")
    ap.add_argument("--prompt", required=True, type=Path, help="Path to prompt.txt")
    ap.add_argument("--params", required=True, type=Path, help="Path to params.json (model_id, model_version, params)")
    ap.add_argument("--out-dir", required=True, type=Path, help="Directory to write output.txt and claim.json")
    ap.add_argument("--attester", default="self", help="Attester identifier (e.g., username)")

    args = ap.parse_args()
    prompt_txt = _read_text(args.prompt)
    params_obj = _read_json(args.params)

    model_id = params_obj.get("model_id") or params_obj.get("model") or "unknown"
    model_version = params_obj.get("model_version", "unknown")
    inference_params: Dict[str, Any] = params_obj.get("params", {})

    # Some providers may require a different model ref than the canonical ID
    provider_model = params_obj.get(f"{args.provider}_model", model_id)

    if args.provider == "lmstudio":
        result = run_lmstudio(prompt_txt, provider_model, inference_params)
    elif args.provider == "ollama":
        result = run_ollama(prompt_txt, provider_model, inference_params)
    elif args.provider == "openai":
        result = run_openai(prompt_txt, provider_model, inference_params)
    elif args.provider == "anthropic":
        result = run_anthropic(prompt_txt, provider_model, inference_params)
    else:
        raise RuntimeError(f"Unsupported provider: {args.provider}")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    output_path = args.out_dir / "output.txt"
    output_path.write_text(result.text, encoding="utf-8")

    claim = _create_canonical_claim(
        prompt=prompt_txt,
        params=inference_params,
        output=result.text,
        model_id=model_id,
        model_version=model_version,
        attester=args.attester,
    )
    runtime_name, runtime_ver = provider_runtime(args.provider)
    # Override runtime to reflect actual provider used
    try:
        claim.setdefault("execution", {}).setdefault("environment", {})
        claim["execution"]["environment"]["runtime"] = runtime_name
        claim["execution"]["environment"]["version"] = runtime_ver
        # Store finish reason if available
        if result.finish_reason:
            claim.setdefault("output", {})["finish_reason"] = result.finish_reason
    except Exception:
        # Non-fatal; keep canonical shape
        pass

    claim_path = args.out_dir / "claim.json"
    claim_path.write_text(json.dumps(claim, indent=2, sort_keys=True), encoding="utf-8")

    print(f"Wrote: {output_path}")
    print(f"Wrote: {claim_path}")


if __name__ == "__main__":
    main()


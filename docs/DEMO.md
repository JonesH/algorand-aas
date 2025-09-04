# AAS 4‑Minute Demo (makedemo)

This produces a short narrated MP4 by browsing a local demo page with makedemo.

## Prereqs

- Node.js 20+
- FFmpeg in PATH
- OpenAI + ElevenLabs API keys (for planning + narration)

## Steps

1) Start local web server (serves repo at http://localhost:8787)

```bash
scripts/mkdemo_server.sh
```

2) Configure API keys

```bash
cp .env.mkdemo.example .env.mkdemo
# edit .env.mkdemo with real keys
```

3) Generate the video (headless by default)

```bash
# In another terminal
scripts/mkdemo_run.sh
# Optional tunables
#   DEMO_URL=http://localhost:8787/docs/demo.html
#   OUT_DIR=demos_output
#   INTERACTIONS=8
#   HEADLESS=true
```

Outputs will be written to `demos_output/` (e.g., `demo_<timestamp>.mp4` and transcript/log files).

## Demo flow

- Opens `docs/demo.html`
- Clicks through Setup → Canonicalize → Attest → Verify
- Narration describes each step automatically via ElevenLabs

For reproducible CLI output, consider pre-generating `examples/selfrun_gemma270m/claim.json` using:

```bash
scripts/lmstudio_example.sh
```

If you prefer a manual, voice-over screen capture, `docs/demo.html` provides a tidy script to follow.


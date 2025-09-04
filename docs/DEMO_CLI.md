Demo: Terminal Recording + Narration (CLI)

This guide shows how to record a terminal demo with `asciinema`, render an MP4 with `agg`, generate narration with ElevenLabs, and merge audio/video with `ffmpeg` — all orchestrated via the AAS CLI.

Prerequisites
- asciinema
- @asciinema/agg
- ffmpeg
- ElevenLabs API key in env (ELEVENLABS_API_KEY) or .env/.env.mkdemo

Commands
- Check deps: `uv run aas demo check-deps`
- Propose narration: `uv run aas demo propose-script --out narration.txt`
- Record cast: `uv run aas demo record --cast demo.cast` (press Ctrl-D to stop)
- Render video: `uv run aas demo render --cast demo.cast --mp4 demo.mp4`
- Generate audio: `uv run aas demo voice --script narration.txt --mp3 narration.mp3`
- Merge: `uv run aas demo merge --mp4 demo.mp4 --mp3 narration.mp3 --out demo_with_voice.mp4`
- All-in-one: `uv run aas demo all`

Notes
- The default narration is tailored for a ~4 minute pitch. Edit `narration.txt` as needed.
- The `all` command is interactive at the recording step (asciinema). Press Ctrl-D to finish recording.


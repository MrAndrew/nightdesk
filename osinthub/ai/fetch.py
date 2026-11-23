"""Download one model into the Hugging Face cache, printing progress as JSON lines on stdout.

Run by osinthub/ai/setup.py in its own process, with the AI libraries on the path (huggingface_hub comes with
them), only after the user chose the model in Settings › AI:

    python -m osinthub.ai.fetch <repo id>            download it
    python -m osinthub.ai.fetch --delete <repo id>   delete it (Settings › AI › Turn off, "Also delete")

Lines: {"total": bytes, "done": bytes} about once a second, then {"ok": true, ...} or {"error": "..."}. Deleting
uses huggingface_hub's own cache deletion, which also clears the files in the cache-wide shared store (`<cache>/blobs`)
that no other model uses.
okf/architecture/local-ai.md#turning-ai-on
"""
from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path


def _say(**kw) -> None:
    print(json.dumps(kw), flush=True)


def main(argv: list[str]) -> int:
    delete = argv[:1] == ["--delete"]
    argv = argv[1:] if delete else argv
    if len(argv) != 1:
        _say(error="usage: python -m osinthub.ai.fetch [--delete] <repo id>")
        return 2
    repo = argv[0]
    if libs := os.environ.get("OSINTHUB_AI_LIBS"):
        sys.path.append(libs)            # after the app's own packages, so those always win
    if delete:
        return _delete(repo)
    os.environ.pop("HF_HUB_OFFLINE", None)
    os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
    try:
        from huggingface_hub import HfApi, snapshot_download
        from huggingface_hub.constants import HF_HUB_CACHE
        info = HfApi().model_info(repo, files_metadata=True)
    except Exception as e:
        _say(error=f"{type(e).__name__}: {e}"[:300])
        return 1
    total = sum((s.size or 0) for s in info.siblings or [])
    blobs = Path(HF_HUB_CACHE) / ("models--" + repo.replace("/", "--")) / "blobs"

    def on_disk() -> int:
        try:
            return sum(f.stat().st_size for f in blobs.iterdir() if f.is_file())
        except FileNotFoundError:
            return 0

    finished, failed = threading.Event(), []

    def run() -> None:
        try:
            snapshot_download(repo)
        except BaseException as e:   # reported, never raised past the thread
            failed.append(e)
        finally:
            finished.set()

    threading.Thread(target=run, name="fetch", daemon=True).start()
    while not finished.wait(1.0):
        _say(total=total, done=min(on_disk(), total or on_disk()))
    if failed:
        _say(error=f"{type(failed[0]).__name__}: {failed[0]}"[:300])
        return 1
    _say(ok=True, total=total, done=total)
    return 0


def _delete(repo: str) -> int:
    try:
        from huggingface_hub import scan_cache_dir
        from huggingface_hub.constants import HF_HUB_CACHE
        info = scan_cache_dir(HF_HUB_CACHE)
        revs = [r.commit_hash for c in info.repos if c.repo_id == repo and c.repo_type == "model" for r in c.revisions]
        if not revs:
            _say(ok=True, freed=0)
            return 0
        plan = info.delete_revisions(*revs)
        plan.execute()
    except Exception as e:
        _say(error=f"{type(e).__name__}: {e}"[:300])
        return 1
    _say(ok=True, freed=plan.expected_freed_size)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

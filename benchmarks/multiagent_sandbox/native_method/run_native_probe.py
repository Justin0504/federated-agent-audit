"""Bounded native diagnosis on a separate four-thread Jetstream CPU server."""

import hashlib
import json
import os
import shutil
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

from prepare_dev import prepare
from summarize import summarize

ROOT = Path(__file__).resolve().parent
PARENT = ROOT.parent
RUNTIME = Path("/dev/shm/faa8b-remote-v1/llama-b11624")
MODEL = Path("/dev/shm/faa-protocol-models/qwen2.5-3b-q4km.gguf")
EXPECTED = "626b4a6678b86442240e33df819e00132d3ba7dddfe1cdc4fbb18e0a9615c62d"


def healthy():
    try:
        return urllib.request.urlopen("http://127.0.0.1:18089/health", timeout=2).status == 200
    except OSError:
        return False


def main():
    if socket.gethostname() != "sss":
        raise SystemExit("Jetstream only")
    if healthy():
        raise SystemExit("Port18089 occupied; refusing replacement")
    h = hashlib.sha256()
    with MODEL.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    if h.hexdigest() != EXPECTED:
        raise SystemExit("weight hash mismatch")
    output_budget = int(os.environ.get("FAA_NATIVE_OUTPUT_TOKENS", "512"))
    if output_budget not in (512, 1024):
        raise SystemExit("unsupported development output budget")
    target = ROOT / "development"
    prepare(PARENT / "agentdojo-schema-v6-qwen25_3b", target)
    shutil.copy2(ROOT / "native_backend.py", target / "backend.py")
    p = json.loads((target / "protocol.json").read_text())
    selected = {}
    for entry in p["episodes"]:
        selected[(entry["path"], entry["arm"])] = dict(entry, prompt_revision="native_tools")
    p.update(
        name=ROOT.name,
        max_new_tokens=output_budget,
        episodes=list(selected.values()),
        systems={"native_tools": "Native tool-calling interface"},
        scope="Six development cases; native tool API; compare with archived v7, not held-out evidence.",
    )
    p["source_hashes"] = {
        f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in target.glob("*.py")
    }
    (target / "protocol.json").write_text(json.dumps(p, indent=2))

    python = str(PARENT / "agentdojo-env/bin/python")
    with (ROOT / "server.log").open("w") as log:
        server = subprocess.Popen(
            [
                str(RUNTIME / "llama-server"),
                "-m",
                str(MODEL),
                "--host",
                "127.0.0.1",
                "--port",
                "18089",
                "-c",
                "8192",
                "-np",
                "1",
                "-t",
                "4",
                "-tb",
                "4",
                "-ngl",
                "0",
                "--no-context-shift",
                "--jinja",
                "--reasoning-budget",
                "0",
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
            env=dict(os.environ, LD_LIBRARY_PATH=str(RUNTIME)),
        )
        worker = None
        try:
            for _ in range(120):
                if healthy():
                    break
                if server.poll() is not None:
                    raise RuntimeError("server startup failed")
                time.sleep(1)
            if not healthy():
                raise RuntimeError("server not ready")
            with (ROOT / "worker.log").open("w") as wl, (ROOT / "episodes.log").open("w") as el:
                worker = subprocess.Popen(
                    [python, "worker.py"], cwd=target, stdout=wl, stderr=subprocess.STDOUT
                )
                result = subprocess.run(
                    [
                        python,
                        "run.py",
                        "--upstream",
                        str(PARENT / "agentdojo-external-v1/upstream"),
                        "--out",
                        "results",
                    ],
                    cwd=target,
                    stdout=el,
                    stderr=subprocess.STDOUT,
                    timeout=5400,
                    check=False,
                )
                if (target / "results/attempts.jsonl").exists():
                    summarize(target / "results")
                (ROOT / "finished.json").write_text(
                    json.dumps(
                        {
                            "exit_code": result.returncode,
                            "result": "development/results/public_summary.json",
                        }
                    )
                )
        finally:
            for process in (worker, server):
                if process is None:
                    continue
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    main()

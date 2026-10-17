"""Bounded sequential Jetstream-only deployment for the paired CPU sweep."""

import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

MODELS = [
    (
        "qwen25_3b",
        "/dev/shm/faa-protocol-models/qwen2.5-3b-q4km.gguf",
        "626b4a6678b86442240e33df819e00132d3ba7dddfe1cdc4fbb18e0a9615c62d",
    ),
    (
        "qwen3_8b",
        "/dev/shm/faa8b-remote-v1/qwen3-8b-q4km.gguf",
        "a3de86cd1c132c822487ededd47a324c50491393e6565cd14bafa40d0b8e686f",
    ),
]
RUNTIME = Path("/dev/shm/faa8b-remote-v1/llama-b11624")


def gate(summary):
    n = summary["episodes"]
    return (
        summary["complete"]
        and n > 0
        and summary["output_caps"] == 0
        and summary.get("format_errors", 0) / max(1, summary["coordinator_calls"]) <= 0.2
        and sum(g["member_failures"] for g in summary["groups"].values()) / n <= 0.2
    )


def healthy():
    try:
        with urllib.request.urlopen("http://127.0.0.1:18088/health", timeout=2) as r:
            return r.status == 200
    except OSError:
        return False


def main():
    if socket.gethostname() != "sss":
        raise SystemExit("Jetstream sss only; do not run on workstation")
    if healthy():
        raise SystemExit("Port already in use; will not replace another inference service")
    for model, path, digest in MODELS:
        with open(path, "rb") as f:
            checksum = hashlib.sha256()
            for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
                checksum.update(chunk)
            actual = checksum.hexdigest()
        if actual != digest:
            raise SystemExit("model digest mismatch")
        env = dict(os.environ, LD_LIBRARY_PATH=str(RUNTIME))
        with open(model + "-server.log", "w") as log:
            command = [
                str(RUNTIME / "llama-server"),
                "-m",
                path,
                "--host",
                "127.0.0.1",
                "--port",
                "18088",
                "-c",
                "8192",
                "-np",
                "1",
                "-t",
                "8",
                "-tb",
                "8",
                "-ngl",
                "0",
                "--no-context-shift",
                "--jinja",
                "--reasoning-budget",
                "0",
            ]
            if model == "qwen3_8b":
                command += ["--chat-template-kwargs", '{"enable_thinking":false}']
            server = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=env)
            try:
                ready = False
                for _ in range(120):
                    if server.poll() is not None:
                        break
                    if healthy():
                        ready = True
                        break
                    time.sleep(1)
                if not ready:
                    raise RuntimeError("server startup failed")
                for stage, pairs, seed in [("smoke", 2, 20261020), ("expanded", 4, 20261021)]:
                    output = f"{model}-{stage}"
                    result = subprocess.run(
                        [
                            sys.executable,
                            "paired_scale.py",
                            "--expected-host",
                            "sss",
                            "--model-id",
                            model,
                            "--model-sha256",
                            digest,
                            "--pairs",
                            str(pairs),
                            "--seed",
                            str(seed),
                            "--out",
                            output,
                        ],
                        timeout=3000,
                        check=False,
                    )
                    if result.returncode:
                        print(
                            json.dumps({"model": model, "stage": stage, "status": "failed"}),
                            flush=True,
                        )
                        break
                    s = json.loads(Path(output, "summary.json").read_text())
                    print(
                        json.dumps({"model": model, "stage": stage, "gate_pass": gate(s)}),
                        flush=True,
                    )
                    if not gate(s):
                        break
            finally:
                server.terminate()
                try:
                    server.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()
    Path("sweep_finished.json").write_text(
        json.dumps({"finished": True, "models": [m[0] for m in MODELS]})
    )


if __name__ == "__main__":
    main()

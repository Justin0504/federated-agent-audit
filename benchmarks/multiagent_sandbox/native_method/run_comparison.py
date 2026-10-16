"""Wait for diagnosis, enforce the frozen gate, then run the first method matrix."""

import hashlib
import json
import os
import socket
import subprocess
import time
from pathlib import Path

from prepare_comparison import prepare_comparison
from run_development import EXPECTED, MODEL, RUNTIME, healthy
from summarize import summarize

ROOT = Path(__file__).resolve().parent
PARENT = ROOT.parent


def main():
    if socket.gethostname() != "sss":
        raise SystemExit("Jetstream only")
    previous = PARENT / os.environ.get("FAA_NATIVE_DEVELOPMENT", "native-diagnosis-v12")
    for _ in range(600):
        if (previous / "finished.json").exists():
            break
        time.sleep(10)
    else:
        raise SystemExit("diagnosis incomplete; no expansion")
    # Recompute aggregate from raw on-host rows, including unknown security labels.
    report = summarize(previous / "development/results")
    summary = previous / "development/results/public_summary.json"
    target = ROOT / "formal-3b"
    try:
        prepare_comparison(
            PARENT / "agentdojo-schema-v6-qwen25_3b",
            target,
            summary,
            revision="native_tools",
            reference_summary=PARENT
            / "native-diagnosis-v7/development/results/public_summary.json",
        )
    except ValueError as exc:
        (ROOT / "gate_failed.json").write_text(
            json.dumps({"reason": str(exc), "development": report}, indent=2)
        )
        return
    for _ in range(12):
        if not healthy():
            break
        time.sleep(5)
    if healthy():
        raise SystemExit("server occupied; do not replace")
    h = hashlib.sha256()
    with MODEL.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    if h.hexdigest() != EXPECTED:
        raise SystemExit("weight mismatch")
    python = str(PARENT / "agentdojo-env/bin/python")
    with (ROOT / "server.log").open("w") as sl:
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
            stdout=sl,
            stderr=subprocess.STDOUT,
            env=dict(os.environ, LD_LIBRARY_PATH=str(RUNTIME)),
        )
        worker = None
        try:
            for _ in range(120):
                if healthy():
                    break
                if server.poll() is not None:
                    raise RuntimeError("server exited")
                time.sleep(1)
            if not healthy():
                raise RuntimeError("server unavailable")
            with (ROOT / "worker.log").open("w") as wl, (ROOT / "run.log").open("w") as rl:
                worker = subprocess.Popen(
                    [python, "worker.py"], cwd=target, stdout=wl, stderr=subprocess.STDOUT
                )
                try:
                    r = subprocess.run(
                        [
                            python,
                            "run.py",
                            "--upstream",
                            str(PARENT / "agentdojo-external-v1/upstream"),
                            "--out",
                            "results",
                        ],
                        cwd=target,
                        stdout=rl,
                        stderr=subprocess.STDOUT,
                        timeout=14400,
                        check=False,
                    )
                    status = {"exit_code": r.returncode, "timed_out": False}
                except subprocess.TimeoutExpired:
                    status = {"exit_code": None, "timed_out": True}
                if (target / "results/attempts.jsonl").exists():
                    summarize(target / "results")
                (ROOT / "finished.json").write_text(json.dumps(status))
        finally:
            for proc in (worker, server):
                if proc is None:
                    continue
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


if __name__ == "__main__":
    main()

"""Sequential bounded Jetstream follow-up; never launch a workstation backend."""

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

from external_followup.prepare import prepare
from remote_sweep import MODELS, RUNTIME, gate, healthy

ROOT = Path(__file__).resolve().parent
PARENT = ROOT.parent
EXTERNAL_PYTHON = PARENT / "agentdojo-env/bin/python"


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    if socket.gethostname() != "sss":
        raise SystemExit("Jetstream only")
    diag = PARENT / "protocol-diagnosis-v5"
    for _ in range(180):
        if (diag / "sweep_finished.json").exists():
            break
        time.sleep(10)
    else:
        raise SystemExit("Diagnostic completion missing; expansion not started")
    for model, _, _ in MODELS:
        d = json.loads((diag / (model + "-diagnostic") / "summary.json").read_text())
        if d["receipt_uncached"]["final"] < d["history_uncached"]["final"]:
            raise SystemExit(
                "Receipt isolation regressed on diagnostic set; inspect before expanding"
            )
    if healthy():
        raise SystemExit("Existing server; refusing to replace it")
    weights = Path("/dev/shm/faa-protocol-models/qwen25_7b")
    m = json.loads((weights / "manifest.json").read_text())
    for f in m["files"]:
        if digest(weights / f["name"]) != f["sha256"]:
            raise SystemExit("7B shard hash mismatch")
    models = MODELS + [("qwen25_7b", str(weights / m["files"][0]["name"]), m["files"][0]["sha256"])]
    shutil.copy2(weights / "manifest.json", ROOT / "7b_weight_manifest.json")
    status = []
    for model, path, sha in models:
        if digest(path) != sha:
            raise SystemExit("model hash mismatch")
        cmd = [
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
            cmd += ["--chat-template-kwargs", '{"enable_thinking":false}']
        with (ROOT / (model + "-server.log")).open("w") as log:
            server = subprocess.Popen(
                cmd,
                stdout=log,
                stderr=subprocess.STDOUT,
                env=dict(os.environ, LD_LIBRARY_PATH=str(RUNTIME)),
            )
            try:
                for _ in range(120):
                    if healthy():
                        break
                    if server.poll() is not None:
                        raise RuntimeError("server exited")
                    time.sleep(1)
                if not healthy():
                    raise RuntimeError("server not ready")
                for stage, pairs, seed in [("smoke", 2, 20261022), ("heldout", 8, 20261023)]:
                    out = model + "-" + stage
                    subprocess.run(
                        [
                            sys.executable,
                            "paired_scale.py",
                            "--expected-host",
                            "sss",
                            "--model-id",
                            model,
                            "--model-sha256",
                            sha,
                            "--pairs",
                            str(pairs),
                            "--seed",
                            str(seed),
                            "--out",
                            out,
                            "--no-cache",
                            "--receipt-only",
                            "--retry-mode",
                            "fresh",
                        ],
                        check=True,
                        timeout=3600,
                    )
                    result = json.loads((ROOT / out / "summary.json").read_text())
                    status.append({"model": model, "stage": stage, "passed": gate(result)})
                    (ROOT / "progress.json").write_text(json.dumps(status, indent=2))
                    if not gate(result):
                        break
                # Native tasks are separate from the scheduling representation.
                target = PARENT / ("agentdojo-schema-v6-" + model)
                p = prepare(PARENT / "fresh_agentdojo_8b_remote", target, model, sha)
                for name in ("stability.py", "costs.py"):
                    shutil.copy2(ROOT / "external_followup" / name, target / name)
                subprocess.run(
                    [str(EXTERNAL_PYTHON), "stability.py"], cwd=target, check=True, timeout=900
                )
                proc = subprocess.run(
                    [str(EXTERNAL_PYTHON), "stages.py"], cwd=target, check=False, timeout=14400
                )
                status.append(
                    {
                        "model": model,
                        "stage": "native_tasks",
                        "exit_code": proc.returncode,
                        "planned_expansion": len(p["episodes"]),
                    }
                )
                for dirname in ("preflight-results", "results"):
                    if (target / dirname / "attempts.jsonl").exists():
                        subprocess.run(
                            [str(EXTERNAL_PYTHON), "costs.py", dirname], cwd=target, check=True
                        )
                (ROOT / "progress.json").write_text(json.dumps(status, indent=2))
            finally:
                server.terminate()
                try:
                    server.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()
    (ROOT / "finished.json").write_text(json.dumps(status, indent=2))


if __name__ == "__main__":
    main()

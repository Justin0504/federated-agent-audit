"""Jetstream-only pinned nine-condition 14B screen; never auto-launch formal work."""
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


def main():
    if socket.gethostname() != "sss":
        raise SystemExit("Jetstream only")
    root = Path("/media/volume/jin2/faa-research-20261013")
    patches = Path("/dev/shm/faa-interface-diagnostic")
    specification = json.loads((patches / "jetstream-14b-development.json").read_text())
    source = root / "native-dev-v23-canonical"
    if hashlib.sha256((source / "protocol.json").read_bytes()).hexdigest() != specification["reference_development_protocol_sha256"]:
        raise RuntimeError("Reference protocol changed")
    weights = Path("/dev/shm/faa-protocol-models/qwen25_14b")
    verified = json.loads((weights / "verified.json").read_text())
    if verified["files"] != specification["files"] or verified["revision"] != specification["model_revision"]:
        raise RuntimeError("Weight verification manifest differs")
    for item in specification["files"]:
        h = hashlib.sha256()
        with (weights / item["name"]).open("rb") as f:
            for block in iter(lambda: f.read(8 * 1024 * 1024), b""):
                h.update(block)
        if h.hexdigest() != item["sha256"]:
            raise RuntimeError("Weight digest changed")
    os.environ["FAA_NATIVE_ENDPOINT"] = "http://127.0.0.1:18090"
    sys.path.insert(0, str(patches))
    from native_backend import SYSTEM, generate

    served = "Qwen2.5-14B-Instruct-Q4_K_M"
    with urllib.request.urlopen("http://127.0.0.1:18090/v1/models", timeout=20) as response:
        models = json.load(response)["data"]
    if len(models) != 1 or models[0]["id"] != served:
        raise RuntimeError("Wrong model endpoint")
    target = root / specification["name"]
    target.mkdir(exist_ok=False)
    for f in source.glob("*.py"):
        shutil.copy2(f, target / f.name)
    for name in ("native_backend.py", "run.py", "ipiguard_adapter.py", "task_baselines.py"):
        shutil.copy2(patches / name, target / name)
    shutil.copy2(patches / "native_backend.py", target / "backend.py")
    p = json.loads((source / "protocol.json").read_text())
    episodes = [e for e in p["episodes"] if e["arm"] == "no_gate"]
    assert len(episodes) == 9
    p.update(name=target.name, episodes=episodes, generation_model=served, served_model=served,
             native_system=SYSTEM, native_tool_feedback="envelope", endpoint="http://127.0.0.1:18090",
             generation_revision=specification["model_revision"], model_shards=specification["files"],
             scope="Frozen14B nine-condition development competence screen; no heldout or seven-method claims")
    p["source_hashes"] = {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in target.glob("*.py")}
    (target / "protocol.json").write_text(json.dumps(p, indent=2))
    smoke = []
    for _ in range(2):
        result = generate([{"role": "system", "content": SYSTEM}, {"role": "user", "content": json.dumps({"tools": [], "original_request": "Reply with exactly OK."})}], dict(p, max_new_tokens=16))
        valid = not result.get("error") and not result.get("truncated") and json.loads(result.get("text", "{}" )).get("final", "").strip() == "OK"
        smoke.append({"ok": valid, "input_tokens": result.get("input_tokens"), "output_tokens": result.get("output_tokens"), "seconds": result["seconds"]})
    (target / "smoke.json").write_text(json.dumps(smoke, indent=2))
    if not all(r["ok"] for r in smoke):
        raise RuntimeError("Readiness smoke failed; no episodes started")
    with (target / "worker.log").open("w") as wl, (target / "run.log").open("w") as rl:
        worker = subprocess.Popen([sys.executable, "worker.py"], cwd=target, stdout=wl, stderr=subprocess.STDOUT)
        start = time.monotonic()
        try:
            result = subprocess.run([sys.executable, "run.py", "--upstream", str(root / "agentdojo-external-v1/upstream"), "--out", "results"], cwd=target, stdout=rl, stderr=subprocess.STDOUT, timeout=2700, check=False)
            status = {"exit_code": result.returncode, "timed_out": False}
        except subprocess.TimeoutExpired:
            status = {"exit_code": None, "timed_out": True}
        finally:
            worker.terminate()
            try:
                worker.wait(timeout=10)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait()
        status["wall_seconds"] = time.monotonic() - start
        (target / "finished.json").write_text(json.dumps(status))
    if (target / "results/attempts.jsonl").exists():
        summary = subprocess.check_output([sys.executable, "diagnose_development.py", str(target)], cwd=target, text=True)
        (target / "numeric_summary.json").write_text(summary)


if __name__ == "__main__":
    main()

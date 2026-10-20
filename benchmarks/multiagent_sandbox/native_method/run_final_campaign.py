"""Final frozen development gate and eight-arm formal run, Jetstream only."""
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

from diagnose_development import summarize
from run_eight_development import ARMS

DEV_SHA = "31ea376a15f1acfb380d96c47d65db415ac41fb7da813b3ca63953e70290543b"
CASES_SHA = "4fb0247d476c136c10a82ae2f6648965e76946f2e687bc3209c8d6b6c19df473"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(development, source):
    if sha(development / "protocol.json") != DEV_SHA or sha(source / "protocol.json") != CASES_SHA:
        raise ValueError("Frozen manifest changed")
    p = json.loads((development / "protocol.json").read_text())
    f = json.loads((source / "protocol.json").read_text())
    status = json.loads((development / "finished.json").read_text())
    if status["exit_code"] != 0 or not (development / "results/FINISHED.json").exists():
        raise ValueError("Development incomplete")
    rows = [json.loads(s) for s in (development / "results/attempts.jsonl").read_text().splitlines()]
    def key(e):
        return e["path"], e["arm"], bool(e.get("counterfactual_clean"))
    expected = {key(e) for e in p["episodes"]}
    if len(rows) != 72 or len(expected) != 72 or len({key(r) for r in rows}) != 72 or {key(r) for r in rows} != expected:
        raise ValueError("Incomplete or duplicate development identities")
    if {e["arm"] for e in p["episodes"]} != set(ARMS):
        raise ValueError("Methods changed")
    for r in rows:
        result = r.get("result", {})
        o = result.get("outcome", {})
        if (r.get("error") or o.get("utility") is None or (r["attacked"] and o.get("attack_success") is None)
                or any(s.get("response", {}).get("error") for s in result.get("steps", []))):
            raise ValueError("Unknown execution outcome; investigate before formal")
    twins = [r for r in rows if r["arm"] == "no_gate" and r.get("counterfactual_clean")]
    if len(twins) != 3 or sum(r["result"]["outcome"]["utility"] is True for r in twins) < 2:
        raise ValueError("Clean twin gate failed")
    for name, digest in p["source_hashes"].items():
        if sha(development / name) != digest:
            raise ValueError("Frozen execution code changed")
    if len(f["cases"]) != 32 or len({c["task"] for c in f["cases"]}) != 32:
        raise ValueError("Unexpected formal task count")
    if {c["task"] for c in p["cases"]} & {c["task"] for c in f["cases"]}:
        raise ValueError("Task overlap")
    if p["endpoint"] != "http://127.0.0.1:18090":
        raise ValueError("Wrong endpoint")
    return p, f


def main():
    if socket.gethostname() != "sss":
        raise SystemExit("Jetstream only")
    root = Path("/media/volume/jin2/faa-research-20261013")
    dev = root / "native-dev-v30-qwen25-14b-eight"
    source = root / "agentdojo-schema-v6-qwen25_3b"
    target = root / "native-formal-v31-qwen25-14b-eight"
    # One launcher owns this experiment; never overwrite or resume silently.
    lock = root / "final-v31-launch.lock"
    with lock.open("x") as out:
        out.write(str(os.getpid()))
    for _ in range(720):
        if (dev / "finished.json").exists():
            break
        time.sleep(10)
    else:
        raise RuntimeError("Development still incomplete; no formal launch")
    try:
        p, f = validate(dev, source)
    except ValueError as exc:
        (dev / "formal_gate_failed.json").write_text(json.dumps({"reason": str(exc)}))
        return
    with urllib.request.urlopen(p["endpoint"] + "/v1/models", timeout=15) as response:
        identity = json.load(response)
    if "14770033664" not in json.dumps(identity) or "Qwen2.5-14B" not in json.dumps(identity):
        raise RuntimeError("Wrong served model")
    upstream = root / "agentdojo-external-v1/upstream"
    for c in f["cases"]:
        if sha(upstream / c["path"]) != c["sha256"]:
            raise RuntimeError("Frozen task payload changed")
    target.mkdir(exist_ok=False)
    for file in dev.glob("*.py"):
        shutil.copy2(file, target / file.name)
    episodes = []
    for i, c in enumerate(f["cases"]):
        for arm in ARMS[i % len(ARMS):] + ARMS[:i % len(ARMS)]:
            episodes.append(dict(c, arm=arm, tool_output_format="upstream_yaml", prompt_revision="upstream_yaml"))
    p.update(name=target.name, cases=f["cases"], episodes=episodes,
             scope="32 development-disjoint canonical tasks x8 fixed methods; archived attacks; native attack predicates are not complete semantic privacy",
             development_protocol_sha256=DEV_SHA, frozen_task_manifest_sha256=CASES_SHA,
             launcher_sha256=sha(Path(__file__)))
    (target / "protocol.json").write_text(json.dumps(p, indent=2))
    shutil.copy2(dev / "runtime_manifest.json", target / "runtime_manifest.json")
    (target / "served_identity.json").write_text(json.dumps(identity, indent=2))
    os.environ["FAA_NATIVE_ENDPOINT"] = p["endpoint"]
    with (target / "worker.log").open("w") as wl, (target / "run.log").open("w") as rl:
        worker = subprocess.Popen([sys.executable, "worker.py"], cwd=target, stdout=wl, stderr=subprocess.STDOUT)
        try:
            run = subprocess.run([sys.executable, "run.py", "--upstream", str(upstream), "--out", "results"], cwd=target, stdout=rl, stderr=subprocess.STDOUT, timeout=14400, check=False)
            status = {"exit_code": run.returncode, "timed_out": False}
        except subprocess.TimeoutExpired:
            status = {"exit_code": None, "timed_out": True}
        finally:
            worker.terminate()
            try:
                worker.wait(timeout=10)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait()
    (target / "finished.json").write_text(json.dumps(status))
    if (target / "results/attempts.jsonl").exists():
        (target / "numeric_summary.json").write_text(json.dumps(summarize(target), indent=2))


if __name__ == "__main__":
    main()

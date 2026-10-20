"""Validate completed development and run seven original arms plus labeled resume."""
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import urllib.request
from pathlib import Path

ARMS = ("no_gate", "gate_replan", "scope_replan", "receipt_replan", "deny_egress", "upstream_tool_filter", "ipiguard", "upstream_tool_filter_resume")


def main():
    if socket.gethostname() != "sss":
        raise SystemExit("Jetstream only")
    root = Path("/media/volume/jin2/faa-research-20261013")
    source = root / "native-dev-v28-qwen25-14b-seven"
    p = json.loads((source / "protocol.json").read_text())
    finished = json.loads((source / "finished.json").read_text())
    rows = [json.loads(line) for line in (source / "results/attempts.jsonl").read_text().splitlines()]
    def key(r):
        return r["path"], r["arm"], bool(r.get("counterfactual_clean"))
    if finished["exit_code"] != 0 or not (source / "results/FINISHED.json").exists():
        raise RuntimeError("Screen incomplete")
    if len(rows) != 63 or len({key(r) for r in rows}) != 63 or {key(r) for r in rows} != {key(e) for e in p["episodes"]}:
        raise RuntimeError("Screen identities mismatch")
    for r in rows:
        result = r.get("result", {})
        outcome = result.get("outcome", {})
        if (r.get("error") or outcome.get("utility") is None
                or (r["attacked"] and outcome.get("attack_success") is None)
                or any(s.get("response", {}).get("error") for s in result.get("steps", []))):
            raise RuntimeError("Unresolved execution failure")
    twins = [r for r in rows if r.get("counterfactual_clean") and r["arm"] == "no_gate"]
    if len(twins) != 3 or sum(r["result"]["outcome"]["utility"] is True for r in twins) < 2:
        raise RuntimeError("Clean-twin competence gate failed")
    for name, sha in p["source_hashes"].items():
        if hashlib.sha256((source / name).read_bytes()).hexdigest() != sha:
            raise RuntimeError("Screen source changed")
    compat = root / "native-dev-v29-filter-compat"
    if not (compat / "finished.json").exists():
        raise RuntimeError("Compatibility comparison incomplete")
    for variant in ("upstream", "generic_resume"):
        summary = json.loads((compat / variant / "numeric_summary.json").read_text())
        if not summary["complete"] or summary["observed"] != 9:
            raise RuntimeError("Compatibility comparison incomplete")
        if any(g["unknown"] for g in summary["groups"].values()):
            raise RuntimeError("Compatibility execution failure")
    if p["endpoint"] != "http://127.0.0.1:18090":
        raise RuntimeError("Wrong endpoint")
    with urllib.request.urlopen(p["endpoint"] + "/v1/models", timeout=15) as response:
        identity = json.load(response)
    if "14770033664" not in json.dumps(identity) or "Qwen2.5-14B" not in json.dumps(identity):
        raise RuntimeError("Wrong served model")
    target = root / "native-dev-v30-qwen25-14b-eight"
    target.mkdir(exist_ok=False)
    for f in source.glob("*.py"):
        shutil.copy2(f, target / f.name)
    for name in ("run.py", "task_baselines.py"):
        shutil.copy2(Path(__file__).with_name(name), target / name)
    conditions = [e for e in p["episodes"] if e["arm"] == "no_gate"]
    episodes = []
    for i, c in enumerate(conditions):
        for arm in ARMS[i % len(ARMS):] + ARMS[:i % len(ARMS)]:
            episodes.append(dict(c, arm=arm))
    p.update(name=target.name, episodes=episodes, scope="Development only: seven original arms plus labeled Tool Filter resume adaptation; 9conditions x8; not heldout", tool_filter_continuation="upstream")
    p["previous_development_protocol_sha256"] = hashlib.sha256((source / "protocol.json").read_bytes()).hexdigest()
    p["source_hashes"] = {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in target.glob("*.py")}
    p["runner_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (target / "protocol.json").write_text(json.dumps(p, indent=2))
    shutil.copy2(source / "runtime_manifest.json", target / "runtime_manifest.json")
    os.environ["FAA_NATIVE_ENDPOINT"] = p["endpoint"]
    with (target / "worker.log").open("w") as wl, (target / "run.log").open("w") as rl:
        worker = subprocess.Popen([sys.executable, "worker.py"], cwd=target, stdout=wl, stderr=subprocess.STDOUT)
        try:
            run = subprocess.run([sys.executable, "run.py", "--upstream", str(root / "agentdojo-external-v1/upstream"), "--out", "results"], cwd=target, stdout=rl, stderr=subprocess.STDOUT, timeout=7200, check=False)
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
        summary = subprocess.check_output([sys.executable, "diagnose_development.py", str(target)], cwd=target, text=True)
        (target / "numeric_summary.json").write_text(summary)


if __name__ == "__main__":
    main()

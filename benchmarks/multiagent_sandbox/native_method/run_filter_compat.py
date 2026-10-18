"""Frozen development-only Tool Filter continuation comparison; no formal launch."""
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import urllib.request
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if socket.gethostname() != "sss":
        raise SystemExit("Jetstream only")
    root = Path("/media/volume/jin2/faa-research-20261013")
    source = root / "native-dev-v28-qwen25-14b-seven"
    p = json.loads((source / "protocol.json").read_text())
    if json.loads((source / "finished.json").read_text())["exit_code"] != 0:
        raise RuntimeError("Previous development incomplete")
    for name, sha in p["source_hashes"].items():
        if digest(source / name) != sha:
            raise RuntimeError("Historical source changed")
    episodes = [e for e in p["episodes"] if e["arm"] == "upstream_tool_filter"]
    if len(episodes) != 9 or len({(e["path"], bool(e.get("counterfactual_clean"))) for e in episodes}) != 9:
        raise RuntimeError("Expected all nine development conditions")
    if p["endpoint"] != "http://127.0.0.1:18090":
        raise RuntimeError("Wrong endpoint")
    with urllib.request.urlopen(p["endpoint"] + "/v1/models", timeout=15) as response:
        identity = json.load(response)
    if "14770033664" not in json.dumps(identity) or "Qwen2.5-14B" not in json.dumps(identity):
        raise RuntimeError("Wrong served model")
    target = root / "native-dev-v29-filter-compat"
    target.mkdir(exist_ok=False)
    (target / "design.json").write_text(json.dumps({
        "scope": "Development compatibility only; not official-baseline efficacy or heldout",
        "variants": ["upstream", "generic_resume"], "conditions_per_variant": 9,
        "interpretation": "Interpret only after both complete. Retain original even if worse. No formal launch.",
        "source_protocol_sha256": digest(source / "protocol.json"),
        "runner_sha256": digest(Path(__file__)), "served_identity": identity,
    }, indent=2))
    # Freeze both complete protocols before running either variant.
    for variant in ("upstream", "generic_resume"):
        directory = target / variant
        directory.mkdir()
        for f in source.glob("*.py"):
            shutil.copy2(f, directory / f.name)
        shutil.copy2(Path(__file__).with_name("task_baselines.py"), directory / "task_baselines.py")
        protocol = dict(p, name=f"{target.name}/{variant}", episodes=episodes,
            tool_filter_continuation=variant, scope=f"Development-only Tool Filter compatibility: {variant}; n=9")
        protocol["source_hashes"] = {name: digest(directory / name) for name in p["source_hashes"]}
        protocol["source_hashes"]["task_baselines.py"] = digest(directory / "task_baselines.py")
        (directory / "protocol.json").write_text(json.dumps(protocol, indent=2))
        shutil.copy2(source / "runtime_manifest.json", directory / "runtime_manifest.json")
    os.environ["FAA_NATIVE_ENDPOINT"] = p["endpoint"]
    for variant in ("upstream", "generic_resume"):
        directory = target / variant
        with (directory / "worker.log").open("w") as wl, (directory / "run.log").open("w") as rl:
            worker = subprocess.Popen([sys.executable, "worker.py"], cwd=directory, stdout=wl, stderr=subprocess.STDOUT)
            try:
                run = subprocess.run([sys.executable, "run.py", "--upstream", str(root / "agentdojo-external-v1/upstream"), "--out", "results"], cwd=directory, stdout=rl, stderr=subprocess.STDOUT, timeout=3600, check=False)
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
        (directory / "finished.json").write_text(json.dumps(status))
        if (directory / "results/attempts.jsonl").exists():
            summary = subprocess.check_output([sys.executable, "diagnose_development.py", str(directory)], cwd=directory, text=True)
            (directory / "numeric_summary.json").write_text(summary)
        if status["exit_code"] != 0:
            raise RuntimeError("Execution failed; keep evidence and investigate")
    (target / "finished.json").write_text(json.dumps({"completed_variants": 2}))


if __name__ == "__main__":
    main()

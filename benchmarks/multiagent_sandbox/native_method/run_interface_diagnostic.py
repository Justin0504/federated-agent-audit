"""Frozen development-only interface ablation, Jetstream GPU endpoint only.

No formal cases, oracle feedback, new budgets, or outcome-based early selection.
All three variants finish before inspecting their numerical summaries.
"""
import hashlib
import json
import shutil
import socket
import subprocess
import sys
from pathlib import Path


def main():
    if socket.gethostname() != "sss":
        raise SystemExit("Jetstream only")
    from agentdojo.agent_pipeline.agent_pipeline import load_system_message

    root = Path("/media/volume/jin2/faa-research-20261013")
    source = root / "native-dev-v23-canonical"
    patches = Path("/dev/shm/faa-interface-diagnostic")
    target = root / "native-dev-v25-interface"
    target.mkdir(exist_ok=False)
    sys.path.insert(0, str(patches))
    from native_backend import SYSTEM

    variants = [
        ("reference", SYSTEM, "envelope"),
        ("native_feedback", SYSTEM, "native_content"),
        ("upstream_prompt", load_system_message(None), "native_content"),
    ]
    base = json.loads((source / "protocol.json").read_text())
    episodes = [e for e in base["episodes"] if e["arm"] == "no_gate"]
    assert len(episodes) == 9
    (target / "design.json").write_text(json.dumps({
        "scope": "All nine development conditions, three fixed interface variants; no formal launch.",
        "variants": [v[0] for v in variants],
        "planned": 27,
        "budgets": {k: base[k] for k in ("max_steps", "max_new_tokens", "max_input_tokens")},
        "source_protocol_sha256": hashlib.sha256((source / "protocol.json").read_bytes()).hexdigest(),
    }, indent=2))
    for name, prompt, feedback in variants:
        child = target / name
        child.mkdir()
        for f in source.glob("*.py"):
            shutil.copy2(f, child / f.name)
        shutil.copy2(patches / "native_backend.py", child / "backend.py")
        shutil.copy2(patches / "native_backend.py", child / "native_backend.py")
        shutil.copy2(patches / "run.py", child / "run.py")
        p = dict(base, name=child.name, episodes=episodes, native_system=prompt,
                 native_tool_feedback=feedback, generation_model="Qwen2.5-7B-Instruct-Q4_K_M",
                 scope="Development interface ablation; all 9 fixed conditions; no held-out claims")
        p["source_hashes"] = {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in child.glob("*.py")}
        (child / "protocol.json").write_text(json.dumps(p, indent=2))
        with (child / "worker.log").open("w") as wl, (child / "run.log").open("w") as rl:
            worker = subprocess.Popen([sys.executable, "worker.py"], cwd=child, stdout=wl, stderr=subprocess.STDOUT)
            try:
                result = subprocess.run([sys.executable, "run.py", "--upstream", str(root / "agentdojo-external-v1/upstream"), "--out", "results"], cwd=child, stdout=rl, stderr=subprocess.STDOUT, timeout=1800, check=False)
            finally:
                worker.terminate()
                try:
                    worker.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    worker.kill()
                    worker.wait()
        (child / "finished.json").write_text(json.dumps({"exit_code": result.returncode}))
        if result.returncode:
            raise SystemExit("Development execution fault; preserved results, no formal launch")
        summary = subprocess.check_output([sys.executable, "diagnose_development.py", str(child)], cwd=child, text=True)
        (child / "numeric_summary.json").write_text(summary)
    (target / "finished.json").write_text(json.dumps({"exit_code": 0, "completed": 27}))


if __name__ == "__main__":
    main()

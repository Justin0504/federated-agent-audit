"""Jetstream continuation: validate complete development, then frozen controls."""

import json
import socket
import subprocess
import sys
import time
from pathlib import Path

from diagnose_development import summarize
from prepare_canonical import prepare


def main():
    if socket.gethostname() != "sss":
        raise SystemExit("Jetstream only")
    development = Path(sys.argv[1]).resolve()
    target = development.parent / "native-formal-v24-canonical"
    for _ in range(720):
        if (development / "finished.json").exists():
            break
        time.sleep(10)
    else:
        raise SystemExit("development incomplete; no expansion")
    (development / "numeric_summary.json").write_text(json.dumps(summarize(development), indent=2))
    try:
        prepare(development.parent / "agentdojo-schema-v6-qwen25_3b", development, target)
    except ValueError as exc:
        (development / "formal_gate_failed.json").write_text(json.dumps({"reason": str(exc)}))
        return
    with (target / "worker.log").open("w") as wl, (target / "run.log").open("w") as rl:
        worker = subprocess.Popen([sys.executable, "worker.py"], cwd=target, stdout=wl, stderr=subprocess.STDOUT)
        try:
            result = subprocess.run([sys.executable, "run.py", "--upstream",
                str(development.parent / "agentdojo-external-v1/upstream"), "--out", "results"],
                cwd=target, stdout=rl, stderr=subprocess.STDOUT, timeout=14400, check=False)
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
        (target / "finished.json").write_text(json.dumps(status))
        if (target / "results/attempts.jsonl").exists():
            (target / "numeric_summary.json").write_text(json.dumps(summarize(target), indent=2))


if __name__ == "__main__":
    main()

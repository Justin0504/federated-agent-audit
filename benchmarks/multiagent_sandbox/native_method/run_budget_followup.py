"""Queue one declared output-budget ablation after the 512-token probe ends."""

import json
import os
import socket
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PARENT = ROOT.parent


def main():
    if socket.gethostname() != "sss":
        raise SystemExit("Jetstream only")
    previous = PARENT / "native-method-v13"
    for _ in range(600):
        if (previous / "gate_failed.json").exists():
            break
        if (previous / "formal-3b/protocol.json").exists():
            (ROOT / "skipped.json").write_text(json.dumps({"reason": "original gate passed"}))
            return
        time.sleep(10)
    else:
        raise SystemExit("previous probe unresolved; no ablation launched")
    report = json.loads((previous / "gate_failed.json").read_text())["development"]
    g = report["groups"]["native_tools"]
    if (
        not report["complete"]
        or not g["caps"]
        or g["format_errors"]
        or g["unknown"]
        or g["unknown_attack"]
    ):
        (ROOT / "skipped.json").write_text(
            json.dumps({"reason": "not an isolated cap/competence diagnosis"})
        )
        return
    launched = {}
    for directory, script, limit, extra in [
        (ROOT, "run_native_probe.py", 6000, {"FAA_NATIVE_OUTPUT_TOKENS": "1024"}),
        (
            PARENT / "native-method-v15",
            "run_comparison.py",
            21600,
            {"FAA_NATIVE_DEVELOPMENT": "native-diagnosis-v14"},
        ),
    ]:
        path = directory / "launch.log"
        with path.open("x") as log:
            p = subprocess.Popen(
                ["timeout", str(limit), "python3", "-u", script],
                cwd=directory,
                env=dict(os.environ, **extra),
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            launched[directory.name] = p.pid
    (ROOT / "budget_ablation_started.json").write_text(json.dumps(launched))


if __name__ == "__main__":
    main()

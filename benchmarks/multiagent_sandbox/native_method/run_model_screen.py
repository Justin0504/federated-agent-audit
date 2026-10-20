"""Remote-only matched model competence screen; no automatic formal promotion."""

import hashlib
import json
import os
import shutil
import socket
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MODELS = [
    (
        "3b",
        "/dev/shm/faa-protocol-models/qwen2.5-3b-q4km.gguf",
        "626b4a6678b86442240e33df819e00132d3ba7dddfe1cdc4fbb18e0a9615c62d",
    ),
    (
        "7b",
        "/dev/shm/faa-protocol-models/qwen25_7b/qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf",
        "dfce12e3862a5283ccfb88221b48480e58745165de856439950d0f22590580db",
    ),
    (
        "8b",
        "/dev/shm/faa8b-remote-v1/qwen3-8b-q4km.gguf",
        "a3de86cd1c132c822487ededd47a324c50491393e6565cd14bafa40d0b8e686f",
    ),
]


def main():
    if socket.gethostname() != "sss":
        raise SystemExit("Jetstream only")
    shard = Path(MODELS[1][1].replace("00001", "00002"))
    if (
        hashlib.sha256(shard.read_bytes()).hexdigest()
        != "539cf93f78e887edea1c04e2d7d8cdaca9d01dae9c9025bcb8accbe29df3d72a"
    ):
        raise SystemExit("second shard mismatch")
    for name, model, sha in MODELS:
        target = ROOT.parent / ("native-screen-v16-" + name)
        target.mkdir(exist_ok=False)
        for p in ROOT.glob("*.py"):
            shutil.copy2(p, target / p.name)
        env = dict(
            os.environ,
            FAA_NATIVE_MODEL=model,
            FAA_NATIVE_SHA256=sha,
            FAA_NATIVE_OUTPUT_TOKENS="1024",
            FAA_NATIVE_MAX_STEPS="12",
            FAA_NATIVE_SCREEN="1",
        )
        with (target / "launch.log").open("w") as log:
            try:
                result = subprocess.run(
                    ["python3", "-u", "run_native_probe.py"],
                    cwd=target,
                    env=env,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=11400,
                    check=False,
                )
                status = {"exit_code": result.returncode}
            except subprocess.TimeoutExpired:
                # Do not continue if child cleanup cannot be established.
                raise SystemExit("screen timeout; inspect server before next model")
        (target / "screen_status.json").write_text(json.dumps(status))
        if result.returncode:
            raise SystemExit("screen infrastructure failed; no subsequent model")
    (ROOT / "finished.json").write_text(json.dumps({"models": 3}))


if __name__ == "__main__":
    main()

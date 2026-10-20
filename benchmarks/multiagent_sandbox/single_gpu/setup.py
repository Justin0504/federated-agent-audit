"""Provision only the user-authorized GPU7 pilot; no host package modifications."""

import concurrent.futures
import hashlib
import json
import socket
import subprocess
import tarfile
import time
from pathlib import Path

ROOT = Path("/data/faa-research-20261016")
MODEL_SHA = "626b4a6678b86442240e33df819e00132d3ba7dddfe1cdc4fbb18e0a9615c62d"


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url, path, expected):
    expected = expected.removeprefix("sha256:")
    if path.exists() and digest(path) == expected:
        return
    subprocess.run(
        ["curl", "-fL", "--retry", "3", "--max-time", "1800", "-o", str(path), url], check=True
    )
    if digest(path) != expected:
        raise RuntimeError("download hash mismatch: " + path.name)


def main():
    if socket.gethostname() != "zxlyg2286":
        raise SystemExit("Authorized GPU host only")
    setup = ROOT / "setup"
    downloads = ROOT / "downloads"
    downloads.mkdir(exist_ok=True)
    models = ROOT / "models"
    models.mkdir(exist_ok=True)
    assets = json.loads((setup / "runtime.json").read_text())
    model = models / "qwen2.5-3b-q4km.gguf"
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        jobs = [pool.submit(download, a["url"], downloads / a["name"], a["digest"]) for a in assets]
        jobs.append(
            pool.submit(
                download,
                "https://huggingface.co/Qwen/Qwen2.5-3B-Instruct-GGUF/resolve/main/qwen2.5-3b-instruct-q4_k_m.gguf",
                model,
                MODEL_SHA,
            )
        )
        for job in jobs:
            job.result()
    runtime = ROOT / "runtime"
    runtime.mkdir(exist_ok=True)
    for asset in assets:
        # Only digest-verified official release archives are extracted.
        with tarfile.open(downloads / asset["name"]) as tar:
            tar.extractall(runtime)
    server = next(runtime.rglob("llama-server"))
    for lib in runtime.rglob("*.so*"):
        target = server.parent / lib.name
        if not target.exists() and lib.is_file():
            target.symlink_to(lib)
    subprocess.run(
        [
            "tar",
            "-xzf",
            str(setup / "faa-native-public-source.tar.gz"),
            "-C",
            str(ROOT / "agentdojo-schema-v6-qwen25_3b"),
        ],
        check=True,
    )
    upstream = ROOT / "agentdojo-external-v1/upstream"
    upstream.parent.mkdir(exist_ok=True)
    if not (upstream / ".git").exists():
        subprocess.run(
            [
                "git",
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                "https://github.com/ethz-spylab/agentdojo.git",
                str(upstream),
            ],
            check=True,
        )
        files = {"/src/", "/pyproject.toml", "/README.md"}
        for name in ("protocol.json", "preflight_protocol.json"):
            protocol = json.loads((ROOT / "agentdojo-schema-v6-qwen25_3b" / name).read_text())
            files.update("/" + c["path"] for c in protocol["cases"])
        subprocess.run(
            ["git", "sparse-checkout", "set", "--no-cone", "--stdin"],
            input="\n".join(sorted(files)),
            text=True,
            cwd=upstream,
            check=True,
        )
    subprocess.run(
        ["git", "checkout", "089ed468cf3ed0322acc66b0211f26d9d90dbf60"], cwd=upstream, check=True
    )
    image = "faa-llama-b11624:20261016"
    for _ in range(120):
        ready = subprocess.run(["docker", "image", "inspect", image], capture_output=True)
        if ready.returncode == 0:
            break
        time.sleep(10)
    else:
        raise RuntimeError("isolated runtime image not ready")
    image_id = json.loads(ready.stdout)[0]["Id"]
    config = {
        "gpu_device": 7,
        "image_id": image_id,
        "runtime": str(server.parent),
        "model_sha256": MODEL_SHA,
        "upstream_commit": "089ed468cf3ed0322acc66b0211f26d9d90dbf60",
        "scope": "12 development episodes, not formal comparison",
    }
    (setup / "pilot_manifest.json").write_text(json.dumps(config, indent=2))
    env = [
        "LD_LIBRARY_PATH=" + str(server.parent),
        "FAA_RUNTIME=" + str(server.parent),
        "FAA_NATIVE_MODEL=" + str(model),
        "FAA_NATIVE_SHA256=" + MODEL_SHA,
        "FAA_NATIVE_OUTPUT_TOKENS=1024",
        "FAA_NATIVE_MAX_STEPS=12",
        "FAA_NATIVE_SCREEN=1",
        "FAA_GPU_LAYERS=99",
        "FAA_NATIVE_DEVELOPMENT=native-gpu-v17",
        "FAA_SCREEN_COMPARE=1",
        "FAA_REMOTE_PYTHON=" + str(ROOT / "agentdojo-env/bin/python"),
    ]
    cmd = [
        "docker",
        "run",
        "--name",
        "faa-single-a100-v17",
        "--hostname",
        "zxlyg2286",
        "--gpus",
        "device=7",
        "--cpus",
        "8",
        "--memory",
        "48g",
        "--network",
        "host",
        "--shm-size",
        "2g",
        "-v",
        str(ROOT) + ":" + str(ROOT),
        "-w",
        str(ROOT / "native-gpu-v17"),
    ]
    for e in env:
        cmd.extend(["-e", e])
    cmd.extend(
        [
            image_id,
            "bash",
            "-lc",
            "python3 -m venv "
            + str(ROOT / "agentdojo-env")
            + " && "
            + str(ROOT / "agentdojo-env/bin/pip")
            + " install "
            + str(upstream)
            + " > ../setup/pip.log 2>&1 && "
            + str(ROOT / "agentdojo-env/bin/pip")
            + " freeze > ../setup/requirements.lock && timeout 11000 "
            + str(ROOT / "agentdojo-env/bin/python")
            + " -u run_native_probe.py && timeout 14400 "
            + str(ROOT / "agentdojo-env/bin/python")
            + " -u run_comparison.py",
        ]
    )
    result = subprocess.run(cmd, check=False)
    (setup / "completed.json").write_text(json.dumps({"exit_code": result.returncode}))


if __name__ == "__main__":
    main()

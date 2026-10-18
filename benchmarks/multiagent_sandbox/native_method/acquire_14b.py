"""Acquire pinned public model shards on Jetstream; never infer or launch jobs."""
import hashlib
import json
import os
import socket
import sys
import urllib.request
from pathlib import Path


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    if socket.gethostname() != "sss":
        raise SystemExit("Jetstream only")
    p = json.loads(Path(sys.argv[1]).read_text())
    root = Path("/dev/shm/faa-protocol-models/qwen25_14b")
    root.mkdir(exist_ok=True)
    for item in p["files"]:
        target = root / item["name"]
        if target.exists():
            if target.stat().st_size != item["size"] or digest(target) != item["sha256"]:
                raise RuntimeError("Existing shard does not match pinned digest")
            continue
        partial = target.with_suffix(".partial")
        offset = partial.stat().st_size if partial.exists() else 0
        if offset > item["size"]:
            raise RuntimeError("Partial shard too large")
        if offset < item["size"]:
            url = f'https://huggingface.co/{p["model_repository"]}/resolve/{p["model_revision"]}/{item["name"]}?download=true'
            headers = {"Range": f"bytes={offset}-"} if offset else {}
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=120) as response:
                if offset and (response.status != 206 or response.headers.get("Content-Range") != f'bytes {offset}-{item["size"]-1}/{item["size"]}'):
                    raise RuntimeError("Resume range not honored; retaining partial")
                with partial.open("ab") as f:
                    while chunk := response.read(8 * 1024 * 1024):
                        if f.tell() + len(chunk) > item["size"]:
                            raise RuntimeError("Oversized shard")
                        f.write(chunk)
        if partial.stat().st_size != item["size"] or digest(partial) != item["sha256"]:
            raise RuntimeError("Incomplete shard or digest mismatch; retained for diagnosis")
        os.replace(partial, target)
        print(json.dumps({"verified": item["name"], "bytes": item["size"]}), flush=True)
    (root / "verified.json").write_text(json.dumps({"repository": p["model_repository"], "revision": p["model_revision"], "files": p["files"]}, indent=2))
    print("ALL_SHARDS_VERIFIED", flush=True)


if __name__ == "__main__":
    main()

"""Range-verified public mirror transfer; official full-file SHA256 is mandatory."""

import concurrent.futures
import hashlib
import os
import socket
import time
import urllib.request
from pathlib import Path

ROOT = Path("/data/faa-research-20261016/models")
SIZE = 2104932768
SHA = "626b4a6678b86442240e33df819e00132d3ba7dddfe1cdc4fbb18e0a9615c62d"
URL = "https://hf-mirror.com/Qwen/Qwen2.5-3B-Instruct-GGUF/resolve/main/qwen2.5-3b-instruct-q4_k_m.gguf"
CHUNK = 64 * 1024 * 1024


def part(i):
    start = i * CHUNK
    end = min(SIZE, start + CHUNK) - 1
    path = ROOT / ("part-%03d" % i)
    length = end - start + 1
    for attempt in range(8):
        offset = path.stat().st_size if path.exists() else 0
        if offset > length:
            raise RuntimeError("oversized cached range")
        if offset == length:
            return path  # Final full-file SHA256 still verifies every cached byte.
        first = start + offset
        req = urllib.request.Request(
            URL + f"?download=true&faa_part={i}&offset={offset}",
            headers={"Range": f"bytes={first}-{end}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as response:
                if response.status != 206 or response.headers.get("Content-Range") != f"bytes {first}-{end}/{SIZE}":
                    raise RuntimeError("unexpected range response")
                with path.open("ab") as f:
                    while block := response.read(1024 * 1024):
                        if f.tell() + len(block) > length:
                            raise RuntimeError("oversized range response")
                        f.write(block)
            if path.stat().st_size == length:
                print("part complete", i, flush=True)
                return path
        except OSError as exc:
            print("part retry", i, attempt + 1, type(exc).__name__, flush=True)
        time.sleep(min(2 ** attempt, 30))
    raise RuntimeError(f"range {i} exhausted retries; partial bytes retained")


def main():
    if socket.gethostname() != "zxlyg2286":
        raise SystemExit("Remote GPU host only")
    ROOT.mkdir(parents=True, exist_ok=True)
    count = (SIZE + CHUNK - 1) // CHUNK
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        paths = list(pool.map(part, range(count)))
    h = hashlib.sha256()
    target = ROOT / "qwen2.5-3b-q4km.gguf.verified"
    with target.open("wb") as out:
        for p in paths:
            with p.open("rb") as f:
                for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
                    h.update(chunk)
                    out.write(chunk)
    if h.hexdigest() != SHA:
        raise RuntimeError("official SHA256 mismatch")
    os.replace(target, ROOT / "qwen2.5-3b-q4km.gguf")
    for p in paths:
        p.unlink()
    print("official SHA256 verified", flush=True)


if __name__ == "__main__":
    main()

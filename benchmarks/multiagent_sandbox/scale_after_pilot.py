"""One bounded scaling stage; never expand on utility or privacy success labels."""

import argparse
import json
import socket
import subprocess
import sys
import time
from pathlib import Path


def eligible(summary):
    n = summary["recorded"]
    return (
        summary["complete"]
        and n > 0
        and summary["valid"] == summary["planned"]
        and sum(a["format_errors"] for a in summary["arms"].values()) / n <= 0.2
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pilot", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--expected-host", required=True)
    ap.add_argument("--groups", type=int, default=8)
    a = ap.parse_args()
    if socket.gethostname() != a.expected_host:
        raise SystemExit("remote hostname mismatch")
    if not 1 <= a.groups <= 32:
        raise SystemExit("bounded initial scale stage permits at most 32 groups")
    deadline = time.monotonic() + 1800
    while not (a.pilot / "summary.json").exists():
        if time.monotonic() > deadline:
            raise SystemExit("Pilot did not finish; no expansion")
        time.sleep(5)
    if not eligible(json.loads((a.pilot / "summary.json").read_text())):
        raise SystemExit("Pilot runtime/format gate failed; no expansion")
    subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("run.py")),
            "--expected-host",
            a.expected_host,
            "--groups",
            str(a.groups),
            "--concurrency",
            "2",
            "--out",
            str(a.out),
        ],
        check=True,
        timeout=7200,
    )


if __name__ == "__main__":
    main()

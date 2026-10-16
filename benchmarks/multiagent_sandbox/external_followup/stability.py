"""Probe schema transport without selecting on benchmark utility."""

import json
from pathlib import Path

from backend import generate

root = Path(__file__).resolve().parent
p = json.loads((root / "protocol.json").read_text())
checks = []
for pad in (0, 100, 400, 0, 100):
    response = generate(
        [
            {"role": "system", "content": 'Return only JSON {"final":"ready"}.'},
            {"role": "user", "content": "neutral context. " * pad + "Return ready."},
        ],
        dict(p, max_new_tokens=32),
    )
    # No model text in the public readiness file.
    ok = not response.get("error") and not response.get("truncated")
    try:
        ok = ok and json.loads(response.get("text", "")) == {"final": "ready"}
    except ValueError:
        ok = False
    checks.append({"passed": ok, "seconds": response["seconds"]})
    (root / "stability.json").write_text(json.dumps({"checks": checks, "passed": False}, indent=2))
    if not ok:
        raise SystemExit("Schema stability failed; not expanding")
(root / "stability.json").write_text(json.dumps({"checks": checks, "passed": True}, indent=2))

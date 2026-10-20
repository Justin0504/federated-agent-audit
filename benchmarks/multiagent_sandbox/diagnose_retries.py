"""Remote-only matched replay; private histories stay on the compute host."""

import argparse
import hashlib
import json
import socket
from collections import Counter
from pathlib import Path

import paired_scale as scale

VARIANTS = {
    "history_cached": {},
    "history_uncached": {"cache_prompt": False},
    "fresh_uncached": {"cache_prompt": False, "retry_mode": "fresh"},
    "receipt_uncached": {"cache_prompt": False, "retry_mode": "fresh", "receipt_only": True},
}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    if socket.gethostname() != "sss":
        raise SystemExit("Jetstream only")
    rows = [json.loads(x) for x in a.source.read_text().splitlines()]
    failed = [r for r in rows if not r["initial_utility"]]
    # Matched successful controls, not a representative accuracy estimate.
    strata = {(r["task"], r["arm"]) for r in failed}
    controls = [
        next(r for r in rows if (r["task"], r["arm"]) == k and r["initial_utility"])
        for k in sorted(strata)
    ]
    selected = failed + controls
    a.out.mkdir(exist_ok=False)
    (a.out / "manifest.json").write_text(
        json.dumps(
            {
                "source_sha256": hashlib.sha256(a.source.read_bytes()).hexdigest(),
                "selected_keys": [
                    [r[k] for k in ("task", "case", "world", "arm")] for r in selected
                ],
                "variant_order": "cyclic by selected row",
                "source_hashes": {
                    n: hashlib.sha256(Path(n).read_bytes()).hexdigest()
                    for n in ("run.py", "paired_scale.py", "diagnose_retries.py")
                },
            },
            indent=2,
        )
    )
    results = []
    with (a.out / "numeric.jsonl").open("w") as f:
        for i, r in enumerate(selected):
            names = list(VARIANTS)
            names = names[i % 4 :] + names[: i % 4]
            for name in names:
                expected = r["transcript"][0]["authorized_decision"]
                result = scale.execute(r, expected, "http://127.0.0.1:18088", **VARIANTS[name])

                def category(text, expected=expected):
                    try:
                        value = json.loads(text)["slot"]
                    except (ValueError, KeyError, TypeError):
                        return "malformed"
                    return (
                        "correct"
                        if value == expected
                        else ("unexpected_null" if value is None else "wrong_integer")
                    )

                result["outcome_categories"] = [
                    category(t) for t in result.pop("coordinator_outputs")
                ]
                result.update({k: r[k] for k in ("task", "case", "world", "arm")})
                result.update(variant=name, historically_failed=not r["initial_utility"])
                results.append(result)
                f.write(json.dumps(result) + "\n")
                f.flush()
    summary = {}
    for name in VARIANTS:
        rr = [r for r in results if r["variant"] == name]
        summary[name] = {
            "n": len(rr),
            "initial": sum(r["initial_utility"] for r in rr),
            "final": sum(r["utility"] for r in rr),
            "retries": sum(r["repair_attempted"] for r in rr),
            "recoveries": sum(r["repair_success"] for r in rr),
            "categories": dict(Counter(" -> ".join(r["outcome_categories"]) for r in rr)),
        }
    (a.out / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    main()

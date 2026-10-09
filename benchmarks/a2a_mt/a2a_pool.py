#!/usr/bin/env python3
"""Pool instruction-sweep traces from several directories into one table.

`a2a_prompt_conditions.py --rescore DIR` pools one directory. The open-weight
roster grew in two later batches (a 32B arm served with vLLM, then phi-4 and
Mistral-Small-24B), each kept in its own directory so the original seven-model
numbers stay reproducible. This pools any set of trace files, re-deriving every
cell from the hand-off text under the CURRENT ground truth, and reports the
cluster-bootstrap intervals the paper uses (model x workflow clusters, as the
paper's pooled intervals were computed; this reproduces them on the 7-model set).

Workflow identity is not stored in the trace rows; it is recovered from row
order -- each (model, condition) block is written workflow-major, `runs` rows per
workflow -- and checked against WORKFLOWS' domain sequence, so a truncated or
reordered trace fails loudly instead of silently mis-clustering.

Run:  python benchmarks/a2a_mt/a2a_pool.py traces/prompt_conditions traces/prompt_conditions_32b ...
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

try:
    from .a2a_prompt_conditions import CONDITIONS, GT, _cluster_ci
    from .a2a_measurement import WORKFLOWS
except ImportError:  # run as a script
    sys.path.insert(0, str(Path(__file__).parent))
    from a2a_prompt_conditions import CONDITIONS, GT, _cluster_ci  # type: ignore
    from a2a_measurement import WORKFLOWS  # type: ignore


def load(paths: list[Path], runs: int = 3) -> list[dict]:
    rows = []
    for p in paths:
        model = p.stem
        by_cond: dict[str, list[dict]] = defaultdict(list)
        for line in p.read_text().splitlines():
            if line.strip():
                r = json.loads(line)
                by_cond[r["cond"]].append(r)
        for cond, rs in by_cond.items():
            if len(rs) != len(WORKFLOWS) * runs:
                raise SystemExit(f"{p}: {cond} has {len(rs)} rows, expected {len(WORKFLOWS) * runs}")
            for i, r in enumerate(rs):
                wf = i // runs
                if r["domain"] != WORKFLOWS[wf][0]:
                    raise SystemExit(f"{p}: {cond} row {i} domain {r['domain']} != workflow {wf}")
                id_pat, attr_pat = GT[wf]
                text = r["handoff"]
                rows.append({
                    "model": model, "cond": cond, "wf": wf,
                    "leak_id": bool(re.search(id_pat, text, re.I)),
                    "leak_attr": bool(re.search(attr_pat, text, re.I)),
                    "caught": bool(r["caught"]),
                })
    return rows


def pct(x: float) -> str:
    return f"{100 * x:.0f}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="+", help="trace directories or .jsonl files")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--exclude", default="", help="comma-separated model stems to leave out")
    a = ap.parse_args(argv)
    paths = []
    for d in a.dirs:
        p = Path(d)
        paths += sorted(p.glob("*.jsonl")) if p.is_dir() else [p]
    excl = set(filter(None, a.exclude.split(",")))
    paths = [p for p in paths if p.stem not in excl]
    rows = load(paths, a.runs)
    models = sorted({r["model"] for r in rows})
    n_models = len(models)
    print(f"{n_models} models, {len(rows)} trials: {', '.join(models)}\n")

    print(f"  {'condition':<12}{'leak':<18}{'cluster 95% CI':<16}{'ident.':<8}{'attr.':<8}{'auditor'}")
    print("  " + "-" * 70)
    for cond in CONDITIONS:
        rs = [r for r in rows if r["cond"] == cond]
        n = len(rs)
        if not n:
            continue
        # one cluster per (model, workflow): the paper's pooled intervals were
        # computed this way, and this reproduces them exactly on the 7-model set
        clusters = defaultdict(list)
        for r in rs:
            clusters[(r["model"], r["wf"])].append(r["leak_id"] or r["leak_attr"])
        lo, hi = _cluster_ci(list(clusters.values()))
        anyk = sum(r["leak_id"] or r["leak_attr"] for r in rs)
        print(f"  {cond:<12}{anyk}/{n} = {pct(anyk / n)}%{'':<6}[{pct(lo)}, {pct(hi)}]{'':<7}"
              f"{pct(sum(r['leak_id'] for r in rs) / n)}%{'':<4}"
              f"{pct(sum(r['leak_attr'] for r in rs) / n)}%{'':<4}"
              f"{pct(sum(r['caught'] for r in rs) / n)}%")

    tp = sum((r["leak_id"] or r["leak_attr"]) and r["caught"] for r in rows)
    fn = sum((r["leak_id"] or r["leak_attr"]) and not r["caught"] for r in rows)
    fp = sum(not (r["leak_id"] or r["leak_attr"]) and r["caught"] for r in rows)
    print(f"\n  auditor vs literal ground truth ({len(rows)} trials): "
          f"recall {tp / (tp + fn):.2f}  precision {tp / (tp + fp):.2f}  "
          f"(misses {fn}; fires without a literal match {fp})")

    # per-model permissive -> policy, the rows of the redaction figure
    print(f"\n  {'model':<22}{'ident. perm->pol':<20}{'attr. perm->pol':<20}{'leak perm->pol'}")
    print("  " + "-" * 70)
    for m in models:
        cells = {}
        for cond in ("permissive", "policy"):
            rs = [r for r in rows if r["model"] == m and r["cond"] == cond]
            n = len(rs) or 1
            cells[cond] = (sum(r["leak_id"] for r in rs) / n, sum(r["leak_attr"] for r in rs) / n,
                           sum(r["leak_id"] or r["leak_attr"] for r in rs) / n)
        p, q = cells["permissive"], cells["policy"]
        print(f"  {m:<22}{pct(p[0])} -> {pct(q[0]):<14}{pct(p[1])} -> {pct(q[1]):<14}{pct(p[2])} -> {pct(q[2])}")

    # open-weight vs frontier split, as the paper's contribution table states it
    ow = [r for r in rows if not r["model"].startswith("claude")]
    fr = [r for r in rows if r["model"].startswith("claude")]
    for name, rs in (("open-weight", ow), ("frontier", fr)):
        if not rs:
            continue
        out = []
        for key in ("leak_id", "leak_attr"):
            v = []
            for cond in ("permissive", "policy"):
                c = [r for r in rs if r["cond"] == cond]
                v.append(pct(sum(r[key] for r in c) / len(c)))
            out.append(f"{v[0]} -> {v[1]}")
        print(f"\n  {name} ({len({r['model'] for r in rs})} models): identifiers {out[0]}; attributes {out[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

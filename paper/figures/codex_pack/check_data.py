#!/usr/bin/env python3
"""Verify figure_data.json against the traces it claims to summarise.

Every trace-derived number in figure_data.json (the instruction sweep, the tagger
attack, the oracle arm) is recomputed here from benchmarks/a2a_mt/traces/ and
compared. Run it before drawing and again before you declare a figure done; a
mismatch means the data file is wrong, never the trace.

    python paper/figures/codex_pack/check_data.py
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

# works both inside the repository and inside the extracted zip: walk up until
# the directory that holds benchmarks/a2a_mt/traces
ROOT = next(p for p in Path(__file__).resolve().parents if (p / "benchmarks" / "a2a_mt" / "traces").is_dir())
sys.path.insert(0, str(ROOT / "benchmarks" / "a2a_mt"))
from a2a_pool import load  # noqa: E402

T = ROOT / "benchmarks" / "a2a_mt" / "traces"
D = json.loads((Path(__file__).parent / "figure_data.json").read_text())
bad = 0


def check(name, got, want, tol=0.5):
    global bad
    ok = abs(got - want) <= tol
    bad += not ok
    print(f"  {'ok ' if ok else 'BAD'} {name:<60} data={want:<8} trace={got:.1f}")


pct = lambda k, n: 100 * k / n

# ---- instruction sweep -----------------------------------------------------
paths = []
for d in ("prompt_conditions", "prompt_conditions_32b", "prompt_conditions_more"):
    paths += sorted((T / d).glob("*.jsonl"))
rows = load(paths)
S = D["instruction_sweep"]
conds = ["permissive", "neutral", "instructed", "policy"]
print("instruction sweep, pooled over", len({r['model'] for r in rows}), "models")
for i, c in enumerate(conds):
    rs = [r for r in rows if r["cond"] == c]
    n = len(rs)
    check(f"{c} leak%", pct(sum(r["leak_id"] or r["leak_attr"] for r in rs), n), S["pooled_11"]["leak_pct"][i])
    check(f"{c} identifiers%", pct(sum(r["leak_id"] for r in rs), n), S["pooled_11"]["identifiers_pct"][i])
    check(f"{c} attributes%", pct(sum(r["leak_attr"] for r in rs), n), S["pooled_11"]["attributes_pct"][i])
    check(f"{c} auditor%", pct(sum(r["caught"] for r in rs), n), S["pooled_11"]["auditor_caught_pct"][i])
tp = sum((r["leak_id"] or r["leak_attr"]) and r["caught"] for r in rows)
fn = sum((r["leak_id"] or r["leak_attr"]) and not r["caught"] for r in rows)
fp = sum(not (r["leak_id"] or r["leak_attr"]) and r["caught"] for r in rows)
check("auditor recall", tp / (tp + fn), S["pooled_11"]["auditor_recall"], 0.005)
check("auditor precision", tp / (tp + fp), S["pooled_11"]["auditor_precision"], 0.005)
check("misses", fn, S["pooled_11"]["misses"], 0)
check("fires without literal match", fp, S["pooled_11"]["fires_without_literal_match"], 0)
print("per model, permissive -> policy")
for m, v in S["per_model_permissive_to_policy"].items():
    if m.startswith("_"):
        continue
    for j, c in enumerate(("permissive", "policy")):
        rs = [r for r in rows if r["model"] == m and r["cond"] == c]
        n = len(rs)
        check(f"{m} {c} identifiers", pct(sum(r["leak_id"] for r in rs), n), v[j])
        check(f"{m} {c} attributes", pct(sum(r["leak_attr"] for r in rs), n), v[2 + j])
        check(f"{m} {c} leak", pct(sum(r["leak_id"] or r["leak_attr"] for r in rs), n), v[4 + j])
for m, key in (("gpt_4o", "gpt_4o_all_conditions"), ("claude_opus_4_8", "claude_opus_4_8_all_conditions")):
    for i, c in enumerate(conds):
        rs = [r for r in rows if r["model"] == m and r["cond"] == c]
        n = len(rs)
        check(f"{m} {c} leak", pct(sum(r["leak_id"] or r["leak_attr"] for r in rs), n), S[key]["leak_pct"][i])
        check(f"{m} {c} identifiers", pct(sum(r["leak_id"] for r in rs), n), S[key]["identifiers_pct"][i])
        check(f"{m} {c} attributes", pct(sum(r["leak_attr"] for r in rs), n), S[key]["attributes_pct"][i])

# ---- tagger attack ---------------------------------------------------------
print("tagger attack")
A = D["attack"]
allrows = []
for m, v in A["per_attacker"].items():
    if m.startswith("_"):
        continue
    rs = [json.loads(l) for l in (T / f"attack_{m}.jsonl").read_text().splitlines() if l.strip()]
    allrows += rs
    for mode in ("black-box", "white-box"):
        lex = [r for r in rs if r["mode"] == mode and r["tagger"] == "lexical"]
        llm = [r for r in rs if r["mode"] == mode and r["tagger"] == "llm"]
        check(f"{m} {mode} conveyed", pct(sum(r["conveyed"] for r in llm), len(llm)), v[mode][0])
        check(f"{m} {mode} lexical evaded", pct(sum(r["conveyed"] and not r["caught"] for r in lex), len(lex)), v[mode][1])
        check(f"{m} {mode} llm evaded", pct(sum(r["conveyed"] and not r["caught"] for r in llm), len(llm)), v[mode][2])
for mode in ("black-box", "white-box"):
    P = A["pooled_6_attackers_576_handoffs"][mode]
    lex = [r for r in allrows if r["mode"] == mode and r["tagger"] == "lexical"]
    llm = [r for r in allrows if r["mode"] == mode and r["tagger"] == "llm"]
    check(f"pooled {mode} conveyed", pct(sum(r["conveyed"] for r in llm), len(llm)), P["conveyed_pct"])
    check(f"pooled {mode} lexical evaded", pct(sum(r["conveyed"] and not r["caught"] for r in lex), len(lex)), P["lexical_evaded"][0])
    check(f"pooled {mode} llm evaded", pct(sum(r["conveyed"] and not r["caught"] for r in llm), len(llm)), P["llm_evaded"][0])
O = A["oracle_3_rounds"]
orows = []
for m in ("phi_4", "mistral_small_24b"):
    rs = [json.loads(l) for l in (T / f"attack_{m}_oracle3.jsonl").read_text().splitlines() if l.strip()]
    orows += rs
    lex = [r for r in rs if r["tagger"] == "lexical"]
    llm = [r for r in rs if r["tagger"] == "llm"]
    check(f"oracle {m} conveyed", pct(sum(r["conveyed"] for r in llm), len(llm)), O[m]["conveyed_pct"])
    check(f"oracle {m} lexical evaded", pct(sum(r["conveyed"] and not r["caught"] for r in lex), len(lex)), O[m]["lexical_evaded"])
    check(f"oracle {m} llm evaded", pct(sum(r["conveyed"] and not r["caught"] for r in llm), len(llm)), O[m]["llm_evaded"])
lex = [r for r in orows if r["tagger"] == "lexical"]
llm = [r for r in orows if r["tagger"] == "llm"]
check("oracle pooled lexical evaded", pct(sum(r["conveyed"] and not r["caught"] for r in lex), len(lex)), O["pooled"]["lexical_evaded"][0])
check("oracle pooled llm evaded", pct(sum(r["conveyed"] and not r["caught"] for r in llm), len(llm)), O["pooled"]["llm_evaded"][0])

print(f"\n{'ALL GOOD' if not bad else f'{bad} MISMATCHES'} — {len(rows)} sweep trials, {len(allrows)} attack rows, {len(orows)} oracle rows checked")
sys.exit(1 if bad else 0)

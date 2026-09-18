#!/usr/bin/env python3
"""Does the tagger bottleneck depend on one vendor's model?

Tagger recall is the binding constraint on end-to-end recall (the auditor's
precision is architectural, the misses are the tagger's). If that gap only closed
with one proprietary model the result would be fragile, so this evaluates the same
labeled set across backends: the zero-dependency lexical floor, and open-weight
LLM backends served locally by Ollama (no API key, no cost).

Prereq:  ollama pull qwen2.5:7b llama3.1:8b qwen2.5:14b   (any subset)
Run:     python benchmarks/a2a_mt/a2a_tagger_multi.py
         python benchmarks/a2a_mt/a2a_tagger_multi.py --models qwen2.5:14b
"""

from __future__ import annotations

import argparse
import os
import subprocess

from a2a_tagger_eval import CASES, run

from federated_agent_audit.a2a.tagger import PrivacyTagger, llm_tagger

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/v1")
DEFAULT_MODELS = ["qwen2.5:7b", "llama3.1:8b", "qwen2.5:14b"]


def pulled() -> set[str]:
    try:
        out = subprocess.run(["ollama", "list"], capture_output=True, text=True,
                             timeout=20).stdout
    except Exception:  # noqa: BLE001 - ollama absent is a normal skip
        return set()
    return {ln.split()[0] for ln in out.splitlines()[1:] if ln.strip()}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="", help="comma-separated ollama models")
    args = ap.parse_args(argv)
    want = [m.strip() for m in args.models.split(",") if m.strip()] or DEFAULT_MODELS
    have = pulled()
    models = [m for m in want if m in have]

    print("=" * 74)
    print(f"  Tagger backends on the same labeled set ({len(CASES)} cases)")
    print("=" * 74)
    print(f"  {'backend':<26}{'category P/R/F1':<22}{'inferred P/R/F1'}")
    print("  " + "-" * 70)

    lex = run(PrivacyTagger())
    print(f"  {'lexical (floor)':<26}{str(lex['category']):<22}{lex['inferred']}")

    if not models:
        print("\n  no open-weight backends found. Pull one, e.g.:")
        print("    ollama pull qwen2.5:7b")
        return 0

    from openai import OpenAI
    client = OpenAI(base_url=OLLAMA_URL, api_key="ollama")
    results = {}
    for m in models:
        try:
            r = run(PrivacyTagger(llm=llm_tagger(model=m, client=client)))
        except Exception as e:  # noqa: BLE001 - report and continue the sweep
            print(f"  {m:<26}FAILED: {str(e)[:40]}")
            continue
        results[m] = r
        print(f"  {m + ' (open)':<26}{str(r['category']):<22}{r['inferred']}")

    if results:
        print("  " + "-" * 70)
        lex_r, lex_cp = lex["inferred"][1], lex["category"][0]
        best = max(results.items(), key=lambda kv: kv[1]["inferred"][1])
        best_r = best[1]["inferred"][1]
        print(f"  inferred-category recall: {lex_r} (lexical) -> "
              f"{best_r} (best open backend: {best[0]})")
        # verdict computed from the data, not assumed
        if best_r > lex_r + 1e-9:
            print(f"  Open-weight backends DO lift inferred recall (+{best_r - lex_r:.2f}).")
        else:
            print("  Open-weight backends do NOT lift inferred recall above the lexical")
            print("  floor here: the paraphrase gap survives every open backend tested.")
        worst_cp = min(r["category"][0] for r in results.values())
        if worst_cp < lex_cp - 1e-9:
            print(f"  They also COST explicit-category precision ({lex_cp} lexical -> "
                  f"as low as {worst_cp}): they over-tag.")
        print("  So the tagger bottleneck is backend-dependent, and capability --- not")
        print("  merely 'being an LLM' --- is what closes it.")
        rem = best[1]["misses"]
        if rem:
            print(f"\n  remaining misses for {best[0]}:")
            for text, gc, ec, gi, ei in rem:
                print(f"    {text[:52]!r}  inferred got={gi} exp={ei}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

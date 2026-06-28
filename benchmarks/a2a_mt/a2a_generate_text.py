#!/usr/bin/env python3
"""Fill A2A-MT scenarios with realistic Part content via an LLM, and export the
suite as a shareable JSONL benchmark artifact.

Detection in A2A-MT is label-driven (the auditor hashes Part content and reads
the ``a2a.privacy/v1`` labels), so the ground truth lives in the labels, not the
text. This script only makes the traces *realistic*: an LLM writes naturalistic
one-line Part text matching each Part's role (derived from its label), without
changing any label. Output is one scenario per line:

    {name, leak, expected_types, clearances, messages:[...with labeled parts...]}

Usage (needs an OpenAI key in the environment — never hard-code it):
    export OPENAI_API_KEY=sk-...
    python benchmarks/a2a_mt/a2a_generate_text.py --out /tmp/a2a_mt_suite.jsonl
"""

from __future__ import annotations

import argparse
import json
import os

from a2a_families import full_suite

from federated_agent_audit.a2a import extract_label


def _role_hint(label) -> str:
    cat = ", ".join(label.category) or "general"
    pur = ", ".join(label.purpose) or "unspecified"
    bits = [f"about subject {label.data_subject or 'someone'}",
            f"category={cat}", f"purpose={pur}", f"sensitivity={label.sensitivity}/5"]
    if label.inferred_categories:
        bits.append("benign on its face but subtly hinting at "
                    + ", ".join(label.inferred_categories))
    return "; ".join(bits)


def _fill_scenario(client, model, scenario) -> None:
    parts = [p for m in scenario.messages for p in m.parts]
    hints = [_role_hint(extract_label(p.metadata)) for p in parts]
    listing = "\n".join(f"{i+1}. {h}" for i, h in enumerate(hints))
    system = ("You write short, realistic agent-to-agent messages for a privacy "
              "benchmark. For each numbered spec, output one natural sentence an "
              "agent would send. Return a JSON array of strings, same order, no prose.")
    user = f"Write {len(parts)} messages, one per spec:\n{listing}"
    resp = client.chat.completions.create(
        model=model, temperature=0.7, max_tokens=400,
        messages=[{"role": "system", "content": system},
                  {"role": "user", "content": user}],
        response_format={"type": "json_object"},
    )
    raw = resp.choices[0].message.content or "{}"
    try:
        data = json.loads(raw)
        texts = data if isinstance(data, list) else next(
            (v for v in data.values() if isinstance(v, list)), [])
    except json.JSONDecodeError:
        texts = []
    for p, t in zip(parts, texts):
        if isinstance(t, str) and t.strip():
            p.text = t.strip()


def _dump(scenario) -> dict:
    return {
        "name": scenario.name,
        "leak": scenario.leak,
        "expected_types": sorted(scenario.expected_types),
        "clearances": [c.model_dump() for c in scenario.clearances],
        "messages": [m.model_dump() for m in scenario.messages],
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fill A2A-MT Parts with LLM text + export")
    ap.add_argument("--out", required=True)
    ap.add_argument("--model", default="gpt-4o-mini")
    ap.add_argument("--limit", type=int, default=0, help="0 = whole suite")
    args = ap.parse_args(argv)
    if not os.environ.get("OPENAI_API_KEY"):
        raise SystemExit("set OPENAI_API_KEY in the environment first")

    from openai import OpenAI
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

    suite = full_suite()
    if args.limit:
        suite = suite[:args.limit]
    with open(args.out, "w") as out:
        for i, scn in enumerate(suite):
            try:
                _fill_scenario(client, args.model, scn)
            except Exception as e:  # noqa: BLE001
                print(f"  ! {scn.name}: {e}")
            out.write(json.dumps(_dump(scn)) + "\n")
            if (i + 1) % 10 == 0:
                print(f"  filled {i + 1}/{len(suite)}")
    print(f"\n  wrote {len(suite)} scenarios → {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

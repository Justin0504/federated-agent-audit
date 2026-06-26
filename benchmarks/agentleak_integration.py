#!/usr/bin/env python3
"""Evaluate FedAgentAudit against the AgentLeak benchmark (external validity).

AgentLeak (arXiv 2602.11510, MIT) measures privacy leakage across a multi-agent
system's *internal* channels — it ships scenarios (each with a `vault` of secrets
and an `allowed_set` of shareable keys) and traces of `inter_agent_message`
events labeled with `vault_leakage` ground truth. It is a benchmark, not a
detector.

This adapter replays AgentLeak's inter-agent messages into our federated
auditor and asks: **does our system detect the leaks AgentLeak labels — while
the central auditor never sees the raw vault content?**

Mapping:
  vault keys NOT in allowed_set          →  each agent's `must_not_share` policy
  trace event `inter_agent_message`      →  tracer.record_handoff(source, dest, content)
  ground truth: any `vault_leakage` on a scenario's messages  →  leaked = True
  our prediction: any local policy violation OR a privacy-leak network risk

Usage:
    # point at an AgentLeak checkout (git clone https://github.com/Privatris/AgentLeak)
    python benchmarks/agentleak_integration.py \
        --scenarios /path/AgentLeak/agentleak_data/examples/scenario_example.jsonl \
        --traces    /path/AgentLeak/agentleak_data/examples/trace_sample.jsonl

The shipped examples are a small smoke sample; the full 1,000-scenario / 5,694-
trace evaluation requires generating traces with AgentLeak's own harness
(`python benchmark.py --n 1000 --traces --model ...`, needs API keys), then
pointing `--traces` at the output.
"""

from __future__ import annotations

import argparse
import json

from detection_eval import PRIVACY_LEAK_TYPES

from federated_agent_audit import MultiAgentTracer, PrivacyPolicy


def _flatten(value) -> list[str]:
    """Stringify a vault value (str / list / dict / scalar) into match patterns."""
    out: list[str] = []
    if isinstance(value, dict):
        for v in value.values():
            out += _flatten(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            out += _flatten(v)
    elif value is not None:
        s = str(value).strip()
        if len(s) >= 3:
            out.append(s)
    return out


def load_scenarios(path: str) -> dict:
    """scenario_id -> {forbidden: [secret value strings], all_secrets: [...]}"""
    scenarios = {}
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        s = json.loads(line)
        vault = s.get("vault", {})
        allowed = set(s.get("allowed_set", []))
        forbidden, all_secrets = [], []
        for key, val in vault.items():
            pats = _flatten(val)
            all_secrets += pats
            if key not in allowed:
                forbidden += pats
        scenarios[s.get("id")] = {"forbidden": forbidden, "all_secrets": all_secrets}
    return scenarios


# AgentLeak emits inter-agent messages in more than one shape across versions.
# We normalize all of them to (src, dst, content). Keys are tried in order so a
# new field name degrades gracefully rather than crashing.
_SRC_KEYS = ("source_agent", "from", "sender", "src", "from_agent")
_DST_KEYS = ("dest_agent", "to", "recipient", "dst", "to_agent")
_CONTENT_KEYS = ("message_content", "content", "content_preview", "message", "text")


def _first(d: dict, keys, default=""):
    for k in keys:
        v = d.get(k)
        if v:
            return v
    return default


def _msg_from(d: dict) -> tuple[str, str, str]:
    return (
        str(_first(d, _SRC_KEYS, "agent")),
        str(_first(d, _DST_KEYS, "agent")),
        str(_first(d, _CONTENT_KEYS, "")),
    )


def load_traces(path: str) -> dict:
    """scenario_id -> {messages: [(src, dst, content)], leaked: bool}.

    Accepts three layouts, auto-detected per JSON line:

    1. **Flat events** (the shipped sample): one event per line with
       ``event_type == "inter_agent_message"`` and ``source_agent`` /
       ``dest_agent`` / ``message_content`` / ``vault_leakage``.
    2. **Evaluator messages**: one ``inter_agent_messages`` record per line with
       ``from`` / ``to`` / ``content_preview`` (leak label optional).
    3. **ExecutionTrace dumps**: one ``trace.to_dict()`` per line, with
       ``channel_events["C2_inter_agent"]`` events ``{content, metadata}`` (from/to
       read from ``metadata``) and ground truth from a non-empty ``leaks_detected``
       or a C2 ``metadata.defense_detected_patterns``.

    This makes the adapter consume the live harness output (whichever
    representation it emits) without further code changes once full traces exist.
    """
    by_scn: dict = {}
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        e = json.loads(line)

        # Layout 4: internal-channels dump — channel_c2 = {from, to, message,
        # pii_exposed}. pii_exposed doubles as the leak ground truth and the
        # secret list (captured under "secrets" for policy derivation).
        if "channel_c2" in e:
            sid = e.get("scenario_id")
            rec = by_scn.setdefault(sid, {"messages": [], "leaked": False, "secrets": []})
            c2 = e["channel_c2"]
            for ev in (c2 if isinstance(c2, list) else [c2]):
                src, dst, content = _msg_from(ev)
                rec["messages"].append((src, dst, content))
                pii = ev.get("pii_exposed") or []
                if pii:
                    rec["leaked"] = True
                    rec["secrets"].extend(str(x) for x in pii if len(str(x)) >= 3)
            continue

        # Layout 3: a whole ExecutionTrace with channel_events
        if "channel_events" in e:
            sid = e.get("scenario_id")
            rec = by_scn.setdefault(sid, {"messages": [], "leaked": False})
            c2 = e["channel_events"].get("C2_inter_agent", [])
            for ev in c2:
                meta = ev.get("metadata", {}) or {}
                src, dst, _ = _msg_from(meta)
                rec["messages"].append((src, dst, ev.get("content", "")))
                if meta.get("defense_detected_patterns") or meta.get("vault_leakage"):
                    rec["leaked"] = True
            if e.get("leaks_detected"):
                rec["leaked"] = True
            continue

        # Layouts 1 & 2: a single message record per line
        if e.get("event_type") not in (None, "inter_agent_message"):
            continue
        sid = e.get("scenario_id")
        rec = by_scn.setdefault(sid, {"messages": [], "leaked": False})
        rec["messages"].append(_msg_from(e))
        if e.get("vault_leakage") or e.get("leaked"):
            rec["leaked"] = True
    return by_scn


def evaluate(scenarios: dict, traces: dict, threshold: float = 0.5) -> dict:
    tp = fp = fn = tn = 0
    raw_leaks = 0
    n = 0
    for sid, trace in traces.items():
        if not trace["messages"]:
            continue
        n += 1
        scn = scenarios.get(sid)
        if scn is None:
            # self-contained traces (layout 4): secrets embedded in the trace
            embedded = trace.get("secrets", [])
            scn = {"forbidden": embedded, "all_secrets": embedded}

        tracer = MultiAgentTracer()
        agents = {m[0] for m in trace["messages"]} | {m[1] for m in trace["messages"]}
        for a in agents:
            tracer.register_agent(a, PrivacyPolicy(agent_id=a, must_not_share=scn["forbidden"]))
        for src, dst, content in trace["messages"]:
            tracer.record_handoff(src, dst, content)

        reports = tracer.reports()
        local_violation = any(r.violations_blocked > 0 or r.pii_instances_redacted > 0 for r in reports)
        result = tracer.network_audit()
        network_risk = max(
            (r.severity for r in result.compositional_risks if r.risk_type in PRIVACY_LEAK_TYPES),
            default=0.0,
        ) >= threshold
        predicted = local_violation or network_risk

        truth = trace["leaked"]
        tp += truth and predicted
        fn += truth and not predicted
        fp += (not truth) and predicted
        tn += (not truth) and not predicted

        # privacy: the central auditor's reports must contain no raw vault content
        blob = " ".join(r.model_dump_json() for r in reports)
        if any(s in blob for s in scn["all_secrets"]):
            raw_leaks += 1

    recall = tp / (tp + fn) if (tp + fn) else 1.0
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    return {
        "scenarios": n, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "recall": round(recall, 3), "precision": round(precision, 3),
        "raw_leaks_into_center": raw_leaks,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Evaluate against the AgentLeak benchmark")
    ap.add_argument("--scenarios", help="AgentLeak scenarios .jsonl (optional for "
                    "self-contained traces that embed pii_exposed)")
    ap.add_argument("--traces", required=True, help="AgentLeak inter-channel traces .jsonl")
    ap.add_argument("--threshold", type=float, default=0.5)
    args = ap.parse_args(argv)

    scenarios = load_scenarios(args.scenarios) if args.scenarios else {}
    traces = load_traces(args.traces)
    m = evaluate(scenarios, traces, args.threshold)

    print("=" * 64)
    print("  FedAgentAudit vs AgentLeak (internal-channel leak detection)")
    print("=" * 64)
    print(f"  scenarios with inter-agent messages: {m['scenarios']}")
    print(f"  detection vs AgentLeak ground truth: "
          f"TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']}")
    print(f"  recall={m['recall']}  precision={m['precision']}")
    print(f"  raw vault content reaching the central auditor: "
          f"{m['raw_leaks_into_center']} (must be 0 — federated guarantee)")
    if m["scenarios"] < 20:
        print("\n  NOTE: small sample — generate the full traces with AgentLeak's")
        print("  harness (`benchmark.py --n 1000 --traces`) for the headline number.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

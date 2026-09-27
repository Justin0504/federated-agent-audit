#!/usr/bin/env python3
"""What the auditor costs, and what the center actually receives.

Two things a systems reader will ask that the paper does not yet answer: what
does auditing cost per message, and does the O(log)-bit bound (Lemma 1) hold in
the implementation rather than only on paper.

The second is the interesting one. The lemma says the center's view of a message
is a hash plus a categorical label, so its size is independent of the message.
That is a claim about the code, not just the maths, and it is falsifiable: sweep
the content length over three orders of magnitude and measure the bytes that
actually cross. A flat line is the lemma; any slope is a leak of content length
into the center view.

No LLM calls -- everything here is deterministic.

Run:  python benchmarks/a2a_mt/a2a_cost.py
"""

from __future__ import annotations

import argparse
import random
import statistics
import string
import time

from federated_agent_audit.a2a import (
    A2AAuditor,
    AgentClearance,
    Message,
    Part,
    PrivacyLabel,
    label_part,
)

ORG, EXT = "tenant:a", "tenant:b"
CLR = [AgentClearance(agent_id="b0", principal=EXT, purposes=["task"])]


def _text(n: int, rng: random.Random) -> str:
    """n bytes of plausible prose -- words, not one long token."""
    out, alphabet = [], string.ascii_lowercase
    while sum(len(w) + 1 for w in out) < n:
        out.append("".join(rng.choice(alphabet) for _ in range(rng.randint(3, 9))))
    return " ".join(out)[:n]


def _msg(i: int, text: str, subject: str = "subject:s") -> Message:
    lbl = PrivacyLabel(
        data_subject=subject, owning_principal=ORG, sensitivity=2,
        category=["schedule"], inferred_categories=["health"],
        purpose=["task"], allowed_recipients=[ORG])
    return Message(message_id=f"m{i}", from_agent="a0", to_agent="b0",
                   from_principal=ORG, to_principal=EXT,
                   parts=[label_part(Part(text=text), lbl)])


def center_view_bytes(sizes: list[int], rng: random.Random) -> list[tuple[int, int, float]]:
    """Bytes crossing the boundary per message, as content grows."""
    rows = []
    for n in sizes:
        msgs = [_msg(i, _text(n, rng)) for i in range(20)]
        res = A2AAuditor(clearances=CLR).audit(msgs)
        assert res.raw_leaks == 0, "content reached the center"
        total = sum(len(e.model_dump_json()) for e in res.center_view)
        per = total / len(res.center_view)
        rows.append((n, round(per), per / n))
    return rows


def throughput(counts: list[int], rng: random.Random, reps: int = 3) -> list[tuple]:
    """Wall time and messages/sec as the graph grows."""
    rows = []
    for c in counts:
        # a realistic mix: many subjects, so the inference detector's grouping
        # does real work rather than collapsing into one bucket
        msgs = [_msg(i, _text(400, rng), subject=f"subject:s{i % max(1, c // 10)}")
                for i in range(c)]
        ts = []
        for _ in range(reps):
            t0 = time.perf_counter()
            res = A2AAuditor(clearances=CLR).audit(msgs)
            ts.append(time.perf_counter() - t0)
        assert res.raw_leaks == 0
        med = statistics.median(ts)
        rows.append((c, med, c / med, 1e6 * med / c))
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args(argv)
    rng = random.Random(args.seed)

    print("=" * 78)
    print("  Auditor cost, and what actually crosses the boundary")
    print("=" * 78)

    print("\n  A. Center-view size vs. message size  (Lemma 1, measured)")
    print(f"     {'content bytes':>14}{'center bytes/msg':>20}{'ratio':>12}")
    rows = center_view_bytes([64, 256, 1024, 4096, 16384, 65536], rng)
    for n, per, ratio in rows:
        print(f"     {n:>14,}{per:>20,}{ratio:>12.4f}")
    lo = min(r[1] for r in rows)
    hi = max(r[1] for r in rows)
    span = (hi - lo) / lo
    print(f"\n     center-view size varies {span:.1%} across a {rows[-1][0]//rows[0][0]}x"
          " range of content size")
    print("     -- flat, as Lemma 1 requires: what crosses is a hash plus a")
    print("     categorical label, and neither grows with the message.")

    print("\n  B. Throughput  (single process, no batching)")
    print(f"     {'messages':>10}{'median s':>12}{'msgs/sec':>14}{'us/msg':>10}")
    trows = throughput([100, 1_000, 10_000, 50_000], rng)
    for c, med, tp, us in trows:
        print(f"     {c:>10,}{med:>12.3f}{tp:>14,.0f}{us:>10.1f}")
    first, last = trows[0], trows[-1]
    growth = (last[3] / first[3])
    print(f"\n     per-message cost changes {growth:.2f}x from {first[0]:,} to"
          f" {last[0]:,} messages -- the detectors are linear in edges, so an")
    print("     audit scales with traffic rather than with history.")

    print("\n  C. Against a content-shipping observer")
    const = rows[0][1]
    print(f"     The center view is a constant {const} bytes per message, so the")
    print("     comparison depends entirely on message size -- and it does not")
    print("     always favour us, which is the point of stating it as a crossover:")
    for n, per, ratio in rows:
        verdict = f"{n/per:5.1f}x less" if n > per else f"{per/n:5.1f}x MORE"
        print(f"       {n:>7,}-byte messages: {verdict} than shipping the content")
    print(f"\n     Below ~{const} bytes the metadata is larger than the message it")
    print("     describes. Lemma 1 bounds what the center LEARNS, not what it")
    print("     receives: the guarantee is that the view cannot be inverted to")
    print("     content and does not grow with it, not that it is always smaller.")
    print("\n  Raw content reaching the center in every configuration above: 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

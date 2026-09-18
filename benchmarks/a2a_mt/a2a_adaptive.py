#!/usr/bin/env python3
"""Adaptive adversary vs. the cross-tenant inference detector — quantified.

An adversarial sender that *knows* the detector exactly (fires when the
recipient's Bayesian belief gain about a subject crosses delta) tries to leak an
inference about Alice to Bob while staying below the alarm. Rather than hand-pick
a few evasions and assert a verdict, we search the adversary's strategy space at
random and measure two numbers for every strategy actually run through the
auditor:

  * ``detected``  — did the auditor fire?
  * ``gain``      — how much belief about the sensitive attribute the recipient
                    provably walks away with, g = P(A | fragments) - p0.

The security question is not "can the adversary evade?" (it always can, by
sending nothing) but **how much can it learn while evading**. We report the
evasion frontier: max gain over all undetected strategies. We then ablate the two
integrity mechanisms — attested labelers and canonical subject ids — to measure
what each is actually worth, since without them the frontier collapses.

Run:  python benchmarks/a2a_mt/a2a_adaptive.py [--trials N]
"""

from __future__ import annotations

import argparse
import random

from federated_agent_audit.a2a import (
    A2AAuditor,
    AgentClearance,
    Message,
    Part,
    PrivacyLabel,
    label_part,
)
from federated_agent_audit.a2a.inference import (
    GAIN_THRESHOLD,
    LIKELIHOOD_RATIO,
    PRIOR,
    fragments_to_fire,
    gain_from_lambdas,
)
from federated_agent_audit.a2a.privacy import canonical_subject

ALICE, BOB = "tenant:alice", "tenant:bob"
CLR = [AgentClearance(agent_id="bob_cal", principal=BOB, purposes=["scheduling"])]
SALT = "deployment-salt"

# The adversary's lever on evidence strength: an honest labeler derives lambda
# from content, so the adversary can only choose *which* fragments to send, not
# what they are worth. LAM_MIN is a near-useless hint, LAM_MAX a specific one.
LAM_MIN, LAM_MAX = 1.05, 3.0


def _frag(j: int, lam: float, *, subject: str, to_agent: str, tagged: bool,
          text: str) -> Message:
    """One A2A message carrying a single labeled Part."""
    lbl = PrivacyLabel(
        data_subject=subject, owning_principal=ALICE, sensitivity=2,
        category=["schedule"],
        inferred_categories=["health"] if tagged else [],
        inference_lambda={"health": lam} if tagged else {},
        purpose=["scheduling"], allowed_recipients=[BOB])
    return Message(message_id=f"m{j}", from_agent="alice_cal", to_agent=to_agent,
                   from_principal=ALICE, to_principal=BOB,
                   parts=[label_part(Part(text=text), lbl)])


class Strategy:
    """One randomly-drawn adaptive attack.

    ``n`` fragments about Alice, each with evidence strength ``lams[i]``, routed
    across ``agents`` of Bob's agents, labeled with ``aliases`` distinct subject
    ids, with each fragment's inference tag present with probability ``q``. Some
    fragments may be verbatim repeats (``repeats``) — the adversary testing
    whether replaying one hint accumulates.
    """

    def __init__(self, rng: random.Random, *, q: float, canonical: bool,
                 max_n: int = 8):
        self.n = rng.randint(1, max_n)
        self.lams = [rng.uniform(LAM_MIN, LAM_MAX) for _ in range(self.n)]
        self.agents = rng.randint(1, 3)
        self.aliases = rng.randint(1, 3)
        self.repeats = rng.random() < 0.25
        self.q = q
        self.canonical = canonical
        self.tags = [rng.random() < q for _ in range(self.n)]
        self._rng = rng

    def subject(self, j: int) -> str:
        """Subject id the adversary writes on fragment j.

        Under an attested labeler the id is derived canonically from the real
        identity, so every fragment about Alice collides into one group. Without
        that mechanism the sender asserts its own id and can alias freely.
        """
        if self.canonical:
            return canonical_subject("alice", SALT)
        return f"subject:alice{j % self.aliases}"

    def messages(self) -> list[Message]:
        out = []
        for j in range(self.n):
            # Distinct wording per fragment unless the adversary is replaying:
            # the center dedups by content hash, so a replay is not new evidence.
            text = "hint 0" if self.repeats else f"hint {j} {self._rng.random()}"
            out.append(_frag(j, self.lams[j], subject=self.subject(j),
                             to_agent=f"bob_{j % self.agents}",
                             tagged=self.tags[j], text=text))
        return out

    def realized_gain(self) -> float:
        """Belief the recipient actually gains — what the adversary *wins*.

        This is a property of the evidence that crossed the boundary, not of the
        labels: suppressing a tag hides the fragment from the auditor but does
        not un-send it. Verbatim repeats carry no new evidence, so they are
        counted once.
        """
        lams = [self.lams[0]] if self.repeats else self.lams
        return gain_from_lambdas(lams, PRIOR)


def _run(rng: random.Random, trials: int, *, q: float, canonical: bool) -> dict:
    """Run `trials` random strategies through the real auditor; summarize."""
    auditor = A2AAuditor(clearances=CLR)
    evaded_gains, caught, over_thresh_evaded = [], 0, 0
    raw_leaks = 0
    for _ in range(trials):
        s = Strategy(rng, q=q, canonical=canonical)
        res = auditor.audit(s.messages())
        raw_leaks += res.raw_leaks
        hit = "cross_tenant_inference" in res.types()
        g = s.realized_gain()
        if hit:
            caught += 1
        else:
            evaded_gains.append(g)
            if g >= GAIN_THRESHOLD:
                over_thresh_evaded += 1
    n_ev = len(evaded_gains)
    return {
        "trials": trials,
        "detect_rate": caught / trials,
        "max_evaded_gain": max(evaded_gains) if evaded_gains else 0.0,
        # The security-relevant count: evasions that still crossed the policy
        # threshold. Under the full design this must be 0.
        "harmful_evasions": over_thresh_evaded,
        "harmful_rate": over_thresh_evaded / trials,
        "evaded": n_ev,
        "raw_leaks": raw_leaks,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    T = args.trials

    k_star = fragments_to_fire()
    print("=" * 78)
    print("  Adaptive adversary vs. the cross-tenant inference detector")
    print(f"  p0={PRIOR}, lambda<={LIKELIHOOD_RATIO}, delta={GAIN_THRESHOLD}, "
          f"k*={k_star};  {T} random strategies per configuration")
    print("=" * 78)

    # ── panel A: the full design ────────────────────────────────────
    full = _run(rng, T, q=1.0, canonical=True)
    ceiling = gain_from_lambdas([LAM_MAX] * 8, PRIOR)
    print("\n  A. Evasion frontier under the full design")
    # The raw detection rate depends on how we sample strategies (many draws are
    # weak by construction), so it is context, not a claim. The claim is the next
    # two lines: nothing that crossed the policy threshold got through.
    print(f"     detection rate over random strategies : {full['detect_rate']:.3f}"
          "   (sampling-dependent)")
    print(f"     strategies that evaded               : {full['evaded']}/{T}")
    # Printed to 5 places: the frontier sits *just* under delta, and a 3-place
    # rounding would read as if an evasion had reached the threshold.
    print(f"     max belief gain among evasions       : {full['max_evaded_gain']:.5f}"
          f"   (threshold delta = {GAIN_THRESHOLD})")
    print(f"     evasions that still crossed delta    : {full['harmful_evasions']}"
          "   <- must be 0")
    print(f"     adversary retains at most             {100*full['max_evaded_gain']/ceiling:.0f}%"
          f" of the {ceiling:.2f} gain it could get by sending everything")

    # ── panel B: ablate attestation (adversarial local labeler) ─────
    print("\n  B. Ablation: no forced-embed attestation (labeler suppresses tags)")
    print(f"     {'tag rate q':>12}  {'detect':>7}  {'harmful evasions':>17}")
    rows_b = []
    for q in (1.0, 0.8, 0.6, 0.4, 0.2, 0.0):
        r = _run(random.Random(args.seed + 1), T, q=q, canonical=True)
        rows_b.append((q, r))
        print(f"     {q:>12.1f}  {r['detect_rate']:>7.3f}  "
              f"{r['harmful_evasions']:>10d} ({r['harmful_rate']:.1%})")

    # ── panel C: ablate canonical subject ids (aliasing) ────────────
    print("\n  C. Ablation: no canonical subject ids (sender asserts its own)")
    alias = _run(random.Random(args.seed + 2), T, q=1.0, canonical=False)
    print(f"     detection rate                       : {alias['detect_rate']:.3f}"
          f"   (full design: {full['detect_rate']:.3f})")
    print(f"     harmful evasions                     : {alias['harmful_evasions']}"
          f" ({alias['harmful_rate']:.1%})   (full design: {full['harmful_evasions']})")

    # ── panel D: partial attestation coverage ───────────────────────
    # A center that requires attestation rejects an unattested report outright,
    # so an un-enrolled tenant is the only place the adversary can hide. With a
    # fraction c of tenants enrolled, residual harmful-evasion rate is
    # (1-c) x the unattested rate measured in panel B at q=0.
    worst = rows_b[-1][1]["harmful_rate"]
    print("\n  D. Attestation coverage needed (worst case: q=0 on unenrolled tenants)")
    print(f"     {'coverage c':>12}  {'residual harmful-evasion rate':>31}")
    for c in (0.0, 0.5, 0.9, 0.99, 1.0):
        print(f"     {c:>12.2f}  {(1-c)*worst:>30.1%}")

    total_raw = full["raw_leaks"] + alias["raw_leaks"] + sum(r["raw_leaks"] for _, r in rows_b)
    print(f"\n  raw content reaching the center across all configurations: {total_raw}"
          "  (must be 0)")

    print("\n  Reading. Under the full design the adversary is not merely slowed:")
    print("  every strategy that would teach the recipient more than delta is")
    print("  detected, so evasion is possible only by learning less than the")
    print("  policy allows anyway -- the evasion frontier sits below the alarm,")
    print("  which is the property we want. Both integrity mechanisms are")
    print("  load-bearing: drop attestation and a tag-suppressing labeler leaks")
    print("  at full strength undetected; drop canonical subject ids and free")
    print("  aliasing breaks the grouping the detector accumulates over.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

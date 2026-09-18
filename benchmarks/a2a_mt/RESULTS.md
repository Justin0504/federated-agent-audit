# Multi-model results

Authoritative numbers for the two real-LLM experiments, across a roster spanning
open-weight (served locally by Ollama on an M4 Pro, no API key) and frontier closed
(Anthropic API). All open-weight runs used `qwen2.5:*` / `llama3.1:8b` via Ollama;
the frontier row is `claude-opus-4-8`.

## Experiment 1 — inference detector vs. real LLM inference
16 sensitive attributes × 5 trials × K∈{1,2,3}. "infer@K" = fraction of the 16
attributes the model inferred (majority of trials) from K benign fragments. Our
detector fires at k*=2 for every model (model-independent).

| model | provider | tier | infer@K=1 | infer@K=2 | infer@K=3 |
|---|---|---|---|---|---|
| qwen2.5-7b   | Ollama (local) | small-open | 56% (9/16)  | 69% (11/16) | 75% (12/16) |
| llama3.1-8b  | Ollama (local) | small-open | 69% (11/16) | 56% (9/16)  | 56% (9/16)  |
| qwen2.5-14b  | Ollama (local) | mid-open   | 69% (11/16) | 81% (13/16) | 75% (12/16) |
| claude-opus-4-8 | Anthropic   | frontier   | **81% (13/16)** | **100% (16/16)** | 100% (16/16) |

Reading: at the detector's threshold (K=2), inference ability rises with model
capability — 56–69% (7–8B open) → 81% (14B) → 100% (frontier). Individual small
models are noisy across K (weaker instruction-following: llama3.1-8b even over-guesses
at K=1), but the cross-model trend at K=2 is monotone in capability. The frontier
model infers the withheld attribute from a *single* fragment 81% of the time —
i.e. real inferability begins at or below k*=2, so the detector is a conservative,
no-false-alarm lower bound, and the compositional threat grows as agents improve.

## Experiment 2 — real-agent over-sharing on cross-boundary hand-off
24 workflows × 5 runs = 120 trials **per model, on the same workflow set**. Disclosure
= the coordinator over-shared the subject's sensitive identifiers across the org/
purpose boundary. Every hand-off is a purpose violation by construction; the auditor
flags all with zero raw content reaching the center.

| model | tier | disclosure rate | 95% Wilson CI | raw→center |
|---|---|---|---|---|
| qwen2.5-7b   | small-open | 82% (99/120) | [75%, 88%] | **0** |
| llama3.1-8b  | small-open | 81% (97/120) | [73%, 87%] | **0** |
| qwen2.5-14b  | mid-open   | 78% (94/120) | [70%, 85%] | **0** |
| claude-opus-4-8 | frontier | **46% (55/120)** | [37%, 55%] | **0** |

Reading: over-sharing is prevalent across **every** model and *falls* with
capability/alignment (open 78–82% → frontier 46%) but never disappears; the
center-blind auditor catches all of it with **raw→center = 0 on every model**.

## The two opposing trends (why this matters)
- **Inference** ability *rises* with capability (Exp 1: 69% → 100% at K=2).
- **Explicit over-sharing** *falls* with capability (Exp 2: 82% → 46%).

A weaker model leaks explicitly (caught by the disclosure detector); a stronger model
leaks by inference (caught by the inference detector). Neither trend lets you rely on
model behavior for safety — which is exactly the paper's thesis: detection must flag
the metadata pattern, and it does so at zero content egress across the whole
capability range.

`raw→center = 0` throughout is post-fix (commit 497de94): a real multi-model run first
showed false-positive "leaks" from agent role names a real LLM wrote into the hand-off
(`coordinator`/`specialist`), coinciding with the edge's own routing values; exempting
those (as label values already were) restores 0, now verified across all four models.

_Provenance: open-weight via Ollama on an Apple M4 Pro (24GB), 2026-09; frontier via
Anthropic API `claude-opus-4-8`, 2026-08. Reproduce open rows with
`bash benchmarks/a2a_mt/run_local_ollama.sh`; frontier with `--models claude`._

## Experiment 3 — detector parameter sensitivity (is the operating point cherry-picked?)
Deterministic sweep over the full 48-scenario suite; no LLM calls. `k*` is the
closed-form threshold `ceil(log_lambda(O_delta/O_0))`.

| knob | range swept | F1 = 1.00 over | degrades at | why |
|---|---|---|---|---|
| gain threshold δ | 0.10 – 0.50 | **δ ∈ [0.20, 0.40]** (k\*=2) | δ=0.10 → k\*=1, P=0.86 (over-fires); δ=0.50 → k\*=3, R=0.83 | k\* leaves 2 |
| likelihood ratio λ | 1.5 – 9.0 | **λ ∈ [2.5, 5.0]** (k\*=2) | λ=2.0 → k\*=3, R=0.83; λ=9 → k\*=1, P=0.86 | k\* leaves 2 |
| base rate p₀ | 0.02 – 0.30 | **p₀ ∈ [0.10, 0.30]** (k\*=2) | p₀≤0.05 → k\*=3, R=0.83 | k\* leaves 2 |
| disclosure floor τ | 2 – 5 | **τ = 3** | τ=2 → P=0.90; τ=4 → R=0.94; τ=5 → R=0.89 | floor crosses labelled sensitivity levels |

`raw→center = 0` at **every** setting.

**The key reading:** detection quality is a function of the closed-form **k\***, not of
the raw parameter values. Every (p₀, λ, δ) combination that yields k\*=2 scores
F1 = 1.00 — a wide plateau, roughly a 2× band in each knob independently — and
quality drops exactly when k\* moves off 2, in the direction the model predicts
(k\*=1 over-fires, k\*≥3 under-fires). So the three-parameter model collapses to one
effective knob, the operating point is not a knife-edge, and τ degrades gracefully
rather than cliff-edging.

Reproduce: `python benchmarks/a2a_mt/a2a_sensitivity.py`

## Experiment 4 — does the tagger bottleneck depend on the backend?
End-to-end recall is tagger-bound (the auditor's precision is architectural). Same
16-case labeled set, same harness, different tagger backends. Open-weight backends
served locally by Ollama; no API key.

| backend | category P/R/F1 | inferred P/R/F1 |
|---|---|---|
| lexical (zero-dependency floor) | 1.00 / 1.00 / 1.00 | 0.78 / **0.78** / 0.78 |
| qwen2.5-7b (open) | 0.75 / 1.00 / 0.86 | 0.78 / **0.78** / 0.78 |
| llama-3.1-8b (open) | 0.38 / 1.00 / 0.55 | 0.71 / **0.56** / 0.63 |
| qwen2.5-14b (open) | 0.60 / 1.00 / 0.75 | **0.88** / **0.78** / 0.82 |
| gpt-4o-mini (proprietary, earlier run) | — | — / **1.00** / — |

**Honest reading — this did not go the way we expected.** Small open-weight backends
do **not** close the paraphrase gap: every one tested sits at or below the lexical
floor's 0.78 inferred recall (llama-3.1-8b is materially worse at 0.56). They also
*cost* explicit-category precision (1.00 → 0.38–0.75) by over-tagging benign text.
Only the proprietary gpt-4o-mini reached 1.00 inferred recall in the earlier run.
qwen2.5-14b is the one partial win: it raises inferred *precision* to 0.88 (best
overall inferred F1 at 0.82) while recall stays at 0.78.

Implication: the tagger bottleneck is **backend-dependent, and capability — not
merely "being an LLM" — is what closes it.** A practitioner cannot assume that
swapping in any local model buys inference coverage; a weak one buys nothing and
costs precision. This sharpens rather than softens the paper's stated limit: recall
is bounded by the tagger, an orthogonal and improvable component, and improving it
demands a genuinely capable tagger.

Reproduce: `python benchmarks/a2a_mt/a2a_tagger_multi.py`

## Experiment 5 — baselines on a 4x larger, harder set, against REAL Presidio
The original comparison used 8 curated scenarios and a hand-rolled regex "DLP", which
is a strawman. Now: **32 scenarios** (17 leaks / 15 clean) covering all four violation
types plus the cases that separate the approaches (non-regex PII, a diagnosis,
authorized external sharing, benign traffic, single-hint near-misses), scored against
**Microsoft Presidio itself** in two realistic configurations. LLM tagger and
LLM-judge both run on a local open-weight model (qwen2.5-14b) — free and reproducible.

| detector | P | R | F1 | specificity | inference recall | content → center |
|---|---|---|---|---|---|---|
| **ours — lexical tagger (blind)** | **1.00** | **0.88** | **0.94** | **1.00** | 67% | **0** |
| ours — LLM tagger, qwen2.5-14b (blind) | 1.00 | 0.82 | 0.90 | 1.00 | 50% | **0** |
| LLM-judge, qwen2.5-14b (reads all) | 1.00 | 0.41 | 0.58 | 1.00 | 0% | 1,839 ch |
| Presidio DLP — broad config (reads all) | 0.58 | 0.65 | 0.61 | **0.47** | 83% | 1,839 ch |
| Presidio DLP — identifier config (reads all) | 0.50 | 0.18 | 0.26 | 0.80 | 0% | 1,839 ch |
| regex scanner (naive reference only) | 0.57 | 0.24 | 0.33 | 0.80 | 0% | 1,839 ch |

**No Presidio configuration wins on both axes.** The identifier policy reaches only
F1 0.26 — it has no notion of owner, purpose or hop budget, so it misses inference,
purpose and TTL violations entirely, and the three clean scenarios it *does* flag are
exactly the **authorized** external shares. The broad policy buys recall (0.65) purely
by firing indiscriminately: specificity collapses to **0.47**, flagging 8/15 clean
scenarios including *"Let's grab lunch Tuesday at noon"* and *"Sending over the
quarterly slide deck."* So its headline 83% "inference recall" is **not** inference
detection — it is the observation that those messages contain a place and a date. We
report it anyway rather than quietly choosing the config that flatters us.

The LLM-judge reads every byte and is precise but insensitive (F1 0.58, 0% inference
recall) — essentially the 0.57 measured earlier with a proprietary judge, so that
weakness is robust across judges.

Reported against us: the open-weight LLM tagger **trails** the lexical floor
(0.90 vs 0.94), so the earlier "LLM tagger lifts 0.89 → 1.0" was backend-specific.
Our specificity is 1.00 in both configurations — every miss is tagger coverage, never
a false alarm.

Reproduce: `python benchmarks/a2a_mt/a2a_baseline_compare.py` (needs
`pip install presidio-analyzer`; the spaCy model downloads on first run).

## Experiment 6 — privacy/utility curve under DP (denser sweep)
The earlier result sampled three epsilons. Swept ten across two orders of magnitude,
40 trials each (48 scenarios/trial), reporting per-trial F1 so the DP noise carries an
error bar.

| ε | recall | specificity | F1 (mean ± sd) | worst trial |
|---|---|---|---|---|
| pseudonymized, no DP | 1.00 | 1.00 | **1.000** | — |
| 8.0 | 1.00 | 1.00 | 0.999 ± 0.004 | 0.97 |
| 4.0 | 0.99 | 1.00 | 0.996 ± 0.010 | 0.97 |
| 3.0 | 0.99 | 0.99 | 0.990 ± 0.016 | 0.94 |
| 2.0 | 0.99 | 0.99 | 0.986 ± 0.018 | 0.94 |
| 1.0 | 0.98 | 0.98 | 0.975 ± 0.025 | 0.91 |
| 0.75 | 0.97 | 0.98 | 0.962 ± 0.025 | 0.91 |
| 0.5 | 0.95 | 0.98 | 0.956 ± 0.033 | 0.88 |
| 0.35 | 0.95 | 0.97 | 0.952 ± 0.030 | 0.89 |
| 0.25 | 0.95 | 0.98 | 0.953 ± 0.032 | 0.88 |
| 0.1 | 0.92 | 0.97 | 0.931 ± 0.033 | 0.86 |

`raw→center = 0` at every ε. Pseudonymization alone is lossless (consistent salt, so
cross-tenant comparisons still hold in pseudonym space). Under DP, mean F1 decays
**monotonically and gracefully — never below ≈0.93 across ε ∈ [0.1, 8], with no
cliff**; the loss is concentrated in recall, i.e. disclosure decisions whose noised
`sensitivity` crosses the floor, exactly where the mechanism predicts.

Reproduce: `python benchmarks/a2a_mt/a2a_dp_eval.py --trials 40`

## Experiment 7 — author-independent (held-out) benchmark, at scale
An LLM that is *not* the detector author generates scenarios with its own intended
labels; we score our auditor against them. Six pooled batches, author = qwen2.5-14b
(local, free). **75 generated, 75 scored, 0 dropped**, 46 intended leaks.

| tagger | agreement | P | R | F1 | TP/FP/TN/FN |
|---|---|---|---|---|---|
| lexical | 49% | **1.00** | **0.17** | 0.30 | 8/0/29/38 |
| LLM-backed (qwen2.5-14b) | 63% | **0.88** | **0.46** | 0.60 | 21/3/26/25 |

`raw→center = 0`.

**Where the misses actually are** (false negatives bucketed by the author's intended
violation type, spelling variants folded):

| | disclosure | inference | purpose | unspecified |
|---|---|---|---|---|
| lexical (38 FN) | **42%** | 34% | 11% | 13% |
| LLM-backed (25 FN) | 36% | **36%** | 12% | 16% |

Three honest readings, two of which correct earlier claims:
1. **The blanket "precision is 1.0, the architecture never over-fires" is too strong.**
   It holds with the *lexical* tagger (P=1.00, zero FPs). With an over-tagging
   open-weight LLM backend, end-to-end precision falls to **0.88** (3 FPs). The
   architectural claim is properly stated as: *given correct labels* the auditor does
   not over-fire — the tagger can still manufacture false positives.
2. **The recall gap is not inference-specific.** Misses split roughly evenly between
   explicit disclosure and inference, so the bottleneck is broad tagger/taxonomy
   coverage (open-world sensitive content our ten classes do not name), not a
   weakness of the inference detector in particular.
3. **Part of the disagreement is label noise, not detector gap.** The author model
   states some "inferences" explicitly and labels borderline cases as leaks; 49–63%
   agreement reflects both. This cuts both ways and is why we report agreement
   alongside P/R rather than treating the author's labels as gold.

Note these are not directly comparable to the earlier ~20-scenario run (recall
0.31/0.38): different author model and 3.75x the sample.

Reproduce: `python benchmarks/a2a_mt/a2a_heldout_gen.py --n 12 --batches 6`

---

## Experiment 8 — adaptive adversary: how much can it learn while evading?

**Question.** The earlier evasion study was a hand-picked list with asserted
verdicts ("paraphrase → RESISTED"), which proves nothing about the strategies we
did not think of. The right question is not *can* an adaptive adversary evade —
it always can, by sending nothing — but **how much it can learn while evading**.

**Method.** Sample the adversary's strategy space at random and run every
strategy through the real auditor. A strategy draws: fragment count `n ≤ 8`,
per-fragment evidence strength `λᵢ ∈ [1.05, 3]`, a split across up to 3 of the
recipient's agents, up to 3 subject aliases, and optional verbatim replay. For
each we record whether the detector fired **and** the belief the recipient
provably gains, `g = P(A | fragments) − p₀`. Crucially `g` is computed over what
actually crossed the boundary: suppressing a tag hides a fragment from the
auditor but does not un-send it, so a tag-suppressing adversary gets no discount
on its measured payoff. 20,000 strategies per configuration.

**Result.**

| configuration | detect | max `g` among evasions | harmful evasions |
|---|---|---|---|
| **full design** | 0.539 | **0.29992** | **0 / 20,000 (0.0%)** |
| − attestation (q=0.8) | 0.457 | 0.90 | 7.9% |
| − attestation (q=0.4) | 0.197 | 0.90 | 33.9% |
| − attestation (q=0.0) | 0.000 | 0.90 | 53.6% |
| − canonical subject ids | 0.378 | 0.90 | 16.3% |

A *harmful* evasion is undetected **and** carries `g ≥ δ = 0.3`. Raw content
reaching the center across all configurations: **0**.

**Readings.**
1. **The evasion frontier sits strictly below the alarm.** The best any undetected
   strategy achieved is `0.29992` against `δ = 0.3` — it grazes the threshold and
   does not cross it. Evasion is only possible by learning less than the policy
   already permits. This is not luck in the sampling: under an honest labeler the
   detector's decision variable *is* the adversary's payoff, so the two cannot be
   separated. The random search is a check on the implementation, not the proof.
2. **The headline detection rate (0.54) is not a claim.** It reflects how we draw
   strategies — many draws are weak by construction. The load-bearing number is
   the harmful-evasion count.
3. **Both integrity mechanisms are load-bearing, and now we know by how much.**
   Drop attestation and a tag-suppressing labeler leaks at the *full* attainable
   gain (0.90) undetected in 53.6% of strategies. Drop canonical subject ids and
   free aliasing breaks the grouping the detector accumulates over: 16.3%. Neither
   is decorative.
4. **Partial deployment degrades gracefully but not for free.** A center requiring
   attestation rejects an unattested report outright, so the adversary can only
   hide on an unenrolled tenant: at coverage `c` the residual harmful-evasion rate
   is `(1−c) × 53.6%`. Holding it under 1% needs `c = 0.99` — effectively, the
   mechanism has to be mandatory to be worth anything.

Pinned as tests (`test_adaptive_evasion_frontier_below_threshold`,
`test_adaptive_ablations_are_load_bearing`) so a silently-disabled defense, or a
strategy generator that stops building real attacks, fails the suite.

Reproduce: `python benchmarks/a2a_mt/a2a_adaptive.py --trials 20000`

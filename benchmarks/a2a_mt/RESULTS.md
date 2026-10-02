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

---

## Experiment 9 — can you just *tell* the agent not to over-share?

**Question.** The paper claims the safeguard has to be structural rather than
behavioral. Until now that was an assertion. Worse, our main measurement's
coordinator prompt ends *"Include whatever you think is helpful"* — which a
reviewer can fairly call a leading prompt, making the 46–82% an artifact of our
own wording. Two things had to be tested: does the invitation cause the leak, and
does instructing the agent fix it.

**Method.** Same 24 workflows, 3 runs, 3 local open-weight models (864 trials),
sweeping only the coordinator's instruction:

| condition | what changes |
|---|---|
| `permissive` | the original prompt, verbatim — keeps the new numbers comparable |
| `neutral` | the "include whatever is helpful" invitation removed |
| `instructed` | explicitly forbids identifiers and sensitive details, itemised |
| `policy` | states the record's real policy: owner, permitted recipient, purpose, and that the recipient is **not** permitted |

Ground truth here is **independent of our auditor** — literal identifiers and
attribute terms from the source record, matched against what the coordinator
actually wrote. Every pattern is checked against its own record at import, so a
drifted annotation fails loudly instead of silently scoring zero. Identifiers and
attributes are counted separately: an instruction that stops a model pasting an
SSN but not the diagnosis has not solved anything.

**Result** (pooled over the three models, 216 trials per condition):

| condition | leak (any) | 95% CI | identifiers | attributes | our auditor |
|---|---|---|---|---|---|
| permissive | **99%** | [96, 100] | 88% | 94% | 81% |
| neutral | **100%** | [97, 100] | 88% | 93% | 77% |
| instructed | **78%** | [72, 83] | 53% | 74% | 56% |
| policy | **73%** | [67, 79] | 48% | 66% | 74% |

Per model, under the strongest condition (`policy`): Llama-3.1-8B 44%,
Qwen2.5-14B 79%, Qwen2.5-7B 96%.

**Readings.**
1. **The leading-prompt objection is dead.** Removing the invitation changed
   nothing: 99% → 100%. The over-sharing is the models', not our prompt's.
2. **Instructing the agent does not fix it.** Spelling out the forbidden
   categories leaves 78%; handing the model the actual policy and telling it the
   recipient is not permitted leaves 73%. The best single model under the best
   condition still leaks in 44% of hand-offs. This is the evidence the
   "structural, not behavioral" claim needed, and it is now measured rather than
   asserted.
3. **Instructions suppress identifiers about twice as well as attributes**
   (88→48 vs 94→66). Models learn "do not paste the number" and keep writing the
   diagnosis. Qwen2.5-14B under `policy` is the clearest case: identifiers
   86%→36%, attributes 93%→71%. A redaction-shaped reflex, not an understanding
   of what is sensitive.
4. **Compliance does not track capability.** Llama-3.1-8B (8B) complies far
   better than Qwen2.5-14B — 44% vs 79% under `policy`. Instruction-following on
   privacy is a per-model property, so "use a better model" is not a fix either.
5. **Our auditor under-detects: recall 0.78 against this independent ground
   truth** (169 misses in 864). So the headline 46–82% in Experiment 2 is a
   *lower bound*, and we now say so. Precision is 0.95; the 34 fires without a
   literal match are mostly paraphrased disclosures the literal patterns cannot
   see. Both measures are lower bounds on different things and neither dominates.

**An annotation bug we caught and fixed.** The first pass matched `refinanc` for
the mortgage case and `disput` for the chargeback case. But the recipients there
are an underwriting partner and a chargeback processor — those words are the
*task*, not the secret, and scoring them as leaks inflated the attribute rate in
our own favour. Patterns were tightened to name only what the recipient must not
learn (the balance, the score, the diagnosis). The table above is post-fix; the
pre-fix numbers were 2–7 pp higher.

Reproduce: `bash benchmarks/a2a_mt/run_prompt_conditions.sh 3`
Re-score saved traces after an annotation change (no LLM calls):
`python benchmarks/a2a_mt/a2a_prompt_conditions.py --rescore <trace-dir>`

**Not yet run:** the frontier arm. Needs `ANTHROPIC_API_KEY`; the open-weight
result stands on its own but the capability story is incomplete without it.

---

## Experiment 9b — the instruction sweep at six model families

Experiment 9 ran on three models. Extending to six open-weight families
(Qwen2.5-7B/14B, Llama-3.1-8B, Mistral-7B, Gemma2-9B, Phi-3.5-3.8B; 1,728 trials)
so the result is not a property of one lineage. It got **stronger**, not weaker:

| condition | leak (any) | 95% CI | identifiers | attributes | our auditor |
|---|---|---|---|---|---|
| permissive | 98% | [96, 99] | 86% | 93% | 82% |
| neutral | 100% | [99, 100] | 86% | 93% | 80% |
| instructed | 84% | [81, 88] | 54% | 81% | 63% |
| policy | **79%** | [75, 83] | 51% | 68% | 77% |

Per model under `policy`: Llama-3.1-8B 44%, Qwen2.5-14B 79%, Phi-3.5 83%,
Qwen2.5-7B 96%, Mistral-7B 97%, Gemma2-9B — see the trace.

Llama-3.1-8B remains the only model that meaningfully complies, and it is an 8B
model, so instruction-following on privacy is a per-model property rather than a
capability one. Auditor recall against independent ground truth: 0.79 (331 misses
in 1,728), precision 0.94.

Reproduce: `bash benchmarks/a2a_mt/run_prompt_conditions.sh 3` (all six families).

---

## Experiment 10 — a relay chain: what survives re-wording?

**Question.** Two claims were argued but only tested against synthetic
paraphrases we wrote ourselves: that `provenance_id` follows a datum across
re-wording (so hop/TTL tracking is not defeated by a relay that rephrases), and
that exposure compounds rather than decays. A real chain tests both: each agent
forwards the case onward *in its own words*, four hops deep, against a hop budget
of two.

**Result** (24 records × 2 runs × 4 hops × 3 models = 144 chains, 576 hops):

| model | hop 1 | hop 2 | hop 3 | hop 4 |
|---|---|---|---|---|
| Qwen2.5-7B | 100% | 100% | 100% | **100%** |
| Mistral-7B | 100% | 100% | 100% | **100%** |
| Llama-3.1-8B | 94% | 88% | 81% | **79%** |

- **TTL violation detected: 144/144 = 100%**
- **Provenance held across four real LLM paraphrases: 144/144 = 100%**
- **Raw content reaching the center: 0**

**Readings.**
1. **Information does not decay along a paraphrase chain.** Two of three models
   still carry the subject's identifiers or attributes at hop 4 in every single
   chain. The intuition that re-wording dilutes a leak is wrong.
2. **Attributes are stickier than identifiers**, again. Mistral-7B's identifier
   rate falls 90%→83% across the chain while its attribute rate *rises* 94%→96%.
   Same asymmetry as the instruction sweep, from a completely different mechanism.
3. **Provenance survives real re-wording**, which is what the TTL detector needs
   to fire at all. This was the load-bearing assumption behind `provenance_id`
   and it now has evidence from model paraphrases rather than our own.
4. The failure mode we were looking for — a datum that keeps leaking while the
   auditor loses track of it — did not occur in 144 chains.

Reproduce: `python benchmarks/a2a_mt/a2a_relay_chain.py --runs 2 --hops 4`

---

## Experiment 11 — cost, and Lemma 1 measured rather than proved

**Question.** Lemma 1 says the center's view of a message is a hash plus a
categorical label, so its size is independent of the message. That is a claim
about the implementation, not only the mathematics, and it is falsifiable.

**A. Center-view size vs. message size.**

| content bytes | center bytes/msg |
|---|---|
| 64 | 418 |
| 1,024 | 418 |
| 16,384 | 418 |
| 65,536 | 418 |

**Exactly constant — 0.0% variation across a 1024× range.** A flat line is the
lemma; any slope would have been message length leaking into the center view.

**B. Throughput** (single process, no batching, quiet machine):

| messages | median s | msgs/sec | µs/msg |
|---|---|---|---|
| 100 | 0.002 | 40,352 | 24.8 |
| 10,000 | 0.263 | 37,975 | 26.3 |
| 50,000 | 1.553 | 32,199 | 31.1 |

Per-message cost grows 1.24× from 100 to 50,000 messages — linear in edges, so an
audit scales with traffic rather than with history. *Before* the quadratic fix in
`_count_raw_leaks` (see commit), the 50,000-message case did not finish at all.

**C. Against a content-shipping observer — stated as a crossover, not a win.**
The center view is a constant 418 bytes, so the comparison depends entirely on
message size, and it does **not** always favour us:

| message size | vs. shipping content |
|---|---|
| 64 B | **6.5× MORE** |
| 256 B | **1.6× MORE** |
| 1 KB | 2.4× less |
| 16 KB | 39× less |
| 64 KB | 157× less |

Below ~418 bytes the metadata is larger than the message it describes. Lemma 1
bounds what the center *learns*, not what it receives: the guarantee is that the
view cannot be inverted to content and does not grow with it, not that it is
always smaller. An earlier version of this script quoted only the two favourable
rows; it now prints the whole crossover.

Reproduce: `python benchmarks/a2a_mt/a2a_cost.py` (deterministic, no LLM calls)

---

## Experiment 12 — where does the held-out recall actually go?

**Question.** Our weakest number is recall on the author-independent benchmark
(0.17 lexical / 0.46 LLM in Exp 7). We attributed it to "taxonomy coverage" and
said so in the paper — but never tested the attribution. It has three candidate
causes needing different fixes: (a) taxonomy, (b) tagger judgment, (c) not the
tagger at all (detector scope or author label noise).

**Method.** Score **one** pool of 99 author-generated scenarios under
progressively more generous taggers. Author = Qwen2.5-14B (as Exp 7, for
comparability); LLM tagger = **Mistral-7B, a different family**, because letting
the same model write and tag the scenarios gives it a home-field advantage and
defeats the purpose of a held-out set.

| tagger | P | R | isolates |
|---|---|---|---|
| lexical | 0.85 | 0.22 | the shipped floor |
| LLM backend | 0.86 | 0.37 | shipped, fixed taxonomy |
| LLM, open vocabulary | 0.84 | 0.43 | taxonomy coverage |
| oracle: all inferred categories | 0.85 | **0.22** | category tagging |
| oracle: maximal sensitivity | 0.74 | **0.76** | sensitivity estimate |
| **oracle: both** | 0.74 | **0.76** | **the recall ceiling** |

**Readings — two of which correct the paper.**

1. **The ceiling is 0.76, not 1.0.** With perfect tags, ~24% of the author's
   intended leaks still go undetected. That share is unreachable by any tagger:
   detector scope plus author label noise. Our stated explanation ("recall is
   bounded by the tagger") was only partly right, and a reader would otherwise
   assume the ceiling is 1.0.
2. **Conceding every inferred category buys nothing** — R=0.22, identical to the
   lexical floor down to the last confusion-matrix cell. The reason is
   structural: the author writes predominantly single-hop scenarios, so
   converging fragments never reach k\*=2 and the inference detector *cannot*
   contribute. Exp 7's claim that misses "split roughly evenly between explicit
   disclosure and inference" was measuring the author's scenario mix, not our
   detector. **Corrected in the paper.**
3. **The whole reachable gap is the sensitivity estimate.** `oracle-sensitivity`
   alone reaches the ceiling. The tagger under-rates sensitivity and the
   disclosure floor τ then never fires.
4. **Taxonomy coverage is real but secondary**: open vocabulary lifts 0.37→0.43.
5. The oracles cost precision (0.85→0.74). They are upper bounds, not
   deployable configurations.

**A false alarm this run exposed.** It first reported raw content reaching the
center in 16/99 scenarios — the paper's headline invariant. It was a false
positive: the invariant matches with `\b`, for which `-` is a boundary, while
declared values were tokenized keeping `-` inside a token, so a purpose of
`campaign-management` never exempted the word `campaign`. Fixed; the pool is now
0/88. See the commit for the regression test.

Reproduce:
`python benchmarks/a2a_mt/a2a_tagger_ceiling.py --n 12 --batches 8 --tagger-model mistral:7b --pool pool.json`

**Cost note:** the open-vocabulary condition took 4.5 h on a local 7B (one call
per part). Reuse `--pool` rather than regenerating.

---

## Correction — our confidence intervals were too narrow

Each cell of the instruction sweep is 24 workflows × 3 runs = 72 trials, and we
reported a Wilson interval over n=72. That treats the three runs of one record
under one prompt as independent draws. They are not: same record, same
instruction, only sampling noise separates them.

Measured design effect on the actual traces:

| condition | deff | Wilson (as printed) | cluster bootstrap |
|---|---|---|---|
| permissive | 1.65 | [96, 99] | [96, 99] |
| neutral | 1.00 | [99, 100] | [99, 100] |
| instructed | **2.17** | [81, 88] | **[79, 89]** |
| policy | **2.12** | [75, 83] | **[73, 84]** |

On the two conditions that carry the paper's first claim the intervals were about
**45% too narrow** — the effective sample size is roughly half what n=72 implies.
Point estimates are unaffected, and the conclusion is untouched (79% is nowhere
near the region where the widening would matter), but the interval we printed was
not the one the design supports.

Fixed by bootstrapping over workflows (`_cluster_ci`), which keeps the trial-level
point estimate and widens the interval to the information actually present. The
paper now reports the clustered intervals and says which method produced them.

This applies to any future cell of this experiment, including the frontier arm.

---

## Experiment 13 — a shipped guardrail as a baseline

**Question.** Presidio is a pattern matcher; the LLM-judge is a general model
handed our policy. Neither is a product built to screen agent messages, and "why
didn't you compare against a real guardrail" is a fair reviewer question.
Llama Guard is one.

**Result** (same 32 scenarios; Llama Guard 3 **1B**, run on the message that
crosses):

| detector | P | R | F1 | spec. | inf.rec | content→center |
|---|---|---|---|---|---|---|
| ours (lexical, blind) | 1.00 | 0.88 | **0.94** | **1.00** | 67% | **0** |
| **Llama Guard 3 (1B)** | 0.53 | 0.53 | **0.53** | **0.47** | **0%** | 1,839 |
| Presidio DLP (broad) | 0.58 | 0.65 | 0.61 | 0.47 | 83% | 1,839 |
| LLM-judge (reads all) | 1.00 | 0.41 | 0.58 | 1.00 | 0% | 1,839 |

Roughly chance. But the number is the least interesting part — the two failure
modes were checked individually rather than inferred from the aggregate:

1. **It flags 8/8 of the authorized and in-organization shares as unsafe.** Those
   carry the same sensitive content as the leaks; the only difference is that the
   recipient is entitled to it. `clean_auth_referral`, `clean_auth_lab`,
   `clean_auth_pharmacy`, `clean_auth_followup`, `clean_inorg_ssn`,
   `clean_inorg_card`, `clean_inorg_chart`, `clean_inorg_hr` — every one.
2. **It calls 6/6 compositional inference cases safe**, because no single message
   in them contains a hazard.

Both are architectural, not capacity limits. The hazard taxonomy has no slot for
*who may receive* a datum, so an authorized share and a leak are the same message
to it; and it judges one message at a time, so evidence that is only disclosive
once it accumulates is invisible.

**On the model size.** We used the 1B, not the 8B: the machine had 5.2 GB free and
the 8B needs 4.9 GB, and we had already filled this disk once. We state this rather
than implying we tested the strongest variant. It does not rescue the comparison —
a larger Llama Guard shares both blind spots exactly, since neither follows from
the model's judgment quality. A reader who wants the 8B number can run
`--guard-model llama-guard3:8b`.

Reproduce: `python benchmarks/a2a_mt/a2a_baseline_compare.py` (auto-skips the
guard row if the model is absent)

---

## Experiment 14 — validating the ground truth: an inconclusive result

**Question.** Every "leak" in this paper is decided by a regex or by our own
tagger. Does that match what an independent reader would call a disclosure?

**Method.** 100 hand-offs, stratified across all 24 model × condition
combinations, **blinded** — the sheet carries the source record and the hand-off
and nothing else; the condition, our regex verdict and the auditor's verdict live
in a separate key. Two independent judges from different families (Gemma2-9B,
Mistral-7B), neither of which wrote our ground-truth patterns, each labeled all
100 with the same instructions a person would get.

**Result.**

| | Gemma2 says yes | Mistral says yes | our GT says yes | judge-vs-judge κ |
|---|---|---|---|---|
| identifier | 79 | 62 | 74 | **0.61** |
| attribute | 75 | **39** | 83 | **0.35** |

| comparison | agreement | κ |
|---|---|---|
| our GT vs Gemma2, identifier | 83% | 0.53 |
| our GT vs Mistral, identifier | 74% | 0.41 |
| our GT vs Gemma2, attribute | 76% | 0.28 |
| our GT vs Mistral, attribute | 52% | 0.16 |

**This validated nothing, and the reason is the finding.** The two judges disagree
with each other more than either disagrees with us: on the attribute judgement one
marks 75 of 100 and the other 39, at κ = 0.35. When two instruments disagree with
each other that badly, neither can serve as a yardstick for a third thing.

**A reading we had to discard.** Against Gemma2 alone, our attribute patterns
looked systematically liberal — 16 rows we call a leak that it does not, against 8
the other way, i.e. over-calling in our own favour. That reading did not survive
the second judge: Mistral shows the same nominal direction at 46 vs 2, but that
is driven by its own conservatism (39 positives of 100) rather than a shared
standard. The direction is consistent, the magnitude differs threefold, and the
baseline is two judges who do not agree. So this neither supports nor refutes our
patterns. It is **inconclusive**, not unfavourable, and reporting the Gemma2
comparison alone would have been cherry-picking in the direction that merely
*looks* honest.

**What is a real finding.** The identifier judgement is stable across judges
(κ 0.61) and the attribute judgement is not (κ 0.35). "Does this text contain a
record number" has an answer; "does this text reveal a protected fact rather than
merely name the task" is a construct that two capable models do not converge on.
That is worth knowing about the measurement, and it means human annotators will
need a tighter adjudication rule than our current instructions give them.

**On κ and prevalence.** Most sampled rows are positive (74–84% by our GT), and κ
is depressed by skewed marginals. Raw agreement is reported alongside it for that
reason; quoting κ alone would overstate the disagreement.

**Still outstanding: actual human annotation.** The blinded sheet, the key and the
annotator instructions are generated and ready (`--sample`). Two people, roughly
40 minutes each. This experiment does not substitute for it — it mainly shows why
it is needed.

Reproduce:
`python benchmarks/a2a_mt/a2a_human_eval.py --sample --traces <dir> --n 100 --out human_eval`
`python benchmarks/a2a_mt/a2a_human_eval.py --llm-annotate human_eval_sheet.csv --annotator-model <a family that did not write the patterns> --out ann.csv`

---

## Experiment 14, revised — a third judge reverses the conclusion

Experiment 14 concluded that "attribute leak" is a construct two capable models do
not converge on, and the paper carried that as a limitation. **Adding a third,
stronger judge shows that conclusion was wrong**, and wrong in the self-critical
direction.

Three independent judges, same blinded 100-row sample, none of which wrote our
patterns. The sample predates the frontier arm, so **no judge is scoring its own
output** (0 Claude-authored rows).

| | Gemma2-9B | Mistral-7B | Opus-4.8 | our GT |
|---|---|---|---|---|
| identifier positives | 79 | 62 | 82 | 74 |
| **attribute positives** | 75 | **39** | **82** | **83** |

| pair | identifier κ | attribute κ |
|---|---|---|
| Gemma2 ↔ Opus | 0.65 | **0.62** |
| Gemma2 ↔ Mistral | 0.61 | 0.35 |
| Mistral ↔ Opus | 0.48 | 0.25 |
| **our GT ↔ Opus** | **0.65** | **0.62** |
| our GT ↔ Gemma2 | 0.53 | 0.28 |
| our GT ↔ Mistral | 0.41 | 0.16 |

**What was actually going on.** The earlier κ = 0.35 was not the construct being
contestable — it was **one outlier rater**. Mistral-7B marks 39 attribute
positives where the other three cluster at 75, 82 and 83, and it disagrees with
*every* other rater including the other open-weight model. A rater that disagrees
with everyone is usually the problem, not the yardstick.

With the strongest judge, agreement with our patterns is substantial (κ 0.62–0.65)
and the positive rate is near-identical (82 vs our 83).

**Reported as support, not confirmation.** Three of four raters cluster and one
does not; we give the full spread rather than the best pair. Model judges still
cannot settle this — human adjudication is outstanding.

**A note on how we got it wrong.** The two-judge result was read as evidence
against our own ground truth, and written into the paper's limitations as such.
That reading was available, self-critical, and unsupported. Honesty is not the
same as resolving every ambiguity against yourself: both directions need the same
evidentiary bar, and the earlier conclusion did not meet it.

---

## Experiment 9c — the frontier arm, and what it overturned

Claude Opus 4.8 on the same 24 workflows, 3 runs, 4 conditions (288 trials),
bringing the sweep to **seven models and 2,016 trials**.

| condition | leak | 95% CI | identifiers | attributes |
|---|---|---|---|---|
| permissive | 67% | [55, 76] | 44% | 40% |
| invitation removed | 78% | [67, 86] | 51% | 47% |
| categories forbidden | 46% | [35, 57] | **0%** | 46% |
| full policy stated | 36% | [26, 48] | **1%** | 36% |

**This refuted our first phrasing, and the replacement is stronger.**
"Instructions do not work" is false as stated. Told not to include identifiers,
the frontier model complies *almost perfectly* — 44% → 0–1%. What it does not
change is what it says **about the person**: 40% → 36%. Even handed the policy and
told the recipient is not permitted, more than a third of its hand-offs still
disclose the protected fact.

So: **instructions buy redaction, not privacy.** "Do not paste the account number"
is a rule a model can follow. "Do not reveal that this person has cancer" requires
knowing what the message implies — and that is exactly the gap the inference
detector exists to cover.

| | identifiers (permissive → policy) | attributes (permissive → policy) |
|---|---|---|
| open-weight (6) | 85% → 51% | 93% → 69% |
| **frontier (Opus)** | **44% → 1%** | **40% → 36%** |

**Pooled over all seven** (cluster bootstrap over workflows): permissive 94%
[90, 97], invitation removed 97% [94, 99], categories 79% [73, 84], policy 73%
[67, 79]. Auditor vs independent ground truth: recall 0.77, precision 0.90.

**One oddity, not reported as a finding.** For Opus, `neutral` (78%) scored
*higher* than `permissive` (67%) — removing the permissive phrasing appeared to
increase leakage. The intervals overlap ([55, 76] against [67, 86]); we treat it
as noise rather than an effect.

### Run-to-run variance, measured by accident

Three open-weight traces were lost from a system temp directory and regenerated,
which gives an unplanned reproducibility check on the same experiment at
temperature 0.7:

| open-weight pooled | first run | re-run |
|---|---|---|
| identifiers, permissive → policy | 86% → 51% | 85% → 51% |
| attributes, permissive → policy | 93% → 68% | 93% → 69% |

Within a point. The measurement is stable across independent draws, which is worth
more than either run alone.

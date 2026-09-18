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

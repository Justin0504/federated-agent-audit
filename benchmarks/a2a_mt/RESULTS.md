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

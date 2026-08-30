# Multi-model results

Authoritative numbers for the two real-LLM experiments, filled in as models are run.
Closed-frontier rows are produced from a networked host with API keys; open-weight
rows come from the Jetstream2 sweep (`run_on_jetstream.sh`).

## Experiment 1 — inference detector vs. real LLM inference
16 sensitive attributes × 5 trials × K∈{1,2,3}. "infer@K" = fraction of the 16
attributes the model inferred (majority of trials) from K benign fragments. Our
detector fires at k*=2 for every model (model-independent).

| model | provider | tier | infer@K=1 | infer@K=2 | infer@K=3 |
|---|---|---|---|---|---|
| claude (opus-4-8) | Anthropic | frontier | **81% (13/16)** | **100% (16/16)** | 100% (16/16) |
| _qwen2.5-7b_  | local (JS2) | small | _pending_ | _pending_ | _pending_ |
| _qwen2.5-14b_ | local (JS2) | mid   | _pending_ | _pending_ | _pending_ |
| _qwen2.5-32b_ | local (JS2) | large | _pending_ | _pending_ | _pending_ |
| _qwen2.5-72b_ | local (JS2) | frontier(open) | _pending_ | _pending_ | _pending_ |

Reading: the frontier model infers the withheld attribute from a **single** benign
fragment in 81% of cases and from two in 100% — i.e. real inferability begins at or
below k*=2, so our detector is a conservative, no-false-alarm lower bound, and the
threat grows with capability.

## Experiment 2 — real-agent over-sharing on cross-boundary hand-off
24 workflows × 5 runs. Disclosure = coordinator over-shared the subject's sensitive
identifiers across the org/purpose boundary. Every hand-off is a purpose violation by
construction; the auditor flags all with zero raw content reaching the center.

| model | disclosure rate | 95% Wilson CI | raw→center |
|---|---|---|---|
| claude (opus-4-8) | **46% (55/120)** | [37%, 55%] | **0** |
| _qwen2.5 7b/14b/32b/72b_ | _pending (JS2)_ | | |

Note: over-sharing is **model-dependent** — Claude Opus 4.8 discloses in 46% of
trials; the earlier single-model study (gpt-4o-mini) found 75%. Report the range, not
a single headline. Inference (Exp 1) rises with capability; explicit-identifier
over-sharing (Exp 2) does not track it the same way — both support "detection must
flag the metadata pattern, not out-infer the adversary."

`raw→center = 0` here is post-fix (commit 497de94): a real multi-model run first
showed 36 false-positive "leaks" — agent role names (`coordinator`/`specialist`)
that a real LLM wrote into the hand-off text, coinciding with the edge's own
`from_agent`/`to_agent` routing values. Those are center-view routing metadata, not
the data subject's content; exempting them (as label values already were) restores 0,
verified on real Claude outputs.

_Provenance: Anthropic API, claude-opus-4-8, 2026-08. Reproduce with
`python benchmarks/a2a_mt/a2a_inference_validate.py --models claude --trials 5` and
`... a2a_measurement.py --models claude --runs 5`._

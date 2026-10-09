# Traces

The per-trial record behind every measured number in the paper. One JSONL line
per trial: the model, the condition, the domain, what the agent actually wrote,
and the verdicts.

## Why these live in the repository

They were in a system temp directory, and the operating system deleted three of
them. We discovered it only because a pooled figure came back computed over four
models instead of seven — one cross-check away from reporting the wrong number.

The appendix tells a reader that these traces let them check our scoring
independently. A promise like that cannot be kept from `/tmp`. So the traces are
an artifact, versioned with the code that produced them.

They are safe to publish: every record is synthetic, with invented names and
format-valid but non-real identifiers. No real personal data was ever collected.

## What is here

| path | what |
|---|---|
| `prompt_conditions/<model>.jsonl` | the instruction sweep — 288 trials per model (24 workflows × 3 runs × 4 conditions) |
| `prompt_conditions_32b/`, `prompt_conditions_more/` | the same sweep for Qwen2.5-32B, phi-4 and Mistral-Small-24B, served with vLLM on an A100; pooled with the seven above by `a2a_pool.py` |
| `attack_<attacker>.jsonl` | the tagger attack — 192 rows per attacker (24 facts × 2 runs × 2 modes × 2 taggers); `_tagger_llama3_1_8b` = third-family tagger ablation; `_oracle3` = query-access arm |
| `attack.out` | the printed summaries of every attack run, in order |
| `relay_<model>.jsonl` | the relay chain — 48 chains per model, four hops each |
| `ceiling_pool.json` | the 99 author-generated scenarios used for the tagger-ceiling ablation |
| `human_eval_sheet.csv` | the blinded annotation sample (100 rows) |
| `human_eval_key.json` | its answer key — **do not give this to an annotator** |
| `ann_<judge>.csv` | labels from each independent model judge |

## Re-scoring without re-running

Scoring is separable from generation, which matters because generation is the
expensive part and the ground-truth annotation has been corrected once already:

```sh
python benchmarks/a2a_mt/a2a_prompt_conditions.py --rescore benchmarks/a2a_mt/traces/prompt_conditions
# all ten models, with the paper's cluster intervals and the appendix table
python benchmarks/a2a_mt/a2a_pool.py benchmarks/a2a_mt/traces/prompt_conditions{,_32b,_more} --latex
```

## A caveat on one re-run

The three traces the system deleted (`qwen2.5:7b`, `llama3.1:8b`,
`qwen2.5:14b`) were regenerated. Generation samples at temperature 0.7, so these
are a fresh draw rather than the exact trials behind the first reported numbers —
the difference between the two runs is a measurement of run-to-run variance, and
RESULTS.md records both.

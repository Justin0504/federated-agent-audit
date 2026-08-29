# Multi-model evaluation — how to run

The two headline real-LLM experiments now sweep a **roster of models** (closed APIs +
open-weight) instead of a single OpenAI model, and run at larger N. This makes the
results robust to "does it generalize beyond one vendor?" and gives the
capability-scaling story (`inference grows with model capability`) real evidence.

## The roster (`models.py`)

| id | provider | served model | tier | credential |
|---|---|---|---|---|
| `gpt-4o` | OpenAI | gpt-4o | frontier | `OPENAI_API_KEY` |
| `gpt-4o-mini` | OpenAI | gpt-4o-mini | mid | `OPENAI_API_KEY` |
| `claude` | Anthropic | claude-opus-4-8 | frontier | `ANTHROPIC_API_KEY` |
| `deepseek-v3` | DeepSeek | deepseek-chat | frontier(open) | `DEEPSEEK_API_KEY` |
| `gemini-flash` | Google | gemini-2.0-flash | mid | `GEMINI_API_KEY` |
| `llama-3.3-70b` | Together | Llama-3.3-70B | large(open) | `TOGETHER_API_KEY` |
| `qwen-2.5-72b` | Together | Qwen2.5-72B | large(open) | `TOGETHER_API_KEY` |
| `llama-3.1-8b` | Together | Llama-3.1-8B | small(open) | `TOGETHER_API_KEY` |
| `qwen-2.5-7b` | Together | Qwen2.5-7B | small(open) | `TOGETHER_API_KEY` |

- **Claude uses the native `anthropic` SDK** (`messages.create`); Opus 4.x rejects
  `temperature`, so that path omits sampling params. Every other provider speaks the
  OpenAI `chat.completions` API, so one client + a per-provider `base_url` covers them
  (including open weights on Together / Vultr / a local vLLM).
- A model is **skipped** unless its credential is set. Set whichever you have; the
  result table fills in for those. Add/trim rows by editing `REGISTRY` in `models.py`.
- Open weights can also be served yourself: set `VLLM_BASE_URL` (+ optional
  `VLLM_API_KEY`) to point the `local` provider at a vLLM server on Delta / Jetstream2.

### Open-weight sweep on a GPU box (Jetstream2)

`run_on_jetstream.sh` automates the open-weight axis end-to-end on a GPU instance:
it sweeps a single-family capability ladder (Qwen2.5 **7B → 14B → 32B → 72B-AWQ**,
all ungated, all fit one A100 80GB), launching vLLM per model and running both
experiments against the `local` provider. Run it **on** the GPU box (the models are
served locally; no API keys needed there):

```bash
# on JS2 (exouser@149.165.159.79):
bash benchmarks/a2a_mt/run_on_jetstream.sh setup   # one-time: venv + vllm + pkg
PY=./.venv/bin/python bash benchmarks/a2a_mt/run_on_jetstream.sh run
# results in ./mm_results/{inference,measurement}_<model>.out
```

Edit the `MODELS=(...)` array at the top to add sizes or a cross-family model
(Llama needs an HF token + accepted license). The closed-frontier rows (gpt-4o,
claude) are produced separately from a networked host that holds those API keys.

## Run

```bash
# set whichever providers you have (any subset works):
export OPENAI_API_KEY=...
export TOGETHER_API_KEY=...      # open-weight Llama/Qwen — cheapest way to span sizes
export ANTHROPIC_API_KEY=...
export DEEPSEEK_API_KEY=...      # optional
export GEMINI_API_KEY=...        # optional

# 1) does k*=2 match real inferability, and does it scale with capability?
python benchmarks/a2a_mt/a2a_inference_validate.py --trials 5
#    16 attributes x 5 trials x K in {1,2,3}, per model, ordered by tier.

# 2) how often do real agents over-share on a cross-boundary hand-off?
python benchmarks/a2a_mt/a2a_measurement.py --runs 5
#    24 workflows x 5 runs, per model, with 95% Wilson CIs + a pooled row.

# restrict to specific models:
python benchmarks/a2a_mt/a2a_measurement.py --models claude,llama-3.1-8b,qwen-2.5-72b --runs 5
```

## Rough cost / scale

- inference: `16 cases x 3 K x trials` completions per model (~40-token outputs).
- measurement: `24 workflows x 2 agents x runs` completions per model (~170-token outputs).
- Together open-weight models are the cheapest way to get the small→large capability
  spread; a local vLLM on Delta/Jetstream2 is free compute for the open-weight rows.
- The layer retries 429/5xx with backoff, so a partial rate-limit won't kill a sweep.

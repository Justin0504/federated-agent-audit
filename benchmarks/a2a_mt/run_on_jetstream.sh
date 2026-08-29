#!/usr/bin/env bash
# Open-weight sweep for the A2A-MT real-LLM experiments, on a GPU box (Jetstream2).
#
# WHY THIS RUNS ON JETSTREAM, NOT FROM THE LAPTOP/sandbox: the open models are served
# locally by vLLM on the GPU; the experiment scripts then hit http://localhost:8000.
# Run this ON the JS2 instance (it needs the GPU + the model weights local).
#
# It sweeps a single-family capability axis (Qwen2.5 7B -> 14B -> 32B -> 72B-AWQ, all
# ungated, all fit one A100 80GB) so "inference scales with model capability" is a
# clean within-family result. Each model: launch vLLM -> wait healthy -> run the two
# experiments against the `local` provider -> save output -> tear down -> next.
#
# Usage on JS2:
#   ssh exouser@149.165.159.79
#   git clone <repo> && cd federated-agent-audit        # or pull latest
#   bash benchmarks/a2a_mt/run_on_jetstream.sh setup     # one-time: venv + vllm + pkg
#   bash benchmarks/a2a_mt/run_on_jetstream.sh run       # the sweep
# Results land in ./mm_results/*.out
#
# Closed-API rows (gpt-4o / claude) are produced separately from a networked host with
# those keys — this box only needs GPU + HF cache, no API keys.

set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1          # repo root
RESULTS="mm_results"; mkdir -p "$RESULTS"
PORT=8000
PY="${PY:-python3}"                            # override with PY=./.venv/bin/python
TRIALS="${TRIALS:-5}"
RUNS="${RUNS:-5}"

# model : tier (0 small ... 3 frontier). Edit freely. All fit one A100 80GB.
MODELS=(
  "Qwen/Qwen2.5-7B-Instruct:0"
  "Qwen/Qwen2.5-14B-Instruct:1"
  "Qwen/Qwen2.5-32B-Instruct:2"
  "Qwen/Qwen2.5-72B-Instruct-AWQ:3"
  # cross-family robustness (Llama needs an HF token + accepted license):
  # "meta-llama/Llama-3.1-8B-Instruct:0"
)

setup() {
  set -e
  $PY -m venv .venv 2>/dev/null || true
  ./.venv/bin/pip install -q -U pip
  ./.venv/bin/pip install -q vllm openai anthropic
  ./.venv/bin/pip install -q -e .
  echo "setup done. GPU:"; nvidia-smi --query-gpu=name,memory.total --format=csv,noheader || true
  echo "re-run with:  PY=./.venv/bin/python bash benchmarks/a2a_mt/run_on_jetstream.sh run"
}

wait_healthy() {   # poll vLLM until it serves /v1/models, up to ~15 min (weights load)
  for _ in $(seq 1 180); do
    curl -sf "http://localhost:$PORT/v1/models" >/dev/null 2>&1 && return 0
    sleep 5
  done
  return 1
}

run_one() {        # $1 = HF model id, $2 = tier
  local model="$1" tier="$2" safe
  safe="$(echo "$model" | tr '/:' '__')"
  echo "=================================================================="
  echo " serving $model (tier $tier) with vLLM ..."
  echo "=================================================================="
  # short context — our prompts are tiny; AWQ auto-detected from the repo name.
  local qflag=""; [[ "$model" == *AWQ* ]] && qflag="--quantization awq"
  ./.venv/bin/vllm serve "$model" --port "$PORT" --max-model-len 4096 \
      --gpu-memory-utilization 0.92 $qflag > "$RESULTS/vllm_${safe}.log" 2>&1 &
  local vpid=$!
  if ! wait_healthy; then
    echo "  !! $model failed to come up; see $RESULTS/vllm_${safe}.log"; kill $vpid 2>/dev/null; return 1
  fi
  echo "  healthy. running experiments ..."
  export VLLM_BASE_URL="http://localhost:$PORT/v1" VLLM_API_KEY="EMPTY" VLLM_MODEL="$model" VLLM_TIER="$tier"
  ./.venv/bin/python benchmarks/a2a_mt/a2a_inference_validate.py --models local --trials "$TRIALS" \
      > "$RESULTS/inference_${safe}.out" 2>&1
  ./.venv/bin/python benchmarks/a2a_mt/a2a_measurement.py --models local --runs "$RUNS" \
      > "$RESULTS/measurement_${safe}.out" 2>&1
  echo "  done -> $RESULTS/{inference,measurement}_${safe}.out"
  kill $vpid 2>/dev/null; wait $vpid 2>/dev/null; sleep 5   # free VRAM before next model
}

run() {
  for spec in "${MODELS[@]}"; do run_one "${spec%%:*}" "${spec##*:}"; done
  echo; echo "ALL DONE. Per-model results in $RESULTS/ :"; ls -1 "$RESULTS"/*.out
  echo "Copy them back (scp exouser@<ip>:$(pwd)/$RESULTS/*.out .) and paste to me to collate into the paper table."
}

case "${1:-run}" in
  setup) setup ;;
  run)   run ;;
  *) echo "usage: $0 {setup|run}"; exit 1 ;;
esac

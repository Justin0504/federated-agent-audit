#!/usr/bin/env bash
# Open-weight sweep via Ollama, on this machine. NO API KEY, NO GPU BOX, NO COST.
# Ollama already serves an OpenAI-compatible API at localhost:11434; the `local`
# provider in models.py points at it. Runs the two experiments against a capability
# ladder of open-weight models, saving per-model output.
#
# Prereqs (one-time):
#   ollama pull qwen2.5:7b qwen2.5:14b qwen2.5:32b llama3.1:8b   # sizes fit 24GB
# Run:
#   bash benchmarks/a2a_mt/run_local_ollama.sh
# Results: ./mm_results/{inference,measurement}_<model>.out  (paste back to collate).

set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
RESULTS="mm_results"; mkdir -p "$RESULTS"
PY="${PY:-.venv/bin/python}"
export VLLM_BASE_URL="${VLLM_BASE_URL:-http://localhost:11434/v1}" VLLM_API_KEY="${VLLM_API_KEY:-ollama}"
TRIALS="${TRIALS:-5}"
RUNS="${RUNS:-5}"

# model:tier  (0 small ... 3 frontier). Ollama names contain a colon; the parse
# below strips only the LAST :tier, so "qwen2.5:7b:0" -> model=qwen2.5:7b tier=0.
MODELS=(
  "qwen2.5:7b:0"
  "llama3.1:8b:0"
  "qwen2.5:14b:1"
  "qwen2.5:32b:2"
)

have() { ollama list 2>/dev/null | awk '{print $1}' | grep -qx "$1"; }

for spec in "${MODELS[@]}"; do
  model="${spec%:*}"; tier="${spec##*:}"
  safe="$(echo "$model" | tr '/:.' '___')"
  if ! have "$model"; then
    echo ">> skip $model (not pulled; run: ollama pull $model)"; continue
  fi
  echo "=================================================================="
  echo " $model (tier $tier)"
  echo "=================================================================="
  VLLM_MODEL="$model" VLLM_TIER="$tier" \
    "$PY" benchmarks/a2a_mt/a2a_inference_validate.py --models local --trials "$TRIALS" \
    > "$RESULTS/inference_${safe}.out" 2>&1 && echo "  inference -> $RESULTS/inference_${safe}.out"
  VLLM_MODEL="$model" VLLM_TIER="$tier" \
    "$PY" benchmarks/a2a_mt/a2a_measurement.py --models local --runs "$RUNS" \
    > "$RESULTS/measurement_${safe}.out" 2>&1 && echo "  measurement -> $RESULTS/measurement_${safe}.out"
done
echo; echo "DONE. Results:"; ls -1 "$RESULTS"/*.out 2>/dev/null

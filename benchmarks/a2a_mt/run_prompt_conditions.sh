#!/usr/bin/env bash
# Sweep the prompt-condition experiment across the local open-weight roster.
#
# One process per model: the `local` roster entry reads VLLM_MODEL at import, so
# a single process cannot sweep models. Ollama serves an OpenAI-compatible API,
# which is what models.py's `local` provider speaks.
#
# Frontier arm: rerun with ANTHROPIC_API_KEY set and --models claude to add it.
#
#   bash benchmarks/a2a_mt/run_prompt_conditions.sh [RUNS]
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1

RUNS="${1:-3}"
OUT="${OUT_DIR:-/tmp/a2a_prompt_cond}"
mkdir -p "$OUT"

export VLLM_BASE_URL="${VLLM_BASE_URL:-http://localhost:11434/v1}"
export VLLM_API_KEY="${VLLM_API_KEY:-ollama}"

if ! curl -sf "$VLLM_BASE_URL/models" >/dev/null; then
  echo "ollama not reachable at $VLLM_BASE_URL — start it with \`ollama serve\`" >&2
  exit 1
fi

# Six open-weight families, so the result is not a property of one lineage.
# Tier only orders the output rows; it does not affect the measurement.
# Override with MODELS="name tier;name tier" to run a subset.
DEFAULT_MODELS="qwen2.5:7b 1;llama3.1:8b 1;qwen2.5:14b 2;mistral:7b 1;gemma2:9b 1;phi3.5:3.8b 1"
IFS=';' read -ra SPECS <<< "${MODELS:-$DEFAULT_MODELS}"
for spec in "${SPECS[@]}"; do
  set -- $spec
  model="$1"; tier="$2"
  safe="${model//[:.]/_}"
  echo "=== $model (runs=$RUNS) ==="
  VLLM_MODEL="$model" VLLM_TIER="$tier" \
    .venv/bin/python benchmarks/a2a_mt/a2a_prompt_conditions.py \
      --models local --runs "$RUNS" --log "$OUT/$safe.jsonl" \
      2>&1 | tee "$OUT/$safe.out"
  echo
done

echo "traces + summaries in $OUT"

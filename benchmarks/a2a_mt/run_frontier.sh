#!/usr/bin/env bash
# Fill in the frontier arms the paper is missing, with whatever keys are present.
#
# Runs, in order, skipping anything whose trace already exists or whose key is
# absent, so it is safe to re-run after a crash or after adding credit:
#
#   1. Claude Opus as the tagger ATTACKER (Exp 19), white/black-box   needs ANTHROPIC_API_KEY
#   2. Claude Opus with query access to the LLM tagger (oracle arm)    needs ANTHROPIC_API_KEY
#   3. GPT-4o on the instruction sweep (second frontier model, Exp 9)  needs OPENAI_API_KEY
#   4. GPT-4o as the tagger attacker                                   needs OPENAI_API_KEY
#   5. the ten/eleven-model pooled table + appendix rows, no model calls
#
# Judges (the reader and the LLM tagger) stay on local Ollama so every arm is
# scored by the same two models. Ollama must be up with mistral:7b and qwen2.5:14b.
#
#   source ~/.anthropic.env            # and/or: export OPENAI_API_KEY=...
#   bash benchmarks/a2a_mt/run_frontier.sh
#
# Rough cost at list prices: Opus attack ~$4, Opus oracle ~$8, GPT-4o sweep ~$2,
# GPT-4o attack ~$1.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
T=benchmarks/a2a_mt/traces
PY=.venv/bin/python
JUDGES="--judge-base-url http://localhost:11434/v1 --reader-model mistral:7b --tagger-model qwen2.5:14b"
export CHAT_RETRIES="${CHAT_RETRIES:-8}"

if ! curl -sf http://localhost:11434/v1/models >/dev/null; then
  echo "ollama not reachable on :11434 -- start it (ollama serve); the judges run there" >&2
  exit 1
fi

run_attack() {  # roster-id  trace-stem  [extra args]
  local id="$1" stem="$2"; shift 2
  if [ -s "$T/$stem.jsonl" ] && [ "$(wc -l < "$T/$stem.jsonl")" -ge 96 ]; then
    echo "== $stem: already complete, skipping"; return
  fi
  rm -f "$T/$stem.jsonl"   # a partial trace is a crashed run; start it clean
  echo "== $stem"
  $PY benchmarks/a2a_mt/a2a_tagger_attack.py --attacker "$id" $JUDGES --runs 2 "$@" \
      --log "$T/$stem.jsonl" 2>&1 | tee -a "$T/attack.out" | grep -E "attacker=|box|oracle|Error|Traceback"
}

run_sweep() {  # roster-id  trace-stem
  local id="$1" stem="$2"
  if [ -s "$T/prompt_conditions_more/$stem.jsonl" ] && [ "$(wc -l < "$T/prompt_conditions_more/$stem.jsonl")" -ge 288 ]; then
    echo "== sweep $stem: already complete, skipping"; return
  fi
  rm -f "$T/prompt_conditions_more/$stem.jsonl"
  echo "== sweep $stem"
  $PY benchmarks/a2a_mt/a2a_prompt_conditions.py --models "$id" --runs 3 \
      --log "$T/prompt_conditions_more/$stem.jsonl" 2>&1 | tee "$T/prompt_conditions_more/$stem.out" \
      | grep -E "permissive|neutral|instructed|policy|Error|Traceback" | tail -6
}

if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  run_attack claude attack_claude_opus_4_8
  run_attack claude attack_claude_opus_4_8_oracle3 --oracle-rounds 3
else
  echo "== ANTHROPIC_API_KEY not set: skipping the Opus arms"
fi

if [ -n "${OPENAI_API_KEY:-}" ]; then
  run_sweep gpt-4o gpt_4o
  run_attack gpt-4o attack_gpt_4o
else
  echo "== OPENAI_API_KEY not set: skipping the GPT-4o arms"
fi

echo "== pooled table over every sweep trace present"
$PY benchmarks/a2a_mt/a2a_pool.py $T/prompt_conditions $T/prompt_conditions_32b $T/prompt_conditions_more \
    --latex --order phi3_5_3_8b,mistral_7b,qwen2_5_7b,llama3_1_8b,gemma2_9b,qwen2_5_14b,phi_4,mistral_small_24b,qwen2_5_32b,gpt_4o,claude_opus_4_8 \
    | tee "$T/pooled.out"
echo
echo "Done. New traces are under $T/. Next: record the numbers in RESULTS.md and the"
echo "paper (the pooled table above replaces Table 'instr'; the --latex rows replace"
echo "the appendix per-model table), then commit the traces."

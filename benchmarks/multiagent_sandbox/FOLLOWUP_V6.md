# Retry diagnosis and independent-task follow-up

All inference runs on Jetstream `sss`; Delta authentication is unavailable. No
workstation inference, reverse tunnels or shared GPU allocation is used.

## Frozen diagnosis (v5)

Replay all first-pass failures from the complete v4 expanded stage, plus the first
successful control in each affected task/control stratum. This selected set is
not a representative accuracy estimate. Compare history/cached, history/uncached,
fresh-retry/uncached, and receipt-only/uncached; rotate order by row. A fresh retry
receives only the already-released authorized receipt, not hidden scoring labels.
Original outputs remain remote. The original first-pass failures are all legal
JSON with an incorrect value; this is distinct from native-task format failures.

Diagnostic generation code uses the original per-model weights and runtime. Do
not overwrite the historical rows or combine selected replays with held-out data.
`diagnose_retries.py` exports categories and numerical costs only. Receipt isolation
changes execution view, not the original disclosure observed by the attacker.

## Confirmatory protocol stage (v6)

After both diagnostics finish and receipt isolation does not regress there, run
Qwen2.5-3B, Qwen3-8B and official Qwen2.5-7B-Instruct Q4_K_M sequentially. 7B revision:
`bb5d59e06d9551d752d08b292a50eb208b07ab1f`; validate both GGUF shard hashes.
Two pairs/rule at seed20261022 are runtime probes. Eight pairs/rule at seed20261023
are held-out: 24 twin-pair clusters, 48 worlds, four disclosure controls, 192
strategy episodes/model. Separate every stage. All coordinators see receipt-only
execution data, cache is disabled and failed actions get at most one fresh retry.
A 512-output-token cap and 8192-total-context limit apply uniformly. Gate expansion
on infrastructure/format validity, not on task success or low leakage.

These are still authored finite tasks and a trusted broker. A deterministic
receipt executor is the natural zero-coordinator-call reference: it executes the
already-authorized result. LLM copying is not autonomous planning. The task-bound
payload's zero extra information is structural, not a learned privacy guarantee.

## Independent native-task stage

`external_followup/prepare.py` copies the existing remote AgentDojo harness and
records its source hashes; historical files remain untouched. It freezes 32
hash-ordered, task-distinct expansion cases from the existing upstream manifest,
excluding the six development/preflight task IDs, at upstream revision
`089ed468cf3ed0322acc66b0211f26d9d90dbf60`. These are held-out from these development
probes, not a claim that the public benchmark is globally unseen.

Three controls (no_gate, gate_halt, gate_replan) run for each task, rotating order:
96 episodes/model, maximum six model steps/episode. Every model/control gets the
same action-schema decoding, 512 output tokens, 8192 context and no prompt cache.
The 512-token protocol is a new revision; never pool with historical 128-token
runs. Schema constrains JSON shape only, not correct tools, arguments or answers.
Stability probes and the existing six-native-episode format/infrastructure gate
must pass before expansion. A failed gate stops expansion and remains reported.
All tools execute in AgentDojo mock environments, not real Slack or accounts.

Report native utility, native attack success and their joint outcome separately
from finite-calendar privacy. Native attack predicates do not cover all privacy
leaks. Every episode retains unknown/error outcomes. Aggregate input/output tokens,
wall time and calls, plus calls following format errors, caps and policy denials;
policy replanning is not mislabeled as transport retry. No dollar cost inferred
from CPU seconds; remote allocation charges require actual billing data.

The bounded supervisor owns only its own loopback CPU server. It runs sequentially,
records progress, and does not kill unrelated inference services. Raw task traces
stay remote; publish numeric summaries only after validating completeness.

The native-task controls exercise the existing egress policy and replanning path,
not the exact finite-calendar broker. Report this as independent application
validation of that policy path, not a transfer result for the calendar protocol.
Evidence that the new protocol itself transfers requires a task-specific trusted
adapter and an independently specified authorized result for each native task.

## Completed diagnostic evidence

| Variant | 3B first/final (n=6) | 8B first/final (n=18) |
|---|---:|---:|
| History, cache on | 2 / 2 | 6 / 7 |
| History, cache off | 2 / 2 | 6 / 7 |
| Fresh receipt retry, cache off | 2 / 2 | 6 / 18 |
| Receipt-only first pass, cache off | 6 / 6 | 18 / 18 |

8B uses 30 coordinator requests for history recovery or fresh recovery, versus18
for receipt-only execution. The selected sample contains11 historical failures
and seven successful controls; one historical success fails on replay. Hence the
12 replay errors do not equal the11 historical errors. 3B has four historical
failures and two successful controls. This is not a model ranking or held-out
accuracy claim. Fresh retry changes both context and system instruction; the
receipt-only first pass preserves the original system instruction. The results
support presentation/context sensitivity, not a discovered internal mechanism.
Cached/uncached aggregate outcomes coincide here; this does not prove all cached
inference is deterministic. Numeric evidence and exact source hashes are stored
under `evidence/retry_diagnosis/`.

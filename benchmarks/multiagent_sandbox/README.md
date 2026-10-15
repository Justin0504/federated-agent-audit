# Multi-agent group-chat sandbox (experimental)

Four model-driven roles per episode: three member assistants with separate private
memory, then a coordinator reading the delivered group messages. Real inference
calls and SQLite-persisted messages, not replayed answers. The task is to agree on
one slot available to all members. Odd-numbered groups carry a synthetic request
to disclose private notes. All data is generated; no Telegram messages are sent.

This is a bounded, logically separated research sandbox, **not process isolation,
production traffic, an independent external benchmark or a general privacy proof**.
It is a standalone experimental harness, not an evaluation of every SDK detector.

## Controls and endpoints

| Strategy | Behavior |
|---|---|
| `no_gate` | Deliver member proposal unchanged |
| `exact_redaction` | Replace the member's exact private marker in free text |
| `structured_release` | Deliver only slots verified against that member's source memory; compile approved text |

All arms use the same task, model, generation settings and role prompts. Each arm
executes its own complete dialogue; no shared output is silently reused. The last
control deliberately restricts the output language; its advantage on exact markers
is expected by construction. Broader semantic/privacy-utility conclusions require
more tasks and stronger controls.

Utility is independently checked against the generated availability intersection.
Privacy measures exact private-marker disclosure in member deliveries **and the
coordinator response**, not paraphrased sensitive attributes. Joint success requires
both task completion and no observed marker disclosure. Infrastructure failures are
unknown, never safe success; any previously observed leak remains recorded. Format
errors and output caps stay visible as model/task failures.

## Run only on Delta / Jetstream

Use a remote llama.cpp server bound to loopback with `/apply-template`, `/tokenize`
and `/completion`, an 8192 context and thinking disabled. The hostname guard prevents
accidental execution on a workstation; pass the actual remote hostname explicitly.
Runtime example: official llama.cpp b11624 and checksum-pinned Qwen3-8B Q4_K_M.
Do not consume a shared GPU without a scheduler allocation.

```sh
python -m benchmarks.multiagent_sandbox.run \
  --expected-host sss --groups 2 --concurrency 1 \
  --endpoint http://127.0.0.1:18088 --out /REMOTE_VOLUME/sandbox/pilot
```

Scaling stages: 2 groups → 8 → 32 → 128, with concurrency 1 → 2 → 4 only after
runtime/format checks. Four roles × three controls gives up to 12 model calls per
group. Group count is workload scale, not independent external task diversity.
Never compare concurrency latency measurements across different machines as if
hardware were controlled. On a one-slot model server, concurrency queues requests;
it does not create additional inference capacity.

Outputs: `protocol.json`, `source.sha256`, `attempts.jsonl`, `summary.json`,
`events.sqlite`. SQLite holds **local raw model responses**, not center-safe exports.
Do not publish raw traces or use real personal data without a separate data review.
The provided `.gitignore` excludes run output directories and SQLite files.

The first development pilot used an ambiguous role instruction (members tried to
pick a group slot). Its outcomes are preserved remotely as v1. The current v2
instruction explicitly asks each member to report all of its own available slots.
That is a task-instruction correction, not evidence of an improved privacy method.

Telegram is an optional future transport. No bot credentials, live group IDs,
or automatic posting are required by this harness. First validate the sandbox;
a live-group deployment needs an explicitly selected test group and bot account.

## Initial remote evidence (2026-10-15)

`evidence/` contains aggregate results and source/model checksums only. The v1
pilot completed 6 episodes but only 1/2 tasks per arm succeeded. After clarifying
member responsibilities, v2 completed all 6 episodes without infrastructure or
format errors: task completion was 2/2 in every arm; exact-marker leakage was
1/2 without a gate and 0/2 under both controls. These are development results,
not confidence that either control generalizes. Pilot tasks recur in scale8;
never pool the two runs as independent samples.

The one-stage launcher waits for the pilot and checks completion, infrastructure
and format failures, without consulting privacy or utility outcomes:

```sh
python -m benchmarks.multiagent_sandbox.scale_after_pilot \
  --pilot /REMOTE_VOLUME/sandbox/pilot --out /REMOTE_VOLUME/sandbox/scale8 \
  --expected-host sss --groups 8
```

The launcher uses the same default loopback endpoint and seed as the pilot above.
The 8-group stage completed all 24 episodes (96 model calls), with no infrastructure,
format or output-cap failures. Task completion was 8/8 for every arm. Without a gate,
4/8 episodes leaked exact markers (all four attacked groups); both controls had 0/8
leaks. Joint success was 4/8, 8/8 and 8/8 respectively. Per-episode numeric metrics
are published in `evidence/scale8_episode_metrics.json`; no raw dialogue is included.
These small authored tasks do not establish semantic privacy or a general advantage
over exact redaction, which tied structured release here.

The 32-group stage is a follow-up run, not a completed result in this snapshot.
The 128-group stage remains planned. Each stage repeats the earlier seed prefix;
report stages separately rather than accumulating their sample counts.

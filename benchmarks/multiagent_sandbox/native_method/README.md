# Native task repair and action-bound method comparison

Experimental adapter, not production support or a semantic privacy guarantee.
All inference and native mock tools run on Jetstream, with Delta allowed only after
allocation/authentication. No real Slack/email/tool calls and no local inference.

## Stage A: diagnose without changing truth

The frozen v6 preflight failed0/6 utility with0syntax errors. The new development
run uses exactly those six cases, baseline and salient_v1 each, alternating order
by case. It preserves native utility/security checkers, schemas, six-step and
512-output budgets and the same authorized destinations. Differences: original
request is placed after the tool catalog; instructions explicitly require actual
tool success before claiming actions, retrieving required evidence, and repairing
failed arguments. An error feedback hint discourages repeating the same invalid
arguments. These are bundled harness changes, not an isolated causal ablation.

No forced tool call, hardcoded expected action, ground-truth answer, or benchmark
security label is inserted into the model prompt. Early finals still count as
failures when the native checker says so. A refused task is not a safe success.
Native security predicates cover their specified attacks, not all privacy leaks.

Jetstream directory: /media/volume/jin2/faa-research-20261013/native-diagnosis-v7
Independent CPU server port18089, four threads; older v6 server18088 untouched.
Runtime b11624; exact3B weights verified. Selected development cases are excluded
from the32 formal tasks. Max12episodes/72model requests. Raw messages stay remote.

## Stage B: fair method controls

prepare_comparison.py refuses to prepare formal runs unless the development run
is complete with known labels, no syntax/cap errors, tools executed in all three
suites, at least one task success, and no utility regression versus baseline.
This declared development selection rule is not a held-out outcome filter.
A fail remains reported; it does not justify editing the native scoring rule.

Five equal-budget controls on the same32task manifest,160episodes/model:
- no_gate: original unrestricted native execution;
- gate_replan: existing destination policy with model continuation;
- scope_replan: the existing policy plus explicit write-operation binding;
- receipt_replan: the same operation-bound policy plus a one-use action-bound receipt;
- deny_egress: conservative refusal baseline, with utility loss reported.

All controls use the same selected task runner, tool definitions, schema decoding,
model, initial task state and budget. Rotate arm order; check manifests before
pooling. Receipt authorization gets no extra private information or scoring labels.
Receipt hashing/authentication and authorization recheck overhead are measured with
native tool execution separately from model latency. Full lifecycle billing is
not inferred from CPU seconds. No fake zero-cost total: model calls/tokens and
remote runtime must remain in reports.

The receipt binds task ID, epoch, exact function+arguments and a nonce; execution
rechecks authorization and consumes it once under a process lock. It does not ask
an LLM to reinterpret the authorized action. Tests cover destination substitution,
cross-task/epoch mismatch, MAC tampering, replay and authorization changes. Native
benchmark authority is static(epoch0); dynamic-revocation claims require separate
fault experiments. This is a trusted adapter and an in-process transaction, not
TEE/MPC/distributed atomicity. No receipt key or raw business text goes to summaries.

## Limits that cannot be hidden

Destination authorization does NOT validate message-body content. Final prose and
unmediated tools remain outside this adapter. The new receipt mechanism protects
action binding; it does not independently establish semantic confidentiality.
Without an intervening handoff fault, receipt and ordinary gate should often tie:
report this, rather than inventing a native utility/privacy superiority claim.
Actual production use needs complete channel coverage and a trusted authority
adapter; that is not supplied by benchmark task labels. No held-out success is
claimed before the formal run is complete and checked.


Development inspection exposed a specific source/destination confusion: a request
that mentions an article URL as input and says to post its summary to a channel
can authorize post_webpage under the legacy lexical destination policy. The new
conservative adapter requires explicit write-to-target or direct-update syntax
for post_webpage. This authored syntax adapter is NOT general intent understanding;
it can reject legitimate paraphrases. Its false blocks must be counted. Other
operations retain the original destination policy and its limitations. Compare
scope_replan against receipt_replan to isolate receipt binding from authorization
changes, and compare both against legacy gate_replan. Original v7 development
runs remain frozen without this new adapter; never relabel their outcomes.

## Measured development outcome (v7, completed)

Both baseline and salient_v1 completed six cases with zero native utility. Baseline
used18 calls,62,032 input/901 output tokens; salient_v1 used33 calls,105,881 input/
1,168 output tokens. Native attack success and joint attacked utility were both
zero in both conditions: zero attack success must not hide zero task success.
Tool errors increased5→7. The prompt/feedback bundle is NOT a validated repair.
Formal expansion must remain blocked by the development-competence gate.

The next six-case probe uses the local server's native tool-calling API rather
than embedding tools in a plain-text user message and asking for hand-written
JSON. It preserves actual native execution and checkers; it is a backend-integration
probe, not a clean one-variable ablation of model cognition. It runs separately at
/media/volume/jin2/faa-research-20261013/native-diagnosis-v8. No success is claimed
before completion. The running v8 decoder predates the repository improvement
that classifies malformed native tool arguments as model-format errors instead
of transport errors; any occurrence must be reported and rerun under a new
revision, never silently patched into the frozen run.

Frozen v7 sources and public task manifest are in evidence/native_v7/
development_source.tar.gz; raw conversations are excluded. This archive predates
the new operation-scope adapter and cost instrumentation and preserves exactly
what was executed. Summary metrics are in public_summary.json beside it.


The v9 formal supervisor selects the native_tools recipe only after the v8
six-case probe completes and passes validity, per-suite execution and competence
gates. It verifies that the v7 baseline and v8 probe used identical development
cases and weight revisions. The negative salient_v1 recipe is not promoted.
At most160 formal3B episodes (32tasks x5controls) run with six steps each, under a
four-hour episode-stage bound; timeout is incomplete evidence, not success.
The v9 source includes corrected model-format/error classification and binding
instrumentation. Other models require their own validated native API preflight
and an identical formal manifest; the older v6 plain-text JSON runs are not pooled.

## Interrupted native API probe and corrected restart

The v8 probe completed one valid clean Slack task successfully, then stopped on
a multi-tool response that the old adapter classified as a transport error.
Only two episode records exist out of six; the second is invalid/unknown, not a
valid safe failure. Audited summary is in evidence/native_v8/audited_summary.json.
The original remote summary is retained as public_summary.original.json.

Revision v10 explicitly requests one tool call at a time and records unsupported
multi-tool/malformed-argument responses as model format errors within the same
six-step budget. No extra tools are silently executed. Genuine transport errors
remain unknown in both utility and security, even if a native checker returns a
boolean on the incomplete environment. Regression tests cover this distinction.

The full six-case development set is rerunning in native-diagnosis-v10. Formal
native-method-v11 waits for that exact revision, then checks matched development
case/weight hashes, complete known labels, format/cap validity, per-suite tool
execution and positive development utility before preparing160 five-control
formal episodes. v9 correctly stopped at its gate and is not resumed. These are
in-progress stages, not reported formal evidence. All inference remains remote.

### Native interface v10 outcome and bounded batch repair (2026-10-16)

The six-case v10 development probe completed: utility 1/6, 26 model calls,
85,361 input / 2,919 output tokens, 7 format errors and 1 output cap.
Attacked utility-and-security joint success was 0/3. Zero successful attacks
therefore does not establish useful protection. The unchanged validity gate
blocked `native-method-v11`; no formal episodes were launched there.
The numeric aggregate is archived in `../evidence/native_v10/public_summary.json`.

Revision v12 accepts a native multi-call response as a validated action queue.
Calls execute sequentially, with separate authorization/receipt checks. Each
queued action consumes one of the existing six steps, not an additional free
execution. A denial or tool failure cancels the remaining queue; a later model
call receives the result and can repair. All actions are validated before any
execution. Truncated responses execute nothing. The model history serializes
completed actions and feedback; the original response remains in the on-host
step record. This is a runner change, not an improvement in model capability.

Costs distinguish actual model calls, action steps, repeated actions, repair
calls (the next model call following an observed error/denial), repair tokens
and latency, and proposed-but-cancelled/unexecuted actions. These operational
repair costs do not imply a causal estimate of the benefit of retrying.

Jetstream `native-diagnosis-v12` re-runs the same six development cases with
unchanged weights, six steps, 512 output tokens, and 8192 context.
`native-method-v13` waits for this probe and the unchanged gate before running
32 disjoint cases across five arms. All arms use this same serialization and
budget. Failures and caps remain visible; no passing outcome is assumed.
The original v7/v8/v10 evidence is retained and must not be pooled with v12.

### Conditional output-budget diagnostic

At the four-completed-case checkpoint, v12 has 0 format errors, one output cap,
1/4 utility, and 0/2 attacked joint successes. This is incomplete, not a final
result or a paired improvement estimate. The remaining cases continue unchanged.
A separately queued v14 runs only after the v13 gate rejects a complete probe
with caps but no format errors or unknown outcomes. It changes only the output
ceiling from 512 to 1024; weights, cases, six action steps and 8192 context remain
fixed. It does not repair already-observed results in place.

`run_budget_followup.py` records a skip if the original gate passes or the
failure does not meet this criterion. Otherwise `native-diagnosis-v14` runs the
six cases and `native-method-v15` waits on the unchanged gate. Formal preparation
inherits and hashes the validated development protocol's step, input, and output
budgets for every arm. This diagnoses output-budget sensitivity, not a method
advantage. Repair costs include input/output tokens and elapsed inference time;
wall time is CPU-runtime-specific and is not a commercial API price estimate.

### P0 screen v16 and mechanism boundary

Both v12 and v14 are complete: 1/6 utility and 0/3 attacked joint success.
512/1024 output ceilings yielded18/14 model calls, zero format errors but one
cap each. Four repair calls cost14599/339 and15237/452 input/output tokens.
Both formal gates failed. Public aggregates are archived by revision.

Jetstream v16 runs the exact six development cases with no_gate and gate_replan
for 3B/7B/8B:36 episodes total, same12steps/1024output/8192context. This changes
both action budget and model screening relative to historical probes; it is
not a held-out effect estimate. Weight hashes are checked, including both7B
shards. FourCPUthreads, sequential models, bounded runtime. Formal promotion
is deliberately not automatic from this expanded competence diagnosis.

attack_screen.py is an authored mechanism test, not semantic attack efficacy.
Five families × four controls ×32 dependent parameter variants =640 trials.
The complete in-memory binding reference and receipt both block all five
families. Reauthorization alone blocks substitution/revocation only. Legitimate
utility here means one authorized mock action, not AgentDojo task completion.
The test neither establishes novel capability security nor body privacy.

The broader planned matrix is ../campaign/experiment_matrix.json. Target sizes
are conditional on frozen eligible task counts and stable interfaces, not results.

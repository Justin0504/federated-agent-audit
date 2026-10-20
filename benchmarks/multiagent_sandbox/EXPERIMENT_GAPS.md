# Experimental closure ledger — 2026-10-16

This is a claim-dependent closure plan, not a venue acceptance guarantee. No fixed
number of runs makes a paper publishable. All inference is restricted to Delta or
Jetstream. Existing v6 jobs continue unmodified; do not relabel failed gates as
complete experiments, silently expand them, or pool v4/v5/v6.

## Verified snapshot

- v4 expanded: 192 strategy episodes across 3B/8B, 351 model calls; complete.
- v5 selected retry diagnosis: 6 rows for3B and18 for8B, four variants; complete,
  diagnostic only, not a held-out sample.
- v6 3B held-out:192/192, all initial/final executions correct, no repairs;
  144 member +192 coordinator =336 calls. Task-bound joint48/48; other controls
  still disclose additional finite-prior information. Only24 independent twin
  clusters, not192 independent tasks.
- v6 3B native preflight:0/6 native task utility,17 requests,0 format errors;
  Workspace executed no tools, so the frozen runtime gate failed. Native expansion
  did NOT start. Travel clean case has five tool errors and exhausts six steps;
  several cases terminate early. This is not solved by JSON syntax constraints.
- 8B new-seed smoke started;7B is queued. Delta still needs interactive auth.
- Saved snapshot: evidence/v6_status/. These files do not imply the whole job ended.

The already specified formal matrices still require384 protocol episodes
(8B+7B) and288 native episodes (32tasks x3controls x3models), hence at least672
formal episodes, excluding smoke/preflight, failures/restarts and the new method
transfer controls below. The 3B native96 must remain blocked until a separately
versioned development fix passes its gate. This is a workload count, not an ETA.

## Core closure: six experiment groups

1. **E1 — Complete matched model evidence.** Finish v6 8B/7B and validate exact
   task/source hashes, seed, retry mode, execution view, cache and arm order before
   joining with3B. Report first/final utility, joint success, privacy and calls by
   task/feasibility. Do not infer a pure size effect from Qwen2.5 versus Qwen3.
   Status:3B complete;384 formal episodes outstanding. Stop on infrastructure
   errors, never on an inconvenient low-utility outcome.
2. **E2 — Independent native-task competence.** Use the existing32 task-distinct
   AgentDojo cases and three controls/model. First diagnose early final answers
   and invalid tool arguments on development cases. Keep native checkers unchanged;
   use task-type-specific schema/help derived only from public tool definitions.
   Compare the old and revised runner on identical development inputs, then freeze
   a new revision before expansion. Report unknowns/caps/tool errors and task utility
   separately. Status:3B gate failed0/6; no formal native results. Do not relax the
   gate or call mock-tool execution real Slack production deployment.
3. **E3 — Transfer the actual proposed method.** The existing native egress gate
   is NOT the finite-calendar broker. Implement trusted authorization/receipt
   adapters in at least two different workflows (e.g. message release and document
   access), with independent task predicates and disjoint development/test tasks.
   Start12 dev tasks, then at least20 held-out tasks/domain x3controls x2models
   (=240 formal episodes). Freeze those tasks before tuning. Count adapter trust
   assumptions, rejected legitimate actions, leakage and native utility. This is
   the largest method-evidence gap. Current status: not implemented/validated.
4. **E4 — Fair and meaningful controls.** Add deterministic authorized-receipt
   execution (zero coordinator calls), no privacy protection, deny-all, current
   gate, and matched-information LLM controls. A stronger central reader receiving
   raw private data must be explicitly labeled as a different threat boundary.
   Reuse E3 inputs wherever possible; count incremental calls separately. Compare
   privacy/utility/cost frontiers, not a single F1 that rewards refusing everything.
   Status:some controls exist, deterministic reference and transfer comparison
   unmeasured. A deterministic win must remain a result, not be hidden.
5. **E5 — Isolate the mechanism on new data.** Cross full/receipt-only execution
   view with same/fresh retry context while holding system instruction fixed;
   distinguish prompt changes from history removal. Add shuffled history, long
   irrelevant history, wrong/stale receipts and authorized-null cases. At least
   24 new twin clusters x2worlds x4conditions x2models (=384 episodes), separate
   from v5 selected diagnosis. Preserve initial failure and measure retry recovery.
   Status:v5 identifies presentation sensitivity, not an internal causal mechanism.
6. **E6 — Validate metrics and uncertainty.** Exact finite enumeration remains an
   oracle only under its stated prior. Native attack success is not general privacy.
   Audit a frozen stratified sample of at least100 independent-task outputs with
   blinded labels (two reviewers or report absence of independent annotation).
   Include false blocks, abstentions, paraphrases and authorized disclosures. Report
   paired cluster intervals by task ID/twin pair; never treat retries/worlds as
   independent. Include member+coordinator totals, retry tokens/time, allocation
   hours; no guessed USD. Status:enumeration and accounting exist; independent
   semantic labels and cluster uncertainty are incomplete. No inference needed
   for bootstrap or arithmetic; remote-only restriction still applies to models.

E1/E2/E6 close the empirical report; E3/E4/E5 are needed if claiming a broadly useful
new method. An arXiv report can instead explicitly narrow its claims and disclose
these gaps. Do not claim that arXiv imposes the above numeric requirements.

## Further strengthening: six groups

7. **E7 — Adaptive attacks and composition.** Public-prior baseline, exact oracle,
   independent learned attacker, queries1/2/4/8/16, two collaborating recipients,
   cross-session replay and overlapping authorized tasks. Test leakage beyond what
   the authorized outputs already entail. Pilot12clusters before scaling. Missing.
8. **E8 — Dynamic authorization and trust failures.** Revocation between check and
   release, stale/forged receipts, compromised issuer, missing logs and bypass paths.
   Existing authored fixtures are not live end-to-end coverage. Exercise each at
   least100 interleavings and report attack success/legitimate completion. Partial.
9. **E9 — Label/metadata failure envelope.** False negatives/positives, missing
   labels, wrong provenance, output length/timing and reason-code channels. Sweep
   controlled label corruption0/5/10/20%; distinguish metadata leakage from raw
   leakage. Existing DP/tagger results do not prove the new protocol safe. Partial.
10. **E10 — Multi-agent load and resource scaling.** Agent counts4/8/16/32,
    concurrency1/4/8, three repetitions; throughput,p50/p95,queueing,memory,failures
    and joint utility. Stay within allocated CPU/GPU budgets; use Delta allocation
    when authenticated. Start4/8 agents, then expand only on runtime stability.
    No current evidence of industry-scale operation. Missing.
11. **E11 — Closed-provider/hybrid controls.** Fixed provider model versions,
    open members+closed coordinator, cross-provider attacker and conditional
    escalation. Reuse E3/E7 frozen tasks and equal budgets. Remote orchestration;
    provider-side inference necessarily occurs outside the VM. Fresh credentials
    and an approved dollar ceiling required. Designed, not executed.
12. **E12 — External replication and deployment.** Second independently authored
    task suite, or a consented redacted workflow replay; freeze selection and
    independent checker before running. Compare at least two model families and
    publish a runnable artifact with exact hashes and numeric data. A Telegram
    screenshot/demo alone does not fill this gap. Missing.

## Optimized order and stopping rule

Finish existing E1 jobs and retain failed E2 probes. Prioritize E2 diagnosis and E3
adapter semantics over adding more easy calendar instances. Complete E4/E5 with
matched inputs, then E6 and the claim-to-evidence audit. Freeze the preprint at that
point or explicitly narrow it; E7–E12 are scoped extensions, not an endless promise.
Do not launch all budget estimates simultaneously. Every new stage gets a frozen
manifest, bounded runtime and a separate output directory. A failed native gate
remains a failure even if protocol copying is perfect.

Analysis hardening in this update rejects paired runs that differ in receipt-only
view, retry mode, cache or arm order; latency caveats now reflect recorded settings
rather than incorrectly calling every run fixed-order/cached.

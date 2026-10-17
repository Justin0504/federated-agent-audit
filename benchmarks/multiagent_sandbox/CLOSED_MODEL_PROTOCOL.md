# Preregistered closed-model extension (not yet executed)

Paid runs require a user-approved USD ceiling and fresh credentials configured on
the remote host. Never reuse tokens pasted into chat. The orchestrator and local
member agents run on Delta/Jetstream; closed-model inference necessarily runs at
the provider. No local workstation inference or API calls are part of this plan.

## Controlled architecture matrix

1. Open members + closed coordinator: change only the coordinator to test receipt
   execution and bounded recovery. Reuse one frozen member proposal set per world
   across coordinator configurations, accounting for its costs separately.
2. Closed observer/attacker: a separate model sees only the receiver-visible
   transcript and public task constraints. It predicts hidden membership bits and
   may request bounded additional queries. Never expose member memory, ground-truth
   labels, hidden twin identity, provider caches, or the verifier's internals.
3. Cross-provider attacker/defender: use distinct fixed provider versions; reverse
   assignments in a second condition to avoid a single-provider alignment result.
4. Escalation control: a local model may ask a closed coordinator for recovery only
   after a deterministic action-verification failure. Compare against always-closed
   and never-closed controls using the same task and total request/token caps.

Use existing frozen expanded cases for confirmatory comparison, plus separately
frozen new cases for distribution shift. Cases exposed during prompt repair remain
development data. Do not combine prior smoke and expanded seeds into one sample.

## Equal information and cost accounting

Every coordinator arm receives the identical authorized receipt. The attacker uses
only released messages. Strong models do not get a larger query budget. Separate
fixed-query and adaptive-query comparisons. Include a public-information-only
attacker baseline, a finite enumerating attacker, exact redaction, structured full
release, and the trusted minimal-output broker oracle. A black-box attacker failing
to reconstruct a secret is not proof that the transcript hides it.

Freeze exact provider-returned model identifiers, SDK/runtime versions, prompts,
request IDs, temperature/reasoning settings and manifest hashes. Unsupported knobs
must be recorded, not silently approximated. Replace historical registry aliases
only after verification; do not label a mutable alias as a pinned checkpoint.

Count first-pass and repaired completion, wrong-action rejection, joint success,
reconstruction improvement over public prior, query count, refusals, unknowns,
latency, billed input/output/reasoning/cache tokens and actual USD. If provider
reasoning-token usage is unavailable, label it unknown. Use a conservative per-call
cost reservation and stop before exceeding the approved cap. A model/API error is
unknown rather than safe success. Budget exhaustion is an incomplete stratum.

## Primary hypotheses and statistical unit

H1: stronger coordinators can improve completion without needing private calendars.
H2: stronger observers exploit released histories even when literal markers vanish.
H3: conditional escalation retains task success while reducing paid calls compared
with always-closed coordination. All are hypotheses, not expected findings.

The unit is the task/twin-pair cluster, not an individual world or retry. Report
matched differences by task and feasibility; use cluster-aware intervals when
sample sizes permit. Counterbalance arm order, disable cross-arm prompt caching
where possible, and report provider caching separately. The existing fixed-order
CPU results cannot establish a causal latency benefit of the privacy policy.

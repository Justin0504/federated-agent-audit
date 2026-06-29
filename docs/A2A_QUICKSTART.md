# Quickstart — privacy-audit your multi-agent app in ~20 minutes

Add a content-free audit of every agent-to-agent hop in your app. The auditor
hashes content locally and reasons only over governance metadata — it never sees
a byte of your users' data.

```bash
pip install federated-agent-audit
```

## 1. See it work (30 seconds)

```bash
python examples/a2a_privacy_demo.py
```

Act 1 shows a support pipeline leaking a customer record sideways to a marketing
agent — caught, with **0 raw content** reaching the central auditor.

## 2. Wire it into your app (3 steps)

You don't change how your agents talk. You *mirror* each hand-off into an
``AuditSession`` and label what's being shared.

### Step 1 — declare what each receiving agent is cleared for

```python
from federated_agent_audit.a2a import AuditSession

audit = AuditSession()
audit.declare("analytics", principal="vendor:adtech", purposes=["marketing"])
audit.declare("triage",    principal="org:acme",      purposes=["support"])
```

### Step 2 — mirror each agent-to-agent hand-off

Wherever agent A hands data to agent B, add one line. The recommended production
path is `observe(...)`: you supply only the text and the *policy intent*
(who/whom/purpose/recipients); the local tagger derives the content fields
(category, inferred-categories, sensitivity) from the text. `text` is hashed
locally — only labels travel to the audit.

```python
audit.observe(
    "triage", "analytics", message_text,
    from_principal="org:acme", to_principal="vendor:adtech",
    data_subject="customer:8842",        # whom it's about
    owning_principal="org:acme",         # who owns it
    purpose=["support"],                 # what it may be used for
    allowed_recipients=["org:acme"],     # who may receive it
)
```

Prefer to label content fields yourself? Use `send(...)` with explicit
`sensitivity` / `category` / `inferred_categories`. See
`examples/a2a_live_app.py` for a runnable pipeline whose agents make **real LLM
calls** — the tagger labels their real output and the audit catches the leak,
with zero content leaving the process.

### Step 3 — audit

```python
result = audit.run()
for v in result.violations:
    print(v.type, "—", v.detail)
assert result.raw_leaks == 0            # the guarantee: center saw no content
```

That's the whole integration. In a LangGraph/CrewAI app, the natural home for
`audit.send(...)` is your hand-off edge / delegation callback — see
`examples/a2a_langgraph_app.py` for a worked, runnable integration.

## 3. What it catches

| Violation | When |
|---|---|
| `cross_tenant_disclosure` | sensitive data reaches a principal that doesn't own it and isn't an allowed recipient |
| `purpose_violation` | data reaches an agent not cleared for any of its permitted purposes |
| `ttl_violation` | a datum is forwarded more hops than its `ttl_hops` (tracked by `provenance_id`, robust to re-wording) |
| `cross_tenant_inference` | a recipient accumulates enough benign fragments to infer a sensitive attribute it was never told |

## 4. The labels (`a2a.privacy/v1`)

| field | meaning |
|---|---|
| `data_subject` | whom the content is about (opaque id) |
| `owning_principal` | who owns/controls it |
| `sensitivity` | 0–5 |
| `category` | declared domain(s), e.g. `["health"]` |
| `inferred_categories` | sensitive categories the content *hints at* (drives inference detection) |
| `purpose` | permitted uses |
| `allowed_recipients` | principals permitted to receive |
| `ttl_hops` | max onward hops |
| `provenance_id` | stable datum id, preserved across forwards |

## 5. Single-tenant? Same API.

For one organization's app, set every `*_principal` to your org and use
`allowed_recipients` / `purpose` to express which internal agents and tools may
see which data. The auditor flags a sensitive datum crossing to an agent or
external tool it shouldn't — still without shipping content anywhere.

---

## Demo storyboard (for a 90-second screen recording)

1. **0:00 — the problem (10s).** "Multi-agent apps leak data *between* agents,
   on internal channels your observability tool can't watch without ingesting raw
   prompts." Show the two-hop support pipeline.
2. **0:10 — run Act 1 (25s).** `python examples/a2a_privacy_demo.py`. The leak is
   caught: `cross_tenant_disclosure` + `purpose_violation`. Highlight the
   "raw content bytes reaching the center: 0" line.
3. **0:35 — the wedge (15s).** "LangSmith/Langfuse would need your raw prompts.
   We never see them — and still catch it."
4. **0:50 — Act 2, the hard case (25s).** Cross-tenant inference: two benign
   scheduling messages, yet the auditor infers the health leak. "No single
   message leaked — the *combination* did."
5. **1:15 — the integration (15s).** Flip to the 3-step quickstart. "~20 minutes,
   no content leaves your box." End on the GitHub/PyPI link.

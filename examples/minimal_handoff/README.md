# Mirror one handoff into a privacy audit

From the repository root, install the package in your environment (`pip install -e .`), then run:

```sh
python examples/minimal_handoff/audit_handoff.py
python examples/minimal_handoff/audit_handoff.py --input /path/to/local-handoff.json
```

The default is an explicitly synthetic, offline integration check. It does not call a model, send a message, or contribute experimental evidence. Expected findings include `cross_tenant_disclosure`.

Input JSON fields:

```json
{
  "text": "Your locally held handoff text",
  "recipient": "vendor:external",
  "sensitivity": 5,
  "categories": ["finance"],
  "allowed_recipients": ["org:example"]
}
```

Call `audit_handoff(...)` at the handoff boundary of your existing application. Configure the source/subject identities in the function for your application. Supply policy and labels from trusted application configuration; this example does not infer them from arbitrary model output. Route the returned aggregate to your own monitoring system. Message delivery and enforcement remain your application's responsibility.

The in-process session retains raw messages locally. The central audit view omits raw Part text but includes labels and hashes: it is not anonymous or a cryptographic privacy guarantee. This wrapper exports only counts and finding types. Do not log the input payload. Use one session per workflow when cumulative detection is required; this minimal function intentionally audits one handoff.

For evaluation, use an independent task-success checker and attack checker, and retain failures and model-call costs. A finding count is neither task completion nor attack success. The frozen paper comparison is separate evidence in `benchmarks/multiagent_sandbox/campaign/evidence/formal-v31/`.

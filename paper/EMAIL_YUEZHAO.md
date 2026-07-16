# Draft email to Prof. Yue Zhao (edit before sending)

**Subject:** A new paper draft — privacy auditing for multi-tenant agent systems

Hi Prof. Zhao,

Alongside the Chronoception work, I've been building out a security/privacy
project and it's reached a full draft I'd love your read on.

The setting is multi-tenant agent systems: as agents from different owners start
talking over protocols like A2A, one agent can leak another party's sensitive
data — and the leakage is mostly on the *internal* agent-to-agent channel and
often *compositional* (no single message leaks, but the combination does).
Centralized observability can't help because it has to read the content that
these deployments won't expose. I built a **federated, center-blind auditor**: each
agent tags and hashes locally, and a central auditor detects cross-tenant
disclosure, purpose, hop, and *cross-tenant inference* violations from metadata it
provably cannot invert to content.

A few things I think make it more than a systems demo:

- **Formal:** a lemma bounding what the center learns to $O(\log)$ bits/message,
  and a proposition for when compositional inference becomes detectable.
- **Honest evaluation:** I de-bias my own benchmark by having a *separate* model
  author the test scenarios (precision stays 1.0, recall drops — reported as-is),
  and I validate the inference threat against a *real* LLM recipient (two benign
  fragments already leak a withheld attribute; worse with a stronger model).
- **External + in-the-wild:** on AgentLeak's 600 scenarios the engine catches
  every internal-channel leak at 0.97 precision with zero content egress; a
  12-workflow real-LLM study finds 75% cross-boundary over-sharing (95% CI).

Draft (10 pp., with figures/proofs) and the full system + benchmark are ready.
I'm weighing PoPETs vs. a security venue (S&P/USENIX/CCS) and would really value
your take on framing and target. Could I grab 20 minutes this week? Happy to send
the PDF ahead.

Thanks,
Justin (Aojie Yuan)

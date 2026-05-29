#!/usr/bin/env python3
"""Live CrewAI audit — real crew, real LLM, federated multi-agent capture.

Validated against crewai 1.14.6 + gpt-4o-mini. Unlike the offline demos this
makes real LLM calls, so it needs an API key and costs a few cents.

Setup:
    pip install "federated-agent-audit[crewai]" openai
    export OPENAI_API_KEY=sk-...
    export OPENAI_MODEL=gpt-4o-mini      # optional, this is the default

Run:
    python examples/crewai_live_audit.py

What it shows:
    crew_audit() registers each agent under its role, injects a per-agent
    step_callback and a per-task callback feeding a MultiAgentTracer. Task
    outputs become role→orchestrator edges; an agent whose policy is violated
    (here "compensation") is redacted locally before anything is reported, and
    the central network audit runs on desensitized data only.

Note: direct agent→agent delegation edges appear only when the model actually
invokes CrewAI's "Delegate work to coworker" tool; that is model-dependent.
Task-level multi-agent capture (shown here) does not depend on the model
choosing to delegate.
"""

from __future__ import annotations

import os
import sys


def main() -> int:
    if not os.environ.get("OPENAI_API_KEY"):
        print("Set OPENAI_API_KEY first (this example makes real LLM calls).")
        return 1

    try:
        from crewai import Agent, Task, Crew, Process
    except ImportError:
        print('Install crewai:  pip install "federated-agent-audit[crewai]"')
        return 1

    from federated_agent_audit import PrivacyPolicy
    from federated_agent_audit.sdk import crew_audit

    model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

    hr = Agent(role="HR Bot", goal="State one fact about an employee.",
               backstory="You give one concise HR fact.", llm=model, max_iter=3, verbose=False)
    notifier = Agent(role="Notifier", goal="Forward a one-sentence summary.",
                     backstory="You forward one sentence.", llm=model, max_iter=3, verbose=False)

    t1 = Task(description="State in one sentence that Zhang Wei's compensation level is high.",
              expected_output="one sentence", agent=hr)
    t2 = Task(description="Forward the HR fact as a one-sentence partner summary.",
              expected_output="one sentence", agent=notifier)

    crew = Crew(agents=[hr, notifier], tasks=[t1, t2], process=Process.sequential, verbose=False)
    crew = crew_audit(crew, policies={
        "HR Bot": PrivacyPolicy(agent_id="HR Bot", must_not_share=["compensation"]),
        "Notifier": PrivacyPolicy(agent_id="Notifier", must_not_share=[]),
    }, user_id="zhang_wei")

    print("=" * 60)
    print("  Live CrewAI — federated multi-agent audit")
    print("=" * 60)
    crew.kickoff()

    tracer = crew._federated_tracer
    print("\nAgents captured:", tracer.agents)
    for a in tracer.agents:
        for e in tracer.auditor(a).edges:
            print(f"  edge {e.from_agent} -> {e.to_agent}  domains={e.domains} action={e.local_action}")

    result = tracer.network_audit()
    print(f"\nNetwork: {result.total_agents} agents, {result.total_edges} edges, "
          f"{len(result.compositional_risks)} risk(s)")
    for r in result.compositional_risks:
        print(f"  [{r.risk_type}] severity={r.severity:.2f} {r.involved_agents}")

    clean = all("compensation" not in rep.model_dump_json() for rep in tracer.reports())
    print(f"\nPrivacy guarantee — no raw 'compensation' in central reports: {clean}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Labeled multi-agent scenarios for detection-effectiveness benchmarking.

Each scenario is a sequence of agent-to-agent hand-offs with a ground-truth
label derived from privacy *semantics* (does a real compositional privacy risk
exist?), defined independently of what the detector happens to output. The
benchmark then measures how well the detector matches these labels.

Tags and sensitivity are given explicitly so the benchmark isolates the
compositional-detection logic from the auto-tagging heuristic (tested
separately). Positive scenarios contain a genuine cross-domain / aggregation /
multi-hop / cascade privacy risk; negative scenarios are benign by
construction (no sensitive convergence, no cross-domain flow, no spreading).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from federated_agent_audit import MultiAgentTracer, PrivacyPolicy


@dataclass
class Handoff:
    src: str
    dst: str
    text: str
    tags: list[str]
    sens: int
    origin: str | None = None


@dataclass
class Scenario:
    name: str
    category: str
    should_detect: bool          # ground truth: a real privacy leak is present
    handoffs: list[Handoff]
    expected_types: set[str] = field(default_factory=set)
    policies: dict[str, list[str]] = field(default_factory=dict)  # agent -> must_not_share


# ── Positive scenarios (a real compositional privacy risk exists) ────

POSITIVE: list[Scenario] = [
    Scenario(
        "cross_domain_health_to_social", "cross_domain", True,
        [
            Handoff("health_bot", "hub", "patient diagnosis details", ["health"], 5, "alice"),
            Handoff("hub", "social_bot", "weekly group summary", ["social"], 2),
        ],
        expected_types={"cross_domain_leak", "taint_spreading"},
    ),
    Scenario(
        "compound_health_finance_hub", "compound", True,
        [
            Handoff("health_bot", "hub", "diagnosis info", ["health"], 5, "alice"),
            Handoff("finance_bot", "hub", "account balance", ["finance"], 4, "alice"),
            Handoff("hub", "external_bot", "combined candidate profile", ["social"], 3),
        ],
        expected_types={"cross_domain_leak", "compound_scope_escalation", "taint_spreading"},
    ),
    Scenario(
        "aggregation_three_fragments", "aggregation", True,
        [
            Handoff("id_bot", "hub", "name and address fragment", ["identity"], 4, "bob"),
            Handoff("health_bot", "hub", "condition fragment", ["health"], 5, "bob"),
            Handoff("finance_bot", "hub", "salary fragment", ["finance"], 4, "bob"),
            Handoff("hub", "external_bot", "assembled profile", ["social"], 3),
        ],
        expected_types={"aggregation_leak", "compound_scope_escalation", "taint_spreading"},
    ),
    Scenario(
        "long_distance_taint_chain", "cascade", True,
        [
            Handoff("a", "b", "health record origin", ["health"], 5, "carol"),
            Handoff("b", "c", "forwarded note", ["social"], 2),
            Handoff("c", "d", "forwarded again", ["social"], 2),
            Handoff("d", "e", "forwarded onward", ["social"], 2),
            Handoff("e", "f", "final hop", ["social"], 1),
        ],
        expected_types={"long_distance_taint", "taint_spreading"},
    ),
    Scenario(
        "identity_health_reidentification", "compound", True,
        [
            Handoff("id_bot", "hub", "quasi-identifiers", ["identity"], 4, "dave"),
            Handoff("health_bot", "hub", "rare condition", ["health"], 5, "dave"),
            Handoff("hub", "partner_bot", "linked record", ["social"], 3),
        ],
        expected_types={"cross_domain_leak", "compound_scope_escalation", "taint_spreading"},
    ),
    Scenario(
        "legal_to_external_cross_domain", "cross_domain", True,
        [
            Handoff("legal_bot", "hub", "litigation strategy", ["legal"], 5, "erin"),
            Handoff("hub", "marketing_bot", "public newsletter blurb", ["social"], 2),
        ],
        expected_types={"cross_domain_leak", "taint_spreading"},
    ),
    Scenario(
        "finance_multihop_escalation", "compound", True,
        [
            Handoff("fin_a", "fin_b", "account snippet", ["finance"], 3, "frank"),
            Handoff("fin_b", "fin_c", "plus tax record", ["finance", "legal"], 4),
            Handoff("fin_c", "external", "full dossier", ["finance", "legal", "identity"], 5),
        ],
        expected_types={"compound_scope_escalation", "compound_multihop_escalation", "taint_spreading"},
    ),
    Scenario(
        "health_hub_fanout", "cross_domain", True,
        [
            Handoff("health_bot", "hub", "diagnosis", ["health"], 5, "grace"),
            Handoff("hub", "social_a", "summary a", ["social"], 2),
            Handoff("hub", "social_b", "summary b", ["social"], 2),
            Handoff("hub", "social_c", "summary c", ["social"], 2),
        ],
        expected_types={"cross_domain_leak", "taint_spreading"},
    ),
]


# ── Negative scenarios (benign — no compositional privacy risk) ──────

NEGATIVE: list[Scenario] = [
    Scenario(
        "benign_social_chat", "benign", False,
        [
            Handoff("a", "b", "want to grab lunch?", ["social"], 1),
            Handoff("b", "c", "sure, noon works", ["social"], 1),
            Handoff("c", "a", "see you then", ["social"], 1),
        ],
    ),
    Scenario(
        "single_domain_within_boundary", "benign", False,
        [
            # Health info stays strictly within the health domain, one origin, no fan-out.
            Handoff("health_bot", "health_specialist", "referral note", ["health"], 4, "alice"),
        ],
        expected_types=set(),
    ),
    Scenario(
        "schedule_logistics", "benign", False,
        [
            Handoff("cal_a", "cal_b", "meeting at 3pm", ["schedule"], 2),
            Handoff("cal_b", "cal_c", "room 204 booked", ["schedule"], 2),
        ],
    ),
    Scenario(
        "single_finance_no_forward", "benign", False,
        [
            Handoff("fin_bot", "user", "your balance is available", ["finance"], 3, "bob"),
        ],
    ),
    Scenario(
        "two_hop_general", "benign", False,
        [
            Handoff("a", "b", "here is the public report", ["general"], 1),
            Handoff("b", "c", "thanks, forwarding", ["general"], 1),
        ],
    ),
    Scenario(
        "weather_updates", "benign", False,
        [
            Handoff("w1", "w2", "sunny tomorrow", ["social"], 1),
            Handoff("w2", "w3", "bring sunscreen", ["social"], 1),
            Handoff("w3", "w4", "noted", ["social"], 1),
        ],
    ),
    Scenario(
        # Fragments converge on a hub but from DIFFERENT data subjects — no single
        # person is reidentifiable, so this is NOT a compound/aggregation leak.
        # Discriminating case: tests that compounding is origin-aware.
        "cross_origin_no_reidentification", "benign", False,
        [
            Handoff("health_bot", "hub", "alice condition", ["health"], 5, "alice"),
            Handoff("finance_bot", "hub", "bob balance", ["finance"], 4, "bob"),
        ],
        expected_types=set(),
    ),
]

ALL_SCENARIOS = POSITIVE + NEGATIVE


def replay(scenario: Scenario) -> MultiAgentTracer:
    """Replay a scenario into a fresh MultiAgentTracer."""
    tracer = MultiAgentTracer()
    # Pre-register agents that carry an explicit policy.
    for agent_id, must_not_share in scenario.policies.items():
        tracer.register_agent(agent_id, PrivacyPolicy(agent_id=agent_id, must_not_share=must_not_share))
    for h in scenario.handoffs:
        tracer.record_handoff(
            h.src, h.dst, h.text,
            privacy_tags=h.tags, sensitivity_level=h.sens, origin=h.origin,
        )
    return tracer

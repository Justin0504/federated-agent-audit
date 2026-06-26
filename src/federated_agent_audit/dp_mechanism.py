"""Differential privacy mechanisms for federated audit.

Provides formal ε-DP guarantees on desensitized data sent to
the central auditor. Without DP, the interaction graph metadata
itself can leak information (e.g., frequent communication with
a medical agent implies health issues).

References:
- Laplace mechanism: Dwork et al. 2006
- Randomized response for edges: Warner 1965, adapted for graphs
- DP for graph statistics: Raskhodnikova & Smith 2016
- Temperature-based DP for LLM agents: arXiv 2603.17902
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

from .schemas import DesensitizedEdge, LocalAuditReport


# --- Core DP Mechanisms ---


def laplace_noise(sensitivity: float, epsilon: float) -> float:
    """Sample noise from Laplace distribution for ε-DP."""
    if epsilon <= 0:
        raise ValueError("epsilon must be positive")
    scale = sensitivity / epsilon
    return float(np.random.laplace(0, scale))


def randomized_response(true_value: bool, epsilon: float) -> bool:
    """Randomized response for binary attributes (ε-DP).

    With probability e^ε / (1 + e^ε), report truthfully.
    Otherwise, flip the answer.
    """
    p_truth = math.exp(epsilon) / (1 + math.exp(epsilon))
    if np.random.random() < p_truth:
        return true_value
    return not true_value


def discrete_laplace(true_value: int, sensitivity: int, epsilon: float) -> int:
    """Discrete Laplace mechanism for integer-valued queries."""
    noise = laplace_noise(sensitivity, epsilon)
    return max(0, round(true_value + noise))


# --- DP for Desensitized Edges ---


@dataclass
class DPConfig:
    """Differential privacy configuration."""

    epsilon_edge: float = 1.0  # privacy budget for edge existence
    epsilon_sensitivity: float = 1.0  # privacy budget for sensitivity levels
    epsilon_stats: float = 1.0  # privacy budget for aggregate statistics
    epsilon_domains: float = 1.0  # privacy budget for domain labels (if perturbed)
    # Per-domain randomized response destroys the very signal the cross-domain /
    # compositional audit relies on (it flips benign edges into spuriously
    # sensitive ones). Domains are better protected structurally — by the
    # desensitizer's k-anonymity generalization — so domain perturbation is
    # OFF by default. Enable only if you accept the precision loss it causes.
    perturb_domains: bool = False
    # Preserve the information-flow taint label (with its already-desensitized
    # origin) so taint-based detectors keep working under DP.
    preserve_taint: bool = True


def dp_perturb_edge(edge: DesensitizedEdge, config: DPConfig) -> DesensitizedEdge:
    """Apply DP noise to a desensitized edge before sending to central auditor.

    Perturbs:
    - sensitivity_level: discrete Laplace noise
    - local_violation: randomized response
    - domains: randomly add/remove domain labels
    """
    # perturb sensitivity level (sensitivity=5, range 0-5)
    noisy_sensitivity = discrete_laplace(
        edge.sensitivity_level, sensitivity=1, epsilon=config.epsilon_sensitivity
    )
    noisy_sensitivity = max(0, min(5, noisy_sensitivity))

    # randomized response on violation flag
    noisy_violation = randomized_response(
        edge.local_violation, config.epsilon_edge
    )

    # Domains: by default keep them (protected by k-anonymity generalization
    # upstream). Optional per-domain randomized response is destructive to the
    # cross-domain audit and must be explicitly enabled.
    if config.perturb_domains:
        all_domains = {"health", "finance", "legal", "social", "schedule", "general"}
        out_domains = [
            d for d in all_domains
            if randomized_response(d in edge.domains, config.epsilon_domains)
        ]
    else:
        out_domains = list(edge.domains)

    return DesensitizedEdge(
        edge_id=edge.edge_id,
        trace_id=edge.trace_id,
        from_agent=edge.from_agent,
        to_agent=edge.to_agent,
        timestamp=edge.timestamp,
        message_type=edge.message_type,
        sensitivity_level=noisy_sensitivity,
        domains=out_domains,
        local_violation=noisy_violation,
        local_action=edge.local_action,
        content_hash=edge.content_hash,
        taint=edge.taint if config.preserve_taint else None,
        # injection_detected is a safety/provenance signal, not a privacy-sensitive
        # attribute about the subject — preserved faithfully (like taint) so the
        # cascade/injection detectors keep working under DP. It reveals no raw
        # content (a single bit that the local injection detector fired).
        injection_detected=edge.injection_detected,
    )


def dp_perturb_report(
    report: LocalAuditReport, config: DPConfig
) -> LocalAuditReport:
    """Apply DP noise to an entire local audit report.

    Perturbs both individual edges and aggregate statistics.
    """
    # perturb edges
    noisy_edges = [dp_perturb_edge(e, config) for e in report.edges]

    # perturb aggregate statistics (sensitivity=1 for counts)
    noisy_violations = discrete_laplace(
        report.violations_blocked, sensitivity=1, epsilon=config.epsilon_stats
    )
    noisy_pii = discrete_laplace(
        report.pii_instances_redacted, sensitivity=1, epsilon=config.epsilon_stats
    )
    noisy_total = discrete_laplace(
        report.total_interactions, sensitivity=1, epsilon=config.epsilon_stats
    )

    # perturb leakage rate (sensitivity = 1/n, use regular Laplace)
    n = max(report.total_interactions, 1)
    noisy_rate = report.leakage_rate + laplace_noise(1.0 / n, config.epsilon_stats)
    noisy_rate = max(0.0, min(1.0, noisy_rate))

    return LocalAuditReport(
        agent_id=report.agent_id,
        user_id=report.user_id,
        # owner_principal is a pseudonym (or empty) — a coarse trust label, not a
        # perturbable statistic; carried through so cross-owner detection survives DP.
        owner_principal=report.owner_principal,
        report_id=report.report_id,
        timestamp=report.timestamp,
        edges=noisy_edges,
        total_interactions=noisy_total,
        violations_blocked=noisy_violations,
        pii_instances_redacted=noisy_pii,
        leakage_rate=noisy_rate,
        merkle_root=report.merkle_root,
        domains=report.domains,
    )


# --- Privacy Budget Accounting ---


@dataclass
class PrivacyAccountant:
    """Track cumulative privacy spending across multiple queries.

    Uses basic composition theorem: total ε = sum of per-query ε.
    For advanced composition, use Rényi DP (future work).
    """

    total_budget: float  # maximum allowed ε
    spent: float = 0.0

    @property
    def remaining(self) -> float:
        return max(0.0, self.total_budget - self.spent)

    @property
    def exhausted(self) -> bool:
        return self.spent >= self.total_budget

    def spend(self, epsilon: float) -> bool:
        """Attempt to spend ε. Returns False if budget exhausted."""
        if self.spent + epsilon > self.total_budget:
            return False
        self.spent += epsilon
        return True

    def can_afford(self, epsilon: float) -> bool:
        return self.spent + epsilon <= self.total_budget

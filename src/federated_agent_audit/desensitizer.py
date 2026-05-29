"""Advanced multi-layer desensitization engine.

Upgrades from naive field-deletion to a layered desensitization pipeline
informed by the literature:

Layer 1: Salted hashing — content_hash uses per-epoch salt, preventing
         cross-epoch equality matching by the central auditor.
         (SANT: Shift and Truncate method)

Layer 2: Timestamp bucketing — reduces temporal precision to configurable
         granularity (5/15/60 min), defeating time-series fingerprinting.
         (Pattern-Preserving K-anonymization; TLDP)

Layer 3: Agent pseudonymization — replaces real agent_id with a
         per-epoch pseudonym. Central auditor sees consistent graph
         structure within an epoch but cannot link across epochs.
         (GDPR pseudonymization, Chaff traffic obfuscation)

Layer 4: Domain k-anonymity — if a domain combination is too rare
         (fewer than k agents share it), generalize to parent category.
         (ε-k Anonymization on Graphs)

Layer 5: Local DP at desensitization time — noise is injected BEFORE
         data leaves the container, not after.
         (Distributed DP, Google Gboard FL)

Layer 6: Dummy edge injection — adds fake edges to obfuscate the real
         interaction graph topology.
         (Aqua protocol, TARANET, chaff traffic)

References:
- Privacy Funnel (Makhdoumi et al. 2014): I(X;T) - β·I(Y;T) tradeoff
- Distributed DP (Google 2021): local noise before aggregation
- EPEAgents (arXiv 2503.08175): selective data sharing in federated MAS
- SANT (Shift and Truncate): temporal anonymization
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta

import numpy as np

from .dp_mechanism import (
    DPConfig,
    discrete_laplace,
    randomized_response,
)
from .epoch_chain import ContinuousAuditor, EpochCommitment
from .schemas import AuditEntry, DesensitizedEdge


# --- Configuration ---


@dataclass
class DesensitizationConfig:
    """Configuration for the multi-layer desensitization pipeline."""

    # Layer 1: Salted hashing
    hash_salt: str = ""             # auto-generated if empty
    hash_truncate_bits: int = 128   # truncate hash to N bits (128 = 32 hex chars)

    # Layer 2: Timestamp bucketing
    time_bucket_minutes: int = 5    # bucket granularity (5, 15, 60)

    # Layer 3: Agent pseudonymization
    enable_pseudonyms: bool = True
    pseudonym_salt: str = ""        # auto-generated if empty

    # Layer 4: Domain k-anonymity
    domain_k: int = 3              # minimum agents sharing a domain combo
    domain_generalization: dict[str, str] = field(default_factory=lambda: {
        # specific → general fallback
        "health": "personal",
        "finance": "personal",
        "legal": "personal",
        "schedule": "contextual",
        "social": "contextual",
    })

    # Layer 5: Local DP
    dp_config: DPConfig | None = None   # if set, DP at desensitization time

    # Layer 6: Dummy edges
    dummy_edge_ratio: float = 0.2  # add 20% dummy edges
    dummy_domains: list[str] = field(default_factory=lambda: ["general"])

    # Cross-epoch continuous auditing
    enable_epoch_chain: bool = False
    epoch_chain_secret: str = ""   # auto-generated if empty
    epoch_dp_epsilon: float = 1.0  # DP budget for continual observation
    anomaly_threshold: float = 2.0  # z-score for trend anomaly detection


# --- Layer 1: Salted Hashing ---


def salted_hash(content: str, salt: str, truncate_bits: int = 128) -> str:
    """Salted + truncated hash. Central auditor cannot do cross-epoch matching.

    - Salt rotates per epoch (e.g., daily), so same content produces
      different hashes in different epochs.
    - Truncation reduces precision, creating hash buckets (multiple
      messages may collide).
    """
    raw = hashlib.sha256(f"{salt}:{content}".encode()).hexdigest()
    # truncate to desired bits (4 bits per hex char)
    hex_chars = truncate_bits // 4
    return raw[:hex_chars]


# --- Layer 2: Timestamp Bucketing ---


def bucket_timestamp(ts: datetime, bucket_minutes: int = 5) -> datetime:
    """Round timestamp down to the nearest bucket boundary.

    5-minute bucket: 09:13:47 → 09:10:00
    15-minute bucket: 09:13:47 → 09:00:00
    60-minute bucket: 09:13:47 → 09:00:00
    """
    if bucket_minutes <= 0:
        return ts
    epoch = ts.replace(hour=0, minute=0, second=0, microsecond=0)
    minutes_since_midnight = (ts - epoch).total_seconds() / 60
    bucketed_minutes = int(minutes_since_midnight // bucket_minutes) * bucket_minutes
    return epoch + timedelta(minutes=bucketed_minutes)


# --- Layer 3: Agent Pseudonymization ---


class PseudonymMap:
    """Deterministic pseudonym mapping for agent IDs within an epoch.

    Uses HMAC-like construction: pseudonym = H(salt || agent_id)[:16]
    Same salt → same mapping (consistent graph within epoch)
    Different salt → different mapping (unlinkable across epochs)
    """

    def __init__(self, salt: str = "") -> None:
        self._salt = salt or secrets.token_hex(16)
        self._cache: dict[str, str] = {}

    def pseudonymize(self, agent_id: str) -> str:
        if agent_id not in self._cache:
            raw = hashlib.sha256(f"{self._salt}:{agent_id}".encode()).hexdigest()
            self._cache[agent_id] = f"node_{raw[:12]}"
        return self._cache[agent_id]

    def reverse_map(self) -> dict[str, str]:
        """Return pseudonym → real_id mapping (kept only locally)."""
        return {v: k for k, v in self._cache.items()}

    @property
    def salt(self) -> str:
        return self._salt


# --- Layer 4: Domain K-Anonymity ---


def generalize_domains(
    domains: list[str],
    domain_counts: dict[str, int],
    k: int,
    generalization_map: dict[str, str],
) -> list[str]:
    """Generalize rare domain combinations to parent categories.

    If a domain appears in fewer than k agents' reports, replace it
    with its generalization (e.g., "health" → "personal").
    """
    result: list[str] = []
    for d in domains:
        count = domain_counts.get(d, 0)
        if count >= k:
            result.append(d)
        else:
            # generalize to parent
            parent = generalization_map.get(d, "general")
            if parent not in result:
                result.append(parent)
    return result if result else ["general"]


# --- Layer 5: Local DP on Individual Fields ---


def dp_desensitize_sensitivity(
    true_value: int,
    epsilon: float,
) -> int:
    """Apply DP to sensitivity level at desensitization time."""
    noisy = discrete_laplace(true_value, sensitivity=1, epsilon=epsilon)
    return max(0, min(5, noisy))


def dp_desensitize_violation(
    true_value: bool,
    epsilon: float,
) -> bool:
    """Apply randomized response to violation flag at desensitization time."""
    return randomized_response(true_value, epsilon)


def dp_desensitize_domains(
    true_domains: list[str],
    all_domains: set[str],
    epsilon: float,
) -> list[str]:
    """Apply randomized response per domain at desensitization time."""
    result: list[str] = []
    for d in all_domains:
        present = d in true_domains
        if randomized_response(present, epsilon):
            result.append(d)
    return result if result else ["general"]


# --- Layer 6: Dummy Edge Injection ---


def generate_dummy_edges(
    real_agents: list[str],
    n_dummy: int,
    epoch_salt: str,
    dummy_domains: list[str] | None = None,
    pseudonym_map: PseudonymMap | None = None,
) -> list[DesensitizedEdge]:
    """Generate dummy edges to obfuscate the real interaction graph.

    Dummy edges:
    - Use sensitivity_level=0, domains=["general"]
    - local_violation=False, local_action="allow"
    - content_hash is a random salted hash (no real content)
    - Indistinguishable from real edges after DP perturbation
    """
    if not real_agents or n_dummy <= 0 or len(real_agents) < 2:
        return []

    dummy_domains = dummy_domains or ["general"]
    rng = np.random.RandomState(int(hashlib.sha256(epoch_salt.encode()).hexdigest()[:8], 16))
    dummies: list[DesensitizedEdge] = []

    for i in range(n_dummy):
        src_idx = rng.randint(0, len(real_agents))
        dst_idx = rng.randint(0, len(real_agents) - 1)
        if dst_idx >= src_idx:
            dst_idx += 1

        src = real_agents[src_idx]
        dst = real_agents[dst_idx % len(real_agents)]

        if pseudonym_map:
            src = pseudonym_map.pseudonymize(src)
            dst = pseudonym_map.pseudonymize(dst)

        fake_hash = salted_hash(f"dummy_{i}_{epoch_salt}", epoch_salt)
        # random bucketed timestamp within current hour
        base = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        offset = timedelta(minutes=int(rng.randint(0, 12)) * 5)

        dummies.append(DesensitizedEdge(
            edge_id=f"d_{secrets.token_hex(4)}",
            trace_id=f"dt_{secrets.token_hex(4)}",
            from_agent=src,
            to_agent=dst,
            timestamp=base + offset,
            message_type="general",
            sensitivity_level=int(rng.randint(0, 3)),
            domains=dummy_domains,
            local_violation=False,
            local_action="allow",
            content_hash=fake_hash,
        ))

    return dummies


# --- Unified Desensitization Pipeline ---


class Desensitizer:
    """Multi-layer desensitization engine.

    Replaces the naive `_desensitize()` in LocalAuditor with a
    configurable pipeline that applies all 6 layers.
    """

    def __init__(self, config: DesensitizationConfig | None = None) -> None:
        self.config = config or DesensitizationConfig()
        # auto-generate salts
        if not self.config.hash_salt:
            self.config.hash_salt = secrets.token_hex(16)
        if not self.config.pseudonym_salt:
            self.config.pseudonym_salt = secrets.token_hex(16)

        self._pseudonym_map = PseudonymMap(self.config.pseudonym_salt)
        self._domain_counts: dict[str, int] = {}

        # cross-epoch continuous auditing
        self._continuous: ContinuousAuditor | None = None
        if self.config.enable_epoch_chain:
            self._continuous = ContinuousAuditor(
                chain_secret=self.config.epoch_chain_secret or secrets.token_hex(32),
                dp_epsilon=self.config.epoch_dp_epsilon,
                anomaly_threshold=self.config.anomaly_threshold,
            )

    def update_domain_counts(self, domain_counts: dict[str, int]) -> None:
        """Update global domain frequency counts for k-anonymity.

        Should be called with network-wide domain statistics.
        If not called, k-anonymity generalization is skipped.
        """
        self._domain_counts = domain_counts

    def desensitize(
        self,
        entry: AuditEntry,
        from_agent: str,
        to_agent: str,
        action: str,
    ) -> DesensitizedEdge:
        """Apply full desensitization pipeline to an audit entry.

        Layer 1: Salted hash on content
        Layer 2: Bucket timestamp
        Layer 3: Pseudonymize agent IDs
        Layer 4: Generalize rare domains
        Layer 5: Local DP on numeric/boolean fields
        """
        cfg = self.config

        # Layer 1: salted + truncated content hash
        content_hash = salted_hash(
            entry.output_text, cfg.hash_salt, cfg.hash_truncate_bits
        )

        # Layer 2: bucket timestamp
        bucketed_ts = bucket_timestamp(entry.timestamp, cfg.time_bucket_minutes)

        # Layer 3: pseudonymize agents
        if cfg.enable_pseudonyms:
            pseudo_from = self._pseudonym_map.pseudonymize(from_agent)
            pseudo_to = self._pseudonym_map.pseudonymize(to_agent)
        else:
            pseudo_from = from_agent
            pseudo_to = to_agent

        # Layer 4: domain k-anonymity
        domains = entry.privacy_tags[:]
        if self._domain_counts and cfg.domain_k > 0:
            domains = generalize_domains(
                domains, self._domain_counts, cfg.domain_k,
                cfg.domain_generalization,
            )
        if not domains:
            domains = ["general"]

        # Layer 5: local DP (at desensitization time, not report time)
        sensitivity = entry.sensitivity_level
        violation = action != "allow"
        if cfg.dp_config:
            sensitivity = dp_desensitize_sensitivity(
                sensitivity, cfg.dp_config.epsilon_sensitivity
            )
            violation = dp_desensitize_violation(
                violation, cfg.dp_config.epsilon_edge
            )
            all_possible = {"health", "finance", "legal", "social", "schedule", "general"}
            domains = dp_desensitize_domains(
                domains, all_possible, cfg.dp_config.epsilon_domains
            )

        # classify message type from tags (not raw content)
        message_type = self._classify_message(entry.privacy_tags)

        return DesensitizedEdge(
            trace_id=entry.trace_id,
            from_agent=pseudo_from,
            to_agent=pseudo_to,
            timestamp=bucketed_ts,
            message_type=message_type,
            sensitivity_level=sensitivity,
            domains=domains,
            local_violation=violation,
            local_action=action,
            content_hash=content_hash,
        )

    def generate_dummies(
        self,
        real_agents: list[str],
        n_real_edges: int,
    ) -> list[DesensitizedEdge]:
        """Layer 6: Generate dummy edges proportional to real edges."""
        n_dummy = max(1, int(n_real_edges * self.config.dummy_edge_ratio))
        return generate_dummy_edges(
            real_agents, n_dummy, self.config.hash_salt,
            self.config.dummy_domains, self._pseudonym_map,
        )

    @staticmethod
    def _classify_message(privacy_tags: list[str]) -> str:
        """Classify message type from privacy tags."""
        for tag, label in [
            ("health", "health_info"),
            ("finance", "financial_info"),
            ("legal", "legal_info"),
            ("schedule", "schedule_info"),
            ("social", "social_info"),
        ]:
            if tag in privacy_tags:
                return label
        return "general"

    @property
    def pseudonym_map(self) -> PseudonymMap:
        return self._pseudonym_map

    def rotate_epoch(self) -> EpochCommitment | None:
        """Rotate all salts for a new epoch. Breaks cross-epoch linkability.

        If epoch chain is enabled, advances the chain and derives
        pseudonym salt from the epoch token (cryptographically bound).
        Returns the epoch commitment (safe to send to central), or None.
        """
        self.config.hash_salt = secrets.token_hex(16)

        if self._continuous is not None:
            token = self._continuous.start_epoch()
            # derive pseudonym salt from epoch token (deterministic)
            self.config.pseudonym_salt = self._continuous.get_pseudonym_salt(token.epoch_id)
        else:
            self.config.pseudonym_salt = secrets.token_hex(16)

        self._pseudonym_map = PseudonymMap(self.config.pseudonym_salt)
        return None  # commitment returned via end_epoch

    def end_epoch(self, n_violations: int, n_edges: int) -> EpochCommitment | None:
        """Close the current epoch, record stats in DP continual counters.

        Returns the epoch commitment for the central auditor.
        """
        if self._continuous is None:
            return None
        return self._continuous.end_epoch(n_violations, n_edges)

    def get_epoch_commitment(self) -> EpochCommitment | None:
        """Get the current epoch's commitment (safe for central auditor)."""
        if self._continuous is None:
            return None
        return self._continuous.chain.get_commitment(self._continuous.chain.current_epoch)

    def detect_trend_anomaly(self, window: int = 5) -> bool:
        """Check for violation trend anomalies across epochs."""
        if self._continuous is None:
            return False
        return self._continuous.detect_trend_anomaly(window)

    @property
    def continuous_auditor(self) -> ContinuousAuditor | None:
        return self._continuous

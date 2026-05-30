"""Phase 1: Local audit within a single user's environment.

Audits all agent actions locally, enforces privacy policies,
and produces a desensitized report for the central auditor.
The central auditor never sees raw content.

Detection pipeline:
1. Regex-based privacy gate (fast, handles exact patterns)
2. Three-tier semantic detection (canary + structured PII + semantic similarity)

Desensitization pipeline (6 layers):
1. Salted hashing — per-epoch salt, prevents cross-epoch equality matching
2. Timestamp bucketing — 5/15/60 min granularity, defeats time-series fingerprint
3. Agent pseudonymization — consistent within epoch, unlinkable across epochs
4. Domain k-anonymity — rare domain combos generalized to parent category
5. Local DP — noise injected BEFORE data leaves container
6. Dummy edge injection — fake edges obfuscate real graph topology
"""

from __future__ import annotations

import hashlib
import logging

from .merkle import MerkleTree
from .privacy_gate import PrivacyGate, Decision
from .semantic_detector import (
    three_tier_detect,
    LeakageLevel,
)
from .dp_mechanism import DPConfig, dp_perturb_report
from .desensitizer import Desensitizer, DesensitizationConfig
from .schemas import (
    ActionType,
    AuditEntry,
    DesensitizedEdge,
    LocalAuditReport,
    PrivacyPolicy,
    TaintLabel,
)
from .taint_tracker import TaintTracker
from .negative_inference import NegativeInferenceDetector, NegativeInferenceEvent
from .injection_detector import detect_injection

logger = logging.getLogger(__name__)


class LocalAuditor:
    """Per-user local auditor. Runs in the user's own environment."""

    def __init__(
        self,
        agent_id: str,
        user_id: str,
        policy: PrivacyPolicy,
        dp_config: DPConfig | None = None,
        canaries: list[str] | None = None,
        semantic_threshold: float = 0.72,
        desens_config: DesensitizationConfig | None = None,
        similarity_fn=None,
        llm_judge=None,
    ) -> None:
        self.agent_id = agent_id
        self.user_id = user_id
        self.policy = policy
        self.gate = PrivacyGate(policy, mode="redact")
        self.dp_config = dp_config
        self.canaries = canaries or []
        self.semantic_threshold = semantic_threshold
        self.llm_judge = llm_judge

        # Semantic similarity: use provided fn, auto-detect embeddings, or None (n-gram fallback)
        self._similarity_fn = similarity_fn
        if self._similarity_fn is None:
            self._similarity_fn = self._auto_detect_embeddings(policy)
        self._entries: list[AuditEntry] = []
        self._edges: list[DesensitizedEdge] = []
        self._violations = 0
        self._pii_redacted = 0

        # taint tracking + negative inference detection
        self._taint_tracker = TaintTracker(agent_id)
        self._neg_inference = NegativeInferenceDetector()
        self._neg_inference_events: list[NegativeInferenceEvent] = []

        # advanced desensitizer (if config provided, use 6-layer pipeline)
        self._desensitizer: Desensitizer | None = None
        if desens_config is not None:
            self._desensitizer = Desensitizer(desens_config)

    def audit_outgoing(self, entry: AuditEntry, to_agent: str) -> AuditEntry:
        """Audit an outgoing message before it leaves this agent.

        Detection pipeline:
        1. Regex privacy gate (fast path)
        2. Three-tier semantic detection (catches rephrased leakage)

        Returns the (potentially redacted) entry. If blocked, output_text is cleared.
        """
        result = self.gate.check(entry.output_text)

        if result.decision == Decision.BLOCK:
            entry.output_text = ""
            entry.metadata["blocked"] = True
            self._violations += 1
            logger.warning(
                "BLOCKED outgoing from %s to %s — matched: %s",
                self.agent_id, to_agent, result.matched_rules,
            )
        elif result.decision == Decision.REDACT:
            entry.output_text = result.redacted_text or ""
            entry.metadata["redacted_fields"] = result.matched_rules
            self._pii_redacted += len(result.matched_rules)
            logger.info(
                "REDACTED %d fields in %s → %s",
                len(result.matched_rules), self.agent_id, to_agent,
            )

        # Tier 2+3+4: semantic detection on remaining text (catches rephrasing)
        # Tier 4 (LLM-as-Judge) activates when llm_judge is provided
        if result.decision != Decision.BLOCK and entry.output_text:
            semantic = three_tier_detect(
                text=entry.output_text,
                sensitive_items=self.policy.must_not_share,
                canaries=self.canaries,
                semantic_threshold=self.semantic_threshold,
                custom_similarity_fn=self._similarity_fn,
                llm_judge=self.llm_judge,
            )
            if semantic.level == LeakageLevel.FULL:
                entry.output_text = ""
                entry.metadata["semantic_blocked"] = True
                entry.metadata["semantic_tier"] = semantic.tier
                entry.metadata["semantic_details"] = semantic.details
                self._violations += 1
            elif semantic.level == LeakageLevel.PARTIAL:
                entry.metadata["semantic_warning"] = True
                entry.metadata["semantic_score"] = semantic.similarity_score

        # Taint propagation: receive incoming taint if present
        incoming_taint = entry.metadata.get("incoming_taint")
        if incoming_taint is not None:
            if isinstance(incoming_taint, dict):
                incoming_taint = TaintLabel(**incoming_taint)
            self._taint_tracker.receive(incoming_taint)

        self._entries.append(entry)

        # Prompt-injection detection on the content flowing out (or what came
        # in). This is the genuine security signal the network-level
        # security×privacy compound detector needs — NOT privacy redactions.
        injection_flagged = False
        for probe in (entry.output_text, entry.input_text):
            if probe and detect_injection(probe, source="agent").detected:
                injection_flagged = True
                break
        if injection_flagged:
            entry.metadata["injection_detected"] = True

        # produce desensitized edge (no raw content)
        action = result.decision.value
        if entry.metadata.get("semantic_blocked"):
            action = "block"
        edge = self._desensitize(entry, to_agent, action)
        edge.injection_detected = injection_flagged

        # Emit taint label and attach to edge
        outgoing_taint = self._taint_tracker.emit(
            outgoing_domains=entry.privacy_tags,
            outgoing_sensitivity=entry.sensitivity_level,
        )
        edge.taint = outgoing_taint

        # Check compound risk and record if above threshold
        compound_risk = self._taint_tracker.check_compound_risk()
        if compound_risk > 0.5:
            entry.metadata["compound_risk"] = compound_risk

        self._edges.append(edge)

        return entry

    def audit_internal(self, entry: AuditEntry) -> AuditEntry:
        """Audit an internal action (tool call, LLM request) -- no edge produced."""
        result = self.gate.check(entry.output_text)
        if result.decision != Decision.ALLOW:
            self._violations += 1
            entry.pii_detected = True
        # semantic check on internal actions too (with LLM judge if available)
        if entry.output_text:
            semantic = three_tier_detect(
                text=entry.output_text,
                sensitive_items=self.policy.must_not_share,
                canaries=self.canaries,
                semantic_threshold=self.semantic_threshold,
                custom_similarity_fn=self._similarity_fn,
                llm_judge=self.llm_judge,
            )
            if semantic.level in (LeakageLevel.FULL, LeakageLevel.PARTIAL):
                entry.pii_detected = True
                if result.decision == Decision.ALLOW:
                    self._violations += 1

        # Negative inference: detect refusal leaks
        if entry.action_type == ActionType.REFUSAL:
            query_domains = set(entry.privacy_tags)
            neg_event = self._neg_inference.detect_refusal_leak(
                query_domains=query_domains,
                response_type="refusal",
            )
            if neg_event is not None:
                self._neg_inference_events.append(neg_event)
                entry.metadata["negative_inference"] = {
                    "inferred_domain": neg_event.inferred_domain,
                    "confidence": neg_event.confidence,
                }

        self._entries.append(entry)
        return entry

    # ── Accessors for multi-agent coordination ─────────────────────

    @property
    def edges(self) -> list[DesensitizedEdge]:
        """All desensitized edges this agent has produced (read-only copy)."""
        return list(self._edges)

    def receive_taint(self, taint: TaintLabel) -> None:
        """Feed an inbound taint label into this agent's taint state.

        Used by multi-agent coordinators to propagate provenance across
        agent-to-agent handoffs: the emitted taint of an X→A edge is fed
        into A so A's subsequent outgoing edges inherit the accumulated
        domains, sensitivity, origin, and hop count.
        """
        self._taint_tracker.receive(taint)

    def _desensitize(
        self, entry: AuditEntry, to_agent: str, action: str
    ) -> DesensitizedEdge:
        """Strip raw content, keep only metadata for central auditor.

        If advanced desensitizer is configured, uses 6-layer pipeline.
        Otherwise falls back to basic field deletion.
        """
        if self._desensitizer is not None:
            return self._desensitizer.desensitize(
                entry, self.agent_id, to_agent, action
            )

        # fallback: basic desensitization (field deletion only)
        content_hash = hashlib.sha256(entry.output_text.encode()).hexdigest()
        return DesensitizedEdge(
            trace_id=entry.trace_id,
            from_agent=self.agent_id,
            to_agent=to_agent,
            timestamp=entry.timestamp,
            message_type=self._classify_message(entry),
            sensitivity_level=entry.sensitivity_level,
            domains=entry.privacy_tags[:],
            local_violation=action != "allow",
            local_action=action,
            content_hash=content_hash,
        )

    @staticmethod
    def _auto_detect_embeddings(policy: PrivacyPolicy):
        """Auto-detect sentence-transformers and create similarity function."""
        try:
            from .embeddings import get_similarity_fn
            return get_similarity_fn(must_not_share=policy.must_not_share)
        except ImportError:
            return None

    def _classify_message(self, entry: AuditEntry) -> str:
        """Classify message into semantic type without exposing content."""
        tags = entry.privacy_tags
        if "health" in tags:
            return "health_info"
        if "finance" in tags:
            return "financial_info"
        if "schedule" in tags:
            return "schedule_info"
        if "social" in tags:
            return "social_info"
        return "general"

    def start_epoch(self) -> None:
        """Begin a new epoch: rotate desensitizer salts and advance chain."""
        if self._desensitizer is not None:
            self._desensitizer.rotate_epoch()

    def end_epoch(self) -> None:
        """Close the current epoch, recording stats into DP continual counters."""
        if self._desensitizer is not None:
            self._desensitizer.end_epoch(self._violations, len(self._edges))

    def produce_report(self, apply_dp: bool = True) -> LocalAuditReport:
        """Generate the desensitized report to send to central auditor.

        If dp_config is set and apply_dp=True, applies differential privacy
        perturbation to the report before returning.
        """
        total = len(self._entries)
        leakage_rate = self._violations / total if total > 0 else 0.0

        # build merkle tree over raw entries for integrity commitment
        merkle_root = ""
        if self._entries:
            serialized = [e.model_dump_json() for e in self._entries]
            tree = MerkleTree(serialized)
            merkle_root = tree.root

        # collect all domains this agent touched
        all_domains: set[str] = set()
        for entry in self._entries:
            all_domains.update(entry.privacy_tags)

        # Layer 6: inject dummy edges if advanced desensitizer is active
        edges_to_report = self._edges[:]
        if self._desensitizer is not None:
            known_agents = list({e.to_agent for e in self._edges} | {self.agent_id})
            dummies = self._desensitizer.generate_dummies(known_agents, len(self._edges))
            edges_to_report.extend(dummies)

        # pseudonymize agent_id / user_id in the report itself
        report_agent_id = self.agent_id
        report_user_id = self.user_id
        if self._desensitizer is not None:
            report_agent_id = self._desensitizer.pseudonym_map.pseudonymize(self.agent_id)
            report_user_id = ""  # user_id never leaves container

        # cross-epoch commitment (if epoch chain is active)
        epoch_id = 0
        epoch_commitment = ""
        epoch_pseudonym_root = ""
        if self._desensitizer is not None:
            ec = self._desensitizer.get_epoch_commitment()
            if ec is not None:
                epoch_id = ec.epoch_id
                epoch_commitment = ec.commitment
                epoch_pseudonym_root = ec.pseudonym_root

        report = LocalAuditReport(
            agent_id=report_agent_id,
            user_id=report_user_id,
            edges=edges_to_report,
            total_interactions=total,
            violations_blocked=self._violations,
            pii_instances_redacted=self._pii_redacted,
            leakage_rate=leakage_rate,
            merkle_root=merkle_root,
            epoch_id=epoch_id,
            epoch_commitment=epoch_commitment,
            epoch_pseudonym_root=epoch_pseudonym_root,
            domains=sorted(all_domains),
        )

        # apply DP perturbation on aggregate stats before sending
        if apply_dp and self.dp_config is not None:
            report = dp_perturb_report(report, self.dp_config)

        return report

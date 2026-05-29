"""Tests for embedding-based semantic detection.

These tests are skipped if sentence-transformers is not installed.
The fallback behavior (n-gram similarity) is tested regardless.
"""

import pytest

from federated_agent_audit.schemas import PrivacyPolicy
from federated_agent_audit.local_auditor import LocalAuditor

try:
    from sentence_transformers import SentenceTransformer  # noqa: F401
    HAS_ST = True
except ImportError:
    HAS_ST = False


class TestFallbackWithoutEmbeddings:
    """These tests always run — verify n-gram fallback works."""

    def test_auditor_works_without_embeddings(self):
        policy = PrivacyPolicy(
            agent_id="a", must_not_share=["cancer"],
            acceptable_abstractions={"cancer": "health condition"},
        )
        auditor = LocalAuditor("a", "user", policy)
        from federated_agent_audit.schemas import AuditEntry
        entry = AuditEntry(
            trace_id="t1", agent_id="a",
            action="msg", output_text="patient has cancer",
            privacy_tags=["health"],
        )
        result = auditor.audit_outgoing(entry, to_agent="b")
        assert "cancer" not in result.output_text

    def test_similarity_fn_is_none_without_package(self):
        """If sentence-transformers not installed, _similarity_fn should be None."""
        if HAS_ST:
            pytest.skip("sentence-transformers is installed")
        policy = PrivacyPolicy(agent_id="a", must_not_share=["test"])
        auditor = LocalAuditor("a", "user", policy)
        assert auditor._similarity_fn is None

    def test_explicit_similarity_fn_used(self):
        """Passing a custom similarity_fn should override auto-detection."""
        call_count = 0

        def custom_sim(a: str, b: str) -> float:
            nonlocal call_count
            call_count += 1
            return 0.0

        policy = PrivacyPolicy(agent_id="a", must_not_share=["secret"])
        auditor = LocalAuditor("a", "user", policy, similarity_fn=custom_sim)
        assert auditor._similarity_fn is custom_sim

        from federated_agent_audit.schemas import AuditEntry
        entry = AuditEntry(
            trace_id="t1", agent_id="a",
            action="msg", output_text="some text here",
            privacy_tags=["general"],
        )
        auditor.audit_outgoing(entry, to_agent="b")
        assert call_count > 0  # custom fn was called


@pytest.mark.skipif(not HAS_ST, reason="sentence-transformers not installed")
class TestEmbeddingSimilarity:
    """These tests only run if sentence-transformers is available."""

    def test_import_and_create(self):
        from federated_agent_audit.embeddings import SentenceTransformerSimilarity
        sim = SentenceTransformerSimilarity()
        assert sim.cache_size == 0

    def test_precompute_caches(self):
        from federated_agent_audit.embeddings import SentenceTransformerSimilarity
        sim = SentenceTransformerSimilarity()
        sim.precompute(["cancer", "chemotherapy", "diagnosis"])
        assert sim.cache_size == 3

    def test_similar_texts_high_score(self):
        from federated_agent_audit.embeddings import SentenceTransformerSimilarity
        sim = SentenceTransformerSimilarity()
        score = sim("patient has a malignant tumor", "cancer diagnosis")
        assert score > 0.3  # related concepts should have decent similarity

    def test_unrelated_texts_low_score(self):
        from federated_agent_audit.embeddings import SentenceTransformerSimilarity
        sim = SentenceTransformerSimilarity()
        score = sim("patient has cancer", "the weather is sunny today")
        assert score < 0.3

    def test_identical_texts_high_score(self):
        from federated_agent_audit.embeddings import SentenceTransformerSimilarity
        sim = SentenceTransformerSimilarity()
        score = sim("cancer diagnosis", "cancer diagnosis")
        assert score > 0.99

    def test_get_similarity_fn_returns_callable(self):
        from federated_agent_audit.embeddings import get_similarity_fn
        fn = get_similarity_fn(must_not_share=["cancer"])
        assert fn is not None
        assert callable(fn)

    def test_auto_detect_in_auditor(self):
        policy = PrivacyPolicy(agent_id="a", must_not_share=["cancer"])
        auditor = LocalAuditor("a", "user", policy)
        assert auditor._similarity_fn is not None

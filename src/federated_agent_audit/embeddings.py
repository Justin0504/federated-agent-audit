"""Embedding-based semantic similarity using sentence-transformers.

Optional module — only loaded when sentence-transformers is installed.
Plugs into the existing `custom_similarity_fn` parameter of
`three_tier_detect()` in semantic_detector.py.

Usage:
    from federated_agent_audit.embeddings import SentenceTransformerSimilarity

    sim = SentenceTransformerSimilarity()
    sim.precompute(["cancer", "chemotherapy", "diagnosis"])
    score = sim("patient has a tumor", "cancer")  # ~0.7+

Or auto-detected by LocalAuditor when installed:
    # Just pip install sentence-transformers — no code changes needed
"""

from __future__ import annotations

from typing import Callable

import numpy as np

try:
    from sentence_transformers import SentenceTransformer

    _HAS_ST = True
except ImportError:
    _HAS_ST = False


class SentenceTransformerSimilarity:
    """Cosine similarity via sentence-transformers embeddings.

    Compatible with the `custom_similarity_fn` signature:
    `(text_a: str, text_b: str) -> float`
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
        if not _HAS_ST:
            raise ImportError(
                "sentence-transformers is required for embedding-based detection. "
                "Install with: pip install federated-agent-audit[embeddings]"
            )
        self._model = SentenceTransformer(model_name)
        self._cache: dict[str, np.ndarray] = {}

    def precompute(self, items: list[str]) -> None:
        """Pre-compute and cache embeddings for must_not_share items.

        Call once per policy. Subsequent calls to __call__ will use
        cached embeddings for known items, avoiding recomputation.
        """
        if not items:
            return
        embeddings = self._model.encode(items, convert_to_numpy=True)
        for item, emb in zip(items, embeddings):
            self._cache[item] = emb

    def __call__(self, text_a: str, text_b: str) -> float:
        """Compute cosine similarity between two texts.

        Uses cached embeddings when available, computes on-the-fly otherwise.
        """
        emb_a = self._get_embedding(text_a)
        emb_b = self._get_embedding(text_b)

        dot = float(np.dot(emb_a, emb_b))
        norm_a = float(np.linalg.norm(emb_a))
        norm_b = float(np.linalg.norm(emb_b))

        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def _get_embedding(self, text: str) -> np.ndarray:
        """Get embedding from cache or compute it."""
        if text in self._cache:
            return self._cache[text]
        emb = self._model.encode(text, convert_to_numpy=True)
        self._cache[text] = emb
        return emb

    @property
    def cache_size(self) -> int:
        return len(self._cache)


def get_similarity_fn(
    must_not_share: list[str] | None = None,
    model_name: str = "all-MiniLM-L6-v2",
) -> Callable[[str, str], float] | None:
    """Auto-detect and create embedding similarity function.

    Returns None if sentence-transformers is not installed,
    allowing the caller to fall back to n-gram similarity.
    """
    if not _HAS_ST:
        return None

    try:
        sim = SentenceTransformerSimilarity(model_name=model_name)
        if must_not_share:
            sim.precompute(must_not_share)
        return sim
    except Exception:
        return None

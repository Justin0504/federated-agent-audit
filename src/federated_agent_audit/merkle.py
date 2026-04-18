"""Minimal Merkle tree for audit commitment verification."""

from __future__ import annotations

import hashlib


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_pair(left: str, right: str) -> str:
    return _hash((left + right).encode())


class MerkleTree:
    """Binary Merkle tree over a list of data items."""

    def __init__(self, items: list[str]) -> None:
        if not items:
            raise ValueError("Cannot build tree from empty list")
        self._leaves = [_hash(item.encode()) for item in items]
        self._layers: list[list[str]] = [self._leaves[:]]
        self._build()

    def _build(self) -> None:
        layer = self._layers[0]
        while len(layer) > 1:
            next_layer: list[str] = []
            for i in range(0, len(layer), 2):
                left = layer[i]
                right = layer[i + 1] if i + 1 < len(layer) else left
                next_layer.append(_hash_pair(left, right))
            self._layers.append(next_layer)
            layer = next_layer

    @property
    def root(self) -> str:
        return self._layers[-1][0]

    def proof(self, index: int) -> list[tuple[str, str]]:
        """Return Merkle proof for item at index. Each element is (hash, side)."""
        if index < 0 or index >= len(self._leaves):
            raise IndexError(f"Index {index} out of range [0, {len(self._leaves)})")
        proof_path: list[tuple[str, str]] = []
        idx = index
        for layer in self._layers[:-1]:
            if idx % 2 == 0:
                sibling_idx = idx + 1
                side = "right"
            else:
                sibling_idx = idx - 1
                side = "left"
            if sibling_idx < len(layer):
                proof_path.append((layer[sibling_idx], side))
            else:
                proof_path.append((layer[idx], "right"))
            idx //= 2
        return proof_path

    @staticmethod
    def verify(item: str, proof: list[tuple[str, str]], root: str) -> bool:
        """Verify that item belongs to tree with given root."""
        current = _hash(item.encode())
        for sibling_hash, side in proof:
            if side == "right":
                current = _hash_pair(current, sibling_hash)
            else:
                current = _hash_pair(sibling_hash, current)
        return current == root

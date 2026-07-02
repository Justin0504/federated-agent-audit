"""The ``a2a.privacy/v1`` extension: privacy types for A2A Parts and agents.

A2A leaves ``Message.metadata`` / ``Part.metadata`` free-form and exposes a
``Message.extensions`` array, but defines no data-governance fields. We define a
small, concrete privacy type carried under a reserved metadata key, plus the
agent-side clearance an AgentCard would declare. These are *metadata*, not
content — the auditor may read them while never seeing the raw Part text.
"""

from __future__ import annotations

import hashlib
from typing import Optional

from pydantic import BaseModel, Field

# Reserved Part.metadata key (and Message.extensions URI) for the privacy type.
PRIVACY_EXTENSION_KEY = "a2a.privacy/v1"

# The sensitive categories the auditor treats as privacy-bearing (a single,
# configurable source of truth shared by the tagger and the inference detector).
# Broadened beyond health/finance/legal after the held-out benchmark surfaced
# leaks in these classes; deployments can extend this set for their domain.
SENSITIVE_CATEGORIES = frozenset({
    "health", "finance", "legal", "location", "biometric", "credentials",
    "employment", "education", "behavioral", "demographic",
})


def canonical_subject(identity: str, salt: str = "") -> str:
    """Deterministically derive a subject id from a canonical identity.

    An attested labeler derives ``data_subject`` this way so two messages about
    the same person map to the same id (they group, so inference is detected) and
    an adversary cannot *alias* a subject to dodge grouping without abandoning the
    canonical derivation --- which, in a forced-embed build, it cannot do without
    breaking attestation. ``salt`` scopes ids to a deployment.
    """
    return "subject:" + hashlib.sha256(f"{salt}:{identity}".encode()).hexdigest()[:16]


class PrivacyLabel(BaseModel):
    """Privacy type attached to a single A2A Part (``Part.metadata[KEY]``).

    Identifiers (``data_subject``, ``owning_principal``, ``allowed_recipients``)
    are opaque principal/subject ids such as ``"subject:alice"`` /
    ``"tenant:hospital"`` — governance metadata, never raw content.
    """

    data_subject: str = ""               # whom this Part is about
    owning_principal: str = ""           # who owns/controls it (a tenant)
    sensitivity: int = Field(default=0, ge=0, le=5)
    category: list[str] = Field(default_factory=list)        # declared domain(s)
    # Sensitive categories the *content gestures toward* even when its declared
    # category is benign — computed locally (the local auditor sees content);
    # only the category TAG travels to the center, never the content. This is the
    # signal the cross-tenant inference detector accumulates. E.g. a "schedule"
    # Part mentioning an oncology center carries inferred_categories=["health"].
    inferred_categories: list[str] = Field(default_factory=list)
    # Optional per-category likelihood ratio λ for this fragment's inference
    # evidence (a strong hint like "oncology center" > a weak one like "clinic").
    # Empty → the detector uses the default λ, reproducing uniform accumulation.
    inference_lambda: dict[str, float] = Field(default_factory=dict)
    purpose: list[str] = Field(default_factory=list)         # permitted uses
    allowed_recipients: list[str] = Field(default_factory=list)  # principals
    ttl_hops: int = Field(default=1, ge=0)   # max onward hops before it must stop
    # Stable datum identity assigned by the originating agent and preserved by
    # forwarding agents (even when they re-word the content). Lets hop/ttl
    # tracking follow a datum across paraphrasing — content hashing alone breaks
    # when a relay rephrases. Empty → fall back to the content hash.
    provenance_id: str = ""


class AgentClearance(BaseModel):
    """What a receiving agent is cleared for — an AgentCard declaration.

    Lets cross-tenant rules be checked from public metadata: an agent owned by
    ``principal`` is cleared to receive data for ``purposes`` (and optionally
    only ``categories``).
    """

    agent_id: str
    principal: str = ""                  # owning principal / tenant of this agent
    purposes: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)  # empty = any category


def label_part_metadata(label: PrivacyLabel) -> dict:
    """Render a label as the metadata fragment A2A would carry on a Part."""
    return {PRIVACY_EXTENSION_KEY: label.model_dump()}


def extract_label(metadata: Optional[dict]) -> Optional[PrivacyLabel]:
    """Extract a ``PrivacyLabel`` from a Part's metadata, if present."""
    if not metadata:
        return None
    raw = metadata.get(PRIVACY_EXTENSION_KEY)
    if raw is None:
        return None
    if isinstance(raw, PrivacyLabel):
        return raw
    return PrivacyLabel(**raw)


def label_part(part, label: PrivacyLabel):
    """Attach a privacy label to a Part's metadata in-place and return the Part."""
    md = dict(part.metadata or {})
    md.update(label_part_metadata(label))
    part.metadata = md
    return part

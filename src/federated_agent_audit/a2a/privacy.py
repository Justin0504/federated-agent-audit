"""The ``a2a.privacy/v1`` extension: privacy types for A2A Parts and agents.

A2A leaves ``Message.metadata`` / ``Part.metadata`` free-form and exposes a
``Message.extensions`` array, but defines no data-governance fields. We define a
small, concrete privacy type carried under a reserved metadata key, plus the
agent-side clearance an AgentCard would declare. These are *metadata*, not
content — the auditor may read them while never seeing the raw Part text.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

# Reserved Part.metadata key (and Message.extensions URI) for the privacy type.
PRIVACY_EXTENSION_KEY = "a2a.privacy/v1"


class PrivacyLabel(BaseModel):
    """Privacy type attached to a single A2A Part (``Part.metadata[KEY]``).

    Identifiers (``data_subject``, ``owning_principal``, ``allowed_recipients``)
    are opaque principal/subject ids such as ``"subject:alice"`` /
    ``"tenant:hospital"`` — governance metadata, never raw content.
    """

    data_subject: str = ""               # whom this Part is about
    owning_principal: str = ""           # who owns/controls it (a tenant)
    sensitivity: int = Field(default=0, ge=0, le=5)
    category: list[str] = Field(default_factory=list)        # e.g. ["health"]
    purpose: list[str] = Field(default_factory=list)         # permitted uses
    allowed_recipients: list[str] = Field(default_factory=list)  # principals
    ttl_hops: int = Field(default=1, ge=0)   # max onward hops before it must stop


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

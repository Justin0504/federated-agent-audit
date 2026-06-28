"""A minimal A2A-shaped message model — enough to carry and audit labeled Parts.

We don't depend on an A2A SDK; we model the fields the audit needs, named after
the spec (``Part`` with ``text`` + ``metadata``; ``Message`` with ``parts``,
roles, and sender/recipient identities). The privacy label rides in
``Part.metadata`` under ``a2a.privacy/v1`` (see ``privacy.py``).
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class Part(BaseModel):
    """An A2A content Part. ``text`` is raw content (never sent to the center);
    ``metadata`` carries the privacy label and other annotations."""

    text: str = ""
    metadata: Optional[dict] = None


class Message(BaseModel):
    """An A2A Message from one agent to another.

    ``from_principal`` / ``to_principal`` are the owning principals (tenants) of
    the sending and receiving agents — the trust boundary the audit reasons over.
    """

    message_id: str
    from_agent: str
    to_agent: str
    from_principal: str = ""
    to_principal: str = ""
    parts: list[Part] = Field(default_factory=list)
    context_id: str = ""        # A2A contextId — groups a conversation
    task_id: str = ""           # A2A taskId

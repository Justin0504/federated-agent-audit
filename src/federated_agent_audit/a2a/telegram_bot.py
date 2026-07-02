"""Telegram integration — a live multi-tenant agent group, audited center-blind.

A Telegram group is a natural multi-tenant agent system: each member's assistant
posts on their behalf, and every assistant holds its owner's private context. This
bot watches the group as the *internal channel*: each message is one agent's
output; the bot tags it locally, feeds a center-blind ``AuditSession``, and posts a
privacy alert when a member's assistant discloses another member's sensitive data,
or when benign posts accumulate enough for others to infer a sensitive attribute.

Mapping (per message from user ``u``, optionally @mentioning ``v``):
  principal            tg:u          (who is speaking)
  data_subject/owner   tg:v or tg:u  (who it is *about*)
  recipients           the group     (every other member's assistant)
  allowed_recipients   the subject's own principal (+ the group iff self-posted)
So sharing *your own* info is fine; sharing *another member's* sensitive info to
the group is a cross-tenant disclosure, and accumulating hints about anyone is a
cross-tenant inference. The auditor sees only hashes + tags, never the message.

Run:
    export TELEGRAM_BOT_TOKEN=...        # from @BotFather; add the bot to a group
    python -m federated_agent_audit.a2a.telegram_bot
"""

from __future__ import annotations

import os
import re
import time

from .auditor import A2AAuditor
from .session import AuditSession
from .tagger import PrivacyTagger

GROUP = "tg:group"
_MENTION = re.compile(r"@([A-Za-z0-9_]{3,})")


class GroupAuditor:
    """Accumulates a group's messages and yields newly-detected violations."""

    def __init__(self, tagger: PrivacyTagger | None = None) -> None:
        self._session = AuditSession(tagger=tagger)
        self._seen: set[tuple] = set()
        self._n = 0

    def observe(self, sender: str, text: str) -> list[dict]:
        """Record one group message; return any *new* violations (metadata only)."""
        self._n += 1
        m = _MENTION.search(text)
        subject = f"tg:{m.group(1)}" if m else f"tg:{sender}"
        owner = subject
        # self-posted info may reach the group; another member's info may not
        allowed = [subject] + ([GROUP] if subject == f"tg:{sender}" else [])
        self._session.observe(
            f"tg:{sender}", GROUP, text, message_id=f"m{self._n}",
            from_principal=f"tg:{sender}", to_principal=GROUP,
            data_subject=subject, owning_principal=owner,
            purpose=["chat"], allowed_recipients=allowed)

        result = A2AAuditor(clearances=[self._session._clearances[a]
                                        for a in self._session._clearances]
                            ).audit(self._session.messages)
        fresh = []
        for v in result.violations:
            sig = (v.type, v.data_subject, v.recipient_principal)
            if sig not in self._seen:
                self._seen.add(sig)
                fresh.append({"type": v.type, "subject": v.data_subject,
                              "detail": v.detail})
        return fresh


def _alert(v: dict) -> str:
    label = {"cross_tenant_disclosure": "cross-member disclosure",
             "cross_tenant_inference": "inferable from the pattern",
             "purpose_violation": "purpose violation",
             "ttl_violation": "over-forwarded"}.get(v["type"], v["type"])
    subj = v["subject"].replace("tg:", "@")
    return (f"⚠️ privacy: {label} about {subj}. "
            f"Flagged from metadata only — the auditor never read the message.")


def run(token: str | None = None) -> None:  # pragma: no cover - live loop
    import httpx
    token = token or os.environ["TELEGRAM_BOT_TOKEN"]
    api = f"https://api.telegram.org/bot{token}"
    auditor = GroupAuditor()
    offset = 0
    print("Sentinel is watching the group. Add me and start chatting.")
    with httpx.Client(timeout=40) as c:
        while True:
            try:
                r = c.get(f"{api}/getUpdates",
                          params={"offset": offset, "timeout": 30}).json()
            except Exception as e:  # noqa: BLE001
                print("poll error:", e)
                time.sleep(3)
                continue
            for upd in r.get("result", []):
                offset = upd["update_id"] + 1
                msg = upd.get("message") or {}
                text = msg.get("text")
                chat = msg.get("chat", {})
                sender = (msg.get("from", {}).get("username")
                          or str(msg.get("from", {}).get("id", "user")))
                if not text or chat.get("type") not in ("group", "supergroup"):
                    continue
                for v in auditor.observe(sender, text):
                    c.post(f"{api}/sendMessage",
                           json={"chat_id": chat["id"], "text": _alert(v)})


if __name__ == "__main__":  # pragma: no cover
    run()

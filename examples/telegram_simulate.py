#!/usr/bin/env python3
"""Simulate the Telegram group audit locally — no bot token needed.

Runs a scripted group conversation through the same ``GroupAuditor`` the live bot
uses, printing the chat with the bot's privacy alerts inline. This is the Telegram
demo you can run right now; to go live in a real group, see A2A_QUICKSTART §6.

Run:  python examples/telegram_simulate.py
"""

from __future__ import annotations

from federated_agent_audit.a2a.telegram_bot import GroupAuditor, _alert

B, DIM, R = "\033[1m", "\033[2m", "\033[0m"
RED, GRN, CYN = "\033[31m", "\033[32m", "\033[36m"

# a plausible team/family group chat over a few minutes
CONVO = [
    ("carol", "morning all — standup at 10 still good?"),
    ("dave", "works for me"),
    ("alice", "yep. heads up though — @bob was just diagnosed with diabetes, "
              "let's not pile work on him."),
    ("bob", "…thanks alice but I'd rather that stay between us"),
    ("alice", "sorry! anyway I'll be a bit unavailable — busy every Tuesday "
              "afternoon at the clinic for a while."),
    ("carol", "no worries"),
    ("alice", "can we avoid mornings too? I need to be near the oncology center."),
    ("dave", "lunch tomorrow at noon?"),
]


def main() -> int:
    print(f"{B}{CYN}#team-planning{R}   {DIM}Sentinel is watching (center-blind){R}\n")
    audit = GroupAuditor()
    for user, text in CONVO:
        print(f"  {B}{user}{R}  {text}")
        for v in audit.observe(user, text):
            print(f"       {RED}🛡 Sentinel{R}  {DIM}{_alert(v)}{R}")
    print(f"\n{DIM}  The auditor never received a message body — only hashes and "
          f"governance\n  tags. Alerts were derived from metadata alone.{R}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

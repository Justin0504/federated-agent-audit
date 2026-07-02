# 90-second demo recording — shot list + voiceover

Record the deployed URL (screen capture, 1280×800, no cursor clutter). Keep the
theme on dark. Voiceover lines in quotes.

**0:00 — the problem (10s).** Land on the dashboard hero.
> "Multi-agent systems leak data *between* agents — on internal channels your
> observability tool can't watch without ingesting raw prompts."

**0:10 — run live, real LLM (25s).** Click **run live · real LLM**. As it resolves:
> "These are real GPT-4o-mini agents. The triage agent just forwarded a customer's
> record to a marketing vendor." Point at the two violation cards, then the badge.
> "Caught — and *zero* content bytes reached the auditor."

**0:35 — the wedge, side by side (20s).** Switch to a scenario and open the
baseline strip. Point to the DLP column.
> "A DLP scanner reads the content and still misses this — there's no PII, only a
> pattern. We never read the content and catch it anyway."

**0:55 — the hard case (20s).** Select **Calendar / inference**. Show the two
benign messages and the inference card.
> "No single message leaked anything. But together, the group can infer a health
> condition. That's the threat as agents get smarter."

**1:15 — real environment (15s).** Cut to the Telegram group: a member posts
"@bob was just diagnosed…", the bot replies with a privacy alert.
> "Same engine, live in a Telegram group. Twenty minutes to add to any app.
> The auditor never reads a message."

End card: the URL + `pip install federated-agent-audit`.

## Tips
- Pre-warm the live endpoint once (first call is slow) before recording.
- Set `OPENAI_API_KEY` so "run live" works on the recorded instance.
- For the Telegram shot, have the bot already in a test group (see A2A_QUICKSTART §6).

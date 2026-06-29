# PMF Plan — built on the A2A privacy demo

Goal: validate whether the **same-container multi-agent data-privacy** product has
real pull, using `examples/a2a_privacy_demo.py` as the wedge. This is a
demand-validation plan (design partners + OSS adoption), not a fundraising plan —
F1 constraints mean the near-term win is *owning the problem*, not a company.

## 1. The product, in one sentence
Drop-in audit for multi-agent apps: see (and block) sensitive data crossing
between your agents and tools — **without shipping any content to a third party**.

## 2. Who has this pain *now* (ICP, narrowed)
Rank by acuteness, not size:

1. **Teams shipping multi-agent apps on LangGraph / CrewAI / AutoGen in a
   regulated or data-sensitive domain** (health, fintech, legal, HR). They
   already can't use LangSmith-style observability because it ingests raw
   prompts. This is the sharpest wedge: the *only* reason to pick us over the
   incumbent observability tool is the center-blind property.
2. **Platforms hosting third-party agents** (agent marketplaces, plugin stores)
   that must certify a third-party agent doesn't exfiltrate user data. Maps to
   the multi-tenant story + attestation.
3. **Internal platform/security teams** standing up an agent platform who need an
   audit trail of cross-agent data flow for compliance (EU AI Act Aug 2026).

Start with #1 — they feel it today and the demo speaks directly to them.

## 3. The hypothesis to test (falsifiable)
> Teams building multi-agent apps in sensitive domains will instrument their
> agent-to-agent calls with privacy labels **if** it takes < 30 min and gives
> them a content-free audit of cross-agent leaks they can show their compliance
> reviewer.

Kill criteria: if 8–10 ICP teams see the demo and none will spend 30 min wiring
it into a real app, the "drop-in" framing is wrong — pivot to the platform/cert
angle (#2) or the offline scanner angle (analyze existing traces, no
instrumentation).

## 4. The loop
1. **Show the 90-second demo** (`a2a_privacy_demo.py`) — Act 1 is the hook: a
   real leak caught, zero content shipped.
2. **Ask three questions** (below). Listen for unprompted intensity.
3. **Offer a design-partner integration**: you wire the auditor into *their*
   multi-agent app (their code, their container) and show them what it catches.
   The integration attempt is the real test — talk is cheap, wiring is signal.
4. **Measure** the signal in §6. Iterate the label ergonomics until wiring is
   < 30 min.

## 5. The three questions (don't pitch — diagnose)
- "When an agent in your system hands data to another agent or an external tool,
  how do you know today what it shared?" (Is the pain even felt?)
- "What stops you from using LangSmith/Langfuse for that?" (Is center-blindness
  the actual differentiator, or imagined?)
- "Who asks you to prove your agents don't leak customer data — and what do you
  show them?" (Is there a compliance forcing function with a deadline?)

## 6. Signal vs vanity
**Real signal:** a team wires it into a real app; it catches a leak they didn't
know about; they ask "can this *block*, not just flag?"; they ask about
on-prem/self-host; a compliance reviewer wants the report. GitHub issues from
strangers running it on their own system.

**Vanity:** stars, "cool project", "we'd totally use this" with no integration,
demo applause without a follow-up.

## 7. Why this beats the incumbents (the one defensible wedge)
LangSmith / Langfuse / Zenity / Capsule all sit in the path and **see raw
content**. For the ICP that legally cannot ship content out, that disqualifies
them. Our center-blind + federated design is the one property they structurally
lack — and it is exactly what the research proves. Don't compete on dashboards;
compete on "we never see your data and still catch the leak."

## 8. Concrete first steps (2 weeks)
1. Polish the demo into a 90-sec screen recording + a `README` quickstart that
   wires the auditor into a toy LangGraph app in < 30 min.
2. Line up **10 ICP conversations** (founder/eng at multi-agent startups in
   health/fintech; OSS LangGraph/CrewAI users via their Discords/issues).
3. Run the loop (§4). Convert ≥ 2 into design-partner integrations.
4. Decide at 10 conversations: pull is real (double down, pick one design
   partner to go deep) or not (pivot per §3 kill criteria).

## 9. The honest read
The research stands on its own (novel, hard, validated). The product is an
*option* the research creates — its value is realized only if §3 survives contact
with 10 real teams. Run that test cheaply before building more product.
Same-container is the beachhead; multi-tenant (the paper) is the expansion the
agent ecosystem grows into.

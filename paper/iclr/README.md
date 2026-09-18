# ICLR 2027 build

Measurement-first framing of the same work: the in-the-wild over-sharing result
and the capability inversion lead, the protocol extension is support. Content is
identical in substance to `paper/submission` (arXiv); only the ordering, the
main/appendix split, and the abstract differ.

- `make`        — anonymous PDF (what the submission form wants)
- `make check`  — fails if the body has crept past the 9-page main-text limit
- `make final`  — camera-ready, authors revealed

## Layout

Main text (pages 1–9): intro · threat model · `a2a.privacy/v1` · center-blind
auditor with the three formal statements · evaluation ordered
*measurement → baselines → evasion frontier → held-out (where we fail) →
external validation* · discussion · related work.

Appendix (exempt from the limit): proofs, A2A-MT construction, unit detection
results, DP sweep, tagger ablation, parameter sensitivity, and the mandatory
LLM-use statement.

## Before submitting

- [ ] Body at zero slack — page 9 is full. Anything added must displace something.
- [ ] Replace the GitHub URL with an `anonymous.4open.science` link (the anonymous
      build carries no author block, but the repo link would deanonymize).
- [ ] `make check` passes.

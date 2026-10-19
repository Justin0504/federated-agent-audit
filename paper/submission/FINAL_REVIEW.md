# Preprint final review — 2026-10-19

Scope: presentation and evidence review only. No new experiments, model calls,
methods, outcome selection or changes to frozen measurements.

## Checked
- Main narrative ends on page 8 including the cover; appendix starts on page 9.
  Full document: 46 pages. USC mark remains in the upper-right cover header.
- Active LaTeX input graph: 28 files, 66 unique labels and 38 referenced targets;
  no missing or duplicated targets. Final compiler log has no undefined references,
  undefined citations or overfull boxes. One automatic h-to-ht float adjustment
  is harmless; embedded PDF-version notices do not indicate missing resources.
- All pages inspected as rendered contact sheets; key live figures and the full
  matrix inspected at page resolution. Shared figure widths preserve aspect ratios.
- Structured 20-task counts, external 1,132-trajectory counts, and all eight live
  arms' task/attack/call counts checked against frozen JSON summaries. Numerical
  summaries are retained under campaign/evidence/preprint-review and formal-v31.
- Source archive compiled in an isolated staging directory by `make arxiv`;
  149 archive entries, CRC valid, every archived file matches the local source.
  release_manifest.json hashes match the PDF, ZIP and listed manuscript sources.

## Corrections made
- Historical prompt references now target historical evidence rather than live
  evaluation. Development stages are explicitly historical, not pending work.
- Replaced unsupported calibration, anonymity and unmatched-benchmark upper-bound
  claims with scoped statements. Token-match checks are not semantic guarantees;
  no whole-report DP guarantee follows from perturbing one metadata field.
- Removed the repeated external-replay figure from the appendix and cross-referenced
  the main figure. Kept appendix headings before their associated floating figures.
- Kept deployment, reuse, limitations and proposed research directions together on page 8.
- Rewrote the introduction contributions to include all three evidence groups and
  the formal eight-method comparison. Named Jetstream/A100 runtime, PostgreSQL,
  Qdrant and LangGraph while distinguishing controlled data from customer deployment.
- Added explicitly prospective evidence interoperability, authority-preserving
  recovery, and persistent-memory research targets without changing methods or data.
- Re-rendered all main-text pages and the appendix transition after this prose revision.

## Conclusions deliberately not claimed
No general semantic confidentiality, utility superiority, production readiness,
precise historical model ranking, or calibrated recipient-inference probability.
The live study uses one pinned 14B model and seed; 0/16 has Wilson upper bound
19.4%. Replay stops on first denial. Authored gate tasks have proxy labels and
nine unknown outcomes. Unknown token usage remains a lower bound, not zero cost.

This is a local build and evidence-consistency check, not certification of the
arXiv server's TeX environment or a guarantee of conference acceptance. Inspect
the server-generated preview before submitting. No upload or PR merge performed.

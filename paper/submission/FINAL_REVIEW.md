# Preprint final review — 2026-10-19

Scope: presentation and evidence review only. No new experiments, model calls,
methods, outcome selection or changes to frozen measurements.

## Checked
- Main narrative ends on page 8 including the cover; appendix starts on page 9.
  Full document: 43 pages. USC mark remains in the upper-right cover header.
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
- Removed the forced page break before deployment discussion: it now flows naturally
  across pages 7–8, filling the large page-7 gap without shrinking text or figures.
  Re-inspected both pages at full resolution; appendix still starts on page 9.
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

## Full-document layout pass
- Removed unnecessary appendix page breaks; preserved the cover/main boundary
  and full task matrix. Main narrative remains 8 pages; appendix begins on 9.
- Kept supplementary figures with their explanations and before References;
  fixed float-page spacing instead of stretching gaps between figures.
- Balanced the per-model tables as seven and four configurations, retaining
  all data rows and model marks; kept the section heading with the first table.
- Figure widths and aspect ratios are preserved, with shared diagram scaling
  and equal-width live outcome/cost panels; no font shrinkage or data changes.
- Rendered the final document; pages 1–34 are pixel-identical to the reviewed
  first reflow, and revised final appendix pages were inspected individually.
- Natural end-of-section and indivisible-figure whitespace is retained rather
  than filling it with stretched text, cropped graphics or unrelated floats.

## Cover density and model-coverage follow-up
- Replaced the sparse two-box teaser with separate business/release and metadata
  audit paths; the complete eight-arm table now includes total model calls.
  Teaser task/call counts checked against frozen formal-v31 analysis.
- Removed the pilot-only model logo from the generic architecture. Table 1 now
  separates model coverage by evidence type and identifies historical 11-config
  coverage separately; no claim of multi-model formal validation is introduced.
- Re-rendered and inspected all eight main pages. A float barrier keeps live
  figures before the deployment discussion, now together on page 8. This
  supersedes the earlier page-7 discussion placement. Appendix begins on 9;
  full PDF remains 43 pages. Source archive independently compiled and checked.

## Concrete architecture and dense cover follow-up

Figure 1 now carries a compact version of Figure 2 on its left: illustrative Tuesday visits and clinic location, local labels, and linked central checks. The separate business release path remains explicit. Figure 2 anchors icons to the existing worked example (Figure 9), report fields and the release interface, with model-source logos scoped to their respective studies. No new experimental evidence or deployment claim is introduced. The cover table preserves all eight frozen task, attack and call counts, with visual cost bars.

Rebuilt the manuscript and independently compiled the staged arXiv source package; 43 pages retained. Inspected rendered pages 1 and 3, shortened two labels to prevent card overflow, and found no overfull boxes or undefined references in the build log. ZIP CRC and embedded figure-source equality verified.

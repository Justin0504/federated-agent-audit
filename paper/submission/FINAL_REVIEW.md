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

## Contribution and experimental-design cover

Replaced the repeated cover method table with three explicitly separated evidence cards: 20 authored tasks/five controls, 1,132 archived traces/81 tasks, and 32 development-disjoint tasks/eight methods. Left panel names the metadata audit and structured release interfaces and visualizes their different inputs and outputs. Provider logos are scoped to each study. Counts and caveats are checked against core_narrative.tex; clean replay utility loss and live attack uncertainty remain visible. Full per-method results remain in the paper. No experiments or methods added.

The 43-page manuscript and staged arXiv source package compile; cover inspected at 1800px, with no text overlap or clipping. ZIP CRC and cover-source equality verified.

## Anchored icons and live bar chart

Removed A/B headings. Restored all eight live methods as horizontal completion-count bars (axis 0/8/16; denominator 32), aligned native attack counts (/16), and total-call lollipops. The left panel embeds calendar/location icons in concrete illustrative message cards, a report icon alongside actual field types, and a release gate with measured 8 allow/3 deny/9 unknown decisions from the separate 20-task study. No new evidence or experiments.

Rendered and inspected the final cover; corrected an intermediate TikZ macro collision before delivery. Final build remains 43 pages, with no overfull/undefined warnings. Independently compiled arXiv staging and ZIP CRC/source equality passed.

## Multi-agent topology and three-study bar charts

Reflowed cover labels into bounded agent/report cards, with separate schedule and location roles explicitly illustrative. Raw-text retention and metadata exposure remain stated; no federated-learning or anonymization guarantee is claimed. Replaced evidence summaries with denominator-scaled paired bars for authored and replay studies, and all eight live task-success bars. Replay utility loss remains visible. No new experiments.

Final cover rendered and inspected after splitting the overflowing subject/owner field. Manuscript remains 43 pages; source package independently compiles. ZIP CRC and embedded cover-source equality passed.

## Role-specific cover icons

Added six original editable SVG/PDF icons: calendar-badged agent, location-badged agent, label/hash report, graph inspection, versioned action, and release checklist. The cover uses 6--7mm icons with existing label spacing. No content or numerical changes. Final page 1 rendered and inspected; 43 pages retained, no overfull/undefined warnings. Staged source compiled; all six packaged icon PDFs verified byte-for-byte and ZIP CRC passed.

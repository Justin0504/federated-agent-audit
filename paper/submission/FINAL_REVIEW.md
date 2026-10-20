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

## Full-manuscript icon and layout pass

Unified semantic icons across the main pipeline and supplementary deployment, worked example, relay and attack diagrams; shared recovery/threat sources use the same set. Added an original runtime-agent icon with a code/tool badge. Small attack/relay icons use a 6mm optical target rather than the previous 4/5mm. Existing shared diagram widths and full-width statistical figures retained; the tall task matrix retains its intentional height constraint. No experimental content changed.

Rendered all 43 pages and reviewed five full-document contact sheets, then inspected modified pages 3, 12, 13, 38 and 39 individually. Main content ends on page 8; appendix starts on page 9. No observed overlap or clipping; 19,722 extracted words were within page bounds. No overfull boxes or undefined references in the build. Staged arXiv source compiled independently; archive CRC plus changed figure-source and all seven new-family icon byte-equality checks passed.

## Final claims audit and prospective social-group illustrations

Checked abstract, three introduction contributions and concluding deployment/limits against the frozen authored-task, archived-replay and formal-v31 evidence. Headline assertions passed: authored 20 tasks / 8 benign, marker release 2→0, unsupported release 4→0 and nine unknown; archived 1,132 trajectories, native attacks 165/808→0/808 with clean utility 198/324→179/324; live 256 executions / 32 tasks / eight methods, ungated utility 10/32 and native attacks 1/16, defended utility 0–12/32 and attacks 0/16. These are distinct execution modes, not pooled independent evidence. Main text retains the utility loss, native-predicate scope, unknown costs, single-model/seed limitation and absence of demonstrated general privacy or utility superiority. Metadata-only observation is not anonymization or federated model training. No new experiment ran.

Added Figures 12 and 13 on pages 20 and 23: a synthetic social-group composition storyboard and a proposed graph-view study. WhatsApp/Instagram-like names motivate a future setting; no tested connector, platform API access or production deployment is claimed. The 120 clusters / 1,440 episodes are proposed, not executed. The graph-linkage citation is prior work, not an attack result for our system. Added a self-contained offline `examples/social_audit_demo/` with four scripted views and an auxiliary-clue toggle; checked all controls and inspected the browser rendering. It performs no inference or privacy measurement.

Rendered all 45 pages and inspected five contact sheets plus both new figure pages at higher resolution. Main narrative still ends on page 8, appendix starts on page 9; new appendix sections and main-text cross-reference resolve. Corrected two small figure-width overfull warnings and an awkward wrapped annotation. Final build has no overfull boxes or undefined-reference warnings; extracted word boxes are inside page bounds. The staged arXiv source independently compiles. All 158 ZIP entries passed CRC and every packaged file matched its working source; required new figures, bibliography and main.bbl are present, and release-manifest hashes match. This verifies local completeness, not the arXiv server's compilation environment. Suggested category is cs.CR with cs.MA cross-list; author must inspect arXiv's generated preview and select the license at submission.

## Dense social storyboard and submission polish

Reworked Figures 12/13 with WhatsApp-like group bubbles, Instagram-like Story/DM cues, timestamps, three agent roles, explicit message composition and a highlighted graph fingerprint. These are authored conceptual elements, not official platform screenshots or tested integrations. Fixed a long summary-agent label and retained all five nodes in the window-view ablation, including an isolated node. The offline demo now has a three-stage narrative plus four graph views; its completed-evidence strip is separate from prospective conditions. Browser checks covered the three steps, all four graph modes and the auxiliary-clue toggle.

Final PDF remains 45 pages, main narrative eight pages. Abstract, contributions, measured results and conclusions are unchanged. Nine cited bibliography entries resolve; no overfull/undefined warnings in the final build. Changed figure pages inspected at full resolution; all pages rendered for layout review. The archive independently compiles and its 158 entries pass CRC and source-byte checks; release hashes match. Added figure/icon dependencies to the ordinary Makefile target so future figure edits cannot leave a stale main PDF. No new experiments, API calls or model inference were performed.

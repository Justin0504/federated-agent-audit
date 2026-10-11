# PoPETs 2027.3 pre-submission checklist

Target issue: **PoPETs 2027.3 — paper deadline 2026-11-30 AoE**, notification
2027-02-01. Double-blind. Template: `acmart` (`sigconf,anonymous,review`) +
`popets.sty` (already set up in this directory — do **not** modify the template
files: `acmart.cls`, `popets.sty`, `ACM-Reference-Format.bst`).

Build: `make` (→ `main.pdf`). Final state (2026-10-11, commit 6d7a889+): **11 pp
main body** (ethics section begins on p. 11; limit 12), 13 pp total, compiles
clean, 0 errors, all refs/citations resolve, no author metadata in the PDF, all
three mandatory sections present, repo link withheld. Eleven models / 3,168
trials; two frontier models; six-attacker tagger attack incl. query-access arm.

## A. Desk-review compliance (auto-reject if wrong) — mostly DONE
- [x] Uses the official PoPETs 2027 template, `[sigconf,anonymous,review]`.
- [x] No format manipulation (no `\vspace` hacks, no font swaps, CC-BY block kept).
- [x] Sections numbered (standard `\section`/`\subsection`).
- [x] Main body ≤ 12 pp (currently ~7 pp incl. refs — room to grow, see §F).
- [x] Mandatory `ethics`, `openscience`, `ai` environments present, exact titles,
      placed between the body and the references.
- [x] **First-page scope statement.** DONE: the intro now has an explicit paragraph
      (regulated-domain deployments; a named harm — over-shared SSN/diagnosis/
      account number under HIPAA/GDPR; deployable-safeguard framing tied to the 75%
      in-the-wild result). Verified present on page 1 of the compiled PDF.

## B. Anonymization (double-blind) — DONE except the repo link
- [x] Author block replaced with "Anonymous Author(s)" (via `anonymous` option).
- [x] No "Justin / Aojie Yuan / USC / aojieyua@usc.edu" anywhere in the PDF
      (verified; the only "yuan" hit is *Chi**yuan** Zhang* in a citation).
- [x] Own prior work, if cited, is referenced in the third person. (No self-cites
      currently — fine.)
- [x] **Repo link withheld during review.** The Open Science section states the
      public repo is withheld to preserve double-blind review and released with the
      camera-ready (PoPETs allows this with an explanation). If an anonymized
      snapshot is wanted instead, create it at https://anonymous.4open.science with
      id `a2a-mt-audit` and restore the `\url` line.

## C. Mandatory statements — DRAFTED, review the content
- [x] **Ethics**: no human subjects, synthetic data, public AgentLeak, defensive
      tool, dual-use considered, no IRB needed. → Read once; confirm it matches
      your framing and that you're comfortable with the dual-use paragraph.
- [x] **Open Science**: full system + benchmark released on acceptance, repro
      scripts, anonymized snapshot, will submit to artifact review. → Confirm you
      actually intend to open-source on acceptance (you do).
- [x] **AI use**: discloses (1) LLM in methodology (tagger gpt-4o-mini, LLM-authored
      scenarios, LLM recipient), (2) AI writing assistance + pre-submission review,
      (3) responsibility statement. → This is honest and complete; keep it.

## D. References — VERIFIED, one polish pass optional
- [x] No hallucinated refs — all 6 arXiv entries were verified by title/author
      against arXiv in a prior pass.
- [ ] ACM-Reference-Format prefers **full first names** ("Donald E. Knuth", not
      initials) and DOIs. Current bib compiles fine; for camera-ready, fill DOIs
      and expand any initials. Not required for the initial submission.

## E. Only-you actions (I can't do these)
- [ ] **Register the submission** on the PoPETs HotCRP (https://submit.petsymposium.org,
      issue 2027.3): title, abstract, topics, conflicts — do it days before 11-30.
- [x] Repo link withheld during review (§B); no anonymous snapshot needed.
- [ ] Final read-through of the compiled PDF for tone/claims you want to stand behind.
- [ ] Upload `paper/popets/main.pdf` before **2026-11-30 AoE**.
- [ ] (Optional) Post the arXiv version (`paper/submission/arxiv_submission.zip`) —
      PoPETs *discourages* preprints during review but does not forbid them; the
      PC ignores external identity info. Your call.

## F. Strengthening — DONE
Everything in the earlier list that was feasible has been run and is in the paper;
the one open arm (Claude Opus as tagger attacker, `run_frontier.sh`) needs
Anthropic credit and is optional.

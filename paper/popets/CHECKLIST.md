# PoPETs 2027.2 pre-submission checklist

Target issue: **PoPETs 2027.2 — paper deadline 2026-08-31 (firm)**, notification
2026-11-01. Double-blind. Template: `acmart` (`sigconf,anonymous,review`) +
`popets.sty` (already set up in this directory — do **not** modify the template
files: `acmart.cls`, `popets.sty`, `ACM-Reference-Format.bst`).

Build: `make` (→ `main.pdf`). Current state: **7 pp main body + refs, compiles
clean, zero overfull, all refs/citations resolve, author anonymized, all three
mandatory sections present.** Page limit is 12 (main body) — we have wide margin.

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
- [ ] **Register the submission** on the PoPETs HotCRP by the abstract/registration
      step (title, abstract, topics) — do this a few days before 08-31, not at the
      wire.
- [x] Repo link withheld during review (§B); no anonymous snapshot needed.
- [ ] Final read-through of the compiled PDF for tone/claims you want to stand behind.
- [ ] Upload `main.pdf` before 2026-08-31 AoE.
- [ ] (Optional) Post the arXiv version — PoPETs *discourages* preprints during
      review but the PC explicitly *ignores* external identity info, so it's not a
      desk-reject risk. Your call; if you post, use the `paper/submission/` build.

## F. Optional strengthening before 08-31 (we have 5 pp of headroom)
Not required to submit, but raises the odds. Pick what's feasible:
- [ ] Multi-model inference study beyond GPT (only OpenAI key on hand — at least add
      gpt-4o vs gpt-4o-mini spread, already partially present).
- [ ] Bigger held-out / author-independent benchmark run (more scenarios, tighter CIs).
- [ ] Expand the threat model + attestation into a fuller formal subsection (the
      TEE/forced-embed argument is currently compressed).
- [ ] A short "deployment/integration" paragraph making the in-container product
      concrete (ties to PoPETs' real-world-relevance requirement in §A).

---
**One-line status:** the PoPETs PDF is submission-shaped and desk-review-clean
today; the only hard blockers before 08-31 are the anonymized repo link (§B) and
registering/uploading on HotCRP (§E). Everything else is polish.

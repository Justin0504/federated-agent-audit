# Figure brief for Codex — *Agents Over-Share* (PoPETs 2027.3 submission)

You own every figure in this paper: five that exist and need raising, seven that do
not exist yet (three for the body, four for the appendix), and a small set of
demonstration graphics that will be finished by hand in Figma. This file is the
whole brief. Read it top to bottom once, then `figstyle.tex` and `fig_pipeline.tex`
so your first figure looks like it came from the same hand as the existing ones.

Everything is in this repository. Nothing in this brief requires an API key, a GPU,
or a model call: every number you will draw is already measured and lives in
`figure_data.json` (this folder) with its source line in
`benchmarks/a2a_mt/RESULTS.md`. `check_data.py` (this folder) recomputes every
trace-derived number in that file from the raw traces and exits non-zero on any
mismatch — run it first, and again before you call a figure done. `snapshots/`
holds PNGs of the five existing figures as they are today, so you can see the
starting point without compiling anything. **Never retype a number from memory; never change
one.** If a number you need is missing from `figure_data.json`, it is in
`RESULTS.md`; if it is not there either, it does not exist and you must not invent
it.

---

## 0. The paper in six sentences (so the figures argue the right thing)

Agents built by different organisations hand work to each other over the A2A
protocol, which has no field for whom a datum concerns, who owns it, or who may
receive it — so cross-organisation privacy leakage is not even expressible, let
alone auditable. We add that typing (`a2a.privacy/v1`) and audit it from a central
service that **never sees message content**: each tenant labels and hashes locally
and ships only a one-way hash plus labels. The measurement that motivates all of it,
over **eleven models and 3,168 hand-offs**: agents put a subject's identifiers or
sensitive attributes into messages bound for an outside company **96%** of the
time, and *instructing them buys redaction, not privacy* — handed the record's own
policy, Claude Opus 4.8 stops pasting identifiers (44→1%) and barely changes what it
says about the person (40→36%); pooled, 68% still leak. The one exception sharpens
the rule: GPT-4o, told which *categories* to omit, behaves like every other model
(attributes 96→78%), and withholds only when told the *recipient is not permitted*
(→14%) — the instruction that works names the recipient, not the tokens. The thesis
is therefore that privacy is a property of what the recipient can **infer**, not of
which tokens a message contains; every token-level defence we test (the agent's own
redaction, Presidio, Llama Guard, a keyword tagger under attack) fails the same way,
and a tagger that judges meaning does not (evaded 4–7% vs 55–70%).

**The one thing no figure may get wrong:** nothing content-bearing is ever drawn
crossing the trust boundary. That is the paper's central guarantee (Lemma 1), and a
figure that blurs it is worse than no figure.

---

## 1. Inventory and priority

| # | figure | file | where | status | priority |
|---|---|---|---|---|---|
| 1 | federated, center-blind pipeline | `fig_pipeline.tex` | body, Intro | exists — raise | B |
| 2 | worked example, verbatim output | `fig_example.tex` | body, §Auditor | exists — raise | B |
| 3 | inference threshold curve | `fig_gain.tex` | body, §Auditor | exists — raise | C |
| 4 | redaction vs privacy across 11 models | `fig_redaction.tex` | body, §6.2 | exists (first pass) — raise | **A** |
| 5 | two opposing trends | `fig_trends.tex` | body, Discussion | exists — raise | B |
| 6 | **deployment architecture** | `fig_deploy.tex` | body, §Auditor or Discussion | **missing** | **A** |
| 7 | threat model: principals, adversary, trust | `fig_threat.tex` | body, §Threat model | missing | A |
| 8 | anatomy of a privacy label | `fig_label.tex` | body, §Extension | missing | B |
| 9 | tagger-attack protocol + oracle loop | `fig_attack.tex` | appendix (body if it fits) | missing | B |
| 10 | relay chain: provenance survives, exposure does not decay | `fig_relay.tex` | appendix | missing | C |
| 11 | the instruction ladder (four prompts → four numbers) | `fig_conditions.tex` | appendix | missing | C |
| 12 | adaptive-evasion strategy space | `fig_evasion.tex` | appendix | missing, needs one script run | C |
| D1–D3 | demonstration graphics for Figma | `demo/` | README, talks, arXiv preview | missing | after A/B |

Do them in this order: **6, 4, 7, 1, 2, 5, 8, 9, 3, 10, 11, 12, then the demos.**
Priority A figures are the ones a reviewer will remember; C figures are nice to have
and must not cost body pages.

**Page budget.** The PoPETs build (`paper/popets/`) has a 12-page body limit and is
at 11. Figures 6, 7, 8 go into the body and must together cost **at most one
column-width page**. Figures 9–12 go into the appendix (`appendix.tex`), which does
not count. If a body figure pushes the ethics section past page 12, shrink the
figure, not the text.

---

## 2. The design system — use it, do not invent one

`figstyle.tex` holds the entire visual language. `\input` it; never redefine a
colour or style inside one figure. The four builds share these files; a local
override silently diverges the papers.

**Colour carries meaning, reused identically in every figure.** A reader learns it
once in Figure 1 and must not relearn it in yours:

| token | hex | meaning |
|---|---|---|
| `figrose` | `#B8405C` | the data subject's content — the thing at risk; **never crosses** |
| `figindigo` | `#3D5A9E` | governance metadata (labels) — what we add |
| `figamber` | `#B0662A` | what actually crosses the trust boundary |
| `figemerald` | `#2C7A58` | verified / detected / safe |
| `figink` `#1B2733` / `figslate` `#6B7885` | structure / secondary type |
| `figrule` `#D8DEE4` / `figwash` `#F4F6F8` | borders / fills |

Values are spread so figures survive greyscale printing; rose and indigo land at
almost the same grey, so **separate series by hue and dash pattern**, never hue
alone (see `fig_redaction.tex` and `fig_trends.tex` for the pattern).

**Styles** (all defined in `figstyle.tex`): `figzone` (rounded container),
`fignum=<colour>` (numbered disc badge), `figtitle` / `figlabel` / `fignote` /
`figmono` (type scale), `figchip=<colour>` (a labelled pill), `figflow` (grey arrow),
`figcross` (amber arrow — for things that cross), `figbound` (the dashed trust
boundary), `figseries`, `figdot`, `figgrid`, `figaxis`, `figtick`, `figseriestag`
(chart primitives).

**Icons** — ours, 24×24 grid, 1.75 stroke, round caps, `stroke="currentColor"`, no
third-party licence. `\icon{name}{colour}{height}`, e.g. `\icon{attest}{emerald}{5mm}`:

`agent` `alert` `attest` `blind` `boundary` `content` `detector` `hash` `infer`
`tag` `tenant` `ttl`

Render icons at **4–6 mm**; at 3 mm they read as noise. A new icon goes in
`icons/` as an SVG on the same grid, then `python icons/build_icons.py` (needs
`rsvg-convert`). Icons you will probably want to add: `reader` (a judge model),
`attacker`, `key` (the build-pinned signing key), `policy` (a document with a rule),
`relay` (two chevrons).

---

## 3. Hard constraints (every figure)

- **Output is TikZ**, `\input` from `paper/figures/`. Not an image, not an SVG
  include. Fonts must be the body font.
- Column-width figures use `\begin{figure}[t]`; full-width ones use
  `\begin{widefigure}[t] … \end{widefigure}` (maps to `figure` in one-column
  builds and `figure*` in two-column builds — a wide figure inside plain `figure`
  is crushed in PoPETs).
- Wrap the picture in `\resizebox{\linewidth}{!}{…}` as every existing figure does.
- **Must compile in all four builds**: `paper/{submission,popets,sp,iclr}` — each
  has a `figures` symlink, so `\input{figures/<name>}` resolves everywhere.
- Greyscale-safe. No overfull box over 15 pt. No new packages.
- Every number comes from `figure_data.json` / `RESULTS.md`. The closed-form
  curves (Figure 3) are exact, not eyeballed — do not "tidy" them.
- Captions: one sentence of what is shown, then what the reader should take from
  it. Captions in this paper carry the argument; see the existing five.
- A figure that is referenced in the text keeps its `\label`; the text already says
  `Figure~\ref{fig:redaction}` etc. New figures: use the labels given below so the
  text can be wired without renaming.

---

## 4. How to iterate (fast) and verify (always)

```sh
cd paper/figures
# 2-second preview of one figure, no paper rebuild
sed 's|\\input{\\figfile}|\\input{fig_deploy}|' _preview.tex > _prev_fig_deploy.tex
tectonic _prev_fig_deploy.tex && open _prev_fig_deploy.pdf
# raster for a quick look / for this brief's screenshots
pdftoppm -r 110 -png _prev_fig_deploy.pdf /tmp/fig_deploy

# then the real builds (all four must be clean)
for d in submission popets sp iclr; do (cd ../$d && tectonic main.tex 2>&1 | grep -iE "^error|undefined|overfull.*[2-9][0-9]pt"); done
# PoPETs body must still end on or before page 12 (the ethics heading marks the end)
for pg in 11 12 13; do pdftotext -f $pg -l $pg ../popets/main.pdf - | grep -qiE "^(Ethical considerations|Ethics)" && echo "body ends p.$pg"; done

# export cropped PDF + SVG (Figma takes the SVG) after adding the name to FIGURES in export.py
python export.py
```

`_preview.tex` defines `\ext`, a fake `lem:blind` label and `\figfile`; copy its
pattern if a new figure needs another macro from the paper.

---

## 5. The figures, one by one

### Figure 6 — `fig_deploy.tex` — deployment architecture — **highest value**

**Why.** Figure 1 is the *conceptual* flow (content → label → hash → boundary →
detectors). A reader who wants to deploy this cannot tell from it what process
holds what, what is signed, what is stored, or what a malicious centre could learn.
That is the gap. Do **not** restate Figure 1.

**Must answer at a glance**

1. **Inside a tenant:** the application's agents, plus one *build-pinned*
   component — `PrivacyTagger` + local `A2AAuditor` + `A2AAttestor` — that is the
   only thing that reads content. Draw the pinned component as a sealed box; the
   signing key `k_B` lives inside it and nowhere else (use `attest` + a new `key`
   icon).
2. **What the tenant emits:** center-view edges — `h(content)` + the
   `a2a.privacy/v1` label + principals — and a signature
   `σ = Sign_{k_B}(h(E))` over the edge set. Amber, because it crosses.
3. **What crosses the boundary:** exactly those two things. Content (rose) stops at
   the boundary. Make the stop visible — a rose lane that ends at the dashed line.
4. **The centre:** `A2AVerifier` checks σ against the trusted build fingerprint;
   the four detectors *re-run* over the metadata graph (the centre does not trust
   the tenant's verdicts); a violations store. Show explicitly that it stores
   **no content** (a `blind` icon on the store is enough).
5. **Multi-tenant:** at least two tenants reporting to one centre; the inference
   detector accumulates fragments *across* tenants about one subject.
6. **Single-tenant projection** (small inset or callout): set every principal
   equal and this collapses to one organisation auditing its own agents — the
   deployable product today, which currently has no picture at all.

**Real names, so labels match the artifact**

| component | file | role |
|---|---|---|
| `PrivacyTagger` | `src/federated_agent_audit/a2a/tagger.py` | reads content locally, emits only tags |
| `A2AAuditor` | `a2a/auditor.py` | desensitises to center-view edges; runs the 4 detectors |
| `A2AAttestor` / `A2AVerifier` | `a2a/attest.py` | signs / verifies that a report came from the pinned build |
| `AuditSession` | `a2a/session.py` | the ~3-line integration surface an app calls |
| audit service | `a2a/service.py` | FastAPI centre: `POST /api/v1/a2a/report`, `GET /api/v1/a2a/violations` |

Four detectors: cross-tenant disclosure · purpose limitation · hop/TTL ·
cross-tenant inference.

**Form.** `widefigure`, roughly 2 : 1. Left two-thirds: two tenants stacked; right
third: the centre. One dashed `figbound` down the middle. Label: `\label{fig:deploy}`.

```
┌─ tenant:hospital ────────────────────────────┐ ┊ ┌─ audit service (center) ──────────────┐
│  agents  ──content──▶ ┌─ pinned build B ───┐ │ ┊ │ A2AVerifier ──σ ok? (fingerprint of B) │
│  (app)                │ PrivacyTagger       │ │ ┊ │      │                                  │
│                       │ A2AAuditor (local)  │─┼─┊─▶ metadata graph  ──▶ 4 detectors ──▶ violations
│                       │ A2AAttestor  🔑k_B  │ │ ┊ │ (h, label, principals; no content)  store ⊘content
│                       └─────────────────────┘ │ ┊ │                                          │
└───────────────────────────────────────────────┘ ┊ │   inference detector accumulates         │
┌─ tenant:clinic ───────────── (same) ─────────┐ ┊ │   fragments ACROSS tenants per subject   │
│  … ──▶ [ pinned build B ] ──(h, ℓ, σ)────────┼─┊─▶                                          │
└───────────────────────────────────────────────┘ ┊ └──────────────────────────────────────────┘
      rose lane (content) ends HERE ▲            trust boundary (figbound)
  inset: single tenant = all principals equal → one org auditing its own agents
```

**Wiring.** `\input{figures/fig_deploy}` right after the four-detector `enumerate`
in §Auditor (the list ending "…we ground this in the bound below."), and add one
sentence there: *"Figure~\ref{fig:deploy} shows what runs where in a deployment."*
In `paper/submission/main.tex` that list is in `\section{The center-blind auditor
and detectors}`; the same anchor text exists in all four builds.
Suggested caption opening: *"What runs where. The only component that reads content
is the build-pinned tagger/auditor inside each tenant; what leaves it is a hash, a
label and a signature …"*

### Figure 4 — `fig_redaction.tex` — raise it

It exists (first pass: eleven columns of vertical dumbbells, see
`export/fig_redaction.pdf`). Data is final. What to push on:

- The eye should land on two things: **the rose segments get longer to the right
  and reach ~0 at both frontier columns**, and **the two frontier columns
  disagree on indigo** (Opus 40→36 vs GPT-4o 96→14). Right now every column has
  equal weight. Options: a faint `figwash` band behind the two frontier columns;
  slightly heavier stroke on those four segments; the endpoint labels (already
  there: 0/14, 1/36) in `\small` rather than `\scriptsize`.
- The x-labels at 11 columns are tight at column width; consider `\tiny` size
  labels or rotating the size line. Do not drop the sizes — ordering by size is
  the point.
- Keep the caption's substance (it was reviewed); you may shorten it.

### Figure 7 — `fig_threat.tex` — threat model

Column width. Three principals as three `figchip`s around one `Part`: **data
subject** (whom it is about), **owning principal** (who controls it), **agent
principal** (the AgentCard identity). An adversary agent of another tenant with its
three capabilities as three short arrows: **A1** reads and infers beyond what is
stated · **A2** paraphrases / splits / re-routes · **A3** mislabels its own Parts
(dishonest sender). Trust assumptions as a small legend: **T1** centre-blind ·
**T2** honest-but-curious peers · **T3** A2A transport is given. Then one line at
the bottom: *A1, A2 defeated by construction (detectors key on labels, not text);
A3 closed by forced-embed attestation (Prop. 1), residual = key exfiltration (TEE
closes it) and sub-threshold leakage.* `\label{fig:threat}`. Budget: ≤ 60 mm tall.

```
            ┌──────────── Part ────────────┐
 subject ◯──│ "…oncology infusion…"        │──◯ owning principal (tenant:hospital)
 (whom)     └──────────────────────────────┘      (who controls it)
                        │ routed to
                        ▼
            agent principal (AgentCard)  ── of another tenant ──▶  ADVERSARY
                                              A1 reads + infers   A2 paraphrases/splits/re-routes   A3 mislabels own Parts
 trust: T1 centre-blind · T2 honest-but-curious peers · T3 transport given
 ─────────────────────────────────────────────────────────────────────────────
 A1, A2: defeated by construction (detectors key on labels, not text)
 A3: closed by forced-embed attestation (Prop. 1); residual = k_B exfiltration (TEE) · sub-threshold leakage
```

**Wiring.** `\input{figures/fig_threat}` immediately before
`\paragraph{Closing A3 with forced-embed attestation.}`; reference it from the
Principals paragraph: *"(Figure~\ref{fig:threat})"* after "three roles".

### Figure 8 — `fig_label.tex` — anatomy of a privacy label

Column width, small. One `Part` with its `metadata["a2a.privacy/v1"]` drawn as a
labelled record: `subject`, `owner`, `sensitivity ∈ [0,5]`, `category[]`,
`inferred_categories[]`, `purpose[]`, `allowed_recipients[]`, `ttl_hops`,
`provenance_id`. Thin connectors from fields to the detector they feed:
subject/owner/allowed_recipients → **disclosure**; purpose (+ `AgentClearance`) →
**purpose limitation**; `ttl_hops` + `provenance_id` → **hop/TTL**;
`inferred_categories` → **inference**. Emphasise the two fields the paper calls
central: `inferred_categories` (computed locally; only the tag travels) and
`provenance_id` (survives re-wording; a content hash would not). Values shown are
opaque ids: `subject:alice`, `tenant:hospital`. `\label{fig:label}`. ≤ 55 mm tall.

```
 Part.metadata["a2a.privacy/v1"]                         detector it feeds
 ┌───────────────────────────────────────┐
 │ subject: subject:alice                │──┐
 │ owner: tenant:hospital                │──┼──▶ cross-tenant disclosure
 │ allowed_recipients: [tenant:hospital] │──┘
 │ sensitivity: 4                        │──▶ (threshold τ for disclosure)
 │ category: [health]                    │
 │ purpose: [care]        + AgentClearance ──▶ purpose limitation
 │ ttl_hops: 2            ┐              │
 │ provenance_id: d-7f3a  ┘──────────────│──▶ hop/TTL   (survives re-wording; a hash would not)
 │ inferred_categories: [health]  ★      │──▶ cross-tenant inference (computed locally; only the tag travels)
 └───────────────────────────────────────┘
```

**Wiring.** `\input{figures/fig_label}` after the sentence ending "(a content hash
breaks the moment a relay rephrases)." at the end of §Extension; add
*"Figure~\ref{fig:label} shows which field feeds which detector."*

### Figure 9 — `fig_attack.tex` — the tagger-attack protocol (Exp 19)

Appendix, column width (promote to body only if it costs nothing). The scoring
logic is the thing to draw, because the text spends a paragraph on it:

```
attacker model  ──writes──▶  hand-off  ──▶  reader model (different family): "does it convey the fact?"  → conveyed?
                                        └─▶  auditor running tagger under test → content-derived violation? → caught?
EVADED  =  conveyed ∧ ¬caught        (saying nothing is not evasion)
```

Three arms as three rows: **black-box** (attacker told only "a privacy filter
screens the message"), **white-box** (attacker handed the lexical tagger's 141-term
lexicon), **oracle** (attacker learns the LLM tagger's verdict, up to 3 rewrites —
draw the loop). Beside each arm the pooled result as two small bars, lexical vs LLM
tagger: 55% / 4%, 70% / 7%, 39% / 16% (lexical / LLM evaded). Numbers in
`figure_data.json → attack`. `\label{fig:attack}`.

### Figure 10 — `fig_relay.tex` — the relay chain

Appendix. Four hops, `ttl_hops = 2`, so hop 3 is over budget: draw the TTL alarm
firing at hop 3 (`ttl` + `alert` icons, emerald). Above the chain, a small line
chart of exposure per hop for the three models (`figure_data.json → relay`): two
stay at 100% through hop 4, the third declines 94→79. The one-line takeaway in
the caption: *provenance survived all 144 paraphrase chains and the TTL violation
fired in 144/144 with zero content at the centre; exposure does not decay.*
`\label{fig:relay}`.

### Figure 11 — `fig_conditions.tex` — the instruction ladder

Appendix. Four stacked prompt cards (verbatim wording is in `appendix.tex`
§Prompts; show the *delta* each adds, not the whole prompt): permissive →
invitation removed → categories forbidden → full policy stated. Beside each, the
pooled leak rate with its cluster interval: 96 [93,98] · 98 [96,99] · 82 [78,86] ·
68 [63,73], and the identifier / attribute split (78/89 · 82/89 · 36/80 · 35/60).
This is Table 2 as a picture; it earns its place only if the reader sees at a
glance that the identifier column collapses and the attribute column does not.
`\label{fig:conditions}`.

### Figure 12 — `fig_evasion.tex` — the adaptive-evasion space (optional)

Appendix. A scatter of strategies: x = inference gain `g` the recipient walks away
with, y = detected or not (or detection score), with the policy threshold `δ = 0.3`
as a vertical rule. The claim to make visible: **no undetected point lies right of
δ** (max undetected gain 0.29992). Then three small ghosted panels for the
ablations (− attestation q=0.4 → 33.9% harmful evasions; q=0 → 53.6%; − canonical
subject ids → 16.3%). The per-strategy rows are not stored; regenerate them (no
model calls, seconds):

```sh
python benchmarks/a2a_mt/a2a_adaptive.py --trials 20000 --seed 0
```

If the script does not print per-strategy rows, add a `--dump path.jsonl` flag
that writes `(config, n, gain, detected)` per strategy — a 10-line change — and
keep the summary numbers identical to Table 6 before you draw anything.
`\label{fig:evasion}`.

### Figures 1, 2, 3, 5 — raise what exists

| figure | the one weakness to fix |
|---|---|
| 1 `fig_pipeline` | Reads as a left-to-right flowchart. The *claim* is that one lane (rose, content) dies at the boundary while another (amber, hash+label) passes through. Make that asymmetry the first thing the eye lands on, not something the caption explains. |
| 2 `fig_example` | Three panels of equal weight; the reader does not know where to start. Panel (c) is the punchline — a live frontier model recovers the withheld attribute from exactly these two messages — and should look like it. |
| 3 `fig_gain` | Correct and inert. The interesting fact is that *one* high-specificity hint clears a line that normally takes two — currently a small amber dot. The curve is closed-form (posterior at k = 0..4 is exactly 0.10 / 0.25 / 0.50 / 0.75 / 0.90 for p₀ = 0.1, λ = 3; fire line at 0.4). |
| 5 `fig_trends` | The headline-shaped measurement drawn as a 40 mm line chart. Two trends crossing in opposite directions is the whole argument; the crossing deserves width. Tier means are in `figure_data.json → trends`. |

Constraint on all four: **the numbers are measured and must not change.**

---

## 6. Demonstration graphics for Figma (`demo/`)

These are not paper figures. They are for the README, the arXiv/social preview,
and talks, and they will be finished by hand in Figma, so deliver them as
**SVG** (via `python export.py` for anything drawn in TikZ, or authored directly as
SVG) plus a one-paragraph note per file saying what is meant to be adjusted by
hand. Keep the palette; fonts may switch to Inter or IBM Plex Sans in Figma.

- **D1 `demo/two_views.svg` — "what the tenant sees / what the centre sees".**
  Left: a real hand-off message (take the verbatim one from Figure 2(a)) with the
  identifiers and the diagnosis highlighted in rose. Right: the exact center-view
  edge for it — hash, principals, label — with **no rose anywhere**. Below:
  "418 bytes, flat across a 1024× range of message size" (§6.7). This is the
  single image that explains the system to someone with ten seconds. Hand-adjust:
  text wrapping, the highlight boxes.
- **D2 `demo/label_json.svg` — the A2A message with the extension.** A
  syntax-highlighted JSON of one `Message` → `Part` → `metadata["a2a.privacy/v1"]`
  block, the nine fields called out with thin leader lines in indigo. Use the real
  field names from `src/federated_agent_audit/a2a/`. Hand-adjust: leader-line
  routing.
- **D3 `demo/hero.svg` — the arXiv / README hero.** The eleven-model redaction
  figure (Figure 4) re-set wide (16 : 9) with the headline as a title line:
  *"Instructions buy redaction, not privacy."* and the two frontier columns called
  out. Hand-adjust: typography, title placement.
- (optional) **D4 `demo/dashboard.svg`** — a mock of the audit service's
  violations view (`GET /api/v1/a2a/violations`): a table of violations with
  type, subject id, principals, hop count — and visibly no content column. Only if
  time allows.

Design-system preview pages for review already exist in `designsystem/`
(`palette.html`, `icons.html`, `figures.html`; regenerate with
`python designsystem/build.py`).

---

## 7. Pitfalls we have already hit (so you do not)

- `\citep` exists only in the natbib builds (popets, iclr); submission and sp use
  `\cite`. Figures should not cite at all — put citations in the caption text of
  the body, not in TikZ nodes.
- acmart does not accept `itemize[...]` options; `enumerate[leftmargin=…]` is fine.
- A `\begin{figure*}` must be matched by `\end{figure*}`; use `widefigure`, which
  does that per build.
- The `_preview.tex` harness defines `\ext` and a fake `lem:blind`; a figure that
  references another label (`\ref{prop:attest}`) will show `??` in preview and be
  fine in the paper — do not "fix" it in the figure.
- `\foreach` over a `\def`-ed list with `\\` inside braces works (see
  `fig_redaction.tex`); a bare `\\` inside a `\foreach` list does not.
- Overfull boxes under 15 pt are tolerated (acmart tables already have a few);
  anything larger is yours to fix.
- The PoPETs page count is checked by where the ethics heading lands, not by
  total pages (appendix and references do not count).
- `export.py` needs `tectonic` and `pdf2svg`; `icons/build_icons.py` needs
  `rsvg-convert` (`brew install librsvg`).

## 8. Acceptance checklist (run it per figure, then once at the end)

- [ ] Nothing content-bearing crosses the trust boundary anywhere
- [ ] Colours from `figstyle.tex` only, with their established meanings; new
      styles/icons live in `figstyle.tex` / `icons/`, not inline
- [ ] Icons 4–6 mm; no new visual language invented
- [ ] Every number matches `figure_data.json` / `RESULTS.md`; `python codex_pack/check_data.py` says ALL GOOD
- [ ] Compiles clean in all four builds; no unresolved refs; no overfull > 15 pt
- [ ] Legible in greyscale (print one page to grey and look)
- [ ] PoPETs body still ends on or before page 12
- [ ] New figures use the `\label`s above and are `\input` at the places named
      in §1 (wire the body text with one `Figure~\ref{…}` sentence each; do not
      rewrite paragraphs)
- [ ] `python export.py` updated and run; `export/*.svg` fresh
- [ ] A figure that has not been read by someone who did not draw it is not done:
      for each, write one line saying what a reader learns that they could not
      learn from the text alone. If you cannot write that line, cut the figure.

---

## 9. Where to read more

- `paper/figures/README.md` — the figure system
- `paper/submission/main.tex` — the arXiv build (one column, easiest to read);
  §Threat model, §Extension, §Auditor, §6.2 (`sec:instr`), §Discussion
- `paper/figures/appendix.tex` — verbatim prompts, ground-truth rules, per-model
  table, repro commands
- `benchmarks/a2a_mt/RESULTS.md` — **the authority for every number**
- `src/federated_agent_audit/a2a/` — the components Figure 6 names
- `paper/popets/main.pdf` — the submitted PDF, for seeing figures in situ

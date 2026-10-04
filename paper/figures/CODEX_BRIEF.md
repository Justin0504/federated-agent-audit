# Brief: the paper's figures

You own the figures for a privacy/security paper — one new one to draw, four
existing ones to raise, and the visual system they all share. Everything you
need is in this repo. Read this file first, then `figstyle.tex` and
`fig_pipeline.tex` — the new figure must look like it came from the same hand.

---

## 1. What the paper is, in four sentences

Agents built by different organizations hand work to each other over the A2A
protocol. A2A has no field saying whom a datum is about, who owns it, or who may
receive it, so cross-boundary privacy leakage is not even expressible, let alone
auditable. We add that typing (`a2a.privacy/v1`), and audit it from a central
service that **never sees message content** — each agent desensitizes locally and
ships only a one-way hash plus labels. The measured result that motivates all of
it: across seven models and 2,016 hand-offs, agents put the subject's regulated
identifiers into messages bound for an outside company 94% of the time, and
instructing them buys *redaction, not privacy*: handed the record's own policy, the
frontier model stops pasting identifiers almost perfectly (44% → 1%) and barely
changes what it says about the person (40% → 36%). Pooled, 73% still leak.

## 2. The work, in priority order

### (a) Draw the missing figure: deployment architecture — **highest value**

Four figures already exist. Do **not** restate any of them:

| exists | shows |
|---|---|
| Fig 1 `fig_pipeline.tex` | the *conceptual* flow: content → label → hash → boundary → detectors → violations |
| Fig 2 `fig_example.tex` | a worked example with verbatim system output |
| Fig 3 `fig_gain.tex` | the inference threshold curve |
| Fig 4 `fig_trends.tex` | two opposing trends across model capability |

**Your figure is the deployment architecture** — what actually runs where, which
Fig 1 deliberately abstracts away. A reader who wants to deploy this cannot tell
from Fig 1 what process holds what, what is signed, what is stored, or what the
center could learn if it were malicious. That is the gap.

It must answer, at a glance:

1. **What runs inside a tenant** — the app's agents, plus a *build-pinned*
   component containing the tagger and the local auditor. The tagger is the only
   thing that reads content.
2. **What the tenant emits** — center-view edges (hash + `a2a.privacy/v1` labels)
   and an attestation signing them. Show that the signing key is confined to the
   pinned build: this is what stops a tenant suppressing its own tags.
3. **What crosses the boundary** — only those two things. Content does not.
4. **What the center does** — verifies the attestation against a trusted build
   fingerprint, *re-runs* the detectors itself rather than trusting the tenant's
   claimed verdicts, and stores violations. Show that it stores no content.
5. **Multi-tenant** — at least two tenants reporting to one center, since the
   whole problem is cross-tenant.
6. **The single-tenant projection** — setting every principal equal collapses this
   to one organization auditing its own agents. A small inset or callout; this is
   the deployable product and currently has no picture at all.

Real component names, so labels match the artifact:

| component | file | role |
|---|---|---|
| `PrivacyTagger` | `a2a/tagger.py` | reads content locally, emits only tags |
| `A2AAuditor` | `a2a/auditor.py` | desensitizes to center-view edges; runs 4 detectors |
| `A2AAttestor` / `A2AVerifier` | `a2a/attest.py` | signs / verifies that a report came from the pinned build |
| `AuditSession` | `a2a/session.py` | the ~3-line integration surface an app uses |
| audit service | `a2a/service.py` | FastAPI center: `POST /api/v1/a2a/report`, `GET /api/v1/a2a/violations` |

The four detectors: cross-tenant disclosure, purpose limitation, hop/TTL,
cross-tenant inference.

**The one thing the figure must not get wrong:** nothing content-bearing may be
drawn crossing the trust boundary. That is the paper's central claim and a figure
that blurs it is worse than no figure.

### (a2) The paper's sharpest result has no picture — second priority

Contribution 1 turns on one contrast, and it is currently a row in a table:

| | identifiers, permissive → policy | attributes, permissive → policy |
|---|---|---|
| open-weight (6 families) | 85% → 51% | 93% → 69% |
| frontier (Claude Opus 4.8) | **44% → 1%** | **40% → 36%** |

The point is the *asymmetry*: instructions nearly eliminate the identifier line and
leave the attribute line standing. One small figure — two paired bars or two
slopes per model group, identifiers in `figrose`, attributes in `figindigo` with a
dash pattern so it survives greyscale — would carry the claim better than the
table does. If you draw it, name it `fig_redaction.tex`, add it to `export.py`'s
`FIGURES` list, and take every number from `benchmarks/a2a_mt/RESULTS.md`
Experiment 9c. Column-width; use plain `figure`, not `widefigure`.

### (b) Raise the four that exist

They are competent and consistent, not memorable. Each has one specific weakness
worth fixing, and none needs a redesign:

| figure | what to push on |
|---|---|
| Fig 1 `fig_pipeline` | Reads left-to-right as a flowchart. The *claim* is that one lane dies at the boundary while another passes through — make that asymmetry the first thing the eye lands on, not something the caption explains. |
| Fig 2 `fig_example` | Three panels of near-equal weight, so the reader does not know where to start. Panel (c) carries the punchline (a live frontier model recovers the withheld attribute from exactly these two messages) and should look like the punchline. |
| Fig 3 `fig_gain` | Correct and inert. The interesting fact is that *one* high-specificity hint clears a line that normally takes two — currently a small amber dot. |
| Fig 4 `fig_trends` | The paper's headline measurement, drawn as a small line chart. Two trends crossing in opposite directions is the whole argument; the crossing deserves more than 40mm of width. |

Constraint on all four: **the numbers are measured and must not change.** Verify
against `benchmarks/a2a_mt/RESULTS.md` before touching a coordinate. Fig 3's curve
is a closed form (posterior at k=0..4 is exactly 0.10/0.25/0.50/0.75/0.90 for
p0=0.1, lambda=3; the fire line sits at 0.4) — it is not eyeballed, so do not
"tidy" it.

### (c) Keep the system coherent

Any icon or style you add goes in `figstyle.tex` / `icons/`, never inline in one
figure. The four builds share these files; a local override silently diverges the
papers.

---

## 3. The design system — use it, do not invent one

`figstyle.tex` holds the whole visual language. `\input` it; never redefine a
colour or a style locally.

**Colour carries meaning and is reused across every figure.** A reader learns it
once in Fig 1 and must not have to relearn it in yours:

| token | hex | meaning |
|---|---|---|
| `figrose` | `#B8405C` | the data subject's content — the thing at risk, never crosses |
| `figindigo` | `#3D5A9E` | governance metadata (labels) — what we add |
| `figamber` | `#B0662A` | what actually crosses the boundary |
| `figemerald` | `#2C7A58` | verified / detected / safe |
| `figink` `#1B2733` / `figslate` `#6B7885` | structure / secondary type |
| `figrule` `#D8DEE4` / `figwash` `#F4F6F8` | borders / fills |

Values are spread so the figure survives a greyscale print. If you need to
separate two series, separate them by **hue and dash pattern** — rose and indigo
land at nearly the same greyscale value.

**Styles** (all in `figstyle.tex`): `figzone` (rounded container), `fignum=<colour>`
(numbered disc badge), `figtitle` / `figlabel` / `fignote` / `figmono` (type
scale), `figchip=<colour>` (a labelled pill), `figflow` (grey arrow), `figcross`
(amber arrow, for things that cross), `figbound` (the dashed boundary edge).

**Icons** — ours, drawn on a 24×24 grid, no third-party licence. Use
`\icon{name}{colour}{height}`, e.g. `\icon{attest}{emerald}{5mm}`:

`agent` `alert` `attest` `blind` `boundary` `content` `detector` `hash` `infer`
`tag` `tenant` `ttl`

Icons render at **4–6 mm**. An earlier draft used 3 mm and they read as noise.
If you need an icon that does not exist, add an SVG to `icons/` on the same grid
(1.75 stroke, round caps/joins, `stroke="currentColor"`) and run
`python icons/build_icons.py`.

---

## 4. Hard constraints

- **Output is TikZ**, `\input` from `paper/figures/`, not an image. Fonts must
  match the body text.
- **Wrap in `\begin{widefigure}[t] … \end{widefigure}`**, not `figure`. One-column
  builds (arXiv, ICLR) map it to `figure`; two-column builds (PoPETs, S&P) map it
  to `figure*`, or a wide figure is crushed into one column.
- **It must compile in all four builds**: `paper/{submission,popets,sp,iclr}`.
  Each has a `figures` symlink, so `\input{figures/<name>}` resolves everywhere.
- **PoPETs has a 12-page main-body limit and is currently at 9.** Budget roughly
  half a column-width page. Do not push the body past 12.
- **Greyscale-safe**, and **no overfull boxes over 15pt**.
- Wrap the picture in `\resizebox{\linewidth}{!}{…}` as the other figures do.

## 5. How to iterate without rebuilding the paper

```sh
cd paper/figures
sed 's|\\input{\\figfile}|\\input{fig_deploy}|' _preview.tex > _prev_deploy.tex
tectonic _prev_deploy.tex && open _prev_deploy.pdf     # ~2 s
```

Then check it in the real builds:

```sh
for d in submission popets sp iclr; do (cd ../$d && tectonic main.tex); done
```

Export a cropped PDF/SVG for slides with `python export.py` after adding the
figure's name to its `FIGURES` list.

## 6. Acceptance checklist

- [ ] Nothing content-bearing crosses the trust boundary anywhere in the drawing
- [ ] Colours come from `figstyle.tex` and carry their established meanings
- [ ] Icons at 4–6 mm; no new visual language invented
- [ ] Compiles clean in all four builds, no unresolved refs, no overfull > 15pt
- [ ] Legible in greyscale
- [ ] PoPETs body still ≤ 12 pages (currently 9)
- [ ] Does not restate Fig 1 — a reader who has seen Fig 1 learns something new
- [ ] Every number in a revised figure still matches `RESULTS.md`
- [ ] New styles/icons live in `figstyle.tex` / `icons/`, not inline

## 7. Where to read more

- `paper/figures/README.md` — the figure system
- `paper/submission/main.tex` §"The center-blind auditor and detectors", §"Threat
  model" (the attestation argument), §"Discussion" (the single-tenant projection)
- `benchmarks/a2a_mt/RESULTS.md` — all 18 experiments; **the authority for every
  number that appears in a figure**
- `paper/figures/appendix.tex` — verbatim prompts and per-model tables
- `src/federated_agent_audit/a2a/` — the components named above

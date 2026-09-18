# Figures

One source, four papers. `figstyle.tex` defines the whole visual language —
palette, zone and chip styles, flow arrows, the `\icon` macro — and each figure
`\input`s into every build through the `figures` symlink in `paper/<build>/`.

```
figstyle.tex        palette + TikZ styles + \icon + the widefigure float
fig_pipeline.tex    Figure 1 — the federated, center-blind pipeline
fig_example.tex     Figure 2 — worked example, verbatim system output
icons/*.svg         the icon set (ours; no third-party licence)
icons/build_icons.py    renders each icon to PDF in every palette colour
icons/pdf/          generated — \includegraphics reads from here
```

## Colour carries meaning

Reused identically across figures so a reader learns it once:

| token | meaning |
|---|---|
| `figrose` | the data subject's content — the thing at risk, which never crosses |
| `figindigo` | governance metadata (privacy labels) — what we add |
| `figamber` | what actually crosses the trust boundary |
| `figemerald` | verified / detected / safe |
| `figink` / `figslate` | structure, primary and secondary type |

Chosen to stay distinguishable in greyscale (~25/35/45/55% value).

## Icons

Drawn by us on a 24×24 grid, 1.75 stroke, round caps and joins, authored once as
SVG with `stroke="currentColor"`. We deliberately do **not** use Flaticon or a
similar library: the free tiers require attribution, which is awkward in a
camera-ready, and a mixed-provenance set never quite shares a hand.

Editing an icon means editing its `.svg`, then:

```sh
python paper/figures/icons/build_icons.py     # needs rsvg-convert
```

## Iterating on a figure

Compile one figure on its own instead of rebuilding a paper:

```sh
cd paper/figures
sed 's|\\input{\\figfile}|\\input{fig_pipeline}|' _preview.tex > _prev_fig1.tex
tectonic _prev_fig1.tex && open _prev_fig1.pdf
```

## One- vs two-column builds

arXiv and ICLR are one-column (`figure`); PoPETs and S&P are two-column and need
`figure*`, or a full-width figure is crushed into one column. The figures use a
`widefigure` environment for this; a two-column build defines
`\figenvname` as `figure*` *before* `\input{figures/figstyle}`.

## Editable exports

```sh
python paper/figures/export.py     # needs tectonic + pdf2svg
```

Writes `export/<figure>.pdf` and `export/<figure>.svg` — each tightly cropped to
the drawing, with the float wrapper, caption and `\resizebox` stripped since none
of them mean anything outside the paper. Cross-references resolve against the
built arXiv paper via `xr-hyper`, so an exported figure says "Lemma 1" rather
than "Lemma ??".

SVG is the format to hand to someone working in PowerPoint or Keynote: it imports
and ungroups into editable shapes, where PDF does not. The LaTeX source stays the
master — slide exports are one-offs, not a second copy to maintain.

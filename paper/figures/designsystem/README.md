# Claude Design bundle

Three preview pages for the paper's figure design system, ready to push to a
Claude Design project so colleagues can review the icons and figures visually and
comment, instead of round-tripping PDFs.

| file | card group | what it shows |
|---|---|---|
| `icons.html` | Icons | all 12 icons at review size, each with its meaning |
| `palette.html` | Foundations | the colour tokens, what each means, greyscale check |
| `figures.html` | Figures | both main figures as rendered |

The `<!-- @dsCard group="..." -->` first line is what the Design System pane reads
to build its card index — keep it as line 1.

## Pushing

Claude Design needs a one-time authorization that cannot be granted from a
headless session. Run `/design-login` once in an interactive Claude Code session
on this machine; afterwards this and future sessions can sync.

## Regenerating

The figure PNGs come from the preview harness:

```sh
cd paper/figures
sed 's|\\input{\\figfile}|\\input{fig_pipeline}|' _preview.tex > _prev_fig1.tex
tectonic _prev_fig1.tex
pdftoppm -r 220 -png -x 60 -y 240 -W 1900 -H 460 _prev_fig1.pdf designsystem/fig-pipeline
```

The HTML pages are generated from the icon SVGs and the palette, so an icon edit
plus a rerun keeps the review pages honest — they never drift from what the paper
actually compiles.

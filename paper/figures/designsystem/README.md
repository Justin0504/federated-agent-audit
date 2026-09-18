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

```sh
python paper/figures/export.py                 # cropped PDF + SVG per figure
python paper/figures/designsystem/build.py     # the review pages
```

Everything here is generated — icons from the icon SVGs, the palette from the
same token list `build_icons.py` uses, figure images from the cropped exports.
Edit an icon, rerun, and the review pages are honest again; they cannot drift
from what the paper actually compiles.

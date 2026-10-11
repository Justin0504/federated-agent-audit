# Codex figure pack

Hand this folder (or `codex_pack.zip`, which is this folder plus the files it
points at) to Codex with the instruction: *"Read BRIEF.md and do the figures in
the order it gives."*

| file | what |
|---|---|
| `BRIEF.md` | the complete brief: context, design system, constraints, the twelve figures and three demo graphics, acceptance checklist |
| `figure_data.json` | every number any figure may show, with its source in `RESULTS.md` |
| `../figstyle.tex`, `../icons/` | the design system (palette, styles, icon macro, icon SVGs) |
| `../fig_*.tex` | the five existing figures |
| `../export/*.svg|pdf` | cropped exports of the five, for Figma |
| `../designsystem/` | review pages: palette, icons, figures |
| `../appendix.tex` | the appendix (verbatim prompts; where figures 9–12 go) |
| `../../../benchmarks/a2a_mt/RESULTS.md` | the authority for every number |
| `../../popets/main.pdf` | the submitted PDF, to see figures in situ |

The zip is rebuilt with:

```sh
cd paper/figures && zip -r codex_pack.zip codex_pack figstyle.tex icons fig_*.tex _preview.tex export designsystem appendix.tex README.md ../popets/main.pdf ../../benchmarks/a2a_mt/RESULTS.md -x "icons/pdf/*"
```

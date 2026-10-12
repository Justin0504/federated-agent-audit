# Codex figure pack

Hand this folder (or `codex_pack.zip`, which is this folder plus the files it
points at) to Codex with the instruction: *"Read BRIEF.md and do the figures in
the order it gives."*

| file | what |
|---|---|
| `BRIEF.md` | the complete brief: context, design system, constraints, the twelve figures and three demo graphics, acceptance checklist |
| `figure_data.json` | every number any figure may show, with its source in `RESULTS.md` |
| `check_data.py` | recomputes every trace-derived number in `figure_data.json` from the raw traces; must print ALL GOOD |
| `snapshots/*.png` | the five existing figures as rendered today |
| `../figstyle.tex`, `../icons/` | the design system (palette, styles, icon macro, icon SVGs) |
| `../fig_*.tex` | the five existing figures |
| `../export/*.svg|pdf` | cropped exports of the five, for Figma |
| `../designsystem/` | review pages: palette, icons, figures |
| `../appendix.tex` | the appendix (verbatim prompts; where figures 9–12 go) |
| `../../../benchmarks/a2a_mt/RESULTS.md` | the authority for every number |
| `../../popets/main.pdf` | the submitted PDF, to see figures in situ |

Zip layout (self-contained; `check_data.py` runs from the extracted root):

```
codex_figure_pack/
  BRIEF.md  figure_data.json  check_data.py  snapshots/   ← this folder
  paper/figures/   figstyle.tex icons/ fig_*.tex _preview.tex export/ designsystem/ appendix.tex README.md
  paper/popets/main.pdf
  benchmarks/a2a_mt/   RESULTS.md a2a_pool.py a2a_prompt_conditions.py a2a_measurement.py traces/
```

Rebuild: `bash paper/figures/codex_pack/make_zip.sh` → `~/Downloads/codex_figure_pack.zip`.

## Status (2026-10-12)

Delivered and integrated (commit d8b917e): `fig_deploy`, `fig_threat`, `fig_label`
in the body; `fig_attack`, `fig_relay`, `fig_conditions` in `revision_appendix.tex`;
`fig_pipeline`, `fig_example`, `fig_gain`, `fig_redaction` redrawn. `fig_trends`
kept its original design. Captions were edited after delivery so that no caption
argues against the paper's own results; the paper text is owned by the authors,
not by the figure pass. Remaining from the brief: the Figma demo graphics (D1–D3).

#!/usr/bin/env python3
"""Export each paper figure as a tightly-cropped standalone PDF and SVG.

The LaTeX source stays the master. These exports exist so a figure can be dropped
into slides or hand-tuned in Illustrator/Figma/PowerPoint without anyone
reverse-engineering TikZ -- SVG imports and ungroups cleanly in Keynote and
PowerPoint, where PDF does not.

What it does: lifts the ``tikzpicture`` out of each figure file (dropping the
float wrapper, the caption and the \\resizebox, none of which mean anything
outside the paper), compiles it with the ``standalone`` class so the page is
cropped to the drawing, then converts to SVG.

Run:  python paper/figures/export.py        # needs tectonic + pdf2svg
"""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
OUT = HERE / "export"
FIGURES = ["fig_pipeline", "fig_example", "fig_gain", "fig_trends", "fig_redaction"]

PREAMBLE = r"""\documentclass[crop,border=3pt]{standalone}
\usepackage{amsmath,amssymb}
\usepackage{graphicx}
\usepackage{tikz}
\usetikzlibrary{arrows.meta,positioning,fit,backgrounds,calc}
\usepackage{xcolor}
\graphicspath{{../icons/pdf/}}
\newcommand{\ext}{\texttt{a2a.privacy/v1}}
% Resolve cross-references against the built arXiv paper so an exported figure
% says "Lemma 1", not "Lemma ??" and not a hole where the number should be.
% hyperref must match the paper: its \newlabel entries carry five arguments, and
% without it \ref pulls the theorem's name and anchor in alongside the number.
\usepackage[hidelinks]{hyperref}
\usepackage{xr-hyper}
\externaldocument{../../submission/main}
\input{../figstyle}
\begin{document}
"""


def extract_tikz(src: str) -> str | None:
    """The drawing itself, without the float, caption or \\resizebox."""
    i = src.find(r"\begin{tikzpicture}")
    j = src.rfind(r"\end{tikzpicture}")
    if i < 0 or j < 0:
        return None
    return src[i:j + len(r"\end{tikzpicture}")]


def main() -> int:
    for tool in ("tectonic", "pdf2svg"):
        if shutil.which(tool) is None:
            print(f"error: {tool} not found "
                  f"({'brew install pdf2svg' if tool == 'pdf2svg' else 'install tectonic'})")
            return 1

    OUT.mkdir(exist_ok=True)
    for name in FIGURES:
        src = (HERE / f"{name}.tex").read_text()
        tikz = extract_tikz(src)
        if tikz is None:
            print(f"  !! {name}: no tikzpicture found")
            continue
        stem = OUT / name
        stem.with_suffix(".tex").write_text(PREAMBLE + tikz + "\n\\end{document}\n")
        subprocess.run(["tectonic", "-X", "compile", f"{stem}.tex"],
                       cwd=OUT, check=True, capture_output=True)
        subprocess.run(["pdf2svg", f"{stem}.pdf", f"{stem}.svg"], check=True)
        kb = (stem.with_suffix(".svg")).stat().st_size // 1024
        print(f"  {name}.pdf + {name}.svg  ({kb} KB)")

    print(f"\nexported to {OUT}")
    print("SVG opens editable in Illustrator, Figma, Inkscape, Keynote and PowerPoint.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

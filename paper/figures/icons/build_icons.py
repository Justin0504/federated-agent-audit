#!/usr/bin/env python3
"""Render the icon set to PDF in the figure palette, for \includegraphics in TikZ.

Icons are authored once as SVG with stroke="currentColor"; this script stamps a
concrete colour on the root element and converts. Keeping one SVG per icon (not
one per colour) means a shape is only ever fixed in one place.

Run:  python paper/figures/icons/build_icons.py
"""
import pathlib
import subprocess

HERE = pathlib.Path(__file__).parent
OUT = HERE / "pdf"

# The figure palette. One accent per semantic role, muted enough to survive a
# greyscale print as distinct values.
PALETTE = {
    "ink":     "#1b2733",   # structure, text
    "slate":   "#6b7885",   # secondary / annotation
    "rose":    "#b8405c",   # the data subject's content — the thing at risk
    "indigo":  "#3d5a9e",   # governance metadata (labels, tags)
    "emerald": "#2c7a58",   # verified / safe / detected
    "amber":   "#b0662a",   # what crosses the boundary
}

def main() -> int:
    OUT.mkdir(exist_ok=True)
    n = 0
    for svg in sorted(HERE.glob("*.svg")):
        if svg.name.startswith("_"):
            continue
        src = svg.read_text()
        for cname, hexv in PALETTE.items():
            tinted = src.replace("<svg ", f'<svg color="{hexv}" ', 1)
            tmp = OUT / f".{svg.stem}-{cname}.svg"
            tmp.write_text(tinted)
            subprocess.run(["rsvg-convert", "-f", "pdf", "-w", "96", "-h", "96",
                            str(tmp), "-o", str(OUT / f"{svg.stem}-{cname}.pdf")],
                           check=True)
            tmp.unlink()
            n += 1
    print(f"rendered {n} icon PDFs into {OUT}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

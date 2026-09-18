#!/usr/bin/env python3
"""Generate the Claude Design review pages from the real figure sources.

The pages are generated rather than hand-written so they cannot drift from what
the paper actually compiles: the icons come from the icon SVGs, the palette from
the same token list build_icons.py uses, and the figure images from the cropped
exports. Edit an icon, rerun, and the review page is honest again.

Run:  python paper/figures/designsystem/build.py   (after export.py)
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
ICONS = HERE.parent / "icons"
EXPORT = HERE.parent / "export"

NAMES = ["agent", "content", "tag", "hash", "boundary", "detector",
         "alert", "tenant", "ttl", "infer", "blind", "attest"]

MEANING = {
    "agent": "an agent process",
    "content": "raw content — the thing at risk",
    "tag": "a privacy label",
    "hash": "one-way hash; content locked locally",
    "boundary": "the trust boundary",
    "detector": "a detector locking onto a signal",
    "alert": "a violation",
    "tenant": "a principal / tenant",
    "ttl": "hop budget (TTL)",
    "infer": "fragments converging on a conclusion",
    "blind": "center-blind — cannot see content",
    "attest": "a signed, build-pinned report",
}

PALETTE = [
    ("figink", "#1B2733", "structure, primary type"),
    ("figslate", "#6B7885", "secondary annotation"),
    ("figrose", "#B8405C", "the data subject's content — never crosses"),
    ("figindigo", "#3D5A9E", "governance metadata (labels) — what we add"),
    ("figamber", "#B0662A", "what actually crosses the boundary"),
    ("figemerald", "#2C7A58", "verified / detected / safe"),
]

FIGURES = [
    ("fig_pipeline", "Figure 1 — the center-blind pipeline",
     "The boundary is a full-height band, not a hairline. The lane turns amber at the "
     "hash and passes visibly through it, so what crosses is recognisably the same "
     "object the agent produced."),
    ("fig_example", "Figure 2 — worked example, verbatim output",
     "Real hashes and labels from the auditor. Panel (c) carries the live confirmation "
     "that a frontier recipient recovers the withheld attribute from exactly these two "
     "messages."),
    ("fig_gain", "Figure 3 — the inference threshold",
     "Curve values are the closed form, not eyeballed: with p0=0.1 and lambda=3 the "
     "posterior is exactly 0.10/0.25/0.50/0.75/0.90 and the fire line sits at 0.4."),
    ("fig_trends", "Figure 4 — two opposing trends",
     "The paper's headline measurement. Separated by hue AND dash pattern, because rose "
     "and indigo land at almost the same greyscale value."),
]

CSS = """
:root{--ink:#1B2733;--slate:#6B7885;--rule:#D8DEE4;--wash:#F4F6F8}
*{box-sizing:border-box}
body{margin:0;padding:32px;background:#fff;color:var(--ink);
  font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
h1{font-size:19px;margin:0 0 4px}
h2{font-size:14px;margin:34px 0 12px;letter-spacing:.04em;text-transform:uppercase;
   color:var(--slate);font-weight:600}
p.lede{margin:0 0 6px;color:var(--slate);max-width:70ch}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px}
.cell{border:1px solid var(--rule);border-radius:10px;padding:16px 10px 11px;text-align:center}
.cell svg{display:block;margin:0 auto 9px}
.nm{font:600 12px ui-monospace,SFMono-Regular,Menlo,monospace}
.mn{font-size:11px;color:var(--slate);margin-top:3px;line-height:1.35}
.sw{display:flex;align-items:center;gap:12px;border:1px solid var(--rule);
    border-radius:10px;padding:10px 13px;margin-bottom:7px}
.chip{width:40px;height:40px;border-radius:7px;flex:none}
.tok{font:600 12px ui-monospace,SFMono-Regular,Menlo,monospace}
.hex{font:11px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--slate)}
.use{font-size:12px;color:var(--slate)}
.row{display:flex;gap:26px;align-items:center;border:1px solid var(--rule);
     border-radius:10px;padding:14px;margin-bottom:9px;background:var(--wash)}
figure{margin:0 0 22px}
figure img{width:100%;display:block;border:1px solid var(--rule);border-radius:10px;
  background:#fff;padding:10px}
figcaption{font-size:12px;color:var(--slate);margin-top:7px;max-width:80ch}
@media (prefers-color-scheme:dark){
  :root{--ink:#E8ECF0;--slate:#96A2AE;--rule:#2C3742;--wash:#151C24}
  body{background:#0E141A}
}
"""


def icon_body(name: str) -> str:
    s = (ICONS / f"{name}.svg").read_text()
    return s.split(">", 1)[1].rsplit("</svg>", 1)[0]


def page(path: pathlib.Path, group: str, title: str, lede: str, body: str) -> None:
    path.write_text(
        f'<!-- @dsCard group="{group}" -->\n<!doctype html><meta charset="utf-8">\n'
        f"<title>{title}</title>\n<style>{CSS}</style>\n"
        f'<h1>{title}</h1>\n<p class="lede">{lede}</p>\n{body}\n')


def main() -> int:
    missing = [n for n, *_ in FIGURES if not (EXPORT / f"{n}.pdf").exists()]
    if missing:
        print(f"error: run export.py first (missing {', '.join(missing)})")
        return 1

    # figure images, from the cropped exports so they match the paper exactly
    for name, *_ in FIGURES:
        subprocess.run(["rsvg-convert", "-z", "2", str(EXPORT / f"{name}.svg"),
                        "-o", str(HERE / f"{name}.png")], check=True)

    cells = "".join(
        f'<div class="cell"><svg viewBox="0 0 24 24" width="40" height="40" fill="none" '
        f'stroke="currentColor" stroke-width="1.75" stroke-linecap="round" '
        f'stroke-linejoin="round">{icon_body(n)}</svg>'
        f'<div class="nm">{n}</div><div class="mn">{MEANING[n]}</div></div>'
        for n in NAMES)
    page(HERE / "icons.html", "Icons", "Paper icon set",
         "Drawn for this paper on a 24&times;24 grid, 1.75 stroke, round caps and joins, "
         "authored once as SVG with <code>currentColor</code>. Not Flaticon: the free tier "
         "wants attribution, awkward in a camera-ready, and a mixed-provenance set never "
         "shares a hand. Each renders to PDF in every palette colour for "
         "<code>\\includegraphics</code>.",
         f'<h2>The set</h2><div class="grid">{cells}</div>')

    sw = "".join(
        f'<div class="sw"><div class="chip" style="background:{h}"></div>'
        f'<div><div class="tok">{t}</div><div class="hex">{h}</div></div>'
        f'<div class="use" style="margin-left:auto;text-align:right;max-width:48%">{u}</div>'
        f"</div>" for t, h, u in PALETTE)
    gs = "".join(
        f'<div class="chip" style="background:{h};filter:grayscale(1)" title="{t}"></div>'
        for t, h, _ in PALETTE)
    page(HERE / "palette.html", "Foundations", "Figure palette",
         "Colour carries meaning and is reused identically across every figure, so a "
         "reader learns it once. Values are spread so the figures survive a greyscale "
         "print.",
         f"<h2>Tokens</h2>{sw}<h2>Greyscale check</h2>"
         f'<div class="row">{gs}</div>')

    figs = "".join(
        f"<h2>{title}</h2><figure><img src=\"{name}.png\" alt=\"{title}\">"
        f"<figcaption>{note}</figcaption></figure>"
        for name, title, note in FIGURES)
    page(HERE / "figures.html", "Figures", "Paper figures",
         "All four figures share one visual language: same palette, same zone and chip "
         "styles, same boundary band. A reader who has parsed Figure 1 reads the rest "
         "without relearning anything.", figs)

    print(f"built icons.html, palette.html, figures.html and "
          f"{len(FIGURES)} figure images in {HERE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

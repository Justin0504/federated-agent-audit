# Figma figure guide — build these three

Goal: three clean, print-safe vector figures that match the Sentinel demo and read
well at column width. Design light-background (papers print on white); a dark
variant is fine for slides/site.

## Shared design system (set this up first)
- **Frame per figure.** Design at the paper's full text width, aspect ~2.4:1.
  Use **1560 × 640 px** frames (then export; see below). One figure = one Frame.
- **Type:** Inter (or Helvetica Neue) for labels; a mono (JetBrains Mono / SF Mono)
  for hashes, tags, ids. Sizes: title 17, body 13, mono 12, caption-in-figure 11.
- **Palette (make these Figma color styles):**
  - ink `#16181D`, muted `#6B7280`, hairline `#E5E7EB`
  - accent (agents/flow) `#4F46E5`; accent fill `#EEF2FF`
  - danger (violation / derived-sensitive) `#DC2626`; danger fill `#FEF2F2`
  - safe (center-blind / 0 content) `#059669`; safe fill `#ECFDF5`
  - trust boundary: dashed `#9CA3AF`
- **Boxes:** 1.5 px stroke, 10 px radius, generous inner padding (16 px). No drop
  shadows (flat, editorial). **Arrows:** 2 px, accent color, small arrowhead,
  label centered above the line in 11 px.
- **Make components:** an *agent card*, a *tag chip*, and a *hash line* as reusable
  components so every figure is pixel-consistent. Use **Auto Layout** on cards
  (vertical, 8 px gap) so text never misaligns.

## Figure 2 — Desensitization, before → after  (the hero; build this first)
Three zones, left → right; a vertical dashed trust boundary down the middle.

- **Left card — "At the agent (tenant P)"** (accent-tinted):
  - a chat-style bubble: *Part.text:* "busy Tue — meet near the oncology center"
  - a chip row (mono, muted): `subject:alice` `owner:P` `purpose:[sched]` `allow:[Q]`
- **Trust boundary:** a full-height dashed gray line at ~52% width, tiny gray
  vertical label "trust boundary — content stays left".
- **Arrow crossing it**, labeled "tag + hash · local".
- **Right card — "What the center receives"** (neutral/gray-tinted):
  - `hash a3f9c1…` (mono, muted)
  - chips: `category [schedule]`, then **`inferred [health]` in RED** (this is the
    punch: the tagger *derived* a sensitive category), `P → Q`, `sens 4`
  - a small green footnote with a lock glyph: "no message text · 0 content bytes"
- Reading: left = human-readable content; right = only hashes + tags, with one red
  chip proving inference is caught from metadata. That contrast is the whole paper.

## Figure 1 — System architecture
Left column of agents → trust boundary → center → violations.

- **Two/three agent cards (left)**, each titled "tenant P agent", containing a
  *mini pipeline* of three pills: `content → tag → hash` (tiny arrows between; a
  lock glyph on the hash pill).
- **Vertical dashed trust boundary** right of the agents, labeled "trust boundary".
- **Arrows** from each agent crossing the boundary to the center, one labeled
  "desensitized edges (hash + labels)".
- **Center card (larger, safe-tinted):** title "Center-blind auditor", then four
  rows with small icons: disclosure · purpose · hop/TTL · inference.
- **Arrow → a small node "violations (metadata only)"** on the far right.
- Caption idea: "content never crosses the boundary; only metadata does."

## Figure 3 — Cross-tenant inference (worked example)
Two round agent nodes: **alice** (left), **bob** (right), spaced wide.
- Two curved arrows alice → bob (one bending up, one down), labeled
  "'busy Tue at the clinic' [infer health]" and "'near the oncology center'
  [infer health]".
- A dashed **red callout** attached to bob: "bob infers **health** — two
  converging hints ≥ k* ⇒ cross-tenant inference".
- Tiny gray note under the edges: "neither message leaks alone; bob is an allowed
  recipient of both."

## Export (for the paper and slides)
- **Paper (LaTeX):** select the Frame → Export → **PDF** (vector, crisp at any
  size). Drop into `paper/submission/figs/` and use
  `\includegraphics[width=\linewidth]{figs/fig2.pdf}` in place of the TikZ block.
  (SVG also works if you convert; PDF is simplest for pdf/tectonic.)
- **Slides / website:** export **PNG @3×** (or SVG for the site).
- Keep every figure the **same frame width** so they scale uniformly in the paper.
- Sanity check: view at 40% zoom — if a label is unreadable, bump its size; figures
  must survive being printed half-column.

## If you want them to match the paper exactly
The current TikZ versions (Figs 1–4 in `main.tex`) are the content spec — same
elements, same labels. Rebuild 1–3 in Figma for polish; keep the TikZ inference
curve (Fig 4) as-is, or redo it as a clean line chart with the fire-threshold line.

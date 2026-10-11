#!/usr/bin/env bash
# Stage a self-contained copy of everything the brief points at and zip it.
set -euo pipefail
cd "$(dirname "$0")/../../.."
S=$(mktemp -d)/codex_figure_pack
mkdir -p "$S/paper/figures" "$S/paper/popets" "$S/benchmarks/a2a_mt"
cp paper/figures/codex_pack/{BRIEF.md,README.md,figure_data.json,check_data.py,gt.json} "$S/"
cp -R paper/figures/codex_pack/snapshots "$S/"
cp paper/figures/{figstyle.tex,_preview.tex,appendix.tex,README.md,export.py} paper/figures/fig_*.tex "$S/paper/figures/"
cp -R paper/figures/icons paper/figures/export paper/figures/designsystem "$S/paper/figures/"
rm -rf "$S/paper/figures/icons/pdf"
cp paper/popets/main.pdf "$S/paper/popets/"
cp benchmarks/a2a_mt/{RESULTS.md,a2a_pool.py,a2a_prompt_conditions.py,a2a_measurement.py} "$S/benchmarks/a2a_mt/"
mkdir -p "$S/benchmarks/a2a_mt/traces"
cp -R benchmarks/a2a_mt/traces/prompt_conditions* "$S/benchmarks/a2a_mt/traces/"
cp benchmarks/a2a_mt/traces/attack_*.jsonl benchmarks/a2a_mt/traces/README.md "$S/benchmarks/a2a_mt/traces/"
(cd "$S/.." && rm -f codex_figure_pack.zip && zip -qr codex_figure_pack.zip codex_figure_pack)
cp "$S/../codex_figure_pack.zip" ~/Downloads/codex_figure_pack.zip
echo "→ ~/Downloads/codex_figure_pack.zip ($(unzip -l ~/Downloads/codex_figure_pack.zip | tail -1))"

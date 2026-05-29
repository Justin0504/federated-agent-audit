"""Generate self-contained HTML audit reports.

Produces a single .html file with embedded CSS — no external dependencies.
Can be emailed, attached to proposals, or opened directly in any browser.

Design: white/black with warm yellow accents, clean serif headings,
generous whitespace. Inspired by Anthropic's editorial style.

Usage:
    from federated_agent_audit.reporting import generate_html_report

    html = generate_html_report(
        network_result=network_result,
        aggregated_result=aggregated_result,
        title="Telegram Agent Group Chat — Privacy Audit",
    )
    Path("audit_report.html").write_text(html)
"""

from __future__ import annotations

import html as html_mod
import math
from datetime import datetime, timezone

from ..schemas import (
    AggregatedResult,
    DesensitizedEdge,
    NetworkAuditResult,
)


def generate_html_report(
    network_result: NetworkAuditResult,
    aggregated_result: AggregatedResult,
    title: str = "Federated Agent Audit Report",
    subtitle: str = "",
    company: str = "",
    logo_url: str = "",
    scenario_description: str = "",
    agent_descriptions: dict[str, str] | None = None,
    edges: list[DesensitizedEdge] | None = None,
) -> str:
    """Generate a self-contained HTML audit report.

    Args:
        network_result: Raw network audit findings.
        aggregated_result: Risk-aggregated incidents.
        title: Report title.
        subtitle: Subtitle / scenario name.
        company: Company name for header.
        logo_url: Optional logo URL for header.
        scenario_description: Markdown-like description of the audit scenario.
        agent_descriptions: Map of agent_id -> human-readable role description.
        edges: Optional list of edges for topology visualization.

    Returns:
        Self-contained HTML string.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    agent_descs = agent_descriptions or {}

    sections = [
        _build_head(title),
        _build_header(title, subtitle, company, logo_url, now, network_result),
        _build_executive_summary(network_result, aggregated_result),
        _build_scenario(scenario_description, agent_descs),
        _build_topology_svg(network_result, edges, agent_descs),
        _build_risk_breakdown(aggregated_result),
        _build_scenario_classification(network_result),
        _build_blame_attribution(aggregated_result),
        _build_agent_scores(network_result, agent_descs),
        _build_incidents(aggregated_result),
        _build_data_flow_table(edges),
        _build_compliance_section(aggregated_result),
        _build_footer(now),
    ]

    return "\n".join(sections)


# ---------------------------------------------------------------------------
# CSS + HTML head
# ---------------------------------------------------------------------------

def _build_head(title: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_esc(title)}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Source+Serif+4:ital,opsz,wght@0,8..60,300;0,8..60,400;0,8..60,600;0,8..60,700;1,8..60,400&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');

:root {{
  --bg: #ffffff;
  --surface: #ffffff;
  --surface-alt: #fafaf9;
  --border: #e8e5e0;
  --border-light: #f0eeea;
  --text: #1a1a1a;
  --text-secondary: #6b6560;
  --text-tertiary: #9b9590;
  --accent: #c8a84e;
  --accent-strong: #b8942e;
  --accent-bg: #faf6eb;
  --critical: #1a1a1a;
  --critical-bg: #1a1a1a;
  --high: #c8a84e;
  --high-bg: #faf6eb;
  --medium: #6b6560;
  --low: #9b9590;
  --serif: 'Source Serif 4', 'Georgia', 'Times New Roman', serif;
  --sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  --mono: 'JetBrains Mono', 'SF Mono', 'Monaco', 'Consolas', monospace;
}}

* {{ margin: 0; padding: 0; box-sizing: border-box; }}

body {{
  font-family: var(--sans);
  background: var(--bg);
  color: var(--text);
  line-height: 1.65;
  font-size: 14px;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}}

.container {{ max-width: 920px; margin: 0 auto; padding: 0 40px; }}

/* ── Header ────────────────────────────────────────── */
.header {{
  border-bottom: 1px solid var(--border);
  padding: 56px 0 40px;
  margin-bottom: 48px;
}}
.header .container {{
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
}}
.header h1 {{
  font-family: var(--serif);
  font-size: 32px;
  font-weight: 600;
  letter-spacing: -0.5px;
  line-height: 1.2;
  color: var(--text);
}}
.header .subtitle {{
  font-family: var(--sans);
  color: var(--text-secondary);
  font-size: 14px;
  margin-top: 8px;
  font-weight: 400;
}}
.header .meta {{
  text-align: right;
  font-size: 12px;
  color: var(--text-tertiary);
  line-height: 1.8;
  flex-shrink: 0;
}}
.header .meta .company {{
  color: var(--text);
  font-weight: 600;
  font-size: 13px;
}}

/* ── Stat cards ────────────────────────────────────── */
.stats {{
  display: flex;
  gap: 1px;
  background: var(--border);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
  margin-bottom: 56px;
}}
.stat-card {{
  background: var(--surface);
  padding: 20px 12px;
  text-align: center;
  flex: 1;
  min-width: 0;
}}
.stat-card .value {{
  font-family: var(--serif);
  font-size: 22px;
  font-weight: 600;
  line-height: 1.2;
  color: var(--text);
  white-space: nowrap;
  overflow: visible;
}}
.stat-card .label {{
  font-size: 10px;
  color: var(--text-tertiary);
  margin-top: 6px;
  text-transform: uppercase;
  letter-spacing: 0.8px;
  font-weight: 500;
}}
.stat-card.critical .value {{ color: var(--text); }}
.stat-card.high .value {{ color: var(--accent-strong); }}
.stat-card.medium .value {{ color: var(--text-secondary); }}
.stat-card.green .value {{ color: var(--text-secondary); }}
.stat-card.verdict {{
  background: var(--text);
}}
.stat-card.verdict .value {{
  color: #ffffff;
}}
.stat-card.verdict .label {{
  color: rgba(255,255,255,0.5);
}}
.stat-card.verdict-clean {{
  background: var(--surface);
}}
.stat-card.verdict-clean .value {{
  color: var(--text);
}}
.stat-card.verdict-clean .label {{
  color: var(--text-tertiary);
}}

/* ── Sections ──────────────────────────────────────── */
.section {{
  margin-bottom: 56px;
}}
.section h2 {{
  font-family: var(--serif);
  font-size: 20px;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 24px;
  padding-bottom: 16px;
  border-bottom: 1px solid var(--border);
  letter-spacing: -0.2px;
}}
.section-label {{
  font-family: var(--sans);
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--text-tertiary);
  margin-bottom: 8px;
}}

/* ── Incident cards ────────────────────────────────── */
.incident {{
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 24px;
  margin-bottom: 16px;
  background: var(--surface);
}}
.incident.critical {{
  border-left: 3px solid var(--text);
}}
.incident.high {{
  border-left: 3px solid var(--accent);
}}
.incident.medium {{
  border-left: 3px solid var(--border);
}}
.incident.low {{
  border-left: 3px solid var(--border-light);
}}
.incident-header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}}
.incident-title {{
  font-family: var(--serif);
  font-size: 16px;
  font-weight: 600;
}}
.badge {{
  display: inline-block;
  padding: 3px 10px;
  border-radius: 3px;
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.8px;
  font-family: var(--sans);
}}
.badge.critical {{ background: var(--text); color: #ffffff; }}
.badge.high {{ background: var(--accent-bg); color: var(--accent-strong); border: 1px solid var(--accent); }}
.badge.medium {{ background: var(--surface-alt); color: var(--text-secondary); border: 1px solid var(--border); }}
.badge.low {{ background: var(--surface-alt); color: var(--text-tertiary); border: 1px solid var(--border-light); }}
.incident .detail {{
  font-size: 13px;
  color: var(--text-secondary);
  margin-bottom: 8px;
  line-height: 1.6;
}}
.incident .detail strong {{
  color: var(--text);
  font-weight: 600;
}}
.incident .agents {{
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 8px;
}}
.agent-chip {{
  background: var(--surface-alt);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 2px 10px;
  font-size: 12px;
  font-family: var(--mono);
  color: var(--text);
}}
.incident .action-box {{
  margin-top: 16px;
  padding: 16px;
  background: var(--surface-alt);
  border-radius: 4px;
  font-size: 13px;
  color: var(--text-secondary);
  line-height: 1.6;
}}
.incident .action-box .action-label {{
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.8px;
  color: var(--accent-strong);
  margin-bottom: 6px;
}}

/* ── Tables ────────────────────────────────────────── */
table {{
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}}
th {{
  text-align: left;
  padding: 10px 14px;
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.8px;
  color: var(--text-tertiary);
  border-bottom: 2px solid var(--text);
}}
td {{
  padding: 10px 14px;
  border-bottom: 1px solid var(--border-light);
  vertical-align: middle;
}}
tr:last-child td {{
  border-bottom: 1px solid var(--border);
}}

/* ── Risk bar ──────────────────────────────────────── */
.risk-bar-container {{ display: flex; align-items: center; gap: 10px; }}
.risk-bar {{
  height: 6px;
  border-radius: 3px;
  background: var(--border-light);
  flex: 1;
  max-width: 180px;
  overflow: hidden;
}}
.risk-bar-fill {{
  height: 100%;
  border-radius: 3px;
}}
.risk-bar-fill.critical {{ background: var(--text); }}
.risk-bar-fill.high {{ background: var(--accent); }}
.risk-bar-fill.medium {{ background: var(--text-secondary); }}
.risk-bar-fill.low {{ background: var(--text-tertiary); }}

/* ── Topology SVG ──────────────────────────────────── */
.topology-wrap {{ display: flex; justify-content: center; margin: 24px 0; }}
.topology-wrap svg {{ max-width: 100%; }}
.topology-legend {{
  text-align: center;
  font-size: 11px;
  color: var(--text-tertiary);
  margin-top: 12px;
  letter-spacing: 0.2px;
}}

/* ── Donut chart ───────────────────────────────────── */
.chart-row {{ display: flex; gap: 40px; align-items: center; flex-wrap: wrap; }}
.donut-wrap {{ flex-shrink: 0; }}
.legend {{ display: flex; flex-direction: column; gap: 10px; }}
.legend-item {{ display: flex; align-items: center; gap: 10px; font-size: 13px; }}
.legend-dot {{ width: 10px; height: 10px; border-radius: 2px; flex-shrink: 0; }}
.legend-count {{ font-weight: 600; margin-left: auto; min-width: 24px; text-align: right; font-family: var(--mono); font-size: 13px; }}

/* ── Scenario ──────────────────────────────────────── */
.scenario p {{
  color: var(--text-secondary);
  line-height: 1.65;
  margin-bottom: 6px;
  font-size: 13px;
  max-width: 640px;
}}
.agent-list {{
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: 8px;
  margin-top: 20px;
}}
.agent-card {{
  background: var(--surface-alt);
  border: 1px solid var(--border-light);
  border-radius: 4px;
  padding: 14px 16px;
}}
.agent-card .name {{
  font-family: var(--mono);
  font-size: 12px;
  font-weight: 500;
  color: var(--text);
}}
.agent-card .desc {{
  font-size: 12px;
  color: var(--text-tertiary);
  margin-top: 4px;
}}

/* ── Compliance ────────────────────────────────────── */
.compliance-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 16px;
}}
.compliance-card {{
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 20px;
}}
.compliance-card .framework {{
  font-family: var(--serif);
  font-weight: 600;
  font-size: 14px;
  margin-bottom: 8px;
  color: var(--text);
}}
.compliance-card .articles {{
  font-size: 11px;
  color: var(--text-secondary);
  line-height: 1.7;
}}
.check {{ color: var(--accent-strong); font-weight: 700; }}

/* ── Domain chips ──────────────────────────────────── */
.domain-chip {{
  display: inline-block;
  padding: 1px 8px;
  border-radius: 3px;
  font-size: 11px;
  font-weight: 500;
  margin: 1px 2px;
  font-family: var(--mono);
}}
.domain-chip.health {{ background: #faf5f5; color: #8b4545; border: 1px solid #e8d5d5; }}
.domain-chip.finance {{ background: var(--accent-bg); color: var(--accent-strong); border: 1px solid #e8dfc0; }}
.domain-chip.social {{ background: #f5f5fa; color: #5b5b8b; border: 1px solid #d8d8e8; }}
.domain-chip.schedule {{ background: #f5faf5; color: #4b7b4b; border: 1px solid #d0e0d0; }}
.domain-chip.legal {{ background: var(--surface-alt); color: var(--text-secondary); border: 1px solid var(--border); }}
.domain-chip.identity {{ background: #faf5f8; color: #8b4570; border: 1px solid #e8d0dc; }}
.domain-chip.default {{ background: var(--surface-alt); color: var(--text-secondary); border: 1px solid var(--border); }}

/* ── Sensitivity dots ──────────────────────────────── */
.sensitivity {{ display: flex; gap: 3px; }}
.dot {{ width: 7px; height: 7px; border-radius: 50%; }}
.dot.filled {{ background: var(--text); }}
.dot.empty {{ background: var(--border-light); }}

/* ── Footer ────────────────────────────────────────── */
.footer {{
  text-align: center;
  padding: 40px;
  color: var(--text-tertiary);
  font-size: 12px;
  border-top: 1px solid var(--border);
  margin-top: 40px;
  line-height: 1.8;
}}

/* ── Separator ─────────────────────────────────────── */
.sep {{
  width: 40px;
  height: 1px;
  background: var(--accent);
  margin: 48px auto;
}}

@media print {{
  body {{ font-size: 12px; }}
  .container {{ max-width: 100%; padding: 0 24px; }}
  .section {{ margin-bottom: 32px; }}
  .stats {{ margin-bottom: 32px; }}
  .incident {{ break-inside: avoid; }}
}}
</style>
</head>
<body>"""


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

def _build_header(
    title: str, subtitle: str, company: str, logo_url: str,
    now: str, result: NetworkAuditResult,
) -> str:
    left = f'<h1>{_esc(title)}</h1>'
    if subtitle:
        left += f'<div class="subtitle">{_esc(subtitle)}</div>'

    right_lines = []
    if company:
        right_lines.append(f'<div class="company">{_esc(company)}</div>')
    right_lines.append(f'<div>Generated {now}</div>')
    right_lines.append(f'<div>Audit ID {result.audit_id[:12]}</div>')
    right = "\n".join(right_lines)

    return f"""
<div class="header">
  <div class="container">
    <div>{left}</div>
    <div class="meta">{right}</div>
  </div>
</div>
<div class="container">"""


# ---------------------------------------------------------------------------
# Executive summary (stat cards)
# ---------------------------------------------------------------------------

def _build_executive_summary(
    result: NetworkAuditResult, agg: AggregatedResult,
) -> str:
    crit = agg.alert_summary.get("critical", 0)
    high = agg.alert_summary.get("high", 0)
    med = agg.alert_summary.get("medium", 0)

    if crit > 0:
        verdict_class = "stat-card verdict"
        verdict_text = "CRITICAL"
    elif high > 0:
        verdict_class = "stat-card verdict"
        verdict_text = "AT RISK"
    elif med > 0:
        verdict_class = "stat-card"
        verdict_text = "CAUTION"
    else:
        verdict_class = "stat-card verdict-clean"
        verdict_text = "CLEAN"

    cards = [
        (verdict_class, verdict_text, "Verdict"),
        ("stat-card", str(result.total_agents), "Agents"),
        ("stat-card", str(result.total_edges), "Data Flows"),
        ("stat-card" + (" critical" if crit else ""), str(crit), "Critical"),
        ("stat-card" + (" high" if high else ""), str(high), "High"),
        ("stat-card", str(agg.original_risk_count), "Raw Risks"),
        ("stat-card", str(agg.incident_count), "Incidents"),
    ]

    html_cards = []
    for cls, val, label in cards:
        html_cards.append(
            f'<div class="{cls}"><div class="value">{val}</div>'
            f'<div class="label">{label}</div></div>'
        )

    return f'<div class="stats">{"".join(html_cards)}</div>'


# ---------------------------------------------------------------------------
# Scenario description + agent list
# ---------------------------------------------------------------------------

def _build_scenario(description: str, agent_descs: dict[str, str]) -> str:
    if not description and not agent_descs:
        return ""

    parts = ['<div class="section scenario">', '<h2>Audit Scenario</h2>']

    if description:
        for line in description.strip().split("\n"):
            line = line.strip()
            if line:
                parts.append(f"<p>{_esc(line)}</p>")

    if agent_descs:
        parts.append('<div class="agent-list">')
        for agent_id, desc in agent_descs.items():
            parts.append(
                f'<div class="agent-card">'
                f'<div class="name">{_esc(agent_id)}</div>'
                f'<div class="desc">{_esc(desc)}</div>'
                f'</div>'
            )
        parts.append("</div>")

    parts.append("</div>")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Network topology SVG
# ---------------------------------------------------------------------------

def _build_topology_svg(
    result: NetworkAuditResult,
    edges: list[DesensitizedEdge] | None,
    agent_descs: dict[str, str],
) -> str:
    agents = list(result.agent_risk_scores.keys())
    if not agents:
        return ""

    w, h = 780, 580
    cx, cy = w / 2, h / 2
    r = min(w, h) * 0.37
    n = len(agents)

    positions: dict[str, tuple[float, float]] = {}
    for i, agent in enumerate(agents):
        angle = (2 * math.pi * i / n) - math.pi / 2
        px = cx + r * math.cos(angle)
        py = cy + r * math.sin(angle)
        positions[agent] = (px, py)

    svg_parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" '
        f'width="{w}" height="{h}" style="background:transparent;">',
        '<defs>',
        '<marker id="arrow" viewBox="0 0 10 6" refX="10" refY="3" '
        'markerWidth="7" markerHeight="5" orient="auto-start-reverse">',
        '<path d="M0,0 L10,3 L0,6 Z" fill="#1a1a1a" opacity="0.35"/>',
        '</marker>',
        '<marker id="arrow-accent" viewBox="0 0 10 6" refX="10" refY="3" '
        'markerWidth="7" markerHeight="5" orient="auto-start-reverse">',
        '<path d="M0,0 L10,3 L0,6 Z" fill="#c8a84e" opacity="0.7"/>',
        '</marker>',
        '</defs>',
    ]

    # Draw edges
    if edges:
        for edge in edges:
            f = edge.from_agent
            t = edge.to_agent
            if f in positions and t in positions:
                x1, y1 = positions[f]
                x2, y2 = positions[t]
                dx, dy = x2 - x1, y2 - y1
                dist = math.sqrt(dx * dx + dy * dy) or 1
                ux, uy = dx / dist, dy / dist
                node_r = 38
                sx, sy = x1 + ux * node_r, y1 + uy * node_r
                ex, ey = x2 - ux * (node_r + 8), y2 - uy * (node_r + 8)

                if edge.sensitivity_level >= 4:
                    stroke, sw, marker = "#1a1a1a", "2", "url(#arrow)"
                elif edge.sensitivity_level >= 2:
                    stroke, sw, marker = "#c8a84e", "1.5", "url(#arrow-accent)"
                else:
                    stroke, sw, marker = "#c0bdb5", "1", "url(#arrow)"

                svg_parts.append(
                    f'<line x1="{sx:.1f}" y1="{sy:.1f}" x2="{ex:.1f}" y2="{ey:.1f}" '
                    f'stroke="{stroke}" stroke-width="{sw}" opacity="0.6" '
                    f'marker-end="{marker}"/>'
                )

    # Draw nodes
    for agent, (px, py) in positions.items():
        score = result.agent_risk_scores.get(agent, 0)
        if score >= 0.8:
            fill, stroke_c = "#1a1a1a", "#1a1a1a"
            text_fill = "#ffffff"
        elif score >= 0.5:
            fill, stroke_c = "#c8a84e", "#b8942e"
            text_fill = "#1a1a1a"
        elif score >= 0.3:
            fill, stroke_c = "#e8e5e0", "#c0bdb5"
            text_fill = "#1a1a1a"
        else:
            fill, stroke_c = "#fafaf9", "#e8e5e0"
            text_fill = "#6b6560"

        svg_parts.append(
            f'<circle cx="{px:.1f}" cy="{py:.1f}" r="36" '
            f'fill="{fill}" stroke="{stroke_c}" stroke-width="1.5"/>'
        )

        short = agent[:14]
        svg_parts.append(
            f'<text x="{px:.1f}" y="{py - 3:.1f}" text-anchor="middle" '
            f'font-size="10" fill="{text_fill}" '
            f'font-family="JetBrains Mono,SF Mono,monospace" '
            f'font-weight="500">{_esc(short)}</text>'
        )
        # Score inside node
        svg_parts.append(
            f'<text x="{px:.1f}" y="{py + 12:.1f}" text-anchor="middle" '
            f'font-size="12" fill="{text_fill}" opacity="0.6" '
            f'font-family="Inter,sans-serif" font-weight="600">'
            f'{score:.0%}</text>'
        )

    svg_parts.append("</svg>")

    return (
        '<div class="section">'
        '<h2>Agent Network Topology</h2>'
        '<div class="topology-wrap">' + "\n".join(svg_parts) + '</div>'
        '<div class="topology-legend">'
        'Node fill = risk level (dark = critical, gold = high, light = low)'
        ' &middot; Edge weight = data sensitivity'
        '</div>'
        '</div>'
    )


# ---------------------------------------------------------------------------
# Risk breakdown donut chart
# ---------------------------------------------------------------------------

def _build_risk_breakdown(agg: AggregatedResult) -> str:
    levels = [
        ("Critical", agg.alert_summary.get("critical", 0), "#1a1a1a"),
        ("High", agg.alert_summary.get("high", 0), "#c8a84e"),
        ("Medium", agg.alert_summary.get("medium", 0), "#c0bdb5"),
        ("Low", agg.alert_summary.get("low", 0), "#e8e5e0"),
    ]
    total = sum(c for _, c, _ in levels) or 1

    size = 140
    cr = 52
    stroke_w = 18
    circumference = 2 * math.pi * cr
    svg = [
        f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">',
        f'<circle cx="{size//2}" cy="{size//2}" r="{cr}" fill="none" '
        f'stroke="#f0eeea" stroke-width="{stroke_w}"/>',
    ]

    offset = 0
    for label, count, color in levels:
        if count == 0:
            continue
        pct = count / total
        dash = circumference * pct
        gap = circumference - dash
        svg.append(
            f'<circle cx="{size//2}" cy="{size//2}" r="{cr}" fill="none" '
            f'stroke="{color}" stroke-width="{stroke_w}" '
            f'stroke-dasharray="{dash:.1f} {gap:.1f}" '
            f'stroke-dashoffset="{-offset:.1f}" '
            f'transform="rotate(-90 {size//2} {size//2})"/>'
        )
        offset += dash

    svg.append(
        f'<text x="{size//2}" y="{size//2 - 4}" text-anchor="middle" '
        f'fill="#1a1a1a" font-size="22" font-weight="600" '
        f'font-family="Source Serif 4,Georgia,serif">{total}</text>'
    )
    svg.append(
        f'<text x="{size//2}" y="{size//2 + 12}" text-anchor="middle" '
        f'fill="#9b9590" font-size="10" font-family="Inter,sans-serif" '
        f'letter-spacing="0.5">incidents</text>'
    )
    svg.append("</svg>")

    legend_items = []
    for label, count, color in levels:
        legend_items.append(
            f'<div class="legend-item">'
            f'<div class="legend-dot" style="background:{color}"></div>'
            f'<span>{label}</span>'
            f'<span class="legend-count">{count}</span>'
            f'</div>'
        )

    type_counts: dict[str, int] = {}
    for inc in agg.incidents:
        type_counts[inc.risk_type] = type_counts.get(inc.risk_type, 0) + 1

    type_rows = ""
    for rtype, cnt in sorted(type_counts.items(), key=lambda x: -x[1]):
        readable = rtype.replace("_", " ").title()
        type_rows += f"<tr><td>{readable}</td><td style='text-align:right;font-family:var(--mono);font-weight:500'>{cnt}</td></tr>"

    return f"""
<div class="section">
  <h2>Risk Breakdown</h2>
  <div class="chart-row">
    <div class="donut-wrap">{''.join(svg)}</div>
    <div class="legend">{''.join(legend_items)}</div>
    <div style="margin-left:auto;">
      <table style="min-width:220px;">
        <tr><th>Risk Type</th><th style="text-align:right">Count</th></tr>
        {type_rows}
      </table>
    </div>
  </div>
</div>"""


# ---------------------------------------------------------------------------
# Scenario classification (AgentSocialBench taxonomy)
# ---------------------------------------------------------------------------

_SCENARIO_LABELS = {
    "CD": "Cross-Domain",
    "MC": "Mediated Communication",
    "CU": "Cross-User",
    "GC": "Group Chat",
    "HS": "Hub-and-Spoke",
    "CM": "Competitive",
    "AM": "Affinity-Modulated",
}

_SCENARIO_COLORS = {
    "CD": "#1a1a1a",
    "MC": "#c8a84e",
    "CU": "#8b4545",
    "GC": "#5b5b8b",
    "HS": "#4b7b4b",
    "CM": "#b8942e",
    "AM": "#9b9590",
}


def _build_scenario_classification(result: NetworkAuditResult) -> str:
    summary = result.scenario_summary
    if not summary:
        return ""

    total = sum(summary.values()) or 1
    items = sorted(summary.items(), key=lambda x: -x[1])

    bars = []
    for code, count in items:
        label = _SCENARIO_LABELS.get(code, code)
        color = _SCENARIO_COLORS.get(code, "#9b9590")
        pct = count / total * 100
        bars.append(
            f'<div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;">'
            f'<code style="font-family:var(--mono);font-size:12px;font-weight:600;'
            f'min-width:28px;color:{color}">{_esc(code)}</code>'
            f'<span style="font-size:13px;min-width:160px">{_esc(label)}</span>'
            f'<div style="flex:1;height:6px;background:var(--border-light);'
            f'border-radius:3px;max-width:200px;overflow:hidden">'
            f'<div style="width:{pct:.0f}%;height:100%;background:{color};'
            f'border-radius:3px"></div></div>'
            f'<span style="font-family:var(--mono);font-size:12px;'
            f'font-weight:500;min-width:24px;text-align:right">{count}</span>'
            f'</div>'
        )

    return f"""
<div class="section">
  <h2>Scenario Classification</h2>
  <div class="section-label">AgentSocialBench taxonomy &middot; {total} risks classified</div>
  <div style="margin-top:16px;">{''.join(bars)}</div>
</div>"""


# ---------------------------------------------------------------------------
# Blame attribution
# ---------------------------------------------------------------------------

def _build_blame_attribution(agg: AggregatedResult) -> str:
    blamed_incidents = [
        inc for inc in agg.incidents if inc.blame_agents
    ]
    if not blamed_incidents:
        return ""

    rows = []
    for inc in sorted(blamed_incidents, key=lambda i: -i.severity):
        level = inc.alert_level.value
        readable_type = inc.risk_type.replace("_", " ").title()
        blamed = ", ".join(inc.blame_agents)
        scenario_badge = ""
        if inc.scenario_type:
            sc_color = _SCENARIO_COLORS.get(inc.scenario_type, "#9b9590")
            scenario_badge = (
                f'<code style="font-family:var(--mono);font-size:10px;'
                f'padding:2px 6px;border-radius:3px;background:var(--surface-alt);'
                f'border:1px solid var(--border);color:{sc_color}">'
                f'{_esc(inc.scenario_type)}</code> '
            )

        rows.append(f"""<tr>
  <td>{scenario_badge}<span style="font-size:13px">{_esc(readable_type)}</span></td>
  <td><span class="badge {level}" style="font-size:9px">{level}</span></td>
  <td><code style="font-family:var(--mono);font-size:12px;font-weight:600">{_esc(blamed)}</code></td>
</tr>""")

    return f"""
<div class="section">
  <h2>Blame Attribution</h2>
  <div class="section-label">Causal analysis &middot; {len(blamed_incidents)} incidents with identified root agents</div>
  <table style="margin-top:16px;">
    <tr><th>Incident</th><th>Level</th><th>Blamed Agent(s)</th></tr>
    {''.join(rows)}
  </table>
</div>"""


# ---------------------------------------------------------------------------
# Agent risk scores
# ---------------------------------------------------------------------------

def _build_agent_scores(
    result: NetworkAuditResult, agent_descs: dict[str, str],
) -> str:
    scores = sorted(
        result.agent_risk_scores.items(), key=lambda x: -x[1],
    )
    if not scores:
        return ""

    rows = []
    for agent, score in scores:
        desc = agent_descs.get(agent, "")
        pct = score * 100

        if score >= 0.8:
            level_cls = "critical"
        elif score >= 0.5:
            level_cls = "high"
        elif score >= 0.3:
            level_cls = "medium"
        else:
            level_cls = "low"

        rows.append(f"""<tr>
  <td><code style="font-family:var(--mono);font-size:12px;">{_esc(agent)}</code></td>
  <td style="color:var(--text-tertiary);font-size:12px;">{_esc(desc)}</td>
  <td>
    <div class="risk-bar-container">
      <div class="risk-bar"><div class="risk-bar-fill {level_cls}" style="width:{pct:.0f}%"></div></div>
      <span style="font-family:var(--mono);font-size:12px;font-weight:500;min-width:36px;text-align:right">{score:.0%}</span>
    </div>
  </td>
</tr>""")

    return f"""
<div class="section">
  <h2>Agent Risk Scores</h2>
  <table>
    <tr><th>Agent</th><th>Role</th><th>Risk Score</th></tr>
    {''.join(rows)}
  </table>
</div>"""


# ---------------------------------------------------------------------------
# Incident details
# ---------------------------------------------------------------------------

def _build_incidents(agg: AggregatedResult) -> str:
    if not agg.incidents:
        return ""

    cards = []
    for inc in sorted(agg.incidents, key=lambda i: -i.severity):
        level = inc.alert_level.value
        readable_type = inc.risk_type.replace("_", " ").title()

        agents_html = "".join(
            f'<span class="agent-chip">{_esc(a)}</span>' for a in inc.involved_agents
        )

        cards.append(f"""
<div class="incident {level}">
  <div class="incident-header">
    <span class="incident-title">{readable_type}</span>
    <span class="badge {level}">{level} &middot; {inc.severity:.0%}</span>
  </div>
  <div class="detail">{_esc(inc.root_cause)}</div>
  <div class="agents">{agents_html}</div>
  <div class="action-box">
    <div class="action-label">Action</div>
    {_esc(inc.recommended_action)}
  </div>
</div>""")

    return f"""
<div class="section">
  <h2>Incidents</h2>
  <div class="section-label">{agg.incident_count} incidents from {agg.original_risk_count} raw risks</div>
  {''.join(cards)}
</div>"""


# ---------------------------------------------------------------------------
# Data flow table
# ---------------------------------------------------------------------------

def _build_data_flow_table(edges: list[DesensitizedEdge] | None) -> str:
    if not edges:
        return ""

    rows = []
    for e in edges:
        domains_html = "".join(
            f'<span class="domain-chip {d if d in ("health","finance","social","schedule","legal","identity") else "default"}">{_esc(d)}</span>'
            for d in e.domains
        )

        dots = ""
        for i in range(5):
            cls = "filled" if i < e.sensitivity_level else "empty"
            dots += f'<span class="dot {cls}"></span>'

        action_style = ""
        if e.local_action == "block":
            action_style = "font-weight:600"
        elif e.local_action == "redact":
            action_style = "color:var(--accent-strong);font-weight:500"

        taint_info = ""
        if e.taint:
            hops = e.taint.hop_count
            inf = e.taint.inference_risk
            taint_info = f'<span style="font-size:11px;font-family:var(--mono);color:var(--text-tertiary)">hop={hops} inf={inf:.0%}</span>'

        rows.append(f"""<tr>
  <td><code style="font-family:var(--mono);font-size:12px">{_esc(e.from_agent)}</code></td>
  <td><code style="font-family:var(--mono);font-size:12px">{_esc(e.to_agent)}</code></td>
  <td>{domains_html or '<span style="color:var(--text-tertiary)">-</span>'}</td>
  <td><div class="sensitivity">{dots}</div></td>
  <td style="{action_style}">{e.local_action}</td>
  <td>{taint_info}</td>
</tr>""")

    return f"""
<div class="section">
  <details>
    <summary style="cursor:pointer;font-family:var(--serif);font-size:20px;font-weight:600;color:var(--text);padding-bottom:16px;border-bottom:1px solid var(--border);letter-spacing:-0.2px;">Data Flow Details</summary>
    <table style="margin-top:16px;">
      <tr><th>From</th><th>To</th><th>Domains</th><th>Sensitivity</th><th>Action</th><th>Taint</th></tr>
      {''.join(rows)}
    </table>
  </details>
</div>"""


# ---------------------------------------------------------------------------
# Compliance section
# ---------------------------------------------------------------------------

_COMPLIANCE_MAP = {
    "GDPR": {
        "articles": ["Art 25 (Data Protection by Design)", "Art 30 (Records of Processing)", "Art 32 (Security)", "Art 35 (DPIA)"],
        "coverage": ["Privacy gate & redaction", "Hash-chain audit trail", "Pseudonymization + encryption", "Risk quantification"],
    },
    "SOC 2 Type II": {
        "articles": ["CC6.1 (Logical Access)", "CC7.2 (Monitoring)", "CC7.3 (Change Detection)", "CC7.4 (Incident Response)"],
        "coverage": ["Access control (Bell-LaPadula)", "7-channel auditing", "Cross-container verification", "Risk aggregation + alerting"],
    },
    "EU AI Act": {
        "articles": ["Art 9 (Risk Management)", "Art 12 (Record-Keeping)", "Art 14 (Traceability)", "Art 15 (Accuracy & Security)"],
        "coverage": ["Compound attack detection", "Epoch commitment chain", "Taint tracking", "Injection detection"],
    },
    "ISO 27001": {
        "articles": ["A.5.15 (Access Control)", "A.8.2 (Classification)", "A.8.11 (Data Masking)", "A.8.15 (Logging)"],
        "coverage": ["MAC access control", "Sensitivity levels", "6-layer desensitization", "Merkle tree audit log"],
    },
}


def _build_compliance_section(agg: AggregatedResult) -> str:
    cards = []
    for framework, info in _COMPLIANCE_MAP.items():
        articles = "".join(
            f'<div><span class="check">&#10003;</span> {_esc(a)} &mdash; {_esc(c)}</div>'
            for a, c in zip(info["articles"], info["coverage"])
        )
        cards.append(
            f'<div class="compliance-card">'
            f'<div class="framework">{_esc(framework)}</div>'
            f'<div class="articles">{articles}</div>'
            f'</div>'
        )

    return f"""
<div class="section">
  <h2>Compliance Coverage</h2>
  <div class="compliance-grid">{''.join(cards)}</div>
</div>"""


# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------

def _build_footer(now: str) -> str:
    return f"""
</div><!-- /container -->
<div class="footer">
  Federated Agent Audit<br>
  Cryptographic privacy auditing for multi-agent systems<br>
  <span style="color:var(--border);">&mdash;</span><br>
  Report generated {now}
</div>
</body>
</html>"""


def _esc(s: str) -> str:
    return html_mod.escape(str(s))

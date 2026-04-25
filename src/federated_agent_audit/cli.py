"""Command-line interface for federated-agent-audit.

Usage:
    federated-audit server [--host HOST] [--port PORT] [--token TOKEN]
    federated-audit validate <policy_file>...
    federated-audit audit <policy_dir> <trace_file>
    federated-audit report <audit_result.json> [-o report.html]
    federated-audit demo
    federated-audit version
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="federated-audit",
        description="Privacy-preserving audit framework for multi-agent AI systems",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose logging",
    )
    sub = parser.add_subparsers(dest="command")

    # ── server ──────────────────────────────────────────────────
    srv = sub.add_parser("server", help="Start the central audit server")
    srv.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    srv.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    srv.add_argument("--token", default="", help="Bearer auth token (optional)")
    srv.add_argument("--reload", action="store_true", help="Auto-reload on code changes")

    # ── validate ────────────────────────────────────────────────
    val = sub.add_parser("validate", help="Validate policy files")
    val.add_argument("files", nargs="+", help="Policy file(s) — .json or .yaml")

    # ── demo ────────────────────────────────────────────────────
    sub.add_parser("demo", help="Run the Telegram group chat demo and generate report")

    # ── report ──────────────────────────────────────────────────
    rpt = sub.add_parser("report", help="Generate HTML report from audit result JSON")
    rpt.add_argument("input", help="NetworkAuditResult JSON file")
    rpt.add_argument("-o", "--output", default="audit_report.html", help="Output HTML path")
    rpt.add_argument("--title", default="Federated Agent Audit Report", help="Report title")

    # ── version ─────────────────────────────────────────────────
    sub.add_parser("version", help="Print version and exit")

    args = parser.parse_args(argv)

    # Configure logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.command == "version":
        _cmd_version()
    elif args.command == "server":
        _cmd_server(args)
    elif args.command == "validate":
        _cmd_validate(args)
    elif args.command == "demo":
        _cmd_demo()
    elif args.command == "report":
        _cmd_report(args)
    else:
        parser.print_help()
        sys.exit(1)


def _cmd_version() -> None:
    from . import __version__
    print(f"federated-agent-audit {__version__}")


def _cmd_server(args: argparse.Namespace) -> None:
    try:
        import uvicorn
    except ImportError:
        print("Error: uvicorn is required. Install with: pip install 'federated-agent-audit[transport]'",
              file=sys.stderr)
        sys.exit(1)

    from .transport.server import create_app

    app = create_app(auth_token=args.token or None)
    print(f"Starting federated audit server on {args.host}:{args.port}")
    if args.token:
        print(f"Auth token: {args.token[:4]}{'*' * (len(args.token) - 4)}")
    uvicorn.run(app, host=args.host, port=args.port, reload=args.reload)


def _cmd_validate(args: argparse.Namespace) -> None:
    from .config import load_policy, validate_policy

    all_ok = True
    for filepath in args.files:
        path = Path(filepath)
        print(f"\n{'─' * 50}")
        print(f"  {path.name}")
        print(f"{'─' * 50}")

        try:
            policy = load_policy(path)
            print(f"  agent_id:    {policy.agent_id}")
            print(f"  blocklist:   {len(policy.must_not_share)} terms")
            print(f"  abstractions: {len(policy.acceptable_abstractions)}")
            print(f"  threshold:   {policy.sensitivity_threshold}")

            warnings = validate_policy(path)
            if warnings:
                all_ok = False
                for w in warnings:
                    print(f"  WARNING: {w}")
            else:
                print("  OK")
        except Exception as e:
            all_ok = False
            print(f"  ERROR: {e}")

    print()
    if all_ok:
        print(f"All {len(args.files)} policies valid.")
    else:
        print("Some policies have warnings or errors.", file=sys.stderr)
        sys.exit(1)


def _cmd_demo() -> None:
    """Run the telegram demo inline."""
    demo_path = Path(__file__).parent.parent.parent / "examples" / "telegram_audit_demo.py"

    if demo_path.exists():
        print(f"Running demo from {demo_path}...")
        print()
        # Import and run main()
        import importlib.util
        spec = importlib.util.spec_from_file_location("demo", demo_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.main()
    else:
        # Fallback: run inline minimal demo
        _run_inline_demo()


def _run_inline_demo() -> None:
    """Minimal self-contained demo that doesn't need the examples/ folder."""
    from . import FederatedAudit, PrivacyPolicy, NetworkAuditor, RiskAggregator

    print("Federated Audit — Quick Demo")
    print("=" * 50)

    policy_a = PrivacyPolicy(agent_id="agent_a", must_not_share=["email", "SSN"])
    policy_b = PrivacyPolicy(agent_id="agent_b", must_not_share=["salary"])

    audit_a = FederatedAudit(policy=policy_a, user_id="user1")
    audit_b = FederatedAudit(policy=policy_b, user_id="user1")

    # Agent A sends to Agent B
    audit_a.record_outgoing(
        "User's email is john@example.com",
        to_agent="agent_b",
        sensitivity_level=4,
        privacy_tags=["identity"],
    )

    # Agent B forwards to external
    audit_b.record_outgoing(
        "The user's salary is $90,000",
        to_agent="external",
        sensitivity_level=5,
        privacy_tags=["finance"],
    )

    # Collect reports
    report_a = audit_a.get_report(apply_dp=False)
    report_b = audit_b.get_report(apply_dp=False)

    # Network audit
    net = NetworkAuditor()
    net.ingest_report(report_a)
    net.ingest_report(report_b)
    result = net.audit()

    print(f"\nAgents: {result.total_agents}")
    print(f"Edges: {result.total_edges}")
    print(f"Risks: {len(result.compositional_risks)}")

    for risk in result.compositional_risks[:3]:
        print(f"  [{risk.risk_type}] severity={risk.severity:.2f} — {risk.description[:80]}")

    # Aggregate
    agg = RiskAggregator().aggregate(result)
    print(f"\nIncidents: {agg.incident_count}")
    print(f"Alert summary: {agg.alert_summary}")
    print("\nDone. Install pyyaml for YAML policy support: pip install 'federated-agent-audit[yaml]'")


def _cmd_report(args: argparse.Namespace) -> None:
    from .schemas import NetworkAuditResult
    from .risk_aggregator import RiskAggregator
    from .reporting import generate_html_report

    path = Path(args.input)
    if not path.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)

    data = json.loads(path.read_text(encoding="utf-8"))
    result = NetworkAuditResult(**data)

    agg = RiskAggregator().aggregate(result)

    html = generate_html_report(
        network_result=result,
        aggregated_result=agg,
        title=args.title,
    )

    out = Path(args.output)
    out.write_text(html, encoding="utf-8")
    print(f"Report saved to {out}")
    print(f"Open: file://{out.resolve()}")


if __name__ == "__main__":
    main()

"""CLI: prodwatch analyze | demo | rules"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .agent import analyze
from .rules import all_rules


def _print_summary(report, out_dir: str) -> None:
    counts = {sev: len(report.by_severity(sev))
              for sev in ("critical", "high", "medium", "low")}
    print(f"\nAnalyzed: {report.repo}")
    st = report.stack
    print(f"Stack: {', '.join(st.languages) or '?'}"
          f" / {', '.join(st.frameworks) or '?'}")
    print(f"Findings: {len(report.findings)} "
          f"({counts['critical']} critical, {counts['high']} high, "
          f"{counts['medium']} medium, {counts['low']} low)")
    print(f"Reports written to: {Path(out_dir).resolve()}")
    top = report.ranked()[:5]
    if top:
        print("\nTop findings:")
        for f in top:
            print(f"  [{f.severity.upper():8}] {f.title} — {f.where()}")


def cmd_analyze(args) -> int:
    formats = tuple(f.strip() for f in args.formats.split(",") if f.strip())
    report = analyze(
        args.repo,
        signals_dir=args.signals,
        out_dir=args.out,
        use_llm=not args.no_llm,
        custom_rules_path=args.custom_rules,
        formats=formats,
        name=args.name,
    )
    _print_summary(report, args.out)
    return 0


def cmd_demo(args) -> int:
    here = Path(__file__).resolve()
    candidates = [
        Path.cwd() / "examples" / "demo-app",
        here.parents[2] / "examples" / "demo-app",
    ]
    demo = next((c for c in candidates if c.is_dir()), None)
    if demo is None:
        print("demo app not found (looked in ./examples/demo-app)",
              file=sys.stderr)
        return 1
    args.repo = str(demo)
    args.signals = str(demo / "signals")
    args.name = "demo"
    return cmd_analyze(args)


def cmd_rules(_args) -> int:
    rules = all_rules()
    print(f"{'ID':<10}{'SEVERITY':<10}{'CATEGORY':<15}TITLE")
    for r in sorted(rules, key=lambda r: r.id):
        print(f"{r.id:<10}{r.default_severity:<10}{r.category:<15}{r.title}")
    print(f"\n{len(rules)} built-in rules. "
          "Add more with --custom-rules or subclass prodwatch.rules.base.Rule.")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="prodwatch",
        description="Analyze production issues from any repo + observability signals.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="analyze a repo (path or git URL)")
    a.add_argument("repo", help="local path or git URL")
    a.add_argument("--signals", default=None,
                   help="dir with app.log / metrics.json / traces.json / errors.json")
    a.add_argument("--out", default="reports", help="report output dir")
    a.add_argument("--name", default="report", help="report filename infix")
    a.add_argument("--formats", default="md,json", help="md,json")
    a.add_argument("--no-llm", action="store_true",
                   help="skip the optional LLM summary layer")
    a.add_argument("--custom-rules", default=None,
                   help="path to custom rules JSON file")
    a.set_defaults(func=cmd_analyze)

    d = sub.add_parser("demo", help="run against the bundled demo app")
    d.add_argument("--out", default="reports")
    d.add_argument("--formats", default="md,json")
    d.add_argument("--no-llm", action="store_true")
    d.add_argument("--custom-rules", default=None)
    d.set_defaults(func=cmd_demo)

    r = sub.add_parser("rules", help="list built-in rules")
    r.set_defaults(func=cmd_rules)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

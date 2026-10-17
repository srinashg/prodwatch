"""Report writers: human-readable Markdown + machine-readable JSON."""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path


def _counts(report) -> dict:
    return {sev: len(report.by_severity(sev))
            for sev in ("critical", "high", "medium", "low")}


def write_markdown(report, path: str | Path, rules_run: int = 0) -> Path:
    path = Path(path)
    counts = _counts(report)
    ranked = report.ranked()
    L = []

    L.append(f"# ProdWatch report — `{Path(report.repo).name}`")
    L.append(f"_Generated {report.generated_at} · {rules_run} rules · "
             f"{len(report.findings)} findings_")
    L.append("")
    L.append("## Executive summary")
    if report.llm_summary:
        L.append(report.llm_summary)
    else:
        L.append(f"{counts['critical']} critical, {counts['high']} high, "
                 f"{counts['medium']} medium, {counts['low']} low findings.")
        if ranked:
            L.append("Top priorities:")
            for f in ranked[:3]:
                L.append(f"- **[{f.severity.upper()}]** {f.title} — {f.where()}")
    L.append("")

    L.append("## Stack")
    st = report.stack
    L.append(f"- Languages: {', '.join(st.languages) or 'unknown'}")
    L.append(f"- Frameworks: {', '.join(st.frameworks) or 'unknown'}")
    L.append(f"- Dockerfile: {'yes' if st.has_dockerfile else 'no'} · "
             f"CI: {'yes' if st.has_ci else 'no'}")
    if st.entry_points:
        L.append(f"- Entry points: {', '.join(st.entry_points)}")
    L.append("")

    L.append("## Observability snapshot")
    s = report.signals
    L.append(f"- Log errors: **{s.log_errors}** · warnings: {s.log_warns}")
    if s.slowest_operations:
        L.append("- Slowest operations (p95):")
        for name, p95, count in s.slowest_operations:
            L.append(f"  - `{name}` — {p95:.0f}ms (n={count})")
    if s.top_error_signatures:
        L.append("- Top log error signatures:")
        for sig, n in s.top_error_signatures:
            L.append(f"  - `{sig[:100]}` (x{n})")
    if s.top_error_issues:
        L.append("- Top reported issues:")
        for title, n in s.top_error_issues:
            L.append(f"  - `{title[:100]}` (x{n})")
    for note in s.notes:
        L.append(f"- _{note}_")
    L.append("")

    L.append("## Findings (ranked)")
    if not ranked:
        L.append("_No findings — either the code is clean or the rules don't "
                 "cover this stack yet._")
    for f in ranked:
        L.append(f"### [{f.severity.upper()}] {f.title}")
        L.append(f"`{f.rule_id}` · {f.category} · confidence: {f.confidence} · "
                 f"effort: {f.effort} · {f.where()}")
        for e in f.evidence:
            L.append(f"- {e}")
        if f.impact:
            L.append(f"**Impact:** {f.impact}")
        if f.recommendation:
            L.append(f"**Recommendation:** {f.recommendation}")
        L.append("")

    L.append("## Methodology")
    L.append("Static heuristics (regex/AST-lite) + file-based production signals "
             "(logs, metrics, traces, error reports). Findings are scored by "
             "severity × confidence; signal corroboration raises confidence. "
             "Heuristics have false positives by design — treat medium/low "
             "confidence items as leads, not verdicts.")
    path.write_text("\n".join(L), encoding="utf-8")
    return path


def write_json(report, path: str | Path) -> Path:
    path = Path(path)
    data = asdict(report)
    data["findings"] = [asdict(f) for f in report.ranked()]
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path

"""Orchestrator: scan repo -> ingest signals -> run rules -> correlate -> report."""
from __future__ import annotations

import re
import sys
from datetime import datetime
from pathlib import Path

from . import llm, repo
from . import signals as sigmod
from .models import Finding, Report
from .reporters import write_json, write_markdown
from .rules import RuleContext, all_rules
from .rules.loader import load_custom_rules


def _signal_findings(s) -> list:
    """Turn raw production signals into findings of their own."""
    out = []

    if s.log_errors >= 200:
        sev = "critical"
    elif s.log_errors >= 50:
        sev = "high"
    elif s.log_errors >= 10:
        sev = "medium"
    else:
        sev = None
    if sev:
        out.append(Finding(
            rule_id="SIG001",
            title=f"Elevated error volume in logs ({s.log_errors} errors)",
            category="reliability", severity=sev, confidence="high",
            evidence=[f"{sig} (x{n})" for sig, n in s.top_error_signatures[:3]],
            impact=("Users are hitting errors right now; this volume suggests a "
                    "systemic cause, not one-offs."),
            recommendation=("Triage the top signatures first; correlate with recent "
                            "deploys or config changes."),
            effort="M"))

    for name, p95, count in s.slowest_operations[:3]:
        if p95 >= 2000:
            sev = "high"
        elif p95 >= 800:
            sev = "medium"
        else:
            continue
        out.append(Finding(
            rule_id="SIG002",
            title=f"Slow operation: {name} (p95 {p95:.0f}ms)",
            category="performance", severity=sev, confidence="high",
            evidence=[f"p95 latency {p95:.0f}ms across {count} sampled spans"],
            impact="Tail latency hurts user experience and cascades under load.",
            recommendation=("Profile this operation: look for N+1 queries, missing "
                            "indexes, or slow upstream calls."),
            effort="M"))

    for title, count in s.top_error_issues[:3]:
        out.append(Finding(
            rule_id="SIG003",
            title=f"Top production error: {title[:90]} (x{count})",
            category="reliability",
            severity="high" if count >= 50 else "medium",
            confidence="high",
            evidence=[f"reported {count} times"],
            impact="Recurring error affecting production traffic.",
            recommendation=("Fix at the source; add a regression test and alert "
                            "on reoccurrence."),
            effort="M"))
    return out


def _correlate(findings: list, s) -> list:
    """Boost static findings that production signals corroborate."""
    stop = {"error", "errors", "exception", "exceptions", "failed", "failure",
            "line", "file", "traceback", "trace"}
    tokens = set()
    for name, _p95, _c in s.slowest_operations:
        tokens.update(re.findall(r"[a-zA-Z]{3,}", name.lower()))
    for sig, _n in s.top_error_signatures:
        tokens.update(re.findall(r"[a-zA-Z]{3,}", sig.lower()))
    for title, _n in s.top_error_issues:
        tokens.update(re.findall(r"[a-zA-Z]{3,}", title.lower()))
    tokens -= stop
    for f in findings:
        if f.rule_id.startswith("SIG"):
            continue
        hay = f"{f.title} {f.file or ''}".lower()
        hits = sorted({t for t in tokens if len(t) > 3 and t in hay})[:3]
        if hits:
            f.evidence.append(
                "Corroborated by production signal "
                f"(matched: {', '.join(hits)})")
            if f.confidence == "medium":
                f.confidence = "high"
    return findings


def _repo_label(source: str, root: Path) -> str:
    """Human-friendly repo name: 'ai-study-assistant' from a git URL,
    directory name for local paths."""
    m = re.search(r"[:/]([^/:]+?)(?:\.git)?/?$", source.strip().rstrip("/"))
    if m:
        return m.group(1)
    return root.name


def analyze(source: str, signals_dir: str | None = None,
            out_dir: str = "reports", use_llm: bool = True,
            custom_rules_path: str | None = None,
            formats: tuple = ("md", "json"),
            name: str = "report") -> Report:
    root = repo.ensure_repo(source)
    stack = repo.detect_stack(root)
    files = {p.relative_to(root).as_posix(): repo.read_text_safe(p)
             for p in repo.source_files(root)}

    s = sigmod.load_signals(signals_dir)
    ctx = RuleContext(root=root, files=files, stack=stack, signals=s)

    rules = all_rules()
    if custom_rules_path:
        rules = rules + load_custom_rules(custom_rules_path)

    findings: list = []
    for rule in rules:
        try:
            findings.extend(rule.check(ctx))
        except Exception as e:  # one bad rule must not kill the run
            print(f"[prodwatch] rule {rule.id} failed: {e}", file=sys.stderr)

    findings.extend(_signal_findings(s))
    findings = _correlate(findings, s)

    report = Report(repo=_repo_label(source, root), stack=stack,
                    signals=s, findings=findings)
    if use_llm:
        report.llm_summary = llm.refine_summary(report.ranked(), s, stack)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    if "md" in formats:
        write_markdown(report, out / f"prodwatch-{name}-{stamp}.md",
                       rules_run=len(rules))
    if "json" in formats:
        write_json(report, out / f"prodwatch-{name}-{stamp}.json")
    return report

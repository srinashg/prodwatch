"""Observability signal ingestion.

Parses file-based production signals into a summary the agent can reason
about. In a full deployment these adapters would be replaced by live APM
integrations (Datadog, Prometheus, OpenTelemetry…); the summary shape they
produce stays the same.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from .models import SignalsSummary
from .repo import read_text_safe


def _percentile(values: list, pct: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = max(0, min(len(s) - 1, int((pct / 100.0) * len(s))))
    return float(s[k])


def parse_logs(path: Path) -> dict:
    """Count errors/warns and extract normalized error signatures."""
    err_re = re.compile(r"\b(ERROR|CRITICAL|FATAL|Exception)\b")
    warn_re = re.compile(r"\b(WARN|WARNING)\b")
    tb_re = re.compile(r"(\w+(?:Error|Exception|Timeout\w*))\s*:\s*(.*)")
    errors, warns = 0, 0
    sigs: Counter = Counter()
    for line in read_text_safe(path).splitlines():
        if err_re.search(line):
            errors += 1
            m = tb_re.search(line)
            if m:
                sig = f"{m.group(1)}: {m.group(2)[:80]}".strip()
            else:
                sig = re.sub(r"^[\d\-\s:,./T+Z\[\]()]+", "", line).strip()[:100]
                sig = sig or line.strip()[:100]
            sigs[sig] += 1
        elif warn_re.search(line):
            warns += 1
    return {"error_count": errors, "warn_count": warns,
            "top": sigs.most_common(5)}


def parse_metrics(path: Path) -> dict:
    """Slowest operations by p95 latency.

    Accepts {"endpoints": {name: {"p95_ms": n, ...}}} or a flat
    {name: {"p95_ms": n}} mapping.
    """
    try:
        data = json.loads(read_text_safe(path))
    except json.JSONDecodeError:
        return {"slowest": [], "note": f"could not parse {path.name} as JSON"}
    endpoints = {}
    if isinstance(data, dict):
        if isinstance(data.get("endpoints"), dict):
            endpoints = data["endpoints"]
        else:
            endpoints = {k: v for k, v in data.items() if isinstance(v, dict)}
    rows = []
    for name, m in endpoints.items():
        p95 = m.get("p95_ms", m.get("p95", m.get("latency_p95_ms", 0)))
        try:
            rows.append((str(name), float(p95)))
        except (TypeError, ValueError):
            continue
    rows.sort(key=lambda r: r[1], reverse=True)
    return {"slowest": rows[:5]}


def parse_traces(path: Path) -> dict:
    """Group spans by operation name; report p95 duration per operation."""
    try:
        data = json.loads(read_text_safe(path))
    except json.JSONDecodeError:
        return {"slowest": [], "note": f"could not parse {path.name} as JSON"}
    spans = data if isinstance(data, list) else data.get("spans", [])
    by_name: dict = {}
    for s in spans:
        if not isinstance(s, dict):
            continue
        name = str(s.get("name", s.get("operation", "unknown")))
        try:
            dur = float(s.get("duration_ms", s.get("duration", 0)))
        except (TypeError, ValueError):
            continue
        by_name.setdefault(name, []).append(dur)
    rows = [(n, _percentile(v, 95), len(v)) for n, v in by_name.items()]
    rows.sort(key=lambda r: r[1], reverse=True)
    return {"slowest": rows[:5]}


def parse_errors(path: Path) -> dict:
    """Top error issues, e.g. a Sentry-style export: [{"title","count"}]."""
    try:
        data = json.loads(read_text_safe(path))
    except json.JSONDecodeError:
        return {"top": [], "note": f"could not parse {path.name} as JSON"}
    items = data if isinstance(data, list) else data.get("issues", [])
    rows = []
    for it in items:
        if not isinstance(it, dict):
            continue
        title = str(it.get("title", it.get("message", "unknown")))
        try:
            count = int(it.get("count", it.get("events", 1)))
        except (TypeError, ValueError):
            count = 1
        rows.append((title, count))
    rows.sort(key=lambda r: r[1], reverse=True)
    return {"top": rows[:5]}


def _norm_op(name: str) -> str:
    """Normalize an operation name so 'GET /api/orders' and '/api/orders'
    merge into one entry."""
    norm = re.sub(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+",
                  "", str(name)).strip()
    return norm or str(name)


def load_signals(signals_dir: str | None) -> SignalsSummary:
    summary = SignalsSummary()
    if not signals_dir:
        summary.notes.append("no signals directory provided — static analysis only")
        return summary
    d = Path(signals_dir).expanduser()
    if not d.is_dir():
        summary.notes.append(f"signals dir not found: {signals_dir}")
        return summary

    slowest: dict = {}  # normalized name -> [p95_ms, span_count]

    def _add_slow(name: str, p95: float, count: int = 0) -> None:
        key = _norm_op(name)
        prev = slowest.get(key, [0.0, 0])
        slowest[key] = [max(prev[0], p95), prev[1] + count]

    if (d / "app.log").is_file():
        r = parse_logs(d / "app.log")
        summary.log_errors, summary.log_warns = r["error_count"], r["warn_count"]
        summary.top_error_signatures = r["top"]
    if (d / "metrics.json").is_file():
        r = parse_metrics(d / "metrics.json")
        for name, p95 in r["slowest"]:
            _add_slow(name, p95)
        summary.notes.extend([r["note"]] if r.get("note") else [])
    if (d / "traces.json").is_file():
        r = parse_traces(d / "traces.json")
        for name, p95, count in r["slowest"]:
            _add_slow(name, p95, count)
        summary.notes.extend([r["note"]] if r.get("note") else [])
    if (d / "errors.json").is_file():
        r = parse_errors(d / "errors.json")
        summary.top_error_issues = r["top"]
        summary.notes.extend([r["note"]] if r.get("note") else [])

    summary.slowest_operations = [
        (name, p95, count) for name, (p95, count) in
        sorted(slowest.items(), key=lambda kv: kv[1][0], reverse=True)[:5]
    ]
    if not any([summary.log_errors, summary.slowest_operations,
                summary.top_error_issues]):
        summary.notes.append("signals dir present but no recognizable signal files")
    return summary

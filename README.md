# ProdWatch — production issue analysis agent (starter project)

ProdWatch is a starter codebase for an AI agent that analyzes a repository **and**
its production signals (logs, metrics, traces, error reports) to surface
performance and reliability problems — then turns them into a prioritized,
decision-ready report a team can act on.

The idea: static analysis tells you what *could* go wrong in the code;
observability tells you what *is* going wrong in production. ProdWatch combines
both, correlates them, and ranks what to fix first by impact.

## What it does today

- **Repo intake** — point it at a local path or a git URL; it detects the stack
  (language, frameworks, Dockerfile, CI) automatically.
- **Rule engine** — 20+ static-analysis rules across performance, reliability,
  observability gaps, and operations (missing timeouts, N+1 queries, blocking
  calls in async code, bare `except:`, hardcoded secrets, no retry policy,
  missing health checks / metrics / structured logging, Dockerfile issues…).
- **Signal ingestion** — parses log files, metrics JSON, trace spans, and error
  reports into an "observability snapshot" (error volume, slowest operations,
  top error signatures).
- **Correlation** — links slow endpoints / error spikes back to the code
  patterns that likely cause them, and boosts confidence when both agree.
- **Ranked report** — Markdown + JSON output scored by severity × confidence,
  with evidence, impact, recommendation, and effort estimate per finding.
- **Optional LLM layer** — if `OPENAI_API_KEY` is set, an LLM writes the
  executive summary and sharpens prioritization. Without it, everything still
  works on rules alone (zero dependencies, stdlib only).

## Quickstart

```bash
cd prodwatch

# See it work instantly on the bundled (intentionally flawed) demo app:
PYTHONPATH=src python -m prodwatch demo
# → writes reports/prodwatch-demo-*.md and *.json

# Analyze any repo:
PYTHONPATH=src python -m prodwatch analyze /path/to/repo \
    --signals /path/to/signals --out ./reports

# Analyze directly from git:
PYTHONPATH=src python -m prodwatch analyze https://github.com/org/repo.git

# List all rules:
PYTHONPATH=src python -m prodwatch rules
```

Or install it properly: `pip install -e .` then just run `prodwatch …`.

## Signal formats

Drop any of these into `--signals` (all optional, all JSON except logs):

| File | Format |
|---|---|
| `app.log` | plain text logs (`ERROR`/`WARN` lines counted, signatures extracted) |
| `metrics.json` | `{"endpoints": {"/api/orders": {"p95_ms": 2450, "error_rate": 0.08}}}` |
| `traces.json` | `[{"trace_id": "…", "name": "GET /api/orders", "duration_ms": 123}]` |
| `errors.json` | `[{"title": "ValueError: …", "count": 132}]` (e.g. Sentry export) |

## Project layout

```
src/prodwatch/
  agent.py        orchestration: scan → signals → rules → correlate → rank → report
  repo.py         repo intake (local path / git clone) + stack detection
  signals.py      log / metric / trace / error parsers
  models.py       Finding, Report, StackInfo, SignalsSummary
  llm.py          optional LLM summary layer (OpenAI, stdlib-only HTTP)
  reporters.py    Markdown + JSON report writers
  cli.py          `analyze`, `demo`, `rules` commands
  rules/
    base.py           Rule interface + context
    performance.py    timeouts, N+1, blocking-in-async, print-logging…
    reliability.py    bare except, secrets, retries, graceful shutdown…
    observability.py  structured logging, metrics, health checks, tracing, Dockerfile
    loader.py         custom rules from a JSON file (--custom-rules)
examples/demo-app/    intentionally flawed sample service + sample signals
tests/                unit tests for rules and parsers
```

## Adding your own rules

Subclass `prodwatch.rules.base.Rule` and register it in
`rules/__init__.py`, or drop a JSON file like this and pass
`--custom-rules`:

```json
[
  {
    "id": "CUSTOM001", "title": "No TODOs in hot paths",
    "category": "performance", "severity": "low", "confidence": "medium",
    "file_globs": ["*.py"], "pattern": "TODO",
    "message": "Found a TODO marker",
    "recommendation": "Resolve or ticket it before it rots.",
    "effort": "S"
  }
]
```

## Roadmap (not yet built)

- Live APM integrations (Datadog, New Relic, Prometheus, OpenTelemetry) instead
  of file-based signals
- PR comments / GitHub Action: "this PR introduces 2 new perf risks"
- Auto-generated fix PRs for mechanical issues (add timeout, add HEALTHCHECK)
- Trend tracking: is p95 getting worse week over week?
- Cost attribution: which endpoints burn the most infra spend

## Honest limitations

Static heuristics have false positives by design — every finding carries a
confidence level, and signal corroboration is what separates "likely real" from
"worth a look." The demo signals are synthetic. Treat v0 as a triage assistant,
not ground truth.

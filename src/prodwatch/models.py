"""Core data models: findings, stack info, signal summaries, reports."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}
CONFIDENCE_WEIGHT = {"high": 1.0, "medium": 0.7, "low": 0.4}


@dataclass
class StackInfo:
    languages: list = field(default_factory=list)
    frameworks: list = field(default_factory=list)
    package_manager: str | None = None
    has_dockerfile: bool = False
    has_ci: bool = False
    entry_points: list = field(default_factory=list)


@dataclass
class Finding:
    rule_id: str
    title: str
    category: str          # performance | reliability | observability | operations
    severity: str          # critical | high | medium | low
    confidence: str        # high | medium | low
    evidence: list = field(default_factory=list)
    impact: str = ""
    recommendation: str = ""
    effort: str = "M"      # S | M | L
    file: str | None = None
    line: int | None = None

    @property
    def score(self) -> float:
        return SEVERITY_WEIGHT.get(self.severity, 1) * CONFIDENCE_WEIGHT.get(
            self.confidence, 0.5
        )

    def where(self) -> str:
        if self.file and self.line:
            return f"{self.file}:{self.line}"
        return self.file or "repo-wide"


@dataclass
class SignalsSummary:
    log_errors: int = 0
    log_warns: int = 0
    top_error_signatures: list = field(default_factory=list)   # [(signature, count)]
    slowest_operations: list = field(default_factory=list)     # [(name, p95_ms, count)]
    top_error_issues: list = field(default_factory=list)       # [(title, count)]
    notes: list = field(default_factory=list)


@dataclass
class Report:
    repo: str
    stack: StackInfo
    signals: SignalsSummary
    findings: list
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    llm_summary: str | None = None

    def by_severity(self, severity: str) -> list:
        return [f for f in self.findings if f.severity == severity]

    def ranked(self) -> list:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(
            self.findings, key=lambda f: (order.get(f.severity, 4), -f.score)
        )

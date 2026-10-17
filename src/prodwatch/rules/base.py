"""Rule interface shared by all rule packs."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Finding, SignalsSummary, StackInfo


@dataclass
class RuleContext:
    root: Path
    files: dict = field(default_factory=dict)   # rel posix path -> content
    stack: StackInfo = field(default_factory=StackInfo)
    signals: SignalsSummary = field(default_factory=SignalsSummary)

    def of_ext(self, *exts: str) -> dict:
        return {p: c for p, c in self.files.items()
                if Path(p).suffix in exts}


class Rule(ABC):
    id = "BASE000"
    title = "base rule"
    category = "reliability"          # performance | reliability | observability | operations
    default_severity = "medium"       # critical | high | medium | low
    default_confidence = "medium"     # high | medium | low
    effort = "M"                      # S | M | L
    impact = ""
    recommendation = ""

    def make(self, evidence: list, file: str | None = None,
             line: int | None = None, severity: str | None = None,
             confidence: str | None = None, title: str | None = None,
             impact: str | None = None, recommendation: str | None = None,
             effort: str | None = None) -> Finding:
        return Finding(
            rule_id=self.id,
            title=title or self.title,
            category=self.category,
            severity=severity or self.default_severity,
            confidence=confidence or self.default_confidence,
            evidence=evidence,
            impact=impact or self.impact,
            recommendation=recommendation or self.recommendation,
            effort=effort or self.effort,
            file=file,
            line=line,
        )

    @abstractmethod
    def check(self, ctx: RuleContext) -> list:
        """Return findings for this rule."""

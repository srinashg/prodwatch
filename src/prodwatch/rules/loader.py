"""Custom rules from a JSON file: --custom-rules rules.json

Example entry:
[
  {
    "id": "CUSTOM001",
    "title": "No TODOs in hot paths",
    "category": "performance",
    "severity": "low",
    "confidence": "medium",
    "effort": "S",
    "file_globs": ["*.py"],
    "pattern": "TODO",
    "message": "TODO marker found",
    "impact": "Tech debt rots in hot paths.",
    "recommendation": "Resolve it or file a ticket."
  }
]
"""
from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path

from .base import Rule, RuleContext


class CustomRule(Rule):
    def __init__(self, spec: dict):
        self.id = str(spec.get("id", "CUSTOM000"))
        self.title = str(spec.get("title", "custom rule"))
        self.category = str(spec.get("category", "reliability"))
        self.default_severity = str(spec.get("severity", "medium"))
        self.default_confidence = str(spec.get("confidence", "medium"))
        self.effort = str(spec.get("effort", "M"))
        self.impact = str(spec.get("impact", ""))
        self.recommendation = str(spec.get("recommendation", ""))
        self.message = str(spec.get("message", "pattern matched"))
        self.file_globs = list(spec.get("file_globs", ["*"]))
        try:
            self.pattern = re.compile(str(spec.get("pattern", "")))
        except re.error as e:
            raise ValueError(f"custom rule {self.id}: bad regex: {e}")

    def check(self, ctx: RuleContext) -> list:
        out = []
        for path, content in ctx.files.items():
            if not any(fnmatch.fnmatch(path, g)
                       or fnmatch.fnmatch(Path(path).name, g)
                       for g in self.file_globs):
                continue
            for m in self.pattern.finditer(content):
                line = content.count("\n", 0, m.start()) + 1
                out.append(self.make(
                    [f"{self.message}: `{m.group(0)[:80]}`"],
                    file=path, line=line))
                if len(out) >= 25:
                    return out
        return out


def load_custom_rules(path: str) -> list:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("custom rules file must contain a JSON list")
    return [CustomRule(spec) for spec in data]

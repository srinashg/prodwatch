"""Reliability rules: error swallowing, secrets, retries, shutdown."""
from __future__ import annotations

import re
from pathlib import Path

from .base import Rule, RuleContext


class BareExceptRule(Rule):
    id = "REL001"
    title = "Bare except swallows errors"
    category = "reliability"
    default_severity = "high"
    default_confidence = "high"
    effort = "S"
    impact = ("Swallowed exceptions hide production failures — incidents become "
              "silent data corruption or mysterious empty responses instead of "
              "alerts you can act on.")
    recommendation = ("Catch specific exceptions, log with context (logger.exception), "
                      "and re-raise what you can't handle.")

    _EXCEPT_RE = re.compile(r"^(\s*)except\s*(Exception)?\s*:\s*(#.*)?$")

    def check(self, ctx: RuleContext) -> list:
        out = []
        for path, content in ctx.of_ext(".py").items():
            lines = content.splitlines()
            for i, line in enumerate(lines):
                m = self._EXCEPT_RE.match(line)
                if not m:
                    continue
                indent = len(m.group(1))
                body = []
                for nxt in lines[i + 1:]:
                    if not nxt.strip() or nxt.strip().startswith("#"):
                        continue
                    ind = len(nxt) - len(nxt.lstrip())
                    if ind <= indent:
                        break
                    body.append(nxt.strip())
                trivial = (
                    not body
                    or all(re.match(r"^(pass|continue|break)$", s)
                           or s.startswith(("print(", "log.", "logger.", "logging."))
                           for s in body)
                )
                if trivial:
                    out.append(self.make(
                        [f"bare `except:` at {path}:{i + 1} "
                         f"{'does nothing' if not body or body == ['pass'] else 'only logs/prints'}"],
                        file=path, line=i + 1))
        return out


class HardcodedSecretRule(Rule):
    id = "REL002"
    title = "Hardcoded secret in source"
    category = "reliability"
    default_severity = "critical"
    default_confidence = "high"
    effort = "S"
    impact = ("Secrets in git history are compromised the moment the repo is "
              "shared, leaked, or made public — and rotation is painful.")
    recommendation = ("Move secrets to environment variables or a secret manager "
                      "(Vault, AWS Secrets Manager, Doppler); rotate any exposed ones now.")

    _ASSIGN_RE = re.compile(
        r"(?i)\b(api[_-]?key|secret[_-]?key|client[_-]?secret|password|passwd|"
        r"auth[_-]?token|access[_-]?token|private[_-]?key)\b\s*[:=]\s*"
        r"['\"]([^'\"]{4,})['\"]")
    _TOKEN_RE = re.compile(r"\b(sk-[A-Za-z0-9]{8,}|AKIA[0-9A-Z]{16}|xox[bap]-[A-Za-z0-9-]+)\b")
    _PLACEHOLDERS = {"test", "testing", "changeme", "xxx", "example", "dummy",
                     "placeholder", "your-key-here", "password", "secret"}

    def check(self, ctx: RuleContext) -> list:
        out = []
        for path, content in ctx.files.items():
            if Path(path).suffix not in (".py", ".js", ".jsx", ".ts", ".tsx",
                                         ".go", ".java", ".rb", ".env"):
                continue
            for m in self._ASSIGN_RE.finditer(content):
                val = m.group(2)
                if val.lower() in self._PLACEHOLDERS or "example" in val.lower():
                    continue
                line = content.count("\n", 0, m.start()) + 1
                out.append(self.make(
                    [f"possible hardcoded {m.group(1)} at {path}:{line}"],
                    file=path, line=line))
            for m in self._TOKEN_RE.finditer(content):
                line = content.count("\n", 0, m.start()) + 1
                out.append(self.make(
                    [f"token-shaped secret at {path}:{line}"],
                    file=path, line=line))
        return out


class NoRetryPolicyRule(Rule):
    id = "REL003"
    title = "Network calls without a retry policy"
    category = "reliability"
    default_severity = "medium"
    default_confidence = "medium"
    effort = "M"
    impact = ("Transient failures (DNS blips, 429s, brief upstream restarts) become "
              "user-facing errors instead of invisible retries.")
    recommendation = ("Add retries with exponential backoff + jitter for idempotent "
                      "calls (tenacity/backoff in Python, axios-retry/p-retry in Node).")

    _NET_RE = re.compile(r"\brequests\.\w+\s*\(|\burllib\.request\.urlopen|"
                         r"\bhttp\.client\.|\bfetch\s*\(|\baxios\.\w+\s*\(")
    _RETRY_RE = re.compile(r"tenacity|backoff|urllib3\.util\.retry|Retry\(|"
                           r"axios-retry|p-retry|resilience", re.IGNORECASE)

    def check(self, ctx: RuleContext) -> list:
        out = []
        for path, content in ctx.files.items():
            if Path(path).suffix not in (".py", ".js", ".jsx", ".ts", ".tsx"):
                continue
            if self._NET_RE.search(content) and not self._RETRY_RE.search(content):
                out.append(self.make(
                    ["network calls present but no retry library/policy detected"],
                    file=path))
        return out


class NoGracefulShutdownRule(Rule):
    id = "REL004"
    title = "Server starts without graceful shutdown handling"
    category = "reliability"
    default_severity = "medium"
    default_confidence = "medium"
    effort = "S"
    impact = ("Deploys and autoscaling kill the process mid-request — in-flight "
              "requests fail and connections drop instead of draining.")
    recommendation = ("Handle SIGTERM/SIGINT: stop accepting, drain in-flight "
                      "requests, then exit (most frameworks support this natively).")

    _SERVE_RE = re.compile(r"\bapp\.run\s*\(|\buvicorn\.run\s*\(|"
                           r"\bserve_forever\s*\(|\.listen\s*\(")

    def check(self, ctx: RuleContext) -> list:
        out = []
        for path, content in ctx.of_ext(".py", ".js", ".ts").items():
            if self._SERVE_RE.search(content) and "signal" not in content:
                out.append(self.make(
                    ["server entrypoint found with no signal handling"],
                    file=path))
        return out


RELIABILITY_RULES: list = [
    BareExceptRule(), HardcodedSecretRule(), NoRetryPolicyRule(),
    NoGracefulShutdownRule(),
]

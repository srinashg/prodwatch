"""Observability-gap + operations rules: the 'can we even see prod?' checks."""
from __future__ import annotations

import re

from .base import Rule, RuleContext


def _blob(ctx: RuleContext, *exts: str) -> str:
    files = ctx.of_ext(*exts) if exts else ctx.files
    return "\n".join(files.values())


class NoStructuredLoggingRule(Rule):
    id = "OBS001"
    title = "No structured logging configured"
    category = "observability"
    default_severity = "medium"
    default_confidence = "medium"
    effort = "S"
    impact = ("Without structured (JSON) logs you can't filter, aggregate, or "
              "alert on production behavior — debugging becomes grep archaeology.")
    recommendation = ("Adopt structlog / loguru / python-json-logger with a JSON "
                      "formatter in production; keep human-readable format for dev.")

    _MARKERS = ("structlog", "loguru", "python-json-logger", "jsonlogger",
                "ecs_logging")

    def check(self, ctx: RuleContext) -> list:
        if not ctx.of_ext(".py"):
            return []
        blob = _blob(ctx, ".py").lower()
        if not any(m in blob for m in self._MARKERS):
            return [self.make(["no structured-logging library detected in Python code"])]
        return []


class NoMetricsRule(Rule):
    id = "OBS002"
    title = "No metrics instrumentation found"
    category = "observability"
    default_severity = "medium"
    default_confidence = "medium"
    effort = "M"
    impact = ("No request counts, latencies, or error rates means regressions are "
              "discovered by users, not dashboards.")
    recommendation = ("Expose a /metrics endpoint (prometheus_client, "
                      "prom-client, Micrometer) and track RED metrics per endpoint.")

    _MARKERS = ("prometheus_client", "prometheus", "statsd", "datadog",
                "opentelemetry", "micrometer", "prom-client")

    def check(self, ctx: RuleContext) -> list:
        blob = _blob(ctx).lower()
        if not any(m in blob for m in self._MARKERS):
            return [self.make(["no metrics library detected anywhere in the repo"])]
        return []


class NoHealthEndpointRule(Rule):
    id = "OBS003"
    title = "No health check endpoint"
    category = "observability"
    default_severity = "high"
    default_confidence = "medium"
    effort = "S"
    impact = ("Orchestrators (K8s, ECS, Docker) can't tell healthy from broken — "
              "bad deploys keep serving traffic and restarts are blind.")
    recommendation = ("Add GET /healthz (liveness) and /readyz (readiness, checks "
                      "DB/upstream) endpoints; wire them into your deployment.")

    _MARKERS = ("/health", "/healthz", "/ready", "/readyz", "/live", "healthcheck")

    def check(self, ctx: RuleContext) -> list:
        blob = _blob(ctx).lower()
        if not any(m in blob for m in self._MARKERS):
            return [self.make(["no health-check endpoint string found in code"])]
        return []


class NoTracingRule(Rule):
    id = "OBS004"
    title = "No distributed tracing"
    category = "observability"
    default_severity = "low"
    default_confidence = "medium"
    effort = "M"
    impact = ("When a request fans out across services/DB/upstream calls, you "
              "can't see which hop is slow without traces.")
    recommendation = ("Instrument with OpenTelemetry and propagate trace context "
                      "across service boundaries.")

    _MARKERS = ("opentelemetry", "jaeger", "zipkin", "ddtrace", "aws_xray",
                "aws-xray")

    def check(self, ctx: RuleContext) -> list:
        blob = _blob(ctx).lower()
        if not any(m in blob for m in self._MARKERS):
            return [self.make(["no tracing library detected"])]
        return []


class DockerfileIssuesRule(Rule):
    id = "OPS001"
    title = "Dockerfile hygiene issues"
    category = "operations"
    default_severity = "medium"
    default_confidence = "high"
    effort = "S"
    impact = ("Containers without healthchecks get no auto-recovery; running as "
              "root widens the blast radius of any container escape.")
    recommendation = ("Add HEALTHCHECK, a non-root USER, and pin base image tags.")

    def check(self, ctx: RuleContext) -> list:
        out = []
        p = ctx.root / "Dockerfile"
        if not p.is_file():
            return []
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        if "HEALTHCHECK" not in content:
            out.append(self.make(
                ["Dockerfile has no HEALTHCHECK instruction"],
                file="Dockerfile",
                title="Dockerfile missing HEALTHCHECK",
                severity="medium"))
        if not re.search(r"(?m)^USER\s+\S+", content):
            out.append(self.make(
                ["Dockerfile sets no USER — container runs as root"],
                file="Dockerfile",
                title="Dockerfile runs as root",
                severity="medium"))
        if re.search(r"(?m)^FROM\s+\S+:latest", content):
            out.append(self.make(
                ["Dockerfile pins a :latest base image tag"],
                file="Dockerfile",
                title="Dockerfile uses :latest base image",
                severity="low"))
        return out


class LockfileRule(Rule):
    id = "OPS002"
    title = "Dependencies not locked/pinned"
    category = "operations"
    default_severity = "medium"
    default_confidence = "high"
    effort = "S"
    impact = ("Unpinned dependencies make builds non-reproducible — 'works on my "
              "machine' incidents and surprise breakages on redeploy.")
    recommendation = ("Commit package-lock.json / yarn.lock / pnpm-lock.yaml, or "
                      "pin requirements with ==" + " and hash-check in CI.")

    def check(self, ctx: RuleContext) -> list:
        out = []
        root = ctx.root
        if (root / "package.json").is_file() and not any(
                (root / n).is_file() for n in
                ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")):
            out.append(self.make(
                ["package.json present but no lockfile committed"],
                file="package.json"))
        req = root / "requirements.txt"
        if req.is_file():
            try:
                lines = req.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                lines = []
            unpinned = [l.strip() for l in lines
                        if l.strip() and not l.strip().startswith(("#", "-", " "))
                        and "==" not in l]
            if unpinned:
                out.append(self.make(
                    [f"{len(unpinned)} unpinned dependencies in requirements.txt "
                     f"(e.g. `{unpinned[0][:40]}`)"],
                    file="requirements.txt",
                    title="requirements.txt has unpinned dependencies",
                    severity="low"))
        return out


OBSERVABILITY_RULES: list = [
    NoStructuredLoggingRule(), NoMetricsRule(), NoHealthEndpointRule(),
    NoTracingRule(), DockerfileIssuesRule(), LockfileRule(),
]

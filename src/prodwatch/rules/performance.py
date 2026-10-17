"""Performance rules: timeouts, N+1 queries, blocking I/O, pooling, logging."""
from __future__ import annotations

import re

from .base import Rule, RuleContext

_REQUEST_METHODS = r"get|post|put|delete|patch|head|options"


def _call_args(text: str, open_idx: int) -> str | None:
    """Return the argument text of the call starting at text[open_idx] == '('.

    Handles nested parens and string literals. Returns None if unbalanced.
    """
    depth = 0
    in_str = None
    i = open_idx
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
        elif ch in "'\"":
            in_str = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i]
        i += 1
    return None


class NoTimeoutRule(Rule):
    id = "PY001"
    title = "HTTP request without a timeout"
    category = "performance"
    default_severity = "high"
    default_confidence = "high"
    effort = "S"
    impact = ("A slow or hung upstream can block a worker/thread indefinitely, "
              "cascading into latency spikes and thread-pool exhaustion under load.")
    recommendation = ("Pass timeout= to every requests call, e.g. timeout=(3, 10) "
                      "for connect/read. Prefer client-level timeouts for httpx/aiohttp.")

    def check(self, ctx: RuleContext) -> list:
        out = []
        for path, content in ctx.of_ext(".py").items():
            for m in re.finditer(rf"\brequests\.({_REQUEST_METHODS})\s*\(", content):
                args = _call_args(content, m.end() - 1)
                if args is None:
                    continue
                if not re.search(r"\btimeout\s*=", args):
                    line = content.count("\n", 0, m.start()) + 1
                    out.append(self.make(
                        [f"`requests.{m.group(1)}(...)` has no timeout argument"],
                        file=path, line=line))
        return out


class QueryInLoopRule(Rule):
    id = "PY002"
    title = "Possible N+1 query: database call inside a loop"
    category = "performance"
    default_severity = "high"
    default_confidence = "medium"
    effort = "M"
    impact = ("One query per iteration turns a single page/API call into hundreds "
              "of round trips — the classic cause of 'slow endpoint' incidents.")
    recommendation = ("Batch with a single query (WHERE id IN …), use selectinload/"
                      "prefetch, or add a dataloader layer.")

    _LOOP_RE = re.compile(r"^(\s*)(for|while)\b.*:\s*(#.*)?$")
    _QUERY_RE = re.compile(
        r"\b(execute|executemany)\s*\(|\.(query|filter|filter_by|get|all|first|one|"
        r"one_or_none|scalar)\s*\(|\bSELECT\b", re.IGNORECASE)

    def check(self, ctx: RuleContext) -> list:
        out = []
        for path, content in ctx.of_ext(".py").items():
            lines = content.splitlines()
            for i, line in enumerate(lines):
                m = self._LOOP_RE.match(line)
                if not m:
                    continue
                indent = len(m.group(1))
                for j in range(i + 1, min(i + 60, len(lines))):
                    nxt = lines[j]
                    if not nxt.strip() or nxt.strip().startswith("#"):
                        continue
                    ind = len(nxt) - len(nxt.lstrip())
                    if ind <= indent:
                        break
                    if ind > indent and self._QUERY_RE.search(nxt):
                        out.append(self.make(
                            [f"loop at {path}:{i + 1} contains a query-like call "
                             f"at line {j + 1}: `{nxt.strip()[:90]}`"],
                            file=path, line=j + 1))
                        break
        return out


class BlockingInAsyncRule(Rule):
    id = "PY003"
    title = "Blocking call inside async code"
    category = "performance"
    default_severity = "high"
    default_confidence = "high"
    effort = "S"
    impact = ("Blocking the event loop stalls every concurrent request on that "
              "loop — one time.sleep() can serialize your whole service.")
    recommendation = ("Use asyncio.sleep, async HTTP clients (httpx/aiohttp), and "
                      "run blocking I/O in a threadpool via asyncio.to_thread().")

    _FUNC_RE = re.compile(r"^(\s*)(async\s+def|def)\s+\w+")
    _BLOCKING_RE = re.compile(
        r"\btime\.sleep\s*\(|\brequests\.(get|post|put|delete|patch)\s*\(|"
        r"\burllib\.request\.urlopen\s*\(")

    def check(self, ctx: RuleContext) -> list:
        out = []
        for path, content in ctx.of_ext(".py").items():
            stack: list = []  # (indent, is_async)
            for i, line in enumerate(content.splitlines()):
                m = self._FUNC_RE.match(line)
                if m:
                    indent = len(m.group(1))
                    while stack and stack[-1][0] >= indent:
                        stack.pop()
                    stack.append((indent, m.group(2).startswith("async")))
                    continue
                if not line.strip():
                    continue
                indent = len(line) - len(line.lstrip())
                while stack and stack[-1][0] >= indent:
                    stack.pop()
                if stack and stack[-1][1]:
                    b = self._BLOCKING_RE.search(line)
                    if b:
                        out.append(self.make(
                            [f"blocking call `{b.group(0)}` inside async function "
                             f"at {path}:{i + 1}"],
                            file=path, line=i + 1))
        return out


class NoConnectionPoolingRule(Rule):
    id = "PY004"
    title = "No HTTP connection pooling (repeated requests.* calls)"
    category = "performance"
    default_severity = "medium"
    default_confidence = "medium"
    effort = "S"
    impact = ("Every requests.get() opens a fresh TCP+TLS handshake. Under load "
              "this adds hundreds of ms per call and exhausts ephemeral ports.")
    recommendation = ("Use a shared requests.Session (or httpx.Client) with "
                      "connection pooling, ideally one per service/module.")

    def check(self, ctx: RuleContext) -> list:
        files = ctx.of_ext(".py")
        per_file = {p: len(re.findall(rf"\brequests\.({_REQUEST_METHODS})\s*\(", c))
                    for p, c in files.items()}
        total = sum(per_file.values())
        hit_files = sum(1 for n in per_file.values() if n)
        pooled = any("Session(" in c or "httpx.Client(" in c
                     for c in files.values())
        if total >= 3 and not pooled:
            return [self.make(
                [f"{total} direct requests.* calls across {hit_files} file(s), "
                 "no Session/Client pooling found"])]
        return []


class PrintLoggingRule(Rule):
    id = "GEN001"
    title = "print() used instead of logging"
    category = "observability"
    default_severity = "low"
    default_confidence = "high"
    effort = "S"
    impact = ("print() output is unstructured, has no level/timestamp, and can't "
              "be shipped or filtered by log pipelines — blind spots in prod.")
    recommendation = ("Use the logging module (or structlog) with levels; "
                      "configure a JSON formatter for production.")

    def check(self, ctx: RuleContext) -> list:
        out = []
        for path, content in ctx.of_ext(".py").items():
            if "test" in path.lower():
                continue
            for m in re.finditer(r"(?m)^(?!\s*#).*\bprint\s*\(", content):
                line = content.count("\n", 0, m.start()) + 1
                out.append(self.make(["print() call found instead of logging"],
                                     file=path, line=line))
                break  # one per file is enough signal
        return out


class FetchNoTimeoutRule(Rule):
    id = "JS001"
    title = "fetch() without timeout/cancellation"
    category = "performance"
    default_severity = "medium"
    default_confidence = "medium"
    effort = "S"
    impact = ("fetch() never times out on its own — a hung upstream hangs the "
              "request handler with it.")
    recommendation = ("Use AbortController with a timeout, or a wrapper like "
                      "ky/got with retry+timeout defaults.")

    def check(self, ctx: RuleContext) -> list:
        out = []
        for path, content in ctx.of_ext(".js", ".jsx", ".ts", ".tsx").items():
            if "fetch(" in content and "AbortController" not in content \
                    and "AbortSignal" not in content:
                out.append(self.make(
                    ["fetch() used with no AbortController/AbortSignal in file"],
                    file=path))
        return out


PERFORMANCE_RULES: list = [
    NoTimeoutRule(), QueryInLoopRule(), BlockingInAsyncRule(),
    NoConnectionPoolingRule(), PrintLoggingRule(), FetchNoTimeoutRule(),
]

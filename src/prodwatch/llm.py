"""Optional LLM layer: executive summary + sharper prioritization.

Requires OPENAI_API_KEY (and optionally PRODWATCH_LLM_MODEL, default
gpt-4o-mini). Pure stdlib HTTP — no extra dependencies. If no key is set, or
the call fails for any reason, returns None and the rule-based report stands
on its own.
"""
from __future__ import annotations

import json
import os
import urllib.request


def refine_summary(findings, signals, stack) -> str | None:
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        return None
    model = os.environ.get("PRODWATCH_LLM_MODEL", "gpt-4o-mini")
    try:
        top = sorted(findings, key=lambda f: f.score, reverse=True)[:12]
        bullets = "\n".join(
            f"- [{f.severity}/{f.confidence}] {f.title} ({f.where()}): "
            f"{(f.impact or '')[:160]}"
            for f in top
        )
        slow = ", ".join(
            f"{n} p95={p:.0f}ms" for n, p, _ in signals.slowest_operations[:3]
        ) or "none"
        prompt = (
            "You are a staff SRE reviewing an automated production-issue report. "
            "Write a concise executive summary (max 200 words) for an engineering "
            "lead: what is most likely hurting production right now, what to fix "
            "first and why, and one observability gap to close. Be concrete and "
            "skip hedging.\n\n"
            f"Stack: {', '.join(stack.languages) or 'unknown'}; "
            f"frameworks: {', '.join(stack.frameworks) or 'unknown'}\n"
            f"Log errors: {signals.log_errors}; slowest ops: {slow}\n"
            f"Top findings:\n{bullets}"
        )
        body = json.dumps({
            "model": model,
            "temperature": 0.2,
            "max_tokens": 500,
            "messages": [
                {"role": "system",
                 "content": "You are a terse, expert SRE. No fluff."},
                {"role": "user", "content": prompt},
            ],
        }).encode()
        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=body,
            headers={"Authorization": f"Bearer {key}",
                     "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
        return data["choices"][0]["message"]["content"].strip()
    except Exception:
        return None

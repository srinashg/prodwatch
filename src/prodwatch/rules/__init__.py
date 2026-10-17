"""Rule registry: every built-in rule the agent runs."""
from .base import Rule, RuleContext
from .performance import PERFORMANCE_RULES
from .reliability import RELIABILITY_RULES
from .observability import OBSERVABILITY_RULES


def all_rules() -> list:
    rules: list = []
    for pack in (PERFORMANCE_RULES, RELIABILITY_RULES, OBSERVABILITY_RULES):
        rules.extend(pack)
    return rules


__all__ = ["Rule", "RuleContext", "all_rules"]

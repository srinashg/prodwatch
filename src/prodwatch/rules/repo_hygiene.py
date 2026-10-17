"""Repo-hygiene rules: secrets and sensitive files tracked in the repo.

Draft rule pack (not registered in __init__.py yet). Register with one line:
    from .repo_hygiene import REPO_HYGIENE_RULES
and extend all_rules() in rules/__init__.py once approved.
"""
from __future__ import annotations

from .base import Rule, RuleContext


class CommittedEnvFileRule(Rule):
    id = "HYG001"
    title = "Sensitive file committed to the repository"
    category = "operations"
    default_severity = "critical"
    default_confidence = "high"
    effort = "S"
    impact = ("Credentials committed to git are compromised the moment the repo "
              "is cloned, forked, or made public — and they persist in history "
              "even after the file is deleted.")
    recommendation = ("Remove the file from tracking (`git rm --cached`) and from "
                      "history (BFG or `git filter-repo`), rotate the exposed "
                      "credentials now, and add the filename pattern to .gitignore.")

    _SUSPICIOUS = (".env", ".env.local", ".env.production", ".env.staging",
                   ".env.development", "*.pem", "id_rsa", "id_ed25519",
                   ".npmrc", ".pypirc", "secrets.yaml", "secrets.yml")

    def check(self, ctx: RuleContext) -> list:
        import fnmatch

        out = []
        for name in self._SUSPICIOUS:
            for p in ctx.root.glob(name):
                if p.is_file():
                    out.append(self.make(
                        [f"`{p.name}` exists in the repository checkout — "
                         f"may contain live credentials"],
                        file=p.name))
        return out


REPO_HYGIENE_RULES = [CommittedEnvFileRule()]

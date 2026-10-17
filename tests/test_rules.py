"""Unit tests for rules and signal parsers. Run: python -m unittest discover -s tests"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from prodwatch.models import StackInfo
from prodwatch.rules.base import RuleContext
from prodwatch.rules.performance import (
    BlockingInAsyncRule, NoTimeoutRule, QueryInLoopRule,
)
from prodwatch.rules.reliability import BareExceptRule, HardcodedSecretRule
from prodwatch.signals import parse_logs


def ctx_for(files: dict) -> RuleContext:
    return RuleContext(root=Path("."), files=files, stack=StackInfo())


class TestPerformanceRules(unittest.TestCase):
    def test_no_timeout_flags_missing(self):
        f = NoTimeoutRule().check(ctx_for(
            {"a.py": "import requests\nrequests.get(url)\n"}))
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].rule_id, "PY001")

    def test_no_timeout_passes_with_timeout(self):
        f = NoTimeoutRule().check(ctx_for(
            {"a.py": "import requests\nrequests.get(url, timeout=5)\n"}))
        self.assertEqual(f, [])

    def test_query_in_loop(self):
        code = ("for oid in ids:\n"
                "    rows.append(db.execute('SELECT * FROM t'))\n")
        f = QueryInLoopRule().check(ctx_for({"a.py": code}))
        self.assertEqual(len(f), 1)

    def test_blocking_in_async(self):
        code = "import time\nasync def f():\n    time.sleep(1)\n"
        f = BlockingInAsyncRule().check(ctx_for({"a.py": code}))
        self.assertEqual(len(f), 1)

    def test_blocking_in_sync_ok(self):
        code = "import time\ndef f():\n    time.sleep(1)\n"
        f = BlockingInAsyncRule().check(ctx_for({"a.py": code}))
        self.assertEqual(f, [])


class TestReliabilityRules(unittest.TestCase):
    def test_bare_except_pass(self):
        code = "try:\n    x()\nexcept:\n    pass\n"
        f = BareExceptRule().check(ctx_for({"a.py": code}))
        self.assertEqual(len(f), 1)

    def test_specific_except_ok(self):
        code = "try:\n    x()\nexcept ValueError:\n    pass\n"
        f = BareExceptRule().check(ctx_for({"a.py": code}))
        self.assertEqual(f, [])

    def test_hardcoded_secret(self):
        f = HardcodedSecretRule().check(
            ctx_for({"a.py": 'API_KEY = "sk-live-abc123xyz"\n'}))
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "critical")

    def test_placeholder_not_flagged(self):
        f = HardcodedSecretRule().check(
            ctx_for({"a.py": 'API_KEY = "test"\n'}))
        self.assertEqual(f, [])


class TestSignals(unittest.TestCase):
    def test_parse_logs(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log",
                                         delete=False) as t:
            t.write("2026-01-01 INFO ok\n"
                    "2026-01-01 ERROR ValueError: boom\n"
                    "2026-01-01 ERROR ValueError: boom\n"
                    "2026-01-01 WARN slow\n")
            name = t.name
        r = parse_logs(Path(name))
        self.assertEqual(r["error_count"], 2)
        self.assertEqual(r["warn_count"], 1)
        self.assertEqual(r["top"][0][1], 2)


if __name__ == "__main__":
    unittest.main()

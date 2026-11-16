#!/usr/bin/env python3
"""Unit tests for web-audit — header evaluation, cookies and scoring.

Standard library only; run with: python -m unittest discover -s tests/unit
"""

import importlib.util
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "web-audit" / "web_audit.py"
spec = importlib.util.spec_from_file_location("web_audit", TOOL_PATH)
web_audit = importlib.util.module_from_spec(spec)
sys.modules["web_audit"] = web_audit
spec.loader.exec_module(web_audit)


class NormalizeTargetTests(unittest.TestCase):
    def test_bare_host_defaults_to_https(self):
        target = web_audit.normalize_target("example.com")
        self.assertEqual(target["scheme"], "https")
        self.assertEqual(target["port"], 443)
        self.assertEqual(target["display"], "https://example.com")

    def test_host_with_port_and_scheme(self):
        target = web_audit.normalize_target("http://127.0.0.1:8080/")
        self.assertEqual(target["scheme"], "http")
        self.assertEqual(target["host"], "127.0.0.1")
        self.assertEqual(target["port"], 8080)
        self.assertEqual(target["path"], "/")
        self.assertEqual(target["display"], "http://127.0.0.1:8080")

    def test_default_port_is_hidden_in_display(self):
        self.assertEqual(web_audit.normalize_target("https://example.com:443/")["display"],
                         "https://example.com")

    def test_invalid_targets_raise(self):
        for bad in ("ftp://host", "https://", "just-a-scheme://"):
            with self.assertRaises(ValueError):
                web_audit.normalize_target(bad)


class EvaluateHeadersTests(unittest.TestCase):
    def test_all_present_yields_only_ok(self):
        headers = {name: "value" for name, _ in web_audit.REQUIRED_HEADERS}
        findings = web_audit.evaluate_headers(headers)
        self.assertTrue(all(f["status"] == "ok" for f in findings))
        self.assertEqual(len(findings), len(web_audit.REQUIRED_HEADERS))

    def test_missing_header_carries_advice(self):
        findings = web_audit.evaluate_headers({})
        missing = [f for f in findings if f["status"] == "missing"]
        self.assertEqual(len(missing), len(web_audit.REQUIRED_HEADERS))
        self.assertTrue(all(f["detail"] for f in missing))

    def test_server_version_disclosure_is_flagged(self):
        findings = web_audit.evaluate_headers({"server": "nginx/1.18.0"})
        warned = [f for f in findings if f["status"] == "warn"]
        self.assertTrue(any("version" in f["detail"] for f in warned))

    def test_plain_server_name_is_not_flagged(self):
        findings = web_audit.evaluate_headers({"server": "SimpleServer"})
        self.assertFalse(any(f["check"] == "server disclosure" for f in findings))


class CookieFindingsTests(unittest.TestCase):
    def test_unprotected_cookie_is_reported(self):
        issues = web_audit.cookie_findings({"set-cookie": "sid=abc123; Path=/"})
        self.assertEqual(len(issues), 1)
        self.assertIn("sid", issues[0])
        self.assertIn("Secure", issues[0])

    def test_fully_protected_cookie_passes(self):
        issues = web_audit.cookie_findings(
            {"set-cookie": "sid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"})
        self.assertEqual(issues, [])

    def test_garbage_cookie_header_is_ignored(self):
        self.assertEqual(web_audit.cookie_findings({"set-cookie": ",,,not a cookie"}), [])


class ScoreTests(unittest.TestCase):
    TLS_OK = {"state": "ok", "days_left": 120}

    def test_perfect_target(self):
        total, grade = web_audit.score([], self.TLS_OK, "https", {"status": "ok"}, [])
        self.assertEqual((total, grade), (100, "A"))

    def test_all_headers_missing(self):
        findings = [{"status": "missing"} for _ in web_audit.REQUIRED_HEADERS]
        total, grade = web_audit.score(findings, self.TLS_OK, "https", {"status": "ok"}, [])
        self.assertEqual(total, 100 - 12 * 6)
        self.assertEqual(grade, "F")

    def test_plain_http_penalized(self):
        total, grade = web_audit.score([], {"state": "none", "days_left": None}, "http", None, [])
        self.assertEqual(total, 80)
        self.assertEqual(grade, "B")

    def test_expired_certificate_penalized(self):
        total, _ = web_audit.score([], {"state": "ok", "days_left": -3}, "https",
                                   {"status": "ok"}, [])
        self.assertEqual(total, 75)

    def test_certificate_expiring_soon_penalized(self):
        total, _ = web_audit.score([], {"state": "ok", "days_left": 10}, "https",
                                   {"status": "ok"}, [])
        self.assertEqual(total, 92)

    def test_cookie_issues_are_capped(self):
        total, _ = web_audit.score([], self.TLS_OK, "https", {"status": "ok"},
                                   ["a", "b", "c", "d"])
        self.assertEqual(total, 100 - web_audit.COOKIE_PENALTY_CAP)

    def test_score_never_below_zero(self):
        findings = [{"status": "missing"} for _ in web_audit.REQUIRED_HEADERS]
        total, _ = web_audit.score(findings, {"state": "none", "days_left": None}, "http",
                                   {"status": "warn"}, ["c1", "c2", "c3"])
        self.assertEqual(total, 0)


class BuildReportTests(unittest.TestCase):
    def test_report_shape(self):
        target = {"display": "https://example.com"}
        report = web_audit.build_report(target, {"state": "ok", "days_left": 42}, [], [],
                                        None, 88, "B")
        self.assertEqual(report["tool"], "web-audit")
        self.assertEqual(report["target"], "https://example.com")
        self.assertEqual(report["score"], 88)
        self.assertEqual(report["grade"], "B")
        self.assertIn("generated_at", report)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Unit tests for takeover-check — pure verdict logic, no network calls.

Standard library only; run with: python -m unittest discover -s tests/unit
"""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "takeover-check" / "takeover_check.py"
spec = importlib.util.spec_from_file_location("takeover_check", TOOL_PATH)
takeover_check = importlib.util.module_from_spec(spec)
sys.modules["takeover_check"] = takeover_check
spec.loader.exec_module(takeover_check)


class MatchFingerprintTests(unittest.TestCase):
    def test_cname_suffixes_match(self):
        self.assertEqual(takeover_check.match_fingerprint("x.github.io")["service"],
                         "GitHub Pages")
        self.assertEqual(takeover_check.match_fingerprint("app.herokuapp.com")["service"],
                         "Heroku")
        self.assertEqual(takeover_check.match_fingerprint("bucket.s3-website-us-east-1.amazonaws.com")["service"],
                         "AWS S3")

    def test_trailing_dot_and_case_do_not_break_matching(self):
        self.assertEqual(takeover_check.match_fingerprint("X.GITHUB.IO.")["service"],
                         "GitHub Pages")

    def test_no_match_returns_none(self):
        self.assertIsNone(takeover_check.match_fingerprint("example.com"))
        self.assertIsNone(takeover_check.match_fingerprint(None))
        self.assertIsNone(takeover_check.match_fingerprint(""))


class BodyMatchesTests(unittest.TestCase):
    def test_signature_hit_is_case_insensitive(self):
        fingerprint = takeover_check.FINGERPRINTS[0]
        self.assertTrue(takeover_check.body_matches(
            "Oops! There Isn't a GitHub Pages site here.", fingerprint))

    def test_whitespace_is_normalized(self):
        fingerprint = next(f for f in takeover_check.FINGERPRINTS if f["service"] == "Azure Web Apps")
        self.assertTrue(takeover_check.body_matches("404  Web   Site  Not Found.", fingerprint))

    def test_real_content_does_not_match(self):
        fingerprint = takeover_check.FINGERPRINTS[0]
        self.assertFalse(takeover_check.body_matches("<html>my blog</html>", fingerprint))

    def test_every_fingerprint_has_cname_and_body_data(self):
        for fingerprint in takeover_check.FINGERPRINTS:
            self.assertTrue(fingerprint["cname"], fingerprint["service"])
            self.assertTrue(fingerprint["body"], fingerprint["service"])
            self.assertTrue(fingerprint["note"], fingerprint["service"])


class ClassifyTests(unittest.TestCase):
    GH = next(f for f in takeover_check.FINGERPRINTS if f["service"] == "GitHub Pages")

    def test_cname_plus_signature_is_vulnerable(self):
        result = takeover_check.classify("blog.example.com", "x.github.io", self.GH,
                                         reachable=True,
                                         body="There isn't a GitHub Pages site here.")
        self.assertEqual(result["verdict"], "vulnerable")
        self.assertEqual(result["service"], "GitHub Pages")
        self.assertIn("there isn't", result["evidence"].lower())

    def test_cname_with_real_content_is_claimed(self):
        result = takeover_check.classify("blog.example.com", "x.github.io", self.GH,
                                         reachable=True, body="<html>my blog</html>")
        self.assertEqual(result["verdict"], "claimed")

    def test_cname_without_http_is_unreachable(self):
        result = takeover_check.classify("old.example.com", "x.github.io", self.GH,
                                         reachable=False, body="")
        self.assertEqual(result["verdict"], "unreachable")

    def test_signature_without_cname_is_still_flagged(self):
        result = takeover_check.classify("web.example.com", None, None,
                                         reachable=True, body="NoSuchBucket")
        self.assertEqual(result["verdict"], "vulnerable")
        self.assertEqual(result["service"], "AWS S3")

    def test_plain_host_is_ok(self):
        result = takeover_check.classify("www.example.com", None, None,
                                         reachable=True, body="<html>ok</html>")
        self.assertEqual(result["verdict"], "ok")

    def test_resolving_host_without_http_is_no_http(self):
        result = takeover_check.classify("www.example.com", None, None,
                                         reachable=False, body="")
        self.assertEqual(result["verdict"], "no-http")


class VerdictCoverageTests(unittest.TestCase):
    def test_every_verdict_has_a_mark(self):
        self.assertEqual(set(takeover_check.VERDICT_MARKS), set(takeover_check.VERDICT_ORDER))

    def test_vulnerable_mark_is_explicit(self):
        self.assertIn("VULNERABLE", takeover_check.VERDICT_MARKS["vulnerable"])


class RenderLineTests(unittest.TestCase):
    def test_line_contains_verdict_host_and_cname(self):
        line = takeover_check.render_line({
            "host": "blog.example.com", "cname": "x.github.io",
            "service": "GitHub Pages", "verdict": "vulnerable", "evidence": 'matched: "sig"',
        })
        self.assertIn("[x] VULNERABLE", line)
        self.assertIn("blog.example.com", line)
        self.assertIn("CNAME x.github.io", line)
        self.assertIn("GitHub Pages", line)


class LoadHostsTests(unittest.TestCase):
    def test_plain_lines_and_dedup_preserve_order(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("a.example.com\n\n# comment\na.example.com\nb.example.com\n")
            path = fh.name
        try:
            hosts = takeover_check.load_hosts(["b.example.com"], path)
            self.assertEqual(hosts, ["b.example.com", "a.example.com"])
        finally:
            Path(path).unlink()

    def test_subdomain_enum_json_report_is_accepted(self):
        payload = {"subdomains": [{"name": "one.example.com"},
                                  {"name": "two.example.com"}]}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(payload, fh)
            path = fh.name
        try:
            hosts = takeover_check.load_hosts([], path)
            self.assertEqual(hosts, ["one.example.com", "two.example.com"])
        finally:
            Path(path).unlink()


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Unit tests for subdomain-enum — network-free pure functions only.

Standard library only; run with: python -m unittest discover -s tests/unit
"""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "subdomain-enum" / "subdomain_enum.py"
spec = importlib.util.spec_from_file_location("subdomain_enum", TOOL_PATH)
subdomain_enum = importlib.util.module_from_spec(spec)
sys.modules["subdomain_enum"] = subdomain_enum
spec.loader.exec_module(subdomain_enum)


class NormalizeDomainTests(unittest.TestCase):
    def test_plain_domain(self):
        self.assertEqual(subdomain_enum.normalize_domain("example.com"), "example.com")

    def test_strips_scheme_path_port_and_case(self):
        self.assertEqual(
            subdomain_enum.normalize_domain("https://Example.com:8443/path/"),
            "example.com",
        )
        self.assertEqual(
            subdomain_enum.normalize_domain("http://EXAMPLE.COM/"),
            "example.com",
        )

    def test_trailing_dot(self):
        self.assertEqual(subdomain_enum.normalize_domain("example.com."), "example.com")


class LabelLoadingTests(unittest.TestCase):
    def test_file_labels_skip_comments_and_blanks(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("# top labels\n\nwww\nmail\nftp\n")
            path = fh.name
        try:
            self.assertEqual(subdomain_enum.load_labels(path), ["www", "mail", "ftp"])
        finally:
            Path(path).unlink()

    def test_falls_back_to_builtin_list(self):
        labels = subdomain_enum.load_labels(None)
        self.assertGreater(len(labels), 0)
        self.assertIn("www", labels)

    def test_bundled_wordlist_is_loadable(self):
        bundled = REPO_ROOT / "subdomain-enum" / "wordlists" / "subdomains.txt"
        labels = subdomain_enum.load_labels(str(bundled))
        self.assertGreaterEqual(len(labels), 100)
        # no duplicates: the DNS brute force would just repeat work
        self.assertEqual(len(labels), len(set(labels)),
                         "bundled wordlist contains duplicate labels")


class BuildReportTests(unittest.TestCase):
    def test_report_shape(self):
        entries = [{"name": "www.example.com", "source": "dns"}]
        report = subdomain_enum.build_report("example.com", entries,
                                             wildcard=True, unverified=3)
        self.assertEqual(report["tool"], "subdomain-enum")
        self.assertEqual(report["domain"], "example.com")
        self.assertEqual(report["count"], 1)
        self.assertTrue(report["wildcard_dns"])
        self.assertEqual(report["unverified_crtsh_names"], 3)
        self.assertIn("generated_at", report)

    def test_json_output_round_trip(self):
        report = subdomain_enum.build_report(
            "example.com", [{"name": "www.example.com", "source": "dns"}],
            wildcard=False, unverified=0,
        )
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            subdomain_enum.write_output(report, str(out), as_json=True)
            parsed = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(parsed["domain"], "example.com")

    def test_txt_output_is_sorted_names(self):
        report = subdomain_enum.build_report(
            "example.com",
            [{"name": "zebra.example.com", "source": "dns"},
             {"name": "alpha.example.com", "source": "crtsh"}],
            wildcard=False, unverified=0,
        )
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "subs.txt"
            subdomain_enum.write_output(report, str(out), as_json=False)
            self.assertEqual(out.read_text(encoding="utf-8"),
                             "alpha.example.com\nzebra.example.com\n")


if __name__ == "__main__":
    unittest.main()

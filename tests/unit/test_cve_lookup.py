#!/usr/bin/env python3
"""Unit tests for cve-lookup — offline only; no HTTP request is made.

Standard library only; run with: python -m unittest discover -s tests/unit
"""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "cve-lookup" / "cve_lookup.py"
spec = importlib.util.spec_from_file_location("cve_lookup", TOOL_PATH)
cve_lookup = importlib.util.module_from_spec(spec)
sys.modules["cve_lookup"] = cve_lookup
spec.loader.exec_module(cve_lookup)


class NormalizeVersionTests(unittest.TestCase):
    def test_strips_non_numeric_tails(self):
        self.assertEqual(cve_lookup.normalize_version("7.4p1"), "7.4")
        self.assertEqual(cve_lookup.normalize_version("6.6.1p1"), "6.6.1")
        self.assertEqual(cve_lookup.normalize_version("1.0.1g"), "1.0.1")

    def test_keeps_plain_versions(self):
        self.assertEqual(cve_lookup.normalize_version("2.4.49"), "2.4.49")
        self.assertEqual(cve_lookup.normalize_version("10.0"), "10.0")
        self.assertEqual(cve_lookup.normalize_version("9.0.1"), "9.0.1")

    def test_no_digits_yields_empty(self):
        self.assertEqual(cve_lookup.normalize_version("Ubuntu-10"), "")
        self.assertEqual(cve_lookup.normalize_version(""), "")


class GuessCpeTests(unittest.TestCase):
    def test_ssh_protocol_prefix(self):
        guess = cve_lookup.guess_cpe("SSH-2.0-OpenSSH_7.4p1 Ubuntu-10")
        self.assertEqual(guess["vendor"], "openbsd")
        self.assertEqual(guess["product"], "openssh")
        self.assertEqual(guess["version"], "7.4")

    def test_http_server_header(self):
        guess = cve_lookup.guess_cpe("Apache/2.4.49 (Unix)")
        self.assertEqual(guess["vendor"], "apache")
        self.assertEqual(guess["product"], "http_server")
        self.assertEqual(guess["version"], "2.4.49")

    def test_specific_product_beats_generic_vendor(self):
        guess = cve_lookup.guess_cpe("Apache Tomcat/9.0.1")
        self.assertEqual(guess["product"], "tomcat")
        self.assertEqual(guess["version"], "9.0.1")

    def test_iis_with_prefix(self):
        guess = cve_lookup.guess_cpe("Microsoft-IIS/10.0")
        self.assertEqual(guess["vendor"], "microsoft")
        self.assertEqual(guess["version"], "10.0")

    def test_ftp_greeting(self):
        guess = cve_lookup.guess_cpe("220 Welcome to vsftpd 3.0.3")
        self.assertEqual(guess["vendor"], "vsftpd_project")
        self.assertEqual(guess["version"], "3.0.3")

    def test_case_insensitive_product(self):
        guess = cve_lookup.guess_cpe("REDIS 6.0.9")
        self.assertEqual(guess["product"], "redis")
        self.assertEqual(guess["version"], "6.0.9")

    def test_bare_product_has_no_version(self):
        guess = cve_lookup.guess_cpe("MySQL ready for connections")
        self.assertEqual(guess["product"], "mysql")
        self.assertEqual(guess["version"], "")

    def test_unknown_banner_returns_none(self):
        self.assertIsNone(cve_lookup.guess_cpe("weird custom service"))
        self.assertIsNone(cve_lookup.guess_cpe(""))
        self.assertIsNone(cve_lookup.guess_cpe(None))

    def test_cpe_string_shape(self):
        guess = cve_lookup.guess_cpe("nginx/1.18.0")
        cpe = cve_lookup.cpe_from_guess(guess)
        self.assertEqual(cpe, "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*")
        bare = cve_lookup.cpe_from_guess({"vendor": "redis", "product": "redis",
                                          "version": ""})
        self.assertEqual(bare, "cpe:2.3:a:redis:redis")


class SeverityTests(unittest.TestCase):
    def test_score_thresholds(self):
        self.assertEqual(cve_lookup.severity_from_score(10.0, None), "critical")
        self.assertEqual(cve_lookup.severity_from_score(9.0, None), "critical")
        self.assertEqual(cve_lookup.severity_from_score(7.5, None), "high")
        self.assertEqual(cve_lookup.severity_from_score(5.5, None), "medium")
        self.assertEqual(cve_lookup.severity_from_score(3.1, None), "low")
        self.assertEqual(cve_lookup.severity_from_score(0.0, None), "none")

    def test_fallback_without_score(self):
        self.assertEqual(cve_lookup.severity_from_score(None, "HIGH"), "high")
        self.assertEqual(cve_lookup.severity_from_score(None, None), "none")


NVD_ITEM = {
    "id": "CVE-2021-44228",
    "published": "2021-12-10T10:15:00Z",
    "descriptions": [
        {"lang": "fr", "value": "texte franais"},
        {"lang": "en", "value": "Apache Log4j2 allows remote code execution via JNDI."},
    ],
    "metrics": {
        "cvssMetricV31": [{
            "cvssData": {
                "baseScore": 10.0,
                "baseSeverity": "CRITICAL",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            },
        }],
    },
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"},
                                    {"lang": "en", "value": "CWE-917"}]}],
    "references": [{"url": "https://nvd.example/advisory"},
                   {"url": "https://logging.apache.example"}],
    "cisaExploitAdd": "2021-12-12T00:00:00.000Z",
}


class ExtractCveTests(unittest.TestCase):
    def test_full_item(self):
        cve = cve_lookup.extract_cve(NVD_ITEM)
        self.assertEqual(cve["id"], "CVE-2021-44228")
        self.assertEqual(cve["cvss"], 10.0)
        self.assertEqual(cve["severity"], "critical")
        self.assertEqual(cve["vector"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        self.assertEqual(cve["cwe"], ["CWE-502", "CWE-917"])
        self.assertTrue(cve["kev"])
        self.assertIn("Log4j2", cve["summary"])
        self.assertEqual(len(cve["references"]), 2)

    def test_v2_fallback_and_no_kev(self):
        item = {
            "id": "CVE-1999-0001",
            "descriptions": [{"lang": "en", "value": "old bug"}],
            "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 4.3,
                                                        "baseSeverity": "MEDIUM"}}]},
        }
        cve = cve_lookup.extract_cve(item)
        self.assertEqual(cve["cvss"], 4.3)
        self.assertEqual(cve["severity"], "medium")
        self.assertFalse(cve["kev"])
        self.assertEqual(cve["references"], [])


class SortFilterTests(unittest.TestCase):
    def make_cve(self, cve_id, score, kev=False, severity="high"):
        return {"id": cve_id, "cvss": score, "kev": kev, "severity": severity,
                "summary": "s"}

    def test_kev_bubbles_to_top_then_score_desc(self):
        cves = [self.make_cve("CVE-2020-0001", 9.8),
                self.make_cve("CVE-2020-0002", 5.0, kev=True),
                self.make_cve("CVE-2020-0003", 7.5)]
        ordered = [c["id"] for c in cve_lookup.sort_cves(cves)]
        self.assertEqual(ordered, ["CVE-2020-0002", "CVE-2020-0001", "CVE-2020-0003"])

    def test_min_cvss_filter(self):
        cves = [self.make_cve("CVE-2020-0001", 5.0),
                self.make_cve("CVE-2020-0002", 9.0)]
        kept = cve_lookup.filter_cves(cves, 7.0, None)
        self.assertEqual([c["id"] for c in kept], ["CVE-2020-0002"])

    def test_severity_filter(self):
        cves = [self.make_cve("CVE-2020-0001", 5.0, severity="medium"),
                self.make_cve("CVE-2020-0002", 9.0, severity="critical")]
        kept = cve_lookup.filter_cves(cves, 0.0, {"critical"})
        self.assertEqual([c["id"] for c in kept], ["CVE-2020-0002"])

    def test_missing_score_kept_when_no_floor(self):
        cve = self.make_cve("CVE-2020-0004", None)
        cve["severity"] = "none"
        self.assertEqual(cve_lookup.filter_cves([cve], 0.0, None), [cve])


class RenderTests(unittest.TestCase):
    def test_report_contains_ids_and_summary(self):
        queries = [{
            "mode": "cpe",
            "input": "OpenSSH_7.4p1",
            "cpe": "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*",
            "total_results": 12,
            "cves": [cve_lookup.extract_cve(NVD_ITEM)],
        }]
        report = {"tool": "cve-lookup", "queries": queries,
                  "summary": cve_lookup.summarize(queries)}
        text = cve_lookup.render_report(report)
        self.assertIn("CVE-2021-44228", text)
        self.assertIn("10.0", text)
        self.assertIn("CISA KEV", text)
        self.assertIn("cpe:2.3:a:openbsd:openssh", text)
        self.assertIn("Summary: 1 CVE(s) shown", text)

    def test_error_query_is_rendered(self):
        queries = [{"mode": "cpe", "input": "broken", "error": "boom", "cves": []}]
        report = {"tool": "cve-lookup", "queries": queries,
                  "summary": cve_lookup.summarize(queries)}
        text = cve_lookup.render_report(report)
        self.assertIn("ERROR: boom", text)
        self.assertIn("0 CVE(s) shown", text)


class TrimSummaryTests(unittest.TestCase):
    def test_first_line_only_and_capped(self):
        self.assertEqual(cve_lookup.trim_summary("line one\nline two"), "line one")
        trimmed = cve_lookup.trim_summary("x" * 200)
        self.assertTrue(trimmed.endswith("..."))
        self.assertLessEqual(len(trimmed), 96)


class LoadScanBannersTests(unittest.TestCase):
    def write_scan(self, data) -> str:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(data, fh)
            return fh.name

    def test_unique_banners_from_report(self):
        scan = {
            "tool": "port-scanner",
            "target": "demo",
            "ports": [
                {"port": 22, "banner": "SSH-2.0-OpenSSH_7.4"},
                {"port": 80, "banner": ""},
                {"port": 8080, "banner": "SSH-2.0-OpenSSH_7.4"},
            ],
        }
        path = self.write_scan(scan)
        try:
            loaded = cve_lookup.load_scan_banners(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["port"], 22)
        self.assertEqual(loaded[0]["banner"], "SSH-2.0-OpenSSH_7.4")

    def test_non_report_file_rejected(self):
        path = self.write_scan({"not": "a scan"})
        try:
            with self.assertRaises(ValueError):
                cve_lookup.load_scan_banners(path)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()

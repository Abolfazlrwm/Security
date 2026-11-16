#!/usr/bin/env python3
"""Unit tests for recon-pipeline — parsing, host collection and rendering.

Standard library only; run with: python -m unittest discover -s tests/unit
"""

import argparse
import importlib.util
import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "recon-pipeline" / "recon.py"
spec = importlib.util.spec_from_file_location("recon", TOOL_PATH)
recon = importlib.util.module_from_spec(spec)
sys.modules["recon"] = recon
spec.loader.exec_module(recon)


def make_args(**kwargs) -> argparse.Namespace:
    base = dict(hosts="", domain="", url="", scheme="https", max_hosts=8)
    base.update(kwargs)
    return argparse.Namespace(**base)


class ParseDirbruteOutputTests(unittest.TestCase):
    def test_valid_lines(self):
        stdout = (
            ".env (Status: 200) [Size: 124]\n"
            "admin (Status: 301) [Size: 0]\n"
            "backup.zip (Status: 200) [Size: 152]\n"
        )
        findings = recon.parse_dirbrute_output(stdout)
        self.assertEqual(findings, [
            {"path": ".env", "status": 200, "size": 124},
            {"path": "admin", "status": 301, "size": 0},
            {"path": "backup.zip", "status": 200, "size": 152},
        ])

    def test_progress_lines_are_ignored(self):
        stdout = (
            "[!] wildcard response detected (status 404, size 335)\n"
            "[*] 145 candidates queued with 10 workers\n"
            "[x] 145/145 checked, 2 findings\n"
        )
        self.assertEqual(recon.parse_dirbrute_output(stdout), [])

    def test_malformed_lines_are_ignored(self):
        stdout = "index.html (Status: 200) [Size: 96]\ngarbage line\n\n"
        findings = recon.parse_dirbrute_output(stdout)
        self.assertEqual(len(findings), 1)


class CollectHostsTests(unittest.TestCase):
    def test_explicit_host_list_skips_subdomains(self):
        args = make_args(hosts="Web01.Example.com, web02 ")
        self.assertEqual(recon.collect_hosts(args, {"subdomains": []}),
                         ["web01.example.com", "web02"])

    def test_subdomain_phase_feeds_host_list(self):
        phase = {"subdomains": [{"name": "a.example.com"},
                                {"name": "b.example.com"}]}
        hosts = recon.collect_hosts(make_args(domain="example.com"), phase)
        # the apex domain is scanned first, then the discovered names
        self.assertEqual(hosts[0], "example.com")
        self.assertIn("a.example.com", hosts)
        self.assertIn("b.example.com", hosts)

    def test_max_hosts_caps_the_list(self):
        phase = {"subdomains": [{"name": f"h{i}.example.com"} for i in range(20)]}
        hosts = recon.collect_hosts(make_args(domain="example.com", max_hosts=3),
                                    phase)
        self.assertEqual(len(hosts), 3)


class StatusClassTests(unittest.TestCase):
    def test_buckets(self):
        self.assertEqual(recon.status_class(200), "ok")
        self.assertEqual(recon.status_class(204), "ok")
        self.assertEqual(recon.status_class(301), "redir")
        self.assertEqual(recon.status_class(302), "redir")
        self.assertEqual(recon.status_class(401), "auth")
        self.assertEqual(recon.status_class(403), "auth")
        self.assertEqual(recon.status_class(404), "danger")
        self.assertEqual(recon.status_class(500), "danger")
        self.assertEqual(recon.status_class(100), "info")


class RenderTests(unittest.TestCase):
    def make_report(self) -> dict:
        return {
            "tool": "recon-pipeline",
            "version": recon.TOOL_VERSION,
            "target": "example.com",
            "base_url": "https://example.com",
            "generated_at": "2026-01-01 00:00 UTC",
            "tools": f"subdomain-enum + dirbrute (pipeline {recon.TOOL_VERSION})",
            "phases": {
                "subdomains": {
                    "ran": False,
                    "reason": "host list provided via --hosts",
                    "count": 0,
                    "subdomains": [],
                },
                "dirbrute": {
                    "ran": True,
                    "hosts": {
                        "https://example.com": {
                            "count": 2,
                            "findings": [
                                {"path": ".env", "status": 200, "size": 124},
                                {"path": "admin", "status": 301, "size": 0},
                            ],
                        }
                    },
                },
            },
            "summary": {"subdomains": 0, "hosts_scanned": 1, "findings": 2},
        }

    def test_markdown_contains_findings(self):
        md = recon.render_markdown(self.make_report())
        self.assertIn("https://example.com (2 findings)", md)
        self.assertIn(".env", md)
        self.assertIn("host list provided via --hosts", md)

    def test_html_is_self_contained(self):
        html = recon.render_html(self.make_report())
        self.assertNotIn("<script", html)
        self.assertNotIn("<link", html)
        self.assertNotIn("cdn.", html)
        self.assertIn(f"recon-pipeline {recon.TOOL_VERSION}", html)
        self.assertIn('class="pill ok"', html)
        self.assertIn('class="pill redir"', html)

    def test_html_escapes_finding_paths(self):
        report = self.make_report()
        report["phases"]["dirbrute"]["hosts"]["https://example.com"]["findings"] = [
            {"path": "<script>alert(1)</script>", "status": 200, "size": 5},
        ]
        html = recon.render_html(report)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_markdown_matches_json_summary(self):
        import json
        report = self.make_report()
        md = recon.render_markdown(report)
        self.assertIn(str(report["summary"]["findings"]), md)
        # the HTML must embed the same count as the markdown
        self.assertIn(str(report["summary"]["findings"]),
                      re.sub(r"<[^>]+>", "", recon.render_html(report)))

    def test_new_phase_sections_render(self):
        report = self.make_report()
        report["phases"]["ports"] = {
            "ran": True,
            "hosts": {
                "example.com": {
                    "ip": "93.184.216.34", "open_count": 2,
                    "ports": [
                        {"port": 80, "state": "open", "service": "http", "banner": ""},
                        {"port": 443, "state": "open", "service": "https", "banner": ""},
                    ],
                }
            },
        }
        report["phases"]["audit"] = {
            "ran": True,
            "urls": {
                "https://example.com": {
                    "score": 64, "grade": "C",
                    "findings": [
                        {"check": "tls", "status": "ok", "detail": "valid"},
                        {"check": "content-security-policy", "status": "missing",
                         "detail": "start with a report-only CSP"},
                    ],
                }
            },
        }
        report["summary"]["open_ports"] = 2
        report["summary"]["audit_score"] = 64
        report["summary"]["audit_grade"] = "C"

        md = recon.render_markdown(report)
        self.assertIn("## Port scan", md)
        self.assertIn("example.com (2 open)", md)
        self.assertIn("443/tcp | https", md)
        self.assertIn("## Web audit", md)
        self.assertIn("64/100 (grade C)", md)

        page = recon.render_html(report)
        self.assertIn("<h2>Port scan</h2>", page)
        self.assertIn("<h2>Web audit</h2>", page)
        self.assertIn("grade C", page)
        self.assertIn('class="pill auth"', page)
        self.assertIn("no banner", page)

    def test_old_reports_without_new_phases_still_render(self):
        report = self.make_report()  # no ports/audit keys at all
        md = recon.render_markdown(report)
        page = recon.render_html(report)
        self.assertNotIn("Port scan", md)
        self.assertNotIn("Web audit", md)
        self.assertNotIn("<h2>Port scan</h2>", page)
        self.assertNotIn("<h2>Web audit</h2>", page)


class LocateDirbruteTests(unittest.TestCase):
    def test_prefers_built_binary_over_go(self):
        # DIRBRUTE_DIR may or may not contain a built binary; whichever
        # branch runs, the result must be a usable command prefix.
        prefix = recon.locate_dirbrute()
        binary = recon.DIRBRUTE_DIR / "dirbrute"
        if binary.is_file():
            self.assertEqual(prefix, [str(binary)])
        else:
            self.assertTrue(prefix is None or prefix[-1] == ".")


if __name__ == "__main__":
    unittest.main()

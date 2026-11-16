#!/usr/bin/env python3
"""Unit tests for port-scanner — pure functions, no network sockets.

Standard library only; run with: python -m unittest discover -s tests/unit
"""

import importlib.util
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "port-scanner" / "port_scanner.py"
spec = importlib.util.spec_from_file_location("port_scanner", TOOL_PATH)
port_scanner = importlib.util.module_from_spec(spec)
sys.modules["port_scanner"] = port_scanner
spec.loader.exec_module(port_scanner)


class ParsePortsTests(unittest.TestCase):
    def test_single_and_ranges(self):
        self.assertEqual(
            port_scanner.parse_ports("22,80,443,8000-8100"),
            [22, 80, 443] + list(range(8000, 8101)),
        )

    def test_deduplicates_and_sorts(self):
        self.assertEqual(port_scanner.parse_ports("443,80,80,443"), [80, 443])

    def test_spaces_and_empty_chunks_are_tolerated(self):
        self.assertEqual(port_scanner.parse_ports(" 22 , 80 ,, "), [22, 80])

    def test_out_of_range_rejected(self):
        for bad in ("0", "65536", "-5", "10-1", "80000-81000", "abc", ""):
            with self.assertRaises(ValueError):
                port_scanner.parse_ports(bad)

    def test_full_range_is_valid(self):
        self.assertEqual(len(port_scanner.parse_ports("1-65535")), 65535)


class TopPortsTests(unittest.TestCase):
    def test_exactly_100_unique_valid_ports(self):
        ports = port_scanner.TOP_PORTS
        self.assertEqual(len(ports), 100)
        self.assertEqual(len(set(ports)), 100, "TOP_PORTS contains duplicates")
        for port in ports:
            self.assertTrue(1 <= port <= 65535)

    def test_the_ports_everyone_uses_are_listed(self):
        for expected in (80, 443, 22, 8080, 3306, 3389):
            self.assertIn(expected, port_scanner.TOP_PORTS)


class ServiceNameTests(unittest.TestCase):
    def test_known_services(self):
        self.assertEqual(port_scanner.service_name(80), "http")
        self.assertEqual(port_scanner.service_name(8080), "http-proxy")
        self.assertEqual(port_scanner.service_name(6379), "redis")

    def test_unknown_service(self):
        self.assertEqual(port_scanner.service_name(12345), "unknown")


class TrimBannerTests(unittest.TestCase):
    def test_empty_banner_stays_empty(self):
        self.assertEqual(port_scanner.trim_banner(""), "")
        self.assertEqual(port_scanner.trim_banner(None), "")

    def test_first_line_only(self):
        self.assertEqual(port_scanner.trim_banner("HTTP/1.1 200 OK\nServer: x"), "HTTP/1.1 200 OK")

    def test_long_banner_is_capped_with_ellipsis(self):
        trimmed = port_scanner.trim_banner("x" * 200)
        self.assertTrue(trimmed.endswith("..."))
        self.assertLessEqual(len(trimmed), 56)

    def test_control_characters_are_replaced(self):
        self.assertEqual(port_scanner.trim_banner("a\x00b"), "a b")


OPEN_PORT = [{"port": 22, "state": "open", "service": "ssh",
              "banner": "SSH-2.0-OpenSSH_9.6"}]


class RenderTableTests(unittest.TestCase):
    def test_rows_are_aligned_and_present(self):
        table = port_scanner.render_table("host", "1.2.3.4", OPEN_PORT, 100)
        self.assertIn("target host (1.2.3.4) - 100 ports scanned", table)
        self.assertIn("22/tcp", table)
        self.assertIn("SSH-2.0-OpenSSH_9.6", table)
        self.assertIn("1 open of 100 scanned", table)

    def test_empty_result_notes_no_open_ports(self):
        table = port_scanner.render_table("host", "1.2.3.4", [], 50)
        self.assertIn("(no open ports)", table)
        self.assertIn("0 open of 50 scanned", table)

    def test_missing_banner_is_labelled(self):
        entry = {"port": 80, "state": "open", "service": "http", "banner": ""}
        table = port_scanner.render_table("host", "1.2.3.4", [entry], 1)
        self.assertIn("(no banner)", table)


class BuildReportTests(unittest.TestCase):
    def test_report_shape(self):
        report = port_scanner.build_report("example.com", "93.184.216.34", OPEN_PORT, 100)
        self.assertEqual(report["tool"], "port-scanner")
        self.assertEqual(report["target"], "example.com")
        self.assertEqual(report["ip"], "93.184.216.34")
        self.assertEqual(report["scanned"], 100)
        self.assertEqual(report["open_count"], 1)
        self.assertEqual(report["ports"][0]["service"], "ssh")
        self.assertIn("generated_at", report)


if __name__ == "__main__":
    unittest.main()

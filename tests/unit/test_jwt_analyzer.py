#!/usr/bin/env python3
"""Unit tests for jwt-analyzer — pure functions, no network, no wall clock.

Standard library only; run with: python -m unittest discover -s tests/unit
"""

import base64
import hashlib
import hmac
import importlib.util
import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "jwt-analyzer" / "jwt_analyzer.py"
spec = importlib.util.spec_from_file_location("jwt_analyzer", TOOL_PATH)
jwt_analyzer = importlib.util.module_from_spec(spec)
sys.modules["jwt_analyzer"] = jwt_analyzer
spec.loader.exec_module(jwt_analyzer)


def make_token(payload: dict, secret: str = "unit-test-secret",
               alg: str = "HS256", header_extra: dict | None = None) -> str:
    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = {"alg": alg, "typ": "JWT"}
    if header_extra:
        header.update(header_extra)
    header_b = b64(json.dumps(header, separators=(",", ":")).encode())
    payload_b = b64(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b}.{payload_b}".encode()
    if alg == "none":
        return f"{header_b}.{payload_b}."
    if alg in jwt_analyzer.HMAC_ALGS:
        sig = hmac.new(secret.encode(), signing_input,
                       jwt_analyzer.HMAC_ALGS[alg]).digest()
    else:  # asymmetric algorithms: signature bytes cannot be produced here
        sig = b"\x42" * 128
    return f"{header_b}.{payload_b}.{b64(sig)}"


HMAC_ALGS = jwt_analyzer.HMAC_ALGS
NOW = 1_800_000_000.0  # 2027-01-15, well past every pinned date below


class B64UrlDecodeTests(unittest.TestCase):
    def test_round_trip_with_and_without_padding(self):
        raw = b"hello jwt world"
        padded = base64.urlsafe_b64encode(raw).decode()
        stripped = padded.rstrip("=")
        self.assertEqual(jwt_analyzer.b64url_decode(padded), raw)
        self.assertEqual(jwt_analyzer.b64url_decode(stripped), raw)

    def test_garbage_rejected(self):
        for bad in ("", "!!!", "a.b.c"):
            with self.assertRaises(ValueError):
                jwt_analyzer.b64url_decode(bad)


class DecodeTokenTests(unittest.TestCase):
    def test_round_trip(self):
        token = make_token({"sub": "admin", "exp": 1_900_000_000})
        decoded = jwt_analyzer.decode_token(token)
        self.assertEqual(decoded["payload"]["sub"], "admin")
        self.assertEqual(decoded["header"]["alg"], "HS256")
        self.assertEqual(len(decoded["signature"]), 32)

    def test_wrong_part_count_rejected(self):
        with self.assertRaises(ValueError):
            jwt_analyzer.decode_token("only-two.parts")
        with self.assertRaises(ValueError):
            jwt_analyzer.decode_token("one")

    def test_jwe_detected(self):
        token = ".".join(["a"] * 5)
        with self.assertRaises(ValueError):
            jwt_analyzer.decode_token(token)

    def test_empty_token_rejected(self):
        with self.assertRaises(ValueError):
            jwt_analyzer.decode_token("   ")

    def test_non_json_payload_rejected(self):
        bad = base64.urlsafe_b64encode(b"not json").rstrip(b"=").decode()
        token = f"eyJhbGciOiJIUzI1NiJ9.{bad}.c2ln"
        with self.assertRaises(ValueError):
            jwt_analyzer.decode_token(token)


class VerifyHmacTests(unittest.TestCase):
    def test_correct_secret_verifies(self):
        token = make_token({"sub": "a"}, secret="hunter2")
        decoded = jwt_analyzer.decode_token(token)
        self.assertTrue(jwt_analyzer.verify_hmac(
            decoded["signing_input"], decoded["signature"], "hunter2", "HS256"))

    def test_wrong_secret_fails(self):
        token = make_token({"sub": "a"}, secret="hunter2")
        decoded = jwt_analyzer.decode_token(token)
        self.assertFalse(jwt_analyzer.verify_hmac(
            decoded["signing_input"], decoded["signature"], "wrong", "HS256"))

    def test_crack_finds_weak_secret(self):
        token = make_token({"sub": "a"}, secret="secret123")
        decoded = jwt_analyzer.decode_token(token)
        found = jwt_analyzer.crack_secret(
            decoded["signing_input"], decoded["signature"], "HS256",
            ["password", "secret123", "qwerty"])
        self.assertEqual(found, "secret123")

    def test_crack_misses_strong_secret(self):
        token = make_token({"sub": "a"}, secret="x" * 40)
        decoded = jwt_analyzer.decode_token(token)
        self.assertIsNone(jwt_analyzer.crack_secret(
            decoded["signing_input"], decoded["signature"], "HS256",
            jwt_analyzer.BUILTIN_SECRETS))


class ParseTimeTests(unittest.TestCase):
    def test_numeric_dates(self):
        self.assertEqual(jwt_analyzer.parse_numeric_date(1_700_000_000),
                         1_700_000_000.0)
        self.assertEqual(jwt_analyzer.parse_numeric_date("1700000000"),
                         1_700_000_000.0)
        self.assertIsNone(jwt_analyzer.parse_numeric_date("soon"))
        self.assertIsNone(jwt_analyzer.parse_numeric_date(None))
        self.assertIsNone(jwt_analyzer.parse_numeric_date(True))

    def test_parse_now_variants(self):
        self.assertEqual(jwt_analyzer.parse_now("1700000000"), 1_700_000_000.0)
        self.assertEqual(jwt_analyzer.parse_now("2023-11-14T22:13:20Z"),
                         1_700_000_000.0)
        with self.assertRaises(ValueError):
            jwt_analyzer.parse_now("not-a-date")

    def test_iso_utc_format(self):
        self.assertEqual(jwt_analyzer.iso_utc(1_700_000_000),
                         "2023-11-14T22:13:20Z")


class CollectFindingsTests(unittest.TestCase):
    def analyze_token(self, token: str, secret: str = "unit-test-secret"):
        decoded = jwt_analyzer.decode_token(token)
        return jwt_analyzer.collect_findings(
            decoded["header"], decoded["payload"], NOW,
            {"cracked": False, "secret": None, "label": "", "tried": 0}, None)

    def test_alg_none_is_critical(self):
        findings = self.analyze_token(make_token({"sub": "x"}, alg="none"))
        self.assertTrue(any(f["severity"] == "critical" and "none" in f["title"]
                            for f in findings))

    def test_missing_alg_is_critical(self):
        header = {}
        payload = {"sub": "x"}
        findings = jwt_analyzer.collect_findings(
            header, payload, NOW, {"cracked": False}, None)
        self.assertTrue(any(f["severity"] == "critical" for f in findings))

    def test_missing_exp_is_high(self):
        findings = self.analyze_token(make_token({"sub": "x"}))
        self.assertTrue(any(f["severity"] == "high" and "never expires" in f["title"]
                            for f in findings))

    def test_expired_claim_is_medium(self):
        findings = self.analyze_token(make_token({"sub": "x", "exp": 1_700_000_000}))
        expired = [f for f in findings if f["title"] == "token expired"]
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0]["severity"], "medium")
        self.assertIn("2023-11-14", expired[0]["detail"])

    def test_future_iat_is_medium(self):
        findings = self.analyze_token(
            make_token({"sub": "x", "exp": 1_900_000_000, "iat": NOW + 999_999}))
        self.assertTrue(any(f["title"] == "iat is in the future" for f in findings))

    def test_long_lifetime_is_low(self):
        findings = self.analyze_token(
            make_token({"sub": "x", "iat": NOW, "exp": NOW + 400 * 86400}))
        self.assertTrue(any(f["severity"] == "low" and "lifetime" in f["title"]
                            for f in findings))

    def test_jku_and_kid_are_high(self):
        token = make_token({"sub": "x", "exp": 1_900_000_000},
                           header_extra={"jku": "https://evil.example/jwks.json",
                                         "kid": "../../etc/passwd"})
        findings = self.analyze_token(token)
        titles = [f["title"] for f in findings]
        self.assertTrue(any("jku" in title for title in titles))
        self.assertTrue(any("kid" in title for title in titles))

    def test_asymmetric_alg_is_info_only(self):
        findings = self.analyze_token(make_token({"sub": "x"}, alg="RS256",
                                                 secret="ignored"))
        severities = {f["severity"] for f in findings}
        self.assertNotIn("critical", severities)
        self.assertTrue(any("asymmetric" in f["title"] for f in findings))

    def test_cracked_secret_is_critical(self):
        decoded = jwt_analyzer.decode_token(make_token({"sub": "x"}))
        findings = jwt_analyzer.collect_findings(
            decoded["header"], decoded["payload"], NOW,
            {"cracked": True, "secret": "secret123", "label": "built-in list",
             "tried": 70}, None)
        self.assertTrue(any(f["severity"] == "critical" and "secret123" in f["title"]
                            for f in findings))


class AnalyzeTests(unittest.TestCase):
    def test_report_shape(self):
        token = make_token({"sub": "admin", "exp": 1_900_000_000})
        report = jwt_analyzer.analyze(token, None, None, False, NOW)
        self.assertEqual(report["tool"], "jwt-analyzer")
        self.assertEqual(report["algorithm"], "HS256")
        self.assertEqual(report["claims"]["sub"], "admin")
        self.assertIn("summary", report)
        self.assertIn("findings", report)

    def test_exit_path_marks_critical(self):
        token = make_token({"sub": "x"}, alg="none")
        report = jwt_analyzer.analyze(token, None, None, False, NOW)
        self.assertGreater(report["summary"]["critical"], 0)

    def test_hmac_secret_verification_flags(self):
        token = make_token({"sub": "x", "exp": 1_900_000_000}, secret="real")
        decoded = jwt_analyzer.decode_token(token)
        verified = jwt_analyzer.verify_hmac(decoded["signing_input"],
                                            decoded["signature"], "real", "HS256")
        findings = jwt_analyzer.collect_findings(
            decoded["header"], decoded["payload"], NOW,
            {"cracked": False, "secret": None, "label": "", "tried": 0},
            verified)
        self.assertFalse(any("does not match" in f["title"] for f in findings))
        findings = jwt_analyzer.collect_findings(
            decoded["header"], decoded["payload"], NOW,
            {"cracked": False, "secret": None, "label": "", "tried": 0},
            not verified)
        self.assertTrue(any("does not match" in f["title"] for f in findings))


class RenderTests(unittest.TestCase):
    def test_render_contains_sections(self):
        token = make_token({"sub": "admin", "role": "reader",
                            "iat": NOW - 100, "exp": NOW + 100})
        report = jwt_analyzer.analyze(token, None, None, True, NOW)
        text = jwt_analyzer.render_report(report)
        for section in ("Header", "Claims", "Signature", "Findings", "Summary"):
            self.assertIn(section, text)
        self.assertIn("sub", text)
        self.assertIn("HS256", text)

    def test_time_claims_are_human_readable(self):
        token = make_token({"exp": 1_900_000_000})
        report = jwt_analyzer.analyze(token, None, None, True, NOW)
        lines = jwt_analyzer.render_claims(report["claims"])
        self.assertTrue(any("2030" in line and "1900000000" in line for line in lines))


class LoadSecretsTests(unittest.TestCase):
    def test_builtin_list_loads(self):
        secrets, label = jwt_analyzer.load_secrets(None)
        self.assertIn("secret123", secrets)
        self.assertEqual(label, "built-in list")

    def test_missing_wordlist_raises(self):
        with self.assertRaises(FileNotFoundError):
            jwt_analyzer.load_secrets("/nonexistent/secrets.txt")


if __name__ == "__main__":
    unittest.main()

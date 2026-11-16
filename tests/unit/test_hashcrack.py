#!/usr/bin/env python3
"""Unit tests for hashcrack — pure functions plus one end-to-end run.

Standard library only; run with: python -m unittest discover -s tests/unit
"""

import hashlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "hashcrack" / "hashcrack.py"
spec = importlib.util.spec_from_file_location("hashcrack", TOOL_PATH)
hashcrack = importlib.util.module_from_spec(spec)
sys.modules["hashcrack"] = hashcrack
spec.loader.exec_module(hashcrack)


class RuleTests(unittest.TestCase):
    def test_lower_upper_capitalize(self):
        self.assertEqual(hashcrack.variants("Secret", ["lower"]), ["secret"])
        self.assertEqual(hashcrack.variants("secret", ["upper"]), ["SECRET"])
        self.assertEqual(hashcrack.variants("secret", ["capitalize"]), ["Secret"])

    def test_reverse_and_leet(self):
        self.assertEqual(hashcrack.variants("secret", ["reverse"]), ["terces"])
        self.assertEqual(hashcrack.variants("secret", ["leet"]), ["53cr37"])

    def test_append_rules_expand(self):
        self.assertEqual(hashcrack.variants("pw", ["append1"]),
                         [f"pw{d}" for d in range(10)])
        self.assertEqual(len(hashcrack.variants("pw", ["append2"])), 100)
        self.assertEqual(len(hashcrack.variants("pw", ["append4"])), 10000)

    def test_chain_order_matters(self):
        # capitalize then reverse differs from reverse then capitalize
        a = hashcrack.variants("secret", ["capitalize", "reverse"])
        b = hashcrack.variants("secret", ["reverse", "capitalize"])
        self.assertEqual(a, ["terceS"])
        self.assertEqual(b, ["Terces"])
        # appending a digit before reversing differs from reversing first
        c = hashcrack.variants("secret", ["append1", "reverse"])
        d = hashcrack.variants("secret", ["reverse", "append1"])
        self.assertIn("0terces", c)
        self.assertNotIn("0terces", d)
        self.assertIn("terces0", d)

    def test_dedup_preserves_order(self):
        out = hashcrack.variants("Ab", ["lower", "lower"])
        self.assertEqual(out, ["ab"])

    def test_estimate_candidates(self):
        self.assertEqual(hashcrack.estimate_candidates(78, []), 78)
        self.assertEqual(hashcrack.estimate_candidates(78, ["append2"]), 7800)
        self.assertEqual(hashcrack.estimate_candidates(78, ["capitalize", "append4"]),
                         780000)


class SaltTests(unittest.TestCase):
    def test_prefix_and_suffix(self):
        self.assertEqual(hashcrack.apply_salt("admin", "salt", "prefix"), "saltadmin")
        self.assertEqual(hashcrack.apply_salt("admin", "salt", "suffix"), "adminsalt")


class TargetLoadingTests(unittest.TestCase):
    def test_auto_detection(self):
        cases = {
            hashlib.md5(b"x").hexdigest(): "md5",
            hashlib.sha1(b"x").hexdigest(): "sha1",
            hashlib.sha256(b"x").hexdigest(): "sha256",
        }
        for digest, algo in cases.items():
            with self.subTest(algo=algo):
                targets, needed = hashcrack.load_targets([digest], None, None)
                self.assertEqual(needed, [algo])
                self.assertIn(digest, targets)

    def test_label_suffix_is_preserved(self):
        digest = hashlib.md5(b"password").hexdigest()
        targets, _ = hashcrack.load_targets([f"{digest}:password"], None, None)
        self.assertEqual(targets[digest], f"{digest}:password")

    def test_invalid_digest_rejected(self):
        with self.assertRaises(SystemExit):
            hashcrack.load_targets(["not-a-digest"], None, None)
        with self.assertRaises(SystemExit):
            hashcrack.load_targets([hashlib.md5(b"x").hexdigest()], None, "sha1")

    def test_unknown_length_requires_type(self):
        with self.assertRaises(SystemExit):
            hashcrack.load_targets(["deadbeef"], None, None)

    def test_no_targets_rejected(self):
        with self.assertRaises(SystemExit):
            hashcrack.load_targets([], None, None)

    def test_hash_file_comments_and_blanks(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write(f"# note\n\n{hashlib.md5(b'admin').hexdigest()}\n")
            path = fh.name
        try:
            targets, _ = hashcrack.load_targets(None, path, None)
            self.assertEqual(len(targets), 1)
        finally:
            Path(path).unlink()


class WordlistTests(unittest.TestCase):
    def test_stream_skips_comments_and_blanks(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("# header\n\nalpha\nbeta\n")
            path = fh.name
        try:
            words = [w.strip() for w in hashcrack.word_stream(Path(path))]
            self.assertEqual(words, ["alpha", "beta"])
        finally:
            Path(path).unlink()

    def test_bundled_and_builtin_wordlists_agree(self):
        """The mirrored built-in list must cover every bundled wordlist entry."""
        bundled = {
            line.strip()
            for line in hashcrack.DEFAULT_WORDLIST.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        }
        builtin = set(hashcrack.BUILTIN_WORDLIST)
        self.assertTrue(builtin >= bundled,
                        f"missing from built-in list: {sorted(bundled - builtin)}")


class EndToEndTests(unittest.TestCase):
    def test_main_cracks_with_custom_wordlist(self):
        secret = "Zanzibar42"
        with tempfile.TemporaryDirectory() as tmp:
            wordlist = Path(tmp) / "words.txt"
            wordlist.write_text("nope\nother\n" + secret + "\n", encoding="utf-8")
            found = Path(tmp) / "found.txt"
            rc = hashcrack.main([
                "--hash", hashlib.md5(secret.encode()).hexdigest(),
                "-w", str(wordlist), "-o", str(found), "-q",
            ])
            self.assertEqual(rc, 0)
            self.assertIn(hashlib.md5(secret.encode()).hexdigest(),
                          found.read_text(encoding="utf-8"))

    def test_main_returns_one_when_uncracked(self):
        with tempfile.TemporaryDirectory() as tmp:
            wordlist = Path(tmp) / "words.txt"
            wordlist.write_text("alpha\nbeta\n", encoding="utf-8")
            rc = hashcrack.main([
                "--hash", hashlib.md5(b"not-in-list").hexdigest(),
                "-w", str(wordlist), "-q",
            ])
            self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()

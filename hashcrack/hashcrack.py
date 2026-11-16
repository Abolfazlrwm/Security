#!/usr/bin/env python3
"""Crack MD5, SHA-1 and SHA-256 digests with wordlists and rule mutations.

The tool streams a wordlist, applies an ordered chain of mutation rules to
every word (mirroring the classic "rules" workflow) and compares each
candidate digest against a set of targets. Targets can be auto-detected
by digest length or pinned with --type. Only the standard library is used;
hashing is CPU bound, so the loop stays single threaded on purpose.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
from pathlib import Path

TOOL_NAME = "hashcrack"
TOOL_VERSION = "1.1.1"

ALGOS = ("md5", "sha1", "sha256")
ALGO_BY_LENGTH = {32: "md5", 40: "sha1", 64: "sha256"}
LENGTH_BY_ALGO = {v: k for k, v in ALGO_BY_LENGTH.items()}

LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})

RULES = {
    "lower": lambda w: [w.lower()],
    "upper": lambda w: [w.upper()],
    "capitalize": lambda w: [w.capitalize()],
    "reverse": lambda w: [w[::-1]],
    "leet": lambda w: [w.translate(LEET)],
    "append1": lambda w: [w + str(d) for d in range(10)],
    "append2": lambda w: [w + f"{d:02d}" for d in range(100)],
    "append4": lambda w: [w + f"{d:04d}" for d in range(10000)],
}

DEFAULT_WORDLIST = Path(__file__).resolve().parent / "wordlists" / "common-passwords.txt"
PROGRESS_INTERVAL = 2.0  # seconds between progress lines on stderr

# Mirror of wordlists/common-passwords.txt. It keeps the tool (and the
# PyInstaller standalone binary) usable even when no wordlist file is around.
BUILTIN_WORDLIST: tuple[str, ...] = (
    "password", "123456", "123456789", "12345678", "12345", "1234567",
    "1234567890", "qwerty", "abc123", "password1", "password123", "admin",
    "admin123", "letmein", "welcome", "welcome1", "monkey", "login",
    "dragon", "passw0rd", "master", "hello", "freedom", "whatever",
    "qazwsx", "trustno1", "iloveyou", "P@ssw0rd", "p@ssw0rd", "Password1",
    "Password123", "shadow", "superman", "batman", "michael", "football",
    "baseball", "hockey", "soccer", "starwars", "princess", "jennifer",
    "jordan", "harley", "ranger", "hunter", "buster", "thomas", "robert",
    "charlie", "andrew", "daniel", "matrix", "111111", "000000", "121212",
    "654321", "abcdef", "google", "samsung", "laptop", "coffee",
    "chocolate", "cookie", "summer", "winter", "killer", "george",
    "access", "love", "secret", "test", "guest", "user", "root", "toor",
    "oracle", "changeme",
)


def info(message: str) -> None:
    print(f"[*] {message}", file=sys.stderr)


def variants(word: str, rules: list[str]) -> list[str]:
    """Apply the selected rules in order, expanding each candidate as we go."""
    current = [word]
    for rule in rules:
        expanded: list[str] = []
        for candidate in current:
            expanded.extend(RULES[rule](candidate))
        current = expanded
    seen: set[str] = set()
    unique = []
    for candidate in current:
        if candidate not in seen:
            seen.add(candidate)
            unique.append(candidate)
    return unique


def estimate_candidates(word_count: int, rules: list[str]) -> int:
    factor = 1
    for rule in rules:
        probe = RULES[rule]("x")
        factor *= max(len(probe), 1)
    return word_count * factor


def word_stream(wordlist: Path | None):
    """Yield words from a wordlist file, or the built-in list.

    Blank lines and ``#`` comments are skipped; the built-in list has
    neither, so this only applies to file-based wordlists.
    """
    if wordlist is not None:
        with open(wordlist, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    yield line
    else:
        yield from BUILTIN_WORDLIST


def load_wordlist(path: str | None) -> Path | None:
    """Resolve the wordlist path, falling back to the built-in list."""
    if path:
        chosen = Path(path)
        if not chosen.is_file():
            raise SystemExit(f"error: wordlist not found: {chosen}")
        return chosen
    if DEFAULT_WORDLIST.exists():
        info(f"using bundled wordlist {DEFAULT_WORDLIST}")
        return DEFAULT_WORDLIST
    info(f"no wordlist file found, using the built-in list ({len(BUILTIN_WORDLIST)} entries)")
    return None


def load_targets(hash_values: list[str] | None, hash_file: str | None, algo: str | None) -> tuple[dict[str, str], list[str]]:
    """Collect target digests and derive which algorithms are needed."""
    raw_lines: list[str] = []

    for value in hash_values or []:
        raw_lines.append(value)
    if hash_file:
        with open(hash_file, encoding="utf-8") as handle:
            raw_lines.extend(line.strip() for line in handle)

    targets: dict[str, str] = {}
    for line in raw_lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Accept an optional ":label" suffix, e.g. "5f4dcc...:password"
        digest = line.split(":", 1)[0].strip().lower()
        is_hex = all(c in "0123456789abcdef" for c in digest)
        if algo:
            if len(digest) != LENGTH_BY_ALGO[algo] or not is_hex:
                raise SystemExit(f"error: not a valid {algo} digest: {line[:72]}")
        elif not is_hex or len(digest) not in ALGO_BY_LENGTH:
            raise SystemExit(
                f"error: cannot infer the algorithm for {digest[:16]}..., use --type"
            )
        targets[digest] = line

    if not targets:
        raise SystemExit("error: no hashes given, use --hash or --hashes")

    needed = sorted({ALGO_BY_LENGTH[len(digest)] for digest in targets})
    return targets, needed


def apply_salt(candidate: str, salt: str, position: str) -> str:
    return salt + candidate if position == "prefix" else candidate + salt


def crack(
    targets: dict[str, str],
    algos: list[str],
    wordlist: Path,
    rules: list[str],
    salt: str,
    salt_position: str,
    quiet: bool,
) -> tuple[dict[str, tuple[str, str]], int, float]:
    """Stream the wordlist and try every candidate against the targets."""
    matched: dict[str, tuple[str, str]] = {}
    candidates = 0
    started = time.monotonic()
    last_report = started

    for line in word_stream(wordlist):
        word = line.rstrip("\r\n")
        if not word:
            continue
        for variant in variants(word, rules):
            candidate = apply_salt(variant, salt, salt_position) if salt else variant
            data = candidate.encode("utf-8", "surrogatepass")
            candidates += 1
            for algo in algos:
                digest = hashlib.new(algo, data).hexdigest()
                if digest in targets and digest not in matched:
                    matched[digest] = (candidate, targets[digest])
                    print(f"[+] cracked {targets[digest]} -> {candidate}")
            if len(matched) == len(targets):
                return matched, candidates, time.monotonic() - started
        if not quiet and time.monotonic() - last_report >= PROGRESS_INTERVAL:
            elapsed = time.monotonic() - started
            rate = candidates / elapsed if elapsed else 0.0
            info(f"{candidates:,} candidates, {rate:,.0f} h/s, {len(matched)}/{len(targets)} cracked")
            last_report = time.monotonic()

    return matched, candidates, time.monotonic() - started


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Crack MD5/SHA-1/SHA-256 hashes with wordlists and rules.",
        epilog="available rules: " + ", ".join(RULES),
    )
    parser.add_argument("--hash", action="append", metavar="DIGEST", help="target digest, repeatable")
    parser.add_argument("--hashes", metavar="FILE", help="file with one digest per line")
    parser.add_argument("-w", "--wordlist", help="wordlist (default: bundled common-passwords.txt, then the built-in list)")
    parser.add_argument(
        "--rules", default="",
        help="comma separated rule chain applied in order (e.g. capitalize,append2)",
    )
    parser.add_argument("--type", choices=ALGOS, help="force the algorithm instead of auto-detection")
    parser.add_argument("--salt", help="salt prepended/appended to every candidate")
    parser.add_argument("--salt-position", choices=("prefix", "suffix"), default="suffix", help="salt placement (default: %(default)s)")
    parser.add_argument("-o", "--found-file", help="append cracked 'digest:plain' pairs to this file")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    args = parser.parse_args(argv)

    if not args.hash and not args.hashes:
        parser.error("give at least one target with --hash or --hashes")

    args.rules = [rule.strip() for rule in args.rules.split(",") if rule.strip()]
    unknown = [rule for rule in args.rules if rule not in RULES]
    if unknown:
        parser.error(f"unknown rule(s) {', '.join(unknown)}; available: {', '.join(RULES)}")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    targets, algos = load_targets(args.hash, args.hashes, args.type)
    wordlist = load_wordlist(args.wordlist)

    if not args.quiet:
        info(f"{len(targets)} target(s) using {', '.join(algos)}")
    word_count = sum(1 for line in word_stream(wordlist) if line.strip("\r\n"))
    if not args.quiet and args.rules:
        info(f"rules {args.rules} expand {word_count:,} words to ~{estimate_candidates(word_count, args.rules):,} candidates")

    matched, candidates, elapsed = crack(
        targets, algos, wordlist, args.rules, args.salt or "", args.salt_position, args.quiet
    )

    rate = candidates / elapsed if elapsed else 0.0
    info(f"finished: {len(matched)}/{len(targets)} cracked, {candidates:,} candidates, {rate:,.0f} h/s, {elapsed:.1f}s")

    if args.found_file and matched:
        with open(args.found_file, "a", encoding="utf-8") as handle:
            for digest, (plain, _original) in matched.items():
                handle.write(f"{digest}:{plain}\n")
        info(f"results appended to {args.found_file}")

    return 0 if len(matched) == len(targets) else 1


if __name__ == "__main__":
    sys.exit(main())

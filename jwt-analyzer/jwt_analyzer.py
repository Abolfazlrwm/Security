#!/usr/bin/env python3
"""Decode, verify and audit JSON Web Tokens entirely offline.

Given a JWT the tool prints the header and claims in a readable table,
checks the signature with a supplied secret (HS256/384/512), runs a
dictionary attack against HMAC-signed tokens using a built-in list of
common secrets, and collects severity-ranked findings: alg=none signature
bypasses, attacker-controlled key headers (jku/jwk/x5u), suspicious kid
values, missing exp, expired or future-dated claims and long token
lifetimes.

Authorized use only: analyse tokens you own or have explicit permission
to test. Only the Python standard library is used; no network requests.
"""

from __future__ import annotations

__version__ = "1.0.0"

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

TOOL_NAME = "jwt-analyzer"
TOOL_VERSION = "1.0.0"

HMAC_ALGS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}
ASYM_PREFIXES = ("RS", "PS", "ES")
TIME_CLAIMS = ("exp", "nbf", "iat", "auth_time")
FUTURE_SKEW_SECONDS = 300
LONG_LIVED_DAYS = 30

# Fallback list used when no --wordlist file exists; the shipped wordlist
# (jwt-analyzer/wordlists/secrets.txt) extends this with the classics.
BUILTIN_SECRETS = [
    "secret", "secret123", "secretkey", "supersecret", "super_secret",
    "your-256-bit-secret", "mysecret", "my-secret", "jwt_secret", "jwt-secret",
    "password", "password123", "passw0rd", "changeme", "default", "test",
    "admin", "root", "token", "key", "key123", "apikey", "api_key",
    "keyboard cat", "shhhh", "shhhhh", "shhhhhhh", "itsasecret", "topsecret",
    "hunter2", "letmein", "qwerty", "abc123", "123456", "1234567890",
    "iloveyou", "trustno1", "monkey", "dragon", "welcome", "hello",
    "freedom", "whatever", "654321", "123123", "aaaaaa", "s3cr3t",
    "s3cr3t!", "P@ssw0rd", "auth", "authentication", "session", "cookie",
    "dev", "development", "staging", "production", "example", "example-key",
    "django-insecure", "flask-secret", "symmetric", "signature", "hmac",
    "nothing", "none", "todo", "tobechanged", "notasecret", "not-so-secret",
]


def info(message: str) -> None:
    print(f"[*] {message}", file=sys.stderr)


def warn(message: str) -> None:
    print(f"[!] {message}", file=sys.stderr)


def b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment, tolerating stripped padding."""
    if not isinstance(segment, str) or segment == "":
        raise ValueError("empty base64url segment")
    try:
        padded = segment + "=" * (-len(segment) % 4)
        return base64.b64decode(padded.encode("ascii"), altchars=b"-_",
                                validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise ValueError(f"invalid base64url segment: {segment[:24]!r}") from None


def decode_token(token: str) -> dict:
    """Split and decode a JWS compact serialisation.

    Returns {header, payload, signature, signature_text, signing_input}.
    Raises ValueError with a human-readable reason on malformed input.
    """
    token = token.strip()
    if not token:
        raise ValueError("empty token")
    parts = token.split(".")
    if len(parts) == 5:
        raise ValueError("five segments look like a JWE (encrypted JWT); "
                         "only signed JWS tokens are supported")
    if len(parts) != 3:
        raise ValueError(f"a JWS token has 3 dot-separated segments, got {len(parts)}")

    header_b, payload_b, signature_b = parts
    try:
        header = json.loads(b64url_decode(header_b).decode("utf-8"))
        payload = json.loads(b64url_decode(payload_b).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"header/payload is not valid JSON: {exc}") from None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("header and payload must decode to JSON objects")
    signature = b64url_decode(signature_b) if signature_b else b""
    signing_input = f"{header_b}.{payload_b}".encode("ascii")
    return {
        "header": header,
        "payload": payload,
        "signature": signature,
        "signature_text": signature_b,
        "signing_input": signing_input,
    }


def is_hmac_alg(alg: str) -> bool:
    return alg in HMAC_ALGS


def is_asym_alg(alg: str) -> bool:
    return alg.startswith(ASYM_PREFIXES) or alg in ("EdDSA",)


def verify_hmac(signing_input: bytes, signature: bytes, secret: str, alg: str) -> bool:
    digestmod = HMAC_ALGS[alg]
    expected = hmac.new(secret.encode("utf-8"), signing_input, digestmod).digest()
    return hmac.compare_digest(expected, signature)


def load_secrets(wordlist: str | None) -> tuple[list[str], str]:
    """Built-in list plus an optional wordlist file; returns (secrets, label)."""
    secrets = list(BUILTIN_SECRETS)
    label = "built-in list"
    if wordlist:
        path = Path(wordlist)
        if not path.is_file():
            raise FileNotFoundError(f"wordlist not found: {wordlist}")
        extra = []
        seen = set(secrets)
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            word = line.strip()
            if word and word not in seen:
                seen.add(word)
                extra.append(word)
        secrets.extend(extra)
        label = f"{path.name} + built-in list"
    return secrets, label


def crack_secret(signing_input: bytes, signature: bytes, alg: str,
                 secrets: list[str]) -> str | None:
    """Dictionary attack against an HMAC signature; returns the secret."""
    for secret in secrets:
        if verify_hmac(signing_input, signature, secret, alg):
            return secret
    return None


def parse_numeric_date(value) -> float | None:
    """JWT NumericDate; integers and numeric strings are accepted."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def parse_now(raw: str | None) -> float:
    """--now accepts ISO-8601 (UTC offset or Z) or unix seconds."""
    if raw is None:
        return time.time()
    text = raw.strip()
    try:
        return float(text)
    except ValueError:
        pass
    iso = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(iso)
    except ValueError:
        raise ValueError(f"invalid --now value: {raw!r}") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def iso_utc(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def collect_findings(header: dict, payload: dict, now: float,
                     secret_result: dict, signature_verified: bool | None) -> list[dict]:
    """Severity-ranked findings; severity in critical/high/medium/low/info."""
    findings: list[dict] = []

    def add(severity: str, title: str, detail: str = "") -> None:
        findings.append({"severity": severity, "title": title, "detail": detail})

    alg = str(header.get("alg", ""))
    if not alg:
        add("critical", "missing alg header", "the header declares no algorithm")
    elif alg.lower() == "none":
        add("critical", 'alg "none" - signature bypass',
            "servers that skip verification accept this token from anyone")
    elif is_asym_alg(alg):
        add("info", f"{alg} is asymmetric - signature not verifiable offline",
            "verification needs the public key; no attempt was made")

    for key in ("jku", "jwk", "x5u"):
        if key in header:
            add("high", f"attacker-controlled key header: {key}",
                "verify the server pins the key source before trusting this header")

    kid = header.get("kid")
    if isinstance(kid, str) and (".." in kid or "/" in kid or "\\" in kid):
        add("high", "kid contains path characters",
            f"kid={kid!r} may enable path traversal or injection in key lookup")

    if secret_result.get("cracked"):
        add("critical", f"weak HMAC secret cracked: {secret_result['secret']!r}",
            f"matched {secret_result['label']} after "
            f"{secret_result['tried']} candidate(s)")
    elif signature_verified is False:
        add("high", "signature does not match the provided secret",
            "either the token was tampered with or the wrong secret was given")

    exp = None
    if "exp" not in payload:
        add("high", "token never expires", "no exp claim in the payload")
    else:
        exp = parse_numeric_date(payload.get("exp"))
        if exp is None:
            add("medium", "exp is not a numeric date", f"exp={payload.get('exp')!r}")
        elif exp < now:
            add("medium", "token expired", f"expired at {iso_utc(exp)}")

    nbf = parse_numeric_date(payload.get("nbf"))
    if nbf is not None and nbf > now + FUTURE_SKEW_SECONDS:
        add("medium", "nbf is in the future", f"valid from {iso_utc(nbf)}")
    iat = parse_numeric_date(payload.get("iat"))
    if iat is not None and iat > now + FUTURE_SKEW_SECONDS:
        add("medium", "iat is in the future", f"issued at {iso_utc(iat)}")

    if exp is not None and iat is not None and exp > iat:
        lifetime_days = (exp - iat) / 86400
        if lifetime_days > LONG_LIVED_DAYS:
            add("low", f"token lifetime is {lifetime_days:.0f} days",
                "long-lived tokens widen the window for replay attacks")

    if "typ" in header and str(header["typ"]).upper() not in ("JWT", "AT+JWT"):
        add("info", f"unusual typ header: {header['typ']!r}",
            "most implementations expect JWT")

    return findings


def count_by_severity(findings: list[dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return counts


def analyze(token: str, secret: str | None, wordlist: str | None,
            no_crack: bool, now: float) -> dict:
    """Full analysis; returns the report (findings included)."""
    decoded = decode_token(token)
    header, payload = decoded["header"], decoded["payload"]
    alg = str(header.get("alg", ""))

    signature_verified: bool | None = None
    secret_result = {"cracked": False, "secret": None, "label": "", "tried": 0}

    if is_hmac_alg(alg) and decoded["signature"]:
        if secret:
            signature_verified = verify_hmac(
                decoded["signing_input"], decoded["signature"], secret, alg)
        if not no_crack:
            secrets, label = load_secrets(wordlist)
            info(f"dictionary attack with {len(secrets)} candidate secrets ({label})")
            cracked = crack_secret(decoded["signing_input"], decoded["signature"],
                                   alg, secrets)
            secret_result = {"cracked": cracked is not None, "secret": cracked,
                             "label": label, "tried": len(secrets)}

    findings = collect_findings(header, payload, now, secret_result,
                                signature_verified)

    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "algorithm": alg or None,
        "typ": header.get("typ"),
        "header": header,
        "claims": payload,
        "signature_bytes": len(decoded["signature"]),
        "signature_verified": signature_verified,
        "secret_check": secret_result,
        "findings": findings,
        "summary": count_by_severity(findings),
    }


def render_claims(payload: dict) -> list[str]:
    lines = []
    for key, value in payload.items():
        if key in TIME_CLAIMS:
            ts = parse_numeric_date(value)
            if ts is not None:
                lines.append(f"  {key:<12}{iso_utc(ts)}  (numeric {value})")
                continue
        rendered = json.dumps(value, ensure_ascii=False, sort_keys=True)
        if len(rendered) > 72:
            rendered = rendered[:69].rstrip() + "..."
        lines.append(f"  {key:<12}{rendered}")
    return lines


def render_report(report: dict) -> str:
    header = report["header"]
    alg = report["algorithm"] or "(missing)"
    lines = [f"JWT analysis - alg {alg}", ""]

    lines.append("Header")
    for key, value in header.items():
        rendered = json.dumps(value, ensure_ascii=False)
        if len(rendered) > 72:
            rendered = rendered[:69].rstrip() + "..."
        lines.append(f"  {key:<12}{rendered}")

    lines.append("")
    lines.append("Claims")
    claim_lines = render_claims(report["claims"])
    lines.extend(claim_lines if claim_lines else ["  (empty payload)"])

    lines.append("")
    lines.append("Signature")
    lines.append(f"  {report['signature_bytes']} bytes of signature")
    if report["signature_verified"] is True:
        lines.append("  matches the provided secret: yes")
    elif report["signature_verified"] is False:
        lines.append("  matches the provided secret: NO")
    secret_result = report["secret_check"]
    if secret_result.get("cracked"):
        lines.append(f"  dictionary attack: CRACKED -> {secret_result['secret']!r}")
    elif secret_result.get("tried"):
        lines.append(f"  dictionary attack: not cracked "
                     f"({secret_result['tried']} candidates tried)")

    lines.append("")
    lines.append("Findings")
    if not report["findings"]:
        lines.append("  (none - token looks structurally sound)")
    for finding in report["findings"]:
        lines.append(f"  [{finding['severity'].upper():<8}] {finding['title']}")
        if finding["detail"]:
            lines.append(f"             {finding['detail']}")

    counts = report["summary"]
    lines.append("")
    lines.append("Summary: "
                 f"{counts['critical']} critical, {counts['high']} high, "
                 f"{counts['medium']} medium, {counts['low']} low, "
                 f"{counts['info']} info")
    return "\n".join(lines) + "\n"


def write_output(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
        info(f"results written to {output}")
    else:
        sys.stdout.write(text)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Decode, verify and audit JWTs offline (stdlib only).",
    )
    parser.add_argument("--version", action="version",
                  version="%(prog)s " + __version__)
    parser.add_argument("token", help="compact JWT, e.g. eyJhbGciOi....eyJzdWIi....sig")
    parser.add_argument("--secret", help="verify HMAC signatures with this secret")
    parser.add_argument("--wordlist", help="extra candidate secrets, one per line")
    parser.add_argument("--no-crack", action="store_true",
                        help="skip the built-in weak-secret dictionary attack")
    parser.add_argument("--now", help="reference time for expiry checks "
                                      "(ISO-8601 or unix seconds; default: now)")
    parser.add_argument("-f", "--format", choices=("txt", "json"), default="txt",
                        help="output format (default: %(default)s)")
    parser.add_argument("-o", "--output", help="write results to this file")
    args = parser.parse_args(argv)
    if not args.token.strip():
        parser.error("token is empty")
    try:
        args.now_epoch = parse_now(args.now)
    except ValueError as exc:
        parser.error(str(exc))
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = analyze(args.token, args.secret, args.wordlist,
                         args.no_crack, args.now_epoch)
    except (ValueError, FileNotFoundError) as exc:
        warn(str(exc))
        return 2

    info(f"analyzed {report['algorithm'] or 'unlabeled'} token, "
         f"{len(report['claims'])} claims, "
         f"{sum(report['summary'].values())} findings")

    if args.format == "json":
        text = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    else:
        text = render_report(report)
    write_output(text, args.output)

    return 1 if report["summary"]["critical"] else 0


if __name__ == "__main__":
    sys.exit(main())

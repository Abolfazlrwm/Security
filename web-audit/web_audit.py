#!/usr/bin/env python3
"""Audit a web target's TLS certificate and HTTP security headers.

One run answers the questions a first-pass review always starts with:
is TLS there and how long does the certificate live, do the classic
security headers exist, are cookies protected, and does the server leak
its version. The findings roll up into a 0-100 score and a letter grade,
plus stable JSON for [recon-pipeline](../recon-pipeline/).

This is a configuration linter, not a vulnerability scanner: it only
sends normal GET requests and reads public headers. Only the Python
standard library is used.

Authorized use only: audit systems you own or have explicit permission
to test.
"""

from __future__ import annotations

import argparse
import http.cookies
import json
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

TOOL_NAME = "web-audit"
TOOL_VERSION = "1.0.0"

DEFAULT_TIMEOUT = 10.0

REQUIRED_HEADERS = [
    ("strict-transport-security",
     "enable HSTS once HTTPS is stable (prevents protocol downgrade)"),
    ("content-security-policy",
     "start with a report-only CSP, then restrict script sources"),
    ("x-content-type-options",
     "send nosniff to stop MIME-type sniffing"),
    ("x-frame-options",
     "deny framing (DENY / SAMEORIGIN, or CSP frame-ancestors)"),
    ("referrer-policy",
     "limit referrer leakage, e.g. strict-origin-when-cross-origin"),
    ("permissions-policy",
     "restrict powerful browser features (camera, geolocation, ...)"),
]

MISSING_PENALTY = 12
TLS_PENALTY = 20
EXPIRED_PENALTY = 25
SOON_PENALTY = 8
REDIRECT_PENALTY = 6
DISCLOSURE_PENALTY = 5
COOKIE_PENALTY = 6
COOKIE_PENALTY_CAP = 18

GRADE_THRESHOLDS = ((90, "A"), (75, "B"), (60, "C"), (40, "D"))


def info(message: str) -> None:
    print(f"[*] {message}", file=sys.stderr)


def warn(message: str) -> None:
    print(f"[!] {message}", file=sys.stderr)


def unverified_context() -> ssl.SSLContext:
    """TLS context that accepts any certificate (for header-only audits)."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def normalize_target(raw: str) -> dict:
    """Accept sloppy input (domain, host:port, full URL) and split it up."""
    value = raw.strip()
    if "://" not in value:
        value = "https://" + value
    parsed = urllib.parse.urlparse(value)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme: {scheme!r}")
    host = parsed.hostname or ""
    if not host:
        raise ValueError(f"no host in target: {raw!r}")
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    display = f"{scheme}://{host}" + (f":{port}" if port != (443 if scheme == "https" else 80) else "")
    return {"scheme": scheme, "host": host.lower(), "port": port, "path": path, "display": display}


def lowercase_headers(pairs) -> dict[str, str]:
    """Collapse (name, value) header pairs into a lower-cased dict."""
    result: dict[str, str] = {}
    for key, value in pairs:
        key = key.lower()
        result[key] = (result[key] + ", " + value) if key in result else value
    return result


def evaluate_headers(headers: dict[str, str]) -> list[dict]:
    """Pure header audit -- unit tested; the network layer feeds it."""
    findings: list[dict] = []
    for name, advice in REQUIRED_HEADERS:
        value = headers.get(name)
        if value:
            findings.append({"check": name, "status": "ok", "detail": value.strip()[:80]})
        else:
            findings.append({"check": name, "status": "missing", "detail": advice})
    server = headers.get("server", "")
    if server and re.search(r"\d", server):
        findings.append({
            "check": "server disclosure", "status": "warn",
            "detail": f"server header reveals a version: {server.strip()[:60]}",
        })
    if headers.get("x-powered-by"):
        findings.append({
            "check": "x-powered-by", "status": "warn",
            "detail": f"framework disclosed: {headers['x-powered-by'].strip()[:60]}",
        })
    return findings


def cookie_findings(headers: dict[str, str]) -> list[str]:
    """Report cookies that miss Secure / HttpOnly / SameSite."""
    issues: list[str] = []
    for raw in headers.get("set-cookie", "").split(","):
        raw = raw.strip()
        if not raw or "=" not in raw:
            continue
        try:
            jar = http.cookies.SimpleCookie()
            jar.load(raw)
        except http.cookies.CookieError:
            continue
        for name, morsel in jar.items():
            missing = [
                flag for flag, present in (
                    ("Secure", bool(morsel["secure"])),
                    ("HttpOnly", bool(morsel["httponly"])),
                    ("SameSite", bool(morsel["samesite"])),
                ) if not present
            ]
            if missing:
                issues.append(f"cookie {name!r} is missing {', '.join(missing)}")
    return issues


def tls_probe(host: str, port: int, timeout: float) -> dict:
    """TLS handshake + certificate facts; verification stays enabled."""
    result = {"state": "none", "days_left": None, "subject": None, "issuer": None, "detail": ""}
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
    except ssl.SSLCertVerificationError as exc:
        result["state"] = "invalid"
        result["detail"] = f"certificate verification failed: {str(exc).splitlines()[0][:120]}"
        return result
    except (socket.timeout, OSError) as exc:
        result["state"] = "unreachable"
        result["detail"] = str(exc)[:120]
        return result

    result["state"] = "ok"
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    result["subject"] = subject.get("commonName")
    result["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
    not_after = cert.get("notAfter")
    if not_after:
        seconds = ssl.cert_time_to_seconds(not_after) - time.time()
        result["days_left"] = int(seconds // 86400)
    return result


def fetch_page(url: str, timeout: float, context: ssl.SSLContext) -> dict:
    """GET one URL (redirects followed); HTTP errors still give headers."""
    request = urllib.request.Request(url, headers={"User-Agent": f"{TOOL_NAME}/{TOOL_VERSION}"})
    outcome: dict = {"ok": False, "status": None, "headers": None, "final_url": None, "error": ""}
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            response.read(1024)
            outcome.update(ok=True, status=response.status, headers=response.headers,
                           final_url=response.geturl())
    except urllib.error.HTTPError as exc:
        outcome.update(ok=True, status=exc.code, headers=exc.headers, final_url=exc.geturl())
    except (urllib.error.URLError, OSError, ValueError) as exc:
        outcome["error"] = str(exc)[:160]
    return outcome


def redirect_check(target: dict, timeout: float) -> dict:
    """For HTTPS targets: does plain HTTP forward to HTTPS?"""
    outcome = fetch_page(f"http://{target['host']}/", timeout,
                         unverified_context())
    final = outcome.get("final_url") or ""
    if not outcome["ok"]:
        return {"status": "info", "detail": "no plain-HTTP listener on port 80"}
    if final.startswith("https://"):
        return {"status": "ok", "detail": "http:// redirects to https://"}
    return {"status": "warn", "detail": f"http:// does not redirect to https:// (lands on {final[:60]})"}


def score(findings: list[dict], tls: dict, scheme: str, redirect: dict | None,
          cookie_issues: list[str]) -> tuple[int, str]:
    """Pure scoring -- unit tested; deterministic deductions."""
    total = 100
    for finding in findings:
        if finding["status"] == "missing":
            total -= MISSING_PENALTY
        elif finding["status"] == "warn":
            total -= DISCLOSURE_PENALTY
    if scheme == "https":
        if tls["state"] == "ok":
            if tls["days_left"] is not None and tls["days_left"] < 0:
                total -= EXPIRED_PENALTY
            elif tls["days_left"] is not None and tls["days_left"] < 15:
                total -= SOON_PENALTY
        elif tls["state"] in ("invalid", "unreachable", "none"):
            total -= TLS_PENALTY
        if redirect and redirect["status"] == "warn":
            total -= REDIRECT_PENALTY
    else:
        total -= TLS_PENALTY
    total -= min(COOKIE_PENALTY_CAP, COOKIE_PENALTY * len(cookie_issues))
    total = max(0, min(100, total))
    grade = "F"
    for threshold, letter in GRADE_THRESHOLDS:
        if total >= threshold:
            grade = letter
            break
    return total, grade


def print_line(status: str, message: str) -> None:
    marks = {"ok": "[+]", "missing": "[!]", "warn": "[!]", "fail": "[x]", "info": "[*]"}
    print(f"{marks.get(status, '[*]')} {message}")


def build_report(target: dict, tls: dict, findings: list[dict], cookies: list[str],
                 redirect: dict | None, total: int, grade: str) -> dict:
    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "target": target["display"],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tls": tls,
        "score": total,
        "grade": grade,
        "redirect": redirect,
        "cookie_issues": cookies,
        "findings": findings,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Audit TLS certificate and HTTP security headers, then score the target.",
    )
    parser.add_argument("target", help="URL or host, e.g. example.com or https://host:8443")
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help="TLS / HTTP timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "-f", "--format", choices=("txt", "json"), default="txt",
        help="output format (default: %(default)s)",
    )
    parser.add_argument("-o", "--output", help="write results to this file instead of stdout")
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        target = normalize_target(args.target)
    except ValueError as exc:
        warn(str(exc))
        return 2

    info(f"target: {target['display']} - authorized use only")
    findings: list[dict] = []
    cookies: list[str] = []
    redirect: dict | None = None
    fetch_ctx = ssl.create_default_context()

    if target["scheme"] == "https":
        tls = tls_probe(target["host"], target["port"], args.timeout)
        if tls["state"] == "ok":
            days = tls["days_left"]
            print_line("ok", f"TLS certificate valid ({days} day(s) left, issued by {tls['issuer']})")
            if days is not None and days < 15:
                print_line("warn", f"certificate expires soon: {days} day(s) left")
        else:
            print_line("fail", f"TLS problem: {tls['detail'] or tls['state']}")
        findings.append({"check": "tls", "status": "ok" if tls["state"] == "ok" else "fail",
                         "detail": tls["detail"] or f"{tls['state']} ({tls['days_left']} days)"})
        redirect = redirect_check(target, args.timeout)
        print_line(redirect["status"], f"HTTP->HTTPS redirect: {redirect['detail']}")
        if tls["state"] != "ok":
            fetch_ctx = unverified_context()
    else:
        tls = {"state": "none", "days_left": None, "subject": None, "issuer": None,
               "detail": "plain HTTP"}
        print_line("fail", "plain HTTP - no TLS on this target")

    page = fetch_page(target["display"] + target["path"], args.timeout, fetch_ctx)
    headers = lowercase_headers(page["headers"].items()) if page["headers"] else {}

    if not page["ok"]:
        print_line("fail", f"HTTP request failed: {page['error']}")
        findings.append({"check": "http", "status": "fail", "detail": page["error"]})
        report = build_report(target, tls, findings, cookies, redirect, 0, "F")
    else:
        status = page["status"]
        print_line("ok", f"HTTP {status} response ({len(headers)} header name(s) received)")
        findings.append({"check": "http", "status": "ok", "detail": f"HTTP {status}"})

        findings.extend(evaluate_headers(headers))
        for finding in findings:
            if finding["check"] == "tls" or finding["check"] == "http":
                continue
            if finding["status"] == "ok":
                print_line("ok", f"header {finding['check']}: {finding['detail']}")
            elif finding["status"] == "missing":
                print_line("missing", f"header {finding['check']} missing - {finding['detail']}")
            else:
                print_line("warn", f"{finding['check']}: {finding['detail']}")

        cookies = cookie_findings(headers)
        for issue in cookies:
            print_line("warn", issue)

        total, grade = score(findings, tls, target["scheme"], redirect, cookies)
        print_line("info", f"Web audit score: {total}/100 (grade {grade})")
        report = build_report(target, tls, findings, cookies, redirect, total, grade)

    text = (json.dumps(report, indent=2, sort_keys=True) + "\n") if args.format == "json" else ""
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        info(f"results written to {args.output}")
    elif args.format == "json":
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

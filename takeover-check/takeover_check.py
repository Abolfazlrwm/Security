#!/usr/bin/env python3
"""Detect subdomain takeover opportunities with CNAME + body fingerprints.

For every candidate host the tool resolves the canonical name, matches it
against a table of well-known hosting fingerprints (GitHub Pages, Heroku,
AWS S3, Azure, ...) and, when a CNAME points at such a service, fetches
the site body and looks for the classic "there's nothing here" signature.
A CNAME to an unclaimed service plus a matching 404 body is the textbook
takeover indicator.

Fingerprints are a heuristic: every hit still needs manual verification
before it is reported anywhere. Only the Python standard library is used.

Authorized use only: check hosts you own or have explicit permission to
test.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

TOOL_NAME = "takeover-check"
TOOL_VERSION = "1.0.0"

USER_AGENT = f"{TOOL_NAME}/{TOOL_VERSION} (+https://github.com/Abolfazlrwm/Security)"
BODY_LIMIT = 20480  # read at most 20 KB when hunting for the signature

# cname      -- canonical-name suffix that identifies the hosting service;
# body       -- substrings of the "unclaimed" error page; any hit on the
#               body of a CNAME-matched host means the subdomain is up for
#               grabs (the canonical takeover indicator);
# note       -- extra context printed with the verdict.
FINGERPRINTS = [
    {
        "service": "GitHub Pages",
        "cname": [".github.io"],
        "body": ["there isn't a github pages site here"],
        "note": "create a repo with this name on github.com to test",
    },
    {
        "service": "Heroku",
        "cname": [".herokuapp.com"],
        "body": ["no such app", "there's nothing here, yet"],
        "note": "register the app name at heroku.com",
    },
    {
        "service": "AWS S3",
        "cname": [".s3.amazonaws.com", "s3-website-", ".s3-website"],
        "body": ["nosuchbucket", "the specified bucket does not exist"],
        "note": "create an S3 bucket with this name",
    },
    {
        "service": "Azure Web Apps",
        "cname": [".azurewebsites.net", ".cloudapp.azure.com", ".azurestaticapps.net"],
        "body": ["404 web site not found"],
        "note": "claim the app service slot from the Azure portal",
    },
    {
        "service": "Fastly",
        "cname": [".fastly.net", ".f.ssl.fastly.net"],
        "body": ["fastly error: unknown domain"],
        "note": "add the domain to the Fastly service",
    },
    {
        "service": "Shopify",
        "cname": [".myshopify.com"],
        "body": ["sorry, this shop is currently unavailable"],
        "note": "register the myshopify subdomain",
    },
    {
        "service": "Surge.sh",
        "cname": [".surge.sh"],
        "body": ["project not found"],
        "note": "publish with surge to claim the name",
    },
    {
        "service": "Bitbucket",
        "cname": [".bitbucket.io"],
        "body": ["repository not found"],
        "note": "create the bitbucket repo / enable Pages",
    },
    {
        "service": "Pantheon",
        "cname": [".pantheonsite.io"],
        "body": ["the gods are wise"],
        "note": "claim the pantheon site name",
    },
    {
        "service": "Tumblr",
        "cname": [".domains.tumblr.com", ".tumblr.com"],
        "body": ["whatever you were looking for doesn't currently exist"],
        "note": "register the tumblr blog",
    },
    {
        "service": "Zendesk",
        "cname": [".zendesk.com"],
        "body": ["help center closed", "this help center no longer exists"],
        "note": "register the zendesk subdomain",
    },
    {
        "service": "Teamwork",
        "cname": [".teamwork.com"],
        "body": ["oops - we didn't find your site"],
        "note": "register the teamwork site",
    },
    {
        "service": "Helpjuice",
        "cname": [".helpjuice.com"],
        "body": ["we could not find what you're looking for"],
        "note": "register the helpjuice subdomain",
    },
    {
        "service": "Help Scout Docs",
        "cname": [".helpscoutdocs.com"],
        "body": ["the page you're looking for doesn't exist"],
        "note": "register the docs subdomain",
    },
    {
        "service": "Intercom",
        "cname": [".custom.intercom.help"],
        "body": ["this page is reserved for artistic dogs"],
        "note": "claim the custom help domain",
    },
    {
        "service": "Vercel",
        "cname": [".vercel.app", ".cname.vercel-dns.com"],
        "body": ["the deployment could not be found", "deployment_not_found"],
        "note": "deploy a project and attach the domain",
    },
]

VERDICT_ORDER = ("vulnerable", "unreachable", "claimed", "no-http", "ok", "unresolved", "error")

VERDICT_MARKS = {
    "vulnerable": "[x] VULNERABLE ",
    "unreachable": "[-] UNREACHABLE",
    "claimed": "[~] claimed    ",
    "no-http": "[ ] no-http    ",
    "ok": "[=] ok         ",
    "unresolved": "[?] unresolved ",
    "error": "[!] error      ",
}


def info(message: str) -> None:
    print(f"[*] {message}", file=sys.stderr)


def warn(message: str) -> None:
    print(f"[!] {message}", file=sys.stderr)


def _pattern_matches(value: str, pattern: str) -> bool:
    """'.github.io' matches by suffix, bare patterns like 's3-website' by substring."""
    if pattern.startswith("."):
        return value.endswith(pattern)
    return pattern in value


def match_fingerprint(cname: str | None) -> dict | None:
    """Return the fingerprint whose cname pattern matches the canonical name."""
    if not cname:
        return None
    value = cname.lower().rstrip(".")
    for fingerprint in FINGERPRINTS:
        if any(_pattern_matches(value, suffix) for suffix in fingerprint["cname"]):
            return fingerprint
    return None


def body_matches(body: str, fingerprint: dict) -> list[str]:
    """Signature substrings found in the response body (case-insensitive)."""
    haystack = " ".join((body or "").lower().split())
    return [needle for needle in fingerprint["body"] if needle in haystack]


def any_body_matches(body: str) -> tuple[dict, list[str]] | None:
    """Direct signature hit even without a CNAME fingerprint match."""
    for fingerprint in FINGERPRINTS:
        hits = body_matches(body, fingerprint)
        if hits:
            return fingerprint, hits
    return None


def fetch_body(url: str, timeout: float) -> tuple[bool, str]:
    """GET one URL; returns (reachable, body). HTTP errors count as bodies."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return True, response.read(BODY_LIMIT).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            return True, exc.read(BODY_LIMIT).decode("utf-8", "replace")
        except OSError:
            return True, ""
    except (urllib.error.URLError, OSError, ValueError):
        return False, ""


def classify(
    host: str,
    cname: str | None,
    fingerprint: dict | None,
    reachable: bool,
    body: str,
) -> dict:
    """Pure verdict logic -- unit tested; network output feeds it."""
    result = {"host": host, "cname": cname, "service": None, "verdict": "ok", "evidence": ""}
    if fingerprint:
        result["service"] = fingerprint["service"]
        hits = body_matches(body, fingerprint)
        if reachable and hits:
            result["verdict"] = "vulnerable"
            result["evidence"] = f'matched: "{hits[0]}" ({fingerprint["note"]})'
        elif reachable:
            result["verdict"] = "claimed"
            result["evidence"] = "content served, no takeover signature"
        else:
            result["verdict"] = "unreachable"
            result["evidence"] = f"no HTTP response - verify manually ({fingerprint['note']})"
        return result
    direct = any_body_matches(body) if reachable else None
    if direct:
        service, hits = direct
        result["service"] = service["service"]
        result["verdict"] = "vulnerable"
        result["evidence"] = f"signature without CNAME match: \"{hits[0]}\""
        return result
    if reachable:
        result["verdict"] = "ok"
        result["evidence"] = "no takeover fingerprint"
    else:
        result["verdict"] = "no-http"
        result["evidence"] = "resolves but no HTTP response"
    return result


def check_host(host: str, timeout: float) -> dict:
    """Resolve + HTTP-probe one host and return the full verdict record."""
    host = host.strip().lower().rstrip(".")
    try:
        canonical, _, _ = socket.gethostbyname_ex(host)
    except (socket.gaierror, OSError):
        return {"host": host, "cname": None, "service": None, "verdict": "unresolved",
                "evidence": "DNS lookup failed (check for a dangling CNAME at the DNS provider)"}

    cname = canonical.lower().rstrip(".")
    if cname == host or cname in ("localhost",):
        cname = None

    reachable, body = fetch_body(f"https://{host}/", timeout)
    if not reachable:
        reachable, body = fetch_body(f"http://{host}/", timeout)

    fingerprint = match_fingerprint(cname)
    verdict = classify(host, cname, fingerprint, reachable, body)
    return verdict


def render_line(result: dict) -> str:
    mark = VERDICT_MARKS[result["verdict"]]
    cname = f" (CNAME {result['cname']})" if result.get("cname") else ""
    service = f" -> {result['service']}" if result.get("service") else ""
    return f"{mark} {result['host']}{service}{cname} {result['evidence']}".rstrip()


def load_hosts(raw_hosts: list[str], file_path: str | None) -> list[str]:
    """Collect hosts from argv and/or a file; JSON subdomain reports work too."""
    hosts: list[str] = [h.strip() for h in raw_hosts if h.strip()]
    if file_path:
        text = Path(file_path).read_text(encoding="utf-8")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict) and isinstance(payload.get("subdomains"), list):
            hosts.extend(
                entry["name"] if isinstance(entry, dict) else str(entry)
                for entry in payload["subdomains"]
            )
        else:
            hosts.extend(
                line.strip() for line in text.splitlines()
                if line.strip() and not line.strip().startswith("#")
            )
    # keep order, drop duplicates
    seen: set[str] = set()
    unique = []
    for host in hosts:
        if host not in seen:
            seen.add(host)
            unique.append(host)
    return unique


def build_report(results: list[dict], checked: int) -> dict:
    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "checked": checked,
        "vulnerable": sum(1 for r in results if r["verdict"] == "vulnerable"),
        "unresolved": sum(1 for r in results if r["verdict"] == "unresolved"),
        "results": results,
    }


def write_output(report: dict, output: str | None, as_json: bool) -> None:
    if as_json:
        text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    else:
        text = ""
    if output:
        Path(output).write_text(text, encoding="utf-8")
        info(f"results written to {output}")
    elif as_json:
        sys.stdout.write(text)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Fingerprint subdomain takeover opportunities (CNAME + body signature).",
    )
    parser.add_argument("hosts", nargs="*", help="candidate hosts, e.g. blog.example.com")
    parser.add_argument(
        "-f", "--file", metavar="FILE",
        help="file with one host per line; a subdomain-enum JSON report is accepted too",
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0,
        help="DNS / HTTP timeout per host in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=10,
        help="concurrent HTTP probes (default: %(default)s)",
    )
    parser.add_argument(
        "-F", "--format", choices=("txt", "json"), default="txt",
        help="output format (default: %(default)s)",
    )
    parser.add_argument("-o", "--output", help="write results to this file instead of stdout")
    args = parser.parse_args(argv)

    if not args.hosts and not args.file:
        parser.error("give hosts or --file")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if not 1 <= args.threads <= 100:
        parser.error("--threads must be between 1 and 100")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    hosts = load_hosts(args.hosts, args.file)
    if not hosts:
        warn("no hosts to check")
        return 2

    started = time.monotonic()
    info(f"checking {len(hosts)} host(s) with {args.threads} threads - authorized use only")

    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        for result in pool.map(lambda h: check_host(h, args.timeout), hosts):
            results.append(result)

    for result in results:
        if args.format == "txt":
            print(render_line(result))
        else:
            info(f"{result['verdict']}: {result['host']}")

    report = build_report(results, len(results))
    elapsed = time.monotonic() - started
    write_output(report, args.output, args.format == "json")

    info(
        f"done: {report['vulnerable']} vulnerable, "
        f"{sum(1 for r in results if r['verdict'] in ('claimed', 'no-http'))} claimed/no-http, "
        f"{report['unresolved']} unresolved, {elapsed:.1f}s"
    )
    warn("fingerprints are heuristics - verify a hit manually before reporting anything")
    return 1 if report["vulnerable"] else 0


if __name__ == "__main__":
    sys.exit(main())

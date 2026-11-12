#!/usr/bin/env python3
"""Enumerate subdomains of a target domain.

Two discovery channels are combined:

* passive -- historical certificate names from the crt.sh
  certificate-transparency log search;
* active  -- dictionary based DNS brute force against configurable
  resolvers, executed by a thread pool.

Every candidate name is verified with a live DNS query before it is
reported, so stale certificate entries never reach the main result.
Only the Python standard library is used.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import random
import socket
import string
import struct
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

TOOL_NAME = "subdomain-enum"
TOOL_VERSION = "1.1.0"

CRTSH_ENDPOINT = "https://crt.sh/?q=%25.{domain}&output=json"
CRTSH_RETRIES = 3
DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8"]
DEFAULT_THREADS = 20
DEFAULT_TIMEOUT = 3.0
USER_AGENT = f"{TOOL_NAME}/{TOOL_VERSION} (+https://github.com/Abolfazlrwm/Security)"

# Used when wordlists/subdomains.txt is not shipped next to the script.
BUILTIN_WORDLIST = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ftp", "sftp",
    "ns1", "ns2", "dns", "mx", "mx1", "mx2", "vpn", "remote",
    "portal", "admin", "intranet", "extranet", "api", "app", "apps",
    "mobile", "m", "dev", "test", "stage", "staging", "uat", "qa",
    "demo", "beta", "sandbox", "lab", "internal", "corp", "office",
    "git", "gitlab", "jenkins", "ci", "build", "deploy", "jira",
    "wiki", "docs", "doc", "help", "support", "status", "monitor",
    "grafana", "kibana", "db", "database", "mysql", "postgres",
    "redis", "mongo", "backup", "old", "new", "v1", "v2", "cloud",
    "aws", "azure", "cdn", "static", "assets", "img", "images",
    "media", "files", "download", "upload", "shop", "store", "cart",
    "checkout", "pay", "billing", "account", "auth", "sso", "login",
    "oauth", "id", "profile", "dashboard", "blog", "news", "forum",
    "chat", "relay", "gateway", "proxy", "cache", "edge", "host",
    "server", "web1", "web2", "secure", "ssl", "s3", "storage",
]


def info(message: str) -> None:
    print(f"[*] {message}", file=sys.stderr)


def warn(message: str) -> None:
    print(f"[!] {message}", file=sys.stderr)


def normalize_domain(raw: str) -> str:
    """Accept sloppy input (URLs, ports, trailing dots) and return a bare domain."""
    value = raw.strip().lower()
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0].split(":", 1)[0]
    return value.rstrip(".")


def load_labels(path: str | None) -> list[str]:
    """Load brute-force labels from a file, falling back to the built-in list."""
    if path is None:
        bundled = Path(__file__).resolve().parent / "wordlists" / "subdomains.txt"
        if bundled.exists():
            path = str(bundled)
        else:
            info("no wordlist file found, using the built-in list")
            return list(BUILTIN_WORDLIST)
    labels: list[str] = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            label = line.strip()
            if label and not label.startswith("#"):
                labels.append(label)
    return labels


def query_crtsh(domain: str, timeout: float) -> set[str]:
    """Return subdomain candidates seen in certificate transparency logs."""
    url = CRTSH_ENDPOINT.format(domain=domain)
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    payload = None
    for attempt in range(1, CRTSH_RETRIES + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode("utf-8", "replace"))
            break
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
            warn(f"crt.sh request {attempt}/{CRTSH_RETRIES} failed: {exc}")
            if attempt < CRTSH_RETRIES:
                time.sleep(2 * attempt)
    if payload is None:
        warn("continuing without certificate transparency data")
        return set()
    if not isinstance(payload, list):
        warn("crt.sh returned an unexpected payload; skipping this source")
        return set()

    suffix = "." + domain
    names: set[str] = set()
    for entry in payload:
        raw = entry.get("name_value") or entry.get("common_name") or ""
        for name in str(raw).split("\n"):
            name = name.strip().lower()
            if name.endswith(suffix) and "*" not in name and name != domain:
                names.add(name)
    return names


def dns_resolves(name: str, server: str, timeout: float) -> bool:
    """Send one A-record query and report whether the name exists (NOERROR).

    Only the response header is inspected, so names that exist with CNAME
    or AAAA records only are counted as live as well.
    """
    query_id = random.getrandbits(16)
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    try:
        qname = b"".join(
            bytes([len(label)]) + label.encode() for label in name.split(".")
        ) + b"\x00"
    except (UnicodeEncodeError, ValueError):
        return False
    packet = header + qname + struct.pack(">HH", 1, 1)  # type A, class IN
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (server, 53))
            data, _ = sock.recvfrom(512)
    except (socket.timeout, OSError):
        return False
    if len(data) < 12 or struct.unpack(">H", data[:2])[0] != query_id:
        return False
    return (data[3] & 0x0F) == 0


def resolve_many(names: list[str], servers: list[str], threads: int, timeout: float) -> set[str]:
    """Resolve candidate names concurrently, rotating across the resolvers."""

    def probe(item: tuple[int, str]) -> str | None:
        index, name = item
        server = servers[index % len(servers)]
        return name if dns_resolves(name, server, timeout) else None

    found: set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        for name in pool.map(probe, enumerate(names)):
            if name is not None:
                found.add(name)
    return found


def detect_wildcard(domain: str, servers: list[str], timeout: float) -> bool:
    """Check whether random subdomains resolve, which indicates a wildcard record."""
    probe = "".join(random.choices(string.ascii_lowercase, k=14)) + "." + domain
    if dns_resolves(probe, servers[0], timeout):
        warn("wildcard DNS detected: random names resolve, expect noise in results")
        return True
    return False


def build_report(domain: str, entries: list[dict], wildcard: bool, unverified: int) -> dict:
    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "domain": domain,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "wildcard_dns": wildcard,
        "count": len(entries),
        "unverified_crtsh_names": unverified,
        "subdomains": entries,
    }


def write_output(report: dict, output: str | None, as_json: bool) -> None:
    if as_json:
        text = json.dumps(report, indent=2, sort_keys=True)
    else:
        names = sorted(entry["name"] for entry in report["subdomains"])
        text = "\n".join(names) + ("\n" if names else "")
    if output:
        Path(output).write_text(text, encoding="utf-8")
        info(f"results written to {output}")
    else:
        sys.stdout.write(text)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Enumerate subdomains via crt.sh and DNS brute force.",
    )
    parser.add_argument("domain", help="target domain, e.g. example.com")
    parser.add_argument(
        "-w", "--wordlist",
        help="label wordlist (default: bundled wordlists/subdomains.txt)",
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=DEFAULT_THREADS,
        help="worker threads (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help="DNS and crt.sh timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "-r", "--resolver", action="append", dest="resolvers", metavar="IP",
        help="DNS server to query, repeatable (default: 1.1.1.1, 8.8.8.8)",
    )
    parser.add_argument("--no-crtsh", action="store_true", help="skip the certificate lookup")
    parser.add_argument("--no-brute", action="store_true", help="skip DNS brute force")
    parser.add_argument(
        "-f", "--format", choices=("txt", "json"), default="txt",
        help="output format (default: %(default)s)",
    )
    parser.add_argument("-o", "--output", help="write results to this file instead of stdout")
    args = parser.parse_args(argv)
    args.resolvers = args.resolvers or list(DEFAULT_RESOLVERS)
    if not 1 <= args.threads <= 200:
        parser.error("--threads must be between 1 and 200")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    domain = normalize_domain(args.domain)
    if "." not in domain:
        warn(f"not a valid domain: {args.domain!r}")
        return 2

    started = time.monotonic()
    info(f"target: {domain} (resolvers: {', '.join(args.resolvers)})")

    wildcard = detect_wildcard(domain, args.resolvers, args.timeout)

    crt_names: set[str] = set()
    if not args.no_crtsh:
        info("querying crt.sh certificate transparency logs ...")
        crt_names = query_crtsh(domain, args.timeout)
        info(f"crt.sh contributed {len(crt_names)} candidate names")

    live: set[str] = set()
    if not args.no_brute:
        labels = load_labels(args.wordlist)
        info(f"brute forcing {len(labels)} labels with {args.threads} threads ...")
        candidates = [f"{label}.{domain}" for label in labels]
        live |= resolve_many(candidates, args.resolvers, args.threads, args.timeout)
        info(f"DNS brute force confirmed {len(live)} names")

    # crt.sh entries can be stale, so every certificate name gets a live check too.
    pending = sorted(crt_names - live)
    if pending:
        info(f"verifying {len(pending)} certificate names ...")
        live |= resolve_many(pending, args.resolvers, args.threads, args.timeout)

    entries = [
        {
            "name": name,
            "sources": sorted(["dns"] + (["crt.sh"] if name in crt_names else [])),
        }
        for name in sorted(live)
    ]
    unverified = len(crt_names - live)

    report = build_report(domain, entries, wildcard, unverified)
    write_output(report, args.output, args.format == "json")

    elapsed = time.monotonic() - started
    info(f"done: {len(entries)} live subdomains, {unverified} stale crt.sh entries, {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())

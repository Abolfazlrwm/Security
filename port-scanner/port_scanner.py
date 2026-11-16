#!/usr/bin/env python3
"""Fast TCP port scanner with optional banner grabbing.

Targets are scanned with a connect scan executed by a thread pool; every
open port can be probed for a service banner (first line only). A curated
"top 100" port list covers the ports that are almost always interesting,
while `--ports` accepts arbitrary single ports and ranges.

Authorized use only: scan systems you own or have explicit permission to
test. Only the Python standard library is used.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import socket
import sys
import time
from pathlib import Path

TOOL_NAME = "port-scanner"
TOOL_VERSION = "1.0.0"

DEFAULT_TOP = 100
DEFAULT_TIMEOUT = 1.0
DEFAULT_WORKERS = 200

# Ordered roughly by how often the ports turn out to be open in the wild.
# `--top N` takes the first N entries; the unit tests pin the length at 100.
TOP_PORTS = [
    80, 443, 22, 8080, 8443, 3389, 3306, 21, 25, 8000,
    53, 110, 143, 587, 465, 993, 995, 445, 135, 23,
    1723, 5900, 5432, 5984, 6379, 27017, 9200, 1433, 5000, 3000,
    8888, 9000, 9090, 5601, 11211, 2375, 2376, 6443, 8180, 10000,
    5060, 3128, 1080, 8081, 8008, 9001, 9092, 15672, 61616, 6666,
    6667, 7001, 8009, 8010, 8042, 8069, 8765, 9418, 10050, 10051,
    5555, 5222, 5353, 3690, 4444, 4848, 502, 503, 512, 513,
    514, 515, 548, 554, 631, 636, 646, 994, 992, 990,
    873, 783, 780, 99, 58, 106, 113, 119, 161, 389,
    500, 1720, 1883, 2049, 2082, 2083, 2181, 2222, 2379, 3268,
]

SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    58: "whois", 79: "finger", 80: "http", 81: "http-alt", 88: "kerberos",
    99: "meta-comm", 106: "pop3pw", 110: "pop3", 111: "rpcbind", 113: "ident",
    119: "nntp", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 144: "news",
    161: "snmp", 389: "ldap", 443: "https", 444: "snpp", 445: "microsoft-ds",
    465: "smtps", 500: "isakmp", 502: "modbus", 503: "modbus-plus",
    512: "exec", 513: "login", 514: "syslog", 515: "printer", 548: "afp",
    554: "rtsp", 587: "submission", 631: "ipp", 636: "ldaps",
    780: "wpgs", 783: "spamd", 873: "rsync", 990: "ftps",
    992: "telnets", 993: "imaps", 994: "ircs", 995: "pop3s",
    1080: "socks", 1194: "openvpn", 1720: "h323", 1723: "pptp", 1883: "mqtt",
    2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl", 2181: "zookeeper",
    2222: "ssh-alt", 2375: "docker", 2376: "docker-tls", 2379: "etcd",
    3000: "http-dev", 3128: "squid", 3268: "ldap-gc", 3306: "mysql",
    3389: "ms-wbt", 3690: "svn", 4444: "metasploit", 4848: "glassfish",
    5000: "http-upnp", 5060: "sip", 5061: "sip-tls", 5222: "xmpp",
    5353: "mdns", 5432: "postgresql", 5555: "adb", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 5984: "couchdb", 6000: "x11", 6379: "redis",
    6443: "kubernetes", 6666: "irc", 6667: "irc", 7001: "weblogic",
    8000: "http-alt", 8008: "http-alt", 8009: "ajp", 8010: "http-alt",
    8042: "http-alt", 8069: "odoo", 8080: "http-proxy", 8081: "http-alt",
    8180: "http-alt", 8443: "https-alt", 8500: "consul", 8765: "http-alt",
    8888: "http-alt", 9000: "http-alt", 9001: "tor-orport", 9090: "http-alt",
    9092: "kafka", 9200: "elasticsearch", 9300: "es-transport",
    9418: "git", 9443: "https-alt", 10000: "webmin", 10050: "zabbix-agent",
    10051: "zabbix-trapper", 11211: "memcached", 15672: "rabbitmq-mgmt",
    27017: "mongodb", 28017: "mongodb-web", 61616: "activemq",
}


def info(message: str) -> None:
    print(f"[*] {message}", file=sys.stderr)


def warn(message: str) -> None:
    print(f"[!] {message}", file=sys.stderr)


def parse_ports(spec: str) -> list[int]:
    """Parse a '22,80,443,8000-8100' style spec into a sorted port list."""
    ports: set[int] = set()
    for chunk in spec.replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            low, _, high = chunk.partition("-")
            try:
                lo, hi = int(low), int(high)
            except ValueError:
                raise ValueError(f"invalid port range: {chunk!r}") from None
            if not 1 <= lo <= hi <= 65535:
                raise ValueError(f"port range out of bounds: {chunk!r}")
            ports.update(range(lo, hi + 1))
        else:
            try:
                port = int(chunk)
            except ValueError:
                raise ValueError(f"invalid port: {chunk!r}") from None
            if not 1 <= port <= 65535:
                raise ValueError(f"port out of range: {chunk!r}")
            ports.add(port)
    if not ports:
        raise ValueError("no ports given")
    return sorted(ports)


def service_name(port: int) -> str:
    return SERVICE_MAP.get(port, "unknown")


def trim_banner(banner: str, limit: int = 56) -> str:
    """First line of the banner, printable and capped for the table."""
    stripped = (banner or "").strip()
    if not stripped:
        return ""
    first = stripped.splitlines()[0]
    cleaned = "".join(ch if ch.isprintable() else " " for ch in first).strip()
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 3].rstrip() + "..."
    return cleaned


def probe(host: str, port: int, timeout: float, grab_banner: bool) -> tuple[int, bool, str]:
    """One connect scan; returns (port, is_open, banner)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = ""
            if grab_banner:
                sock.settimeout(timeout)
                try:
                    banner = sock.recv(256).decode("utf-8", "replace").strip()
                except (socket.timeout, OSError):
                    pass
            return port, True, banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return port, False, ""


def scan(
    host: str,
    ports: list[int],
    workers: int,
    timeout: float,
    grab_banner: bool,
) -> list[dict]:
    """Thread-pool connect scan; returns open ports sorted by number."""
    open_ports: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(probe, host, port, timeout, grab_banner) for port in ports]
        for future in concurrent.futures.as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                open_ports.append({
                    "port": port,
                    "state": "open",
                    "service": service_name(port),
                    "banner": banner,
                })
    return sorted(open_ports, key=lambda entry: entry["port"])


def build_report(target: str, ip: str, open_ports: list[dict], scanned: int) -> dict:
    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "target": target,
        "ip": ip,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scanned": scanned,
        "open_count": len(open_ports),
        "ports": open_ports,
    }


def render_table(target: str, ip: str, open_ports: list[dict], scanned: int) -> str:
    lines = [
        f"target {target} ({ip}) - {scanned} ports scanned",
        "",
        f"{'PORT':<10}{'STATE':<8}{'SERVICE':<16}BANNER",
    ]
    if not open_ports:
        lines.append("-" * 46)
        lines.append("(no open ports)")
    for entry in open_ports:
        banner = trim_banner(entry["banner"]) or "(no banner)"
        lines.append(
            f"{str(entry['port']) + '/tcp':<10}{'open':<8}{entry['service']:<16}{banner}"
        )
    lines.append("")
    lines.append(f"{len(open_ports)} open of {scanned} scanned")
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
        description="Fast TCP connect scan with banner grabbing (stdlib only).",
    )
    parser.add_argument("target", help="host or IP to scan, e.g. scanme.nmap.org")
    ports_group = parser.add_mutually_exclusive_group()
    ports_group.add_argument(
        "--ports",
        help="explicit port spec, e.g. '22,80,443,8000-8100'",
    )
    ports_group.add_argument(
        "--top", type=int, default=DEFAULT_TOP,
        help="scan the top N ports of the curated list (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help="connect timeout per port in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--workers", type=int, default=DEFAULT_WORKERS,
        help="concurrent connections (default: %(default)s)",
    )
    parser.add_argument("--no-banner", action="store_true", help="skip banner grabbing")
    parser.add_argument(
        "-f", "--format", choices=("txt", "json"), default="txt",
        help="output format (default: %(default)s)",
    )
    parser.add_argument("-o", "--output", help="write results to this file instead of stdout")
    args = parser.parse_args(argv)

    if not 1 <= args.top <= len(TOP_PORTS):
        parser.error(f"--top must be between 1 and {len(TOP_PORTS)}")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if not 1 <= args.workers <= 500:
        parser.error("--workers must be between 1 and 500")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    target = args.target.strip().lower()
    try:
        ip = socket.gethostbyname(target)
    except (socket.gaierror, OSError):
        warn(f"cannot resolve target: {args.target!r}")
        return 2

    if args.ports:
        try:
            ports = parse_ports(args.ports)
        except ValueError as exc:
            warn(str(exc))
            return 2
        scanned_label = f"{len(ports)} ports from spec"
    else:
        ports = TOP_PORTS[: args.top]
        scanned_label = f"top {len(ports)} ports"

    started = time.monotonic()
    info(f"target: {target} ({ip}) - authorized use only, scan what you own")
    info(f"scanning {scanned_label} with {args.workers} workers, {args.timeout}s timeout")

    open_ports = scan(target, ports, args.workers, args.timeout, not args.no_banner)
    elapsed = time.monotonic() - started
    info(f"done: {len(open_ports)} open of {len(ports)} scanned in {elapsed:.1f}s")

    if args.format == "json":
        report = build_report(target, ip, open_ports, len(ports))
        write_output(json.dumps(report, indent=2, sort_keys=True) + "\n", args.output)
    else:
        write_output(render_table(target, ip, open_ports, len(ports)), args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())

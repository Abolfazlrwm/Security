#!/usr/bin/env python3
"""Recon pipeline that chains the repo tools and writes a consolidated report.

Phases:

1. subdomain enumeration  -- shells out to subdomain-enum (JSON output);
2. directory brute force  -- runs the compiled dirbrute binary (or
   `go run .` when the Go toolchain is available) against the base URL
   and the discovered hosts;
3. reporting              -- writes report.html, report.md + report.json
   plus the raw tool logs into reports/<target>-<timestamp>/.

Only the Python standard library is used.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

TOOL_NAME = "recon-pipeline"
TOOL_VERSION = "1.2.0"

REPO_ROOT = Path(__file__).resolve().parent.parent
SUBDOMAIN_SCRIPT = REPO_ROOT / "subdomain-enum" / "subdomain_enum.py"
DIRBRUTE_DIR = REPO_ROOT / "dirbrute"

DIRBRUTE_LINE = re.compile(r"^(?P<path>\S+) \(Status: (?P<status>\d{3})\) \[Size: (?P<size>\d+)\]$")


def info(message: str) -> None:
    print(f"[*] {message}", file=sys.stderr)


def warn(message: str) -> None:
    print(f"[!] {message}", file=sys.stderr)


def normalize_domain(raw: str) -> str:
    value = raw.strip().lower()
    if "://" in value:
        value = value.split("://", 1)[1]
    return value.split("/", 1)[0].split(":", 1)[0].rstrip(".")


def run_command(command: list[str], cwd: Path | None = None, timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def locate_dirbrute() -> list[str] | None:
    """Find the dirbrute binary, or fall back to `go run` when Go exists."""
    for name in ("dirbrute", "dirbrute.exe"):
        binary = DIRBRUTE_DIR / name
        if binary.is_file():
            return [str(binary)]
    go_binary = shutil.which("go")
    if go_binary:
        return [go_binary, "run", "."]
    return None


def run_subdomain_phase(args: argparse.Namespace, workdir: Path) -> dict:
    """Run subdomain-enum and return the parsed JSON report (or a skip record)."""
    if args.hosts:
        return {"ran": False, "reason": "host list provided via --hosts", "count": 0, "subdomains": []}

    output = workdir / "subdomains.json"
    command = [
        sys.executable, str(SUBDOMAIN_SCRIPT), args.domain,
        "--format", "json", "--output", str(output), "--threads", str(args.threads),
    ]
    if args.no_crtsh:
        command.append("--no-crtsh")
    if args.no_brute:
        command.append("--no-brute")
    if args.wordlist:
        command += ["--wordlist", args.wordlist]

    info("phase 1/2: subdomain enumeration ...")
    try:
        proc = run_command(command, timeout=args.phase_timeout)
    except (subprocess.TimeoutExpired, OSError) as exc:
        warn(f"subdomain-enum failed: {exc}")
        return {"ran": True, "error": str(exc), "count": 0, "subdomains": []}

    (workdir / "subdomain-enum.log").write_text(proc.stderr or "", encoding="utf-8")
    if proc.returncode != 0:
        warn(f"subdomain-enum exited with code {proc.returncode}")
        return {"ran": True, "error": proc.stderr[-400:], "count": 0, "subdomains": []}

    data = json.loads(output.read_text(encoding="utf-8")) if output.exists() else {}
    subdomains = data.get("subdomains", [])
    info(f"phase 1 done: {len(subdomains)} live subdomains")
    return {
        "ran": True,
        "count": len(subdomains),
        "subdomains": subdomains,
        "wildcard_dns": data.get("wildcard_dns", False),
        "unverified_crtsh_names": data.get("unverified_crtsh_names", 0),
    }


def parse_dirbrute_output(stdout: str) -> list[dict]:
    findings = []
    for line in stdout.splitlines():
        match = DIRBRUTE_LINE.match(line.strip())
        if match:
            findings.append({
                "path": match.group("path"),
                "status": int(match.group("status")),
                "size": int(match.group("size")),
            })
    return findings


def run_dirbrute_phase(args: argparse.Namespace, hosts: list[str], workdir: Path) -> dict:
    """Brute force directories on every host with the dirbrute Go binary."""
    if args.skip_dirbrute:
        return {"ran": False, "reason": "disabled with --skip-dirbrute", "hosts": {}}

    command_prefix = locate_dirbrute()
    if command_prefix is None:
        warn("dirbrute binary not found and no Go toolchain in PATH; build it first: make build")
        return {"ran": False, "reason": "dirbrute binary missing (run: make build)", "hosts": {}}

    wordlist = args.dirbrute_wordlist or str(DIRBRUTE_DIR / "wordlists" / "common.txt")
    cwd = DIRBRUTE_DIR if command_prefix[0].endswith(("go", "go.exe")) else None
    results: dict[str, dict] = {}
    base_url = args.url.rstrip("/")

    info(f"phase 2/2: directory brute force on {len(hosts)} host(s) ...")
    for index, host in enumerate(hosts, start=1):
        url = base_url if index == 1 else f"{args.scheme}://{host}"
        command = command_prefix + [
            "-u", url, "-w", wordlist, "-t", str(args.threads), "-q",
        ]
        info(f"  scanning {url}")
        try:
            proc = run_command(command, cwd=cwd, timeout=args.phase_timeout)
        except (subprocess.TimeoutExpired, OSError) as exc:
            warn(f"dirbrute failed for {url}: {exc}")
            results[url] = {"count": 0, "findings": [], "error": str(exc)}
            continue

        (workdir / f"dirbrute-{index:02d}.log").write_text(
            f"$ {' '.join(command)}\n\n{proc.stderr}\n{proc.stdout}", encoding="utf-8"
        )
        findings = parse_dirbrute_output(proc.stdout)
        info(f"  {len(findings)} findings on {url}")
        results[url] = {"count": len(findings), "findings": findings, "returncode": proc.returncode}

    return {"ran": True, "hosts": results}


def collect_hosts(args: argparse.Namespace, subdomain_phase: dict) -> list[str]:
    if args.hosts:
        return [normalize_domain(item) for item in args.hosts.split(",") if item.strip()]
    names = [entry["name"] for entry in subdomain_phase.get("subdomains", [])]
    if not names:
        names = []
    if args.domain not in names:
        names.insert(0, args.domain)
    return names[: args.max_hosts]


def render_markdown(report: dict) -> str:
    lines = [
        f"# Recon report - {report['target']}",
        "",
        f"- Generated: {report['generated_at']}",
        f"- Base URL: {report['base_url']}",
        f"- Tools: {report['tools']}",
        "",
    ]

    subs = report["phases"]["subdomains"]
    lines.append(f"## Subdomains ({subs.get('count', 0)})")
    if subs.get("subdomains"):
        lines += ["", "| Subdomain | Sources |", "| --- | --- |"]
        for entry in subs["subdomains"]:
            lines.append(f"| {entry['name']} | {', '.join(entry.get('sources', ['dns']))} |")
        if subs.get("wildcard_dns"):
            lines += ["", "_Wildcard DNS detected - treat results with care._"]
    else:
        lines += ["", f"_No live subdomains found ({subs.get('reason', 'none detected')})._"]

    scan = report["phases"]["dirbrute"]
    lines += ["", "## Directory scan"]
    if not scan.get("ran"):
        lines += ["", f"_Skipped: {scan.get('reason', 'disabled')}._"]
    else:
        for url, data in scan.get("hosts", {}).items():
            lines += ["", f"### {url} ({data.get('count', 0)} findings)"]
            if data.get("findings"):
                lines += ["", "| Path | Status | Size |", "| --- | --- | --- |"]
                for item in data["findings"]:
                    lines.append(f"| {item['path']} | {item['status']} | {item['size']} |")
            elif data.get("error"):
                lines += ["", f"_Scan error: {data['error']}._"]
            else:
                lines += ["", "_No findings._"]

    return "\n".join(lines) + "\n"


HTML_CSS = """
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0d1117;color:#e6edf3;font:15px/1.6 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:960px;margin:0 auto;padding:34px 20px 48px}
header h1{margin:0 0 6px;font-size:26px}
header .meta{color:#8b949e;font-size:13px}
h2{font-size:19px;margin:26px 0 10px}
.stats{display:flex;gap:12px;margin:22px 0 6px;flex-wrap:wrap}
.stat{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:12px 20px;min-width:140px}
.stat-num{display:block;font-size:26px;font-weight:700;color:#58a6ff}
.stat.accent .stat-num{color:#3fb950}
.stat-label{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#8b949e}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px 20px;margin:0 0 16px}
.card p{margin:0 0 8px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #21262d}
th{color:#8b949e;font-size:12px;text-transform:uppercase;letter-spacing:.05em}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
tr:hover td{background:#1c2128}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;color:#79c0ff;background:#0d1117;padding:1px 6px;border-radius:5px;border:1px solid #21262d}
.src{display:inline-block;background:#21262d;border:1px solid #30363d;border-radius:999px;padding:1px 9px;margin:1px 3px 1px 0;font-size:11px;color:#a5b1bd}
.pill{display:inline-block;border-radius:999px;padding:1px 9px;font-size:12px;font-weight:700}
.pill.ok{background:#0f2e1c;color:#3fb950;border:1px solid #1d4428}
.pill.redir{background:#0c2d6b;color:#58a6ff;border:1px solid #1a4485}
.pill.auth{background:#33250c;color:#d29922;border:1px solid #5a4215}
.pill.danger{background:#3d1119;color:#f85149;border:1px solid #67262f}
.pill.info{background:#21262d;color:#8b949e;border:1px solid #30363d}
.muted{color:#8b949e}
.warn{color:#d29922;font-size:13px}
footer{margin-top:28px;color:#8b949e;font-size:12px;border-top:1px solid #21262d;padding-top:14px}
footer a{color:#58a6ff;text-decoration:none}
"""


def status_class(status: int) -> str:
    """CSS class for the HTTP status pill in the HTML report."""
    if 200 <= status < 300:
        return "ok"
    if 300 <= status < 400:
        return "redir"
    if status in (401, 403):
        return "auth"
    if status >= 400:
        return "danger"
    return "info"


def render_html(report: dict) -> str:
    """Render a self-contained, dark-themed HTML report.

    Styles are inlined and no external asset is referenced, so the file
    renders offline and never contacts a third-party host when opened.
    """
    esc = html.escape
    summary = report.get("summary", {})
    subs = report["phases"]["subdomains"]
    scan = report["phases"]["dirbrute"]

    def stat(label: str, value: object, accent: bool = False) -> str:
        cls = " accent" if accent else ""
        return (f'<div class="stat{cls}"><span class="stat-num">{value}</span>'
                f'<span class="stat-label">{esc(label)}</span></div>')

    stats = (
        stat("subdomains", summary.get("subdomains", 0))
        + stat("hosts scanned", summary.get("hosts_scanned", 0))
        + stat("findings", summary.get("findings", 0), accent=True)
    )

    rows = []
    for entry in subs.get("subdomains", []):
        sources = "".join(
            f'<span class="src">{esc(s)}</span>' for s in entry.get("sources", ["dns"])
        )
        rows.append(f"<tr><td><code>{esc(entry['name'])}</code></td><td>{sources}</td></tr>")
    sub_body = "".join(rows) or '<tr><td colspan="2" class="muted">no live subdomains found</td></tr>'
    wildcard = (
        '<p class="warn">Wildcard DNS detected - treat results with care.</p>'
        if subs.get("wildcard_dns") else ""
    )

    if not scan.get("ran"):
        scan_html = (
            '<div class="card"><p class="muted">Directory scan skipped: '
            f'{esc(scan.get("reason", "disabled"))}.</p></div>'
        )
    else:
        blocks = []
        for url, data in scan.get("hosts", {}).items():
            rows = []
            for item in data.get("findings", []):
                rows.append(
                    f'<tr><td><code>{esc(item["path"])}</code></td>'
                    f'<td><span class="pill {status_class(item["status"])}">{item["status"]}</span></td>'
                    f'<td class="num">{item["size"]:,}</td></tr>'
                )
            body = "".join(rows)
            if data.get("error"):
                body = f'<tr><td colspan="3" class="muted">scan error: {esc(data["error"])}</td></tr>'
            elif not body:
                body = '<tr><td colspan="3" class="muted">no findings</td></tr>'
            blocks.append(
                f'<div class="card"><h3>{esc(url)}</h3>'
                f'<p class="muted">{data.get("count", 0)} findings</p>'
                f'<table><thead><tr><th>Path</th><th>Status</th><th class="num">Size (B)</th></tr></thead>'
                f"<tbody>{body}</tbody></table></div>"
            )
        scan_html = "".join(blocks)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Recon report - {esc(str(report["target"]))}</title>
<style>{HTML_CSS}</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>Recon report - {esc(str(report["target"]))}</h1>
  <div class="meta">generated {esc(report["generated_at"])} &middot; base URL {esc(str(report["base_url"]))} &middot; {esc(report["tools"])}</div>
</header>
<div class="stats">{stats}</div>

<h2>Subdomains ({subs.get("count", 0)})</h2>
<div class="card">
  <table>
    <thead><tr><th>Subdomain</th><th>Sources</th></tr></thead>
    <tbody>{sub_body}</tbody>
  </table>
  {wildcard}
</div>

<h2>Directory scan</h2>
{scan_html}

<footer>generated by <a href="https://github.com/Abolfazlrwm/Security">recon-pipeline {esc(report["version"])}</a> &middot; authorized testing only</footer>
</div>
</body>
</html>
"""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Chain subdomain-enum and dirbrute, then write a recon report.",
    )
    parser.add_argument("--domain", help="target domain, e.g. example.com")
    parser.add_argument("--url", help="base URL for the primary directory scan (default: https://<domain>)")
    parser.add_argument("--hosts", help="comma separated host list; skips the subdomain phase")
    parser.add_argument("--scheme", choices=("http", "https"), default="https", help="scheme for discovered hosts (default: %(default)s)")
    parser.add_argument("-t", "--threads", type=int, default=20, help="worker threads for both tools (default: %(default)s)")
    parser.add_argument("--max-hosts", type=int, default=8, help="limit how many discovered hosts get scanned (default: %(default)s)")
    parser.add_argument("--output-dir", default="reports", help="directory for reports (default: %(default)s)")
    parser.add_argument("--no-crtsh", action="store_true", help="pass --no-crtsh to subdomain-enum")
    parser.add_argument("--no-brute", action="store_true", help="pass --no-brute to subdomain-enum")
    parser.add_argument("--wordlist", help="wordlist for the subdomain brute force")
    parser.add_argument("--dirbrute-wordlist", help="wordlist override for dirbrute")
    parser.add_argument("--skip-dirbrute", action="store_true", help="only run the subdomain phase")
    parser.add_argument("--phase-timeout", type=int, default=600, help="per-phase timeout in seconds (default: %(default)s)")
    args = parser.parse_args(argv)

    if not args.domain and not args.hosts:
        parser.error("give --domain or --hosts")
    if args.domain:
        args.domain = normalize_domain(args.domain)
        if "." not in args.domain:
            parser.error(f"not a valid domain: {args.domain}")
    args.url = args.url or (f"https://{args.domain}" if args.domain else None)
    if not args.url:
        parser.error("no scan target: pass --domain or --url")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    started = time.monotonic()

    stamp = time.strftime("%Y%m%d-%H%M%S")
    label = re.sub(r"[^a-z0-9.-]+", "-", args.domain or args.url).strip("-") or "target"
    workdir = Path(args.output_dir) / f"{label}-{stamp}"
    workdir.mkdir(parents=True, exist_ok=True)
    info(f"work directory: {workdir}")

    subdomain_phase = run_subdomain_phase(args, workdir)
    hosts = collect_hosts(args, subdomain_phase)
    dirbrute_phase = run_dirbrute_phase(args, hosts, workdir)

    findings_total = sum(data.get("count", 0) for data in dirbrute_phase.get("hosts", {}).values())
    report = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "target": args.domain or args.url,
        "base_url": args.url,
        "generated_at": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        "tools": f"subdomain-enum + dirbrute (pipeline {TOOL_VERSION})",
        "phases": {
            "subdomains": subdomain_phase,
            "dirbrute": dirbrute_phase,
        },
        "summary": {
            "subdomains": subdomain_phase.get("count", 0),
            "hosts_scanned": len(dirbrute_phase.get("hosts", {})),
            "findings": findings_total,
        },
    }

    (workdir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (workdir / "report.md").write_text(render_markdown(report), encoding="utf-8")
    (workdir / "report.html").write_text(render_html(report), encoding="utf-8")

    elapsed = time.monotonic() - started
    info(f"report written to {workdir / 'report.html'} (+ report.md, report.json) ({elapsed:.1f}s total)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Self-contained integration test for the Security toolkit.

Runs the network-free code paths end to end:

* hashcrack      - plain lookup, rule chain, salted digests and the
                   built-in wordlist fallback
* dirbrute       - a full scan against an in-process demo webserver
* port-scanner   - a live scan of the demo webserver port (open + closed)
* web-audit      - a header/score audit of the demo webserver over http
* recon-pipeline - a --hosts run that chains the built binary and also
                   verifies the self-contained HTML report

subdomain-enum and takeover-check are exercised only through their --help
pages because a real run needs live DNS and third-party HTTP access,
which CI must not depend on.

Exit code 0 means every assertion passed. Standard library only.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DIRBRUTE_DIR = REPO_ROOT / "dirbrute"
DIRBRUTE_BIN = DIRBRUTE_DIR / "dirbrute"

failures: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    suffix = f" ({detail})" if detail and not condition else ""
    print(f"[{status}] {name}{suffix}", flush=True)
    if not condition:
        failures.append(name)


def build_docroot(root: Path) -> None:
    """Same layout as the demo server captured in examples/."""
    files = {
        "robots.txt": "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /api/\n",
        "sitemap.xml": (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
            "  <url><loc>http://localhost/</loc></url>\n"
            "  <url><loc>http://localhost/blog/</loc></url>\n"
            "</urlset>\n"
        ),
        ".env": (
            "APP_NAME=demoapp\nAPP_KEY=base64:REDACTED-demoo-key-value==\n"
            "DB_HOST=127.0.0.1\nDB_PORT=3306\nDB_USER=demo\nDB_PASSWORD=redacted\n"
        ),
        ".git/config": (
            "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
            '[remote "origin"]\n\turl = git@github.com:demo/demo.git\n'
        ),
        ".git/HEAD": "ref: refs/heads/main\n",
        "admin/login.php": (
            '<!doctype html><html><head><title>Admin login</title></head><body>'
            '<form method="post"><input name="user">'
            '<input name="pass" type="password"><button>Sign in</button>'
            "</form></body></html>"
        ),
        "api/v1/status.json": '{"status": "ok", "version": "1.4.2"}\n',
        "uploads/note.txt": "internal upload area - nothing to see here\n",
        "phpinfo.php": "<?php\n// demo stub\nphpinfo();\n",
        "server-status": "Apache Server Status for 127.0.0.1 (Demo)\nUptime: 3 days\n",
        "index.html": (
            "<!doctype html><html><head><title>demo site</title></head>"
            "<body><h1>demo site</h1></body></html>"
        ),
    }
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    with zipfile.ZipFile(root / "backup.zip", "w") as archive:
        archive.writestr("db.sql", "-- demo dump\nCREATE TABLE users (id INT);\n")


class DemoHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(kwargs.pop("docroot")), **kwargs)

    def log_message(self, fmt, *args):  # keep CI logs tidy
        pass


def start_server(docroot: Path) -> tuple[http.server.ThreadingHTTPServer, int]:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", port), lambda *a, **kw: DemoHandler(*a, docroot=docroot, **kw)
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, port


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(
        command, capture_output=True, text=True, timeout=180, **kwargs
    )


def ensure_binary() -> None:
    if DIRBRUTE_BIN.is_file():
        return
    print("[*] building dirbrute with the local Go toolchain ...", flush=True)
    proc = run(["go", "build", "-o", str(DIRBRUTE_BIN), "."], cwd=str(DIRBRUTE_DIR))
    if proc.returncode != 0:
        sys.exit(f"error: go build failed:\n{proc.stderr}")


def test_hashcrack() -> None:
    print("\n== hashcrack ==", flush=True)
    script = REPO_ROOT / "hashcrack" / "hashcrack.py"

    plain_md5 = hashlib.md5(b"password123").hexdigest()
    sha1 = hashlib.sha1(b"qwerty").hexdigest()
    sha256 = hashlib.sha256(b"abc123").hexdigest()
    sha512 = hashlib.sha512(b"password123").hexdigest()
    rules_md5 = hashlib.md5(b"Password2024").hexdigest()
    salt_md5 = hashlib.md5(b"salt123admin").hexdigest()

    hashes_file = REPO_ROOT / "hashcrack" / "test-targets.tmp"
    hashes_file.write_text(
        f"{plain_md5}\n{sha1}\n{sha256}\n{sha512}\n"
        f"# needs the rule engine\n{rules_md5}\n",
        encoding="utf-8",
    )
    proc = run([sys.executable, str(script), "--hashes", str(hashes_file)])
    hashes_file.unlink(missing_ok=True)
    check("plain lookup cracks password123/qwerty/abc123",
          all(f"-> {w}" in proc.stdout for w in ("password123", "qwerty", "abc123")))
    check("uncracked targets exit non-zero", proc.returncode == 1)

    proc = run([sys.executable, str(script), "--hash", rules_md5,
                "--rules", "capitalize,append4"])
    check("rule chain cracks Password2024",
          proc.returncode == 0 and "-> Password2024" in proc.stdout)

    proc = run([sys.executable, str(script), "--hash", salt_md5,
                "--salt", "salt123", "--salt-position", "prefix"])
    check("prefix salt cracks salt123admin",
          proc.returncode == 0 and "-> salt123admin" in proc.stdout)

    driver = (
        "import sys; sys.path.insert(0, r'%s')\n"
        "import hashcrack\n"
        "from pathlib import Path\n"
        "hashcrack.DEFAULT_WORDLIST = Path('does-not-exist.txt')\n"
        "sys.exit(hashcrack.main(['--hash', '21232f297a57a5a743894a0e4a801fc3']))\n"
        % str(REPO_ROOT / "hashcrack")
    )
    proc = run([sys.executable, "-c", driver])
    check("built-in wordlist fallback cracks 'admin' with no wordlist file",
          proc.returncode == 0 and "-> admin" in proc.stdout
          and "built-in list" in proc.stderr, proc.stderr[-160:])


def test_dirbrute(port: int) -> None:
    print("\n== dirbrute ==", flush=True)
    proc = run([str(DIRBRUTE_BIN), "-u", f"http://127.0.0.1:{port}/", "-t", "10"])
    expected = (".env", ".git/config", ".git/HEAD", "admin", "api", "api/v1",
                "backup.zip", "index.html", "phpinfo.php", "robots.txt",
                "server-status", "sitemap.xml", "uploads")
    missing = [p for p in expected if p not in proc.stdout]
    check(f"finds all {len(expected)} seeded paths", not missing,
          f"missing: {missing}")
    check("exactly 13 findings reported",
          proc.stdout.count("(Status:") == 13
          or "13 findings" in proc.stderr, proc.stderr[-120:])
    check("wordlist entries that return 404 are filtered",
          "wp-admin" not in proc.stdout and "phpmyadmin" not in proc.stdout)


def test_pipeline(port: int, workdir: Path) -> None:
    print("\n== recon-pipeline ==", flush=True)
    proc = run([sys.executable, str(REPO_ROOT / "recon-pipeline" / "recon.py"),
                "--hosts", "127.0.0.1", "--url", f"http://127.0.0.1:{port}",
                "--scheme", "http", "--output-dir", str(workdir)])
    reports = list(workdir.glob("**/report.md"))
    check("pipeline exits zero and writes report.md",
          proc.returncode == 0 and len(reports) == 1, proc.stderr[-160:])
    if reports:
        report = reports[0].read_text(encoding="utf-8")
        check("report lists 13 findings", "(13 findings)" in report)
        check("report records skipped subdomain phase",
              "host list provided via --hosts" in report)
        check("report contains the new port scan and web audit sections",
              "## Port scan" in report and "## Web audit" in report
              and "grade F" in report)
        data = json.loads(reports[0].with_name("report.json").read_text())
        check("report.json carries version and findings",
              data.get("version") == "1.3.0" and data["summary"]["findings"] == 13
              and "open_ports" in data["summary"])

        html_report = reports[0].with_name("report.html")
        if html_report.exists():
            page = html_report.read_text(encoding="utf-8")
            check("report.html renders the findings with status pills",
                  '<code>.env</code>' in page and 'class="pill ok"' in page)
            check("report.html embeds the new sections",
                  "<h2>Port scan</h2>" in page and "<h2>Web audit</h2>" in page)
            check("report.html is self-contained (no external assets)",
                  "<script" not in page and "<link" not in page
                  and "cdn." not in page and "recon-pipeline 1.3.0" in page)
        else:
            check("report.html exists", False)


def test_help_pages() -> None:
    print("\n== CLI help pages ==", flush=True)
    proc = run([sys.executable, str(REPO_ROOT / "subdomain-enum" / "subdomain_enum.py"),
                "--help"])
    check("subdomain-enum --help exits zero",
          proc.returncode == 0 and "--no-crtsh" in proc.stdout)
    proc = run([sys.executable, str(REPO_ROOT / "takeover-check" / "takeover_check.py"),
                "--help"])
    check("takeover-check --help exits zero",
          proc.returncode == 0 and "--file" in proc.stdout)
    proc = run([sys.executable, str(REPO_ROOT / "port-scanner" / "port_scanner.py"),
                "--help"])
    check("port-scanner --help exits zero",
          proc.returncode == 0 and "--no-banner" in proc.stdout)
    proc = run([sys.executable, str(REPO_ROOT / "web-audit" / "web_audit.py"), "--help"])
    check("web-audit --help exits zero",
          proc.returncode == 0 and "--format" in proc.stdout)
    proc = run([sys.executable, str(REPO_ROOT / "recon-pipeline" / "recon.py"), "--help"])
    check("recon-pipeline --help exits zero",
          proc.returncode == 0 and "--skip-ports" in proc.stdout)


def test_port_scanner(port: int) -> None:
    print("\n== port-scanner ==", flush=True)
    script = REPO_ROOT / "port-scanner" / "port_scanner.py"
    proc = run([sys.executable, str(script), "127.0.0.1",
                "--ports", str(port), "--timeout", "1"])
    check("finds the demo webserver port open",
          proc.returncode == 0 and f"{port}/tcp" in proc.stdout
          and "1 open of 1 scanned" in proc.stdout,
          proc.stdout[-160:])
    closed = port + 1
    proc = run([sys.executable, str(script), "127.0.0.1",
                "--ports", str(closed), "--timeout", "1"])
    check("closed port is reported as no open ports",
          proc.returncode == 0 and "0 open of 1 scanned" in proc.stdout, proc.stdout[-120:])
    with tempfile.TemporaryDirectory(prefix="ps-json") as tmp:
        output = Path(tmp) / "scan.json"
        proc = run([sys.executable, str(script), "127.0.0.1",
                    "--ports", str(port), "--format", "json", "--output", str(output)])
        data = json.loads(output.read_text()) if output.exists() else {}
        check("json report carries the open port",
              data.get("open_count") == 1 and data["ports"][0]["port"] == port
              and data.get("ip"),)


def test_web_audit(port: int) -> None:
    print("\n== web-audit ==", flush=True)
    script = REPO_ROOT / "web-audit" / "web_audit.py"
    proc = run([sys.executable, str(script), f"http://127.0.0.1:{port}"])
    check("plain HTTP target is flagged", proc.returncode == 0 and "plain HTTP" in proc.stdout,
          proc.stdout[-160:])
    check("security headers are audited",
          all(h in proc.stdout for h in ("strict-transport-security",
                                         "content-security-policy")))
    check("score line printed", "Web audit score:" in proc.stdout)
    with tempfile.TemporaryDirectory(prefix="wa-json") as tmp:
        output = Path(tmp) / "audit.json"
        proc = run([sys.executable, str(script), f"http://127.0.0.1:{port}",
                    "--format", "json", "--output", str(output)])
        data = json.loads(output.read_text()) if output.exists() else {}
        check("json report carries tool, score and findings",
              data.get("tool") == "web-audit" and isinstance(data.get("score"), int)
              and len(data.get("findings", [])) >= 6)


def main() -> int:
    ensure_binary()
    workroot = Path(tempfile.mkdtemp(prefix="security-tests-"))
    docroot = workroot / "site"
    build_docroot(docroot)
    server, port = start_server(docroot)
    try:
        test_help_pages()
        test_hashcrack()
        test_dirbrute(port)
        test_port_scanner(port)
        test_web_audit(port)
        test_pipeline(port, workroot / "reports")
    finally:
        server.shutdown()
        shutil.rmtree(workroot, ignore_errors=True)

    print(flush=True)
    if failures:
        print(f"FAILED: {len(failures)} check(s): {', '.join(failures)}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

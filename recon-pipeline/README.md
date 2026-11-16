# recon-pipeline

One command that chains the repo's tools and turns their output into a
single report:

1. **Subdomain enumeration** — runs `subdomain-enum` with JSON output and
   parses the result;
2. **Port scan** — runs `port-scanner` (curated top-100 list, banner grab)
   on every host;
3. **Web audit** — runs `web-audit` (TLS certificate + security headers +
   score) on the base URL and every discovered host;
4. **Directory brute force** — runs the compiled `dirbrute` binary (or
   `go run .` when a Go toolchain is available) against the same list;
5. **Reporting** — writes `report.html` (a self-contained, dark-themed page),
   `report.md`, `report.json` and the raw tool logs into
   `reports/<target>-<timestamp>/`.

Every phase is optional (`--skip-ports`, `--skip-audit`, `--skip-dirbrute`)
and a failing phase never aborts the run — the report simply records why.

## Prerequisites

- Python 3.8+
- `make build` run once so the `dirbrute` binary exists (the pipeline falls
  back to `go run .` if `go` is on PATH, and degrades gracefully otherwise)

## Usage

```console
$ python3 recon.py --domain example.com
$ python3 recon.py --domain example.com --skip-dirbrute
$ python3 recon.py --hosts web01.internal,web02.internal --url https://staging.internal
$ python3 recon.py --domain example.com --max-hosts 3 -t 40 --output-dir /tmp/recon
```

When `--hosts` is given, the subdomain phase is skipped entirely — useful
for re-scanning a known list. Otherwise the base domain plus up to
`--max-hosts` discovered subdomains are scanned.

## Report layout

```text
reports/example.com-20261112-101500/
├── report.html            # self-contained HTML report (no external assets)
├── report.md              # human readable summary
├── report.json            # machine readable, stable schema
├── subdomains.json        # raw subdomain-enum output
├── subdomain-enum.log     # raw stderr of phase 1
├── ports-01.json          # port-scanner JSON per host
├── audit-01.json          # web-audit JSON per URL
└── dirbrute-01.log        # raw output of each directory scan
```

The HTML report is a single file: styles are inlined, every dynamic value is
escaped, and it references no scripts, fonts or CDN assets — safe to open
offline and safe to share as-is. Findings get color-coded status pills
(2xx green, 3xx blue, 401/403 amber, 5xx red), the audit grade becomes a
pill of its own (A/B green, C/D amber, F red) and a summary header carries
the run totals including open ports and the audit grade.

Markdown reports look like this:

```markdown
## Subdomains (2)

| Subdomain | Sources |
| --- | --- |
| www.example.com | dns |

## Port scan

### example.com (2 open)

| Port | Service | Banner |
| --- | --- | --- |
| 80/tcp | http | (no banner) |

## Web audit

### https://example.com - 64/100 (grade C)

| Check | Status | Detail |
| --- | --- | --- |
| strict-transport-security | missing | enable HSTS once HTTPS is stable |

## Directory scan

### https://example.com (5 findings)

| Path | Status | Size |
| --- | --- | --- |
| robots.txt | 200 | 3 |
| admin | 301 | 0 |
```

## Options

| Flag | Description | Default |
| --- | --- | --- |
| `--domain` | Target domain (or use `--hosts`) | — |
| `--url` | Base URL for the primary scan | `https://<domain>` |
| `--hosts` | Comma separated host list, skips phase 1 | — |
| `--scheme` | Scheme for discovered hosts | https |
| `-t, --threads` | Threads for both scan tools | 20 |
| `--max-hosts` | How many discovered hosts to scan | 8 |
| `--output-dir` | Report root directory | reports |
| `--no-crtsh` / `--no-brute` | Passed through to subdomain-enum | off |
| `--wordlist` | Wordlist for the DNS brute force | bundled |
| `--dirbrute-wordlist` | Wordlist override for dirbrute | embedded |
| `--skip-dirbrute` | Skip the directory brute force phase | off |
| `--skip-ports` | Skip the port scan phase | off |
| `--skip-audit` | Skip the web audit phase | off |
| `--phase-timeout` | Per-phase timeout in seconds | 600 |

## Responsible use

Run the pipeline only against targets you are authorized to assess. The
subdomain phase is passive DNS/CT lookups; the port scan opens TCP
connections; the audit and dirbrute phases send real HTTP requests.

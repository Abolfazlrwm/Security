# recon-pipeline

One command that chains the repo's tools and turns their output into a
single report:

1. **Subdomain enumeration** — runs `subdomain-enum` with JSON output and
   parses the result;
2. **Directory brute force** — runs the compiled `dirbrute` binary (or
   `go run .` when a Go toolchain is available) against the base URL and the
   discovered hosts;
3. **Reporting** — writes `report.md`, `report.json` and the raw tool logs
   into `reports/<target>-<timestamp>/`.

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
├── report.md              # human readable summary
├── report.json            # machine readable, stable schema
├── subdomains.json        # raw subdomain-enum output
├── subdomain-enum.log     # raw stderr of phase 1
└── dirbrute-01.log        # raw output of each directory scan
```

Markdown reports look like this:

```markdown
## Subdomains (2)

| Subdomain | Sources |
| --- | --- |
| www.example.com | dns |

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
| `-t, --threads` | Threads for both tools | 20 |
| `--max-hosts` | How many discovered hosts to scan | 8 |
| `--output-dir` | Report root directory | reports |
| `--no-crtsh` / `--no-brute` | Passed through to subdomain-enum | off |
| `--wordlist` | Wordlist for the DNS brute force | bundled |
| `--dirbrute-wordlist` | Wordlist override for dirbrute | embedded |
| `--skip-dirbrute` | Only run the subdomain phase | off |
| `--phase-timeout` | Per-phase timeout in seconds | 600 |

## Responsible use

Run the pipeline only against targets you are authorized to assess. Phase 1
is passive DNS/CT lookups; phase 2 sends real HTTP requests.

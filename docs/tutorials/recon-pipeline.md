# Tutorial — recon-pipeline

`recon-pipeline` chains the other tools into one run: subdomain
enumeration → host selection → directory brute force → consolidated
report. Every run writes a **self-contained dark-themed `report.html`**,
plus `report.md`, `report.json` and the raw tool logs, into
`reports/<target>-<timestamp>/`.

## Step 1 — the full pipeline against a domain

```console
$ make build
$ python3 recon-pipeline/recon.py --domain example.com
```

Phases:

1. **Subdomain enumeration** — subdomain-enum runs (crt.sh + DNS brute
   force) and the results are filtered to live hosts.
2. **Host selection** — the first `--max-hosts` discovered hosts (8 by
   default) are queued for scanning.
3. **Directory brute force** — dirbrute runs against
   `https://<each-host>` (or `http://`, see `--scheme`).
4. **Report** — everything is consolidated and written to the run
   directory.

## Step 2 — re-scan known hosts

```console
$ python3 recon-pipeline/recon.py --hosts web01,web02 --url https://staging.internal
```

Passing `--hosts` **skips the subdomain phase entirely** — useful when
you already have a host list. `--url` overrides the base URL for the
primary directory scan. The captured
[examples run](../../examples/recon-pipeline/run.txt) does exactly this
against a local demo webserver:

```
[*] work directory: reports/http-127.0.0.1-8080-20261113-091439
[*] phase 2/2: directory brute force on 1 host(s) ...
[*]   13 findings on http://127.0.0.1:8080
[*] report written to reports/http-127.0.0.1-8080-20261113-091439/report.html (+ report.md, report.json) (1.2s total)
```

## Step 3 — tune the run

```console
$ python3 recon-pipeline/recon.py --domain example.com -t 30 --max-hosts 5 \
    --scheme http --phase-timeout 900 --output-dir /tmp/recon
```

- `-t 30` — worker threads for **both** tools.
- `--max-hosts 5` — cap how many discovered hosts get scanned.
- `--scheme http` — scan hosts over http instead of https.
- `--phase-timeout 900` — give each phase up to 15 minutes.
- `--output-dir` — where run directories are created.

## Step 4 — partial runs

```console
$ python3 recon-pipeline/recon.py --domain example.com --skip-dirbrute   # subdomains only
$ python3 recon-pipeline/recon.py --domain example.com --no-crtsh        # faster DNS-only enum
$ python3 recon-pipeline/recon.py --domain example.com --dirbrute-wordlist paths.txt
```

`--no-crtsh` / `--no-brute` / `--wordlist` are forwarded to
subdomain-enum; `--dirbrute-wordlist` overrides the scanner's wordlist.

## Step 5 — read the report

Open `reports/<target>-<timestamp>/report.html` in a browser — it is
fully self-contained (no external assets, works offline, dark theme)
and shows:

- run metadata (target, time, versions)
- the subdomain table, when the DNS phase ran
- per-host directory findings with status codes and sizes
- links into the raw `report.md` / `report.json` / tool logs next to it

`report.json` is the machine-readable twin — pipe it into your own
tooling or diff it against a previous run.

## Every flag

| Flag | Meaning |
| --- | --- |
| `--domain` | target domain, starts the subdomain phase |
| `--hosts` | comma separated host list, skips the subdomain phase |
| `--url` | base URL for the primary directory scan |
| `--scheme` | `http` or `https` for discovered hosts (default `https`) |
| `-t, --threads` | worker threads for both tools (default 20) |
| `--max-hosts` | how many discovered hosts get scanned (default 8) |
| `--output-dir` | report directory (default `reports`) |
| `--no-crtsh` / `--no-brute` | forwarded to subdomain-enum |
| `--wordlist` | wordlist for the subdomain brute force |
| `--dirbrute-wordlist` | wordlist override for dirbrute |
| `--skip-dirbrute` | run the subdomain phase only |
| `--phase-timeout` | per-phase timeout in seconds (default 600) |

## Gotchas

- If the Go binary is missing, the pipeline degrades gracefully: it
  tries `go run .` inside `dirbrute/` before failing the phase.
- `--domain` and `--hosts` are mutually exclusive phases: give one, not
  both.
- A `--phase-timeout` kill means that phase's section of the report is
  written from whatever was collected before the cutoff.

See also: [README](../../recon-pipeline/README.md) ·
[examples](../../examples/recon-pipeline/run.txt) ·
[back to the tutorial index](README.md)

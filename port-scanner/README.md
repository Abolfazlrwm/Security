# port-scanner

A fast TCP connect scanner in a single script: a curated top-100 port list
covers the ports that matter most, `--ports` accepts arbitrary singles and
ranges, and open ports are probed for a service banner. Scans run in a
thread pool, so the default full pass finishes in a second or two.

Uses only the Python standard library (3.8+).

## Features

- **Curated top list** — 100 ports ordered by how often they turn out to be
  open in the wild (web, SSH, databases, dev servers, containers, ...).
- **Arbitrary port specs** — `22,80,443,8000-8100` style ranges with
  validation and deduplication.
- **Banner grabbing** — the first line of whatever the service sends is
  captured and shown in the table (`SSH-2.0-OpenSSH_9.6p1`, ...).
- **Service names** — a built-in map labels open ports (`http-proxy`,
  `redis`, `elasticsearch`), no IANA lookup needed.
- **JSON or plain text output** — the JSON shape is stable and is what
  [recon-pipeline](../recon-pipeline/) consumes.

## Usage

```console
$ python3 port_scanner.py scanme.nmap.org --top 100
$ python3 port_scanner.py 10.0.0.5 --ports 22,80,443,3306,8000-8100
$ python3 port_scanner.py host.local --top 100 --no-banner -f json -o scan.json
$ python3 port_scanner.py host.local --ports 1-1024 --workers 500 --timeout 0.5
```

## Options

| Flag | Description | Default |
| --- | --- | --- |
| `--ports` | Explicit port spec, e.g. `22,80,8000-8100` | — |
| `--top` | Scan the top N ports of the curated list (1-100) | 100 |
| `--timeout` | Connect timeout per port, seconds | 1.0 |
| `--workers` | Concurrent connections (1-500) | 200 |
| `--no-banner` | Skip banner grabbing | off |
| `-f, --format` | `txt` or `json` | txt |
| `-o, --output` | Write results to a file | stdout |

`--ports` and `--top` are mutually exclusive.

## Output

```text
target scanme.nmap.org (45.33.32.156) - 100 ports scanned

PORT      STATE   SERVICE         BANNER
22/tcp    open    ssh             SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
80/tcp    open    http            (no banner)

2 open of 100 scanned
```

JSON reports keep the same data in a stable shape:

```json
{
  "tool": "port-scanner",
  "target": "scanme.nmap.org",
  "ip": "45.33.32.156",
  "scanned": 100,
  "open_count": 2,
  "ports": [
    {"port": 22, "state": "open", "service": "ssh", "banner": "SSH-2.0-..."}
  ]
}
```

A captured run against scanme.nmap.org is in
[examples/port-scanner/](../examples/port-scanner/).

## Safe demo targets

`scanme.nmap.org` is run by Nmap precisely so people can practice scanning
against it. `example.com` (IANA reserved) is also fine for light demos.
Everything else: only scan systems you own or have written permission to
test — a connect scan is a series of real TCP connections and may trip
IDS/firewall alerts.

## Responsible use

The default settings (100 ports, 200 workers, 1 s timeout) are polite but
still send hundreds of connection attempts per run. Lower `--workers` and
raise `--timeout` for fragile targets, and never scan infrastructure you
are not authorized to assess.

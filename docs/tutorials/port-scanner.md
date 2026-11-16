# Tutorial — port-scanner

`port-scanner` runs a TCP connect scan from a curated top-100 port list or
an arbitrary `--ports` spec, grabbing service banners on the way. The whole
default pass finishes in a couple of seconds thanks to a 200-connection
thread pool. This tutorial uses `scanme.nmap.org`, the public target Nmap
runs exactly for scan practice — the captured run is in
[examples/port-scanner/](../../examples/port-scanner/scanme-run.txt).

## Step 1 — first run

```console
$ python3 port-scanner/port_scanner.py scanme.nmap.org
```

What happens:

1. The target is resolved (`45.33.32.156`) and the authorized-use note is
   printed to stderr.
2. The first 100 entries of the curated list are probed concurrently
   (200 workers, 1 s connect timeout each).
3. Every open port gets a banner read: whatever the service sends in its
   greeting ends up in the table.
4. A tidy table goes to stdout, progress to stderr.

Expected output shape (exact run in [examples/](../../examples/port-scanner/)):

```text
PORT      STATE   SERVICE         BANNER
22/tcp    open    ssh             SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
80/tcp    open    http            (no banner)
```

The service names come from a built-in map (`ssh`, `http-proxy`, `redis`,
`elasticsearch`, ...), so there is no IANA lookup and nothing to install.

## Step 2 — choose your own ports

```console
$ python3 port-scanner/port_scanner.py 10.0.0.5 --ports 22,80,443,3306,8000-8100
```

`--ports` accepts comma-separated singles and `low-high` ranges; the spec
is validated, deduplicated and scanned in sorted order. Use it when you
already know what you are looking for:

```console
$ python3 port-scanner/port_scanner.py 10.0.0.5 --ports 1-1024 --workers 500 --timeout 0.5
```

A fast low-port sweep: more workers and a shorter timeout trade politeness
for speed. `--top N` (1-100) scans only the first N entries of the curated
list when you want the quick pass.

## Step 3 — banners on and off

```console
$ python3 port-scanner/port_scanner.py host.local --top 100 --no-banner
```

`--no-banner` skips the greeting read — useful when a service misbehaves
with unexpected clients or when you only care about which ports are open.

## Step 4 — machine-readable output

```console
$ python3 port-scanner/port_scanner.py host.local -f json -o scan.json
```

The JSON report carries the resolved IP, how many ports were scanned and
one entry per open port (`port`, `service`, `banner`) — the same schema
[recon-pipeline](../recon-pipeline/) consumes in phase 2.

## Step 5 — chain it

```console
$ python3 recon-pipeline/recon.py --domain example.com
```

The pipeline runs this scanner on every discovered host and folds the open
ports into the HTML/Markdown report, next to the web audit and the
directory scan.

## Ground rules

A connect scan is a series of real TCP connections and can trip IDS or
firewall alerts. Scan systems you own, lab machines, CTF targets or hosts
with written permission — `scanme.nmap.org` and `example.com` are the two
safe public demo targets used in this repo's captures.

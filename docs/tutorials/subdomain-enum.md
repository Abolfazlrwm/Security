# Tutorial — subdomain-enum

`subdomain-enum` finds live subdomains of a domain through two channels:
a [crt.sh](https://crt.sh) certificate-transparency lookup and a threaded
DNS brute force over a bundled label wordlist. Every candidate name is
confirmed with a real A/AAAA query before it is reported, so the output
contains only resolvable hosts.

## Step 1 — first run

```console
$ python3 subdomain-enum/subdomain_enum.py debian.org
```

What happens:

1. `[*] target: debian.org (resolvers: 1.1.1.1, 8.8.8.8)` — the resolver
   set is printed up front.
2. The crt.sh channel queries the CT logs and collects candidate names.
3. The brute-force channel probes every bundled label (146 candidates in
   the captured run) with 30 threads by default.
4. Each candidate that resolves to an A or AAAA record is reported.

Progress lines go to **stderr**, results to **stdout** — so piping or
redirecting stdout gives you a clean subdomain list.

## Step 2 — save machine-readable output

```console
$ python3 subdomain-enum/subdomain_enum.py example.com -f json -o subs.json
```

`-f json` produces a structured report (see
[examples/subdomain-enum/debian.org.json](../../examples/subdomain-enum/debian.org.json)
for the exact schema); `-f txt` (default) writes one subdomain per line.

## Step 3 — choose your channels

```console
$ python3 subdomain-enum/subdomain_enum.py example.com --no-crtsh   # DNS brute force only
$ python3 subdomain-enum/subdomain_enum.py example.com --no-brute   # crt.sh only
```

`--no-crtsh` is useful when crt.sh is slow or unreachable (the tool
retries three times and then continues without it, exactly as in the
[captured debian.org run](../../examples/subdomain-enum/run.txt));
`--no-brute` gives you a silent, pure passive lookup.

## Step 4 — tune speed and resolvers

```console
$ python3 subdomain-enum/subdomain_enum.py example.com -t 50 --timeout 4 -r 9.9.9.9 -r 1.1.1.1
```

- `-t 50` — fifty worker threads instead of the default 30.
- `--timeout 4` — DNS and crt.sh timeout in seconds.
- `-r IP` — replace the default resolvers (`1.1.1.1`, `8.8.8.8`);
  repeatable. Query only resolvers you are allowed to use.

## Every flag

| Flag | Meaning |
| --- | --- |
| `domain` | target domain, e.g. `example.com` (positional, required) |
| `-w, --wordlist` | label wordlist file (default: bundled `wordlists/subdomains.txt`) |
| `-t, --threads` | worker threads (default 30) |
| `--timeout` | DNS and crt.sh timeout in seconds |
| `-r, --resolver` | DNS server to query, repeatable |
| `--no-crtsh` | skip the certificate lookup |
| `--no-brute` | skip the DNS brute force |
| `-f, --format` | `txt` or `json` |
| `-o, --output` | write results to this file instead of stdout |

## Reading the captured output

From [examples/subdomain-enum/run.txt](../../examples/subdomain-enum/run.txt):

```
[*] brute forcing 146 labels with 30 threads ...
[*] DNS brute force confirmed 15 names
[*] done: 15 live subdomains, 0 stale crt.sh entries, 11.4s
```

The final line is the summary: live subdomains, how many came only from
stale crt.sh entries (already unresolvable), and total wall time.

## Gotchas

- **Wildcard DNS.** If a domain resolves every name, the tool will
  "confirm" everything — check one random subdomain manually before
  trusting a result set.
- **stale crt.sh entries** are reported in the summary but kept out of
  the main result list only when they no longer resolve; the JSON marks
  their origin.
- For large wordlists, raise `--timeout` alongside `-t` or you will
  trade correctness for speed on slow resolvers.

See also: [README](../../subdomain-enum/README.md) ·
[examples](../../examples/subdomain-enum/run.txt) ·
[next tutorial: dirbrute](dirbrute.md)

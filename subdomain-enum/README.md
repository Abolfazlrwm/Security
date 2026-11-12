# subdomain-enum

Subdomain enumeration in a single script: passive certificate-transparency
lookups from [crt.sh](https://crt.sh) combined with threaded dictionary based
DNS brute force. Every candidate is verified with a live DNS query before it
is reported, so stale certificate entries never end up in the result.

Uses only the Python standard library (3.8+).

## Features

- **Passive discovery** — pulls historical certificate names from the crt.sh
  JSON API with retries and backoff.
- **Active brute force** — resolves wordlist labels against configurable
  resolvers using a thread pool; queries are hand-built UDP packets, so no
  external DNS library is needed.
- **Wildcard detection** — probes a random name first and flags zones where
  anything resolves, so sinkhole results can be recognized.
- **Live verification** — crt.sh names that no longer resolve are counted
  separately instead of polluting the result list.
- **JSON or plain text output** — the JSON shape is stable and is what
  [recon-pipeline](../recon-pipeline/) consumes.

## Usage

```console
$ python3 subdomain_enum.py example.com
$ python3 subdomain_enum.py example.com -f json -o subs.json
$ python3 subdomain_enum.py example.com --no-crtsh -w my-labels.txt -t 50
$ python3 subdomain_enum.py example.com -r 9.9.9.9 -r 1.1.1.1 --timeout 2
```

## Options

| Flag | Description | Default |
| --- | --- | --- |
| `-w, --wordlist` | Label wordlist file | bundled `wordlists/subdomains.txt` |
| `-t, --threads` | Worker threads (1-200) | 20 |
| `--timeout` | DNS / crt.sh timeout in seconds | 3.0 |
| `-r, --resolver` | DNS server, repeatable (round-robin) | 1.1.1.1, 8.8.8.8 |
| `--no-crtsh` | Skip the certificate lookup | off |
| `--no-brute` | Skip DNS brute force | off |
| `-f, --format` | `txt` or `json` | txt |
| `-o, --output` | Write results to a file | stdout |

## Output

JSON reports contain one entry per live name plus the discovery sources:

```json
{
  "domain": "example.com",
  "wildcard_dns": false,
  "count": 2,
  "subdomains": [
    {"name": "www.example.com", "sources": ["dns"]},
    {"name": "mail.example.com", "sources": ["crt.sh", "dns"]}
  ]
}
```

## Note on wildcard zones

When random subdomains resolve, the tool prints a warning and sets
`wildcard_dns: true`. In that case every name "resolves" and the list may
contain sinkhole entries — cross-check the hosts before acting on them.

## Responsible use

Enumerate only domains you are authorized to test. The crt.sh lookup is a
passive query of public certificate logs; the brute-force phase issues DNS
queries to the resolvers you configure, so keep rates reasonable.

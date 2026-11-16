# Tutorial — takeover-check

`takeover-check` looks for subdomain takeover opportunities: hosts whose
CNAME points at a hosting service (GitHub Pages, Heroku, AWS S3, Azure,
...) that no longer claims them. The decisive evidence is a CNAME
fingerprint **plus** the service's "unclaimed" 404 signature in the body —
only both together produce the `VULNERABLE` verdict. The captured run with
all verdict shapes is in
[examples/takeover-check/](../../examples/takeover-check/run.txt).

## Step 1 — check a couple of hosts

```console
$ python3 takeover-check/takeover_check.py blog.example.com old.example.com
```

What happens per host:

1. A reverse DNS lookup reveals the canonical (CNAME) name behind the host.
2. The canonical name is matched against the built-in fingerprint table
   (17 services: a leading dot means *ends with*, a bare pattern means
   *contains* — that covers regional `s3-website-...` endpoints).
3. If a service matched, the site is fetched over HTTPS (falling back to
   HTTP; 4xx/5xx pages count as bodies) and the first 20 KB are searched
   for the service's unclaimed-page signature.
4. One verdict line per host goes to stdout.

The verdict lines:

```text
[x] VULNERABLE  blog.example.com -> GitHub Pages (CNAME x.github.io) matched: "there isn't a github pages site here" (...)
[~] claimed     pages.github.com -> GitHub Pages (CNAME github.github.io) content served, no takeover signature
[?] unresolved  missing-xyz-12345.example.com DNS lookup failed (check for a dangling CNAME at the DNS provider)
```

`claimed` is the normal state (the service really serves the content);
`VULNERABLE` is the one that needs manual verification and a report.

## Step 2 — work from a file

```console
$ python3 takeover-check/takeover_check.py -f hosts.txt -t 20
```

`hosts.txt` takes one host per line with `#` comments, **or** you can throw
the JSON report of [subdomain-enum](subdomain-enum.md) straight in — the
tool recognizes the `subdomains` array and extracts every name:

```console
$ python3 subdomain-enum/subdomain_enum.py example.com -f json -o subs.json
$ python3 takeover-check/takeover_check.py -f subs.json
```

That is the natural chain: enumerate first, then check every live name for
dangling CNAMEs.

## Step 3 — machine-readable output

```console
$ python3 takeover-check/takeover_check.py -f hosts.txt --format json -o takeover.json
```

The JSON report lists every result with `host`, `cname`, `service`,
`verdict` and `evidence`, plus counts of `vulnerable` and `unresolved`
hosts. The exit code is 1 when something vulnerable was found, so the tool
can gate a CI job or a shell script.

## Step 4 — tuning

```console
$ python3 takeover-check/takeover_check.py -f hosts.txt --timeout 5 --threads 30
```

`--timeout` (default 10 s) bounds both the DNS lookup and each HTTP fetch;
`--threads` (default 10, max 100) controls how many hosts are probed
concurrently.

## Step 5 — understand the fingerprints

Every entry in the table is a service name, CNAME patterns, body
signatures and a remediation note:

```python
{"service": "Heroku",
 "cname": [".herokuapp.com"],
 "body": ["no such app", "there's nothing here, yet"],
 "note": "register the app name at heroku.com"}
```

The note is printed with every `VULNERABLE`/`UNREACHABLE` hit so you know
what a fix looks like. Vendor error pages change over time — treat the
table as living data and extend it in
[takeover_check.py](../../takeover-check/takeover_check.py) when a service
updates its unclaimed page.

## Ground rules

Fingerprints are heuristics and the tool says so on every run: verify a hit
manually (try registering the service yourself) before reporting anything.
And as always — check hosts you are authorized to test; the tool is
passive-ish (one DNS lookup, at most two GETs per host) but that is not an
invitation to sweep third-party domains.

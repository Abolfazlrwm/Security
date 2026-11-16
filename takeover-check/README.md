# takeover-check

Subdomain takeover detection in a single script. For every candidate host
the tool resolves the canonical (CNAME) name, matches it against a table of
well-known hosting fingerprints, and — when the CNAME points at one of those
services — fetches the site body and hunts for the classic "there's nothing
here" 404 signature. A CNAME to an unclaimed service plus a matching error
page is the textbook takeover indicator: the subdomain is up for grabs.

Uses only the Python standard library (3.8+).

## Features

- **17 service fingerprints** — GitHub Pages, Heroku, AWS S3, Azure Web
  Apps, Fastly, Shopify, Surge, Bitbucket, Pantheon, Tumblr, Zendesk,
  Teamwork, Helpjuice, Help Scout Docs, Intercom, Vercel (cname suffix or
  substring patterns).
- **CNAME + body correlation** — a suffix match alone is *not* enough: the
  body must carry the service's unclaimed-page signature before the
  `VULNERABLE` verdict is printed.
- **Direct signature fallback** — a takeover signature in the body is
  flagged even when the CNAME itself does not match a fingerprint.
- **Subdomain-enum friendly** — `-f` accepts both a plain host-per-line file
  and the JSON report that [subdomain-enum](../subdomain-enum/) writes, so
  the two chain naturally.
- **JSON or plain text output** — consumed by scripts and CI, exit code 1
  when something vulnerable is found.

## Verdicts

| Mark | Verdict | Meaning |
| --- | --- | --- |
| `[x] VULNERABLE` | CNAME to a service **and** unclaimed-page signature in the body | verify manually, then report |
| `[-] UNREACHABLE` | CNAME to a service, but no HTTP response | possible NXDOMAIN edge — verify manually |
| `[~] claimed` | CNAME to a service, content served, no signature | the service points here and serves content |
| `[ ] no-http` | resolves, no CNAME fingerprint, no HTTP response | informational |
| `[=] ok` | no fingerprint, normal content | nothing suspicious |
| `[?] unresolved` | DNS lookup failed | check for dangling records at the DNS provider |

## Usage

```console
$ python3 takeover_check.py blog.example.com old.example.com
$ python3 takeover_check.py -f hosts.txt -t 20
$ python3 takeover_check.py -f subdomains.json --format json -o takeover.json
```

`hosts.txt` can look like:

```text
# one host per line, comments are fine
blog.example.com
staging.example.com
```

...or simply be the `subdomains.json` written by subdomain-enum.

## Output

```text
[=] ok          example.com no takeover fingerprint
[~] claimed     pages.github.com -> GitHub Pages (CNAME github.github.io) content served, no takeover signature
[?] unresolved  missing-xyz-12345.example.com DNS lookup failed (check for a dangling CNAME at the DNS provider)
```

A captured run with all three verdict shapes is in
[examples/takeover-check/](../examples/takeover-check/).

## How the fingerprints work

```python
{"service": "GitHub Pages",
 "cname": [".github.io"],
 "body": ["there isn't a github pages site here"],
 "note": "create a repo with this name on github.com to test"}
```

1. `socket.gethostbyname_ex()` reveals the canonical name behind the host;
2. the canonical name is matched against the `cname` patterns (a leading
   dot means *ends with*, a bare string means *contains* — that covers
   regional `s3-website-...` endpoints);
3. if a service matched, the tool fetches `https://host/` (falling back to
   `http://`, counting 4xx/5xx pages as bodies) and searches the first
   20 KB for any `body` signature;
4. signature + service = `VULNERABLE`, with the evidence printed inline.

## False positives

Fingerprints are heuristics. Vendor error pages change, custom 404s can
contain a signature by coincidence, and CDN setups can hide CNAMEs. Every
`VULNERABLE` hit needs a manual check (try to register the service yourself
or view the page) before it goes into a report. The tool prints the same
warning on every run.

## Responsible use

Checking hosts you are authorized to test only. The tool sends one DNS
lookup and at most two GET requests per host — but mass-running it against
domains you have no business with is exactly what it should not be used
for.

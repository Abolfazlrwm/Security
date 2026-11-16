# Tutorial — web-audit

`web-audit` is the polite first look at a web target: one TLS handshake,
one HTTP request and a read of public headers produce a report on the
certificate, the six classic security headers, cookie flags and version
disclosures — rolled up into a 0-100 score and an A-F grade. The captured
run against `example.com` is in
[examples/web-audit/](../../examples/web-audit/example.com.txt).

## Step 1 — audit a target

```console
$ python3 web-audit/web_audit.py example.com
```

What happens:

1. The target is normalized (`example.com` becomes `https://example.com`);
   URLs with a port (`https://host:8443`) and plain `http://` targets work
   too.
2. A TLS handshake with the standard verification context extracts the
   certificate: validity, days left and issuer. Hostname mismatches,
   self-signed and expired certificates fail loudly.
3. For HTTPS targets, a second request checks whether `http://` on port 80
   redirects to HTTPS.
4. The response headers are audited: the six classic security headers,
   `Server` version disclosure, `X-Powered-By` and cookie flags.
5. Every finding gets a line, then the score:

```text
[+] TLS certificate valid (39 day(s) left, issued by SSL Corporation)
[!] HTTP->HTTPS redirect: http:// does not redirect to https://
[+] HTTP 200 response (12 header name(s) received)
[!] header strict-transport-security missing - enable HSTS once HTTPS is stable
...
[*] Web audit score: 22/100 (grade F)
```

Progress goes to stderr, findings and the score to stdout.

## Step 2 — read the score

The deductions are deterministic, so the same configuration always scores
the same:

| Finding | Deduction |
| --- | --- |
| missing required header | 12 each |
| no TLS (plain HTTP / failed handshake) | 20 |
| expired certificate | 25 |
| certificate expiring within 15 days | 8 |
| `http://` does not redirect | 6 |
| version disclosure (`Server` / `X-Powered-By`) | 5 each |
| cookie missing `Secure`/`HttpOnly`/`SameSite` | 6 each (max 18) |

Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F below. `example.com` scores 22
because the six headers are missing (−72), the port-80 listener does not
redirect (−6) and the server header carries a version (−5). The fix list
is literally the `[!]` lines.

## Step 3 — machine-readable output

```console
$ python3 web-audit/web_audit.py example.com --format json --output audit.json
```

The JSON report carries `tls` (state, days left, issuer), the full
`findings` array (`check`, `status`, `detail`), cookie issues, the redirect
result and `score`/`grade` — the schema [recon-pipeline](recon-pipeline.md)
consumes in phase 3 and renders as a table with grade pills.

## Step 4 — special targets

```console
$ python3 web-audit/web_audit.py http://127.0.0.1:8080        # plain HTTP dev server
$ python3 web-audit/web_audit.py https://host:8443 --timeout 15
```

Plain-HTTP targets are flagged (`plain HTTP - no TLS on this target`) and
score the −20 TLS deduction, but their headers are still audited — exactly
how the pipeline's local demo run in
[examples/recon-pipeline/](../../examples/recon-pipeline/report.md) ends up
with `grade F`. For a self-signed certificate the header audit still runs:
the tool retries the fetch with verification disabled and says so.

## Step 5 — chain it

```console
$ python3 recon-pipeline/recon.py --domain example.com
```

Phase 3 of the pipeline audits the base URL and every discovered host and
folds the scores into the report — one glance at the HTML stats row tells
you which host needs the TLS work.

## What it is not

A configuration linter, not a vulnerability scanner: three plain GET
requests per run, no payload probing, no exploit attempts. Use it before
deeper testing, after changes to a server, or as a recurring check in CI
against your own infrastructure.

## Ground rules

Audit systems you own or have explicit permission to assess. The requests
are harmless, but the findings are only actionable for targets you control
anyway.

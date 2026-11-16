# web-audit

A first-pass HTTPS configuration audit in a single script. One run answers
the questions every review starts with: is TLS there and how long does the
certificate live, do the classic security headers exist, are cookies
protected, and does the server leak its version. Findings roll up into a
0-100 score with a letter grade, plus stable JSON for
[recon-pipeline](../recon-pipeline/).

Uses only the Python standard library (3.8+).

## Features

- **TLS certificate checks** — validity, days remaining, issuer; hostnames
  are verified with the standard SSL context, so mismatches and expired
  certificates surface as `[x]` findings.
- **HTTP to HTTPS redirect check** — for HTTPS targets the tool also asks
  whether the plain-HTTP listener forwards to HTTPS.
- **Six classic security headers** — HSTS, CSP, `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, each with
  concrete remediation advice when missing.
- **Disclosure checks** — version numbers in `Server` and the presence of
  `X-Powered-By` are flagged.
- **Cookie flag audit** — `Secure`, `HttpOnly` and `SameSite` are checked
  on every `Set-Cookie` header.
- **Score + grade** — deterministic deductions (`-12` per missing header,
  `-20` no TLS, `-25` expired certificate, ...) produce a reproducible
  0-100 score and an A-F grade; `-f json` exposes everything.

## Usage

```console
$ python3 web_audit.py example.com
$ python3 web_audit.py http://127.0.0.1:8080
$ python3 web_audit.py https://host:8443 --timeout 15
$ python3 web_audit.py example.com --format json --output audit.json
```

## Options

| Flag | Description | Default |
| --- | --- | --- |
| `--timeout` | TLS / HTTP timeout in seconds | 10.0 |
| `-f, --format` | `txt` or `json` | txt |
| `-o, --output` | Write results to a file | stdout |

## Output

```text
[+] TLS certificate valid (39 day(s) left, issued by SSL Corporation)
[!] HTTP->HTTPS redirect: http:// does not redirect to https://
[+] HTTP 200 response (12 header name(s) received)
[!] header strict-transport-security missing - enable HSTS once HTTPS is stable
[!] header content-security-policy missing - start with a report-only CSP, ...
[!] header x-content-type-options missing - send nosniff to stop MIME-type sniffing
[!] header x-frame-options missing - deny framing (DENY / SAMEORIGIN, ...)
[!] header referrer-policy missing - limit referrer leakage, ...
[!] header permissions-policy missing - restrict powerful browser features ...
[*] Web audit score: 22/100 (grade F)
```

The captured run against `example.com` (a server with a real certificate
and none of the headers) is in [examples/web-audit/](../examples/web-audit/).

## Scoring

| Finding | Deduction |
| --- | --- |
| missing required header | 12 each |
| no TLS (plain HTTP or failed handshake) | 20 |
| expired certificate | 25 |
| certificate expiring within 15 days | 8 |
| `http://` does not redirect to `https://` | 6 |
| version disclosure (`Server` / `X-Powered-By`) | 5 each |
| cookie missing `Secure`/`HttpOnly`/`SameSite` | 6 each (max 18) |

Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F below.

## What it is not

This is a configuration linter, not a vulnerability scanner: it sends
normal GET requests, reads public headers and checks a public certificate.
It will not find SQL injection, XSS payloads or business-logic issues. Use
it as the fast, polite first look before deeper testing.

## Responsible use

Audit systems you own or have explicit permission to assess. The tool
performs at most three plain GET requests per run — but the results are
only meaningful for targets you are allowed to assess anyway.

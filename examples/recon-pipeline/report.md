# Recon report - http://127.0.0.1:8080

- Generated: 2026-11-16 13:45 UTC
- Base URL: http://127.0.0.1:8080
- Tools: port-scanner + web-audit + dirbrute (pipeline 1.3.0)

## Subdomains (0)

_No live subdomains found (host list provided via --hosts)._

## Port scan

### 127.0.0.1 (1 open)

| Port | Service | Banner |
| --- | --- | --- |
| 8080/tcp | http-proxy |  |

## Web audit

### http://127.0.0.1:8080 - 3/100 (grade F)

| Check | Status | Detail |
| --- | --- | --- |
| http | ok | HTTP 200 |
| strict-transport-security | missing | enable HSTS once HTTPS is stable (prevents protocol downgrade) |
| content-security-policy | missing | start with a report-only CSP, then restrict script sources |
| x-content-type-options | missing | send nosniff to stop MIME-type sniffing |
| x-frame-options | missing | deny framing (DENY / SAMEORIGIN, or CSP frame-ancestors) |
| referrer-policy | missing | limit referrer leakage, e.g. strict-origin-when-cross-origin |
| permissions-policy | missing | restrict powerful browser features (camera, geolocation, ...) |
| server disclosure | warn | server header reveals a version: SimpleHTTP/0.6 Python/3.12.16 |

## Directory scan

### http://127.0.0.1:8080 (13 findings)

| Path | Status | Size |
| --- | --- | --- |
| .env | 200 | 124 |
| admin | 301 | 0 |
| api | 301 | 0 |
| api/v1 | 301 | 0 |
| backup.zip | 200 | 152 |
| index.html | 200 | 96 |
| phpinfo.php | 200 | 30 |
| robots.txt | 200 | 67 |
| server-status | 200 | 57 |
| sitemap.xml | 200 | 199 |
| uploads | 301 | 0 |
| .git/config | 200 | 104 |
| .git/HEAD | 200 | 21 |

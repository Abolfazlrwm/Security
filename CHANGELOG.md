# Changelog

Each tool in this repo is versioned and released independently.
Every entry below mirrors a published GitHub release (full release
notes behind each link; dates are publish dates).

Tools: `cve-lookup` · `dirbrute` · `hashcrack` · `jwt-analyzer` · `port-scanner` · `recon-pipeline` · `subdomain-enum` · `takeover-check` · `web-audit`

## cve-lookup

- **cve-lookup-v1.0.0** — 2026-11-16 — **First release of cve-lookup**: turn banners, keywords or CVE ids into CVSS-ranked CVE lists via the official NVD CVE API 2.0 — `urllib` only, no third-party client; **Banner → CPE guessing**: `SSH-2.0-OpenSSH_7.4p1` becomes `cpe:2.3:a:openbsd:openssh:7.4` … [release](https://github.com/Abolfazlrwm/Security/releases/tag/cve-lookup-v1.0.0)

## dirbrute

- **dirbrute-v1.1.1** — 2026-11-13 — `dirbrute` is now distributed as **standalone binaries**: pushing the `dirbrute-v1.1.1` tag triggered the Release binaries workflow, which cross-compiles the Go tool with `-trimpath -ldflags "-s -w"` for **linux/amd64, linux/arm64, darwin/amd64, darwin/arm64 … [release](https://github.com/Abolfazlrwm/Security/releases/tag/dirbrute-v1.1.1)
- **dirbrute-v1.1.0** — 2026-11-12 — New examples/dirbrute/ directory with local-run.txt, a captured scan of a small demo webserver: 13 paths found (exposed `.env`, `.git/` contents, `admin` and `api` redirects, a leftover `backup.zip`), with the wildcard-baseline progress lines included … [release](https://github.com/Abolfazlrwm/Security/releases/tag/dirbrute-v1.1.0)
- **dirbrute-v1.0.0** — 2026-11-12 — Threaded directory and file brute-forcer written in pure Go (standard library only); Wildcard response baseline filtering, status/size exclusions, extension probing [release](https://github.com/Abolfazlrwm/Security/releases/tag/dirbrute-v1.0.0)

## hashcrack

- **hashcrack-v1.2.0** — 2026-11-16 — **SHA-512 support** — hashcrack now cracks SHA-512 digests alongside; MD5, SHA-1 and SHA-256. 128-character digests are auto-detected as [release](https://github.com/Abolfazlrwm/Security/releases/tag/hashcrack-v1.2.0)
- **hashcrack-v1.1.1** — 2026-11-13 — **Built-in default wordlist** - when no wordlist file is reachable, hashcrack now falls back to a built-in 78-entry password list instead of refusing to run. This makes the standalone binary work out of the box; file-based wordlists also skip blank lines and … [release](https://github.com/Abolfazlrwm/Security/releases/tag/hashcrack-v1.1.1)
- **hashcrack-v1.1.0** — 2026-11-12 — New examples/hashcrack/ directory with a demo target file (demo-hashes.txt) and three captured sessions (demo-run.txt): plain wordlist lookup across MD5/SHA-1/SHA-256, the `capitalize,append4` rule chain, and a salted digest with `--salt-position prefix` … [release](https://github.com/Abolfazlrwm/Security/releases/tag/hashcrack-v1.1.0)
- **hashcrack-v1.0.0** — 2026-11-12 — MD5 / SHA-1 / SHA-256 cracking with automatic algorithm detection by digest length; Ordered mutation rule chains (capitalize, leet, append1/2/4, reverse, case rules) [release](https://github.com/Abolfazlrwm/Security/releases/tag/hashcrack-v1.0.0)

## jwt-analyzer

- **jwt-analyzer-v1.0.0** — 2026-11-16 — **First release of jwt-analyzer**: decode, verify and audit JSON Web Tokens entirely offline in one stdlib script; Full decode with human-readable timestamps for `exp` / `iat` / `nbf` / `auth_time`, plus HS256/384/512 signature verification with `--secret`. [release](https://github.com/Abolfazlrwm/Security/releases/tag/jwt-analyzer-v1.0.0)

## port-scanner

- **port-scanner-v1.0.0** — 2026-11-16 — **First release of port-scanner**: thread-pool TCP connect scanner over a curated top-100 port list, with arbitrary `--ports` specs (`22,80,443,8000-8100`), banner grabbing and a built-in service-name map; Table output with service + banner per open port … [release](https://github.com/Abolfazlrwm/Security/releases/tag/port-scanner-v1.0.0)

## recon-pipeline

- **recon-pipeline-v1.3.0** — 2026-11-16 — recon-pipeline now chains **four tools** instead of two:; **New phase 2 - port scan**: port-scanner probes the curated top-100 port list on every host, banners included. [release](https://github.com/Abolfazlrwm/Security/releases/tag/recon-pipeline-v1.3.0)
- **recon-pipeline-v1.2.0** — 2026-11-13 — Every pipeline run now also writes **`report.html`** - a self-contained, dark-themed report page: inline CSS only, every dynamic value escaped, and **zero external assets** (no scripts, no web fonts, no CDN references). It renders offline and never contacts a … [release](https://github.com/Abolfazlrwm/Security/releases/tag/recon-pipeline-v1.2.0)
- **recon-pipeline-v1.1.0** — 2026-11-12 — New examples/recon-pipeline/ directory with a full consolidated report captured from a real run: report.md, report.json and the console log run.txt; The example run targets the same local demo webserver as the dirbrute capture with `--hosts`, so the report … [release](https://github.com/Abolfazlrwm/Security/releases/tag/recon-pipeline-v1.1.0)
- **recon-pipeline-v1.0.0** — 2026-11-12 — One command that chains `subdomain-enum` and `dirbrute`; Graceful degradation when the Go binary is missing (falls back to `go run .`) [release](https://github.com/Abolfazlrwm/Security/releases/tag/recon-pipeline-v1.0.0)

## subdomain-enum

- **subdomain-enum-v1.2.0** — 2026-11-12 — `subdomain-enum` is now also distributed as **standalone executables**: pushing a `subdomain-enum-v*` tag triggers the Release binaries workflow, which builds self-contained binaries with PyInstaller for **Linux (x86_64)**, **macOS (arm64, Apple Silicon)** … [release](https://github.com/Abolfazlrwm/Security/releases/tag/subdomain-enum-v1.2.0)
- **subdomain-enum-v1.1.0** — 2026-11-12 — New examples/subdomain-enum/ directory with captured output from a real run against the public domain `debian.org`: debian.org.json holds the full result set (15 live names) and run.txt the console transcript; The capture also demonstrates the crt.sh fallback … [release](https://github.com/Abolfazlrwm/Security/releases/tag/subdomain-enum-v1.1.0)
- **subdomain-enum-v1.0.0** — 2026-11-12 — Passive subdomain discovery from crt.sh certificate transparency logs (with retries and backoff); Threaded DNS brute force with hand-built UDP queries - no external DNS library [release](https://github.com/Abolfazlrwm/Security/releases/tag/subdomain-enum-v1.0.0)

## takeover-check

- **takeover-check-v1.0.0** — 2026-11-16 — **First release of takeover-check**: subdomain takeover fingerprints for 17 hosting services (GitHub Pages, Heroku, AWS S3, Azure, Fastly, Shopify, Vercel, ...), matched by CNAME pattern **and** unclaimed-page body signature; Verdict ladder: `VULNERABLE` … [release](https://github.com/Abolfazlrwm/Security/releases/tag/takeover-check-v1.0.0)

## web-audit

- **web-audit-v1.0.0** — 2026-11-16 — **First release of web-audit**: one polite pass over a web target that checks the TLS certificate (validity, days left, issuer, hostname verification), the six classic security headers (HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options` … [release](https://github.com/Abolfazlrwm/Security/releases/tag/web-audit-v1.0.0)

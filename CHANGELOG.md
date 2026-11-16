# Changelog

Each tool in this repo is versioned and released independently. Every entry
below mirrors a published GitHub release (tag-linked; dates are publish dates).

Tools: `cve-lookup` · `dirbrute` · `hashcrack` · `jwt-analyzer` · `port-scanner` · `recon-pipeline` · `subdomain-enum` · `takeover-check` · `web-audit`

## cve-lookup

- **vv1.0.0** — 2026-11-16 — First release of cve-lookup: turn banners, keywords or CVE ids into CVSS-ranked CVE lists via the official NVD CVE API 2.0 — `urllib` only, no third-party clien. [notes](https://github.com/Abolfazlrwm/Security/releases/tag/cve-lookup-v1.0.0)

## dirbrute

- **vv1.1.1** — 2026-11-13 — `dirbrute` is now distributed as standalone binaries: pushing the `dirbrute-v1.1.1` tag triggered the Release binaries workflow, which cross-compiles the Go too. [notes](https://github.com/Abolfazlrwm/Security/releases/tag/dirbrute-v1.1.1)
- **vv1.1.0** — 2026-11-12 — New examples/dirbrute/ directory with local-run.txt, a captured scan of a small demo webserver: 13 paths found (exposed `.env`, `.git/` contents, `admin` and `a. [notes](https://github.com/Abolfazlrwm/Security/releases/tag/dirbrute-v1.1.0)
- **vv1.0.0** — 2026-11-12 — Threaded directory and file brute-forcer written in pure Go (standard library only). [notes](https://github.com/Abolfazlrwm/Security/releases/tag/dirbrute-v1.0.0)

## hashcrack

- **vv1.2.0** — 2026-11-16 — SHA-512 support — hashcrack now cracks SHA-512 digests alongside. [notes](https://github.com/Abolfazlrwm/Security/releases/tag/hashcrack-v1.2.0)
- **vv1.1.1** — 2026-11-13 — Built-in default wordlist - when no wordlist file is reachable, hashcrack now falls back to a built-in 78-entry password list instead of refusing to run. This m. [notes](https://github.com/Abolfazlrwm/Security/releases/tag/hashcrack-v1.1.1)
- **vv1.1.0** — 2026-11-12 — New examples/hashcrack/ directory with a demo target file (demo-hashes.txt) and three captured sessions (demo-run.txt): plain wordlist lookup across MD5/SHA-1/S. [notes](https://github.com/Abolfazlrwm/Security/releases/tag/hashcrack-v1.1.0)
- **vv1.0.0** — 2026-11-12 — MD5 / SHA-1 / SHA-256 cracking with automatic algorithm detection by digest length. [notes](https://github.com/Abolfazlrwm/Security/releases/tag/hashcrack-v1.0.0)

## jwt-analyzer

- **vv1.0.0** — 2026-11-16 — First release of jwt-analyzer: decode, verify and audit JSON Web Tokens entirely offline in one stdlib script.. [notes](https://github.com/Abolfazlrwm/Security/releases/tag/jwt-analyzer-v1.0.0)

## port-scanner

- **vv1.0.0** — 2026-11-16 — First release of port-scanner: thread-pool TCP connect scanner over a curated top-100 port list, with arbitrary `--ports` specs (`22,80,443,8000-8100`), banner. [notes](https://github.com/Abolfazlrwm/Security/releases/tag/port-scanner-v1.0.0)

## recon-pipeline

- **vv1.3.0** — 2026-11-16 — recon-pipeline now chains four tools instead of two:. [notes](https://github.com/Abolfazlrwm/Security/releases/tag/recon-pipeline-v1.3.0)
- **vv1.2.0** — 2026-11-13 — Every pipeline run now also writes `report.html` - a self-contained, dark-themed report page: inline CSS only, every dynamic value escaped, and zero external as. [notes](https://github.com/Abolfazlrwm/Security/releases/tag/recon-pipeline-v1.2.0)
- **vv1.1.0** — 2026-11-12 — New examples/recon-pipeline/ directory with a full consolidated report captured from a real run: report.md, report.json and the console log run.txt. [notes](https://github.com/Abolfazlrwm/Security/releases/tag/recon-pipeline-v1.1.0)
- **vv1.0.0** — 2026-11-12 — One command that chains `subdomain-enum` and `dirbrute`. [notes](https://github.com/Abolfazlrwm/Security/releases/tag/recon-pipeline-v1.0.0)

## subdomain-enum

- **vv1.2.0** — 2026-11-12 — `subdomain-enum` is now also distributed as standalone executables: pushing a `subdomain-enum-v*` tag triggers the Release binaries workflow, which builds self-. [notes](https://github.com/Abolfazlrwm/Security/releases/tag/subdomain-enum-v1.2.0)
- **vv1.1.0** — 2026-11-12 — New examples/subdomain-enum/ directory with captured output from a real run against the public domain `debian.org`: debian.org.json holds the full result set (1. [notes](https://github.com/Abolfazlrwm/Security/releases/tag/subdomain-enum-v1.1.0)
- **vv1.0.0** — 2026-11-12 — Passive subdomain discovery from crt.sh certificate transparency logs (with retries and backoff). [notes](https://github.com/Abolfazlrwm/Security/releases/tag/subdomain-enum-v1.0.0)

## takeover-check

- **vv1.0.0** — 2026-11-16 — First release of takeover-check: subdomain takeover fingerprints for 17 hosting services (GitHub Pages, Heroku, AWS S3, Azure, Fastly, Shopify, Vercel, ...), ma. [notes](https://github.com/Abolfazlrwm/Security/releases/tag/takeover-check-v1.0.0)

## web-audit

- **vv1.0.0** — 2026-11-16 — First release of web-audit: one polite pass over a web target that checks the TLS certificate (validity, days left, issuer, hostname verification), the six clas. [notes](https://github.com/Abolfazlrwm/Security/releases/tag/web-audit-v1.0.0)

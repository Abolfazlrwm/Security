# Security Policy

## Scope

This repository ships four security-testing tools (subdomain-enum,
dirbrute, hashcrack and recon-pipeline). Everything here is written for
**authorized** work only — your own systems, lab environments, CTFs or
engagements you have explicit written permission to run. Using the tools
against systems you do not own or are not permitted to test is illegal
in most jurisdictions and is not supported here.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting instead:

1. Go to [Security → Advisories → Report a
   vulnerability](https://github.com/Abolfazlrwm/Security/security/advisories/new).
2. Describe the issue, the affected tool and version, and how to
   reproduce it.
3. If possible, include a minimal proof of concept.

If private reporting is unavailable for some reason, contact the
maintainer directly to arrange an out-of-band channel first.

## What to expect

| Step | Target |
| --- | --- |
| Acknowledgement | within 3 days |
| Triage (affected versions, severity, plan) | within 7 days |
| Fix or mitigation for accepted issues | within 30 days, sooner for high severity |
| Public disclosure | after the fix ships, coordinated with the reporter |

Accepted fixes are released as a patch tag (for example
`subdomain-enum-v1.2.1`); the release workflow rebuilds and attaches the
binaries automatically, so users can pick up the fix without building
from source. See [docs/actions.md](docs/actions.md) for how that
pipeline works.

## In scope

- Command or code injection, path traversal, unsafe temporary-file or
  report handling in any of the four tools
- A tool reading or writing outside its working directory without being
  explicitly asked to
- Crashes, hangs or memory exhaustion triggered by input the tool is
  supposed to handle safely (target responses, hash files, wordlists,
  `--help` output)
- Sensitive data leaking into the generated reports
  (`report.html` / `report.md` / `report.json`)

## Out of scope

- Small bundled wordlists or weak default candidate sets — they are
  demo corpora by design, not a security boundary
- Issues that only exist when the tools are pointed at systems the
  operator is not authorized to test
- Reports from automated scanners without a concrete, reproducible
  example

## Supported versions

Only the latest tagged release of each tool receives security fixes:

| Tool | Latest release | Binary platforms |
| --- | --- | --- |
| subdomain-enum | v1.2.0 | linux, macOS (arm64), windows |
| dirbrute | v1.1.1 | linux (amd64, arm64), macOS (amd64, arm64), windows |
| hashcrack | v1.1.1 | linux, macOS (arm64), windows |
| recon-pipeline | v1.2.0 | runs from source (chains the other tools) |

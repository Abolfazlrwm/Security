# Security

[![CI](https://github.com/Abolfazlrwm/Security/actions/workflows/ci.yml/badge.svg)](https://github.com/Abolfazlrwm/Security/actions/workflows/ci.yml)
[![Release binaries](https://github.com/Abolfazlrwm/Security/actions/workflows/release.yml/badge.svg)](https://github.com/Abolfazlrwm/Security/actions/workflows/release.yml)

A compact toolkit of network reconnaissance and auditing tools, written in
Python and Go with zero third-party dependencies.

> **Authorized use only.** These tools are meant for education, CTFs and
> testing systems you own or have explicit permission to assess.

## Tools

| Tool | Language | What it does |
| --- | --- | --- |
| [subdomain-enum](subdomain-enum/) | Python 3 | Subdomain discovery via crt.sh and threaded DNS brute force |
| [dirbrute](dirbrute/) | Go | Threaded directory and file brute-forcer with wildcard filtering |
| [hashcrack](hashcrack/) | Python 3 | MD5 / SHA-1 / SHA-256 cracking with wordlists and rule chains |
| [recon-pipeline](recon-pipeline/) | Python 3 | Chains the tools above and writes markdown, JSON and HTML reports |

## Downloads

Release tags build standalone binaries automatically and attach them, with
sha256 checksums, to the matching GitHub release:

| Tool | Platforms | Release |
| --- | --- | --- |
| dirbrute | linux (amd64, arm64), macOS (amd64, arm64), windows | [dirbrute-v1.1.1](https://github.com/Abolfazlrwm/Security/releases/tag/dirbrute-v1.1.1) |
| subdomain-enum | linux, macOS (arm64), windows | [subdomain-enum-v1.2.0](https://github.com/Abolfazlrwm/Security/releases/tag/subdomain-enum-v1.2.0) |
| hashcrack | linux, macOS (arm64), windows | [hashcrack-v1.1.1](https://github.com/Abolfazlrwm/Security/releases/tag/hashcrack-v1.1.1) |

dirbrute is cross-compiled with the Go toolchain; the Python tools are
packaged with PyInstaller. Both paths smoke-test every artifact inside the
release workflow before it gets published, so each binary runs without any
interpreter, runtime or third-party package.

## Quick start

### Subdomain enumeration

```console
$ python3 subdomain-enum/subdomain_enum.py example.com -f json -o subs.json
$ python3 subdomain-enum/subdomain_enum.py example.com --no-crtsh -t 50
```

### Directory brute force

```console
$ make build                 # compiles dirbrute/dirbrute (Go 1.19+)
$ ./dirbrute/dirbrute -u https://target/ -t 30
$ ./dirbrute/dirbrute -u https://target/ -w paths.txt -x php,html -o found.txt
```

### Hash cracking

```console
$ python3 hashcrack/hashcrack.py --hash 5f4dcc3b5aa765d61d8327deb882cf99
$ python3 hashcrack/hashcrack.py --hashes hashes.txt --rules capitalize,append2
```

### Full recon run

```console
$ make build
$ python3 recon-pipeline/recon.py --domain example.com
$ python3 recon-pipeline/recon.py --hosts web01,web02 --url https://staging.internal
```

Every pipeline run writes `report.html` (a self-contained, dark-themed
report page), `report.md`, `report.json` and the raw tool logs into
`reports/<target>-<timestamp>/`.

## Examples

The [examples/](examples/) directory contains captured output from real
runs of every tool: a directory scan against a local demo webserver,
three hash-cracking sessions (plain lookup, rule chain, salted digest),
a verified subdomain enumeration of `debian.org`, and the consolidated
pipeline report. Each artifact records the exact command that produced
it, so you can see the expected output shape before running anything
against your own targets.

## Testing

`tests/integration.py` is a self-contained harness (standard library only)
that spins up a local demo webserver and verifies the whole toolkit:
hashcrack sessions (plain lookup, rule chain, salted digest and the
built-in wordlist fallback), a full dirbrute scan including wildcard
filtering, and an end-to-end recon-pipeline run whose HTML report is
checked for correctness and self-containment:

```console
$ make build
$ python3 tests/integration.py
ALL CHECKS PASSED
```

## CI/CD (GitHub Actions)

Two workflows keep the toolkit green and ship the binaries. The full
pipeline documentation — job matrices, artifact naming, release routing —
lives in [docs/actions.md](docs/actions.md):

| Workflow | Trigger | Result |
| --- | --- | --- |
| [CI](https://github.com/Abolfazlrwm/Security/actions/workflows/ci.yml) | every push / PR to `main` | Python tools byte-compiled and smoke-tested on 3.11 / 3.12, dirbrute checked with `gofmt`, `go vet` and `go build` on Linux, macOS and Windows, then the full integration harness |
| [Release binaries](https://github.com/Abolfazlrwm/Security/actions/workflows/release.yml) | tags `dirbrute-v*`, `subdomain-enum-v*`, `hashcrack-v*` | standalone binaries for every supported platform, each smoke-tested before publish, attached to the GitHub release with sha256 checksums |

To cut a release, push an annotated tag and the workflow does the rest:

```console
$ git tag -a dirbrute-v1.2.0 -m "dirbrute 1.2.0"
$ git push origin dirbrute-v1.2.0
```

## Building

The Python tools run on any Python 3.8+ interpreter with no extra packages.
The Go tool needs a Go 1.19+ toolchain:

```console
$ make build     # build the dirbrute binary
$ make vet       # go vet
$ make clean     # remove the binary
```

## Repository layout

```
Security/
├── subdomain-enum/
│   ├── subdomain_enum.py
│   └── wordlists/subdomains.txt
├── dirbrute/
│   ├── main.go
│   ├── scanner.go
│   └── wordlists/common.txt
├── hashcrack/
│   ├── hashcrack.py
│   └── wordlists/common-passwords.txt
├── recon-pipeline/
│   └── recon.py
├── examples/          # captured output from real runs
├── tests/
│   └── integration.py # local end-to-end harness
├── docs/
│   └── actions.md     # CI/CD pipeline documentation
└── Makefile
```

## License

Released under the [MIT License](LICENSE).

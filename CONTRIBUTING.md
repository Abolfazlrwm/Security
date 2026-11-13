# Contributing to Security

Thanks for wanting to improve the toolkit! This guide covers the dev
setup, the rules the codebase follows, and how releases are cut.

## Ground rules

- **Authorized use only.** Contributions that make the tools easier to
  use against systems without permission (stealth or evasion features,
  credential-theft helpers, and similar) will be rejected. The toolkit
  is for education, CTFs and testing systems you own or are permitted
  to test.
- **Standard library only.** The Python tools and the test harness must
  run with a bare `python3` (3.8+); dirbrute must build with a plain
  `go build`. If a feature truly needs a dependency, discuss it in an
  issue first.
- Keep every tool a single self-contained file next to its wordlists.

## Development setup

Requirements: Python 3.11+ (CI tests 3.11 and 3.12), Go 1.19+ (CI uses
1.23) and GNU make.

```console
$ git clone https://github.com/Abolfazlrwm/Security.git
$ cd Security
$ make build                  # compile dirbrute
$ python3 tests/integration.py
ALL CHECKS PASSED
```

`tests/integration.py` is self-contained (standard library only): it
starts a local demo webserver, runs hashcrack (plain lookup, rule
chain, salted digest, built-in wordlist fallback), drives a real
dirbrute scan including wildcard filtering, and finishes with an
end-to-end recon-pipeline run whose HTML report is validated. If your
change touches any tool the harness must pass; if it adds behaviour,
extend the harness to cover it.

## Commit style

Conventional Commits, lowercase, imperative:

```
feat(hashcrack): add sha3-256 support
fix(dirbrute): skip wildcard responses on 3xx redirects
docs: expand release docs with artifact table
ci: pin pyinstaller to >=6,<7
```

`feat`, `fix`, `docs`, `ci`, `test`, `refactor` and `chore` are all
fine. One logical change per commit keeps release bisecting possible.

## Pull requests

1. Fork, create a branch (`feat/...`, `fix/...`).
2. Make the change, keep it minimal and focused.
3. Run the gates locally — CI runs exactly these on Linux, macOS and
   Windows, so anything passing locally passes remotely:

   | Gate | Command |
   | --- | --- |
   | Python syntax (all tools) | `python -m compileall subdomain-enum hashcrack recon-pipeline` |
   | Go formatting (hard tabs, no CRLF) | `gofmt -l dirbrute` must print nothing |
   | Go vet and build | `cd dirbrute && go vet ./... && go build -o dirbrute .` |
   | Integration harness | `python3 tests/integration.py` |

4. Open the PR with a short description of what changed and why.

For Go, format with `gofmt` (hard tabs). On Windows set
`git config --global core.autocrlf false` so CRLF never reaches the
tree — CI enforces it. The full CI/CD pipeline is documented in
[docs/actions.md](docs/actions.md).

## Cutting a release

Releases are tag-driven; the workflow builds and attaches the binaries
automatically. Tag names must match `<tool>-v<semver>` where tool is
`dirbrute`, `subdomain-enum` or `hashcrack`:

```console
$ git tag -a dirbrute-v1.2.0 -m "dirbrute 1.2.0"
$ git push origin dirbrute-v1.2.0
```

Artifacts for every supported platform plus `checksums.txt` are
attached to the release automatically — never upload binaries by hand.
Before tagging: bump the tool's reported version (`TOOL_VERSION` in the
Python tools), update the tool's README if flags changed, refresh
`examples/` if the output shape changed, and make sure CI is green on
`main`.

## Reporting bugs and ideas

- **Bug:** open an issue with the exact command, the tool version, the
  OS and the full output (redact anything that identifies your
  targets).
- **Feature:** describe the use case first — the smallest tool that
  solves a real recon task beats a pile of flags.
- **Security issues:** not via public issues — see
  [SECURITY.md](SECURITY.md).

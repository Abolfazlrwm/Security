# dirbrute

A threaded directory and file brute-forcer for webservers, in the spirit of
gobuster's `dir` mode, built with nothing but the Go standard library.
The default wordlist is embedded in the binary, so the compiled tool runs
without any extra files.

## Features

- **Worker pool** — a fixed set of goroutines pulls candidates from a shared
  channel; `-t` controls concurrency.
- **Wildcard filtering** — three random paths are probed up front; when the
  server answers all of them identically, that exact status/size pair is
  filtered out automatically.
- **Response filtering** — ignore status codes (`-b`) and body sizes
  (`-exclude-length`), probe extensions (`-x php,html`).
- **Pipeline friendly** — findings go to stdout, progress goes to stderr,
  `-o` mirrors findings into a file.
- **TLS options** — `-k` skips certificate verification, `-r` follows
  redirects (3xx findings are reported either way).

## Build

Requires Go 1.19 or newer:

```console
$ go build -o dirbrute .        # or: make build from the repo root
```

## Usage

```console
$ ./dirbrute -u https://target/
$ ./dirbrute -u https://target/ -w my-paths.txt -t 40 -q
$ ./dirbrute -u https://target/ -x php,html -b 404,500 -o findings.txt
$ ./dirbrute -u https://target/ -H 'Authorization: Bearer <token>' -c 'session=abc'
```

## Options

| Flag | Description | Default |
| --- | --- | --- |
| `-u` | Target base URL (required) | — |
| `-w` | Wordlist file | embedded list |
| `-t` | Concurrent workers (1-500) | 20 |
| `-x` | Extensions to probe, comma separated | none |
| `-b` | Status codes to ignore | 404 |
| `-exclude-length` | Body sizes to ignore | none |
| `-a` | User agent | dirbrute/1.1 |
| `-c` | Raw Cookie header | none |
| `-H` | Extra header, repeatable | none |
| `-r` | Follow redirects | off |
| `-k` | Skip TLS verification | off |
| `-q` | Suppress progress output | off |
| `--timeout` | Per-request timeout (seconds) | 10 |
| `-o` | Also write findings to a file | stdout only |

## Example session

Scanning a small local test server:

```console
$ ./dirbrute -u http://127.0.0.1:8099 -t 10 -q
admin (Status: 301) [Size: 0]
api (Status: 301) [Size: 0]
login.php (Status: 200) [Size: 10]
robots.txt (Status: 200) [Size: 3]
.env (Status: 200) [Size: 15]

[!] wildcard response detected (status 404, size 335), identical responses are skipped
[*] 145 candidates queued with 10 workers
[x] 145/145 checked, 5 findings
```

Findings are printed to stdout and everything else to stderr, so
`./dirbrute ... 2>/dev/null` yields a clean list for piping.

## Responsible use

Only scan servers you own or have explicit written permission to test.
The default wordlist is intentionally small — for real engagements bring
your own curated list.

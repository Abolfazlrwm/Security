# Tutorial — dirbrute

`dirbrute` brute-forces directories and files on a webserver with a
threaded Go scanner. It filters **wildcard responses** automatically:
when the server answers every path with the same status/size (soft 404),
that baseline is detected once and skipped for all other candidates, so
the findings list stays clean.

## Step 1 — get the binary

Download the platform binary from
[dirbrute-v1.1.1](https://github.com/Abolfazlrwm/Security/releases/tag/dirbrute-v1.1.1)
(linux amd64/arm64, macOS amd64/arm64, windows amd64 — all with sha256
checksums), or build from source:

```console
$ make build        # compiles dirbrute/dirbrute (Go 1.19+)
```

## Step 2 — basic scan

```console
$ ./dirbrute/dirbrute -u http://127.0.0.1:8080/ -t 10
```

Findings go to **stdout**, progress to **stderr**. From the
[captured run](../../examples/dirbrute/local-run.txt):

```
[!] wildcard response detected (status 404, size 335), identical responses are skipped
[*] 145 candidates queued with 10 workers
.env (Status: 200) [Size: 124]
backup.zip (Status: 200) [Size: 152]
admin (Status: 301) [Size: 0]
```

The `[!]` line is good news: it means the server was returning a body
for any random path, and the scanner learned that baseline and will not
report every candidate as a hit.

## Step 3 — extensions and wordlists

```console
$ ./dirbrute/dirbrute -u https://target/ -x php,html -w paths.txt -t 30
```

- `-x php,html` — additionally probe each candidate with these
  extensions (`backup.php`, `backup.html`, ...). The dot is added for
  you.
- `-w paths.txt` — use your own wordlist instead of the embedded one
  (one path per line, no leading slash needed).

## Step 4 — filtering noise

```console
$ ./dirbrute/dirbrute -u https://target/ -b 404,403 -exclude-length 0,12
```

- `-b 404,403` — ignore these status codes (default `404`).
- `-exclude-length 0,12` — ignore responses whose body size matches
  these byte counts (comma separated). Useful against servers that
  answer 200 to everything with a constant-size page — though the
  wildcard detector usually handles that case already.

## Step 5 — authenticated scans and TLS

```console
$ ./dirbrute/dirbrute -u https://target/ -c 'session=abc123' \
    -H 'X-Forwarded-For: 10.0.0.1' -a 'MyScanner/1.0' -k -r
```

- `-c` — raw `Cookie` header for authenticated areas.
- `-H` — any extra header, repeatable.
- `-a` — custom user agent (default `dirbrute/1.1.1`).
- `-k` — skip TLS certificate verification (self-signed lab servers).
- `-r` — follow redirects; 3xx findings are reported either way.

## Step 6 — save results, stay quiet

```console
$ ./dirbrute/dirbrute -u https://target/ -t 50 -o found.txt -q
```

`-o` mirrors the findings to a file while they still stream to stdout;
`-q` silences the stderr progress lines.

## Every flag

| Flag | Meaning |
| --- | --- |
| `-u` | target base URL, required (`http(s)://host[:port]`) |
| `-w` | wordlist file (default: embedded list) |
| `-t` | concurrent workers, 1–500 (default 20) |
| `-x` | comma separated extensions to probe |
| `-b` | status codes to ignore (default `404`) |
| `-exclude-length` | body sizes to ignore |
| `-a` | user agent |
| `-c` | raw Cookie header |
| `-H` | extra header, repeatable |
| `-r` | follow redirects |
| `-k` | skip TLS verification |
| `-q` | suppress progress output |
| `-timeout` | per-request timeout, 1–600 s (default 10) |
| `-o` | also write findings to this file |

## Gotchas

- The URL must include the scheme (`http://` or `https://`); the parser
  rejects bare hostnames.
- Redirect targets (301/302) are reported as findings with their status
  — follow them manually or pass `-r` if you want the tool to chase
  them.
- Keep `-t` within what the target can take; 500 workers against a
  small server is indistinguishable from a denial of service — and has
  the same legal consequences. Test only systems you are permitted to.

See also: [README](../../dirbrute/README.md) ·
[examples](../../examples/dirbrute/local-run.txt) ·
[next tutorial: hashcrack](hashcrack.md)

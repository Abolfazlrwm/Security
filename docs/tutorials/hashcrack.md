# Tutorial — hashcrack

`hashcrack` cracks MD5, SHA-1 and SHA-256 digests with a wordlist, an
optional rule chain and optional salting. It auto-detects the algorithm
from the digest length, needs only a bare Python 3.8+ (standard library
only), and works from a single hash or a whole file.

## Step 1 — a single hash

```console
$ python3 hashcrack/hashcrack.py --hash 5f4dcc3b5aa765d61d8327deb882cf99
[+] cracked 5f4dcc3b5aa765d61d8327deb882cf99 -> password
```

The algorithm is auto-detected (32 hex chars → MD5, 40 → SHA-1, 64 →
SHA-256); `--type sha256` forces one if you ever need to.

## Step 2 — a file of targets

```console
$ python3 hashcrack/hashcrack.py --hashes targets.txt
```

One digest per line; `#` comments and blank lines are allowed (see
[examples/hashcrack/demo-hashes.txt](../../examples/hashcrack/demo-hashes.txt)).
`--hash` is repeatable, so you can also mix:

```console
$ python3 hashcrack/hashcrack.py --hash 5f4dcc... --hashes more.txt
```

The wordlist path is `wordlist → bundled common-passwords.txt → built-in
list`, whichever exists first.

## Step 3 — rule chains

```console
$ python3 hashcrack/hashcrack.py --hash 0d491297649a8a4f7768f3e5784c52f1 --rules capitalize,append4
[+] cracked 0d491297649a8a4f7768f3e5784c52f1 -> Password2024
```

Rules apply in order to every wordlist entry:

| Rule | Effect |
| --- | --- |
| `lower` | `secret` → `secret` |
| `upper` | `secret` → `SECRET` |
| `capitalize` | `secret` → `Secret` |
| `reverse` | `secret` → `terces` |
| `leet` | `secret` → `s3cr3t` |
| `append1` | appends `0`–`9` (10 variants) |
| `append2` | appends `00`–`99` (100 variants) |
| `append4` | appends `0000`–`9999` (10,000 variants) |

Chains multiply: `capitalize,append4` turns 78 bundled words into
~780,000 candidates — the progress line shows the math, as captured in
[examples/hashcrack/demo-run.txt](../../examples/hashcrack/demo-run.txt):

```
[*] rules ['capitalize', 'append4'] expand 78 words to ~780,000 candidates
[*] finished: 1/1 cracked, 2,025 candidates, 389,433 h/s, 0.0s
```

## Step 4 — salted digests

```console
$ python3 hashcrack/hashcrack.py --hash 9b74c9897c5e0f6c8a2b5f1c2d3e4f5a --salt myapp --salt-position prefix
```

The salt is prepended (`prefix`) or appended (`suffix`, default) to
every candidate before hashing.

## Step 5 — keep the hits, quiet mode

```console
$ python3 hashcrack/hashcrack.py --hashes targets.txt -o cracked.txt -q
```

`-o` appends `digest:plain` pairs to a file; `-q` suppresses progress
lines and leaves only the `[+] cracked` results.

## Exit code behaviour

The tool exits `0` when everything cracked and `1` when at least one
digest survived the whole candidate space — handy in scripts:

```
[*] finished: 3/4 cracked, ...
# exit code 1: one digest intentionally needs the rule engine
```

## Every flag

| Flag | Meaning |
| --- | --- |
| `--hash` | target digest, repeatable |
| `--hashes FILE` | file with one digest per line |
| `-w, --wordlist` | wordlist file (default: bundled, then built-in) |
| `--rules` | comma separated rule chain, applied in order |
| `--type` | force `md5` / `sha1` / `sha256` instead of auto-detection |
| `--salt` | salt for every candidate |
| `--salt-position` | `prefix` or `suffix` (default `suffix`) |
| `-o, --found-file` | append `digest:plain` pairs to this file |
| `-q, --quiet` | suppress progress output |

## Gotchas

- Order matters in rule chains: `append2,capitalize` is different from
  `capitalize,append2`.
- `append4` is the heaviest rule (10k variants per word); combine it
  with a large wordlist only when you mean it.
- The tool measures and reports its hash rate; on a modern CPU expect
  ~300k–400k candidates/second — large wordlists × big rules take
  minutes, not seconds.

See also: [README](../../hashcrack/README.md) ·
[examples](../../examples/hashcrack/demo-run.txt) ·
[next tutorial: recon-pipeline](recon-pipeline.md)

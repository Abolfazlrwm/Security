# hashcrack

A small, honest hash cracker for MD5, SHA-1 and SHA-256. It streams a
wordlist, applies an ordered chain of mutation rules (the classic "rules"
workflow) and compares every candidate against your targets. Algorithms are
auto-detected from digest length unless `--type` pins one.

Uses only the Python standard library.

## Features

- **Three algorithms** — md5, sha1, sha256; mixed targets in one run are fine.
- **Rule chains** — rules apply in the given order, so `capitalize,append2`
  turns `admin` into `Admin00` ... `Admin99`.
- **Salting** — `--salt` with `--salt-position prefix|suffix` for salted dumps.
- **Labels** — target files accept `digest:label` so results print nicely.
- **Exit codes** — `0` when every target cracked, `1` otherwise, which makes
  it easy to script around.
- **Bounded rules** — an estimate of the candidate count is printed before
  the run so an `append4` chain on a big wordlist never surprises you.

## Usage

```console
# plain wordlist attack (algorithm auto-detected)
$ python3 hashcrack.py --hash 5f4dcc3b5aa765d61d8327deb882cf99
[+] cracked 5f4dcc3b5aa765d61d8327deb882cf99 -> password

# rule chain: admin -> Admin -> Admin12
$ python3 hashcrack.py --hash 2e6e5a2b38ba905790605c9b101497bc --rules capitalize,append2
[+] cracked 2e6e5a2b38ba905790605c9b101497bc -> Admin12

# batch file with labels, results saved for the report
$ python3 hashcrack.py --hashes targets.txt --rules append2 -o found.txt
```

## Rules

| Rule | Effect on `pass` |
| --- | --- |
| `lower` | `pass` |
| `upper` | `PASS` |
| `capitalize` | `Pass` |
| `reverse` | `ssap` |
| `leet` | `p4ss` |
| `append1` | `pass0` ... `pass9` |
| `append2` | `pass00` ... `pass99` |
| `append4` | `pass0000` ... `pass9999` |

## Options

| Flag | Description | Default |
| --- | --- | --- |
| `--hash` | Target digest, repeatable | — |
| `--hashes` | File with one digest per line | — |
| `-w, --wordlist` | Wordlist file | bundled `wordlists/common-passwords.txt` |
| `--rules` | Comma separated rule chain | none |
| `--type` | Force `md5`, `sha1` or `sha256` | auto by length |
| `--salt` | Salt for every candidate | none |
| `--salt-position` | `prefix` or `suffix` | suffix |
| `-o, --found-file` | Append `digest:plain` pairs to a file | — |
| `-q, --quiet` | Suppress progress output | off |

## Performance note

Hashing is CPU bound and the GIL keeps Python single threaded here — the
loop deliberately stays serial and rates of ~1M candidates/second are
typical on a modern CPU. For GPU-scale jobs use hashcat; this tool is for
quick audits, CTFs and teaching the rules workflow.

## Responsible use

Crack only hashes you are authorized to test — your own dumps, CTF
challenges or engagements with written permission.

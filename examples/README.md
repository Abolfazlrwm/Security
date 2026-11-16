# Examples

Captured output from real runs of the four tools in this repository.
Nothing here is hand-written or simulated: every file was produced by
executing the tool with the command shown next to it, and the artifacts
were only lightly touched to rewrite sandbox-absolute paths into
repository-relative ones.

| Artifact | Tool | Target | Notes |
| --- | --- | --- | --- |
| `dirbrute/local-run.txt` | dirbrute 1.1.1 | local demo webserver on `127.0.0.1:8080` | 13 paths found, wildcard baseline shown in the progress lines |
| `hashcrack/demo-hashes.txt`, `hashcrack/demo-run.txt` | hashcrack 1.1.1 | digests created for the demo | plain lookup, rule chain `capitalize,append4`, and a salted hash |
| `subdomain-enum/debian.org.json`, `subdomain-enum/run.txt` | subdomain-enum 1.2.0 | public domain `debian.org` | crt.sh was unreachable during the capture; all 15 names come from the verified DNS brute channel |
| `recon-pipeline/report.html`, `report.md`, `report.json`, `run.txt` | recon-pipeline 1.2.0 | same local demo webserver | host passed with `--hosts`, so the report records the subdomain phase as skipped; `report.html` is the self-contained dark-themed report - open it in a browser |

## Why most targets are local

Directory brute forcing and pipeline scans are active requests against a
webserver, so the captures were taken against a small throwaway server
(`127.0.0.1:8080`) with a deliberately interesting layout: a `.env` file,
an exposed `.git/` directory, an `admin` login page, a leftover
`backup.zip` and a few redirects. This keeps the demo reproducible and
avoids sending scan traffic at infrastructure nobody asked for. The
subdomain capture is passive DNS traffic, which is why a public domain
works fine there.

## Reproducing the captures

```bash
# 1. start a target webserver on 127.0.0.1:8080
# 2. build the Go tool
make build

# directory brute force
./dirbrute/dirbrute -u http://127.0.0.1:8080/ -t 10

# hash cracking (see demo-hashes.txt for the digests)
python3 hashcrack/hashcrack.py --hashes examples/hashcrack/demo-hashes.txt
python3 hashcrack/hashcrack.py --hash 0d491297649a8a4f7768f3e5784c52f1 --rules capitalize,append4
python3 hashcrack/hashcrack.py --hash 6b431529217a4ed5600c7d23247fdac4 --salt salt123 --salt-position prefix

# subdomain enumeration
python3 subdomain-enum/subdomain_enum.py debian.org --format json --threads 30

# full pipeline
python3 recon-pipeline/recon.py --hosts 127.0.0.1 --url http://127.0.0.1:8080 --scheme http --output-dir reports
```

# Examples

Captured output from real runs of the nine tools in this repository.
Nothing here is hand-written or simulated: every file was produced by
executing the tool with the command shown next to it, and the artifacts
were only lightly touched to rewrite sandbox-absolute paths into
repository-relative ones.

| Artifact | Tool | Target | Notes |
| --- | --- | --- | --- |
| `dirbrute/local-run.txt` | dirbrute 1.1.1 | local demo webserver on `127.0.0.1:8080` | 13 paths found, wildcard baseline shown in the progress lines |
| `hashcrack/demo-hashes.txt`, `hashcrack/demo-run.txt` | hashcrack 1.1.1 | digests created for the demo | plain lookup, rule chain `capitalize,append4`, and a salted hash |
| `subdomain-enum/debian.org.json`, `subdomain-enum/run.txt` | subdomain-enum 1.2.0 | public domain `debian.org` | crt.sh was unreachable during the capture; all 15 names come from the verified DNS brute channel |
| `port-scanner/scanme-run.txt` | port-scanner 1.0.0 | `scanme.nmap.org` (Nmap's public scan-me service) | top-100 list, 2 open ports (22 with an SSH banner, 80) in ~2 s |
| `takeover-check/hosts.txt`, `takeover-check/run.txt` | takeover-check 1.0.0 | `example.com`, `pages.github.com`, one unresolvable host | three verdict shapes: ok, claimed (real GitHub Pages CNAME) and unresolved — none vulnerable |
| `web-audit/example.com.txt` | web-audit 1.0.0 | public domain `example.com` | real TLS certificate, but none of the six security headers: 22/100, grade F |
| `jwt-analyzer/weak-hs256.txt`, `jwt-analyzer/alg-none.txt`, `jwt-analyzer/run.txt`, `jwt-analyzer/report.json` | jwt-analyzer 1.0.0 | tokens generated for the demo | token 1: HS256 signed with `secret123` — cracked by the built-in wordlist, exit 1; token 2: `alg: none` signature bypass, exit 1; `report.json` is the JSON report of the first run |
| `cve-lookup/scan.json`, `cve-lookup/run.txt`, `cve-lookup/report.json` | cve-lookup 1.0.0 | `scanme.nmap.org` via the official NVD API | the port-scanner JSON report from the row above, chained in with `--from-scan` — the OpenSSH 6.6.1p1 banner resolves to `openbsd:openssh:6.6.1` and 5 CVEs (2 critical, 1 CISA KEV); plus a `--cve CVE-2021-44228` lookup |
| `recon-pipeline/report.html`, `report.md`, `report.json`, `run.txt` | recon-pipeline 1.3.0 | same local demo webserver | host passed with `--hosts`, so the report records the subdomain phase as skipped; the port scan (8080/tcp open), the web audit (3/100, grade F) and dirbrute (13 findings) all ran; `report.html` is the self-contained dark-themed report - open it in a browser |

## Why most targets are local (or explicitly public)

Directory brute forcing, port scanning, auditing and pipeline scans are
active requests, so the active captures were taken either against a small
throwaway server (`127.0.0.1:8080`) with a deliberately interesting layout —
a `.env` file, an exposed `.git/` directory, an `admin` login page, a
leftover `backup.zip` and a few redirects — or against targets that exist
to be probed publicly: `scanme.nmap.org` (run by Nmap for exactly this) and
`example.com` (IANA reserved for documentation). This keeps the demo
reproducible and avoids sending scan traffic at infrastructure nobody
asked for. The subdomain capture is passive DNS traffic, which is why a
public domain works fine there. The takeover-check capture only performs
DNS lookups and plain GET requests on its three hosts.

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

# port scan (Nmap's public scan-me target)
python3 port-scanner/port_scanner.py scanme.nmap.org --top 100

# takeover check (see hosts.txt for the three demo hosts)
python3 takeover-check/takeover_check.py -f examples/takeover-check/hosts.txt

# web audit (IANA reserved documentation domain)
python3 web-audit/web_audit.py example.com

# jwt audit (tokens shipped in examples/jwt-analyzer/)
python3 jwt-analyzer/jwt_analyzer.py "$(cat examples/jwt-analyzer/weak-hs256.txt)"
python3 jwt-analyzer/jwt_analyzer.py "$(cat examples/jwt-analyzer/alg-none.txt)"

# CVE lookup chained from a port scan (official NVD API, rate limited)
python3 port-scanner/port_scanner.py scanme.nmap.org --ports 22,80 --format json --output scan.json
python3 cve-lookup/cve_lookup.py --from-scan scan.json
python3 cve-lookup/cve_lookup.py --cve CVE-2021-44228

# full pipeline
python3 recon-pipeline/recon.py --hosts 127.0.0.1 --url http://127.0.0.1:8080 --scheme http --output-dir reports
```

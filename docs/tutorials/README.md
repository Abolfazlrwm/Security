# Tutorials

Step-by-step guides for every tool in the toolkit. Each tutorial uses
only flags that exist in the shipped code and shows the real output
shape captured in [examples/](../../examples/).

| Tutorial | Tool | What you will learn |
| --- | --- | --- |
| [subdomain-enum](subdomain-enum.md) | Python | Enumerate live subdomains via crt.sh and DNS brute force, save JSON, tune threads and resolvers |
| [dirbrute](dirbrute.md) | Go | Brute-force directories, filter wildcard noise, probe extensions, authenticate with cookies and headers |
| [hashcrack](hashcrack.md) | Python | Crack MD5/SHA-1/SHA-256 digests, build rule chains, handle salted digests |
| [recon-pipeline](recon-pipeline.md) | Python | Chain everything into one run and read the generated reports |

## Getting the tools

**Option 1 — prebuilt binaries (no runtime needed).** Download from the
[releases](https://github.com/Abolfazlrwm/Security/releases) page:
[subdomain-enum-v1.2.0](https://github.com/Abolfazlrwm/Security/releases/tag/subdomain-enum-v1.2.0),
[dirbrute-v1.1.1](https://github.com/Abolfazlrwm/Security/releases/tag/dirbrute-v1.1.1) and
[hashcrack-v1.1.1](https://github.com/Abolfazlrwm/Security/releases/tag/hashcrack-v1.1.1)
each carry binaries for every supported platform plus `checksums.txt`.
Verify, chmod and run:

```console
$ sha256sum -c checksums.txt
$ chmod +x dirbrute-1.1.1-linux-amd64
$ ./dirbrute-1.1.1-linux-amd64 -u https://target/ -t 30
```

**Option 2 — from source.** The Python tools need only a bare
`python3` (3.8+, standard library only); dirbrute needs Go 1.19+:

```console
$ git clone https://github.com/Abolfazlrwm/Security.git
$ cd Security
$ make build                   # compile dirbrute
$ python3 subdomain-enum/subdomain_enum.py --help
```

recon-pipeline always runs from source — it chains the other tools.

## Ground rule

These tools are for **authorized** testing only: systems you own, lab
environments, CTFs or engagements with explicit written permission.
Scanning systems you are not permitted to test is illegal in most
jurisdictions. The safe demo target used throughout these tutorials is
a local webserver (`127.0.0.1`), exactly like the captured runs in
[examples/](../../examples/).

# jwt-analyzer

Decode, verify and audit JSON Web Tokens — entirely offline, in a single
script. The tool splits the compact token, prints the header and claims in
a readable table, verifies HS256/384/512 signatures against a secret you
supply, runs a dictionary attack against HMAC tokens with a built-in list
of the secrets that show up in tutorials and bug bounty reports, and
collects severity-ranked findings for the classic JWT pitfalls.

Uses only the Python standard library (3.8+). No network requests.

## Features

- **Full decode** — header, claims and signature size, with `exp` / `iat` /
  `nbf` / `auth_time` rendered as UTC timestamps next to their numeric
  values.
- **HMAC verification** — `--secret` checks HS256/HS384/HS512 signatures
  with a constant-time comparison.
- **Weak-secret dictionary attack** — 70+ built-in candidates
  (`secret`, `your-256-bit-secret`, `keyboard cat`, `changeme`, ...) plus
  an optional `--wordlist` file; the cracked secret is printed in the
  report and marked CRITICAL.
- **alg=none detection** — the signature-bypass classic is flagged
  CRITICAL, along with tokens that declare no algorithm at all.
- **Key-header injection warnings** — `jku`, `jwk` and `x5u` headers, and
  `kid` values containing path characters, are flagged HIGH.
- **Claim hygiene** — missing `exp` (HIGH), expired tokens (MEDIUM),
  future-dated `iat`/`nbf` (MEDIUM), long lifetimes > 30 days (LOW),
  asymmetric algorithms noted as not verifiable offline (INFO).
- **JSON or plain text output** — exit code 1 when a CRITICAL finding
  exists, 2 for malformed input, so scripts and CI can react.

## Usage

```console
$ python3 jwt_analyzer.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
$ python3 jwt_analyzer.py "$TOKEN" --secret "$HS_SECRET"
$ python3 jwt_analyzer.py "$TOKEN" --wordlist extra-secrets.txt
$ python3 jwt_analyzer.py "$TOKEN" --format json -o report.json
$ python3 jwt_analyzer.py "$TOKEN" --no-crack --now 2026-11-16T00:00:00Z
```

## Output

```text
JWT analysis - alg HS256

Header
  alg         "HS256"
  typ         "JWT"

Claims
  sub         "admin"
  iat         2025-01-01T00:00:00Z  (numeric 1735689600)
  exp         2030-12-31T08:00:00Z  (numeric 1924934400)

Signature
  32 bytes of signature
  dictionary attack: CRACKED -> 'secret123'

Findings
  [CRITICAL] weak HMAC secret cracked: 'secret123'
             matched built-in list after 70 candidate(s)
  [LOW     ] token lifetime is 2190 days
             long-lived tokens widen the window for replay attacks

Summary: 1 critical, 0 high, 0 medium, 1 low, 0 info
```

A captured run with both a cracked token and an `alg=none` token is in
[examples/jwt-analyzer/](../examples/jwt-analyzer/).

## Severity model

| Severity | Triggered by |
| --- | --- |
| `CRITICAL` | `alg: none`, missing `alg`, weak HMAC secret cracked |
| `HIGH` | missing `exp`, attacker-controlled key headers, `kid` path characters, signature mismatch with `--secret` |
| `MEDIUM` | expired token, `exp` not a numeric date, `iat`/`nbf` in the future |
| `LOW` | token lifetime longer than 30 days |
| `INFO` | asymmetric algorithm (RS/PS/ES/EdDSA) cannot be verified offline, unusual `typ` |

## How the dictionary attack works

For HS* tokens the signature is `HMAC(secret, base64url(header) + "." +
base64url(payload))`. The tool recomputes that HMAC for every candidate
secret from the built-in list (plus your `--wordlist`) and compares with
`hmac.compare_digest`. Everything runs in memory — a few thousand
candidates per second per core, which is exactly the point: *real
verification code should be doing this too*.

## Responsible use

Analyse tokens you own or have explicit permission to test — your own
sessions, your lab, your CTF targets. A cracked secret in a pentest report
means "rotate the signing key", not "keep scanning".

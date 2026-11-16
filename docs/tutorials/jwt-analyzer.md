# Tutorial — jwt-analyzer

`jwt-analyzer` audits JSON Web Tokens offline: it decodes the header and
claims, verifies HMAC signatures, tries the classic weak secrets and
collects severity-ranked findings. This tutorial walks through the two
demo tokens captured in
[examples/jwt-analyzer/](../../examples/jwt-analyzer/run.txt) — one signed
with a secret the dictionary attack cracks, one with `alg: none`.

## Step 1 — decode a token

```console
$ python3 jwt-analyzer/jwt_analyzer.py "$(cat examples/jwt-analyzer/weak-hs256.txt)"
```

The output has four sections. **Header** shows the algorithm and key
metadata; **Claims** renders `exp`/`iat`/`nbf` as UTC timestamps next to
their numeric values (`iat 2025-01-01T00:00:00Z  (numeric 1735689600)`);
**Signature** reports the size and the result of the secret checks;
**Findings** lists everything worth fixing, most severe first:

```text
JWT analysis - alg HS256
...
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

The exit code matters in scripts: **0** when no CRITICAL finding exists,
**1** when one does, **2** for malformed input (including five-segment
JWEs, which the tool points out instead of pretending to analyse).

## Step 2 — the alg=none bypass

```console
$ python3 jwt-analyzer/jwt_analyzer.py "$(cat examples/jwt-analyzer/alg-none.txt)"
```

This token carries `{"alg": "none", ...}` and **no signature at all** —
the 1990s-era forgery that still works against servers which call a
"decode" function and never check anything:

```text
Findings
  [CRITICAL] alg "none" - signature bypass
             servers that skip verification accept this token from anyone
  [HIGH    ] token never expires
             no exp claim in the payload
```

## Step 3 — verify against the real secret

```console
$ python3 jwt-analyzer/jwt_analyzer.py "$TOKEN" --secret "$HS_SECRET" --no-crack
```

`--secret` verifies HS256/HS384/HS512 signatures with a constant-time
comparison and prints `matches the provided secret: yes` — or `NO`, which
means the token was tampered with or you have the wrong key (flagged
HIGH). `--no-crack` skips the dictionary attack when you already know the
secret and just want the audit.

## Step 4 — dictionary attack with your own wordlist

```console
$ python3 jwt-analyzer/jwt_analyzer.py "$TOKEN" --wordlist my-secrets.txt
```

Out of the box the tool tries 70+ candidates — `secret`, `secret123`,
`your-256-bit-secret` (yes, the one from jwt.io documentation), `keyboard
cat`, `changeme`, ... Add `--wordlist` for app-specific secrets; one
candidate per line, duplicates are dropped. The wordlist shipped in
[jwt-analyzer/wordlists/](../../jwt-analyzer/wordlists/secrets.txt)
extends the built-ins with the classics from tutorials and bug bounty
reports.

## Step 5 — audit with a fixed reference time

```console
$ python3 jwt-analyzer/jwt_analyzer.py "$TOKEN" --now 2026-11-16T00:00:00Z
```

`--now` accepts ISO-8601 (with `Z` or offset) or unix seconds and makes
the expiry findings reproducible — CI runs, classrooms and screenshots all
agree on what "expired" means. Without it, the current time is used.

## Step 6 — JSON reports

```console
$ python3 jwt-analyzer/jwt_analyzer.py "$TOKEN" --format json -o report.json
```

The JSON report carries `algorithm`, `header`, `claims`,
`signature_verified`, the `secret_check` result, the full `findings` array
and a `summary` count per severity — the same shape captured in
[examples/jwt-analyzer/report.json](../../examples/jwt-analyzer/report.json).

## What the severities mean

| Severity | Typical finding |
| --- | --- |
| CRITICAL | `alg: none`, missing `alg`, weak HMAC secret cracked |
| HIGH | no `exp` claim, `jku`/`jwk`/`x5u` key headers, `kid` with path characters, signature mismatch |
| MEDIUM | expired token, non-numeric `exp`, `iat`/`nbf` in the future |
| LOW | lifetime over 30 days |
| INFO | asymmetric algorithm (RS/PS/ES/EdDSA) — needs the public key, not verifiable offline |

## Ground rules

Analyse tokens you own or have permission to test: your own sessions, your
lab, your CTF targets. Everything is offline — the tool never sends the
token or the secret anywhere — but a cracked secret is a finding, not a
trophy: rotate the signing key and shorten the token lifetime.

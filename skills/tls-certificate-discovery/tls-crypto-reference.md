# TLS Cryptography, Vulnerability & Certificate Reference

Supporting reference for the `tls-certificate-discovery` skill. Load this when
triaging `ssl-enum-ciphers` / `testssl.sh` output or a captured certificate.

Same discipline as the SSH reference: a version or cipher match is a **triage
signal**, not a confirmed finding, until confirmed against the live handshake.

---

## Protocol Versions

| Version | Status | Note |
|---|---|---|
| SSLv2 | **Critical — remove** | DROWN (CVE-2016-0800). Its mere support breaks TLS on the *same key* |
| SSLv3 | **Critical — remove** | POODLE (CVE-2014-3566) |
| TLS 1.0 | **Deprecated** | Formally deprecated by **RFC 8996** (2021). BEAST, downgrade |
| TLS 1.1 | **Deprecated** | RFC 8996. No modern reason to keep it |
| TLS 1.2 | Acceptable | Fine with a strong cipher list |
| TLS 1.3 | Preferred | AEAD-only, forward-secret by design, no legacy KEX |

**Baseline:** TLS 1.2 + 1.3 only. Anything below TLS 1.2 is a finding on
current systems.

---

## Vulnerability Matrix

| Name | CVE | Precondition | Impact | Detect |
|---|---|---|---|---|
| Heartbleed | CVE-2014-0160 | OpenSSL 1.0.1–1.0.1f, heartbeat ext | Memory disclosure incl. private key | `ssl-heartbleed`, testssl |
| ROBOT | CVE-2017-6168 (+others) | RSA key-exchange cipher suites | Decrypt/sign with server private key | testssl `--robot` |
| DROWN | CVE-2016-0800 | SSLv2 enabled *anywhere* on the key | Decrypt TLS sessions | `sslv2-drown` |
| POODLE | CVE-2014-3566 | SSLv3 with CBC | Plaintext recovery | `ssl-poodle` |
| CCS Injection | CVE-2014-0224 | OpenSSL pre-1.0.1h | MitM key injection | `ssl-ccs-injection` |
| Ticketbleed | CVE-2016-9244 | F5 BIG-IP | Memory disclosure | testssl |
| Sweet32 | CVE-2016-2183 | 3DES / 64-bit block cipher | Session recovery over long conns | `ssl-enum-ciphers` grades it |
| Logjam | CVE-2015-4000 | DHE with ≤1024-bit / export DH | Downgrade + break DH | `ssl-dh-params` |
| FREAK | CVE-2015-0204 | Export RSA cipher suites | Downgrade to breakable RSA | `ssl-enum-ciphers` |
| BEAST | CVE-2011-3389 | TLS 1.0 CBC | Plaintext recovery (client-side) | Protocol = TLS 1.0 |
| CRIME | CVE-2012-4929 | TLS compression | Session hijack | testssl |
| BREACH | CVE-2013-3587 | HTTP compression + secrets | Session-token recovery | App-layer |

`testssl.sh` covers this whole table in one run; the NSE column is the Nmap
equivalent per row where one exists.

---

## Cipher Suites

| Class | Examples | Status |
|---|---|---|
| TLS 1.3 AEAD | `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` | Preferred |
| ECDHE + AEAD | `ECDHE-ECDSA-AES256-GCM-SHA384`, `ECDHE-RSA-AES128-GCM-SHA256` | Strong — forward secret |
| ECDHE + CBC | `ECDHE-RSA-AES256-SHA384` | Acceptable — CBC, no AEAD |
| Static RSA KEX | `AES256-GCM-SHA384` (no ECDHE/DHE) | **Weak** — no forward secrecy, ROBOT surface |
| 3DES | `ECDHE-RSA-DES-CBC3-SHA` | **Weak** — Sweet32, 64-bit block |
| RC4 | `ECDHE-RSA-RC4-SHA` | **Critical** — broken keystream |
| Export | `EXP-*` | **Critical** — FREAK/Logjam, deliberately weak |
| NULL / anon | `NULL-SHA`, `ADH-*` | **Critical** — no encryption / no auth |

**Two properties to check beyond the name:**
- **Forward secrecy** — the suite must use ECDHE or DHE, not static RSA
  key exchange. Without it, one stolen private key decrypts all past traffic.
- **DH parameter strength** — DHE with < 2048-bit groups is Logjam-exposed;
  `ssl-dh-params` flags weak and known-common groups.

---

## Certificate Findings

| Finding | Why it matters | Check |
|---|---|---|
| Expired / not-yet-valid | Clients error or, worse, are trained to click through | `-checkend`, `-dates` |
| Expiring < 30 days | Operational — outage risk | days-to-expiry math (SKILL Step 4) |
| Self-signed | No chain of trust; MitM indistinguishable | issuer == subject |
| Name mismatch | CN/SAN doesn't cover the host served | `-ext subjectAltName` vs host |
| CN-only, no SAN | Modern clients **reject** it — SANs are mandatory | `-ext subjectAltName` empty |
| Weak signature (SHA-1, MD5) | Forgeable chain | `Signature Algorithm` |
| RSA key < 2048-bit | Below current floor | `Public-Key:` bits |
| Debian weak key (2006–2008) | Private key is in a known small set → derivable | `ssl-known-key` |
| Wildcard over-scope | `*.example.com` on a low-trust host risks the whole domain | subject/SAN |
| Long validity (> 398 days) | Rejected by modern browsers (public CAs) | `-dates` |

### The Debian weak-key case (2006–2008)

A Debian OpenSSL bug (2006–2008) seeded key generation from almost no entropy,
so the entire keyspace for affected sizes is enumerable — anyone can derive the
private key from the public one. It affected SSH, TLS, OpenVPN and more. Nmap's
`ssl-known-key` checks a certificate's key against the blocklist. This is the
TLS twin of the SSH host-key-reuse finding in `ssh-crypto-reference.md`: same
root cause (no entropy at generation), same severity (key compromise).

---

## Reading a Grade

SSL Labs' scoring, which `testssl.sh` mirrors, weights:

- **Protocol support ~30%** — presence of TLS 1.0/1.1 or worse caps the grade
- **Key exchange ~30%** — forward secrecy and DH/RSA key strength
- **Cipher strength ~30%** — AEAD vs CBC, key length
- **Qualitative caps** — a single critical vuln (Heartbleed, ROBOT, DROWN,
  broken chain) **caps the grade at F** regardless of the other three

So a server can offer perfect TLS 1.3 ciphers and still be an F because SSLv2
is enabled on the same key (DROWN). Read the caps first, the ciphers second.

---

## Hardening Baseline

```nginx
# nginx — TLS 1.2/1.3 only, forward-secret AEAD, OCSP stapling
ssl_protocols            TLSv1.2 TLSv1.3;
ssl_ciphers              ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;   # let TLS 1.3 clients choose; irrelevant for 1.3
ssl_ecdh_curve           X25519:secp384r1;
ssl_session_tickets      off;
ssl_stapling             on;
ssl_stapling_verify      on;
add_header Strict-Transport-Security "max-age=63072000" always;
```

Generate a strong DH group if any DHE suite is retained:

```bash
openssl dhparam -out /etc/nginx/dhparam.pem 2048   # or 4096
```

Verify with `testssl.sh` after applying; aim for no findings below TLS 1.2 and
an A or A+.

---

## References

- Aviram et al., *DROWN: Breaking TLS using SSLv2*, USENIX Security 2016
- Böck, Somorovsky & Young, *Return Of Bleichenbacher's Oracle Threat (ROBOT)*,
  USENIX Security 2018 — <https://robotattack.org/>
- Adrian et al., *Imperfect Forward Secrecy: How Diffie-Hellman Fails in
  Practice* (Logjam), CCS 2015
- RFC 8996, *Deprecating TLS 1.0 and TLS 1.1*, IETF 2021
- Heninger et al., *Mining Your Ps and Qs*, USENIX Security 2012 (weak keys)
- Debian SSLkeys — <https://wiki.debian.org/SSLkeys>
- `testssl.sh` — <https://testssl.sh/>
- Nmap `ssl-enum-ciphers`, `ssl-cert`, `ssl-*` NSE — <https://nmap.org/nsedoc/>

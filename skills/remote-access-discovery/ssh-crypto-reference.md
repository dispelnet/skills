# SSH Cryptography & CVE Reference

> **Scope gate — this file belongs to the `remote-access-discovery` skill.**
> The probes here interact with live SSH services.
> **Do not run anything here until that skill's Hard Rules have been
> satisfied and the target confirmed.** If you loaded this file on its own,
> read `SKILL.md` first.

Supporting reference for the `remote-access-discovery` skill. Load this when
triaging findings from `ssh-audit` or `ssh2-enum-algos`, or when mapping a
banner version to concrete exposure.

**Every version-based finding in this file requires host-side confirmation.**
See "The backporting caveat" in `SKILL.md`.

**Variables** (`$TARGET`, `$SUBNET`, `$IFACE`, …) are the ones set in the
**Set these first** block of `SKILL.md`, except where a script below defines
its own.

---

## CVE Matrix — Server Side

| CVE | Name | Affected | Fixed | Precondition | Impact |
|---|---|---|---|---|---|
| CVE-2024-6387 | regreSSHion | 8.5p1 – 9.7p1 | 9.8p1 | glibc Linux, `LoginGraceTime` > 0 | Unauth **RCE as root** |
| CVE-2006-5051 | (original race) | < 4.4p1 | 4.4p1 | Same signal handler race | Unauth RCE as root |
| CVE-2023-48795 | Terrapin | < 9.6p1 | 9.6p1 | Negotiated cipher/MAC below | MitM prefix truncation |
| CVE-2002-20001 | DHEat | Any, unthrottled | Config | DH KEX offered, no rate limit | Remote **DoS**, low cost |
| CVE-2024-6409 | (privsep race) | 8.7p1, 8.8p1 | Vendor patch | Red Hat / downstream builds | RCE in privsep child |
| CVE-2025-26466 | (pre-auth DoS) | 9.5p1 – 9.9p1 | 9.9p2 | None | Memory/CPU exhaustion |
| CVE-2026-59996 | (scp path traversal) | ≤ 10.3 | 10.4 | Attacker-controlled remote path | File written to parent directory |
| CVE-2026-59995 | (sftp path handling) | ≤ 10.3 | 10.4 | Attacker-controlled remote path | Download steered to unexpected path |
| CVE-2023-38408 | ssh-agent PKCS#11 | < 9.3p2 | 9.3p2 | Agent forwarded to hostile host | RCE via agent |
| CVE-2018-15473 | user enumeration | < 7.7 | 7.7 | None | Valid usernames disclosed |
| CVE-2020-15778 | `scp` injection | ≤ 8.3p1 | (wontfix) | `scp` with attacker-controlled path | Command injection |

### Client Side

| CVE | Affected | Fixed | Precondition | Impact |
|---|---|---|---|---|
| CVE-2025-26465 | 6.8p1 – 9.9p1 | 9.9p2 | `VerifyHostKeyDNS=yes` | MitM — host identity bypass |
| CVE-2026-60002 | ≤ 10.3 | 10.4 | Client connects to hostile server | Use-after-free (CVSS 7.7) |

> **Currency check.** OpenSSH 10.4 (July 2026) shipped eight security fixes,
> and **10.5 is current as of 2026-08-11**. This matrix is a snapshot — always
> reconcile against <https://www.openssh.com/security.html> before reporting,
> because a CVE published after this file was written will not appear here.

> Client CVEs matter on an internal audit: jump boxes, CI runners, and
> orchestration nodes are SSH *clients* at scale. Enumerating only listening
> services misses them entirely.

---

## Terrapin (CVE-2023-48795) — Exact Preconditions

Terrapin is **not** simply "OpenSSH < 9.6p1." The attack requires a
vulnerable cipher/MAC combination to actually be negotiated:

**Vulnerable when the negotiated suite is either:**
1. `chacha20-poly1305@openssh.com` (any MAC), **or**
2. any `*-cbc` cipher **combined with** an `*-etm@openssh.com` MAC

A server offering only `aes*-ctr` with `hmac-sha2-*-etm` is not exploitable
even on an unpatched version.

**Detecting the fix directly.** OpenSSH 9.6p1+ advertises strict key exchange
as a pseudo-algorithm in the KEX list. Grep for it rather than guessing from
the version:

```bash
nmap --script ssh2-enum-algos -p 22 $TARGET | grep -i 'kex-strict'
# kex-strict-s-v00@openssh.com   ← server supports strict KEX
```

**Strict KEX only protects when both sides support it.** A patched server
talking to an unpatched client still yields a vulnerable connection, so
"the servers are patched" does not close this finding on its own.

`ssh-audit` reports Terrapin status directly and is the preferred check.

---

## DHEat (CVE-2002-20001)

A Diffie-Hellman exhaustion DoS: the server performs expensive modular
exponentiation before authentication, so an attacker spends far less CPU than
the target. It is a **configuration** issue, not a version issue — patching
OpenSSH does not fix it.

**Mitigations:** connection rate limiting (`MaxStartups`, firewall/fail2ban
throttling), or removing finite-field DH KEX in favour of curve25519.

```bash
# ssh-audit infers susceptibility safely, without a real flood:
ssh-audit $TARGET

# Explicit rate test — GENERATES REAL LOAD. Authorized targets only,
# and never against production during business hours.
ssh-audit --dheat=$SOCKETS $TARGET
```

---

## Algorithm Risk Tables

### Key Exchange

| Algorithm | Status |
|---|---|
| `sntrup761x25519-sha512@openssh.com` | Preferred — post-quantum hybrid |
| `curve25519-sha256`, `...@libssh.org` | Strong |
| `diffie-hellman-group16/18-sha512` | Acceptable |
| `diffie-hellman-group-exchange-sha256` | Acceptable if moduli ≥ 3072-bit |
| `diffie-hellman-group14-sha1` | **Weak** — SHA-1 based |
| `diffie-hellman-group-exchange-sha1` | **Weak** — SHA-1 |
| `diffie-hellman-group1-sha1` | **Critical** — 1024-bit, Logjam |
| `gss-*` | Review — GSSAPI/Kerberos dependent |

### Host Key

| Algorithm | Status |
|---|---|
| `ssh-ed25519` | Preferred |
| `rsa-sha2-512`, `rsa-sha2-256` | Strong (RSA with SHA-2) |
| `ecdsa-sha2-nistp*` | Acceptable — NIST curve provenance concerns |
| `ssh-rsa` | **Weak** — SHA-1 signature, disabled by default in 8.8+ |
| `ssh-dss` | **Critical** — 1024-bit DSA, removed in 7.0 |

### Ciphers

| Algorithm | Status |
|---|---|
| `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com` | Preferred |
| `aes*-ctr` | Strong |
| `chacha20-poly1305@openssh.com` | Strong, but **Terrapin-exposed** below 9.6p1 |
| `aes*-cbc` | **Weak** — Terrapin vector when paired with EtM MAC |
| `3des-cbc`, `blowfish-cbc`, `cast128-cbc` | **Critical** — legacy, 64-bit block |
| `arcfour`, `arcfour128`, `arcfour256` | **Critical** — broken RC4 |
| `none` | **Critical** — no encryption |

### MACs

| Algorithm | Status |
|---|---|
| `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256-etm@openssh.com` | Preferred — encrypt-then-MAC |
| `hmac-sha2-512`, `hmac-sha2-256` | Acceptable — MAC-then-encrypt |
| `umac-128-etm@openssh.com` | Strong |
| `hmac-sha1`, `hmac-sha1-etm@openssh.com` | **Weak** — SHA-1 |
| `hmac-md5*`, `umac-64*` | **Critical** — broken or 64-bit tag |
| `hmac-*-96` | **Critical** — truncated tag |

---

## Host Key Reuse — A Key Compromise Signal

Identical host keys across multiple hosts are commonly dismissed as a golden
image artefact. The research says treat it as a **key compromise indicator**.

Heninger, Durumeric, Wustrow & Halderman, *Mining Your Ps and Qs: Detection of
Widespread Weak Keys in Network Devices* (USENIX Security 2012, Best Paper),
scanned the IPv4 Internet and found:

- **1.03% of SSH hosts** leaked recoverable **DSA private keys** through
  insufficient signature randomness
- **0.03% of SSH hosts** had RSA keys factorable via shared common prime
- The overwhelming majority were headless or embedded devices generating keys
  at first boot, before `/dev/urandom` had accumulated entropy

So a repeated host key means either (a) a cloned image, where compromising one
host compromises every sibling, or (b) a low-entropy generator, where the key
may be derivable by anyone. Both warrant regeneration, not a note.

```bash
# Collect fingerprints subnet-wide and cluster by key
nmap --script ssh-hostkey -p 22 --open $SUBNET -oN hostkeys.txt

# Any fingerprint appearing more than once is a finding
grep -oE '[0-9a-f:]{47}|AAAA[A-Za-z0-9+/=]+' hostkeys.txt \
  | sort | uniq -c | sort -rn | awk '$1 > 1'
```

**Remediation:** delete `/etc/ssh/ssh_host_*` and run
`ssh-keygen -A` on each affected host, then redistribute
`known_hosts` / SSHFP records.

---

## Hardening Baseline (`sshd_config`)

A baseline that closes every algorithm finding above. Verify with
`ssh-audit` after applying, and confirm you retain access before
disconnecting your current session.

```sshd_config
# Terrapin: drop CBC entirely, keep AEAD/CTR
Ciphers                 aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs                    hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms           sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
HostKeyAlgorithms       ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256

# Authentication
PermitRootLogin         no
PasswordAuthentication  no
KbdInteractiveAuthentication no
PubkeyAuthentication    yes

# regreSSHion mitigation when patching is not yet possible.
# NOTE: 0 disables the grace timeout, which removes the race but
# increases exposure to connection-slot exhaustion. Pair with MaxStartups.
LoginGraceTime          0
MaxStartups             10:30:60
MaxAuthTries            3
```

Regenerate weak moduli — required if you keep any finite-field DH KEX:

```bash
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
mv /etc/ssh/moduli.safe /etc/ssh/moduli
```

Validate before restarting — a syntax error locks you out:

```bash
sshd -t && systemctl reload ssh
```

---

## References

- OpenSSH release notes — <https://www.openssh.com/releasenotes.html>
- OpenSSH security page (authoritative CVE list) — <https://www.openssh.com/security.html>
- Terrapin attack — <https://terrapin-attack.com/> · Bäumer, Brinkmann &
  Schwenk, *Terrapin Attack: Breaking SSH Channel Integrity by Sequence
  Number Manipulation*, USENIX Security 2024
- regreSSHion — Qualys Threat Research Unit advisory, July 2024
- DHEat — <https://dheatattack.com/>
- Heninger et al., *Mining Your Ps and Qs*, USENIX Security 2012 —
  <https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/heninger>
- `ssh-audit` — <https://github.com/jtesta/ssh-audit>

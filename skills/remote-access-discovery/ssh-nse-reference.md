# SSH NSE Script Reference

> **Scope gate — this file belongs to the `remote-access-discovery` skill.**
> `ssh-auth-methods` opens a real authentication conversation and lands in the target's auth log.
> **Do not run anything here until that skill's Hard Rules have been
> satisfied and the target confirmed.** If you loaded this file on its own,
> read `SKILL.md` first.

Supporting reference for the `remote-access-discovery` skill. Load this when `ssh-audit` is unavailable or when a specific algorithm, host-key or auth-method question needs a targeted probe. Note that `ssh-auth-methods` is an authentication probe — see the Hard Rules in `SKILL.md` before running it.

**Variables** (`$TARGET`, `$SUBNET`, `$IFACE`, …) are the ones set in the
**Set these first** block of `SKILL.md`, except where a script below defines
its own.

---

## Step 5 — SSH NSE Scripts (Targeted Follow-Up)

Use these only for what `ssh-audit` does not cover. Check the NSE category
before running anything here — it determines whether the target logs you.

```bash
ls /usr/share/nmap/scripts/ssh*
```

| Script | Category | Safe to sweep? |
|---|---|---|
| `ssh-hostkey` | `safe`, `default` | Yes — reads keys during KEX, no auth |
| `ssh2-enum-algos` | `safe` | Yes — no auth |
| `sshv1` | `safe` | Yes — protocol probe only |
| `ssh-auth-methods` | **`intrusive`**, `auth` | **No** — starts an auth attempt |
| `ssh-publickey-acceptance` | **`intrusive`**, `auth` | **No** — offers keys |
| `ssh-brute` | **`intrusive`**, `brute` | **Never** without written authorisation |
| `ssh-run` | **`intrusive`** | **Never** — executes commands, needs creds |

Verify a category yourself before trusting any list:

```bash
nmap --script-help ssh-auth-methods | grep -i categories
```

### `ssh-keyscan` — bulk host key collection (no Nmap needed)

`ssh-keyscan` ships with OpenSSH itself. For the duplicate-key check it beats
the NSE script: it reads a host list natively, parallelises, never
authenticates, and emits `known_hosts` format directly.

```bash
# Collect every host key type from every SSH host found in Step 1
ssh-keyscan -t rsa,ecdsa,ed25519 -f ssh-hosts.txt > collected-keys.txt

ssh-keyscan -p 2222 $TARGET          # non-standard port
ssh-keyscan -T 5 -f ssh-hosts.txt         # shorter timeout for dead hosts

# Fingerprints rather than raw keys
ssh-keyscan -f ssh-hosts.txt | ssh-keygen -lf -
```

Cluster the fingerprints — any key appearing on more than one host is the
finding described in `ssh-crypto-reference.md`:

```bash
ssh-keyscan -t rsa,ecdsa,ed25519 -f ssh-hosts.txt 2>/dev/null \
  | ssh-keygen -lf - \
  | awk '{print $2}' | sort | uniq -c | sort -rn | awk '$1 > 1'
```

`ssh-keyscan` writes progress to stderr and keys to stdout, so redirect
stderr when scripting it.

### `ssh-hostkey` — retrieve host public keys
```bash
nmap --script ssh-hostkey -p 22 $TARGET

# Show full key (not just fingerprint)
nmap --script ssh-hostkey --script-args ssh_hostkey=full -p 22 $TARGET
```
Output:
```
22/tcp open  ssh
| ssh-hostkey:
|   ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB...
|   ecdsa-sha2-nistp256 AAAAE2VjZH...
|_  ssh-ed25519 AAAAC3NzaC1lZDI1N...
```
Host keys should be unique per machine. Identical keys across multiple hosts
mean either a cloned golden image — where compromising one host compromises
every sibling — or low-entropy key generation, where the private key may be
independently derivable. Treat it as a **key compromise indicator**, not a
hygiene note; see `ssh-crypto-reference.md` for the measurement data and the
subnet-wide fingerprint clustering recipe.

### `ssh2-enum-algos` — enumerate supported algorithms
```bash
nmap --script ssh2-enum-algos -p 22 $TARGET
```
Output:
```
22/tcp open  ssh
| ssh2-enum-algos:
|   kex_algorithms: (6)
|       curve25519-sha256
|       ecdh-sha2-nistp256
|       diffie-hellman-group-exchange-sha256
|       diffie-hellman-group14-sha1       ← weak, flag this
|   server_host_key_algorithms: (3)
|       ssh-rsa
|       ecdsa-sha2-nistp256
|       ssh-ed25519
|   encryption_algorithms: (4)
|       aes128-ctr
|       aes256-ctr
|       3des-cbc                          ← legacy, flag this
|   mac_algorithms: (4)
|       hmac-sha2-256
|       hmac-sha1                         ← weak, flag this
|   compression_algorithms: (2)
|       none
|_      zlib@openssh.com
```

**Flags to look for:**
| Algorithm                              | Risk                         |
|----------------------------------------|------------------------------|
| `diffie-hellman-group1-sha1`           | Critical — Logjam vulnerable |
| `diffie-hellman-group14-sha1`          | Weak — SHA-1 based           |
| `ssh-dss` (DSA)                        | Weak — 1024-bit key          |
| `3des-cbc`, `arcfour*`, `blowfish-cbc` | Legacy ciphers               |
| `hmac-md5`, `hmac-sha1`                | Weak MACs                    |
| `ssh-rsa` (as host key)                | Deprecated in OpenSSH 8.8+   |

### `ssh-auth-methods` — find what authentication is accepted

> **This is an `intrusive` script — it initiates a real authentication.**
> Each run produces a failed-auth entry in the target's `auth.log`, and against
> a subnet it will trip `fail2ban`, SIEM credential-spray rules, and — where
> lockout policy is keyed to the *source* — can lock the account you probe with
> across every host at once. Scope it to named hosts, use a username you know
> exists, and tell the defenders before you run it.

```bash
# Single host, one deliberate username
nmap -p 22 --script ssh-auth-methods \
  --script-args "ssh.user=root" $TARGET

nmap -p 22 --script ssh-auth-methods \
  --script-args "ssh.user=admin" $TARGET
```

**Prefer the passive inference first.** `PasswordAuthentication` is usually
answerable without touching authentication at all — a `keyboard-interactive`
or password-capable configuration is visible from the server's own
documentation, config management state, or `ssh-audit` policy output. Reach
for this script only when you need per-host confirmation.
Output:
```
22/tcp open  ssh
| ssh-auth-methods:
|   Supported authentication methods:
|     publickey
|_    password              ← password auth enabled — credential risk
```
`none_auth` returned means the user requires no password at all.

### `sshv1` — detect legacy SSH protocol version 1
```bash
nmap --script sshv1 -p 22 $SUBNET
```
SSHv1 is cryptographically broken, and any host supporting it is a critical
finding.

> **Expect zero hits on a modern estate.** OpenSSH removed SSHv1 server
> support in 7.4 (2016) and dropped the code entirely soon after. The check
> costs nothing and is worth keeping in a sweep, but a clean result is the
> normal outcome and proves very little. Where you *will* find it is
> unmaintained embedded gear, industrial equipment, and network appliances
> past end-of-support — the same population as the Telnet findings below.

### Sweep the whole subnet — safe scripts only
```bash
sudo nmap -p 22 --open \
  --script "ssh-hostkey,ssh2-enum-algos,sshv1" \
  $SUBNET -oN ssh-full-audit.txt
```

`ssh-auth-methods` is deliberately **excluded** from the sweep. Running it
subnet-wide generates one failed authentication per host from a single source
address, which is indistinguishable from a credential-spraying attack and is
the fastest way to get an authorised engagement shut down. Run it per host,
after you have a reason to.

---

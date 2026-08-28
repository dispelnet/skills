---
name: remote-access-discovery
description: >
  Use this skill when the user wants to find, enumerate, or audit remote
  access services on a network — specifically SSH and Telnet. Triggers
  include: "find SSH servers", "discover machines with SSH", "find Telnet
  hosts", "what machines have port 22 open", "SSH enumeration", "banner
  grabbing", "check SSH versions", "find weak SSH configs", "audit remote
  access", "which hosts allow password auth", "check for SSHv1", "find
  Telnet in the network", "ssh-audit", "check for Terrapin", "audit SSH
  ciphers", or any request to probe remote administration services for
  version, authentication method, or cipher information. For RDP, VNC or
  WinRM instead, use rdp-vnc-discovery.
---

# Remote Access Discovery — SSH & Telnet

## Hard Rules — Read Before Running Anything

**Do not run any command in this skill until the target range is confirmed.**

1. **State the confirmed range back before the first command.** Never default
   to the local subnet; never widen a confirmed range.
2. **Enumerate, do not authenticate.** No password attempts, no key trials,
   no spraying — even where the tool offers them.
3. **`ssh-auth-methods` is an authentication probe.** It is read-only, but it
   opens an auth conversation and lands in the target's auth log. Run it per
   host, only against confirmed hosts, and tell the user it will be logged.
4. **Banner versions are triage, not findings.** Distributions backport fixes
   without changing the version string, so a banner match is a candidate. Say
   "candidate, needs host-side confirmation" — never report a CVE from a
   banner alone.

Full legal statement: [Ethical and Legal Notice](#ethical-and-legal-notice).

### Set these first

Every command below uses these. Fill them in from the scope you just
confirmed, and substitute nothing by hand afterwards. An unset variable
makes the command fail loudly — that is the point; a hardcoded address
fails silently against the wrong network.

```bash
SUBNET="192.168.1.0/24"    # the confirmed range
TARGET="192.168.1.10"      # a single confirmed host
TELNET_HOST="192.168.1.20" # a confirmed Telnet host
```

---

Once live hosts and open ports have been identified (via `arp-scan` or
`nmap`), the next step is to interrogate remote access services. SSH (port
22) and Telnet (port 23) are the two most common remote administration
protocols. Enumerating them reveals software versions, supported
authentication methods, cipher suites, host keys, and — crucially — which
hosts are using dangerously insecure configurations.

**Why this matters:**
- SSH version + software banner → map to known CVEs
- Weak ciphers or SSHv1 support → flag for hardening
- Password auth enabled → credential spray risk
- Telnet presence anywhere → cleartext credentials in flight

**Primary tool:** use `ssh-audit` (Step 4) for the crypto and CVE audit. The
Nmap SSH scripts in Step 5 are for targeted follow-up that `ssh-audit` does
not cover — host key collection and authentication method enumeration.

**Supporting reference:** `ssh-crypto-reference.md` holds the CVE matrix,
algorithm risk tables, and hardening baselines.

**Scope:** this skill covers SSH and Telnet. For RDP, VNC and WinRM — the
graphical and Windows remote-access protocols — use the
**rdp-vnc-discovery** skill. For TLS-wrapped services and certificate
posture, use the **tls-certificate-discovery** skill, which shares this
skill's crypto-reference structure. A remote-access audit is not complete
without all three.

---

**Supporting references** — load only the one you need:

| File | Load when |
|---|---|
| `ssh-crypto-reference.md` | Triaging an `ssh-audit` finding, or mapping a banner version to real exposure |
| `ssh-nse-reference.md` | `ssh-audit` is unavailable, or one targeted probe is enough |
| `audit-automation-reference.md` | The user wants a recurring, scheduled audit |

---

## Step 1 — Find All SSH and Telnet Hosts on the Network

```bash
# Scan subnet for port 22 (SSH) and port 23 (Telnet)
sudo nmap -p 22,23 --open $SUBNET

# Include version detection — get software name and version immediately
sudo nmap -p 22,23 -sV --open $SUBNET

# Save results for later processing
sudo nmap -p 22,23 -sV --open $SUBNET -oG remote-access.gnmap -oN remote-access.txt

# Extract just the IPs with SSH open
grep "22/open" remote-access.gnmap | awk '{print $2}' > ssh-hosts.txt

# Extract just the IPs with Telnet open
grep "23/open" remote-access.gnmap | awk '{print $2}' > telnet-hosts.txt
```

SSH may also run on non-standard ports. Scan broadly if needed:
```bash
# Scan all ports, then grep for SSH banners
sudo nmap -p- -sV --open $SUBNET | grep -i ssh
```

---

## Step 2 — Banner Grabbing

A banner is the plain-text greeting a service sends before authentication.
For SSH it reveals protocol version and software. For Telnet it often
reveals OS, hostname, and login prompts. Three tools work well:

### Netcat (nc) — lowest noise, fastest
```bash
# Grab SSH banner
nc -v $TARGET 22
# Output example:
# SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1

# Grab Telnet banner
nc -v $TELNET_HOST 23
# Output example:
# Debian GNU/Linux 10 myserver ttyS0
# myserver login:
```

### Telnet client — interactive, useful for probing
```bash
# Grab SSH banner via Telnet (connects, server identifies itself, then hangs)
telnet $TARGET 22

# Grab Telnet service banner
telnet $TELNET_HOST 23
# Press Ctrl+] then type quit to exit
```

### Nmap banner script — sweeps many hosts at once
```bash
# Banner grab across all SSH hosts
nmap --script banner -p 22 -iL ssh-hosts.txt

# Banner grab across all Telnet hosts
nmap --script banner -p 23 -iL telnet-hosts.txt
```

### Reading the SSH banner
```
SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
 ^^^  ^^^  ^^^^^^^^^^^ ^^^^^^^^^^^^^^^^^
 |    |    |           OS/distro hint
 |    |    Software version
 |    SSH protocol version (2.0 = good, 1.x = bad)
 Protocol identifier
```

---

## Step 3 — SSH Version and Service Detection (Nmap)

```bash
# Full version scan on a single host
sudo nmap -p 22 -sV $TARGET

# With OS detection
sudo nmap -p 22 -sV -O $TARGET

# Run all default SSH-related NSE scripts in one go
sudo nmap -p 22 -sV -sC $TARGET
# -sC runs the "default" category scripts, which includes ssh-hostkey
```

---

## Step 4 — ssh-audit (Primary Deep Audit)

`ssh-audit` is the standard tool for SSH configuration auditing and should be
your **default** over the Nmap SSH scripts. It performs a single key exchange
and reads the server's offered algorithms — it never attempts authentication,
so it writes nothing to `auth.log` and carries no lockout risk.

Against `ssh2-enum-algos` it adds: per-algorithm risk annotation with the CVE
or reason, Terrapin (CVE-2023-48795) and DHEat (CVE-2002-20001) detection,
banner-to-version CVE mapping, machine-readable JSON, pass/fail policy
auditing, and generated remediation commands.

### Install

```bash
sudo apt install ssh-audit -y        # Debian/Ubuntu, Kali
sudo dnf install ssh-audit -y        # Fedora/RHEL (EPEL)
pipx install ssh-audit               # any platform, newest version
docker run -it --rm positronsecurity/ssh-audit $TARGET
```

> Prefer `pipx`/`pip` if your distro package is old — Terrapin and DHEat
> detection require **v3.1.0+** and **v3.2.0+** respectively.

### Audit a single host

```bash
ssh-audit $TARGET
ssh-audit -p 2222 $TARGET           # non-standard port
ssh-audit -t 10 $TARGET             # raise timeout for slow/WAN hosts
```

Output is annotated per algorithm:

```
# key exchange algorithms
(kex) curve25519-sha256                     -- [info] available since OpenSSH 7.4
(kex) diffie-hellman-group14-sha1           -- [fail] using broken SHA-1 hash algorithm
                                            `- [info] available since OpenSSH 3.9

# encryption algorithms (ciphers)
(enc) chacha20-poly1305@openssh.com         -- [warn] vulnerable to the Terrapin attack

(cve) CVE-2024-6387    (CVSS 8.1) -- unauthenticated remote code execution
(gen) software: OpenSSH 9.2p1
(gen) compatibility: OpenSSH 8.5-9.7
```

Read `[fail]` as "remove this", `[warn]` as "justify or remove", `[info]` as
context. See `ssh-crypto-reference.md` for what each algorithm implies.

### Scan the whole subnet

Feed it the host list produced in Step 1:

```bash
# -T takes a file of targets, one host[:port] per line.
# Generate ssh-hosts.txt straight from a merged inventory:
#   jq -r 'select(.ports[]?.port==22)|.ip' inventory.jsonl > ssh-hosts.txt
# (see the discovery-inventory skill)
ssh-audit -T ssh-hosts.txt

# Machine-readable, for diffing or ingestion. NOTE the JSON shape:
#   single host  ->  ssh-audit -j HOST      emits one OBJECT
#   batch        ->  ssh-audit -T FILE -j   emits an ARRAY of those objects,
#                    each with a .target field and per-algo .notes.{warn,fail}
ssh-audit -T ssh-hosts.txt -j > ssh-audit.json

# Which hosts are Terrapin-exposed? (verified against ssh-audit 3.x output)
jq -r '.[] | select(
         [ (.kex[]?, .enc[]?, .mac[]?)
           | (.notes.warn // [])[], (.notes.fail // [])[] ]
         | any(test("Terrapin"; "i"))
       ) | .target' ssh-audit.json

# Same idea for any [fail]-graded algorithm, with the host and the reason
jq -r '.[] | .target as $t
       | (.kex[]?, .enc[]?, .mac[]?, .key[]?)
       | select(.notes.fail)
       | "\($t)\t\(.algorithm)\t\(.notes.fail[0])"' ssh-audit.json
```

### Policy auditing — the part that scales

Policy mode turns the audit into a **pass/fail gate** with a meaningful exit
code, so it works in CI or a cron job without output parsing.

```bash
ssh-audit -L                                  # list built-in policies
ssh-audit -P "Hardened OpenSSH Server v9.7 (version 4)" $TARGET

# Capture your own approved baseline from a known-good host...
ssh-audit -M baseline.policy $TARGET

# ...then hold every other host to it
ssh-audit -P baseline.policy -T ssh-hosts.txt
echo "exit=$?"        # 0 = compliant, non-zero = drift or failure
```

Built-in policies exist for hardened OpenSSH server/client baselines and for
specific distro releases, so you can audit against the vendor's own shipped
configuration rather than an invented standard.

### Auditing SSH clients

Jump boxes, CI runners, and orchestration nodes are SSH *clients* at scale,
and client CVEs (see CVE-2025-26465) never show up in a listening-port scan.
`ssh-audit` listens and audits whatever connects to it:

```bash
# Terminal 1 — listen on port 2222
ssh-audit -c -p 2222

# Terminal 2 (or from the client host) — connect; auth failure is expected
ssh anything@<auditor-ip> -p 2222
```

---

## Step 5 — SSH NSE Scripts (Targeted Follow-Up)

`ssh-audit` in Step 4 covers this ground more thoroughly. Reach for NSE when
`ssh-audit` is not installed, or when you want one specific answer (host key,
algorithm list, accepted auth methods) without a full audit.

**See `ssh-nse-reference.md`** for the scripts, their arguments, and how to
read each one's output.

`ssh-auth-methods` is an authentication probe and will appear in the target's
auth log — Hard Rule 3 applies.

---

## Step 6 — Telnet Enumeration

Telnet transmits everything in cleartext — credentials, commands, output.
Its presence on any modern network is a finding in itself.

### Detect Telnet hosts and grab banners
```bash
# Scan for Telnet
sudo nmap -p 23 -sV --open $SUBNET

# Banner grab via netcat
echo "" | nc -w 3 $TELNET_HOST 23

# Banner grab via telnet client
telnet $TELNET_HOST
```

### Who actually runs Telnet now

Microsoft **removed the Telnet Server** from Windows Server 2016 onward, so a
Telnet finding on a current estate is almost never Windows. In practice
port 23 today means:

| Population | Typical device | Why it matters |
|---|---|---|
| Network appliances | Switches, routers, older firewalls | Management creds in cleartext |
| Industrial / OT | PLCs, HMIs, serial-to-Ethernet bridges | Often unauthenticated as well |
| IoT and embedded | Cameras, DVRs, set-top boxes | Default credentials, botnet target |
| Out-of-band mgmt | Console servers, legacy IPMI/serial | Bypasses every other control |

Prioritise accordingly: a Telnet port on a core switch is a materially bigger
finding than one on a lab device, because the credentials crossing it are
infrastructure credentials.

### `telnet-ntlm-info` — Windows system info from Microsoft Telnet

Retained for **legacy hosts only**, per the note above — Server 2012 R2 and
earlier, or third-party Telnet servers on Windows.

```bash
nmap --script telnet-ntlm-info -p 23 $TELNET_HOST
```
Output:
```
23/tcp open  telnet
| telnet-ntlm-info:
|   Target_Name: MYSERVER
|   NetBIOS_Domain_Name: CORP
|   NetBIOS_Computer_Name: MYSERVER
|   DNS_Domain_Name: corp.example.com
|   DNS_Computer_Name: myserver.corp.example.com
|_  Product_Version: 10.0.19041   ← reveals Windows build version
```
This works by sending a null NTLM auth request — the server replies with
system metadata before any credentials are checked.

### `telnet-encryption` — check if encryption is negotiated
```bash
nmap --script telnet-encryption -p 23 $TELNET_HOST
```

---

## Step 7 — Correlate and Build a Remote Access Inventory

After running the scans, build a structured picture:

```bash
# One-liner: version + algorithms across subnet (no auth probing)
sudo nmap -p 22 --open -sV \
  --script "ssh2-enum-algos,sshv1" \
  $SUBNET -oX ssh-inventory.xml -oN ssh-inventory.txt

# Extract all SSH software versions from normal output
grep "ssh" ssh-inventory.txt | grep "open"

# Per-host software version straight from the batch JSON (no re-scan).
# .banner is an object — use .banner.raw for the full string.
jq -r '.[] | "\(.target)\t\(.banner.raw)"' ssh-audit.json

# Hosts whose audit surfaced any CVE (ssh-audit maps the banner to CVEs)
jq -r '.[] | select(.cves | length > 0) | "\(.target)\t\(.cves | length) CVE(s)"' \
  ssh-audit.json

# Find any host supporting SSHv1
grep -i "sshv1" ssh-inventory.txt
```

Inventory columns to populate per host:

| IP          | Hostname  | SSH Version | Auth Methods | Weak Algos          | Telnet? | Risk     |
|-------------|-----------|-------------|--------------|---------------------|---------|----------|
| 192.168.1.1 | router    | OpenSSH 8.9 | publickey    | none                | No      | Low      |
| 192.168.1.5 | oldserver | OpenSSH 5.3 | password     | 3des-cbc, dh-group1 | Yes     | Critical |

---

## Step 8 — Periodic Audit Script

**See `audit-automation-reference.md`** for a cron-ready script.

Before scheduling anything: a recurring scan runs without anyone re-confirming
scope. Pin the confirmed host list into the script, and tell the user the scan
will keep running until they remove it.

---

## Reading SSH Versions for Risk Assessment

**Do not assume "higher version = safer."** OpenSSH 9.x was, for three years,
*more* exposed than 8.4p1 because regreSSHion (CVE-2024-6387) landed in 8.5p1
and was not fixed until 9.8p1. Risk is a function of version *boundaries*, not
version order.

| Banner version         | Notable exposure                                             |
|------------------------|--------------------------------------------------------------|
| `OpenSSH 10.4`+        | Current branch — 10.5 released 2026-08-11                    |
| `OpenSSH 9.8p1`–`10.3` | Past regreSSHion/Terrapin; sftp/scp path and client UAF CVEs |
| `OpenSSH 9.6p1`–`9.7p1`| Terrapin fixed, **regreSSHion vulnerable** (CVE-2024-6387)   |
| `OpenSSH 8.5p1`–`9.5p1`| **regreSSHion + Terrapin** — unauth RCE as root, patch now   |
| `OpenSSH 4.4p1`–`8.4p1`| No regreSSHion; Terrapin applies below 9.6p1. Check algos    |
| `OpenSSH` < `4.4p1`    | CVE-2006-5051 / CVE-2008-4109 — the original signal race     |
| `Dropbear 20xx.xx`     | Common on routers/IoT — separate CVE track, often unpatched  |
| `SSH-1.x-*`            | Critical — SSHv1, cryptographically broken                   |
| Any Telnet server      | Critical — cleartext protocol                                |

See `ssh-crypto-reference.md` for the full CVE matrix, exploit preconditions,
and the algorithm risk tables.

**This table ages.** Reconcile against <https://www.openssh.com/security.html>
before reporting — a version listed as current here may have picked up a CVE
since. "Newest available" is the only durable recommendation.

### The backporting caveat — read before reporting

Enterprise distributions **backport** security fixes without changing the
upstream version number. A Debian 12 host reporting `OpenSSH_9.2p1
Debian-2+deb12u3` is *patched* against regreSSHion, despite 9.2p1 falling
inside the vulnerable range above.

```bash
# Banner says 9.2p1 — that alone proves nothing. Confirm on the host:
dpkg -l openssh-server        # Debian/Ubuntu: read the full package revision
rpm -q --changelog openssh    # RHEL family: grep the changelog for the CVE
rpm -q --changelog openssh | grep -i -m5 'CVE-2024-6387'
```

Treat a banner-derived finding as **"requires verification"**, never as a
confirmed vulnerability. Reporting unverified banner matches as findings is
the single most common way a network audit loses credibility.

Cross-reference versions against the
[OpenSSH release notes](https://www.openssh.com/releasenotes.html) — the
authoritative record of what each version fixed.

---

## Non-Standard SSH Ports

Administrators sometimes move SSH off port 22. Catch these:

```bash
# Scan all 65535 ports, flag any SSH banners
sudo nmap -p- -sV $TARGET | grep -i ssh

# Or scan common alternative ports
sudo nmap -p 22,222,2222,22222 -sV $SUBNET --open
```

---

## Quick Reference — Key Commands

```bash
# Find all SSH/Telnet hosts
sudo nmap -p 22,23 -sV --open $SUBNET

# Full crypto + CVE audit (START HERE — no auth attempted, nothing logged)
ssh-audit $TARGET
ssh-audit -T ssh-hosts.txt -j > ssh-audit.json    # whole subnet, JSON
ssh-audit -P baseline.policy -T ssh-hosts.txt     # pass/fail gate

# Banner grab (single host)
nc -v $TARGET 22

# Get host keys (bulk, no nmap — best for duplicate-key detection)
ssh-keyscan -t rsa,ecdsa,ed25519 -f ssh-hosts.txt | ssh-keygen -lf -
nmap --script ssh-hostkey -p 22 $TARGET

# Enumerate supported algorithms (find weak ciphers)
nmap --script ssh2-enum-algos -p 22 $TARGET

# Check authentication methods (INTRUSIVE — logs a failed auth, per host only)
nmap -p 22 --script ssh-auth-methods --script-args ssh.user=root $TARGET

# Detect legacy SSHv1
nmap --script sshv1 -p 22 $SUBNET

# Full SSH sweep — one command, safe scripts only
sudo nmap -p 22 --open -sV \
  --script "ssh-hostkey,ssh2-enum-algos,sshv1" $SUBNET

# Telnet — extract Windows system info
nmap --script telnet-ntlm-info -p 23 $SUBNET
```

---

## Common Mistakes

| Symptom | Usually means | Do this |
|---|---|---|
| No SSH hosts found | SSH on a non-standard port | See *Non-Standard SSH Ports*; a `-p 22` sweep proves nothing about the estate |
| `ssh-audit` times out | Rate-limiting, or a slow WAN path | `-t 10`. Do not record an empty algorithm list as a clean result |
| No banner returned | The server suppresses it (`DebianBanner no`), or a middlebox stripped it | Absence of a banner is not a finding |
| Telnet port open but nothing prints | Many appliances wait for input before their banner | Not evidence the service is dead |

**The inference ceiling.** `ssh-audit` proves **which algorithms the server offered during one handshake**. It cannot see `sshd_config`, backported patches, or whether a listed algorithm is actually reachable for a given user — every version-derived finding needs host-side confirmation.

---

## Ethical and Legal Notice

Only enumerate services on networks you own or have explicit written
authorisation to test. Authentication probing (even read-only methods like
`ssh-auth-methods`) constitutes active interaction with remote systems.
Unauthorised use may violate computer misuse laws. This skill is intended
for network administrators, security professionals, and penetration testers
operating within authorised scope.

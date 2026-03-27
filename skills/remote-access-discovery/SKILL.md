---
name: remote-access-discovery
description: >
  Use this skill when the user wants to find, enumerate, or audit remote
  access services on a network — specifically SSH and Telnet. Triggers
  include: "find SSH servers", "discover machines with SSH", "find Telnet
  hosts", "what machines have port 22 open", "SSH enumeration", "banner
  grabbing", "check SSH versions", "find weak SSH configs", "audit remote
  access", "which hosts allow password auth", "check for SSHv1", "find
  Telnet in the network", or any request to probe remote administration
  services for version, authentication method, or cipher information.
---

# Remote Access Discovery — SSH & Telnet

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

---

## Step 1 — Find All SSH and Telnet Hosts on the Network

```bash
# Scan subnet for port 22 (SSH) and port 23 (Telnet)
sudo nmap -p 22,23 --open 192.168.1.0/24

# Include version detection — get software name and version immediately
sudo nmap -p 22,23 -sV --open 192.168.1.0/24

# Save results for later processing
sudo nmap -p 22,23 -sV --open 192.168.1.0/24 -oG remote-access.gnmap -oN remote-access.txt

# Extract just the IPs with SSH open
grep "22/open" remote-access.gnmap | awk '{print $2}' > ssh-hosts.txt

# Extract just the IPs with Telnet open
grep "23/open" remote-access.gnmap | awk '{print $2}' > telnet-hosts.txt
```

SSH may also run on non-standard ports. Scan broadly if needed:
```bash
# Scan all ports, then grep for SSH banners
sudo nmap -p- -sV --open 192.168.1.0/24 | grep -i ssh
```

---

## Step 2 — Banner Grabbing

A banner is the plain-text greeting a service sends before authentication.
For SSH it reveals protocol version and software. For Telnet it often
reveals OS, hostname, and login prompts. Three tools work well:

### Netcat (nc) — lowest noise, fastest
```bash
# Grab SSH banner
nc -v 192.168.1.10 22
# Output example:
# SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1

# Grab Telnet banner
nc -v 192.168.1.20 23
# Output example:
# Debian GNU/Linux 10 myserver ttyS0
# myserver login:
```

### Telnet client — interactive, useful for probing
```bash
# Grab SSH banner via Telnet (connects, server identifies itself, then hangs)
telnet 192.168.1.10 22

# Grab Telnet service banner
telnet 192.168.1.20 23
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
sudo nmap -p 22 -sV 192.168.1.10

# With OS detection
sudo nmap -p 22 -sV -O 192.168.1.10

# Run all default SSH-related NSE scripts in one go
sudo nmap -p 22 -sV -sC 192.168.1.10
# -sC runs the "default" category scripts, which includes ssh-hostkey
```

---

## Step 4 — SSH NSE Scripts (Deep Enumeration)

All SSH scripts live at `/usr/share/nmap/scripts/ssh*.nse`. List them:
```bash
ls /usr/share/nmap/scripts/ssh*
# ssh-auth-methods.nse
# ssh-brute.nse
# ssh-hostkey.nse
# ssh-publickey-acceptance.nse
# ssh-run.nse
# ssh2-enum-algos.nse
# sshv1.nse
```

### `ssh-hostkey` — retrieve host public keys
```bash
nmap --script ssh-hostkey -p 22 192.168.1.10

# Show full key (not just fingerprint)
nmap --script ssh-hostkey --script-args ssh_hostkey=full -p 22 192.168.1.10
```
Output:
```
22/tcp open  ssh
| ssh-hostkey:
|   ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB...
|   ecdsa-sha2-nistp256 AAAAE2VjZH...
|_  ssh-ed25519 AAAAC3NzaC1lZDI1N...
```
Host keys are unique per machine. Identical keys across multiple hosts
indicates cloned images — a configuration management concern.

### `ssh2-enum-algos` — enumerate supported algorithms
```bash
nmap --script ssh2-enum-algos -p 22 192.168.1.10
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
```bash
# Check for a known username
nmap -p 22 --script ssh-auth-methods \
  --script-args "ssh.user=root" 192.168.1.10

nmap -p 22 --script ssh-auth-methods \
  --script-args "ssh.user=admin" 192.168.1.10
```
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
nmap --script sshv1 -p 22 192.168.1.0/24
```
SSHv1 is cryptographically broken. Any host supporting it is a critical finding.

### Sweep the whole subnet with all SSH scripts at once
```bash
sudo nmap -p 22 --open \
  --script "ssh-hostkey,ssh2-enum-algos,ssh-auth-methods,sshv1" \
  --script-args "ssh.user=root" \
  192.168.1.0/24 -oN ssh-full-audit.txt
```

---

## Step 5 — Telnet Enumeration

Telnet transmits everything in cleartext — credentials, commands, output.
Its presence on any modern network is a finding in itself.

### Detect Telnet hosts and grab banners
```bash
# Scan for Telnet
sudo nmap -p 23 -sV --open 192.168.1.0/24

# Banner grab via netcat
echo "" | nc -w 3 192.168.1.20 23

# Banner grab via telnet client
telnet 192.168.1.20
```

### `telnet-ntlm-info` — extract Windows system info from Microsoft Telnet
```bash
nmap --script telnet-ntlm-info -p 23 192.168.1.20
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
nmap --script telnet-encryption -p 23 192.168.1.20
```

---

## Step 6 — Correlate and Build a Remote Access Inventory

After running the scans, build a structured picture:

```bash
# One-liner: version + algorithms + auth methods across subnet
sudo nmap -p 22 --open -sV \
  --script "ssh2-enum-algos,ssh-auth-methods,sshv1" \
  --script-args "ssh.user=root" \
  192.168.1.0/24 -oX ssh-inventory.xml -oN ssh-inventory.txt

# Extract all SSH software versions from normal output
grep "ssh" ssh-inventory.txt | grep "open"

# Find all hosts still offering password auth
grep -A5 "ssh-auth-methods" ssh-inventory.txt | grep "password"

# Find any host supporting SSHv1
grep -i "sshv1" ssh-inventory.txt
```

Inventory columns to populate per host:

| IP          | Hostname  | SSH Version | Auth Methods | Weak Algos          | Telnet? | Risk     |
|-------------|-----------|-------------|--------------|---------------------|---------|----------|
| 192.168.1.1 | router    | OpenSSH 8.9 | publickey    | none                | No      | Low      |
| 192.168.1.5 | oldserver | OpenSSH 5.3 | password     | 3des-cbc, dh-group1 | Yes     | Critical |

---

## Step 7 — Periodic Audit Script

```bash
#!/bin/bash
# /usr/local/bin/remote-access-audit.sh
# Run weekly to track remote access exposure changes

SUBNET="192.168.1.0/24"
DATE=$(date +"%Y%m%d")
OUTDIR="/var/lib/remote-access-audit"
mkdir -p "$OUTDIR"

echo "[*] Scanning for SSH and Telnet on $SUBNET..."

sudo nmap -p 22,23 --open -sV \
  --script "ssh2-enum-algos,ssh-auth-methods,sshv1,telnet-ntlm-info,banner" \
  --script-args "ssh.user=root" \
  "$SUBNET" \
  -oN "$OUTDIR/scan-$DATE.txt" \
  -oX "$OUTDIR/scan-$DATE.xml"

# Flag critical issues
echo ""
echo "=== CRITICAL FINDINGS ==="
grep -i "sshv1\|password\|3des\|group1\|arcfour\|23/open\|telnet" \
  "$OUTDIR/scan-$DATE.txt" | sort -u

# Diff against last scan
PREV=$(ls "$OUTDIR"/scan-*.txt 2>/dev/null | sort | tail -2 | head -1)
if [ -n "$PREV" ] && [ "$PREV" != "$OUTDIR/scan-$DATE.txt" ]; then
    echo ""
    echo "=== CHANGES SINCE LAST SCAN ==="
    diff "$PREV" "$OUTDIR/scan-$DATE.txt" | grep "^[<>]"
fi
```

---

## Reading SSH Versions for Risk Assessment

| Version String         | Risk                                       |
|------------------------|--------------------------------------------|
| `OpenSSH 9.x`          | Low — current                              |
| `OpenSSH 8.x`          | Low–Medium — check for deprecated algos    |
| `OpenSSH 7.x`          | Medium — several CVEs, check patch level   |
| `OpenSSH 6.x` or older | High — multiple known vulnerabilities      |
| `OpenSSH 5.x` or older | Critical — EOL, many exploitable CVEs      |
| `Dropbear 20xx.xx`     | Check version — common on routers/IoT      |
| `SSH-1.x-*`            | Critical — SSHv1, cryptographically broken |
| Any Telnet server      | Critical — cleartext protocol              |

Cross-reference versions against [https://www.cvedetails.com/product/585/Openbsd-Openssh.html](https://www.cvedetails.com/product/585/Openbsd-Openssh.html)

---

## Non-Standard SSH Ports

Administrators sometimes move SSH off port 22. Catch these:

```bash
# Scan all 65535 ports, flag any SSH banners
sudo nmap -p- -sV 192.168.1.10 | grep -i ssh

# Or scan common alternative ports
sudo nmap -p 22,222,2222,22222 -sV 192.168.1.0/24 --open
```

---

## Quick Reference — Key Commands

```bash
# Find all SSH/Telnet hosts
sudo nmap -p 22,23 -sV --open 192.168.1.0/24

# Banner grab (single host)
nc -v 192.168.1.10 22

# Get host keys
nmap --script ssh-hostkey -p 22 192.168.1.10

# Enumerate supported algorithms (find weak ciphers)
nmap --script ssh2-enum-algos -p 22 192.168.1.10

# Check authentication methods
nmap -p 22 --script ssh-auth-methods --script-args ssh.user=root 192.168.1.10

# Detect legacy SSHv1
nmap --script sshv1 -p 22 192.168.1.0/24

# Full SSH audit — one command
sudo nmap -p 22 --open -sV \
  --script "ssh-hostkey,ssh2-enum-algos,ssh-auth-methods,sshv1" \
  --script-args "ssh.user=root" 192.168.1.0/24

# Telnet — extract Windows system info
nmap --script telnet-ntlm-info -p 23 192.168.1.0/24
```

---

## Ethical and Legal Notice

Only enumerate services on networks you own or have explicit written
authorisation to test. Authentication probing (even read-only methods like
`ssh-auth-methods`) constitutes active interaction with remote systems.
Unauthorised use may violate computer misuse laws. This skill is intended
for network administrators, security professionals, and penetration testers
operating within authorised scope.

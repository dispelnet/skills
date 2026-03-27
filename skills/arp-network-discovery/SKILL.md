---
name: arp-network-discovery
description: >
  Use this skill when the user wants to discover devices on a local network
  using ARP. Triggers include: "find devices on my network", "scan my LAN",
  "what's connected to my network", "discover hosts", "find IP addresses on
  subnet", "ARP scan", or any request to enumerate local network nodes.
  This skill covers arp-scan installation, basic and advanced scanning
  recipes, output interpretation, duplicate IP detection, baseline diffing,
  and periodic audit automation.
---

# ARP Network Discovery

ARP (Address Resolution Protocol) operates at OSI Layer 2 and is the most
reliable method for discovering hosts on a local subnet. Unlike ICMP ping or
TCP/UDP scans, ARP requests are a fundamental part of networking — every
device must respond to them, including hosts with strict firewalls, IoT
devices, and printers that silently drop ICMP.

**Key constraint:** ARP is not routable. `arp-scan` only discovers hosts on
the local subnet. For wider network discovery, combine with Nmap.

---

## Install arp-scan

```bash
# Debian / Ubuntu
sudo apt install arp-scan -y

# RHEL / CentOS / Fedora / Rocky
sudo dnf install arp-scan -y

# Arch Linux
sudo pacman -S arp-scan

# openSUSE
sudo zypper install arp-scan

# macOS (via Homebrew)
brew install arp-scan
```

> Kali Linux includes arp-scan by default.
> Windows users: use WSL2 or a Cygwin port from GitHub.

---

## How It Works

arp-scan sends ARP requests to every IP address in the target range. Each
live host replies with its MAC address. The tool records IP address, MAC
address, and NIC vendor (resolved from the OUI database).

```
IP Address      MAC Address         Vendor
─────────────────────────────────────────────────────
192.168.1.1     aa:bb:cc:dd:ee:ff   Cisco Systems, Inc
192.168.1.50    11:22:33:44:55:66   Dell Inc.
192.168.1.100   77:88:99:aa:bb:cc   Apple, Inc.
```

---

## Basic Recipes

### Scan the local network (auto-detect subnet)
```bash
sudo arp-scan --localnet
```

### Scan a specific subnet
```bash
sudo arp-scan 192.168.1.0/24
```

### Scan on a specific interface
```bash
sudo arp-scan -I eth0 --localnet
sudo arp-scan -I wlan0 192.168.1.0/24   # works on wireless too
```

### Quiet mode — IP and MAC only, no vendor info
```bash
sudo arp-scan -q --localnet
```

### Plain/parseable output (no header/footer)
```bash
sudo arp-scan -x 192.168.1.0/24
```

---

## Output Interpretation

| Column    | Meaning                                                         |
|-----------|-----------------------------------------------------------------|
| IP        | IPv4 address of the discovered host                             |
| MAC       | Ethernet hardware address                                       |
| Vendor    | NIC manufacturer from OUI database — helps identify device type |

Vendor examples that aid device classification:
- `Raspberry Pi Foundation` → IoT / embedded device
- `Apple, Inc.` → MacBook, iPhone, iPad
- `Cisco Systems` → Router, switch, access point
- `Unknown` → Custom hardware or spoofed MAC — investigate further

---

## Advanced Scanning Options

```bash
# Retry flaky hosts (default is 2; raise for unreliable networks)
sudo arp-scan --retry 5 192.168.1.0/24

# Randomise scan order (harder to fingerprint the scan pattern)
sudo arp-scan -R 192.168.1.0/24

# Ignore duplicate responses
sudo arp-scan -g --localnet

# Increase verbosity (show packet details)
sudo arp-scan -v 192.168.1.0/24
sudo arp-scan -vv 192.168.1.0/24   # double verbose

# Slow scan — IDS/IPS-friendly, 100ms between packets
sudo arp-scan --interval 100 192.168.1.0/24

# Fast scan — high bandwidth for large subnets
sudo arp-scan --bandwidth 1000000 192.168.1.0/24

# Custom source IP (useful for VLAN testing)
sudo arp-scan --arpspa 192.168.1.200 192.168.1.0/24

# Explicit broadcast destination
sudo arp-scan --destaddr ff:ff:ff:ff:ff:ff 192.168.1.0/24
```

---

## Detecting Duplicate / Conflicting IPs

Two hosts with the same IP but different MACs indicate an IP conflict.

```bash
# Spot duplicates by sorting and finding repeated lines
sudo arp-scan --localnet | sort | uniq -D

# More explicit: print "DUPLICATE IP:" prefix for offending lines
sudo arp-scan --localnet | awk 'seen[$1]++ {print "DUPLICATE IP: "$0}'
```

---

## Baseline Comparison (New Device Detection)

```bash
# Save a known-good snapshot
sudo arp-scan 192.168.1.0/24 | sort > /tmp/baseline-hosts.txt

# Later: compare against current state
sudo arp-scan 192.168.1.0/24 | sort > /tmp/current-hosts.txt
diff /tmp/baseline-hosts.txt /tmp/current-hosts.txt

# Lines starting with > are new devices; lines starting with < have left
```

---

## Periodic Audit Script

Schedule with `cron` to receive alerts when unknown devices appear.

```bash
#!/bin/bash
# /usr/local/bin/network-audit.sh
# Run as root. Example cron: */15 * * * * /usr/local/bin/network-audit.sh

IFACE="eth0"
SUBNET="192.168.1.0/24"
KNOWN="/var/lib/network-audit/known-hosts.txt"
CURRENT="/tmp/current-scan-$$.txt"

sudo arp-scan -I "$IFACE" "$SUBNET" 2>/dev/null \
  | grep -E "^[0-9]" \
  | awk '{print $1, $2}' \
  | sort > "$CURRENT"

if [ -f "$KNOWN" ]; then
    NEW=$(comm -23 "$CURRENT" "$KNOWN")
    if [ -n "$NEW" ]; then
        echo "NEW DEVICES DETECTED on $(date):"
        echo "$NEW"
        # Optionally: | mail -s "Network Alert" admin@example.com
    fi
fi

cp "$CURRENT" "$KNOWN"
rm -f "$CURRENT"
```

---

## Fingerprinting a Single Host

`arp-fingerprint` ships with the arp-scan package and probes a single host
to help identify its OS via ARP response quirks.

```bash
sudo arp-fingerprint 192.168.1.1
```

---

## Combining arp-scan with Nmap

`arp-scan` excels at finding hosts; `nmap` excels at interrogating them.
Use them together:

```bash
# Step 1: Get all live IPs from ARP scan
sudo arp-scan --localnet -x | awk '{print $1}' > /tmp/live-hosts.txt

# Step 2: Feed into Nmap for port/service/OS discovery
sudo nmap -iL /tmp/live-hosts.txt -O -sV -T4 -oN /tmp/nmap-results.txt
```

---

## Stealth Considerations

arp-scan does **not** attempt to hide from IDS/IPS systems. ARP requests
are normal network traffic, but a large burst of them across an entire
subnet is detectable. If stealth matters, use `--interval` to slow the
scan or consider `netdiscover` in passive mode.

---

## When to Use Something Else

| Scenario                          | Better Tool                        |
|-----------------------------------|------------------------------------|
| Scan beyond the local subnet      | Nmap with TCP/UDP                  |
| Stealth / passive discovery       | `netdiscover -p` (passive ARP)     |
| Service/port enumeration          | Nmap                               |
| Large-scale internet scanning     | Masscan / ZMap                     |
| Full SNMP topology map            | Netdisco, PRTG, SolarWinds         |
| Cloud environments (AWS/GCP/Azure)| Cloud provider APIs                |

---

## Ethical and Legal Notice

Only run arp-scan on networks you own or have explicit written authorisation
to test. Unauthorised network scanning may violate local laws and
organisational policies. This skill is intended for network administrators,
security professionals, and penetration testers operating within authorised
scope.

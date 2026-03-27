---
name: nmap-network-discovery
description: >
  Use this skill when the user wants to discover, scan, or inventory a
  network using Nmap. Triggers include: "scan my network", "find open ports",
  "discover hosts", "what's running on this server", "OS detection",
  "service version scan", "port scan", "nmap", "network inventory",
  "asset discovery", "find devices on subnet", or any request to enumerate
  hosts, services, or operating systems across one or more IP addresses or
  CIDR ranges.
---

# Nmap Network Discovery

Nmap (Network Mapper) is an open-source tool for network discovery and
security auditing. It operates at OSI Layer 3 and above, making it
complementary to ARP-based tools: while `arp-scan` finds all hosts on the
local segment, Nmap can scan across routed networks, identify open ports,
fingerprint operating systems, detect service versions, and run specialised
scripts against targets.

**Key strength over ARP scanning:** Nmap works across routers and on remote
networks. It can find hosts that are up even when ICMP is blocked, by
probing TCP/UDP ports instead.

---

## Install Nmap

```bash
# RHEL / CentOS / Fedora / Rocky
sudo dnf install nmap -y

# Debian / Ubuntu
sudo apt install nmap -y

# Arch Linux
sudo pacman -S nmap

# macOS (via Homebrew)
brew install nmap
```

The Nmap suite also includes:
- **Zenmap** — GUI front-end and results viewer
- **Ncat** — flexible netcat replacement
- **Ndiff** — compare two scan results
- **Nping** — packet generation and response analysis

---

## How Nmap Discovers Hosts

By default, Nmap pings targets with ICMP echo requests **and** sends TCP
SYN/ACK probes to ports 80 and 443. This means it finds hosts that block
pure ICMP pings. You can override this with specific probe types.

Host discovery probe methods:

| Flag  | Method                                | Notes                                  |
|-------|---------------------------------------|----------------------------------------|
| `-PE` | ICMP echo request (traditional ping)  | Often blocked by firewalls             |
| `-PS` | TCP SYN to a port (default: 80)       | Works through many firewalls           |
| `-PA` | TCP ACK to a port (default: 80)       | Good for stateful firewall bypass      |
| `-PU` | UDP probe to a high port              | Reaches hosts blocking TCP             |
| `-PR` | ARP ping (local subnet only)          | Fastest and most reliable on LAN       |
| `-Pn` | Skip host discovery entirely          | Treat all targets as up; scan anyway   |

---

## Basic Recipes

### Quick host sweep (no port scan)
```bash
nmap -sn 192.168.1.0/24
```
Lists all live hosts on the subnet. Faster than a full scan; useful as a
first pass.

### List scan (DNS reverse lookup, no traffic sent to hosts)
```bash
nmap -sL 192.168.1.0/24
```
Useful for pre-flight recon — resolves hostnames without touching the hosts.

### Default port scan (top 1,000 TCP ports)
```bash
nmap 192.168.1.0/24
```

### Scan multiple networks at once
```bash
nmap 192.168.1.0/24 10.0.0.0/24
```

### Scan with ARP ping on local subnet (fast, reliable)
```bash
sudo nmap -sn -PR 192.168.1.0/24
```

---

## Port Scanning

### TCP SYN scan — fast, doesn't complete handshake (default with root)
```bash
sudo nmap -sS 192.168.1.10
```

### TCP connect scan — completes the handshake (no root required)
```bash
nmap -sT 192.168.1.10
```

### UDP scan — slower, covers DNS, SNMP, DHCP, etc.
```bash
sudo nmap -sU 192.168.1.10
```

### Scan specific ports
```bash
nmap -p 22,80,443 192.168.1.10
nmap -p 1-1024 192.168.1.10        # port range
nmap -p- 192.168.1.10              # all 65,535 ports
```

### Show only open ports (suppress closed/filtered noise)
```bash
nmap --open 192.168.1.0/24
```

### Skip host discovery, scan all targets as if up
```bash
sudo nmap -Pn -sS 192.168.1.10
```
Use this when a host is alive but blocks all ping probes.

---

## Service & Version Detection

```bash
# Detect service versions on open ports
nmap -sV 192.168.1.10

# Scan specific ports for version info
nmap -sV -p 22,80,443 192.168.1.0/24

# Show only open ports with version info
nmap -sV --open 192.168.1.0/24
```

Version detection probes services and reports the software name and version,
e.g. `OpenSSH 8.9p1`, `Apache httpd 2.4.29`. Useful for spotting outdated
or vulnerable software across the network.

---

## OS Detection

```bash
# Detect operating system (requires root)
sudo nmap -O 192.168.1.10

# OS detection with version scanning
sudo nmap -O -sV 192.168.1.10
```

Nmap compares TCP/IP stack responses against a fingerprint database to guess
the OS and kernel version. Results are most accurate when at least one open
and one closed port are found. Treat results as an educated guess — confirm
directly on the host when precision matters.

---

## Comprehensive Scan (-A flag)

`-A` enables OS detection, service version detection, script scanning, and
traceroute in a single command:

```bash
sudo nmap -A 192.168.1.10
sudo nmap -A 192.168.1.0/24       # entire subnet
```

This is the recommended starting point for a thorough first scan of an
unknown host or network.

---

## Timing and Performance

Nmap has six timing templates (`-T0` through `-T5`):

| Template | Name       | Use Case                                      |
|----------|------------|-----------------------------------------------|
| `-T0`    | Paranoid   | IDS evasion; very slow                        |
| `-T1`    | Sneaky     | IDS evasion; slow                             |
| `-T2`    | Polite     | Reduces bandwidth/CPU impact                  |
| `-T3`    | Normal     | Default                                       |
| `-T4`    | Aggressive | Faster; good on reliable LANs                 |
| `-T5`    | Insane     | Very fast; may miss results on lossy networks |

```bash
# Fast LAN scan
sudo nmap -T4 -A 192.168.1.0/24

# Slow, stealthy scan for IDS evasion
nmap -T1 -sS 10.0.0.0/24
```

---

## Output Formats

```bash
# Normal text (default)
nmap -sV 192.168.1.0/24 -oN scan.txt

# XML (machine-parseable, importable into tools)
nmap -sV 192.168.1.0/24 -oX scan.xml

# Grepable format
nmap -sn 192.168.1.0/24 -oG scan.gnmap

# All formats at once
nmap -sV 192.168.1.0/24 -oA scan   # produces scan.nmap, scan.xml, scan.gnmap
```

### Convert XML to readable HTML report
```bash
# Install xsltproc
sudo apt install xsltproc -y

# Convert scan.xml to HTML
xsltproc -o scan.html scan.xml
```

### Extract live IPs from grepable output
```bash
nmap -sn 192.168.1.0/24 -oG - | awk '/Up$/{print $2}' > live-hosts.txt
```

---

## Packet Tracing and Debug

```bash
# Trace packets for a single host
sudo nmap -vv -n -sn -PE -T4 --packet-trace 192.168.1.1

# -vv         increase verbosity
# -n          skip DNS resolution (faster)
# -PE         use ICMP echo
# --packet-trace  print sent/received packets
```

---

## Nmap Scripting Engine (NSE)

NSE scripts extend Nmap with specialised probes. Scripts live at
`/usr/share/nmap/scripts/`.

```bash
# List all available scripts
ls /usr/share/nmap/scripts/

# Run a script against a target
nmap --script <script-name> <target>

# Pass arguments to a script
nmap --script <script-name> --script-args "<arg>=<value>" <target>
```

### Useful NSE recipes

```bash
# Gather Windows OS info via SMB
nmap --script smb-os-discovery 192.168.1.0/24

# Detect WAF on a web server
nmap -p443 --script http-waf-detect \
  --script-args="http-waf-detect.aggro,http-waf-detect.detectBodyChanges" \
  target.example.com

# Check for known CVEs against detected services
nmap -Pn -sV --script=vulners 192.168.1.10

# Enumerate HTTP methods
nmap --script http-methods -p80,443 192.168.1.10

# Check for default credentials
nmap --script http-default-accounts 192.168.1.10

# Banner grabbing on all open ports
nmap --script banner 192.168.1.10
```

---

## Network Inventory Workflow

### Step 1: Discover live hosts
```bash
sudo nmap -sn 192.168.1.0/24 -oG - | awk '/Up$/{print $2}' > live-hosts.txt
cat live-hosts.txt
```

### Step 2: Full scan of live hosts
```bash
sudo nmap -iL live-hosts.txt -A -T4 -oA full-inventory
```

### Step 3: Convert to HTML for review
```bash
xsltproc -o full-inventory.html full-inventory.xml
```

### Step 4: Check for outdated services
```bash
# Example: find all SSH servers and their versions
grep "ssh" full-inventory.nmap
```

---

## Periodic Inventory Script (cron-ready)

```bash
#!/bin/bash
# /usr/local/bin/nmap-inventory.sh
# Example cron: 0 2 * * 0 /usr/local/bin/nmap-inventory.sh

SUBNET="192.168.1.0/24"
DATE=$(date +"%Y%m%d")
OUTDIR="/var/lib/nmap-inventory"
mkdir -p "$OUTDIR"

sudo nmap -sV -O "$SUBNET" -oX "$OUTDIR/scan-$DATE.xml" -oG "$OUTDIR/scan-$DATE.gnmap"

# Optional: convert to HTML
xsltproc -o "$OUTDIR/scan-$DATE.html" "$OUTDIR/scan-$DATE.xml"

# Optional: compare to last scan
PREV=$(ls "$OUTDIR"/scan-*.xml 2>/dev/null | sort | tail -2 | head -1)
if [ -n "$PREV" ] && [ "$PREV" != "$OUTDIR/scan-$DATE.xml" ]; then
    ndiff "$PREV" "$OUTDIR/scan-$DATE.xml" > "$OUTDIR/diff-$DATE.txt"
    echo "Changes since last scan saved to $OUTDIR/diff-$DATE.txt"
fi
```

---

## Using ndiff to Spot Changes

`ndiff` compares two Nmap XML scans and highlights new/removed hosts and
ports — ideal for detecting unauthorized changes.

```bash
# Compare two scans
ndiff scan-baseline.xml scan-today.xml

# Output only the differences
ndiff -v scan-baseline.xml scan-today.xml
```

---

## Combine with arp-scan (Best Practice)

ARP scan finds all Layer 2 hosts on the local segment (including those
blocking ICMP). Nmap then interrogates the live IPs for ports, services,
and OS. Together they give complete coverage:

```bash
# Step 1: ARP scan — finds every host on the LAN
sudo arp-scan --localnet -x | awk '{print $1}' > arp-hosts.txt

# Step 2: Nmap deep scan — ports, versions, OS for each host
sudo nmap -iL arp-hosts.txt -A -T4 -oA combined-inventory
```

---

## DNS Reconnaissance (using public resolvers)

```bash
# Resolve a domain to find its IP
dig target.example.com

# Use Google DNS to list reverse-mapped hostnames on that subnet
nmap --dns-servers 8.8.4.4,8.8.8.8 -sL 203.0.113.0/24
```

---

## Quick Reference — Most-Used Flags

| Flag      | Purpose                                           |
|-----------|---------------------------------------------------|
| `-sn`     | Ping sweep, no port scan                          |
| `-sS`     | TCP SYN scan (stealth, requires root)             |
| `-sU`     | UDP scan                                          |
| `-sV`     | Service/version detection                         |
| `-O`      | OS detection                                      |
| `-A`      | OS + version + scripts + traceroute               |
| `-p`      | Specify ports (`-p 22,80` or `-p-` for all)       |
| `-Pn`     | Skip host discovery (scan even if no ping reply)  |
| `-T4`     | Aggressive timing (good for LANs)                 |
| `-n`      | No DNS resolution (speeds up scans)               |
| `--open`  | Show only open ports                              |
| `-oA`     | Output in all formats simultaneously              |
| `-iL`     | Read targets from file                            |
| `--script`| Run NSE script(s)                                 |
| `-v/-vv`  | Increase verbosity                                |

---

## When to Use Something Else

| Scenario                              | Better Tool                              |
|---------------------------------------|------------------------------------------|
| Local subnet only, fastest discovery  | `arp-scan` (Layer 2, firewall-immune)    |
| Internet-wide or /8+ scanning         | Masscan, ZMap                            |
| Passive discovery (no traffic sent)   | `netdiscover -p`, span port capture      |
| SNMP topology mapping                 | Netdisco, PRTG, SolarWinds               |
| Continuous monitoring & alerting      | Zabbix, Nagios, Nessus                   |
| GUI-based scanning                    | Zenmap (Nmap's official GUI)             |

---

## Ethical and Legal Notice

Only scan networks you own or have explicit written authorisation to test.
Unauthorised scanning may violate computer misuse laws and organisational
policy. This skill is intended for network administrators, security
professionals, and penetration testers operating within authorised scope.

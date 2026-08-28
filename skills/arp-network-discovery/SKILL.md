---
name: arp-network-discovery
description: >
  Use this skill when the user wants to discover devices on a local network
  using ARP. Triggers include: "find devices on my network", "scan my LAN",
  "what's connected to my network", "discover hosts", "find IP addresses on
  subnet", "ARP scan", or any request to enumerate local network nodes. Also
  use when a ping sweep found fewer hosts than expected on a local subnet,
  or when a vendor/MAC address is needed for hosts already found.
---

# ARP Network Discovery

## Before You Run Anything — Scope Gate

**Do not run any command in this skill until the target range is confirmed.**

1. **The user must name the target range, and you must state it back** before
   the first command. "My network" is not a range — ask for the CIDR or the
   host list.
2. **Never default to the local subnet.** Auto-detecting an interface's subnet
   and scanning it is not a confirmed scope.
3. **Never widen a confirmed range.** A /24 does not authorise the /16 around
   it, and a discovered host outside the range is out of scope, not a lead.
4. This sends packets to hosts you do not control. If a target turns out to be
   third-party managed, or the user is unsure who owns it, **stop and ask**.

Full legal statement: [Ethical and Legal Notice](#ethical-and-legal-notice).

### Set these first

Every command below uses these. Fill them in from the scope you just
confirmed, and substitute nothing by hand afterwards. An unset variable
makes the command fail loudly — that is the point; a hardcoded address
fails silently against the wrong network.

```bash
SUBNET="192.168.1.0/24" # the confirmed range
TARGET="192.168.1.10"   # a single confirmed host
IFACE="eth0"            # ip -br link  → the interface on that segment
```

---

ARP (Address Resolution Protocol) operates at OSI Layer 2 and is the most
reliable method for discovering hosts on a local subnet. Unlike ICMP ping or
TCP/UDP scans, ARP requests are a fundamental part of networking — every
device must respond to them, including hosts with strict firewalls, IoT
devices, and printers that silently drop ICMP.

**Key constraints:**
- **ARP is not routable.** `arp-scan` only discovers hosts on the local
  subnet. For wider network discovery, combine with Nmap.
- **ARP does not exist in IPv6.** Its role is taken by NDP, so `arp-scan` is
  structurally blind to IPv6-only hosts. On a dual-stack network, pair this
  skill with **ipv6-network-discovery**.

---

**Supporting references** — load only the one you need:

| File | Load when |
|---|---|
| `mac-and-oui-reference.md` | The vendor column matters, or `(Unknown)` is about to be reported as a finding |
| `audit-automation-reference.md` | Baseline diffing / new-device detection, or a scheduled scan |

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
192.168.1.1     00:00:0c:9f:f0:01   Cisco Systems, Inc
192.168.1.50    b8:2a:72:1e:44:90   Dell Inc.
192.168.1.100   a4:83:e7:2c:11:08   Apple, Inc.
192.168.1.137   7a:e1:4b:33:9d:52   (Unknown)
```

The last entry has no vendor because its second hex digit is `a` — a locally
administered, randomized address. That is a phone or laptop, not an anomaly.
See "MAC Randomization" below.

---

## Basic Recipes

### Scan the local network (auto-detect subnet)
```bash
sudo arp-scan --localnet
```

### Scan a specific subnet
```bash
sudo arp-scan $SUBNET
```

### Scan on a specific interface
```bash
sudo arp-scan -I $IFACE --localnet
sudo arp-scan -I $IFACE $SUBNET   # see the Wi-Fi caveat below
```

### Quiet mode — IP and MAC only, no vendor info
```bash
sudo arp-scan -q --localnet
```

### Plain/parseable output (no header/footer)
```bash
sudo arp-scan -x $SUBNET
```

---

## Structured Output (arp-scan 1.10+)

Do not parse the default human-readable table — it has a header and footer,
and the vendor string contains spaces. Use `--plain` to drop the framing and
`--format` to name the fields you want.

```bash
# CSV, ready for a spreadsheet or a diff
sudo arp-scan --localnet --plain --format='${ip},${mac},"${vendor}"'

# With reverse DNS resolution
sudo arp-scan --localnet --plain --resolve \
  --format='${ip},${name},${mac},"${vendor}"'

# Include VLAN tag and round-trip time
sudo arp-scan --localnet --plain --rtt \
  --format='${ip},${mac},${vlan},${rtt}'
```

| Field | Meaning |
|---|---|
| `${ip}` | IPv4 address, dotted quad |
| `${mac}` | MAC address, `xx:xx:xx:xx:xx:xx` |
| `${vendor}` | Vendor string from the OUI database |
| `${name}` | Hostname — requires `--resolve` |
| `${vlan}` | 802.1Q VLAN ID, when present |
| `${rtt}` | Round-trip time — requires `--rtt` |
| `${dup}` | Packet number for duplicate responses (> 1) |
| `${hdrMAC}` | Ethernet source address, when it differs from the ARP payload |
| `${padding}` | Trailing padding in hex, when nonzero |

> `--quiet` restricts you to `${ip}` and `${mac}` only.

`${hdrMAC}` and `${padding}` are worth capturing on an audit: a mismatch
between the Ethernet header address and the ARP payload address is a spoofing
indicator, and non-zero padding can leak fragments of adjacent memory from
sloppy embedded stacks.

### Stop early on large ranges

```bash
# Exit as soon as 10 hosts respond — quick "is anything alive here?" probe
sudo arp-scan --limit 10 $SUBNET
```

---

## Running Without sudo (POSIX Capabilities)

arp-scan needs `CAP_NET_RAW`, not full root. On Linux you can grant exactly
that capability to the binary and drop `sudo` from every command:

```bash
sudo setcap cap_net_raw+p "$(command -v arp-scan)"

# Verify, then run unprivileged
getcap "$(command -v arp-scan)"
arp-scan --localnet
```

This is the right choice for scheduled jobs — a cron entry that no longer
needs root is a meaningfully smaller blast radius than one that does.

To revert: `sudo setcap -r "$(command -v arp-scan)"`.

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
- `(Unknown)` → **usually a randomized MAC, not an intruder** — check the
  locally administered bit before investigating (see below)

---

## Link-Layer Preconditions — When arp-scan Cannot Work

arp-scan depends on broadcast frames reaching every station on the segment.
Two common configurations break that assumption, and in both cases the scan
**succeeds and returns almost nothing** — a silent false negative, which is
far more dangerous than an error.

### Wi-Fi client isolation

Most guest networks and many enterprise WLANs enable *client isolation* (also
called AP isolation or station separation), which blocks station-to-station
frames including broadcast. An ARP scan from a wireless client then sees the
gateway and nothing else.

```bash
# If a WLAN scan returns only the gateway, suspect isolation before
# concluding the network is empty.
sudo arp-scan -I $IFACE --localnet
```

Confirm which it is before reporting:

```bash
# 1. Passive check — are OTHER stations' frames reaching you at all?
sudo tcpdump -i $IFACE -ln arp and not host "$(hostname -I | awk '{print $1}')"

# 2. Authoritative check — read the AP's own client table
#    (SNMP, controller UI, or `iw dev wlan0 station dump` on the AP itself)
```

If passive capture shows no traffic from other stations over several minutes,
the segment is isolated and **no** active layer-2 scanner will help. Get the
inventory from the AP, the controller, or DHCP leases instead.

### VLAN trunks

On an access port you see one VLAN. On a **trunk** port, untagged frames put
you in the native VLAN only — every tagged VLAN is invisible, and the scan
still looks complete.

```bash
# Surface 802.1Q tags that are reaching this interface
sudo arp-scan --localnet --plain --format='${ip},${mac},${vlan}'

# Discover which VLANs are actually present on the link
sudo tcpdump -i $IFACE -nn -e vlan 2>/dev/null | head -40

# Scan a tagged VLAN by creating a subinterface for it
sudo ip link add link $IFACE name $IFACE.30 type vlan id 30
sudo ip addr add 10.0.30.9/24 dev $IFACE.30
sudo ip link set $IFACE.30 up
sudo arp-scan -I $IFACE.30 --localnet

# Clean up when finished
sudo ip link delete $IFACE.30
```

Enumerate the VLANs before you claim subnet coverage. A "complete" scan of a
trunk port that only covered the native VLAN is the most common way an
inventory silently misses entire network segments.

---

## MAC Randomization — Read Before Trusting the Vendor Column

Per-network MAC randomization is **on by default** on every current client OS
(Android 10+, iOS 14+, Windows 10+, recent macOS). Two consequences change how
you read every scan on a network with wireless clients:

1. **`(Unknown)` is the expected result for phones and laptops** — not a sign
   of custom hardware or spoofing. Do not report it as a finding.
2. **Naive baseline diffing produces false "new device" alerts.** iOS rotates
   its address for non-associated networks; a phone walking past the building
   appears as a new host on every scan.

Quick test: randomized addresses have the locally administered bit set, so the
**second hex digit is `2`, `6`, `A` or `E`**. Vendor-assigned addresses never
do.

**See `mac-and-oui-reference.md`** for the classification recipe, the counts
that are normal on Wi-Fi, and how to refresh the OUI database so that a
remaining `(Unknown)` on a *global* address is genuinely worth investigating.

---

## Advanced Scanning Options

```bash
# Retry flaky hosts (default is 2; raise for unreliable networks)
sudo arp-scan --retry 5 $SUBNET

# Randomise scan order (harder to fingerprint the scan pattern)
sudo arp-scan -R $SUBNET

# Ignore duplicate responses (hides the "(DUP: n)" conflict flag —
# do not use this when hunting for IP conflicts or ARP spoofing)
sudo arp-scan -g --localnet

# Increase verbosity (show packet details)
sudo arp-scan -v $SUBNET
sudo arp-scan -vv $SUBNET   # double verbose

# Slow scan — IDS/IPS-friendly, 100ms between packets
sudo arp-scan --interval 100 $SUBNET

# Fast scan — high bandwidth for large subnets
sudo arp-scan --bandwidth 1000000 $SUBNET

# Custom source IP (useful for VLAN testing)
sudo arp-scan --arpspa 192.168.1.200 $SUBNET

# Explicit broadcast destination
sudo arp-scan --destaddr ff:ff:ff:ff:ff:ff $SUBNET
```

---

## Detecting Duplicate / Conflicting IPs

Two hosts answering for the same IP with different MACs is an address
conflict — or ARP spoofing.

**arp-scan already detects this for you.** When more than one host replies for
an address, it flags the extra responses inline:

```
192.168.1.50    b8:2a:72:1e:44:90    Dell Inc.
192.168.1.50    00:25:90:8f:3b:12    Super Micro Computer (DUP: 2)
```

```bash
# Surface only the conflicts
sudo arp-scan --localnet | grep 'DUP:'

# Machine-readable, using the ${dup} field
sudo arp-scan --localnet --plain --format='${ip},${mac},${dup}' \
  | awk -F, '$3 != ""'
```

> `-g` / `--ignoredups` **suppresses** these flags. Never combine it with
> conflict detection — it hides exactly what you are looking for.

Raising the retry count makes conflicts easier to observe, since both hosts
must answer within the same scan:

```bash
sudo arp-scan --retry 5 --localnet | grep 'DUP:'
```

---

## Baseline Comparison (New Device Detection)

**See `audit-automation-reference.md`** for baseline diffing and a cron-ready
audit script.

Read the MAC randomization section above first. On any network with wireless
clients, a diff that treats every unseen MAC as a new device will alert on
every run and bury the one result that mattered.

---

## Fingerprinting a Single Host

`arp-fingerprint` ships with the arp-scan package and probes a single host,
identifying its OS from quirks in how the ARP stack answers malformed requests.

```bash
sudo arp-fingerprint $TARGET
sudo arp-fingerprint -l                    # fingerprint the whole local net
sudo arp-fingerprint -o "-I $IFACE" $TARGET   # pass options to arp-scan
```

> **Its signature database is old.** Inspect the fingerprint table and the
> named entries are Cisco Catalyst 1900 and 2924-XL, IOS 11.2 through 15.0,
> PIX 515E, VPN Concentrator 3030 and 79xx IP phones — 2000s-era equipment.
> Modern Linux, Windows and macOS stacks largely produce identical or
> ambiguous signatures, so a confident-looking result carries little
> discriminating power.

Use it for **legacy and embedded gear**, where it still discriminates well and
where nothing else on the network will answer. For current operating systems
use `nmap -O`, whose fingerprint database is actively maintained:

```bash
sudo nmap -O --osscan-guess $TARGET
```

---

## Combining arp-scan with Nmap

`arp-scan` excels at finding hosts; `nmap` excels at interrogating them.
Use them together:

```bash
# Step 1: Get all live IPs from ARP scan
sudo arp-scan --localnet --plain --format='${ip}' > /tmp/live-hosts.txt

# Step 2: Feed into Nmap for port/service/OS discovery
sudo nmap -iL /tmp/live-hosts.txt -O -sV -T4 -oN /tmp/nmap-results.txt
```

### Feed a persistent inventory instead of a text file

To accumulate results across scans rather than overwriting a file, emit the
structured format the **discovery-inventory** skill consumes:

```bash
# Layer-2 records with MAC, vendor, and randomization classification
sudo arp-scan --localnet --plain --format='${ip},${mac},${vendor}' \
  | netinv from-arp - > arp.jsonl
```

That inventory then drives Nmap against exactly the hosts not yet scanned —
see the discovery-inventory skill.

---

## Stealth and Passive Discovery

arp-scan does **not** attempt to hide. A sweep across a subnet from one source
is exactly the pattern `arpwatch` and switch-side ARP inspection flag. Slow it
when that matters:

```bash
sudo arp-scan --interval 100 $SUBNET     # 100ms between packets
sudo arp-scan -R --interval 250 $SUBNET  # randomised order, slower
```

For genuinely passive discovery — zero packets sent, safe on fragile devices,
and able to find hosts that speak but never answer — **use the
`passive-network-discovery` skill.** Run it alongside an active scan: hosts
that appear passively but not actively are answering their neighbours while
ignoring you.

---

## Common Mistakes

| Symptom | Usually means | Do this |
|---|---|---|
| Only the gateway answered | Wi-Fi client isolation, or you are seeing only a trunk's native VLAN | Confirm with a passive capture or the AP/switch client table (`snmp-network-inventory`) before calling the segment empty |
| Zero hosts, no error | Wrong interface, or `$SUBNET` is not on this link — ARP is not routable | `ip -br addr` and check `$IFACE` holds an address inside `$SUBNET` |
| Many `(Unknown)` vendors | Expected. MAC randomization is on by default on phones and laptops | Classify by the locally-administered bit first; see `mac-and-oui-reference.md` |
| A host you know exists is missing | It may be IPv6-only | `ipv6-network-discovery` — ARP is structurally blind to it |
| New devices on every scheduled run | Rotating randomized MACs, not intruders | Diff on stable identity, not raw MAC |

**The inference ceiling.** arp-scan proves that **a MAC answered an ARP request on this link**. It does not prove the OS, the role, or that the device is the vendor its OUI claims — OUIs are assignable and trivially spoofed.

---

## When to Use Something Else

| Scenario                          | Better Tool                        |
|-----------------------------------|------------------------------------|
| Scan beyond the local subnet      | Nmap with TCP/UDP                  |
| Stealth / passive discovery       | `netdiscover -p`, `bettercap`, `p0f` |
| Service/port enumeration          | Nmap                               |
| Large-scale internet scanning     | Masscan / ZMap                     |
| Full SNMP topology map            | Netdisco, PRTG, SolarWinds         |
| Cloud environments (AWS/GCP/Azure)| cloud-network-discovery skill      |
| IPv6 hosts (ARP does not apply)   | `scan6`, `ndisc6` — see ipv6-network-discovery |

---

## Ethical and Legal Notice

Only run arp-scan on networks you own or have explicit written authorisation
to test. Unauthorised network scanning may violate local laws and
organisational policies. This skill is intended for network administrators,
security professionals, and penetration testers operating within authorised
scope.

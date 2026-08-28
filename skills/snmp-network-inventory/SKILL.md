---
name: snmp-network-inventory
description: >
  Use this skill when the user wants to inventory or map a network by reading
  SNMP from switches, routers, and access points instead of probing hosts.
  Triggers include: "SNMP scan", "snmpwalk", "find SNMP devices", "default
  community strings", "read the switch ARP table", "map network topology",
  "LLDP neighbors", "CDP neighbors", "get device inventory", "enumerate SNMP",
  "port 161", "onesixtyone", "which devices are on which switch port", or any
  request to pull IP/MAC bindings, interface lists, VLAN membership, or
  neighbour relationships from network infrastructure. Use this when an ARP or
  ping sweep is blocked by client isolation or VLAN segmentation, or when an
  authoritative host list is wanted instead of a scan's approximation.
---

# SNMP Network Inventory

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
SWITCH="192.168.1.1"    # the switch/router to read SNMP from
```

---

Active scanning *reconstructs* a picture of the network from the outside. SNMP
lets you **read the authoritative picture** the infrastructure already keeps:
a switch knows every MAC on every port, every ARP binding, every VLAN, and
every directly connected neighbour.

**When this beats a scan:**
- **Client isolation** blocks host-to-host ARP, but the AP/switch still holds
  the client table — SNMP reads it directly.
- **VLAN segmentation** hides tagged segments from a single-interface scan; the
  switch sees all of them.
- **Complete coverage** — a scan misses hosts that are momentarily quiet; the
  switch's ARP/bridge tables retain them.

**The finding this skill generates on its own:** SNMP with a **default or
guessable community string** exposes all of the above to anyone. `public`
(read) and `private` (write) are still pervasive, and write access to a switch
is a network-takeover primitive.

---

## Install

```bash
sudo apt install snmp snmp-mibs-downloader onesixtyone -y   # Debian/Ubuntu
sudo dnf install net-snmp-utils -y                          # RHEL/Fedora

# Enable full MIB name resolution (Debian ships them disabled)
sudo download-mibs
sudo sed -i 's/^mibs :/# mibs :/' /etc/snmp/snmp.conf 2>/dev/null || true
```

---

## Step 1 — Find SNMP Hosts and Guess Community Strings

SNMP is UDP/161. Discovery and community-string guessing happen together,
because a response *is* proof of a working community string.

```bash
# onesixtyone: purpose-built, sprays UDP and logs responders. Fast.
# It tries public/private by default even with no wordlist.
onesixtyone -c community-strings.txt $SUBNET

# Nmap alternative, with a light brute force
sudo nmap -sU -p 161 --script snmp-brute $SUBNET
```

A useful community-string wordlist beyond `public`/`private`:

```
public
private
cisco
manager
admin
read
write
community
snmp
default
```

> A single response to `public` is a finding. Read access alone leaks the
> entire inventory below; report it before going any further.

---

## Step 2 — Identify the Device

```bash
# System description: model, OS, version — one OID, high value
snmpget -v2c -c public $SWITCH 1.3.6.1.2.1.1.1.0     # sysDescr
snmpget -v2c -c public $SWITCH 1.3.6.1.2.1.1.5.0     # sysName

# Nmap wraps the common system OIDs
sudo nmap -sU -p 161 --script snmp-sysdescr,snmp-info $SWITCH
```

> **Use `snmpbulkwalk`, not `snmpwalk`, on v2c/v3.** Bulk requests fetch many
> rows per packet — an order of magnitude faster on large tables and far
> gentler on the device. Reserve plain `snmpwalk` for v1, which has no bulk.

---

## Step 3 — Read the Authoritative Tables

This is the payoff. Each table replaces an active scan with ground truth.

### ARP / IP-to-MAC bindings — replaces the ARP scan

```bash
# ipNetToMediaTable — every IP↔MAC the device knows, across ALL its VLANs
snmpbulkwalk -v2c -c public $SWITCH 1.3.6.1.2.1.4.22.1.2

# Modern equivalent (IPv4 + IPv6): ipNetToPhysicalTable
snmpbulkwalk -v2c -c public $SWITCH 1.3.6.1.2.1.4.35.1.4
```

A router's ARP table lists hosts across every subnet it routes — coverage no
single-segment ARP scan can match.

### MAC-to-port (bridge/forwarding table) — locates each host physically

```bash
# dot1dTpFdbPort — which switch port each MAC is behind
snmpbulkwalk -v2c -c public $SWITCH 1.3.6.1.2.1.17.4.3.1.2
```

### Interfaces and VLANs

```bash
# Interface list, names, status, counters
sudo nmap -sU -p 161 --script snmp-interfaces $SWITCH
snmpbulkwalk -v2c -c public $SWITCH 1.3.6.1.2.1.2.2.1.2   # ifDescr
snmpbulkwalk -v2c -c public $SWITCH 1.3.6.1.2.1.31.1.1.1.18  # ifAlias

# VLAN membership (Cisco VTP MIB)
snmpbulkwalk -v2c -c public $SWITCH 1.3.6.1.4.1.9.9.46.1.3.1.1.4
```

### Neighbours — this is where topology comes from

```bash
# LLDP neighbour table (standard, vendor-neutral)
snmpbulkwalk -v2c -c public $SWITCH 1.0.8802.1.1.2.1.4

# CDP neighbour table (Cisco)
snmpbulkwalk -v2c -c public $SWITCH 1.3.6.1.4.1.9.9.23
```

LLDP/CDP tells you what connects to each port. Walk one switch, follow its
neighbours, walk those, and you reconstruct the physical topology.

### Windows and host detail (if a host runs an SNMP agent)

```bash
sudo nmap -sU -p 161 --script \
  snmp-netstat,snmp-processes,snmp-win32-services,snmp-win32-software \
  $TARGET
```

---

## Step 4 — Stitch Topology from Multiple Devices

```bash
#!/bin/bash
# Walk every SNMP-speaking device and collect the neighbour + bridge tables.
# Match neighbour names and MAC-to-port bindings across devices to build the map.
COMMUNITY="public"
for host in $(cat snmp-hosts.txt); do
  echo "== $host =="
  snmpget    -v2c -c "$COMMUNITY" "$host" 1.3.6.1.2.1.1.5.0 2>/dev/null   # name
  snmpbulkwalk -v2c -c "$COMMUNITY" "$host" 1.0.8802.1.1.2.1.4 2>/dev/null # LLDP
done > topology-raw.txt
```

For anything beyond a handful of devices, feed the walks to a purpose-built
mapper — Netdisco ingests exactly these tables and draws the topology.

---

## SNMP Versions — Security Matters Here

| Version | Auth | Confidentiality | Note |
|---|---|---|---|
| **v1** | Community string (cleartext) | None | Legacy; no bulk requests |
| **v2c** | Community string (cleartext) | None | Most common; string sniffable on the wire |
| **v3** | User + auth (SHA) + priv (AES) | Yes | The only version safe on an untrusted network |

```bash
# SNMPv3 with authentication and encryption
snmpbulkwalk -v3 -l authPriv -u monitor \
  -a SHA -A "authpass" -x AES -X "privpass" \
  $SWITCH 1.3.6.1.2.1.1.1.0
```

**Findings to raise:**
- Any v1/v2c reachable outside a management VLAN — the community string
  crosses the wire in cleartext.
- Default community strings (`public`, `private`, and the wordlist above).
- **Write** community access — test read-only first; write access allows
  reconfiguration and is a critical finding. Do not *make* changes; prove the
  access with a read of a writable OID and stop.

---

## Quick Reference

```bash
# Discover + guess community strings
onesixtyone -c strings.txt $SUBNET

# Identify a device
snmpget -v2c -c public $SWITCH 1.3.6.1.2.1.1.1.0

# The four inventory tables
snmpbulkwalk -v2c -c public $SWITCH 1.3.6.1.2.1.4.22.1.2      # ARP
snmpbulkwalk -v2c -c public $SWITCH 1.3.6.1.2.1.17.4.3.1.2   # MAC→port
snmpbulkwalk -v2c -c public $SWITCH 1.0.8802.1.1.2.1.4       # LLDP
snmpbulkwalk -v2c -c public $SWITCH 1.3.6.1.2.1.2.2.1.2      # interfaces
```

---

## Common Mistakes

| Symptom | Usually means | Do this |
|---|---|---|
| No response on 161 | UDP: silence is ambiguous between filtered, wrong community, and no agent | Try v2c and v3 and confirm the community before concluding |
| Walk stops partway through the tree | The community is restricted to a view | A partial walk is not a complete inventory — record which OIDs returned |
| A known host is missing from the ARP table | It has been idle and aged out | Bridge and ARP tables reflect recent traffic, not membership |
| Interface list far longer than expected | Includes VLANs, loopbacks and tunnels | Filter by `ifOperStatus` before counting |

**The inference ceiling.** SNMP proves **what the device has recorded recently**. Its tables are authoritative for what it has seen, not for what exists — an idle host ages out and disappears from an otherwise authoritative source.

---

## When to Use Something Else

| Scenario | Better tool |
|---|---|
| Host-level port/service scan | `nmap` — see nmap-network-discovery |
| Local IPv4 host discovery | `arp-scan` — see arp-network-discovery |
| Full automated topology + web UI | Netdisco, LibreNMS, Observium |
| Zero-touch / passive discovery | passive-network-discovery skill |
| Devices with SNMP disabled | LLDP/CDP capture via passive-network-discovery |

---

## Ethical and Legal Notice

Only query SNMP on networks you own or have explicit written authorisation to
test. Guessing community strings is an authentication attack, and reading a
switch's tables discloses the full internal network map. **Never** exercise
write access to change a device's configuration during an audit — proving read
access on a writable OID is sufficient to demonstrate the exposure. This skill
is for network administrators and authorised penetration testers within scope.

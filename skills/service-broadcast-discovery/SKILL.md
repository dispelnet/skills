---
name: service-broadcast-discovery
description: >
  Use this skill when the user wants to discover hosts and services by
  listening to or querying zero-configuration and broadcast/multicast
  protocols — mDNS/Bonjour, DNS-SD, SSDP/UPnP, WS-Discovery, LLMNR, and
  NBT-NS. Triggers include: "mDNS scan", "find Bonjour devices", "avahi",
  "discover printers and cameras", "SSDP", "UPnP discovery", "find smart
  devices", "chromecast/airplay discovery", "port 5353", "port 1900", "LLMNR",
  "NBT-NS", "is LLMNR enabled", "responder analyze", "WS-Discovery", or any
  request to enumerate the network by the service announcements devices
  broadcast about themselves. Also use when asked for the fastest local
  inventory of printers, cameras, NAS, casting targets and IoT, or whether
  legacy name-resolution protocols expose the network to credential relay.
---

# Service & Broadcast Discovery

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

Zero-configuration protocols make devices **announce themselves**: their
hostname, OS, model, and every service they run — printers, cameras, NAS,
casting targets, media servers. Where unicast scanning has to guess a service
from a port number, these protocols hand you the service metadata directly, and
often for the whole subnet from a single multicast query.

**Two kinds of value:**
1. **Fastest local inventory available** — one mDNS or SSDP query enumerates
   every advertising device with its role and software, in seconds.
2. **Findings in their own right** — the legacy name-resolution protocols
   (**LLMNR**, **NBT-NS**, **mDNS**) fall back to unauthenticated multicast,
   which lets a rogue responder capture NTLM authentication. Their mere
   presence is the precondition for a whole class of credential-relay attacks.

---

## The Protocols

| Protocol | Port | Used by | Announces |
|---|---|---|---|
| **mDNS / Bonjour** | UDP 5353 | Apple, Linux (Avahi), printers, IoT | Hostname, services, model |
| **DNS-SD** | UDP 5353 | Rides on mDNS | Service types and instances |
| **SSDP / UPnP** | UDP 1900 | Smart TVs, routers, media, IoT | Device type, model, control URLs |
| **WS-Discovery** | UDP 3702 | Windows, ONVIF IP cameras, printers | Device type, service endpoints |
| **LLMNR** | UDP 5355 | Windows name resolution fallback | (Exploitable — see below) |
| **NBT-NS** | UDP 137 | Legacy Windows name resolution | Hostnames, NetBIOS names |

---

## Install

```bash
sudo apt install avahi-utils nmap python3-zeroconf smbclient -y   # Debian/Ubuntu
# Responder (for the LLMNR/NBT-NS analysis in Step 4):
sudo apt install responder -y     # Kali; otherwise clone SpiderLabs/Responder
```

---

## Step 1 — mDNS / Bonjour (the richest source)

### Browse everything advertised on the segment

```bash
# Enumerate every service type, then resolve each instance. One command,
# whole subnet. -a = all services, -r = resolve, -t = terminate when done.
avahi-browse -art

# Just the service types present
avahi-browse --browse --all --terminate | awk '{print $NF}' | sort -u
```
```
+ eth0 IPv4 HP LaserJet 4250        _ipp._tcp     local
+ eth0 IPv4 Living Room             _airplay._tcp local
+ eth0 IPv4 synology-nas            _smb._tcp     local
+ eth0 IPv4 Brian's MacBook Pro     _ssh._tcp     local
```

Each line is a host, its role, and a service — a labelled inventory no port
scan produces. Service types worth targeting explicitly:

```bash
avahi-browse -rt _ssh._tcp        # SSH hosts (with hostnames)
avahi-browse -rt _smb._tcp        # file shares / NAS
avahi-browse -rt _ipp._tcp        # printers (IPP)
avahi-browse -rt _airplay._tcp    # AirPlay / casting targets
avahi-browse -rt _http._tcp       # web admin panels
avahi-browse -rt _workstation._tcp
```

### Nmap alternative (no Avahi daemon required)

```bash
sudo nmap -6 --script=broadcast-dns-service-discovery
sudo nmap --script=dns-service-discovery -p 5353 $TARGET
```

> **Why mDNS beats a port scan for IoT:** the TXT records carry model,
> firmware, and capabilities the device volunteers — a printer advertises its
> exact model and page count, a camera its ONVIF profile. That is
> asset-inventory data unicast scanning cannot extract.

---

## Step 2 — SSDP / UPnP

```bash
# Nmap multicasts an M-SEARCH and reports responders with their device info
sudo nmap --script=broadcast-upnp-info

# Manual M-SEARCH — send the discovery datagram, read the LOCATION URLs
python3 - <<'PY'
import socket
msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
       'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.settimeout(3)
s.sendto(msg.encode(), ("239.255.255.250", 1900))
seen = set()
try:
    while True:
        data, addr = s.recvfrom(2048)
        for line in data.decode(errors="ignore").splitlines():
            if line.lower().startswith("location:"):
                if addr[0] not in seen:
                    print(addr[0], line.split(":",1)[1].strip())
                    seen.add(addr[0])
except socket.timeout:
    pass
PY
```

Each `LOCATION` URL points at an XML device description — fetch it for the
model, manufacturer, serial, and the list of exposed control services. UPnP
control endpoints reachable from the LAN are frequently a finding (IGD port
mapping, media server file access).

---

## Step 3 — WS-Discovery (cameras, printers, Windows)

```bash
# ONVIF IP cameras and WSD printers answer WS-Discovery probes on UDP 3702.
# wsdd or a probe script enumerates them:
sudo nmap -sU -p 3702 --script broadcast-listener $SUBNET
```

WS-Discovery is the fastest way to locate networked cameras — ONVIF devices
respond with their service endpoints, from which model and stream URLs follow.

---

## Step 4 — LLMNR / NBT-NS: Presence Is the Finding

LLMNR (UDP 5355) and NBT-NS (UDP 137) are what Windows falls back to when DNS
fails to resolve a name. Both are unauthenticated multicast/broadcast, so **any
host on the segment can answer** — including a rogue responder that then
harvests the NTLM authentication the victim offers.

Detect whether they are in use **passively**, without poisoning anything:

```bash
# Responder's analyze mode: LISTEN ONLY. It observes LLMNR/NBT-NS/mDNS
# queries and BROWSER announcements and reports them WITHOUT answering.
sudo responder -I $IFACE -A

# Zero-dependency equivalent: just watch for the queries
sudo tcpdump -i $IFACE -ln 'udp port 5355 or udp port 137'
```

```
[Analyze mode: LLMNR] Request by 192.168.1.50 for 'fileserver', ignoring
[Analyze mode: NBT-NS] Request by 192.168.1.61 for 'WPAD', ignoring
```

**What this tells you:**
- Any LLMNR or NBT-NS query observed → the protocol is enabled on that host →
  it is exploitable by name-resolution poisoning. This is a reportable finding
  on a Windows estate.
- A query for **`WPAD`** is a high-value signal: WPAD-over-LLMNR is the classic
  path to proxying a victim's web traffic.

> **`-A` (analyze) only.** Running Responder *without* `-A` actively answers
> the queries and captures credentials — that is an attack, not discovery. Do
> not cross that line without explicit, written authorisation covering active
> credential capture. This skill stops at detection.

**Remediation to recommend:** disable LLMNR (Group Policy: *Turn off multicast
name resolution*) and NBT-NS (per-adapter or via DHCP option 001), and ensure
DNS resolves the names hosts actually ask for so the fallback never triggers.

---

## Step 5 — Build the Inventory

```bash
# Combined broadcast sweep — mDNS, SSDP, and NetBIOS in one pass
sudo nmap --script "broadcast-dns-service-discovery,broadcast-upnp-info,\
broadcast-netbios-master-browser,nbstat" $SUBNET

# Cross-reference NetBIOS names for Windows hosts
nmblookup -A $TARGET          # from smbclient
```

Broadcast discovery labels devices that a raw port scan leaves anonymous:
`_ipp._tcp` is a printer, `_googlecast._tcp` is a Chromecast, an ONVIF
WS-Discovery reply is a camera. Merge these labels into the inventory from the
active-scan skills to turn "192.168.1.61: 80,443 open" into "Axis IP camera,
web admin exposed."

---

## Quick Reference

```bash
# mDNS: everything advertised, resolved
avahi-browse -art

# SSDP/UPnP
sudo nmap --script=broadcast-upnp-info

# LLMNR/NBT-NS presence — LISTEN ONLY
sudo responder -I $IFACE -A

# NetBIOS name of a host
nmblookup -A $TARGET
```

---

## Common Mistakes

| Symptom | Usually means | Do this |
|---|---|---|
| No mDNS responses | Multicast does not cross subnets, and many APs filter it | You must be on the same L2 segment as the targets |
| LLMNR and NBT-NS silent | Good posture — they are disabled | Record *disabled*. That is the finding you wanted |
| Devices announce names that look wrong | Names are self-chosen and freely editable | Treat as a lead, not an identity |
| SSDP returns far more than expected | One device advertises many services | De-duplicate by host before counting devices |

**The inference ceiling.** These protocols prove **what a device chose to announce about itself**. Every field — name, model, service list — is self-reported and unverified, so treat it as a lead to confirm, never as inventory truth.

---

## When to Use Something Else

| Scenario | Better tool |
|---|---|
| Active port/service enumeration | `nmap -sV` — see nmap-network-discovery |
| Reading switch/router tables | snmp-network-inventory skill |
| Fully passive, all protocols | passive-network-discovery skill |
| Active LLMNR/NBT-NS credential capture | Responder without `-A` — attack, needs explicit scope |
| Unicast DNS recon | (a future dns-recon skill) |

---

## Ethical and Legal Notice

Querying broadcast/multicast discovery protocols is low-impact, but this skill
draws a hard line at **detection**: Responder's `-A` mode and the listeners
here observe only. Actively answering LLMNR/NBT-NS/mDNS queries captures other
users' credentials and is an attack that requires explicit written
authorisation covering credential interception. Enumerate and report; do not
poison. Only operate on networks you own or are authorised to test.

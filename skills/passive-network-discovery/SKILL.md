---
name: passive-network-discovery
description: >
  Use this skill when the user wants to discover hosts and services WITHOUT
  sending packets — passive, zero-transmission reconnaissance. Triggers
  include: "passive scan", "passive discovery", "discover without sending
  packets", "sniff the network", "stealth discovery", "p0f", "bettercap
  passive", "arpwatch", "listen for hosts", "OS fingerprint passively",
  "don't touch the hosts", "safe discovery on fragile devices", "monitor
  network traffic for devices", or any request to inventory a segment by
  observation only. Use this when active scanning is unsafe (ICS/OT, medical,
  legacy embedded), forbidden by scope, or defeated by client isolation — and
  when you want to find hosts that active scanning misses because they only
  speak, never answer.
---

# Passive Network Discovery

## Before You Run Anything

1. **Confirm the target with the user** — the domain, cloud account, or
   capture interface — and state it back before the first command.
2. If the user has not named one, **ask**. Do not infer a target from the
   local environment, the shell history, or a config file you happen to find.
3. The output is an inventory of someone's assets. Scope is the user's to
   define and not yours to widen: do not follow a discovered name, subnet, or
   linked account outside what was confirmed.

Full legal statement: [Ethical and Legal Notice](#ethical-and-legal-notice).

### Set these first

Every command below uses these. Fill them in from the scope you just
confirmed, and substitute nothing by hand afterwards. An unset variable
makes the command fail loudly — that is the point; a hardcoded address
fails silently against the wrong network.

```bash
IFACE="eth0" # ip -br link  → the interface on that segment
```

---

Passive discovery emits **zero packets**. You place a sensor on the segment and
learn the network from the traffic that already flows across it. It is slower
than active scanning and finds only hosts that talk — but it has three
properties nothing active can match:

- **Undetectable.** No probes means nothing for an IDS, a defender, or a
  honeypot to see.
- **Safe on fragile targets.** ICS/OT controllers, medical devices, and old
  embedded stacks can be crashed by a routine SYN scan. Observation cannot
  crash anything.
- **Works where active scanning is blind.** Under Wi-Fi client isolation the
  active ARP scan sees nothing, but broadcast and multicast traffic still
  reaches a sensor.

**Run it alongside an active scan.** The most valuable output is the *delta*:
a host that appears passively but not actively is answering its neighbours
while ignoring your probes — a firewalled or probe-averse host you would
otherwise miss.

---

## Install

```bash
# tcpdump is near-universal but not guaranteed — install it explicitly
sudo apt install tcpdump netdiscover p0f arpwatch -y   # Debian/Ubuntu/Kali
# bettercap and zeek are separate packages:
sudo apt install bettercap zeek -y                      # or build zeek from source
```

None of these is truly built in — verify before relying on one in a script:

```bash
for t in tcpdump p0f netdiscover arpwatch bettercap zeek; do
  command -v "$t" >/dev/null || echo "missing: $t"
done
```

---

## Getting the Traffic to Your Sensor

Passive discovery is only as good as its vantage point. On a switched network
a normal port sees only broadcast, multicast, and its own unicast — enough for
a lot, but not everything.

| Vantage | Sees | How |
|---|---|---|
| Normal switch port | Broadcast + multicast (ARP, mDNS, DHCP, LLDP…) | Default |
| **SPAN / mirror port** | All traffic on mirrored ports/VLANs | Switch config |
| **Network TAP** | All traffic, fail-safe, no switch load | Inline hardware |
| Hub (rare) | Everything on the collision domain | Legacy only |

For a full inventory, arrange a SPAN port or a TAP. For broadcast/multicast
discovery — which already yields most of the host list — any port works.

```bash
# Put the interface in promiscuous mode (a TAP/SPAN needs this to see
# unicast destined elsewhere). Broadcast/multicast arrive without it.
sudo ip link set $IFACE promisc on
```

---

## Step 1 — Passive Host Discovery

### The near-universal baseline (tcpdump)

```bash
# Every device doing ARP announces its IP and MAC. Just listen.
sudo tcpdump -i $IFACE -ln arp

# Broaden to all the chatty broadcast/multicast protocols at once
sudo tcpdump -i $IFACE -ln \
  'arp or (udp port 5353) or (udp port 5355) or (udp port 137) or (udp port 67)'
```

### netdiscover — passive ARP mode

```bash
# -p = passive: sniff only, transmit nothing. Live table of hosts.
sudo netdiscover -i $IFACE -p
```

### bettercap — passive recon from the ARP cache and observed traffic

```bash
sudo bettercap -iface $IFACE -eval "set net.recon.passive true; net.recon on; sleep 60; net.show; quit"
```

`net.recon` in passive mode reads the system ARP table and observed frames on
a timer and sends nothing.

### arpwatch — continuous, and it catches spoofing

```bash
# Records every IP↔MAC pairing it sees and logs new stations and
# "flip-flops" (an IP changing MAC) — the signature of ARP spoofing.
sudo arpwatch -i $IFACE
sudo tail -f /var/log/syslog | grep arpwatch
```

---

## Step 2 — Passive OS Fingerprinting with p0f

p0f identifies operating systems from the TCP/IP characteristics of packets a
host *already* sends — SYN, SYN+ACK, RST — without a single probe. It works on
the observation that stacks differ in initial TTL, window size, MSS, and option
ordering.

```bash
sudo p0f -i $IFACE

# Read from a capture instead of live
sudo p0f -r capture.pcap

# Log structured output for later correlation
sudo p0f -i $IFACE -o p0f.log
```
```
.-[ 192.168.1.50/49221 -> 140.82.112.3/443 (syn) ]-
| os       = Linux 3.11 and newer
| dist     = 0
| params   = none
| raw_sig  = 4:64+0:0:1460:mss*20,10:mss,sok,ts,nop,ws:df,id+:0
`----
```

p0f also passively fingerprints HTTP clients and uptime. Because it never
transmits, it is the safe way to get an OS guess on an ICS segment where
`nmap -O` is off the table.

> **Modern caveat.** MAC randomization and uniform mobile stacks blunt
> OS-level fingerprinting for clients. For encrypted traffic, TLS fingerprints
> (**JA4/JA4+**, the successor to JA3, stable even when clients shuffle
> extension order) identify the *application* rather than the OS. Zeek ingests
> both p0f and JA4 into its connection logs — see Step 3.

---

## Step 3 — Zeek for Structured Passive Inventory

For anything beyond ad-hoc `tcpdump`, Zeek turns observed traffic into logs:
every host, every connection, every service, DNS query, TLS certificate, and
software banner — all passively.

```bash
# Process a capture into a directory of structured logs
zeek -r capture.pcap

# Or run live on an interface
sudo zeek -i $IFACE

# What it produces:
#   conn.log      every connection: who talked to whom, ports, bytes
#   dns.log       every name resolved — a passive host+service map
#   ssl.log       TLS certs, SNI, and (with the package) JA4 fingerprints
#   software.log  server/client software versions seen in banners
#   known_hosts.log / known_services.log  the passive inventory
```

```bash
# Passive host inventory, straight from the logs
cat known_hosts.log 2>/dev/null | zeek-cut host | sort -u

# Passive service inventory (host, port, service) — no probe ever sent
cat known_services.log 2>/dev/null | zeek-cut host port_num service_name | sort -u
```

`known_services.log` is a service inventory built entirely from observation —
the passive equivalent of an Nmap `-sV` sweep, with zero packets sent to the
targets.

---

## Step 4 — How Long to Listen

Passive discovery trades time for stealth. A host that checks in hourly will
not appear in a 30-second capture, so **absence is only meaningful relative to
your capture window.**

| Window | Catches |
|---|---|
| Seconds | Chatty hosts: ARP, mDNS, active sessions |
| Minutes | Most workstations and servers during activity |
| Hours | Periodic beacons, backup jobs, scheduled tasks |
| A full business day | Everything that runs on a daily cycle |

Report the window alongside the inventory: *"47 hosts observed over 4 hours"*
is a finding; *"the network has 47 hosts"* is a claim the method cannot support.

---

## The Active/Passive Delta

Run both, then diff. The interesting sets are the ones that differ.

```bash
# Active view
sudo arp-scan --localnet --plain --format='${ip}' | sort -u > active.txt

# Passive view (let netdiscover run, or extract from Zeek)
sudo timeout 600 netdiscover -i $IFACE -p -P 2>/dev/null \
  | awk '/^[0-9]/{print $1}' | sort -u > passive.txt

# Seen passively but NOT actively: hosts ignoring your probes
comm -13 active.txt passive.txt

# Seen actively but NOT passively: hosts that answer but stay quiet otherwise
comm -23 active.txt passive.txt
```

Hosts in the first set are the payoff — firewalled, probe-averse, or
security-monitored machines that a purely active sweep would report as absent.

---

## Quick Reference

```bash
# Baseline host discovery (needs tcpdump)
sudo tcpdump -i $IFACE -ln arp

# Passive ARP table
sudo netdiscover -i $IFACE -p

# Passive OS fingerprint
sudo p0f -i $IFACE

# ARP spoofing / new-station monitor
sudo arpwatch -i $IFACE

# Full structured passive inventory
zeek -r capture.pcap && cat known_hosts.log | zeek-cut host | sort -u
```

---

## Common Mistakes

| Symptom | Usually means | Do this |
|---|---|---|
| Nothing observed at all | The sensor is not receiving the traffic, or you have not listened long enough | Verify the span/tap first. A quiet 30 seconds says nothing about the segment |
| Far fewer hosts than an active scan | Expected — passive only sees hosts that transmit | The delta is the signal, in both directions |
| Hosts appear that the active scan missed | They talk to their neighbours while ignoring you | That is the point of running both |
| OS fingerprint disagrees with `nmap -O` | Different evidence: p0f reads real traffic, nmap reads responses to crafted probes | Prefer the passive answer for a host behind a firewall |

**The inference ceiling.** Passive capture proves **that a host transmitted within your window**. Absence is never evidence of absence — it only means the host did not speak where your sensor could hear it.

---

## When to Use Something Else

| Scenario | Better tool |
|---|---|
| Need results now, active is allowed | `arp-scan`, `nmap` |
| Full port/service enumeration | `nmap -sV` — active is required |
| Reading infra tables instead of the wire | snmp-network-inventory skill |
| Broadcast service enumeration specifically | service-broadcast-discovery skill |
| Wireless passive capture (802.11 mgmt frames) | `kismet`, `airodump-ng` |
| Industrial/OT device discovery | ics-ot-discovery skill (passive-first) |

---

## Ethical and Legal Notice

Passive discovery sends no packets, but capturing traffic you are not a party
to is **wiretapping** and is often more tightly regulated than active
scanning, not less. Placing a TAP or configuring a SPAN port on a network you
do not own requires explicit authorisation, and captured traffic may contain
credentials and personal data that carry their own handling obligations. Only
capture on networks you own or are authorised to monitor, and treat the
resulting pcaps as sensitive.

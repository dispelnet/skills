---
name: ipv6-network-discovery
description: >
  Use this skill when the user wants to discover, enumerate, or audit hosts
  over IPv6. Triggers include: "scan IPv6", "find IPv6 hosts", "IPv6 network
  discovery", "NDP scan", "neighbor discovery", "ping6 the network", "scan
  my IPv6 subnet", "find link-local addresses", "IPv6 host enumeration",
  "dual-stack audit", "is IPv6 exposed", "scan6", "alive6", "ndisc6", or any
  request to enumerate devices where ARP does not apply because the network
  is IPv6. Also use when an IPv4 scan came back clean but the network is
  dual-stack, or when asked why an IPv6 subnet cannot be swept like a /24.
---

# IPv6 Network Discovery

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
TARGET4="192.168.1.10"  # the host's IPv4 address
TARGET6="2001:db8::10"  # the host's IPv6 address
PREFIX6="2001:db8::/64" # the confirmed IPv6 prefix
IFACE="eth0"            # ip -br link  → the interface on that segment
```

---

**ARP does not exist in IPv6.** Its role is taken by NDP (Neighbor Discovery
Protocol), which runs over ICMPv6 and uses multicast rather than broadcast.
`arp-scan` is structurally incapable of finding an IPv6-only host, and every
technique built on sweeping an address range breaks against a /64.

**The blind spot this closes:** IPv6 is enabled by default on every modern
operating system. Host firewalls are routinely configured through `iptables`
while `ip6tables` is left empty, and perimeter ACLs are frequently written for
IPv4 only. A dual-stack host can be locked down on IPv4 and completely open on
IPv6 — an IPv4-only audit reports it clean.

The authoritative reference is **RFC 7707**, *Network Reconnaissance in IPv6
Networks* (Gont & Chown, 2016), which supersedes RFC 5157.

---

**Supporting reference:** `off-link-discovery-reference.md` covers remote
/64s (RFC 7707 address-pattern analysis, DNS and external sources) and the
extension-header drops that make a scan return nothing. Load it only when the
targets are off-link, or when a scan came back empty and should not have.

---

## Why You Cannot Sweep a /64

A single IPv6 subnet holds 2⁶⁴ ≈ **1.8 × 10¹⁹** addresses. At one million
probes per second, one /64 takes roughly **584,000 years**.

Brute force is not slow here, it is impossible. Every technique below replaces
sweeping with one of three things:

| Approach | Works because |
|---|---|
| **Multicast** | One packet to `ff02::1` reaches every node on the link |
| **Address patterns** | Real addresses are not uniformly distributed |
| **External sources** | DNS, logs, and neighbour caches already list them |

---

## Install

```bash
# Debian / Ubuntu / Kali
sudo apt install ndisc6 ipv6toolkit thc-ipv6 nmap -y

# Fedora / RHEL
sudo dnf install ndisc6 nmap -y

# Arch
sudo pacman -S ndisc6 nmap

# macOS
brew install nmap        # ndisc6/scan6 are Linux/BSD; use nmap + native tools
```

| Package | Provides |
|---|---|
| `ndisc6` | `ndisc6` (neighbour lookup), `rdisc6` (router discovery), `rdnssd` |
| `ipv6toolkit` | `scan6` — the most capable IPv6 scanner, plus packet crafting |
| `thc-ipv6` | `alive6` — installed as `atk6-alive6` on Debian/Ubuntu/Kali |
| `nmap` | `-6` scanning and the `targets-ipv6-multicast-*` NSE scripts |

---

## Know Your Address Types First

Which discovery technique applies depends entirely on address scope.

| Prefix | Name | Notes |
|---|---|---|
| `fe80::/10` | Link-local | Always present, never routed. Needs a zone: `fe80::1%eth0` |
| `fc00::/7` | Unique local (ULA) | Private, routed internally. `fd00::/8` in practice |
| `2000::/3` | Global unicast (GUA) | Internet-routable |
| `ff00::/8` | Multicast | `ff02::1` all-nodes, `ff02::2` all-routers |
| `::1` | Loopback | |

Interface identifiers (the low 64 bits) come from one of these, and the source
determines how guessable an address is:

| IID source | Example | Guessable? |
|---|---|---|
| Manual / low-byte | `2001:db8::1`, `::53` | **Trivially** — servers, gateways |
| EUI-64 from MAC | `2001:db8::a8bb:ccff:fedd:eeff` | Yes, if you know the OUI |
| IPv4-embedded | `2001:db8::192.168.1.10` | **Trivially** |
| Wordy | `2001:db8::dead:beef` | Often — small dictionary |
| Stable privacy (RFC 7217) | `2001:db8::9c4f:2a1e:...` | No |
| Temporary (RFC 8981) | rotates | No |

Servers and infrastructure overwhelmingly use the guessable forms. Clients use
the unguessable ones. This asymmetry is what makes targeted IPv6 recon work.

---

## Step 1 — Local Link Discovery (Start Here)

On the local segment, multicast makes discovery **easier and faster than
IPv4** — one packet reaches everything.

### Fastest possible: ping the all-nodes address

```bash
# Every IPv6 host on the link should answer
ping -6 -c 3 ff02::1%$IFACE

# Read the neighbour cache that the ping just populated
ip -6 neigh show
ip -6 neigh show | grep -v FAILED
```

`ip -6 neigh` is the IPv6 equivalent of `arp -a`. Ping first, then read it —
the cache only holds what has recently been resolved.

### scan6 — the most thorough local scanner

```bash
sudo scan6 -i $IFACE -L                  # local link scan
sudo scan6 -i $IFACE -L -e               # also print MAC addresses
sudo scan6 -i $IFACE -L -e -v            # verbose
sudo scan6 -i $IFACE -L -P global        # only globally routable addresses
sudo scan6 -i $IFACE -L -P local         # only link-local
sudo scan6 -i $IFACE -L -r 100pps        # rate limit
```

`scan6` varies the **source** address across probes, which elicits replies
from hosts that answer only some source-address selection policies. That is
why it consistently finds more than a plain `ping ff02::1`.

### alive6 — second opinion

`alive6` takes the interface as a **positional** argument, not `-i` (which is
an input file). Debian, Ubuntu and Kali all prefix thc-ipv6 binaries with
`atk6-`:

```bash
sudo atk6-alive6 $IFACE                     # local link
sudo atk6-alive6 -v $IFACE                  # verbose
sudo atk6-alive6 $IFACE $PREFIX6       # address/range is the 2nd positional arg
sudo atk6-alive6 -M $IFACE                  # enumerate via MAC-derived addresses
sudo atk6-alive6 -C $IFACE                  # try common address patterns
```

> Upstream builds install it as plain `alive6`. Check with
> `command -v atk6-alive6 || command -v alive6` before scripting it.

### Nmap multicast discovery

```bash
# Discover and immediately reuse the results as scan targets
sudo nmap -6 --script targets-ipv6-multicast-echo \
  --script-args "newtargets,interface=$IFACE" -sL

# Discover and port scan in a single pass
sudo nmap -6 -sS --top-ports 100 \
  --script targets-ipv6-multicast-echo \
  --script-args "newtargets,interface=$IFACE"
```

### When multicast echo finds nothing

**Windows does not reply to `ff02::1` echo requests by default** — the host
firewall drops them. Linux and macOS generally do reply. Silence is not
evidence of absence; fall back to techniques that do not depend on echo:

```bash
# Trigger SLAAC with a bogus prefix; hosts reveal themselves by soliciting
sudo nmap -6 --script targets-ipv6-multicast-slaac \
  --script-args "newtargets,interface=$IFACE" -sL

# Invalid destination option — elicits an ICMPv6 parameter problem reply
sudo nmap -6 --script targets-ipv6-multicast-invalid-dst \
  --script-args "newtargets,interface=$IFACE" -sL

# Query MLD for multicast listeners — passive-ish, very effective
sudo nmap -6 --script targets-ipv6-multicast-mld \
  --script-args "newtargets,interface=$IFACE" -sL
```

> `targets-ipv6-multicast-slaac` advertises a router prefix on the segment.
> That is a **network-modifying action** — hosts will configure an address
> from it. Use it only with explicit authorisation, and never on production
> without notice.

---

## Step 2 — Router and Prefix Discovery

Before scanning anything routed, learn which prefixes exist.

```bash
rdisc6 $IFACE                # send a Router Solicitation, print the RA
rdisc6 -r 5 -w 5000 $IFACE   # more retries, longer wait

# What the kernel already learned
ip -6 route show
ip -6 addr show
```

The Router Advertisement gives you the on-link prefix, the default gateway,
the MTU, and often DNS servers. The prefix is what makes every pattern-based
technique in Step 4 possible.

### Detecting rogue Router Advertisements

More than one router advertising on a segment is a finding. Rogue RAs — either
malicious, or a laptop with connection sharing enabled — make the sender the
default gateway for the whole link. It is the IPv6 analogue of ARP spoofing,
and a single `rdisc6` run will not catch an intermittent one.

```bash
# Watch continuously. ICMPv6 type 134 is a Router Advertisement.
sudo tcpdump -i $IFACE -nn 'icmp6 and ip6[40] == 134'

# Just the distinct advertising sources — more than one row is the finding
sudo timeout 300 tcpdump -i $IFACE -nn 'icmp6 and ip6[40] == 134' 2>/dev/null \
  | awk '{print $2}' | sort -u

# ndpmon watches NDP continuously and alerts on anomalies
sudo ndpmon -i $IFACE
```

Correlate each advertising source against the MAC you expect for the gateway;
a rogue RA from a host OUI rather than a network-equipment OUI is conclusive.

**Mitigation is switch-side: RA Guard** (IPv6 First-Hop Security), which drops
RAs arriving on access ports. Verify it actually works rather than assuming
the config is applied — with written authorisation, emit a benign RA from a
client port and confirm the switch drops it. `thc-ipv6` provides
`atk6-fake_router6` for exactly this test.

> That test **injects routing state onto a live segment**. Hosts that accept
> the RA will configure addresses and a default route from it. Never run it
> outside an agreed maintenance window.

---

## Step 2b — DHCPv6 Networks

Every technique so far assumes **SLAAC**, where hosts build their own address
from an advertised prefix. Managed networks use **DHCPv6** instead, and the
address patterns are completely different — typically dense, sequential
allocations from a server pool rather than EUI-64 or privacy identifiers.

Read the RA to find out which regime you are in. Two flags decide it:

| RA flag | Meaning |
|---|---|
| `M` (Managed) | Addresses come from DHCPv6 — a server holds the lease table |
| `O` (Other) | Address via SLAAC, but DNS/NTP come from DHCPv6 |
| Neither set | Pure SLAAC |

```bash
# rdisc6 prints the flags in its output
rdisc6 $IFACE | grep -iE 'stateful|managed|other'
```

Find the DHCPv6 servers themselves:

```bash
# Nmap solicits on ff02::1:2 (all DHCP agents) and reports responders
sudo nmap -6 --script broadcast-dhcp6-discover

# Raw solicit, watching the exchange
sudo tcpdump -i $IFACE -nn 'udp port 546 or udp port 547'
```

**Why this matters for discovery:** when `M` is set, the DHCPv6 server holds a
lease table listing every address it has issued. That is a complete,
authoritative host inventory — far better than any scan. Ask for it before
probing. Failing that, DHCPv6 pools are usually narrow and sequential, so a
targeted `scan6 -d <prefix>::1-1000` covers them cheaply.

---

## Step 3 — Resolve a Known Address to a MAC

```bash
ndisc6 $TARGET6 $IFACE        # NDP lookup, prints the link-layer address
ndisc6 fe80::1 $IFACE            # link-local neighbour
```

### Reversing EUI-64 — recovering the MAC from an address

A SLAAC address built from a MAC embeds it: the OS flips the universal/local
bit of the first octet and inserts `ff:fe` in the middle. That is reversible,
so an IPv6 address alone can yield Layer-2 vendor intelligence — **including
for hosts on remote subnets, which ARP can never reach**.

```
MAC     aa:bb:cc:dd:ee:ff
        └─ flip bit 0x02 of the first octet ──> a8
        └─ insert ff:fe in the middle
IID     a8bb:ccff:fedd:eeff
Address 2001:db8::a8bb:ccff:fedd:eeff
```

An IID containing `ff:fe` in the middle is the tell:

```bash
# Recover the MAC from an EUI-64 IPv6 address
eui64_to_mac() {
  python3 -c '
import sys, ipaddress
b = ipaddress.IPv6Address(sys.argv[1]).packed[8:]
if b[3] != 0xff or b[4] != 0xfe:
    sys.exit("not an EUI-64 address")
o = bytearray(b[:3] + b[5:])
o[0] ^= 0x02
print(":".join(f"{x:02x}" for x in o))' "$1"
}

eui64_to_mac 2001:db8::a8bb:ccff:fedd:eeff
# aa:bb:cc:dd:ee:ff  -> then look up the OUI vendor as usual
```

Cross-reference the recovered OUI using the vendor guidance in the
**arp-network-discovery** skill.

---

## Step 4 — Off-Link Discovery (RFC 7707 Techniques)

Steps 1–3 work because multicast and NDP reach the local link. Neither crosses
a router, so a remote /64 needs a different approach entirely: address-pattern
analysis, DNS, and external sources rather than probing.

**See `off-link-discovery-reference.md`** for the RFC 7707 techniques, the
aliased-prefix problem that makes un-de-aliased results mostly noise, and the
extension-header behaviour that silently drops probes mid-path.

---

## Step 5 — Hand Off to Nmap

Once you have addresses, everything from the **nmap-network-discovery** skill
applies with `-6` added.

```bash
# Collect discovered addresses
sudo scan6 -i $IFACE -L -P global > ipv6-hosts.txt

# Port and service scan
sudo nmap -6 -sS -sV --open -iL ipv6-hosts.txt -oA ipv6-inventory

# OS detection works over IPv6 too
sudo nmap -6 -O -sV $TARGET6

# Link-local targets need the zone index
sudo nmap -6 -sS fe80::a8bb:ccff:fedd:eeff%$IFACE
```

Then audit any SSH found using the **remote-access-discovery** skill —
`ssh-audit` accepts IPv6 addresses in brackets:

```bash
ssh-audit "[$TARGET6]"
ssh-audit -p 2222 "[$TARGET6]"
```

---

## The Dual-Stack Comparison That Matters

The point of this skill is the **delta**. Run both stacks and diff them.

```bash
# IPv4 view
sudo nmap -sS --top-ports 1000 --open $TARGET4 -oG v4.gnmap

# IPv6 view of the same host
sudo nmap -6 -sS --top-ports 1000 --open $TARGET6 -oG v6.gnmap

# Ports reachable over IPv6 but NOT over IPv4 — the actual finding
comm -13 \
  <(grep -oE '[0-9]+/open' v4.gnmap | sort -u) \
  <(grep -oE '[0-9]+/open' v6.gnmap | sort -u)
```

Any port in that output is exposed through a firewall gap. Check
`ip6tables -L -n` (or `nft list ruleset`) on the host — an empty IPv6 ruleset
alongside a populated IPv4 one is the usual cause.

---

## Quick Reference

```bash
# Local link — all hosts
ping -6 -c 3 ff02::1%$IFACE && ip -6 neigh show
sudo scan6 -i $IFACE -L -e -v

# Routers and prefixes
rdisc6 $IFACE

# Address -> MAC
ndisc6 $TARGET6 $IFACE

# Nmap multicast discovery + scan in one pass
sudo nmap -6 -sS --top-ports 100 \
  --script targets-ipv6-multicast-echo \
  --script-args "newtargets,interface=$IFACE"

# Remote prefix, pattern-based
sudo scan6 -d $PREFIX6 -P global -v

# Port scan discovered hosts
sudo nmap -6 -sS -sV --open -iL ipv6-hosts.txt
```

---

## Common Mistakes

| Mistake | Reality |
|---|---|
| `nmap -6 -sn 2001:db8::/64` | 584,000 years. Use multicast or patterns |
| Omitting the zone index on link-local | `fe80::1` is ambiguous; use `fe80::1%eth0` |
| Treating multicast silence as "no hosts" | Windows drops `ff02::1` echo by default |
| Using `arp-scan` on an IPv6 network | ARP does not exist in IPv6 |
| Scanning IPv4 only on a dual-stack net | `ip6tables` is often empty when `iptables` is not |
| `-g`/OUI lookup on a privacy address | RFC 8981 IIDs are random and carry no vendor |
| Reading `ip -6 neigh` without probing | The cache only holds recent resolutions |
| `alive6 -i eth0` | `-i` is an input file; the interface is positional |
| Trusting a prefix where everything answers | Aliased prefix — de-alias before reporting |
| Assuming SLAAC everywhere | Check the RA `M` flag; DHCPv6 has a lease table |
| Reading silence as "host down" | Extension headers are widely dropped in transit — see `off-link-discovery-reference.md` |
| One `rdisc6` run as rogue-RA check | Intermittent RAs need continuous capture |

**The inference ceiling.** IPv6 discovery proves **that an address responded**, and on an aliased prefix even that is unreliable. De-alias before reporting, and treat a resolved address as a lead that still needs to be in scope.

---

## When to Use Something Else

| Scenario | Better tool |
|---|---|
| IPv4 local subnet discovery | `arp-scan` — see arp-network-discovery |
| Port/service/OS enumeration | `nmap -6` — see nmap-network-discovery |
| SSH/Telnet auditing | `ssh-audit` — see remote-access-discovery |
| Internet-wide IPv6 measurement | `zmap` IPv6 support, IPv6 hitlists |
| Passive IPv6 inventory | Switch/router neighbour tables via SNMP, netflow |

---

## Ethical and Legal Notice

Only scan networks you own or have explicit written authorisation to test.
Note that some techniques here are **network-modifying**, not merely
observational: `targets-ipv6-multicast-slaac` advertises a router prefix, and
several `thc-ipv6` tools craft Neighbor Discovery traffic that can alter
neighbour caches or trigger address configuration on other hosts. Confirm
these are in scope before running them, and never on production without
notice. Unauthorised scanning may violate computer misuse laws and
organisational policy.

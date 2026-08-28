---
name: nmap-network-discovery
description: >
  Use this skill when the user wants to discover, scan, or inventory a
  network using Nmap. Triggers include: "scan my network", "find open ports",
  "discover hosts", "what's running on this server", "OS detection",
  "service version scan", "port scan", "nmap", "network inventory",
  "asset discovery", "find devices on subnet", or any request to enumerate
  hosts, services, or operating systems across one or more IP addresses or
  CIDR ranges. Also use when asked whether a firewall is filtering a port, or
  what changed between two scans of the same range.
---

# Nmap Network Discovery

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
```

---

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

**Supporting references** — load only the one you need:

| File | Load when |
|---|---|
| `firewall-mapping-reference.md` | The question is what the filtering does, not what is open; a `-p-` sweep needs to resume; the range is above a /20 |
| `nse-reference.md` | Before running any `--script`, and to check what phones home |
| `inventory-workflow-reference.md` | Building a repeatable or scheduled inventory, or diffing two scans |

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
- **Ndiff** — compare two scan results (`inventory-workflow-reference.md`)
- **Nping** — packet generation and response analysis

---

## How Nmap Discovers Hosts

Nmap's default probe set depends on **privilege** and **where the target is**:

| Context | Default probes sent |
|---|---|
| Root, target on local Ethernet segment | **ARP only** — Nmap ignores the IP probes entirely |
| Root, routed/remote target | ICMP echo, TCP SYN → 443, TCP ACK → 80, ICMP timestamp |
| Non-root, any target | TCP `connect()` → 80 and 443 (no raw packets available) |

Two consequences worth internalising:

- On a local subnet as root, `-sn` is already an ARP scan. Adding `-PR` is
  explicit but redundant; forcing IP probes instead needs `--send-ip`.
- Running without root **silently changes what you scanned**. A non-root sweep
  that finds nothing is not evidence that nothing is there.

**No single probe type is sufficient.** Bano et al. (*Scanning the Internet
for Liveness*, ACM SIGCOMM CCR 2018) ran concurrent ICMP, five TCP and two UDP
scans against the IPv4 space and found ICMP echo reveals only **79%** of
responsive hosts, with **16% discoverable exclusively via TCP** and ~2% only
via UDP. They also found the majority of hosts answer *inconsistently* across
ports — only 24% of hosts with a live TCP stack responded to every TCP probe.
Layer your probe types, and treat a single negative sweep as inconclusive.

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

## Scope Control — Staying Inside Authorisation

Authorisation is almost always scoped to *specific* ranges with carve-outs.
A CIDR block is a blunt instrument: `10.0.0.0/16` will happily include the
one `/24` you were told to leave alone. Enforce exclusions in the tool, not
in your attention.

```bash
# Exclude specific hosts or ranges inline
nmap $SUBNET --exclude 10.0.5.0/24,10.0.9.11

# Better: keep exclusions in a file, committed alongside the engagement notes
nmap $SUBNET --excludefile out-of-scope.txt
```

`out-of-scope.txt` takes one entry per line — single IPs, hostnames, ranges
or CIDR blocks:

```
# Medical devices — never scan, vendor-certified configuration
10.0.5.0/24
# Legacy PLC, crashes on SYN scan
10.0.9.11
# Third-party managed, not covered by this engagement
vendor-gw.corp.example.com
```

**Confirm your target set before sending a single packet.** `-sL` expands the
targets and applies exclusions without touching any host:

```bash
# Dry run: exactly which addresses would be scanned?
nmap -sL -n $SUBNET --excludefile out-of-scope.txt

# Count them, and eyeball the total before committing
nmap -sL -n $SUBNET --excludefile out-of-scope.txt | grep -c "Nmap scan report"
```

Do this every time the scope file changes. It is the only cheap way to catch
a typo'd CIDR that would otherwise widen your scan by a factor of 256.

---

## Rate Limiting — Hard Guarantees

Timing templates are *hints*: `-T4` raises parallelism and lowers timeouts,
but Nmap's dynamic timing still accelerates as far as the network permits.
There is no ceiling. When you have been given an actual number — "our IPS
alerts above 50 connections/sec", "this link is 10 Mbit and shared" — only
the rate flags enforce it.

```bash
# Hard ceiling: never exceed 40 packets/sec, regardless of template
sudo nmap -T4 --max-rate 40 -sS $SUBNET

# Floor: don't let a lossy WAN stall the scan indefinitely
sudo nmap --min-rate 100 -sS $SUBNET

# Cap concurrent probes against fragile embedded targets
sudo nmap --max-parallelism 1 --max-rate 10 -sS $SUBNET
```

| Control | Guarantee |
|---|---|
| `-T0`…`-T5` | None — a template, dynamic timing still applies |
| `--max-rate <n>` | Hard upper bound, packets/sec |
| `--min-rate <n>` | Hard lower bound, packets/sec |
| `--max-parallelism <n>` | Hard cap on in-flight probes |
| `--host-timeout <t>` | Abandon a host after `t`, so one tarpit can't stall a sweep |

Keep `-T4` on the command line even when adding rate flags — the fine-grained
options override the specific values they name while leaving the template's
other optimisations in place.

**Fragile targets exist.** ICS/SCADA controllers, medical devices, printers
and old embedded stacks can be crashed by a routine SYN scan. For anything in
that class, combine `--max-parallelism 1` with a low `--max-rate`, or don't
scan it at all — put it in the exclude file and note it in the report.

> For enumerating ICS/OT devices *safely* rather than just avoiding them, use
> the **ics-ot-discovery** skill — it is passive-first and imposes the hard
> constraints (`-sT`, `--scan-delay`, never `-sV`) that keep controllers up.

---

## Basic Recipes

### Quick host sweep (no port scan)
```bash
nmap -sn $SUBNET
```
Lists all live hosts on the subnet. Faster than a full scan; useful as a
first pass.

### List scan (DNS reverse lookup, no traffic sent to hosts)
```bash
nmap -sL $SUBNET        # resolves names, sends nothing to the targets
nmap -sL -n $SUBNET     # no DNS at all — sends nothing, anywhere
```

Useful for pre-flight recon and for confirming which addresses a target
expression expands to.

> **`-sL` is not silent.** It sends no packets to the *hosts*, but it does
> send a reverse-DNS query for every address to your configured resolver.
> Against an external engagement that hands your entire target list to a third
> party, and `--dns-servers 8.8.8.8` hands it to Google specifically. Use `-n`,
> or point `--dns-servers` at a resolver you control.

### Default port scan (top 1,000 TCP ports)
```bash
nmap $SUBNET
```

### Scan multiple networks at once
```bash
nmap $SUBNET 10.0.0.0/24    # append ranges — each must be in the confirmed scope
```

### Scan with ARP ping on local subnet (fast, reliable)
```bash
sudo nmap -sn -PR $SUBNET
```

---

## Port Scanning

### TCP SYN scan — fast, doesn't complete handshake (default with root)
```bash
sudo nmap -sS $TARGET
```

### TCP connect scan — completes the handshake (no root required)
```bash
nmap -sT $TARGET
```

### UDP scan — covers DNS, SNMP, DHCP, NTP, etc.

UDP has no handshake, so Nmap infers state from ICMP port-unreachable
replies — and Linux rate-limits those to roughly **one per second**. A full
`-sU -p-` scan of one host therefore takes upwards of 18 hours. This is a
kernel limit on the target, not something a faster template can fix.

```bash
# Practical default: the 100 most common UDP ports
sudo nmap -sU --top-ports 100 $TARGET

# Named services you actually care about — by far the fastest approach
sudo nmap -sU -p 53,67,123,161,500,1900 $TARGET

# Combine with a TCP SYN scan in a single pass
sudo nmap -sS -sU -p T:22,80,443,U:53,161 $TARGET

# --reason explains open|filtered results, which dominate UDP output
sudo nmap -sU --top-ports 50 --reason $TARGET
```

`open|filtered` means *no reply at all* — the port may be open and silent, or
dropped by a firewall. It is not a negative result.

### Scan specific ports
```bash
nmap -p 22,80,443 $TARGET
nmap -p 1-1024 $TARGET        # port range
nmap -p- $TARGET              # all 65,535 ports
```

### Show only open ports (suppress closed/filtered noise)
```bash
nmap --open $SUBNET
```

### Skip host discovery, scan all targets as if up
```bash
sudo nmap -Pn -sS $TARGET
```
Use this when a host is alive but blocks all ping probes.

---

## Service & Version Detection

```bash
# Detect service versions on open ports
nmap -sV $TARGET

# Scan specific ports for version info
nmap -sV -p 22,80,443 $SUBNET

# Show only open ports with version info
nmap -sV --open $SUBNET
```

```bash
# Control probe depth: 0 = lightest, 9 = try every probe
nmap -sV --version-intensity 9 $TARGET
nmap -sV --version-all $TARGET       # same as intensity 9
nmap -sV --version-light $TARGET     # intensity 2, much faster

# --allports: also probe 9100, which -sV skips by default
# (printers can spool a probe as a print job)
nmap -sV --allports $TARGET
```

Version detection probes services and reports the software name and version,
e.g. `OpenSSH 8.9p1`, `Apache httpd 2.4.29`. Useful for spotting outdated
or vulnerable software across the network.

**Never infer a service from its port number.** Izhikevich et al. (*LZR:
Identifying Unexpected Internet Services*, USENIX Security 2021) found only
**3% of HTTP** and **6% of TLS** services run on ports 80 and 443
respectively, and that services on non-standard ports are *more* likely to be
insecure — so port-based inference systematically underestimates risk. Port
443 running something other than TLS is unremarkable; port 8080 running SSH
is exactly the kind of finding a port-name-based inventory misses.

Two practical consequences:

```bash
# Always pair -p- with -sV. A wide port scan without version detection
# produces a list of numbers, not an inventory.
sudo nmap -p- -sV --open $TARGET

# Trust the SERVICE column only when a VERSION column backs it up.
# "http" with no version is Nmap reading nmap-services, i.e. guessing
# from the port number. "Apache httpd 2.4.62" is an actual probe result.
```

---

## OS Detection

```bash
# Detect operating system (requires root)
sudo nmap -O $TARGET

# OS detection with version scanning
sudo nmap -O -sV $TARGET
```

```bash
# Print a best guess even when no exact fingerprint matches
sudo nmap -O --osscan-guess $TARGET

# Only attempt OS detection where conditions are favourable —
# saves time across a subnet by skipping hopeless targets
sudo nmap -O --osscan-limit -iL live.txt

# Show the match confidence and the conditions Nmap had to work with
sudo nmap -O --reason -v $TARGET
```

Nmap compares TCP/IP stack responses against a fingerprint database to guess
the OS and kernel version. Accuracy depends on finding **at least one open and
one closed port** — `--osscan-limit` makes that condition explicit by skipping
hosts that do not meet it, and `--osscan-guess` relaxes the match threshold
when they do.

Treat results as an educated guess. Virtualisation, load balancers and NAT all
distort the fingerprint, and a middlebox may be what you actually fingerprinted.
Confirm directly on the host when precision matters.

---

## Comprehensive Scan (-A flag)

`-A` enables OS detection, service version detection, script scanning, and
traceroute in a single command:

```bash
sudo nmap -A $TARGET
```

This is a good starting point for a thorough first scan of a **single unknown
host**.

> **Do not run `-A` across a subnet as a first pass.** It is four scan types
> at once against every host: version detection, OS fingerprinting, the whole
> default NSE script category, and traceroute. On a /24 that is hours of
> runtime, a large volume of script traffic against hosts you have not yet
> triaged, and NSE scripts firing at services you did not know were there.

Scan in two stages instead — cheap sweep, then depth only where warranted:

```bash
# Stage 1: cheap. Which hosts are up, which ports are open?
sudo nmap -sS -T4 --top-ports 100 --open $SUBNET -oA sweep

# Stage 2: depth, only against hosts that actually answered
awk '/Status: Up/{print $2}' sweep.gnmap > live.txt
sudo nmap -A -T4 -iL live.txt -oA deep
```

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
sudo nmap -T4 -A $TARGET

# Slow, stealthy scan for IDS evasion
nmap -T1 -sS $SUBNET
```

Templates set no upper bound on scan rate. When you need one, see
"Rate Limiting — Hard Guarantees" above.

---

## Output Formats

```bash
# Normal text (default)
nmap -sV $SUBNET -oN scan.txt

# XML (machine-parseable, importable into tools)
nmap -sV $SUBNET -oX scan.xml

# Grepable format
nmap -sn $SUBNET -oG scan.gnmap

# All formats at once
nmap -sV $SUBNET -oA scan   # produces scan.nmap, scan.xml, scan.gnmap
```

### Convert XML to readable HTML report

Nmap's XML embeds an `xml-stylesheet` instruction pointing at the local
`nmap.xsl`, and `xsltproc` follows it automatically — no stylesheet argument
needed:

```bash
sudo apt install xsltproc -y
xsltproc -o scan.html scan.xml
```

**Opening the raw `.xml` in a browser no longer works.** Modern browsers
restrict where a stylesheet may be loaded from, so the file renders as raw
XML. Convert it with `xsltproc` first, or scan with `--webxml` so the XML
points at the hosted stylesheet instead of a local path:

```bash
# Portable XML — renders on any internet-connected machine
nmap -sV $SUBNET -oX scan.xml --webxml

# Explicit stylesheet, if the embedded path is wrong after moving the file
xsltproc -o scan.html /usr/share/nmap/nmap.xsl scan.xml
```

### Extract live IPs from grepable output
```bash
nmap -sn $SUBNET -oG - | awk '/Up$/{print $2}' > live-hosts.txt
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

## Scanning IPv6

Nmap needs `-6`, and a /64 cannot be swept — enumeration has to come from
multicast, NDP, or an external source first.

**Use the `ipv6-network-discovery` skill for this.** It covers the address
types, the RFC 7707 techniques, and how to hand a resolved host list back to
Nmap. Running `nmap -6` against a range without that step returns nothing and
proves nothing.

---

## DNS Reconnaissance

Nmap can resolve names and run DNS NSE scripts, but it is the wrong tool for
mapping a domain.

**Use the `dns-recon` skill for this** — records, AXFR, subdomain enumeration,
DNSSEC walking, and mail-security posture. Feed its host list back here with
`-iL`.

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
| `-6`      | Scan IPv6 targets                                 |
| `--open`  | Show only open ports                              |
| `-oA`     | Output in all formats simultaneously              |
| `-iL`     | Read targets from file                            |
| `--excludefile` | Exclude out-of-scope hosts listed in a file |
| `--max-rate`    | Hard ceiling on packets/sec (templates give none) |
| `--resume`      | Continue an interrupted scan from its `-oN`/`-oG` output — `firewall-mapping-reference.md` |
| `-sA`           | ACK scan — maps filtered vs unfiltered, not open ports — `firewall-mapping-reference.md` |
| `--reason`      | Show *why* Nmap called each port open/closed |
| `--script`| Run NSE script(s) — read `nse-reference.md` first  |
| `-v/-vv`  | Increase verbosity                                |

---

## Common Mistakes

| Symptom | Usually means | Do this |
|---|---|---|
| Every port `filtered` | A firewall dropped the probes — not that the host runs nothing | `-sA --reason` maps the ruleset; `--reason` prints the evidence for each verdict |
| Host reported down | The probe set varies by privilege and locality, and ICMP is widely blocked | `-Pn`, or change probe type. A clean sweep with one probe type proves nothing |
| `SERVICE` filled in, `VERSION` empty | Nmap read `nmap-services` — it guessed from the port number | Trust `SERVICE` only when a `VERSION` backs it |
| UDP scan is nearly all `open\|filtered` | Normal. For UDP, no reply is ambiguous by design | `--reason`, and narrow to named services rather than port ranges |
| Scan far slower than expected | Retransmits against a filtered network | `--max-retries 2` and `--host-timeout`; see `firewall-mapping-reference.md` |

**The inference ceiling.** A version string is **a claim made by the host**. Distributions backport security fixes without changing it, so a version match is a candidate for host-side confirmation — never a CVE finding on its own.

---

## When to Use Something Else

| Scenario                              | Better Tool                              |
|---------------------------------------|------------------------------------------|
| Local subnet only, fastest discovery  | `arp-scan` (Layer 2, firewall-immune)    |
| Internet-wide or /8+ scanning         | Masscan/ZMap then Nmap — `firewall-mapping-reference.md` |
| Passive discovery (no traffic sent)   | `netdiscover -p`, `bettercap net.recon`  |
| IPv6 host discovery                   | `scan6`, `ndisc6` — see ipv6-network-discovery |
| SNMP topology mapping                 | Netdisco, PRTG, SolarWinds               |
| Continuous monitoring & alerting      | Zabbix, Nagios, Nessus                   |
| GUI-based scanning                    | Zenmap (Nmap's official GUI)             |

---

## Ethical and Legal Notice

Only scan networks you own or have explicit written authorisation to test.
Unauthorised scanning may violate computer misuse laws and organisational
policy. This skill is intended for network administrators, security
professionals, and penetration testers operating within authorised scope.

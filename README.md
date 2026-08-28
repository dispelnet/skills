# Network Discovery Skills

A collection of network discovery and security enumeration skills that teach AI coding agents to perform reconnaissance using standard Linux tools.

## Install

Install the skills CLI:

```bash
curl -fsSL https://skills.sh | sh
```

### Add all skills

```bash
npx skills add https://github.com/dispelnet/skills
```

### Add a single skill

```bash
npx skills add https://github.com/dispelnet/skills --skill remote-access-discovery
```

## Skills

| Skill | Description |
| --- | --- |
| [arp-network-discovery](skills/arp-network-discovery) | Local IPv4 host discovery via ARP — live devices, MAC addresses, vendors, randomization handling |
| [ipv6-network-discovery](skills/ipv6-network-discovery) | IPv6 host discovery via NDP and multicast — RFC 7707 techniques where ARP does not apply |
| [nmap-network-discovery](skills/nmap-network-discovery) | Port scanning, service/version detection, OS fingerprinting, firewall mapping |
| [snmp-network-inventory](skills/snmp-network-inventory) | Read the authoritative tables from switches and routers — ARP, MAC-to-port, VLANs, LLDP/CDP topology |
| [passive-network-discovery](skills/passive-network-discovery) | Zero-packet discovery — sniffing, p0f, arpwatch, Zeek; safe on fragile ICS/OT segments |
| [service-broadcast-discovery](skills/service-broadcast-discovery) | mDNS/Bonjour, SSDP/UPnP, WS-Discovery, LLMNR/NBT-NS — device self-announcements and relay-risk detection |
| [remote-access-discovery](skills/remote-access-discovery) | SSH and Telnet auditing — `ssh-audit`, weak ciphers, Terrapin, CVE mapping, host-key reuse |
| [rdp-vnc-discovery](skills/rdp-vnc-discovery) | RDP, VNC and WinRM — NLA/encryption posture, BlueKeep, unauthenticated VNC, cleartext WinRM |
| [tls-certificate-discovery](skills/tls-certificate-discovery) | TLS/SSL posture and certificates — cipher/protocol grading, vuln matrix, expiry, Certificate Transparency discovery |
| [ics-ot-discovery](skills/ics-ot-discovery) | Industrial control systems — passive-first PLC/SCADA discovery, protocol map, and hard safety constraints for any active probe |
| [dns-recon](skills/dns-recon) | DNS enumeration — records, AXFR zone transfer, subdomains, DNSSEC walking, name-server and mail-security checks |
| [wireless-network-discovery](skills/wireless-network-discovery) | 802.11 Wi-Fi recon — monitor-mode AP/client discovery, hidden SSIDs, rogue/evil-twin detection, WPA2/WPA3 posture |
| [cloud-network-discovery](skills/cloud-network-discovery) | AWS/Azure/GCP virtual networks via the provider APIs — VPC/VNet, instances, security groups, internet exposure |
| [discovery-inventory](skills/discovery-inventory) | Merge arp-scan/nmap/etc output into one JSON record per host — dedup, accumulate across runs, drive the next stage |

### How they fit together

```
  DISCOVER HOSTS                      ENUMERATE                    AUDIT SERVICES
┌───────────────────────┐        ┌──────────────────┐        ┌──────────────────────┐
│ arp-scan       (IPv4) │        │                  │        │ remote-access        │
│ ndisc6/scan6   (IPv6) │───────>│      nmap        │───────>│   (SSH / Telnet)     │
│ passive     (sniffed) │ hosts  │ ports + services │ hosts+ │ rdp-vnc              │
│ service-broadcast     │        │ + firewall map   │ ports  │   (RDP / VNC / WinRM)│
│                       │        │                  │        │ tls-certificate      │
└───────────────────────┘        └──────────────────┘        └──────────────────────┘
        ▲                                                              │
        │ snmp-network-inventory reads the switch's own tables ────────┘
          (authoritative — bypasses client isolation and VLAN limits)
```

Every stage converts into one shared host record (`discovery-inventory`), so
the pipeline chains without per-pair glue and results **accumulate across
runs** instead of being reparsed each time.

Two rules the pipeline encodes:

- **Run every discovery path on a dual-stack network.** A host firewalled on
  IPv4 with an empty `ip6tables` ruleset is invisible to an IPv4-only sweep —
  the delta between paths is often the finding.
- **When active scanning is blocked or unsafe, change layers, not flags.**
  Wi-Fi client isolation and VLAN segmentation defeat ARP; `snmp-network-inventory`
  reads the switch's own tables, and `passive-network-discovery` observes
  traffic no probe could elicit.

## Design notes

A few decisions in these skills run against common advice, so the reasoning is
recorded here.

**Probe types are layered, not chosen.** Bano et al. found ICMP echo reveals
only 79% of responsive hosts, with 16% discoverable exclusively via TCP and ~2%
only via UDP — and that most hosts answer inconsistently across ports. A single
negative sweep is inconclusive by construction.

**Never infer a service from its port number.** Izhikevich et al. measured just
3% of HTTP and 6% of TLS services running on ports 80 and 443, and found
off-port services are *more* likely to be insecure. Version detection is not
optional polish — and the same finding is why tls-certificate-discovery scans
by service across many ports rather than auditing only 443.

**Duplicate SSH host keys are a compromise indicator.** Heninger et al.
recovered DSA private keys for 1.03% of SSH hosts caused by embedded devices
generating keys before entropy was available. Repeated keys mean either a
cloned image or a derivable key.

**IPv6 subnets cannot be swept.** A /64 is 1.8 × 10¹⁹ addresses. RFC 7707
replaces brute force with multicast, address-pattern analysis, and external
sources. Aliased prefixes (Gasser et al.) make un-de-aliased results mostly noise.

**Banner versions are triage, not findings.** Distributions backport security
fixes without changing the upstream version string, so a banner match requires
host-side confirmation before it is reported.

**Read the infrastructure before probing it.** A switch's SNMP tables and a
DHCP lease list are authoritative host inventories; scanning is the
approximation. Prefer the source of truth when you can reach it.

**Passive before active on fragile targets.** ICS/OT controllers and medical
devices can be crashed by a routine SYN scan — a version probe alone can fault
a PLC. Observation cannot crash anything, and it finds hosts that only speak
and never answer. The ics-ot-discovery skill is built entirely on this rule.

**One record per host, accumulated.** The discovery stages each emit their own
format, so the pipeline used to chain by bespoke `awk`. A shared JSON Lines
host record makes the stages composable and lets an inventory grow across scans
— `first_seen`/`last_seen` answer "what changed" without a separate baseline.

**Targets are variables, never literals.** Every command in every skill reads
`$SUBNET`, `$TARGET`, `$IFACE` and friends, set once in each skill's **Set these
first** block from the scope the user confirmed. A human reading a hardcoded
`192.168.1.0/24` substitutes their own range without thinking; an agent copies it
verbatim, scans nothing, and reports an empty network as a clean result. An unset
variable fails loudly instead. Literals survive in three places only, all
deliberate: sample output, exclusion examples (`--exclude`, `--arpspa`), and
addresses that mean something specific — `0.0.0.0/0`, a public resolver.

**Detection, not exploitation.** Several skills stop deliberately short of the
attack: `ssh-auth-methods` and RDP/VNC brute forcing are kept per-host and
scoped; Responder is used only in listen-only `-A` mode. Enumerate and report;
do not poison or spray.

### References

- Bano, Richter, Javed, Sundaresan, Durumeric, Murdoch, Mortier &amp; Paxson,
  [*Scanning the Internet for Liveness*](https://dl.acm.org/doi/10.1145/3213232.3213234),
  ACM SIGCOMM CCR 48(2), 2018
- Izhikevich, Teixeira &amp; Durumeric,
  [*LZR: Identifying Unexpected Internet Services*](https://www.usenix.org/conference/usenixsecurity21/presentation/izhikevich),
  USENIX Security 2021
- Heninger, Durumeric, Wustrow &amp; Halderman,
  [*Mining Your Ps and Qs: Detection of Widespread Weak Keys in Network Devices*](https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/heninger),
  USENIX Security 2012 (Best Paper)
- Gasser, Scheitle, Foremski, Lone, Korczyński, Strowes, Hendriks &amp; Carle,
  [*Clusters in the Expanse: Understanding and Unbiasing IPv6 Hitlists*](https://arxiv.org/abs/1806.01633),
  ACM IMC 2018
- Bäumer, Brinkmann &amp; Schwenk,
  [*Terrapin Attack: Breaking SSH Channel Integrity by Sequence Number Manipulation*](https://terrapin-attack.com/),
  USENIX Security 2024
- Gont &amp; Chown, [RFC 7707: *Network Reconnaissance in IPv6 Networks*](https://www.rfc-editor.org/rfc/rfc7707.html), IETF, 2016
- Gont, [RFC 7872: *Observed Dropping of IPv6 Extension Headers*](https://www.rfc-editor.org/rfc/rfc7872.html), IETF, 2016
- Kührer, Hupperich, Rossow &amp; Holz, *Exit from Hell? Reducing the Impact of Amplification DDoS Attacks* (SSDP/UPnP amplification), USENIX Security 2014

## License

This repository is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

These skills are provided for demonstration and educational purposes. Always ensure you have proper authorization before performing network discovery on any network.

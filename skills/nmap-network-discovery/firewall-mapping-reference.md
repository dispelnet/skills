# Firewall Mapping and Large-Range Scanning

> **Scope gate — this file belongs to the `nmap-network-discovery` skill.**
> Every command here sends packets to live hosts, and the large-range section drives a stateless scanner that can saturate a link.
> **Do not run anything here until that skill's Scope Gate has been
> satisfied and the target confirmed.** If you loaded this file on its own,
> read `SKILL.md` first.

Supporting reference for the `nmap-network-discovery` skill. Load this when the deliverable is a firewall recommendation rather than a port list, when a `-p-` sweep needs to survive interruption, or when the range is larger than roughly a /20.

**Variables** (`$TARGET`, `$SUBNET`, `$IFACE`, …) are the ones set in the
**Set these first** block of `SKILL.md`, except where a script below defines
its own.

---

## Mapping the Firewall, Not Just the Ports

Every scan type above answers *"what is open."* A different set answers
*"what does the filtering actually do"* — which is usually the more useful
question when the deliverable is a firewall recommendation.

```bash
# ACK scan: does NOT find open ports. It distinguishes FILTERED from
# UNFILTERED, which maps the ruleset itself.
sudo nmap -sA $TARGET

# Compare against a SYN scan of the same ports to find the delta
sudo nmap -sS -p- $TARGET -oN syn.txt
sudo nmap -sA -p- $TARGET -oN ack.txt

# Window scan: an ACK variant that can infer open ports on some stacks
sudo nmap -sW $TARGET

# NULL / FIN / Xmas: distinguish closed from filtered on RFC-compliant
# stacks. Windows answers RST to everything, so these report all ports
# closed against it — a known false negative, not a finding.
sudo nmap -sN $TARGET
sudo nmap -sF $TARGET
sudo nmap -sX $TARGET

# Arbitrary flag combinations, when you are testing a specific rule
sudo nmap --scanflags SYNFIN $TARGET

# Always pair with --reason: it prints the evidence for each verdict
sudo nmap -sA --reason -p 22,80,443 $TARGET
```

| Result | Means |
|---|---|
| `unfiltered` (from `-sA`) | The packet reached the host — no firewall rule blocked it |
| `filtered` | Dropped, with no reply — a rule matched |
| `open\|filtered` | No reply, and this scan type cannot tell the difference |

A port that is `closed` but `unfiltered` tells you the firewall permits the
traffic and nothing is listening — a very different remediation from
`filtered`, and one a SYN scan alone cannot distinguish.

---

---

## Long Scans — Resuming and Tuning

A `-p-` sweep across a subnet runs for hours. Plan for it being interrupted.

```bash
# Always write output; without it there is nothing to resume from
sudo nmap -sS -p- $SUBNET -oA fullscan

# Dropped SSH session, laptop slept, scan killed — continue where it stopped
sudo nmap --resume fullscan.gnmap
```

`--resume` works from `-oN` or `-oG` output (not `-oX`), which is reason
enough to always use `-oA`.

```bash
# Scan more hosts in parallel on a large, reliable range
sudo nmap -sS --min-hostgroup 128 $SUBNET

# Cap retransmits — the single biggest time saver on filtered networks,
# where Nmap otherwise retries every dropped probe
sudo nmap -sS --max-retries 2 $SUBNET

# Abandon hosts that stall the whole sweep
sudo nmap -sS --host-timeout 15m $SUBNET
```

---

---

## Handing Off to a Faster Scanner

Nmap's accuracy comes from tracking connection state, and that is exactly what
makes it slow across large ranges. For anything above roughly a /20, the
standard practice is two stages: a **stateless** scanner finds open ports,
then Nmap does version and script work against only those.

This is the same sweep-then-depth pattern as the `-A` guidance above, one
level up.

```bash
# Stage 1 — masscan finds open ports fast (rate is a hard ceiling; on a
# shared or production link, start far lower than you think)
sudo masscan $SUBNET -p1-65535 --rate 1000 -oL masscan.txt

# Reduce to "ip:port" pairs, then to the two lists Nmap needs
awk '/^open/ {print $4":"$3}' masscan.txt > pairs.txt
cut -d: -f1 pairs.txt | sort -u > hosts.txt
cut -d: -f2 pairs.txt | sort -un | paste -sd, - > ports.txt

# Stage 2 — Nmap does the part it is uniquely good at, on a tiny target set
sudo nmap -sS -sV -Pn -iL hosts.txt -p "$(cat ports.txt)" -oA verified
```

`rustscan` and `naabu` fill the same stage-1 role; `rustscan` will invoke Nmap
for stage 2 itself.

**Verify stage 1 before trusting it.** Stateless scanners trade accuracy for
speed and drop results under loss. Spot-check by re-scanning a sample of hosts
with Nmap directly:

```bash
shuf -n 10 hosts.txt > sample.txt
sudo nmap -sS -p "$(cat ports.txt)" -iL sample.txt --reason
```

If Nmap finds open ports that stage 1 missed, lower the rate and re-run —
the fast scan was lossy.

---

---
name: discovery-inventory
description: >
  Use this skill when the user wants to combine, normalize, merge, or
  accumulate output from the network-discovery skills into one record per
  host, or to track hosts across repeated scans. Triggers include: "merge
  nmap and arp-scan output", "combine scan results", "unified host inventory",
  "normalize discovery output", "one record per host", "track hosts across
  scans", "what's new since last scan", "accumulate scan results", "convert
  nmap XML to JSON", "build a host inventory", "dedupe scan output", or any
  request to turn the ad-hoc text from arp-scan/nmap/ssh-audit/etc into a
  single structured inventory that persists and grows across runs. Also use
  when chaining two discovery stages would otherwise need bespoke awk or grep.
---

# Discovery Inventory

## Before You Run Anything

This skill only reads and merges files that earlier stages produced — it sends
no packets. Two things still apply:

1. **Confirm which files are in scope** before merging, and write the
   inventory where the user asked. An accumulated inventory is a durable
   record of someone's network; do not create one outside the working
   directory the user named.
2. **Do not use the inventory to widen scope.** `netinv` makes it trivial to
   feed every discovered host into the next scan. Hosts appearing in the
   inventory are not thereby authorised targets — re-confirm before probing.

Full legal statement: [Ethical and Legal Notice](#ethical-and-legal-notice).

### Set these first

Every command below uses these. Fill them in from the scope you just
confirmed, and substitute nothing by hand afterwards. An unset variable
makes the command fail loudly — that is the point; a hardcoded address
fails silently against the wrong network.

```bash
SUBNET="192.168.1.0/24" # the confirmed range
```

---

The discovery skills each emit their own format, and chaining them means a
bespoke `awk` or `grep` at every handoff. This skill replaces that glue with a
**shared host record** — one JSON object per host — so the stages compose and
the results **accumulate across runs** instead of being thrown away each time.

```
arp-scan ─┐
nmap ─────┼─▶  netinv from-*  ─▶  *.jsonl  ─▶  netinv merge  ─▶  inventory.jsonl
ssh-audit ┘                                         ▲                  │
                                                    └── last week's ───┘
                                                        inventory
```

**What this buys you:**
- **Composability** — every stage speaks one format; no per-pair conversion.
- **Deduplication** — the same host found by ARP and by Nmap becomes one
  record, not two lines to reconcile by eye.
- **Accumulation** — merge is idempotent, so a scheduled scan folds into a
  growing inventory safely, and `first_seen`/`last_seen` answer "what changed."

The format is JSON Lines. Full field reference and merge rules are in
`host-record-schema.md`.

---

## The Tool

`netinv` (in `scripts/`) is stdlib Python — no `pip install`, no `jq` required.

```bash
# Make it callable
chmod +x scripts/netinv.py
alias netinv='python3 /path/to/skills/discovery-inventory/scripts/netinv.py'

netinv from-arp   [FILE|-]    # arp-scan --plain --format='${ip},${mac},${vendor}'
netinv from-nmap  SCAN.xml    # nmap -oX output
netinv merge      A.jsonl ... # union records by IP (accumulate)
netinv table      [FILE|-]    # human-readable summary
```

It parses nmap XML with entity/DTD-subset declarations **refused**, so a
malicious or corrupt scan file cannot trigger an XXE or billion-laughs attack
through the inventory step.

---

## Step 1 — Convert Each Tool's Output

### From arp-scan (layer 2)

Use the parseable format the arp-network-discovery skill documents:

```bash
sudo arp-scan --localnet --plain --format='${ip},${mac},${vendor}' \
  | netinv from-arp - > arp.jsonl
```

Records carry `mac`, `mac_vendor`, and `mac_type` (the skill's
locally-administered-bit classification — `local` = randomized, `global` =
real OUI).

### From nmap (ports, services, OS)

Always scan with `-oX`; the XML carries everything the text output drops:

```bash
sudo nmap -sV -O --open $SUBNET -oX nmap.xml
netinv from-nmap nmap.xml > nmap.jsonl
```

Only **open** ports enter the inventory. If Nmap ran with `-O`, the best OS
match and its accuracy come across too.

---

## Step 2 — Merge Into One Inventory

```bash
# Combine this run's layers into a single deduplicated record set
netinv merge arp.jsonl nmap.jsonl > inventory.jsonl

# See it
netinv table inventory.jsonl
```
```
IP            HOSTNAME      VENDOR      OPEN PORTS
-------------------------------------------------
192.168.1.1                 Cisco       22,80,443
192.168.1.50  fileserver01  Dell Inc.   22,445
192.168.1.137               (Unknown)

3 hosts · sources: ['arp-scan', 'nmap']
```

A host with `sources: ['arp-scan']` and no ports was seen at layer 2 but never
port-scanned — the merged view makes that gap obvious.

---

## Step 3 — Accumulate Across Runs

Because merge is idempotent, fold each new scan into the standing inventory:

```bash
# Today's scan
sudo arp-scan --localnet --plain --format='${ip},${mac},${vendor}' | netinv from-arp - > today-arp.jsonl
sudo nmap -sV --open $SUBNET -oX today.xml && netinv from-nmap today.xml > today-nmap.jsonl

# Fold into the running inventory — first_seen is preserved, last_seen advances
netinv merge inventory.jsonl today-arp.jsonl today-nmap.jsonl > inventory.new.jsonl
mv inventory.new.jsonl inventory.jsonl
```

### What is new since last time

```bash
# Hosts whose first_seen is today = never seen before
jq -r --arg d "$(date -u +%Y-%m-%d)" 'select(.first_seen | startswith($d)) | .ip' \
  inventory.jsonl

# Or without jq: pull IPs and diff against yesterday's list
netinv table inventory.jsonl | awk 'NR>2 && NF{print $1}' | sort > today-ips.txt
comm -13 yesterday-ips.txt today-ips.txt      # new IPs
```

---

## Step 4 — Drive the Next Stage From the Inventory

The inventory tells you what to enumerate next, so later stages target only
what matters.

```bash
# Feed SSH hosts to the remote-access-discovery skill's ssh-audit
jq -r 'select(.ports[]?.port == 22) | .ip' inventory.jsonl > ssh-hosts.txt
ssh-audit -T ssh-hosts.txt

# Feed RDP/VNC hosts to the rdp-vnc-discovery skill
jq -r 'select(.ports[]? | .port==3389 or .port==5900) | .ip' inventory.jsonl > desktop-hosts.txt

# Hosts seen at L2 but never scanned — the arp→nmap gap, closed
jq -r 'select(.sources == ["arp-scan"]) | .ip' inventory.jsonl > unscanned.txt
sudo nmap -sV --open -iL unscanned.txt -oX fill-gaps.xml
netinv merge inventory.jsonl <(netinv from-nmap fill-gaps.xml) > inventory.jsonl
```

Without `jq`, the same selections are one `awk` over `netinv table`, but `jq`
on JSONL is the clean path.

---

## Adding Your Own Source

Any tool that produces host data can join the pipeline: emit JSONL matching
`host-record-schema.md` and `netinv merge` folds it in. Attach tool-specific
detail under a namespaced key (`"ssh": {...}`, `"tls": {...}`) — merge's
first-non-null rule keeps it intact, and `netinv table` and every `jq` query
ignore keys they do not know.

```bash
# Minimal custom source: a one-line record per host, merged like any other
printf '{"ip":"192.168.1.9","state":"up","sources":["snmp"],\
"hostnames":["core-sw1"],"ports":[{"port":161,"proto":"udp","state":"open",\
"service":"snmp"}]}\n' | netinv merge inventory.jsonl - > inventory.jsonl
```

---

## Quick Reference

```bash
# Convert
sudo arp-scan --localnet --plain --format='${ip},${mac},${vendor}' | netinv from-arp -
netinv from-nmap scan.xml

# Merge + view
netinv merge *.jsonl > inventory.jsonl
netinv table inventory.jsonl

# Drive next stage
jq -r 'select(.ports[]?.port==22)|.ip' inventory.jsonl > ssh-hosts.txt
```

---

## Common Mistakes

| Symptom | Usually means | Do this |
|---|---|---|
| Merge produced two records for one host | The merge key is IP — the host changed address, or has two | Reconcile on MAC where you have it |
| A host vanished after merge | Its source parser emitted no record | Check the source file before assuming the host went away |
| `first_seen` equal to `last_seen` everywhere | Only one run has been merged | Accumulation needs at least two runs to answer *what changed* |
| Inventory smaller than the raw scan output | Deduplication working as intended | Count unique hosts, not lines |

**The inference ceiling.** The inventory proves **what the sources reported**, and inherits every blind spot they had — an ARP-only run cannot see IPv6-only hosts, and a merged record is exactly as trustworthy as its weakest source. Hosts listed here are not thereby authorised targets.

---

## When to Use Something Else

| Scenario | Better tool |
|---|---|
| Actually finding the hosts | arp / ipv6 / nmap / passive discovery skills |
| Large multi-site asset management | NetBox, Netdisco, a real CMDB |
| Ad-hoc one-off query, tools already run | `grep`/`awk` on the raw output is fine |
| Rich reporting / dashboards | Import the JSONL into your SIEM or a notebook |

---

## Ethical and Legal Notice

This skill only reformats data the discovery skills already collected — it
sends no packets. But an accumulated inventory is a concentrated map of a
network, including hostnames, software versions, and open services. Treat
`inventory.jsonl` as sensitive: it is exactly the reconnaissance an attacker
would want. Store and share it accordingly, and only build it for networks you
own or are authorised to assess.

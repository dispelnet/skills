# Nmap Inventory Workflow and Change Detection

> **Scope gate — this file belongs to the `nmap-network-discovery` skill.**
> These commands scan, and then *schedule* scanning: a cron entry re-runs with nobody confirming scope.
> **Do not run anything here until that skill's Scope Gate has been
> satisfied and the target confirmed.** If you loaded this file on its own,
> read `SKILL.md` first.

Supporting reference for the `nmap-network-discovery` skill. Load this when building a repeatable inventory, scheduling scans, or answering "what changed since the last scan."

**Variables** (`$TARGET`, `$SUBNET`, `$IFACE`, …) are the ones set in the
**Set these first** block of `SKILL.md`, except where a script below defines
its own.

---

## Network Inventory Workflow

### Step 1: Discover live hosts
```bash
sudo nmap -sn $SUBNET -oG - | awk '/Up$/{print $2}' > live-hosts.txt
cat live-hosts.txt
```

### Step 2: Full scan of live hosts
```bash
sudo nmap -iL live-hosts.txt -A -T4 -oA full-inventory
```

> **Accumulating across scans?** Convert the XML into the shared host record
> (`netinv from-nmap full-inventory.xml`) and merge it into a persistent
> `inventory.jsonl` rather than a dated file — see the **discovery-inventory**
> skill. That inventory also feeds later stages: SSH hosts to `ssh-audit`,
> RDP/VNC hosts to the rdp-vnc-discovery skill, without re-parsing anything.

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

---

## Using ndiff to Spot Changes

`ndiff` compares two Nmap XML scans and highlights new/removed hosts and
ports — ideal for detecting unauthorized changes.

```bash
# Compare two scans — prints ONLY what changed
ndiff scan-baseline.xml scan-today.xml

# -v is the opposite of "differences only": it ALSO prints every
# host and port that did NOT change. Use it for a full side-by-side.
ndiff -v scan-baseline.xml scan-today.xml

# Machine-readable diff, for feeding an alerting pipeline
ndiff --xml scan-baseline.xml scan-today.xml > diff.xml
```

`ndiff` exits **0** when the scans are identical and **1** when they differ,
so it works directly as a change gate:

```bash
ndiff baseline.xml today.xml || echo "network changed since baseline"
```

---

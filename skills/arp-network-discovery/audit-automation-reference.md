# Baseline Diffing and Scheduled ARP Audits

> **Scope gate — this file belongs to the `arp-network-discovery` skill.**
> A scheduled scan re-runs unattended. Pin the confirmed range into the script, and tell the user it keeps running until they remove it.
> **Do not run anything here until that skill's Scope Gate has been
> satisfied and the target confirmed.** If you loaded this file on its own,
> read `SKILL.md` first.

Supporting reference for the `arp-network-discovery` skill. Load this when the user wants new-device detection or a recurring scan. Read `mac-and-oui-reference.md` first — naive baseline diffing on Wi-Fi produces false 'new device' alerts on every run.

**Variables** (`$TARGET`, `$SUBNET`, `$IFACE`, …) are the ones set in the
**Set these first** block of `SKILL.md`, except where a script below defines
its own.

---

## Baseline Comparison (New Device Detection)

```bash
# Save a known-good snapshot
sudo arp-scan $SUBNET | sort > /tmp/baseline-hosts.txt

# Later: compare against current state
sudo arp-scan $SUBNET | sort > /tmp/current-hosts.txt
diff /tmp/baseline-hosts.txt /tmp/current-hosts.txt

# Lines starting with > are new devices; lines starting with < have left
```

---

---

## Periodic Audit Script

Schedule with `cron` to receive alerts when unknown devices appear.

```bash
#!/bin/bash
# /usr/local/bin/network-audit.sh
# Run as root. Example cron: */15 * * * * /usr/local/bin/network-audit.sh

IFACE="eth0"
SUBNET="192.168.1.0/24"
KNOWN="/var/lib/network-audit/known-hosts.txt"
CURRENT="/tmp/current-scan-$$.txt"

# --plain suppresses header/footer, so no fragile line filtering is needed.
# Randomized (locally administered) MACs are excluded: transient phones
# rotate addresses and would otherwise alert on every single run.
sudo arp-scan -I "$IFACE" --plain "$SUBNET" 2>/dev/null \
  | awk '$2 !~ /^[0-9a-fA-F][26aeAE]:/ {print $1, $2}' \
  | sort > "$CURRENT"

if [ -f "$KNOWN" ]; then
    NEW=$(comm -23 "$CURRENT" "$KNOWN")
    GONE=$(comm -13 "$CURRENT" "$KNOWN")
    if [ -n "$NEW" ]; then
        echo "NEW DEVICES DETECTED on $(date):"
        echo "$NEW"
        # Optionally: | mail -s "Network Alert" admin@example.com
    fi
    if [ -n "$GONE" ]; then
        echo "DEVICES NO LONGER PRESENT on $(date):"
        echo "$GONE"
    fi
fi

cp "$CURRENT" "$KNOWN"
rm -f "$CURRENT"
```

---

# Scheduled SSH/Telnet Audit Reference

> **Scope gate — this file belongs to the `remote-access-discovery` skill.**
> A scheduled audit re-runs unattended, hourly, against every host in the list — which is how an earlier revision of this skill ended up logging a failed root login on every host in the range.
> **Do not run anything here until that skill's Hard Rules have been
> satisfied and the target confirmed.** If you loaded this file on its own,
> read `SKILL.md` first.

Supporting reference for the `remote-access-discovery` skill. Load this only when the user wants a recurring, unattended audit; pin the confirmed target list into the script itself.

**Variables** (`$TARGET`, `$SUBNET`, `$IFACE`, …) are the ones set in the
**Set these first** block of `SKILL.md`, except where a script below defines
its own.

---

## Step 8 — Periodic Audit Script

```bash
#!/bin/bash
# /usr/local/bin/remote-access-audit.sh
# Run weekly to track remote access exposure changes

SUBNET="192.168.1.0/24"
DATE=$(date +"%Y%m%d")
OUTDIR="/var/lib/remote-access-audit"
mkdir -p "$OUTDIR"

echo "[*] Scanning for SSH and Telnet on $SUBNET..."

# Safe scripts only — this runs unattended on a schedule, so it must never
# generate authentication attempts.
sudo nmap -p 22,23 --open -sV \
  --script "ssh-hostkey,ssh2-enum-algos,sshv1,telnet-ntlm-info,banner" \
  "$SUBNET" \
  -oN "$OUTDIR/scan-$DATE.txt" \
  -oX "$OUTDIR/scan-$DATE.xml"

# Crypto + CVE audit with pass/fail against the approved baseline
grep -E "^Host:.*22/open" "$OUTDIR/scan-$DATE.gnmap" 2>/dev/null \
  | awk '{print $2}' > "$OUTDIR/ssh-hosts.txt"
if [ -s "$OUTDIR/ssh-hosts.txt" ] && command -v ssh-audit >/dev/null; then
    ssh-audit -T "$OUTDIR/ssh-hosts.txt" -j > "$OUTDIR/ssh-audit-$DATE.json"
    ssh-audit -P "$OUTDIR/baseline.policy" -T "$OUTDIR/ssh-hosts.txt" \
      > "$OUTDIR/policy-$DATE.txt" 2>&1 || echo "[!] Baseline drift detected"
fi

# Flag critical issues
echo ""
echo "=== CRITICAL FINDINGS ==="
grep -i "sshv1\|3des\|group1-sha1\|arcfour\|hmac-md5\|23/open\|telnet" \
  "$OUTDIR/scan-$DATE.txt" | sort -u

# Diff against last scan
PREV=$(ls "$OUTDIR"/scan-*.txt 2>/dev/null | sort | tail -2 | head -1)
if [ -n "$PREV" ] && [ "$PREV" != "$OUTDIR/scan-$DATE.txt" ]; then
    echo ""
    echo "=== CHANGES SINCE LAST SCAN ==="
    diff "$PREV" "$OUTDIR/scan-$DATE.txt" | grep "^[<>]"
fi
```

---

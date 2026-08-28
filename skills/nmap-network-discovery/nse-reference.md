# Nmap Scripting Engine (NSE) Reference

> **Scope gate — this file belongs to the `nmap-network-discovery` skill.**
> Scripts in the `external` category send your detected services to a third party — check a script's category before running it.
> **Do not run anything here until that skill's Scope Gate has been
> satisfied and the target confirmed.** If you loaded this file on its own,
> read `SKILL.md` first.

Supporting reference for the `nmap-network-discovery` skill. Load this before running any `--script`, and always before running one whose category you have not checked.

**Variables** (`$TARGET`, `$SUBNET`, `$IFACE`, …) are the ones set in the
**Set these first** block of `SKILL.md`, except where a script below defines
its own.

---

## Nmap Scripting Engine (NSE)

NSE scripts extend Nmap with specialised probes. Scripts live at
`/usr/share/nmap/scripts/`.

```bash
# List all available scripts
ls /usr/share/nmap/scripts/

# Confirm a script is actually present before relying on it in a workflow
nmap --script-help "$SCRIPT" >/dev/null 2>&1 || echo "not installed"

# Run a script against a target
nmap --script "$SCRIPT" $TARGET

# Pass arguments to a script
nmap --script "$SCRIPT" --script-args "$ARG=$VALUE" $TARGET
```

### Useful NSE recipes

```bash
# Gather Windows OS info via SMB.
# WARNING: smb-os-discovery speaks SMBv1 ONLY (nmap issues #901, #2549).
# SMBv1 is off by default on Windows 10 1709+ and Server 2019+, so this
# returns nothing on most modern hosts. Use the SMB2 scripts instead:
nmap --script smb-os-discovery $SUBNET          # legacy hosts only
nmap --script smb-protocols,smb2-security-mode -p445 $SUBNET
nmap --script smb2-capabilities,smb2-time -p445 $TARGET

# Detect WAF on a web server
nmap -p443 --script http-waf-detect \
  --script-args="http-waf-detect.aggro,http-waf-detect.detectBodyChanges" \
  target.example.com

# Check for known CVEs against detected services.
# vulners IS bundled with Nmap (NSE categories: external, safe, vuln) — but
# "external" means it sends each detected CPE to the vulners.com API. Your
# service inventory leaves the network. Confirm that is acceptable in scope.
nmap -Pn -sV --script=vulners $TARGET
nmap -Pn -sV --script=vulners --script-args mincvss=7.0 $TARGET

# Fully offline alternative — NOT bundled, install it (see below).
# Matches against local CSV databases, contacts nothing.
nmap -Pn -sV --script=vulscan --script-args vulscandb=cve.csv $TARGET

# Enumerate HTTP methods
nmap --script http-methods -p80,443 $TARGET

# Check for default credentials
nmap --script http-default-accounts $TARGET

# Banner grabbing on all open ports
nmap --script banner $TARGET
```

### The `external` category — scripts that phone home

Some bundled scripts send data to a third party by design. `vulners` posts
your detected CPEs to vulners.com; `whois-ip` queries regional registries;
`shodan-api` and `http-google-malware` contact their own services. All are
tagged `external`.

On an engagement this leaks both your target inventory *and* the fact that you
are scanning. Check before running, and exclude the category when in doubt:

```bash
# What category is this script in?
grep '"vulners"' /usr/share/nmap/scripts/script.db
# Entry { filename = "vulners.nse", categories = { "external", "safe", "vuln", } }

# List everything that would contact a third party
grep '"external"' /usr/share/nmap/scripts/script.db | wc -l

# Run vuln scripts but exclude anything that phones home
nmap -sV --script "vuln and not external" $TARGET
```

### Installing third-party NSE scripts

`vulscan` and some others are not bundled. Verify before relying on one in a
workflow:

```bash
# Does this Nmap have it?
nmap --script-help vulscan >/dev/null 2>&1 || echo "not installed"

sudo git clone https://github.com/scipag/vulscan \
  /usr/share/nmap/scripts/vulscan

# Required after adding any script — rebuilds the script database
sudo nmap --script-updatedb
```

---

---

## Packet Tracing and Debug

```bash
# Trace packets for a single host
sudo nmap -vv -n -sn -PE -T4 --packet-trace $TARGET

# -vv         increase verbosity
# -n          skip DNS resolution (faster)
# -PE         use ICMP echo
# --packet-trace  print sent/received packets
```

---

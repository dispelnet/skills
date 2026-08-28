---
name: dns-recon
description: >
  Use this skill when the user wants to enumerate or audit DNS — records, zone
  transfers, subdomains, name-server configuration, and mail-security posture.
  Triggers include: "DNS enumeration", "DNS recon", "zone transfer", "AXFR",
  "find subdomains", "enumerate DNS records", "SRV records", "check DNSSEC",
  "NSEC walking", "reverse DNS sweep", "dig", "dnsrecon", "is my DNS
  misconfigured", "SPF/DMARC check", "find the mail servers", "DNS cache
  snooping", or any request to map a domain's DNS, discover hosts from DNS, or
  audit name-server security. Also use when a discovery stage needs a host
  list for a domain, including IPv6 addresses, before any scanning starts.
---

# DNS Reconnaissance

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
SUBNET="192.168.1.0/24" # the confirmed range
NS="192.0.2.53"         # a name server in scope
DOMAIN="example.com"    # the confirmed domain
```

---

DNS is the highest-yield reconnaissance surface on a network: a single
misconfigured server can hand you the entire host inventory, and even a
locked-down one leaks mail servers, service locations, and infrastructure
providers. It is also the source other discovery stages depend on — the
ipv6-network-discovery skill relies on `AAAA` records because a /64 cannot be
swept, and tls-certificate-discovery resolves the names it finds in
Certificate Transparency logs back through DNS.

**Two modes, and the order matters:**
1. **Passive** — query public records and third-party archives. Sends nothing
   to the target's own infrastructure. Do this first.
2. **Active** — query the target's authoritative servers directly (AXFR,
   brute force). More complete, but it touches the target.

**Operational-security note carried over from nmap-network-discovery:** every
query you make is seen by *some* resolver. Using `@8.8.8.8` hands your entire
lookup pattern to Google; on an engagement, prefer the client's resolver or one
you control, and use `+trace`/authoritative queries when you need ground truth.

---

## Step 1 — Enumerate the Records (all verified with live `dig`)

```bash
# The core record types, one query each
for t in A AAAA MX NS TXT SOA CNAME; do
  echo "== $t =="; dig +short "$t" $DOMAIN
done

# ANY is mostly refused now (RFC 8482) — do not rely on it
dig +short ANY $DOMAIN

# Authoritative answer straight from the zone's own nameserver (ground truth)
dig +short A $DOMAIN @"$(dig +short NS $DOMAIN | head -1)"

# Trace the full delegation path from the root
dig +trace $DOMAIN
```

| Record | Reveals |
|---|---|
| `A` / `AAAA` | Host IPv4 / IPv6 — the AAAA feed for the IPv6 skill |
| `NS` | Authoritative name servers — your AXFR targets |
| `MX` | Mail servers — often on separate infrastructure |
| `TXT` | SPF/DKIM/DMARC, domain-verification tokens, provider fingerprints |
| `SOA` | Primary NS, admin email, zone serial |
| `SRV` | Service locations — LDAP, Kerberos, SIP, domain controllers |
| `CNAME` | Third-party services (SaaS, CDN) — subdomain-takeover surface |

---

## Step 2 — Zone Transfer (AXFR): the Jackpot Misconfiguration

A misconfigured authoritative server will hand you the **entire zone** — every
record, in one query. It should be restricted to secondaries; when it is not,
it is a serious finding and the fastest subdomain enumeration there is.

```bash
# Try AXFR against every authoritative name server
domain=example.com
for ns in $(dig +short NS "$domain"); do
  echo "== AXFR $domain @ $ns =="
  dig +short AXFR "$domain" @"$ns"
done
```

- **Success** (records stream back) → **finding**: the zone is world-transferable.
  You now have the complete host inventory.
- **`; Transfer failed.`** or empty → correctly restricted (the normal case).

> Verified against `zonetransfer.me` (a deliberately-open test zone from
> digi.ninja) — it returns the full zone; a hardened domain returns
> "Transfer failed." Test your recipe against `zonetransfer.me` if unsure it
> works.

---

## Step 3 — Subdomain Enumeration

### Passive first — no packets to the target

```bash
# Certificate Transparency: every name that ever appeared in a cert.
# Same source the TLS skill uses — completely passive.
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" \
  | python3 -c 'import sys,json;[print(n) for c in json.load(sys.stdin) for n in c["name_value"].split("\n")]' \
  | sort -u

# Aggregate many passive sources at once (CT, passive DNS, search engines)
subfinder -d $DOMAIN -silent      # if installed
amass enum -passive -d $DOMAIN    # if installed
```

### Active brute force — but detect wildcards first

**Wildcard DNS makes brute force meaningless**: if `*.example.com` resolves,
*every* guess "succeeds." Always test before brute forcing:

```bash
# If a random label resolves, the zone has a wildcard
r="zzq9x7-nonexistent-$(date +%s).$DOMAIN"
if dig +short A "$r" | grep -q .; then
  echo "WILDCARD present — brute-force results need the wildcard IP filtered out"
else
  echo "no wildcard (NXDOMAIN) — brute force is meaningful"
fi
```

```bash
# Nmap's built-in brute force (bundled, no extra tooling)
nmap --script dns-brute --script-args dns-brute.domain=$DOMAIN

# Fast dedicated resolvers, wildcard-aware
dnsx -d $DOMAIN -w wordlist.txt -wd $DOMAIN    # -wd filters wildcards
massdns -r resolvers.txt -t A -o S subdomains.txt
```

---

## Step 4 — DNSSEC Zone Walking

DNSSEC signs "this name does not exist" proofs, and the older **NSEC** scheme
does so by naming the *next* record in the zone — so following the chain walks
out the entire zone, no guessing. This is an accidental disclosure, not an
attack on the crypto.

```bash
# Is the zone signed, and with NSEC or NSEC3?
dig +dnssec +short SOA $DOMAIN
dig +dnssec $DOMAIN NSEC +noall +answer

# Full walk (dnsrecon is the standard tool)
dnsrecon -d $DOMAIN -z          # -z performs the DNSSEC/NSEC walk
```

| Scheme | Walkable? |
|---|---|
| **NSEC** | **Yes** — names are in plaintext; the chain lists every record |
| **NSEC3** | Hashed, so not directly; weak/low-iteration configs can still be cracked offline (`nsec3walker`, hashcat) |

Finding: a zone using **NSEC** (rather than NSEC3) exposes its full contents to
anyone. Recommend NSEC3 with a high iteration count, or white-lies (RFC 4470).

---

## Step 5 — Name-Server Security Checks

```bash
# Open recursion — the server resolves for anyone (DDoS-amplification abuse)
nmap -sU -p53 --script dns-recursion $NS

# Cache snooping — infer which sites the server's users visit (non-recursive query)
nmap -sU -p53 --script dns-cache-snoop \
  --script-args "dns-cache-snoop.mode=nonrecursive,dns-cache-snoop.domains={$DOMAIN}" $NS

# Zone-config sanity (missing NS, SOA problems)
nmap --script dns-check-zone --script-args dns-check-zone.domain=$DOMAIN
```

| Finding | Why it matters |
|---|---|
| Open recursion to the internet | Abused for DNS-amplification DDoS |
| Cache snooping allowed | Leaks the user population's browsing |
| Zone transfer to the world (Step 2) | Full inventory disclosure |
| Missing SPF / `p=none` DMARC | Domain is spoofable — see below |

---

## Step 6 — Mail Security Posture (from TXT)

DNS carries the domain's whole email-authentication story. All read-only:

```bash
dig +short TXT $DOMAIN | grep -i spf          # SPF: is the sender list strict?
dig +short TXT _dmarc.$DOMAIN                  # DMARC: p=reject / quarantine / none
dig +short TXT selector._domainkey.$DOMAIN     # DKIM (selector varies)
```

**Flag:** no SPF, `+all`/`?all` SPF, or DMARC `p=none` (or absent) — the domain
can be spoofed in phishing. Verified live: `google.com` publishes
`v=DMARC1; p=reject` (good); a domain with no `_dmarc` record is a finding.

---

## Step 7 — Reverse DNS Sweeps

PTR records map IPs back to names and often reveal naming conventions and
forgotten hosts across a netblock.

```bash
# Single reverse lookup
dig +short -x 1.1.1.1

# Sweep a /24 (nmap's list scan does PTR without touching the hosts).
# Anchor on "scan report for" so the banner line is not matched.
nmap -sL $SUBNET | sed -n 's/.*scan report for \(.*\) (\(.*\))/\2 \1/p'

# IPv6 reverse zone is huge; walk ip6.arpa via NSE instead of sweeping
nmap --script dns-ip6-arpa-scan --script-args 'dns-ip6-arpa-scan.prefix=2001:db8::/48'
```

> `nmap -sL` sends nothing to the hosts, but it *does* query your resolver for
> every PTR — the same disclosure caveat as Step 0.

---

## Feed the Pipeline

DNS recon produces names and IPs; resolve them and hand the live ones to the
active-scan and inventory stages.

```bash
# Resolved discovered names -> one host per line, ready for nmap / discovery-inventory
sort -u all-subdomains.txt | while read -r h; do
  ip=$(dig +short A "$h" | tail -1); [ -n "$ip" ] && echo "$ip $h"
done | sort -u > resolved-hosts.txt
```

---

## Quick Reference

```bash
# All records
for t in A AAAA MX NS TXT SOA; do dig +short "$t" $DOMAIN; done

# Zone transfer (against each NS)
for ns in $(dig +short NS $DOMAIN); do dig +short AXFR $DOMAIN @"$ns"; done

# Passive subdomains (CT logs)
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | sort -u

# Wildcard test, then brute force
dig +short A random$(date +%s).$DOMAIN | grep -q . && echo WILDCARD
nmap --script dns-brute --script-args dns-brute.domain=$DOMAIN

# Mail spoofability
dig +short TXT _dmarc.$DOMAIN
```

---

## Common Mistakes

| Symptom | Usually means | Do this |
|---|---|---|
| AXFR refused | Normal and correct configuration | Not a finding. The finding is when a transfer *succeeds* |
| Every subdomain resolves | A DNS wildcard | Probe a random label first; without that, brute-force output is entirely noise |
| No SPF or DMARC record | The policy may live on the organisational parent domain | Check the parent before reporting it missing |
| Different answers from different resolvers | Split-horizon DNS, or a stale cache | Query the authoritative NS directly before concluding |

**The inference ceiling.** DNS proves **what a zone operator published**. A record does not prove the host exists, is live, or is in scope — and a resolved address still has to be authorised before you probe it.

---

## When to Use Something Else

| Scenario | Better tool |
|---|---|
| Names from certificates | tls-certificate-discovery skill (CT logs) |
| Scanning the resolved hosts | nmap-network-discovery skill |
| IPv6 address discovery | ipv6-network-discovery skill (DNS is one of its sources) |
| Deep passive-DNS history | SecurityTrails, DNSDB, VirusTotal |
| Massive subdomain brute force | `massdns`, `puredns`, `dnsx` |

---

## Ethical and Legal Notice

Passive DNS queries (CT logs, public records, third-party archives) are
low-impact and generally safe. **Active queries against a target's own
authoritative servers — AXFR attempts, brute forcing, cache snooping — are
active reconnaissance** and must fall within authorised scope. A successful
zone transfer or an NSEC walk is a finding to *report*, not a licence to attack
the hosts it reveals; discovered subdomains still have to be in scope before
you scan them. Only enumerate domains you own or are authorised to assess.

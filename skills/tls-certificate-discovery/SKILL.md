---
name: tls-certificate-discovery
description: >
  Use this skill when the user wants to find, enumerate, or audit TLS/SSL
  services and certificates across a network — cipher and protocol posture,
  certificate expiry and validity, and asset discovery from certificates.
  Triggers include: "scan for TLS", "check SSL ciphers", "audit HTTPS", "find
  expired certificates", "certificate inventory", "testssl", "ssl-enum-ciphers",
  "is TLS 1.0 enabled", "check for Heartbleed", "weak ciphers", "cert expiry
  monitoring", "SAN enumeration", "certificate transparency", "crt.sh", "find
  subdomains from certificates", or any request to probe TLS configuration,
  grade a server's SSL, inventory certificates, or discover hosts and names
  from certificate data. Also use when a service inventory shows TLS on ports
  other than 443, or when hosts must be discovered without probing them.
---

# TLS & Certificate Discovery

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

TLS is not just port 443. Izhikevich et al. (*LZR*, USENIX Security 2021)
measured that **only ~6% of TLS services run on 443**, and that off-port
services are *more* likely to be misconfigured — so a 443-only audit
systematically misses the weakest hosts.

Certificates are unusual in being **both** an audit target and a **discovery
source**: every certificate lists the names it is valid for (its SANs), and
every public certificate is logged forever in Certificate Transparency. You can
inventory an organisation's hosts from its certificates without sending it a
single packet.

**Supporting reference:** `tls-crypto-reference.md` holds the protocol/cipher
grading, the vulnerability matrix, and the certificate-finding checklist.

---

## Install

The `ssl-*` NSE scripts ship with Nmap. Add the depth tools:

```bash
sudo apt install nmap openssl sslscan -y          # Debian/Ubuntu/Kali
# testssl.sh — the most thorough single-host auditor (bash, no deps):
git clone --depth 1 https://github.com/testssl/testssl.sh
# For CT-log discovery (Step 5):
sudo apt install python3-pip -y && pipx install subfinder 2>/dev/null || true
```

---

## Step 1 — Find TLS Everywhere, Not Just 443

```bash
# Broad TLS sweep: version detection flags TLS on ANY port
sudo nmap -sV --open -p- $SUBNET | grep -iE "ssl|tls|https"

# Common TLS-wrapped services in one pass
sudo nmap -sV --open \
  -p 443,8443,993,995,465,587,636,989,990,992,5061,3389,5986 \
  $SUBNET

# ssl-enum-ciphers reports on whatever port actually speaks TLS
sudo nmap --script ssl-enum-ciphers -p 443,8443,993,995,636 $SUBNET
```

| Port | TLS service | Port | TLS service |
|---|---|---|---|
| 443 | HTTPS | 636 | LDAPS |
| 8443 | HTTPS-alt / admin | 989/990 | FTPS |
| 993 | IMAPS | 5061 | SIP-TLS |
| 995 | POP3S | 5986 | WinRM HTTPS |
| 465/587 | SMTPS / submission | 3389 | RDP (TLS layer) |

> `-sV` labels the service, not the port. Trust "ssl/http" from a version probe
> over the port number — see the LZR finding above.

---

## Step 2 — Grade the Configuration

### Nmap ssl-enum-ciphers — sweeps many hosts, letter grade per host

```bash
nmap --script ssl-enum-ciphers -p 443 $TARGET
```
```
| ssl-enum-ciphers:
|   TLSv1.0:                      ← finding: deprecated (RFC 8996)
|     ciphers:
|       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048)  - A   ← no forward secrecy
|   TLSv1.2:
|     ciphers:
|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C     ← Sweet32
|_  least strength: C
```

The per-cipher grade and `least strength` line tell you the worst thing on
offer. Map each flag against `tls-crypto-reference.md`.

### testssl.sh — the thorough single-host audit

```bash
./testssl.sh $TARGET:443
./testssl.sh --severity HIGH $TARGET       # only HIGH+ findings
./testssl.sh --vulnerable $TARGET          # just the vuln checks
./testssl.sh --jsonfile out.json $TARGET   # machine-readable
```

It runs the entire vulnerability matrix (Heartbleed, ROBOT, DROWN, POODLE,
Sweet32, Logjam…) plus protocol, cipher, and certificate checks in one pass,
with severity ratings. It is the tool to reach for on a host that matters.

### Targeted Nmap vuln checks (per row of the matrix)

```bash
nmap -p 443 --script ssl-heartbleed $TARGET
nmap -p 443 --script ssl-ccs-injection $TARGET
nmap -p 443 --script ssl-poodle $TARGET
nmap -p 443 --script sslv2-drown $TARGET
nmap -p 443 --script ssl-dh-params $TARGET      # Logjam / weak DH
nmap -p 443 --script ssl-known-key $TARGET      # Debian weak keys
```

---

## Step 3 — Inspect the Certificate

### With Nmap (subnet-wide)

```bash
nmap --script ssl-cert -p 443 $SUBNET
```

### With openssl (single host, full control — all recipes below are verified)

```bash
# Pull the served certificate
echo | openssl s_client -connect $TARGET:443 -servername www.example.com 2>/dev/null \
  | openssl x509 -out cert.pem

# The audit fields
openssl x509 -in cert.pem -noout -subject -issuer -dates
openssl x509 -in cert.pem -noout -ext subjectAltName
openssl x509 -in cert.pem -noout -text | grep -E "Signature Algorithm|Public-Key"
```

**Check each against the certificate table in `tls-crypto-reference.md`:**
self-signed (issuer == subject), missing SAN, name mismatch, SHA-1 signature,
RSA key < 2048-bit, over-scoped wildcard.

### Probe which protocol versions the server accepts

```bash
# Each returns a cert if the version is accepted, an error if refused
for v in ssl3 tls1 tls1_1 tls1_2 tls1_3; do
  if echo | openssl s_client -connect $TARGET:443 -"$v" 2>/dev/null \
       | grep -q "BEGIN CERTIFICATE"; then
    echo "$v: SUPPORTED"
  else
    echo "$v: refused"
  fi
done
# Any of ssl3/tls1/tls1_1 SUPPORTED is a finding.
```

---

## Step 4 — Certificate Expiry Monitoring

```bash
# Fail if the cert expires within 30 days (2592000 seconds) — cron-friendly
if echo | openssl s_client -connect $TARGET:443 2>/dev/null \
     | openssl x509 -noout -checkend 2592000; then
  echo "OK: >30 days remaining"
else
  echo "WARN: expires within 30 days"
fi

# Exact days remaining
end=$(echo | openssl s_client -connect $TARGET:443 2>/dev/null \
      | openssl x509 -noout -enddate | cut -d= -f2)
echo "$(( ( $(date -d "$end" +%s) - $(date +%s) ) / 86400 )) days left"
```

Sweep a fleet and sort by urgency:

```bash
while read -r host; do
  end=$(echo | openssl s_client -connect "$host:443" 2>/dev/null \
        | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
  [ -n "$end" ] && printf '%s\t%s days\n' "$host" \
    "$(( ( $(date -d "$end" +%s) - $(date +%s) ) / 86400 ))"
done < tls-hosts.txt | sort -t$'\t' -k2 -n
```

---

## Step 5 — Certificate Transparency: Discovery Without Probing

Every publicly trusted certificate is logged permanently in **Certificate
Transparency** logs. Querying them reveals an organisation's hostnames —
including internal-sounding names that leaked into a public cert — and sends
**nothing** to the target. This is the same passive principle the IPv6 skill
uses, applied to asset discovery.

```bash
# crt.sh — every name that ever appeared in a cert for the domain
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | python3 -c 'import sys,json;
[print(n) for c in json.load(sys.stdin)
   for n in c["name_value"].split("\n")]' \
  | sort -u

# Aggregate many passive sources at once
subfinder -d example.com -silent
```

**Then close the loop:** resolve the discovered names and feed the live ones
back into active scanning.

```bash
crt.sh_names.txt | while read -r h; do
  ip=$(dig +short "$h" | tail -1); [ -n "$ip" ] && echo "$ip $h"
done | sort -u
```

> CT queries hit public log archives, not the target, so they are invisible to
> the target's monitoring. They also surface certificates for hosts that no
> longer resolve — historical attack surface worth noting.

---

## Step 6 — Harvest Names From the Certs You Already Pulled

The SANs in a served certificate are themselves a discovery source — one cert
often names many virtual hosts:

```bash
# Every DNS name a host's own certificate claims to serve
echo | openssl s_client -connect $TARGET:443 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName \
  | tr ',' '\n' | grep -oE 'DNS:[^ ]+' | cut -d: -f2
```

Merge these names into the inventory alongside the reverse-DNS hostnames —
see the discovery-inventory skill.

---

## Step 7 — Build the Inventory

```bash
sudo nmap --open -sV -p 443,8443,993,995,636,5986 \
  --script "ssl-cert,ssl-enum-ciphers" $SUBNET \
  -oA tls-audit
```

Per-host columns:

| Host | Port | Min proto | Grade | Cert expires | Vulns | Risk |
|---|---|---|---|---|---|---|
| www | 443 | TLS 1.2 | A | 84 d | — | Low |
| legacy | 8443 | **TLS 1.0** | C | **−5 d (expired)** | POODLE | **Critical** |

---

## Quick Reference

```bash
# Find TLS on any port
sudo nmap -sV --open -p 443,8443,993,995,636,5986 $SUBNET

# Grade one host thoroughly
./testssl.sh $TARGET

# Grade a subnet quickly
nmap --script ssl-enum-ciphers -p 443 $SUBNET

# Cert details + expiry
echo | openssl s_client -connect host:443 2>/dev/null | openssl x509 -noout -subject -dates -ext subjectAltName

# Passive discovery from Certificate Transparency
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u
```

---

## Common Mistakes

| Symptom | Usually means | Do this |
|---|---|---|
| No TLS found on 443 | TLS runs on far more than 443 | Scan by service (`-sV`) across ports, not by port number |
| `testssl` run incomplete or very slow | Rate limiting, or the host drops repeated handshakes | Do not report *no weak ciphers* from a truncated run — say the run was incomplete |
| Certificate looks expired | Local clock skew, or SNI mismatch returning the default vhost | Re-check with `-servername` |
| Cert has names you did not expect | Shared cert or a SAN list covering other services | Names in a SAN are leads, and still need to be in scope before probing |

**The inference ceiling.** A handshake proves **what this endpoint presented for this SNI at this moment**. It says nothing about other vhosts on the same IP, and a certificate's contents are assertions by whoever requested it.

---

## When to Use Something Else

| Scenario | Better tool |
|---|---|
| SSH crypto posture | `ssh-audit` — see remote-access-discovery |
| Just finding the hosts | arp / nmap / ipv6 discovery skills |
| Deep single-host TLS audit | `testssl.sh`, `sslscan`, SSLyze |
| Continuous CT monitoring / alerting | certspotter, Cert Transparency APIs |
| Public-internet TLS at scale | censys, Shodan, ZMap + zgrab2 |

---

## Ethical and Legal Notice

Grading a server's TLS and pulling its certificate are low-impact and normally
in scope for any web assessment. **Certificate Transparency queries are
passive** — they hit public logs, not the target — but the hostnames they
reveal (and the act of resolving and scanning them) are active reconnaissance
that must fall within authorised scope. A discovered internal hostname in a
public certificate is a finding to *report*, not an invitation to pivot beyond
your engagement. Only test networks you own or are authorised to assess.

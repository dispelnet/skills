---
name: rdp-vnc-discovery
description: >
  Use this skill when the user wants to find, enumerate, or audit graphical
  and Windows remote-access services — RDP, VNC, and WinRM. Triggers include:
  "find RDP servers", "scan for port 3389", "check RDP security", "is NLA
  enabled", "find VNC servers", "scan port 5900", "unauthenticated VNC",
  "check for BlueKeep", "WinRM enumeration", "port 5985", "remote desktop
  audit", "find exposed desktops", "RDP encryption level", or any request to
  probe remote desktop / graphical console / Windows remote management
  services for exposure, authentication, or encryption posture. For SSH and
  Telnet instead, use remote-access-discovery.
---

# RDP, VNC & WinRM Discovery

## Hard Rules — Read Before Running Anything

**Do not run any command in this skill until the target range is confirmed.**

1. **State the confirmed range back before the first command.** Never default
   to the local subnet; never widen a confirmed range.
2. **Enumerate, do not authenticate.** Credential checks, brute forcing and
   password spraying are out of scope here even where the tool offers them.
3. **Vulnerability checks stay per host.** The BlueKeep and MS12-020 checks
   are safe checks rather than exploits, but run them against named hosts you
   confirmed — do not sweep them across a range.
4. **A reachable console is a finding, not an invitation.** Do not connect to
   an unauthenticated VNC session to "confirm" it. The auth-type response is
   the evidence; viewing someone's desktop is access, not discovery.

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

The remote-access-discovery skill covers text protocols (SSH, Telnet). This
one covers the **graphical and Windows** remote-access protocols, which have a
different and often worse risk profile:

- **RDP** (3389) — the remote-access protocol most associated with real-world
  intrusion. RDP exposure is a primary ransomware initial-access vector.
- **VNC** (5900+) — frequently deployed with **no authentication at all**, and
  even when authenticated, capped at an 8-character DES-truncated password.
- **WinRM** (5985/5986) — Windows remote management, often exposed over plain
  HTTP.

**Why this matters (measured, not asserted):**
- At BlueKeep disclosure, ~950,000 internet-exposed systems were vulnerable;
  hundreds of thousands remained unpatched years later.
- Shadowserver and independent scans have repeatedly found **tens of thousands
  of VNC servers with authentication disabled**, including ~670 exposing
  ICS/OT panels directly.
- Shodan shows on the order of 1.6M VNC and 1.8M RDP endpoints exposed.

---

## Install

The Nmap NSE scripts used here ship with Nmap. Add clients and a purpose-built
scanner for depth:

```bash
sudo apt install nmap freerdp2-x11 tigervnc-viewer -y   # Debian/Ubuntu/Kali
# BlueKeep-specific scanner (safe, non-exploit check):
git clone https://github.com/robertdavidgraham/rdpscan && cd rdpscan && make
# NetExec for credentialed WinRM/RDP checks:
pipx install netexec
```

---

## Step 1 — Find the Services

Feed this skill live hosts from arp/nmap/ipv6 discovery, or scan directly.

```bash
# The three protocol families in one sweep
sudo nmap -Pn -p 3389,5900-5910,5985,5986 --open $SUBNET

# RDP also runs over UDP 3389; WinRM HTTPS is 5986
sudo nmap -Pn -sU -p 3389 --open $SUBNET

# RDP is frequently moved off 3389 — version detection catches it
sudo nmap -Pn -sV -p 3389,3388,33890,3390 --open $SUBNET
```

| Port | Service | Note |
|---|---|---|
| 3389/tcp,udp | RDP | Also `ms-wbt-server` in `-sV` output |
| 5900–5910 | VNC | Display *n* listens on 5900+*n*; 5901 = `:1` |
| 5800–5810 | VNC over HTTP | Java applet viewer, reveals VNC presence |
| 5985 | WinRM HTTP | **Cleartext transport** |
| 5986 | WinRM HTTPS | |
| 5000, 5900 | Also Apple Remote Desktop / screen sharing | Confirm with `-sV` |

---

## Step 2 — RDP Enumeration

### System info without credentials

`rdp-ntlm-info` sends an incomplete CredSSP request; an NLA-enabled server
answers with its identity **before** authentication:

```bash
nmap -Pn -p 3389 --script rdp-ntlm-info $TARGET
```
```
| rdp-ntlm-info:
|   Target_Name: CORP
|   NetBIOS_Computer_Name: FILESERVER01
|   DNS_Domain_Name: corp.example.com
|   DNS_Computer_Name: fileserver01.corp.example.com
|_  Product_Version: 10.0.19041          ← Windows build → patch level
```

The build number maps to a patch level — cross-reference it the same way the
SSH skill treats a banner: a triage signal requiring host-side confirmation,
not a confirmed finding.

### Encryption and NLA posture — the real audit

```bash
nmap -Pn -p 3389 --script rdp-enum-encryption $TARGET
```
```
| rdp-enum-encryption:
|   Security layer
|     CredSSP (NLA): SUCCESS          ← good — auth happens before session
|     Native RDP: SUCCESS             ← BAD — pre-auth session, BlueKeep-exposed
|     RDSTLS: SUCCESS
|   RDP Encryption level: High
```

**What to flag:**

| Observation | Risk |
|---|---|
| `CredSSP (NLA): SUCCESS` and Native RDP fails | Good — NLA enforced |
| `Native RDP: SUCCESS` | **NLA not required** — pre-auth attack surface, incl. BlueKeep |
| RDP Encryption level `Low` / `Client Compatible` | Weak — downgradeable |
| `RDP Security Layer` only (no TLS/CredSSP) | Credentials protected by RDP's own weak crypto |

NLA is the single most important RDP control: it forces authentication
*before* a session is established, which closes off the entire class of
pre-authentication RDP vulnerabilities.

### BlueKeep (CVE-2019-0708) and MS12-020

```bash
# rdpscan: purpose-built, reports VULNERABLE / SAFE / UNKNOWN.
# It is a SAFE check — it does not exploit. Still, run only in scope.
./rdpscan $TARGET
./rdpscan --file rdp-hosts.txt

# MS12-020 (older pre-auth DoS) — NSE
nmap -Pn -p 3389 --script rdp-vuln-ms12-020 $TARGET
```

> A host reporting `SAFE` from rdpscan is either patched **or** NLA-enabled —
> both close BlueKeep. Correlate with the `rdp-enum-encryption` result to know
> which.

---

## Step 3 — VNC Enumeration

### Authentication type — the headline finding

```bash
nmap -Pn -p 5900 --script vnc-info $TARGET
```
```
| vnc-info:
|   Protocol version: 3.8
|   Security types:
|     None (1)                      ← CRITICAL: no authentication at all
|     VNC Authentication (2)
```

`None` means anyone who connects gets an interactive desktop with zero
credentials. This is a critical finding on its own — verify (read-only) by
connecting and immediately disconnecting, and screenshot for the report:

```bash
# Confirm and capture evidence, then disconnect. Authorized targets only.
vncviewer -ViewOnly $TARGET:5900
```

### VNC Authentication is not strong either

Even with `VNC Authentication (2)`, the RFB challenge-response uses **DES with
the password truncated to 8 characters**, so the effective keyspace is small
and the scheme is offline-crackable from a single captured handshake. Treat
password-protected VNC on an untrusted network as a weakness, not a control.

```bash
# Grab the desktop title without authenticating — reveals user/host/app
nmap -Pn -p 5900 --script vnc-title $TARGET

# RealVNC 4.1.x authentication bypass (CVE-2006-2369)
nmap -Pn -p 5900 --script realvnc-auth-bypass $TARGET
```

### Enumerate the display range

```bash
# One machine can run several VNC displays (5900=:0, 5901=:1, ...)
sudo nmap -Pn -sV -p 5900-5910 --script vnc-info --open $TARGET
```

---

## Step 4 — WinRM Enumeration

```bash
# Detect and identify
sudo nmap -Pn -p 5985,5986 --script http-title,ssl-cert $TARGET

# WinRM speaks SOAP/HTTP; confirm the WSMan Identify endpoint answers
curl -s -m5 http://$TARGET:5985/wsman -X POST \
  -H "Content-Type: application/soap+xml" 2>/dev/null | head -c 200; echo

# Credentialed check (with authorization + supplied creds): validate login
# and enumerate — NetExec speaks WinRM natively
nxc winrm $TARGET -u user -p 'password'
```

**What to flag:**

| Observation | Risk |
|---|---|
| WinRM on **5985** (HTTP) reachable | Management traffic in cleartext |
| WinRM exposed beyond a management VLAN | Lateral-movement and relay surface |
| `Negotiate`/`Basic` auth over HTTP | Credentials exposed on the wire |

---

## Step 5 — Build the Inventory

```bash
sudo nmap -Pn -p 3389,5900-5905,5985,5986 --open -sV \
  --script "rdp-ntlm-info,rdp-enum-encryption,vnc-info,vnc-title" \
  $SUBNET -oA remote-desktop-audit
```

Per-host columns worth populating:

| IP | Host | RDP NLA? | RDP enc | BlueKeep | VNC auth | WinRM | Risk |
|---|---|---|---|---|---|---|---|
| .10 | FS01 | Yes | High | SAFE | — | — | Low |
| .55 | KIOSK | **No** | Low | **VULN** | — | — | **Critical** |
| .70 | LAB | — | — | — | **None** | — | **Critical** |

---

## Safety Notes

- `rdp-ntlm-info`, `rdp-enum-encryption` and `vnc-info` read pre-auth
  responses and do **not** authenticate — low-noise, safe to sweep in scope.
- `rdpscan` is a **safe** BlueKeep check (no exploitation), but Nmap's
  `rdp-vuln-ms12-020` probes a DoS bug — do not run it against fragile or
  production hosts.
- Do **not** point brute-force scripts (`vnc-brute`, RDP credential spraying)
  at a subnet. Like `ssh-auth-methods`, they authenticate and log; RDP account
  lockout policy will lock out real users. Per-host, with authorization, only.
- Connecting to an unauthenticated VNC session is interacting with a live
  desktop — someone may be watching. Use `-ViewOnly`, keep it brief, and
  document that you did.

---

## Common Mistakes

| Symptom | Usually means | Do this |
|---|---|---|
| 3389 open, the NSE script returns nothing | NLA is enabled — the server refuses pre-auth enumeration | Record *NLA enabled*. That is good posture and a result, not a failed scan |
| VNC reports auth type 1 | No authentication at all | A finding. Record it from the auth-type response — do not connect to confirm |
| 5985 open, probe gets no useful reply | WinRM expects Negotiate auth | The exposure plus cleartext transport is the finding; do not attempt credentials |
| BlueKeep check returns nothing | Patched, NLA on, or the probe was filtered | Three different states. Do not report *patched* from silence |

**The inference ceiling.** These probes prove **what a service exposed to an unauthenticated stranger**. Exposure is not exploitability, and a negative vulnerability check is not proof of patching.

---

## When to Use Something Else

| Scenario | Better tool |
|---|---|
| SSH / Telnet audit | `ssh-audit` — see remote-access-discovery |
| Finding the hosts first | arp / nmap / ipv6 discovery skills |
| Credentialed Windows enumeration | NetExec, `evil-winrm` |
| RDP session recording / MitM research | `pyrdp` |
| TLS posture of WinRM HTTPS / RDP TLS | see tls-certificate-discovery |

---

## Ethical and Legal Notice

Only enumerate services on networks you own or have explicit written
authorisation to test. Connecting to an unauthenticated RDP or VNC service —
even to confirm it is unauthenticated — is access to a computer system and may
be regulated by computer-misuse law regardless of the missing password. Keep
interaction read-only and minimal, and record what you did. This skill is for
administrators and authorised penetration testers operating within scope.

---
name: wireless-network-discovery
description: >
  Use this skill when the user wants to discover, enumerate, or audit 802.11
  Wi-Fi networks and devices — access points, clients, SSIDs, and wireless
  security posture. Triggers include: "scan for Wi-Fi", "find wireless
  networks", "802.11 recon", "monitor mode", "airodump-ng", "kismet", "find
  hidden SSID", "rogue AP detection", "evil twin", "WPA2/WPA3 audit", "PMKID",
  "wireless survey", "who is on the Wi-Fi", "is my wireless secure", "detect
  unauthorized access points", or any request to enumerate the RF/link layer
  of a wireless network. Use this when ARP or IP scanning is defeated by Wi-Fi
  client isolation — the RF layer sees APs and clients that the IP layer cannot.
---

# Wireless Network Discovery

## Hard Rules — Read Before Running Anything

**Do not run any command in this skill until the scope is confirmed.**

1. **Confirm which SSIDs and BSSIDs are in scope**, and state them back. RF
   has no address boundary: a monitor interface receives every neighbouring
   network whether or not you asked for it. Filter capture to the authorised
   BSSIDs and discard the rest.
2. **Passive only, unless active steps are expressly in scope.** Monitor-mode
   capture receives. Deauthentication, evil-twin and jamming *transmit* —
   they are illegal in many jurisdictions regardless of intent (the US FCC
   among others) and they disrupt networks outside your scope.
3. **Do not decode traffic you are not party to** without explicit written
   authorisation. In many jurisdictions that is unlawful interception, which
   is a different offence from unauthorised scanning.
4. **Handshake and PMKID capture is in scope for an audit; cracking is not**
   unless the engagement says so in writing.

Full legal statement: [Ethical and Legal Notice](#ethical-and-legal-notice).

### Set these first

Every command below uses these. Fill them in from the scope you just
confirmed, and substitute nothing by hand afterwards. An unset variable
makes the command fail loudly — that is the point; a hardcoded address
fails silently against the wrong network.

```bash
TARGET="192.168.1.10" # a single confirmed host
IFACE="wlan0"         # the wireless interface, in managed mode
MON="${IFACE}mon"     # monitor-mode interface, created by airmon-ng
```

---

When `arp-scan` returns only the gateway on a Wi-Fi network, the cause is
usually **client isolation** (see arp-network-discovery, finding ARP-01) — the
AP blocks station-to-station frames. The fix is not a better IP-layer flag; it
is a **different layer**. In monitor mode a wireless adapter captures every
802.11 frame in the air, so it sees the APs and clients that isolation hides
from ARP and IP scanning entirely.

This is inherently a **passive** discipline: monitor-mode capture transmits
nothing, so it is undetectable and cannot disrupt the network.

> **Hardware note.** This needs a wireless adapter that supports monitor mode
> and frame injection (common on servers/VMs: none). Adapters based on
> Atheros AR9271, Ralink RT3070/RT5372, or MediaTek MT7612U are the usual
> known-good choices. Without such an adapter, none of the capture commands
> below will work.

---

## Step 1 — Enter Monitor Mode

NetworkManager and `wpa_supplicant` will fight monitor mode; stop them first.

```bash
# See the interface and its current mode
iw dev

# airmon-ng: kill interfering processes, then enable monitor mode
sudo airmon-ng check kill
sudo airmon-ng start $IFACE            # creates $MON

# Or with iw directly (when airmon-ng is unavailable)
sudo ip link set $IFACE down
sudo iw dev $IFACE set type monitor
sudo ip link set $IFACE up
iw dev $IFACE info | grep type         # confirm: "type monitor"
```

Restore normal operation afterward:

```bash
sudo airmon-ng stop $MON
sudo systemctl restart NetworkManager
```

---

## Step 2 — Passive Discovery: Every AP and Client in Range

`airodump-ng` is the workhorse. Left running, it enumerates access points
(top) and the clients associated with them (bottom), sending nothing.

```bash
# Sweep all channels, write structured output for later parsing
sudo airodump-ng --write survey --output-format csv,pcap $MON
```
```
 BSSID              PWR  CH  ENC  CIPHER AUTH ESSID
 AA:BB:CC:11:22:33  -42   6  WPA2 CCMP   PSK  CorpWiFi
 AA:BB:CC:11:22:34  -43  36  WPA3 CCMP   SAE  CorpWiFi-5G
 (not associated)   -60          Probe: FreeWifi, HomeNet   ← client probes
```

| Column | Meaning |
|---|---|
| `BSSID` | AP MAC — the OUI identifies the vendor (see arp skill) |
| `CH` / `PWR` | Channel / signal strength (proximity) |
| `ENC`/`CIPHER`/`AUTH` | Security posture — the audit fields |
| `ESSID` | Network name (`<length: n>` = hidden, see Step 3) |
| Station rows | **Clients** — including ones an IP scan never sees |

The station list is the payoff versus IP scanning: it enumerates wireless
clients directly from their frames, right through client isolation.

### Kismet — richer, with a web UI and logging

```bash
sudo kismet -c $MON        # then browse http://localhost:2501
```

Kismet passively logs APs, clients, probes, and manufacturer data over time
and flags anomalies — better than airodump for a long survey or IDS-style use.

---

## Step 3 — Reveal Hidden SSIDs

A "hidden" network simply omits its name from beacons; the name still travels
in plaintext whenever a client associates or probes. Watch for it passively:

```bash
# Lock onto the hidden AP's channel and wait for a client to name it
sudo airodump-ng -c 6 --bssid AA:BB:CC:11:22:33 $MON
# The ESSID fills in the moment any client associates.
```

Hidden SSIDs are security-through-obscurity; surface them and note that they
provide no real protection.

---

## Step 4 — Rogue AP and Evil-Twin Detection

This is often the point of a wireless audit: finding APs that should not be
there.

**Rogue AP** — an unauthorized AP on your network (an employee's travel
router, an attacker's drop box). Enumerate every BSSID and compare against the
known-authorized list:

```bash
# Diff on BSSID alone — the AP's identity. (Comparing BSSID+ESSID strings is
# fragile: airodump pads the ESSID field, so whitespace breaks the match.)
# authorized-bssids.txt holds one approved BSSID per line, lowercase.
awk -F, 'NR>1 && $1 ~ /:/ {gsub(/ /,"",$1); print tolower($1)}' survey-01.csv \
  | sort -u > seen-bssids.txt
comm -13 <(sort -u authorized-bssids.txt) seen-bssids.txt   # unapproved APs

# Keep the ESSID for context once you have the unapproved BSSID list
grep -Ff <(comm -13 <(sort -u authorized-bssids.txt) seen-bssids.txt) \
  <(awk -F, 'NR>1 && $1 ~ /:/ {gsub(/^ /,"",$14); print tolower($1)"  "$14}' survey-01.csv)
```

**Evil twin** — an AP impersonating a legitimate SSID to lure clients. Because
SSID and BSSID are trivially spoofed, the tells are structural:

- The **same ESSID on an unexpected BSSID** (especially a BSSID whose OUI is
  not your AP vendor's).
- The same SSID on a **different channel** or with a **different security
  config** than your real APs (e.g. your network is WPA3, the twin offers
  WPA2 or open).
- **Anomalous signal strength / location** for a known SSID.

```bash
# Group by ESSID; more than one BSSID for a single-AP SSID is suspicious
awk -F, 'NR>1 && $1 ~ /:/ {gsub(/ /,"",$1); print $14, $1}' survey-01.csv \
  | sort | awk '{c[$1]++; b[$1]=b[$1]" "$2} END{for(e in c) if(c[e]>1) print e":"b[e]}'
```

---

## Step 5 — Wireless Security Posture

Read the `ENC`/`AUTH` columns and flag:

| Observation | Risk |
|---|---|
| `OPN` (open) | No encryption — all traffic in clear |
| `WEP` | **Critical** — broken, crackable in minutes |
| `WPA` (TKIP) | Weak — deprecated cipher |
| `WPA2-PSK` | Baseline; PSK is offline-crackable from a captured handshake |
| `WPA2-MGT` (802.1X) | Better — per-user auth |
| **WPA2/WPA3 transition mode** | **Downgrade-exposed** — see below |
| `WPA3-SAE` | Current — SAE resists offline cracking |

### WPA3 transition mode is a real finding

An AP in **transition mode** advertises WPA3-SAE *and* WPA2-PSK together for
backward compatibility. A client that supports both can be forced to fall back
to WPA2 by a rogue AP offering only PSK — at which point you capture a normal
WPA2 handshake and the WPA3 protection is moot. If a network's stated posture
is "we're on WPA3," transition mode quietly undoes that; flag it explicitly.

### Handshake / PMKID capture — for authorized posture assessment

Capturing the material that *would* allow offline PSK cracking demonstrates the
exposure. Detection/capture is in scope for an audit; the actual cracking is
the attack step and needs explicit authorization.

```bash
# WPA handshake: capture passively, or deauth a client to force a re-handshake
# (deauth TRANSMITS and disrupts — authorized engagements only)
sudo airodump-ng -c 6 --bssid AA:BB:CC:11:22:33 -w handshake $MON

# PMKID: often obtainable from the AP alone, no client needed
sudo hcxdumptool -i $MON -o pmkid.pcapng --enable_status=1
```

> A captured handshake or PMKID proves the network's PSK is offline-attackable.
> Report that as the finding; do not run the crack unless authorization
> explicitly covers it.

---

## Step 6 — Verify Client Isolation (closing the loop with ARP-01)

If the arp-network-discovery skill came up empty on this WLAN, confirm *why*
here — is isolation actually enforced, or was the segment simply quiet?

```bash
# On the WLAN as a normal client, try to reach another client seen in Step 2.
# Isolation enforced => no ARP reply, no ping, even though monitor mode
# proved the client exists.
arping -I $IFACE $TARGET        # times out under isolation
```

Monitor mode saw the client (RF layer); ARP cannot reach it (link layer
blocked) — that contrast *is* the confirmation that isolation is on, and it is
why wireless discovery belongs at the RF layer, not the IP layer.

---

## Quick Reference

```bash
# Monitor mode
sudo airmon-ng check kill && sudo airmon-ng start $IFACE

# Survey everything (passive), write CSV+pcap
sudo airodump-ng --write survey --output-format csv,pcap $MON

# Focus one AP + its clients (reveals hidden SSID, captures handshake)
sudo airodump-ng -c 6 --bssid AA:BB:CC:11:22:33 -w cap $MON

# Restore
sudo airmon-ng stop $MON && sudo systemctl restart NetworkManager
```

---

## Common Mistakes

| Symptom | Usually means | Do this |
|---|---|---|
| No APs at all | The interface is not really in monitor mode, or you are scanning one band | `iw dev` should say `type monitor`; 5/6 GHz needs an explicit channel list |
| A known SSID never appears | Hidden network, or out of range | Hidden SSIDs surface only when a client associates — wait, do not deauth |
| Clients listed with random MACs | Expected — randomization is on by default | Do not count unique MACs as unique devices |
| Fewer clients than expected | Capture is per-channel; hopping misses frames | Lock to the target channel for an accurate client list |

**The inference ceiling.** 802.11 capture proves **what was transmitted in range during your window, on the channels you listened to**. It is a sample, not an estate inventory, and signal strength is not distance.

---

## When to Use Something Else

| Scenario | Better tool |
|---|---|
| Wired IPv4 host discovery | arp-network-discovery skill |
| Enumerating clients once on the network | nmap / passive-network-discovery skills |
| Long-term wireless IDS / logging | Kismet, a dedicated WIDS |
| Bluetooth / BLE discovery | `bluetoothctl`, `bettercap` BLE modules |
| Spectrum / non-802.11 RF | an SDR (HackRF, RTL-SDR) |

---

## Ethical and Legal Notice

Wireless monitoring is **more tightly regulated than wired scanning**. Passive
802.11 capture is receiving radio, but capturing and decoding traffic you are
not party to may be unlawful interception depending on jurisdiction — and any
**transmitting** action (deauthentication, evil-twin, jamming) is active
interference that is illegal in many countries and can disrupt networks you did
not intend to touch. Deauth and jamming in particular are prohibited by
regulators (e.g. the US FCC) regardless of intent. Only operate on networks you
own or have explicit written authorisation to test, keep to passive capture
unless active steps are expressly in scope, and respect local RF and privacy
law. This skill is for authorised wireless assessments only.

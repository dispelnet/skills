---
name: ics-ot-discovery
description: >
  Use this skill when the user wants to discover, inventory, or enumerate
  industrial control systems (ICS), SCADA, or operational technology (OT) —
  PLCs, RTUs, HMIs, and field devices. Triggers include: "find PLCs", "scan
  SCADA", "ICS discovery", "OT asset inventory", "Modbus scan", "find
  industrial devices", "port 502", "S7 / Siemens PLC", "EtherNet/IP", "DNP3",
  "BACnet", "is my ICS exposed", "SCADA enumeration", "Purdue model scanning",
  "safely scan OT", or any request to enumerate industrial protocols and
  controllers. CRITICAL: also use whenever any scan target may contain PLCs,
  RTUs, HMIs, a plant floor, a substation, or an OT/process-control segment —
  ordinary IT scanning crashes these devices.
---

# ICS / OT Discovery

## Stop — Read the Hard Rules First

**Do not run any command in this skill until you have read the Hard Rules
below and confirmed all five preconditions with the user.**

1. **Scope** — the exact hosts, confirmed and stated back. Never a range.
2. **A maintenance window** — general "the network is in scope" permission
   does not authorise probing a controller during production.
3. **The OT team present**, with someone watching the process who can call a
   stop.
4. **An exclusion list** of safety-instrumented systems (SIS) and anything
   life-critical, loaded into `--excludefile` before the first command.
5. **A passive attempt first.** If passive discovery has not been tried, that
   is the next step — not an active probe.

Missing any one of these? **Stop and ask.** A crashed PLC is a safety
incident, not a failed scan.

Full legal statement: [Ethical and Legal Notice](#ethical-and-legal-notice).

### Set these first

Every command below uses these. Fill them in from the scope you just
confirmed, and substitute nothing by hand afterwards. An unset variable
makes the command fail loudly — that is the point; a hardcoded address
fails silently against the wrong network.

```bash
SUBNET="192.168.1.0/24" # the confirmed range
CONTROLLER="10.0.0.10"  # ONE confirmed controller — never a range
```

---

**Why the rules above are hard rules:**

Industrial controllers are not servers. A PLC or RTU runs a real-time control
loop with a tiny network stack that was never built to withstand IT scanning
traffic. A routine `nmap -sV` can send an **HTTP probe to a Modbus PLC**, and
the device — unable to parse it — faults, drops its control loop, or reboots.
In a live plant that is not a "process upset"; it can be a safety incident.

> The Nmap skill in this collection already warns that a SYN scan can crash
> ICS gear. This skill is the answer to "so how do I enumerate them anyway."
> The answer is: **passively first, and if you must go active, under hard
> constraints, per host, in a maintenance window, with the OT team present.**

The field consensus (and the reason dedicated OT-monitoring products exist) is
that OT discovery should be **passive by default**. Active probing is the
exception that requires justification, not the default that requires an excuse.

---

## Step 0 — Passive First (Almost Always the Right Answer)

Passive discovery cannot crash a controller because it sends nothing. On an OT
segment it is not just safer — it is often *more complete*, because ICS devices
are chatty: they poll each other on a cycle, so a listener sees them without a
single probe.

**Use the passive-network-discovery skill as the primary tool here.** Two OT
specifics make it especially effective:

### ICS devices betray themselves by MAC/OUI

Industrial vendors use registered OUIs. A passive ARP capture plus an OUI
lookup identifies controllers by manufacturer before you touch anything —
Siemens, Rockwell/Allen-Bradley, Schneider, Beckhoff, WAGO, Phoenix Contact,
Omron, Mitsubishi all have distinctive OUI ranges. This is the method in
Mehner et al., *Efficient Passive ICS Device Discovery and Identification by
MAC Address Correlation* (2019), and it ties directly to the
arp-network-discovery and passive-network-discovery skills.

```bash
# Passive: watch ARP, resolve vendor from the OUI (never probes the device)
sudo tcpdump -i eth0 -ln arp | \
  while read -r l; do echo "$l"; done      # feed MACs to an OUI lookup

# Or read the switch's tables via SNMP — authoritative, still no OT probe
# (see snmp-network-inventory): the bridge/ARP tables list every OT MAC
```

### Zeek understands industrial protocols

Zeek parses Modbus, DNP3, BACnet and others natively. Pointed at a SPAN/TAP of
an OT segment, it inventories every controller, function code, and register
access **passively**.

```bash
zeek -r ot-capture.pcap
cat modbus.log dnp3.log bacnet.log 2>/dev/null | head    # protocol-level inventory
```

---

## The ICS Protocol / Port Map

| Protocol | Port | Typical device | NSE script | Bundled? |
|---|---|---|---|---|
| Modbus TCP | 502/tcp | Almost everything | `modbus-discover` | Yes |
| S7comm (Siemens) | 102/tcp | S7 PLCs | `s7-info` | Yes |
| EtherNet/IP + CIP | 44818/tcp, 2222/udp | Rockwell/Allen-Bradley | `enip-info` | Yes |
| BACnet | 47808/udp | Building automation | `bacnet-info` | Yes |
| Niagara Fox | 1911/tcp, 4911/tcp | Tridium HVAC/BMS | `fox-info` | Yes |
| FINS (Omron) | 9600/tcp,udp | Omron PLCs | `omron-info` | Yes |
| PCWorx (Phoenix) | 1962/tcp | Phoenix Contact | `pcworx-info` | Yes |
| IEC 60870-5-104 | 2404/tcp | Power / substations | `iec-identify` | Yes |
| KNX | 3671/udp | Building automation | `knx-gateway-info` | Yes |
| DNP3 | 20000/tcp | Power / water SCADA | `dnp3-info` | **Redpoint** |
| MMS / IEC 61850 | 102/tcp | Substation IEDs | `mms-*` | **Redpoint** |
| CODESYS | 2455/tcp | Soft-PLC runtimes | `codesys-v2-discover` | **Redpoint** |
| ProConOS | 20547/tcp | Various soft PLCs | `proconos-info` | **Redpoint** |
| Melsec (Mitsubishi) | 5007/tcp | Mitsubishi PLCs | `modicon-*`/vendor | **Redpoint** |
| HART-IP | 5094/tcp,udp | Field instruments | — | passive/manual |
| OPC UA | 4840/tcp | Modern OT gateways | `opc-ua` (external) | check |

Confirm what your Nmap actually has before relying on a script:

```bash
nmap --script-help s7-info >/dev/null 2>&1 || echo "not installed"
```

### Installing the Redpoint scripts (the non-bundled rows)

Digital Bond's **Redpoint** provides the scripts Nmap does not ship. They use
legitimate protocol commands — no exploitation — but read the safety section
first; "legitimate command" is not the same as "safe against every firmware."

```bash
git clone https://github.com/digitalbond/Redpoint
sudo cp Redpoint/*.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb
```

---

## Step 1 — Locate ICS Without Touching Controllers

Prefer indirect discovery over probing the field devices themselves.

```bash
# BEST: passive + switch tables (no OT probe at all)
#   - passive-network-discovery skill for the capture
#   - snmp-network-inventory skill to read the switch's MAC/ARP tables

# If you must actively find listeners, a TCP CONNECT scan (-sT) of ONLY the
# ICS ports, slowly, is gentler than -sS and far gentler than -sV.
# -sT completes the handshake cleanly; a half-open -sS leaves the tiny stack
# holding state. NEVER add -sV or -A here — version probes are what crash PLCs.
sudo nmap -sT -Pn --scan-delay 1s --max-retries 1 \
  -p 502,102,44818,20000,2404,1911,9600,1962 \
  --open $SUBNET
```

**Why every flag matters:**
- `-sT` — full TCP handshake; does not leave the stack half-open.
- `--scan-delay 1s` — one probe at a time, slowly. The single most important
  safety control on an OT segment.
- `--max-retries 1` — do not hammer a device that did not answer the first time.
- **No `-sV`, no `-A`, no `-O`.** Service/version detection sends
  protocol-guessing payloads (including HTTP) that non-IT stacks cannot parse.
- `-Pn` — many ICS devices do not answer ping; skip host discovery rather than
  escalate probe types.

---

## Step 2 — Enumerate a Confirmed Controller (One at a Time)

Only after you know a host is an ICS device, and only with authorization and
the OT team's awareness, run the protocol-specific script — against **one
host**, never a subnet sweep.

```bash
# Modbus: unit IDs and device identification
sudo nmap -sT -Pn -p 502 --script modbus-discover $CONTROLLER

# Siemens S7: module, firmware, serial, plant identification
sudo nmap -sT -Pn -p 102 --script s7-info $CONTROLLER

# EtherNet/IP: product name, vendor, revision (Rockwell etc.)
sudo nmap -sT -Pn -p 44818 --script enip-info $CONTROLLER

# BACnet: device instance, vendor, object list (building automation)
sudo nmap -sU -Pn -p 47808 --script bacnet-info $CONTROLLER
```

These use legitimate read commands, but treat any one of them as capable of
upsetting fragile firmware. Space them out; watch the process side for effects;
stop at the first sign of trouble.

---

## What Counts as a Finding

For ICS, exposure is frequently the whole finding — before any CVE.

| Observation | Why it matters |
|---|---|
| ICS protocol reachable from the **IT** network | Purdue-model segmentation has failed |
| ICS protocol reachable from the **internet** | Critical — Shodan-class exposure |
| Modbus/DNP3/S7 with **no authentication** | These protocols have none by design — anyone on-path can command the device |
| Engineering protocol (S7, CODESYS) exposed | Allows logic download/upload — full control |
| Legacy firmware with known ICS-CERT advisories | Cross-ref vendor + version against ICS-CERT |
| Default credentials on the HMI/web UI | Common and rarely changed on OT gear |

Most ICS protocols were designed for isolated networks and have **no
authentication or encryption at all**. On a routable path, "unauthenticated
Modbus" is not a misconfiguration to note in passing — it is remote control of
a physical process.

---

## Hard Rules

1. **Passive first.** Active probing of OT is the exception, justified per
   engagement, not the default.
2. **Never `-sV`/`-A`/`-O` against ICS.** Version detection is the documented
   cause of PLC crashes (Nmap sending HTTP to a Modbus device).
3. **One host at a time** for protocol enumeration. No subnet sweeps of
   controllers.
4. **Slow.** `--scan-delay`, low `--max-rate`, `--max-parallelism 1`.
5. **In a window, with OT present.** Coordinate; have someone watching the
   process who can call a stop.
6. **Exclude known-fragile devices entirely.** Put safety-instrumented systems
   (SIS) and anything life-critical in an `--excludefile` and do not probe them
   under any circumstances.

---

## Quick Reference

```bash
# Passive OT inventory (safest) — see passive + snmp skills
zeek -r ot-capture.pcap && cat modbus.log dnp3.log 2>/dev/null

# Gentle active listener scan (no version detection, slow, connect scan)
sudo nmap -sT -Pn --scan-delay 1s --max-retries 1 \
  -p 502,102,44818,20000,2404 --open $SUBNET

# Enumerate ONE confirmed controller
sudo nmap -sT -Pn -p 502 --script modbus-discover $CONTROLLER
sudo nmap -sT -Pn -p 102 --script s7-info $CONTROLLER
```

---

## Common Mistakes

| Symptom | Usually means | Do this |
|---|---|---|
| A known PLC does not answer | Many controllers never reply to unsolicited probes | Expected. Go passive — this is not evidence the device is absent |
| A device stops responding mid-scan | **You may have faulted it** | STOP immediately. Notify the OT team. Do not retry or 'confirm' with another probe |
| Port 502 open but no Modbus reply | A gateway or firewall is presenting the port | Do not infer a controller from an open port |
| Passive capture shows nothing | The tap is on the wrong segment, or the poll cycle is slow | OT traffic is periodic — listen across a full cycle before concluding |

**The inference ceiling.** On OT the ceiling is a safety rule, not just an epistemic one: a scan proves **almost nothing about a controller's state**, and the cost of a wrong probe is measured in process, not data. Never infer device health, firmware, or safety state from network behaviour.

---

## When to Use Something Else

| Scenario | Better tool |
|---|---|
| The safe default for OT discovery | passive-network-discovery skill |
| Reading the switch's device tables | snmp-network-inventory skill |
| Purpose-built passive OT monitoring | Nozomi, Claroty, Dragos, Forescout |
| Deep protocol analysis | Wireshark with ICS dissectors |
| Public ICS exposure research | Shodan, Censys (never scan someone else's OT) |

---

## Ethical and Legal Notice

ICS/OT testing carries **physical-world risk** that ordinary network testing
does not: a crashed controller can stop a production line, trip a safety
system, or endanger people. Authorization for OT work must be explicit,
written, scoped to named devices, and coordinated with the operations team and
a defined maintenance window — general "network is in scope" permission does
**not** extend to probing controllers. When in doubt, stay passive. Never scan
industrial systems you do not own and are not expressly authorised, in writing,
to test. Public exposure data (Shodan, Censys) is for defending your own
assets, never for touching someone else's.

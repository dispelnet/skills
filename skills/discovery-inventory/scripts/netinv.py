#!/usr/bin/env python3
"""
netinv — normalize and merge network-discovery output into one record per host.

The discovery skills each emit their own format. netinv converts them to a
shared JSON Lines schema (one host object per line) and merges runs into a
single accumulating inventory keyed by IP.

Stdlib only — no pip install, no jq required. Runs on any Python 3.6+.

Subcommands:
  from-arp   [FILE|-]     arp-scan --plain --format='${ip},${mac},${vendor}'
  from-nmap  SCAN.xml     nmap -oX output
  merge      A.jsonl ...  union records by IP (accumulate across runs)
  table      [FILE|-]     human-readable summary of an inventory

Schema (one JSON object per line):
  ip, mac, mac_vendor, mac_type(global|local), hostnames[], state,
  os{name,accuracy}, ports[{port,proto,state,service,product,version}],
  sources[], first_seen, last_seen   (times are UTC ISO-8601)

See host-record-schema.md for the full field reference.
"""
import sys
import json
import argparse
import datetime
import xml.etree.ElementTree as ET


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc).replace(
        microsecond=0).isoformat()


def mac_is_local(mac):
    """Locally administered bit (0x02 of the first octet) → randomized/assigned.
    Second hex digit is one of 2, 6, A, E when set."""
    if not mac or ":" not in mac:
        return None
    try:
        first = int(mac.split(":")[0], 16)
    except ValueError:
        return None
    return bool(first & 0x02)


def blank_record(ip):
    return {
        "ip": ip, "mac": None, "mac_vendor": None, "mac_type": None,
        "hostnames": [], "state": None, "os": None, "ports": [],
        "sources": [], "first_seen": None, "last_seen": None,
    }


# ---------- converters ----------

def from_arp(lines):
    """Parse arp-scan --plain --format='${ip},${mac},${vendor}' lines."""
    ts = now_utc()
    out = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",", 2)
        if len(parts) < 2:
            continue
        ip, mac = parts[0].strip(), parts[1].strip().lower()
        vendor = parts[2].strip().strip('"') if len(parts) > 2 else ""
        local = mac_is_local(mac)
        rec = blank_record(ip)
        rec.update({
            "mac": mac,
            "mac_vendor": vendor or None,
            "mac_type": "local" if local else "global" if local is False else None,
            "state": "up",
            "sources": ["arp-scan"],
            "first_seen": ts, "last_seen": ts,
        })
        out.append(rec)
    return out


def _safe_parse_xml(path):
    """Parse XML with entity-expansion attacks (billion-laughs, XXE) refused.

    Stdlib ElementTree does not fetch external entities, but it will expand
    internal ones. nmap never emits a custom <!ENTITY>, so a file that
    contains one is either corrupt or hostile — refuse it rather than expand.
    Keeps this tool dependency-free (no defusedxml)."""
    data = sys.stdin.buffer.read() if path == "-" else open(path, "rb").read()
    head = data[:4096].lower()
    if b"<!entity" in head or b"<!doctype" in head and b"[" in head:
        sys.exit("netinv: refusing XML with entity/DTD subset declarations "
                 f"({path}) — possible XXE or billion-laughs payload")
    return ET.fromstring(data)


def from_nmap(path):
    """Parse nmap -oX XML into host records."""
    ts = now_utc()
    root = _safe_parse_xml(path)
    out = []
    for host in root.findall("host"):
        status = host.find("status")
        state = status.get("state") if status is not None else None

        ip = mac = mac_vendor = None
        for addr in host.findall("address"):
            t = addr.get("addrtype")
            if t in ("ipv4", "ipv6"):
                ip = addr.get("addr")
            elif t == "mac":
                mac = (addr.get("addr") or "").lower()
                mac_vendor = addr.get("vendor")
        if not ip:
            continue

        rec = blank_record(ip)
        rec["state"] = state
        rec["sources"] = ["nmap"]
        rec["first_seen"] = rec["last_seen"] = ts
        if mac:
            local = mac_is_local(mac)
            rec["mac"] = mac
            rec["mac_vendor"] = mac_vendor
            rec["mac_type"] = ("local" if local else
                               "global" if local is False else None)

        hn = host.find("hostnames")
        if hn is not None:
            rec["hostnames"] = sorted({
                h.get("name") for h in hn.findall("hostname") if h.get("name")
            })

        ports_el = host.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                st = p.find("state")
                if st is None or st.get("state") != "open":
                    continue  # inventory tracks open ports only
                svc = p.find("service")
                rec["ports"].append({
                    "port": int(p.get("portid")),
                    "proto": p.get("protocol"),
                    "state": "open",
                    "service": svc.get("name") if svc is not None else None,
                    "product": svc.get("product") if svc is not None else None,
                    "version": svc.get("version") if svc is not None else None,
                })
            rec["ports"].sort(key=lambda x: (x["proto"], x["port"]))

        best = None
        os_el = host.find("os")
        if os_el is not None:
            for m in os_el.findall("osmatch"):
                acc = int(m.get("accuracy", "0"))
                if best is None or acc > best["accuracy"]:
                    best = {"name": m.get("name"), "accuracy": acc}
        rec["os"] = best
        out.append(rec)
    return out


# ---------- merge ----------

def merge_records(records):
    """Union records by IP. Ports unioned by (proto,port); richer service wins.
    sources unioned; first_seen=min, last_seen=max."""
    by_ip = {}
    for rec in records:
        ip = rec["ip"]
        if ip not in by_ip:
            by_ip[ip] = blank_record(ip)
        _merge_into(by_ip[ip], rec)
    return list(by_ip.values())


def _merge_into(dst, src):
    for scalar in ("mac", "mac_vendor", "mac_type", "state"):
        if src.get(scalar) and not dst.get(scalar):
            dst[scalar] = src[scalar]
    # a resolved vendor beats a bare/Unknown one
    if src.get("mac_vendor") and src["mac_vendor"] not in ("", "(Unknown)"):
        dst["mac_vendor"] = src["mac_vendor"]

    dst["hostnames"] = sorted(set(dst["hostnames"]) | set(src.get("hostnames", [])))
    dst["sources"] = sorted(set(dst["sources"]) | set(src.get("sources", [])))

    if src.get("os"):
        if not dst.get("os") or src["os"]["accuracy"] > dst["os"]["accuracy"]:
            dst["os"] = src["os"]

    idx = {(p["proto"], p["port"]): p for p in dst["ports"]}
    for p in src.get("ports", []):
        key = (p["proto"], p["port"])
        if key not in idx:
            idx[key] = dict(p)
        else:
            # keep the richer service description
            for f in ("service", "product", "version"):
                if p.get(f) and not idx[key].get(f):
                    idx[key][f] = p[f]
    dst["ports"] = sorted(idx.values(), key=lambda x: (x["proto"], x["port"]))

    for a, keep in (("first_seen", min), ("last_seen", max)):
        vals = [v for v in (dst.get(a), src.get(a)) if v]
        if vals:
            dst[a] = keep(vals)


# ---------- table ----------

def render_table(records):
    rows = sorted(records, key=lambda r: _ip_key(r["ip"]))
    w_ip = max([len(r["ip"]) for r in rows] + [7])
    w_host = max([len(",".join(r["hostnames"])) for r in rows] + [8])
    w_vend = max([len((r.get("mac_vendor") or "")) for r in rows] + [6])
    hdr = f"{'IP':<{w_ip}}  {'HOSTNAME':<{w_host}}  {'VENDOR':<{w_vend}}  OPEN PORTS"
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        openp = ",".join(str(p["port"]) for p in r["ports"] if p["state"] == "open")
        host = ",".join(r["hostnames"])
        vend = r.get("mac_vendor") or ""
        print(f"{r['ip']:<{w_ip}}  {host:<{w_host}}  {vend:<{w_vend}}  {openp}")
    print(f"\n{len(rows)} hosts · sources: "
          f"{sorted(set(s for r in rows for s in r['sources']))}")


def _ip_key(ip):
    try:
        return tuple(int(o) for o in ip.split("."))
    except ValueError:
        return (999, ip)  # IPv6 or hostname sorts last


# ---------- io ----------

def read_lines(path):
    if path in (None, "-"):
        return sys.stdin.readlines()
    with open(path) as f:
        return f.readlines()


def read_jsonl(path):
    return [json.loads(l) for l in read_lines(path) if l.strip()]


def write_jsonl(records):
    for r in records:
        print(json.dumps(r, ensure_ascii=False))


def main():
    ap = argparse.ArgumentParser(description="Normalize and merge discovery output.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("from-arp").add_argument("file", nargs="?", default="-")
    sub.add_parser("from-nmap").add_argument("file")
    m = sub.add_parser("merge"); m.add_argument("files", nargs="+")
    sub.add_parser("table").add_argument("file", nargs="?", default="-")
    args = ap.parse_args()

    if args.cmd == "from-arp":
        write_jsonl(from_arp(read_lines(args.file)))
    elif args.cmd == "from-nmap":
        write_jsonl(from_nmap(args.file))
    elif args.cmd == "merge":
        recs = []
        for f in args.files:
            recs.extend(read_jsonl(f))
        write_jsonl(merge_records(recs))
    elif args.cmd == "table":
        render_table(read_jsonl(args.file))


if __name__ == "__main__":
    main()

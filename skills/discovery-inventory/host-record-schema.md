# Host Record Schema

> **Scope note — this file belongs to the `discovery-inventory` skill.**
> The queries below select hosts to feed into the next stage. Appearing in the
> inventory does not make a host an authorised target — re-confirm scope before
> probing anything this returns.

The shared format every discovery skill converts into. One JSON object per line
(JSON Lines / JSONL): streamable, appendable, greppable, and `jq`-friendly.

## Why JSONL

| Property | Why it matters here |
|---|---|
| One object per line | Append a new scan's hosts by concatenating files |
| Streamable | Pipe through `jq`, `grep`, `awk` without loading everything |
| Nestable | Ports and OS are structured — CSV cannot hold them |
| Diff-friendly | Line-oriented, so `diff` and `git` show per-host changes |

A single JSON array would have to be rewritten in full to add one host; CSV
flattens away the ports; SQLite is not shell-native. JSONL is the format that
lets an inventory *accumulate across runs*.

## Fields

```jsonc
{
  "ip":         "192.168.1.50",      // IPv4 or IPv6. Primary merge key.
  "mac":        "b8:2a:72:1e:44:90", // lowercase, colon-separated, or null
  "mac_vendor": "Dell Inc.",         // from OUI lookup, or null / "(Unknown)"
  "mac_type":   "global",            // "global" (real OUI) | "local" (randomized) | null
  "hostnames":  ["fileserver01"],    // sorted, de-duplicated
  "state":      "up",                // "up" | "down" | null
  "os":         {"name": "Linux 5.x", "accuracy": 95},  // best match, or null
  "ports": [                         // OPEN ports only
    {"port": 22, "proto": "tcp", "state": "open",
     "service": "ssh", "product": "OpenSSH", "version": "9.2p1"}
  ],
  "sources":    ["arp-scan", "nmap"],// which tools contributed, sorted
  "first_seen": "2026-08-28T15:45:09+00:00",  // UTC ISO-8601
  "last_seen":  "2026-08-28T15:45:09+00:00"
}
```

### Field notes

- **`ip`** is the merge key. A host that changes IP but keeps its MAC appears as
  two records; correlate on `mac` in post-processing if you need device
  identity across IP changes.
- **`mac_type`** is derived from the locally-administered bit (`0x02` of the
  first octet). `local` means a randomized or manually assigned address —
  see the arp-network-discovery skill. The OUI lookup is meaningless for these.
- **`ports`** holds **open** ports only. Closed and filtered ports are scan
  state, not inventory, and would bloat every record.
- **`sources`** is the provenance trail. `["arp-scan"]` alone means the host
  was seen at layer 2 but never port-scanned — a signal to scan it next.
- **`first_seen` / `last_seen`** let the inventory answer "what is new since
  last week" without a separate baseline file.

## Merge semantics

`netinv merge` unions records that share an `ip`:

| Field | Rule |
|---|---|
| `mac`, `mac_type`, `state` | First non-null wins |
| `mac_vendor` | A resolved vendor beats `(Unknown)` or empty |
| `hostnames`, `sources` | Set union, sorted |
| `os` | Highest `accuracy` wins |
| `ports` | Union by `(proto, port)`; a richer service description wins |
| `first_seen` | Minimum (earliest) |
| `last_seen` | Maximum (latest) |

Merge is **idempotent**: merging an inventory with itself, or re-merging an
already-merged file, produces the same result. That makes it safe to run on a
schedule against a growing archive.

## Querying with jq (optional)

The format is plain JSONL, so `jq` works if installed — but nothing in the
pipeline requires it.

```bash
# Hosts with SSH open
jq -c 'select(.ports[]?.port == 22)' inventory.jsonl

# Hosts seen at layer 2 but never port-scanned (scan these next)
jq -r 'select(.sources == ["arp-scan"]) | .ip' inventory.jsonl

# Randomized-MAC devices (phones/laptops), by IP
jq -r 'select(.mac_type == "local") | .ip' inventory.jsonl

# Everything running OpenSSH older than 9.x
jq -c 'select(.ports[]? | .product=="OpenSSH" and (.version|startswith("8")))' \
  inventory.jsonl

# New hosts since a timestamp
jq -c --arg t "2026-08-01T00:00:00+00:00" 'select(.first_seen > $t)' inventory.jsonl
```

## Extending the schema

Add fields; do not repurpose existing ones. A downstream consumer ignores keys
it does not know, so an SSH-audit stage can attach `"ssh": {...}` and a TLS
stage `"tls": {...}` without breaking `netinv table` or any `jq` query above.
Keep new nested objects self-contained so `netinv merge`'s first-non-null rule
does the right thing.

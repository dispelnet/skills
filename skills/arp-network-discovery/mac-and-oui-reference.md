# MAC Randomization and the OUI Database

> **Scope gate — this file belongs to the `arp-network-discovery` skill.**
> Commands here re-scan the local segment and fetch from the IEEE registries.
> **Do not run anything here until that skill's Scope Gate has been
> satisfied and the target confirmed.** If you loaded this file on its own,
> read `SKILL.md` first.

Supporting reference for the `arp-network-discovery` skill. Load this when the vendor column matters — before reporting `(Unknown)` as a finding, before diffing a baseline on a Wi-Fi network, or when refreshing the OUI database.

---

## MAC Randomization — Read Before Trusting the Vendor Column

Per-network MAC randomization is **on by default** on every current client OS:
Android 10+ (2019), iOS 14+ (2020), Windows 10+, and recent macOS. Those
devices present a synthetic, locally administered address on Wi-Fi. The OUI
lookup has nothing to resolve, so the vendor column reads `(Unknown)`.

This has two consequences that matter more than the missing vendor string:

1. **`(Unknown)` is now the expected result for phones and laptops**, not a
   sign of custom hardware or spoofing. Treating it as suspicious generates
   noise and buries real findings.
2. **Naive baseline diffing produces false "new device" alerts.** iOS 15+
   rotates its address for non-associated networks, and iOS 18 can rotate
   per-connection. A phone in a pocket walking past the building can appear
   as a new host on every scan.

### Detecting a randomized MAC

Randomized addresses always have the **locally administered bit** (`0x02` of
the first octet) set, which means the **second hex digit is `2`, `6`, `A` or
`E`**. Globally unique, vendor-assigned addresses never have it set.

```bash
# Classify every host as GLOBAL (real OUI) or LOCAL (randomized/assigned)
sudo arp-scan --localnet -x \
  | awk '$2 ~ /^[0-9a-fA-F][26aeAE]:/ {print $1, $2, "LOCAL  (randomized)"; next}
         {print $1, $2, "GLOBAL (vendor OUI)"}'

# Count the split — on a Wi-Fi network, a large LOCAL share is normal
sudo arp-scan --localnet -x \
  | awk '{ if ($2 ~ /^[0-9a-fA-F][26aeAE]:/) l++; else g++ }
         END {print "randomized:", l+0, " vendor-assigned:", g+0}'
```

> This works in POSIX `awk` — no `gawk`-only `and()`/`strtonum()` needed, so it
> runs under `mawk` and `busybox awk` on embedded hosts too.

### What this means for identification

| Address type | Vendor lookup | Stable identifier? |
|---|---|---|
| Globally unique (OUI) | Works | Yes — infrastructure, IoT, printers, servers |
| Locally administered | Meaningless | Only per-SSID, and only until the OS rotates |

**Randomized MACs are still stable *per network* on Android and iOS**, so
baselining works inside your own SSID — devices that have actually joined keep
their address. Transient neighbours are what generate the noise.

Where you need durable device identity, the MAC is the wrong key entirely.
Use DHCP lease history, 802.1X / RADIUS supplicant identity, or MDM inventory.
On the enterprise Wi-Fi side, both iOS and Android expose policy to disable
randomization for managed networks.

**Infrastructure is unaffected.** Routers, switches, printers, cameras,
servers and most IoT devices do not randomize. The vendor column remains
reliable for exactly the assets a network audit cares most about.

---

---

## Keeping the OUI Database Current

The vendor column is only as good as `ieee-oui.txt`. Distributions ship a
snapshot and rarely refresh it, so a device with a recently allocated OUI
resolves to `(Unknown)` — indistinguishable from a randomized MAC.

```bash
# Where is the database, and how old is it?
ls -l /usr/share/arp-scan/ieee-oui.txt
wc -l /usr/share/arp-scan/ieee-oui.txt

# Refresh from the IEEE registries
sudo get-oui -v
```

In arp-scan 1.10 `get-oui` pulls **all four** IEEE registries — MA-L (the
classic 24-bit OUI), MA-M, MA-S and IAB — and concatenates them into a single
file. It now needs the Perl `Text::CSV` module:

```bash
sudo apt install libtext-csv-perl -y     # Debian/Ubuntu
sudo cpanm Text::CSV                     # anywhere else
```

> `get-iab` was **removed** in 1.10, along with the `--iabfile` option. IAB
> data now lives in `ieee-oui.txt`. Older instructions that call `get-iab` or
> pass `--iabfile` will fail.

Refresh before an inventory run. Between a stale database and MAC
randomization, an unexplained `(Unknown)` has two very different causes, and
only one of them is worth investigating — updating the database eliminates
the boring one:

```bash
# After refreshing, anything still Unknown with a GLOBAL bit is genuinely
# unallocated or spoofed — that is the set worth looking at.
sudo arp-scan --localnet --plain --format='${ip},${mac},${vendor}' \
  | awk -F, '$3 ~ /Unknown|^$/ && $2 !~ /^[0-9a-fA-F][26aeAE]:/'
```

---

# Off-Link IPv6 Discovery (RFC 7707) and Extension Headers

> **Scope gate — this file belongs to the `ipv6-network-discovery` skill.**
> These techniques reach hosts beyond your own link, where a confirmed scope is easiest to overrun.
> **Do not run anything here until that skill's Scope Gate has been
> satisfied and the target confirmed.** If you loaded this file on its own,
> read `SKILL.md` first.

Supporting reference for the `ipv6-network-discovery` skill. Load this when the targets are not on your link, so multicast and NDP cannot reach them — and when a scan that should have found hosts returned nothing.

**Variables** (`$TARGET`, `$SUBNET`, `$IFACE`, …) are the ones set in the
**Set these first** block of `SKILL.md`, except where a script below defines
its own.

---

## Step 4 — Off-Link Discovery (RFC 7707 Techniques)

You cannot sweep a remote /64. You *can* probe the small set of addresses
people actually assign.

### Low-byte and pattern addresses

```bash
# Manually configured hosts cluster in the low bytes
sudo scan6 -d $PREFIX6 -P global -v

# Explicit small ranges — vary only the last 16-bit words
sudo scan6 -d $TARGET6-100
sudo scan6 -d 2001:db8:0-10:0-100::1
```

### Known interface identifiers

If you have MACs from an IPv4 ARP scan of the same organisation, derive the
matching SLAAC addresses and probe only those:

```bash
# One IID per line, e.g. a8bb:ccff:fedd:eeff
sudo scan6 -d $PREFIX6 -w known-iids.txt
```

### Virtual machine OUIs

Hypervisors assign MACs from known OUI ranges, so VM SLAAC addresses are a
tractable search space:

```bash
sudo scan6 -d $PREFIX6 --tgt-virtual-machines all
```

### Aliased prefixes — the dominant false positive

Some prefixes are **aliased**: a single device answers for *every* address in
the range, so a scan reports millions of "live hosts" that do not exist. This
is common in CDN, cloud and load-balancer allocations.

Gasser et al. (*Clusters in the Expanse: Understanding and Unbiasing IPv6
Hitlists*, ACM IMC 2018) found 1.5% of prefixes were aliased — and those
accounted for roughly **half of all target addresses** in their hitlist. Any
IPv6 discovery result that has not been de-aliased is mostly noise.

Detect it by probing addresses that should not exist:

```bash
# Pick several random addresses in the prefix. If they ALL answer,
# the prefix is aliased and every result from it is worthless.
for i in 1 2 3 4; do
  printf '2001:db8::%04x:%04x\n' $RANDOM $RANDOM
done | while read -r a; do
  ping -6 -c1 -W1 "$a" >/dev/null 2>&1 && echo "$a responded"
done
```

Four random hits out of four means alias, not discovery. Drop the prefix.

### DNS — usually the highest-yield source

For thorough DNS enumeration (AXFR, subdomain brute force, reverse zones),
use the **dns-recon** skill; the essentials:

```bash
dig AAAA target.example.com +short
dig AXFR example.com @ns1.example.com | grep AAAA     # if transfer is allowed

# Reverse DNS over ip6.arpa
dig -x $TARGET6 +short
```

### Free sources that require no probing at all

- Server logs, netflow records, and the local neighbour cache
- `ip -6 neigh` on any host you already control
- Certificate transparency logs and passive DNS for `AAAA` records
- Traceroute intermediate hops — `traceroute6 $TARGET6`
- The public **IPv6 Hitlist** service (<https://ipv6hitlist.github.io/>),
  which publishes de-aliased, responsive address lists updated continuously

For generating candidate addresses from a seed set, the published algorithms
are **Entropy/IP** and **6Gen**; Gasser et al. found entropy clustering
reduces a whole hitlist to about six distinct addressing schemes, which is
what makes targeted generation tractable at all.

---

---

## Extension Headers — A Scanning Failure Mode

IPv6 puts optional features in chained **extension headers** after the main
header. They matter to discovery for two opposite reasons.

**They cause false negatives.** Many transit networks and middleboxes drop
packets carrying extension headers outright. RFC 7872 (*Observations on the
Dropping of Packets with IPv6 Extension Headers in the Real World*) measured
substantial drop rates across the Internet, varying by header type and
markedly worse for Hop-by-Hop options. A probe that gets no answer may have
been discarded in transit rather than ignored by the target.

```bash
# Plain probe vs. one carrying a fragment header — a differing result
# means something on the path is filtering on extension headers,
# not that the host is down.
ping -6 -c3 $TARGET6
sudo scan6 -d $TARGET6 -v
```

**They cause false negatives in firewalls too.** An ACL that inspects only the
first header can be traversed by a packet that buries the transport header
behind a chain. If a target answers a header-chained probe but not a plain
one, the filtering is header-naive — a finding in its own right.

Report a silent IPv6 host as *unreachable by this method*, not as down, unless
you have confirmed reachability by a second path.

---

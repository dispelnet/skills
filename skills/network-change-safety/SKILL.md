---
name: network-change-safety
description: >
  Use this skill when the user is about to change the configuration of a live
  network device — a router, switch, firewall, or any host reached over the
  network. Triggers include: "apply this ACL", "restrict SSH to", "lock down
  management access", "change the firewall rule", "update the route", "tighten
  the inbound filter", "push this config", "apply it to the uplink", "block
  everything except", "add a prefix-list", "change the management VLAN", or any
  request to modify filtering, routing, addressing, or access control on a
  device that is currently reachable. CRITICAL: also use whenever the change
  could affect the path the operator is connected over — that includes almost
  every management-plane, ACL, firewall, routing and interface change.
---

# Network Change Safety

## Stop — Read the Hard Rules First

**Do not run a mutating command until all four rules below are satisfied.**

1. **Name the device.** State the hostname and address you are about to change
   and confirm it against the request. A device you cannot name is a device you
   must not change.
2. **Prove the permit path before you deny anything.** If the change will allow
   only some sources, log in from one of those sources *first*. An allow rule
   you have never traversed is a guess.
3. **Arm a rollback before the mutating command**, not after. The rollback must
   fire without you — a scheduled revert, not an intention.
4. **Verify from a new session** on the permitted path, then cancel the
   rollback. Never cancel it on the strength of the command having returned 0.

Missing any one? **Stop and ask.** A device you cannot reach is an outage, and
it does not matter that the config on it is correct.

Full legal statement: [Ethical and Legal Notice](#ethical-and-legal-notice).

### Set these first

```bash
DEVICE="rtr-core-01"    # the device named in the change request
MGMT="10.20.0.21"       # its management address
PERMIT="10.20.0.5"      # a source the change will still allow
MYSRC="$(who am i | sed -n 's/.*(\(.*\))/\1/p')"   # the address you arrive from
```

---

**Why these are hard rules.**

The danger in a management-plane change is not that the config is wrong. It is
that the config is *right* and you are on the wrong side of it. The command
succeeds, the rule does exactly what it says, and the device is now
unreachable — by you, and possibly by everyone.

This failure does not come from ignorance. Measured across five independent
agents applying a routine "restrict management SSH to the jump-host range"
change, **five of five severed their own access and none armed a rollback** —
while correctly predicting the lockout in the same breath. Knowing the risk
does not prevent it. The procedure does.

---

## The Ordered Procedure

The order is the whole point. Steps 1 and 2 are worthless after step 3.

### Step 0 — Confirm which device you are on

```bash
hostname; ip -br addr show scope global
```

Compare to `$DEVICE`/`$MGMT`. In a lab of five identical routers, one operator
in five applied a change to the wrong one after misreading an identifier. Do
this even when — *especially* when — you have several similar sessions open.

### Step 1 — Prove the permit path, before touching anything

Log in from the source the new rule will allow, and confirm it works:

```bash
ssh "$PERMIT" "ssh $MGMT 'hostname'"     # does the permitted source actually reach it?
```

If nothing currently lives at `$PERMIT`, or you cannot log in from it, **the
change is not ready to apply.** A permit clause pointing at a decommissioned,
mistyped, or wrong-VLAN jump host is indistinguishable from a deny-all until
the moment you need it.

### Step 2 — Arm the rollback

Pick the mechanism the platform gives you. All of them do the same thing:
undo the change if you stop being able to talk to the device.

| Platform | Armed rollback |
|---|---|
| Cisco IOS / IOS-XE | `reload in 5` — reboots to startup-config unless you `reload cancel` |
| Junos | `commit confirmed 5` — reverts unless you `commit` again |
| Arista EOS | `configure session X` + `commit timer 0:05:00` |
| Linux / iptables | `(sleep 300; iptables-restore < /tmp/pre-change.rules) &` after `iptables-save > /tmp/pre-change.rules` |
| Anything else | A scheduled job that restores the saved config, verified to be running |

```bash
# Confirm it is actually armed before proceeding — an intention is not a rollback
jobs; atq 2>/dev/null; show reload 2>/dev/null
```

### Step 3 — Apply the change

Only now. One device, one change.

### Step 4 — Verify from a NEW session on the permitted path

```bash
ssh "$PERMIT" "ssh $MGMT 'hostname'"     # a NEW connection, not your existing one
```

A new connection is the only thing that tests the rule. See the trap below.

### Step 5 — Cancel the rollback

`reload cancel` / second `commit` / `kill %1`. Only after step 4 returned the
right hostname. If step 4 failed, do nothing and let the rollback fire.

---

## The Established-Connection Trap

Every operator observed in testing added an exemption so their in-flight
session would survive the change:

```bash
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

This is good practice and it is **not** a safety measure. It keeps the TCP
session you already have; it says nothing about whether you can open a new one.
The session persists, the command returns cleanly, everything looks healthy —
and the next connection, after your laptop sleeps or the session times out, is
refused.

**"My session survived" is not "I can get back in."** Only step 4 answers that.

---

## Rationalizations — All of These Mean Stop

Each of these is a verbatim conclusion from an operator who had just locked
themselves out of a production-equivalent device.

| Rationalization | Reality |
|---|---|
| "My path is now correctly blocked — that's evidence the restriction works" | You tested the deny. You never tested the permit. Half a test. |
| "It timed out, confirming inbound access is denied" | Confirming *you* are denied is not confirming *someone* is allowed. |
| "That's expected and is itself proof the rule is working" | An outage that was predicted is still an outage. |
| "The allow rule is verified by inspection, not by a live login" | Inspection cannot detect a jump host that no longer exists. Log in or don't apply. |
| "I kept the established session alive, so I'm fine" | You are fine until the session drops. Then you are not. |
| "The change is small — one line" | One line is how every lockout is written. |
| "I'll verify after I finish the rest of the change" | After is too late; the path you would verify from is already gone. |
| "There's console access if it goes wrong" | Then use it deliberately, before the change, not as a story you tell yourself. |

---

## Red Flags — STOP and Start Over

- You are about to run a mutating command and no rollback is armed
- The permitted source has never been logged in from during this change
- You cannot state the device's hostname without scrolling up
- You are relying on an ESTABLISHED/RELATED exemption to stay in
- You are about to report success because a *deny* test passed
- You have several similar sessions open and are not sure which is which

**All of these mean: stop, arm the rollback, prove the permit path.**

---

## Common Mistakes

| Symptom | Usually means | Do this |
|---|---|---|
| Change applied, session alive, new connections refused | The established-connection trap | Roll back from the console; re-apply with step 1 done first |
| Permitted source cannot reach the device afterwards | The permit clause was never traversed | Roll back. The rule was a guess, not a change |
| You are locked out and there is no rollback | Step 2 was skipped | Console or out-of-band; if neither exists, this is now a site visit |
| Wrong device changed | Step 0 was skipped | Revert it, then re-verify identity on *both* devices before retrying |
| Rule vanished after a reboot | Applied to the running config only | Persist it — but only after step 4 passes |

**The inference ceiling.** A successful command proves the device accepted the
config. It does not prove the device is reachable, that the permitted source
can reach it, or that the change did what was intended. Reachability is
established only by connecting — from the permitted path, in a new session.

---

## When to Use Something Else

| Scenario | Better approach |
|---|---|
| The change touches an OT/ICS segment | ics-ot-discovery — different and stricter rules |
| Many devices, same change | Config management with automatic rollback (Ansible `--check`, NSO, Nornir), never a loop of live edits |
| You need to know what a device currently is | The discovery skills in this collection |
| A change window does not exist yet | Get one. This skill does not substitute for change control |

---

## Ethical and Legal Notice

Only make configuration changes to devices you own or are explicitly authorised
to administer, within an approved change window where one is required.
Management-plane changes can cause outages affecting people who did not consent
to your maintenance; a locked-out core device can take a service down until
someone physically reaches it. Authorization to *read* a device's configuration
is not authorization to *change* it.

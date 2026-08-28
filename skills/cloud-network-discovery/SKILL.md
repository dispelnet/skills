---
name: cloud-network-discovery
description: >
  Use this skill when the user wants to discover or inventory network assets in
  a cloud environment — AWS, Azure, or GCP virtual networks — using the
  provider APIs rather than packet scanning. Triggers include: "scan my VPC",
  "AWS network inventory", "list EC2 instances", "security group audit", "Azure
  VNet discovery", "NSG rules", "GCP firewall rules", "find public IPs in the
  cloud", "what's exposed to the internet", "cloud asset discovery", "0.0.0.0/0
  ingress", "prowler", "ScoutSuite", "steampipe", or any request to enumerate
  cloud instances, subnets, security groups/firewall rules, load balancers, or
  internet exposure. Also use when someone is about to port-scan a cloud
  network, where dynamic IPs and provider terms make scanning the wrong tool.
---

# Cloud Network Discovery

## Before You Run Anything

1. **Confirm the target with the user** — the domain, cloud account, or
   capture interface — and state it back before the first command.
2. If the user has not named one, **ask**. Do not infer a target from the
   local environment, the shell history, or a config file you happen to find.
3. The output is an inventory of someone's assets. Scope is the user's to
   define and not yours to widen: do not follow a discovered name, subnet, or
   linked account outside what was confirmed.

Full legal statement: [Ethical and Legal Notice](#ethical-and-legal-notice).

---

In an on-premises network you scan because there is no other source of truth.
**In the cloud the opposite holds:** the provider's control-plane API is the
authoritative inventory of every instance, subnet, security group, and public
IP. Querying it is faster, complete, and — unlike scanning — does not risk
violating the provider's acceptable-use policy or getting throttled behind
ephemeral IPs.

So this skill is **API-first**. The other discovery skills' *"When to use
something else → cloud provider APIs"* rows point here.

**The finding this skill exists to surface:** resources reachable from
`0.0.0.0/0`. A security group or firewall rule open to the whole internet is
the cloud equivalent of an unfirewalled host, and it is the single most common
serious cloud misconfiguration.

---

## Prerequisites

Read-only credentials are enough and are the right choice for discovery:

```bash
aws sts get-caller-identity                    # AWS — who am I / is auth working
az account show                                # Azure
gcloud config list                             # GCP — active project + account
```

AWS: attach the managed `SecurityAudit` or `ReadOnlyAccess` policy. Azure:
the `Reader` role. GCP: `roles/viewer`. Never use write credentials for an
inventory pass.

---

## AWS — VPC, Instances, Exposure

```bash
# The virtual networks themselves
aws ec2 describe-vpcs \
  --query 'Vpcs[].{VPC:VpcId,CIDR:CidrBlock,Default:IsDefault}' --output table

# Subnets, with which are auto-assign-public (a common exposure source)
aws ec2 describe-subnets \
  --query 'Subnets[].{Subnet:SubnetId,VPC:VpcId,CIDR:CidrBlock,AZ:AvailabilityZone,PublicIP:MapPublicIpOnLaunch}' \
  --output table

# Instances: private + PUBLIC IP, state, and the SGs attached
aws ec2 describe-instances \
  --query 'Reservations[].Instances[].{ID:InstanceId,State:State.Name,Private:PrivateIpAddress,Public:PublicIpAddress,SG:SecurityGroups[].GroupId}' \
  --output table

# Every instance that has a public IP — the internet-facing set
aws ec2 describe-instances \
  --filters Name=instance-state-name,Values=running \
  --query 'Reservations[].Instances[?PublicIpAddress!=`null`].{ID:InstanceId,Public:PublicIpAddress}' \
  --output text
```

### The exposure query — security groups open to the world

```bash
# Security-group rules allowing 0.0.0.0/0 ingress, with the ports
aws ec2 describe-security-groups \
  --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].{Group:GroupId,Name:GroupName}' \
  --output table

# Sharper: list the exact world-open port ranges per group
aws ec2 describe-security-groups --query \
  'SecurityGroups[].{Group:GroupId,Open:IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]].[FromPort,ToPort,IpProtocol]}' \
  --output json
```

Also worth pulling: `describe-network-interfaces` (ENIs, incl. those on
Lambda/RDS), `describe-vpc-peering-connections` and `describe-route-tables`
(lateral reachability), `describe-nat-gateways`, and
`elbv2 describe-load-balancers` (internet-facing LBs).

> Run these **per region** — VPCs are regional. Loop `--region` over
> `aws ec2 describe-regions --query 'Regions[].RegionName' --output text`.

---

## Azure — VNet, NSG, Exposure

```bash
# Virtual networks and their address space
az network vnet list \
  --query '[].{Name:name,RG:resourceGroup,CIDR:addressSpace.addressPrefixes[0]}' -o table

# Subnets in a VNet
az network vnet subnet list --resource-group RG --vnet-name VNET \
  --query '[].{Name:name,CIDR:addressPrefix,NSG:networkSecurityGroup.id}' -o table

# VMs with their private and public IPs
az vm list-ip-addresses \
  --query '[].{VM:virtualMachine.name,Private:virtualMachine.network.privateIpAddresses[0],Public:virtualMachine.network.publicIpAddresses[0].ipAddress}' -o table

# Public IPs allocated in the subscription
az network public-ip list \
  --query '[].{Name:name,IP:ipAddress,Assigned:ipConfiguration.id}' -o table
```

### The exposure query — NSG rules open to the internet

```bash
# NSG rules allowing inbound from Internet / * / 0.0.0.0/0
az network nsg list --query \
  "[].{NSG:name,Rules:securityRules[?access=='Allow' && direction=='Inbound' && (sourceAddressPrefix=='*' || sourceAddressPrefix=='Internet' || sourceAddressPrefix=='0.0.0.0/0')].{Port:destinationPortRange,Proto:protocol}}" \
  -o json
```

---

## GCP — VPC, Instances, Exposure

```bash
# VPC networks (GCP VPCs are GLOBAL; subnets are regional)
gcloud compute networks list \
  --format='table(name,x_gcloud_subnet_mode,x_gcloud_bgp_routing_mode)'

# Subnets across all regions, with their ranges
gcloud compute networks subnets list \
  --format='table(name,region,network,ipCidrRange)'

# Instances with internal + EXTERNAL IP
gcloud compute instances list \
  --format='table(name,zone,networkInterfaces[0].networkIP,networkInterfaces[0].accessConfigs[0].natIP,status)'

# Reserved/external addresses
gcloud compute addresses list --format='table(name,address,region,status)'
```

### The exposure query — firewall rules open to the world

```bash
# Ingress-allow rules sourced from 0.0.0.0/0, with ports
gcloud compute firewall-rules list \
  --filter='direction=INGRESS AND sourceRanges:0.0.0.0/0' \
  --format='table(name,network,sourceRanges.list(),allowed[].map().firewall_rule().list())'
```

---

## Multi-Cloud: Do It All at Once

For anything beyond a quick look, a purpose-built auditor beats hand-rolled
queries — it enumerates every service and flags exposure across providers.

```bash
# Prowler — AWS/Azure/GCP/K8s, hundreds of checks incl. exposure & compliance
prowler aws                              # full assessment
prowler aws --services ec2 vpc --severity high
prowler azure ; prowler gcp

# ScoutSuite — multi-cloud, produces an HTML report (note: less actively
# maintained; verify currency before relying on it)
scout aws ; scout azure ; scout gcp

# Steampipe — query cloud APIs with SQL; ideal for custom exposure questions
steampipe query "select instance_id, public_ip_address from aws_ec2_instance where public_ip_address is not null"
```

- **Prowler** — the broadest and most current check coverage; start here.
- **Steampipe** — when you have a specific question ("every public instance
  whose SG allows 22 from 0.0.0.0/0") that no canned check answers.
- **ScoutSuite** — good single-report visual overview; confirm it is current.

---

## What Counts as a Finding

| Observation | Why it matters |
|---|---|
| SG/NSG/firewall rule from `0.0.0.0/0` | Internet-facing exposure — the headline finding |
| Management port (22/3389/5985) open to the world | Direct remote-access exposure — cross-ref rdp-vnc / remote-access skills |
| Database port (3306/5432/1433/27017) world-open | Data exposure, frequently unauthenticated |
| Instance with a public IP that need not have one | Unnecessary attack surface |
| Default VPC/VNet still in use | Often over-permissive out of the box |
| Overly broad VPC peering / routes | Lateral movement between environments |
| Public storage (S3/Blob/GCS) | Not network, but pull it in the same pass |

> Discovery is authoritative here, but **do not then port-scan the public IPs
> you find from outside** without confirming that fits provider terms and
> scope — the API already told you what is open; scanning adds risk for little.

---

## Feed the Pipeline

Cloud public IPs can flow into the same inventory as everything else:

```bash
# AWS public IPs -> host records for discovery-inventory
aws ec2 describe-instances --query \
  'Reservations[].Instances[?PublicIpAddress!=`null`].PublicIpAddress' --output text \
  | tr '\t' '\n' | while read -r ip; do
      printf '{"ip":"%s","state":"up","sources":["aws-api"]}\n' "$ip"
    done > cloud-hosts.jsonl
# merge with netinv (see discovery-inventory skill)
```

---

## Quick Reference

```bash
# AWS: instances with public IPs + world-open security groups
aws ec2 describe-instances --query 'Reservations[].Instances[?PublicIpAddress!=`null`].[InstanceId,PublicIpAddress]' --output text
aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].GroupId' --output text

# Azure: public IPs + internet-open NSG rules
az network public-ip list --query '[].ipAddress' -o tsv

# GCP: external IPs + world-open firewall rules
gcloud compute instances list --format='value(name,networkInterfaces[0].accessConfigs[0].natIP)'
gcloud compute firewall-rules list --filter='sourceRanges:0.0.0.0/0' --format='value(name)'

# Everything, audited: prowler <aws|azure|gcp>
```

---

## Common Mistakes

| Symptom | Usually means | Do this |
|---|---|---|
| Empty list of instances or VPCs | Wrong region, project or subscription — or the credential cannot read | Verify identity first, then enumerate every region, not just the default |
| A security group shows `0.0.0.0/0` | Reachability also depends on NACLs, route tables and whether anything is attached | Confirm the resource is actually reachable before calling it internet-facing |
| Fewer resources than the console shows | The credential is scoped, or pagination truncated the result | Check for a pagination token before treating the list as complete |
| Public IP present but service unreachable | Host firewall or the instance is stopped | The control plane describes configuration, not liveness |

**The inference ceiling.** The provider API proves **what the configuration says**. It does not prove reachability, and a permissive rule is a finding only once you confirm something is behind it.

---

## When to Use Something Else

| Scenario | Better tool |
|---|---|
| On-prem / non-cloud networks | arp / nmap / passive discovery skills |
| Deep multi-service posture + compliance | Prowler, Steampipe |
| Attack-path / exposure graphing | CloudMapper, Cartography |
| Runtime/agent-based inventory | provider-native (AWS Config, Azure Resource Graph, GCP Asset Inventory) |
| Credential/permission enumeration | Pacu (AWS), ROADtools (Azure AD) |

---

## Ethical and Legal Notice

Querying cloud APIs with your own read-only credentials for accounts you
control or are authorised to assess is routine and low-risk. But cloud scope
has sharp edges: **do not** enumerate accounts, subscriptions, or projects you
were not explicitly authorised to touch, and **do not** actively scan cloud IPs
from outside — even ones you discovered — without confirming it complies with
the provider's acceptable-use policy and your engagement scope (AWS, for one,
requires that testing stay within your own resources). The API gives you the
answer without that risk; prefer it. Use read-only credentials, and treat the
resulting inventory as sensitive.

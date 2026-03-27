# Network Discovery Skills

A collection of network discovery and security enumeration skills that teach AI coding agents to perform reconnaissance using standard Linux tools.

## Install

Install the skills CLI:

```bash
curl -fsSL https://skills.sh | sh
```

### Add all skills

```bash
npx skills add https://github.com/dispelnet/skills
```

### Add a single skill

```bash
npx skills add https://github.com/dispelnet/skills --skill remote-access-discovery
```

## Skills

| Skill | Description |
| --- | --- |
| [arp-network-discovery](skills/arp-network-discovery) | Local subnet host discovery using ARP — find all live devices, MAC addresses, and vendors on your LAN |
| [nmap-network-discovery](skills/nmap-network-discovery) | Comprehensive network scanning — host discovery, port scanning, service/version detection, and OS fingerprinting |
| [remote-access-discovery](skills/remote-access-discovery) | SSH and Telnet enumeration — banner grabbing, weak cipher detection, authentication method analysis |

These skills form a natural discovery pipeline: **ARP scan** (find hosts) → **Nmap** (enumerate ports/services) → **Remote access audit** (deep-dive SSH/Telnet).

## License

This repository is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

These skills are provided for demonstration and educational purposes. Always ensure you have proper authorization before performing network discovery on any network.

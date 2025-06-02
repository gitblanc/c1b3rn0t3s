---
title: SNMP 🍍
tags:
  - Protocol
---
>[!Note]
>*It typically runs on port `161` or `162`.*

# HTB Cheatsheet

| **Command**                                       | **Description**                                     |
| ------------------------------------------------- | --------------------------------------------------- |
| `snmpwalk -v2c -c <community string> <FQDN/IP>`   | Querying OIDs using snmpwalk.                       |
| `onesixtyone -c community-strings.list <FQDN/IP>` | Bruteforcing community strings of the SNMP service. |
| `braa <community string>@<FQDN/IP>:.1.*`          | Bruteforcing SNMP service OIDs.                     |

## Useful wordlists (community strings)

- Check inside `/usr/share/seclists/Discovery/SNMP/`.

You should check [Footprinting Theory 🌚](/notes/Info/HTB%20Academy/footprinting_theory.md) to get further knowledge.
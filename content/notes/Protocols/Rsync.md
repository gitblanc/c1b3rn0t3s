---
title: Rsync 🐄
tags:
  - Protocol
---
>[!Note]
>*It typically runs on port `873` over UDP.*

## Nmap Scan

```shell
sudo nmap -sV -p 873 127.0.0.1
```

# HTB Cheatsheet

| **Command**                                   | **Description**                 |
| --------------------------------------------- | ------------------------------- |
| `nc -nv 127.0.0.1 873`                        | Probing for accessible shares.  |
| `rsync -av --list-only rsync://127.0.0.1/dev` | Enumerating an open share.      |
| `braa <community string>@<FQDN/IP>:.1.*`      | Bruteforcing SNMP service OIDs. |

> You should check [Footprinting Theory 🌚](/notes/Info/HTB%20Academy/footprinting_theory.md) to get further knowledge.
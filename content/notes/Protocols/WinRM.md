---
title: WinRM 🐓
tags:
  - Protocol
---
>[!Note]
>*It typically runs on ports `5985` (over HTTP) and `5986` (over HTTPS).*

## Nmap scan

```shell
nmap -sV -sC 10.129.201.248 -p5985,5986 --disable-arp-ping -n
```

| **Command**                                            | **Description**                                                                                         |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| `evil-winrm -i 10.129.201.248 -u USERNAME -p PASSWORD` | Interact with WinRM.                                                                                    |

> You should check [Footprinting Theory 🌚](/notes/Info/HTB%20Academy/footprinting_theory.md) to get further knowledge.
---
title: RDP 📺
tags:
  - Protocol
---
>[!Note]
>*It typically runs on port `3389`.*

## Nmap scan

```shell
nmap -sV -sC 10.129.201.248 -p3389 --script rdp*
# Use --packet-trace to identify EDRs
nmap -sV -sC 10.129.201.248 -p3389 --packet-trace --disable-arp-ping -n
```

# HTB Cheatsheet

| **Command**                                                                                                          | **Description**                                                                      |
| -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `./rdp-sec-check.pl 10.129.201.248`                                                                                  | RDP Security Check. [Github link](https://github.com/CiscoCXSecurity/rdp-sec-check). |
| `xfreerdp /u:USERNAME /p:"PASSWORD" /v:10.129.201.248`                                                               | Initiate RDP session.                                                                |
| `sqlplus <user>/<pass>@<FQDN/IP>/<db>`                                                                               | Log in to the Oracle database.                                                       |
| `./odat.py utlfile -s <FQDN/IP> -d <db> -U <user> -P <pass> --sysdba --putFile C:\\insert\\path file.txt ./file.txt` | Upload a file to a web server (to test for reverse shells).                          |

> You should check [Footprinting Theory 🌚](/notes/Info/HTB%20Academy/footprinting_theory.md) to get further knowledge.

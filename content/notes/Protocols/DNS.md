---
title: DNS 🐍
tags:
  - Protocol
---
# HTB Cheatsheet

| **Command**                                                                                                                                                                                                                        | **Description**                                           |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| `dig ns DOMAIN @NAMESERVER`                                                                                                                                                                                                        | NS request to the specific nameserver.                    |
| `dig any DOMAIN @NAMESERVER`                                                                                                                                                                                                       | ANY request to the specific nameserver.                   |
| `dig axfr DOMAIN @NAMESERVER`                                                                                                                                                                                                      | AXFR request to the specific nameserver (Zone transfers). |
| `for sub in $(cat /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 \| grep -v ';\|SOA' \| sed -r '/^\s*$/d' \| grep $sub \| tee -a subdomains.txt;done` | Manual subdomain brute forcing.                           |
| `dnsenum --dnsserver NAMESERVER --enum -p 0 -s 0 -o found_subdomains.txt -f /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt DOMAIN`                                                                  | Subdomain brute forcing.                                  |

> You should check [Footprinting Theory 🌚](/notes/Info/HTB%20Academy/footprinting_theory.md) to get further knowledge.
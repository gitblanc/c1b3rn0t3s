---
title: FTP 🐐
tags:
  - Protocol
---
>[!Note]
>*It typically runs on port `21`.*

# HTB Cheatsheet (basic commands)

| **Command**                                                                                                                                                                                                | **Description**                                                         |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `ftp <FQDN/IP>`                                                                                                                                                                                            | Interact with the FTP service on the target.                            |
| `nc -nv <FQDN/IP> 21`                                                                                                                                                                                      | Interact with the FTP service on the target.                            |
| `telnet <FQDN/IP> 21`                                                                                                                                                                                      | Interact with the FTP service on the target.                            |
| `openssl s_client -connect <FQDN/IP>:21 -starttls ftp`                                                                                                                                                     | Interact with the FTP service on the target using encrypted connection. |
| `wget -m --no-passive ftp://anonymous:anonymous@<target>`                                                                                                                                                  | Download all available files on the target FTP server.                  |
| `ls -R`                                                                                                                                                                                                    | List all content recursively.                                           |
| `get whatever.example`                                                                                                                                                                                     | Download a file.                                                        |

- You should check [Footprinting Theory 🌚](/notes/Info/HTB%20Academy/footprinting_theory.md) to get further knowledge.
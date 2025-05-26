---
title: SMB/CIFS 🐿
tags:
  - Protocol
---
> [!Note]
> *It typically runs on ports `137`, `138`, `139` (SMB) or `445` (CIFS).*

To check for SAMBA version run this Nmap scan:

```shell
nmap -sCV -T4 10.129.199.212 -p139,445

[redacted]
139/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 4
445/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 4
```

# HTB Cheatsheet (Basic Commands)

| **Command**                                       | **Description**                                                              |
| ------------------------------------------------- | ---------------------------------------------------------------------------- |
| `smbclient -N -L //<FQDN/IP>`                     | Null session authentication on SMB.                                          |
| `smbclient //<FQDN/IP>/<share>`                   | Connect to a specific SMB share.                                             |
| `rpcclient -U "" <FQDN/IP>`                       | Interaction with the target using RPC.                                       |
| `samrdump.py <FQDN/IP>`                           | Username enumeration using Impacket scripts.                                 |
| `smbmap -H <FQDN/IP>`                             | Enumerating SMB shares.                                                      |
| `crackmapexec smb <FQDN/IP> --shares -u '' -p ''` | Enumerating SMB shares using null session authentication.                    |
| `enum4linux-ng.py <FQDN/IP> -A`                   | SMB enumeration using enum4linux.                                            |
| `get filename`                                    | Download a file.                                                             |
| `!<command>`                                      | Execute a command (in your machine) without leaving the current SMB session. |

## RPCClient Enumeration

| **Query**                                                                                                                                                                                                  | **Description**                                                    |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `srvinfo`                                                                                                                                                                                                  | Server information.                                                |
| `enumdomains`                                                                                                                                                                                              | Enumerate all domains that are deployed in the network.            |
| `querydominfo`                                                                                                                                                                                             | Provides domain, server, and user information of deployed domains. |
| `netshareenumall`                                                                                                                                                                                          | Enumerates all available shares.                                   |
| `netsharegetinfo <share>`                                                                                                                                                                                  | Provides information about a specific share.                       |
| `enumdomusers`                                                                                                                                                                                             | Enumerates all domain users.                                       |
| `queryuser <RID>`                                                                                                                                                                                          | Provides information about a specific user.                        |
| `for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" \| grep "User Name\|user_rid\|group_rid" && echo "";done`                                               | Brute force user RIDs                                              |
| Python script from [Impacket](https://github.com/SecureAuthCorp/impacket) called [samrdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/samrdump.py) -> `samrdump.py 10.129.14.128` | Alternative to bruteforce user RIDs.                               |

## SMBmap

> *[SMBmap](https://github.com/ShawnDEvans/smbmap)*

| **Command**               | **Description** |
| ------------------------- | --------------- |
| `smbmap -H 10.129.14.128` | Basic command.  |

## CrackMapExec

> *[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)*

| **Command**                                           | **Description** |
| ----------------------------------------------------- | --------------- |
| `crackmapexec smb 10.129.14.128 --shares -u '' -p ''` | Basic command.  |

## Enum4Linux-ng

>*[Enum4Linux-ng](https://github.com/cddmp/enum4linux-ng)*

| **Command**                           | **Description** |
| ------------------------------------- | --------------- |
| `./enum4linux-ng.py 10.129.14.128 -A` | Basic command.  |

- You should check [Footprinting Theory 🌚](/notes/Info/HTB%20Academy/footprinting_theory.md) to get further knowledge.
- You must see the contents of [SAMBA shares 🗂️](/notes/samba.md)

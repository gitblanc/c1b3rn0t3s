---
title: SMTP 🐅
tags:
  - Protocol
---
>[!Note]
>*It typically runs on port `25` (not encrypted), `587` (in newer versions) and other port like `465` for encrypted communications.*

# HTB Cheatsheet

| **Command**                                                                                                        | **Description**                                                   |
| ------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------- |
| `telnet <FQDN/IP> 25`                                                                                              | Connect to the service.                                           |
| `smtp-user-enum -M VRFY -w 15 -U /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -t IP_ADDRESS -v` | Brute force users. Alter the time (`-w`) to get better responses. |

## SMTP Commands

|**Command**|**Description**|
|---|---|
|`AUTH PLAIN`|AUTH is a service extension used to authenticate the client.|
|`HELO`|The client logs in with its computer name and thus starts the session.|
|`MAIL FROM`|The client names the email sender.|
|`RCPT TO`|The client names the email recipient.|
|`DATA`|The client initiates the transmission of the email.|
|`RSET`|The client aborts the initiated transmission but keeps the connection between client and server.|
|`VRFY`|The client checks if a mailbox is available for message transfer.|
|`EXPN`|The client also checks if a mailbox is available for messaging with this command.|
|`NOOP`|The client requests a response from the server to prevent disconnection due to time-out.|
|`QUIT`|The client terminates the session.|

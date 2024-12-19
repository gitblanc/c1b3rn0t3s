---
title: Cap
tags:
  - HackTheBox
  - Easy
  - Linux
  - IDOR
date: 2024-08-30T00:00:00Z
---
![](Pasted%20image%2020241030093859.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.10.245 cap.htb" | sudo tee -a /etc/hosts
```

Then I performed a Nmap scan:

```shell
nmap -sC -T4 -p- cap.htb > sC.txt

[redacted]
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http
|_http-title: Security Dashboard
```

So I checked the website:

![](Pasted%20image%2020241030094147.png)

Seems to be some kind of security dashboard. After inspecting the source code, I found the `/capture` subdirectory which allows to download a `.pcap`:

![](Pasted%20image%2020241030094954.png)

Once downloaded, I opened it with Wireshark. Unfortunately, this pcap hadn't anything interesting.

## Exploitation

Going back to check the website again, I tested for **IDOR** (Insecure Direct Object Reference) in the url, because the capture creation relays under `/data/<ID>`, so I tested it changing manually the id:

![](Pasted%20image%2020241030095410.png)

This worked and gave me a new capture to download.

Following along the TCP stream I noticed that there were FTP credentials in plain text:

![](Pasted%20image%2020241030095704.png)

> FTP Creds: `nathan:Buck3tH4TF0RM3!`

So I logged in the FTP service and saw the user.txt, but got no permissions. So I tried tris credentials via ssh, which also worked:

![](Pasted%20image%2020241030100147.png)

## Privilege escalation

I uploaded `linpeas` to the machine:

![](Pasted%20image%2020241030100854.png)

So I checked [GTFObins](https://gtfobins.github.io/gtfobins/python/#capabilities):

> [!Info]
> If the binary has the Linux `CAP_SETUID` capability set or it is executed by another binary with the capability set, it can be used as a backdoor to maintain privileged access by manipulating its own process UID.

```shell
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

> Got the root flag :)

![](Pasted%20image%2020241030101440.png)

==Machine pwned!==
---
title: Keeper
tags:
  - HackTheBox
  - Easy
  - Linux
date: 2025-02-17T00:00:00Z
---
![](Pasted%20image%2020250217174935.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.227 keeper.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- keeper.htb > sC.txt

[redacted]
PORT   STATE SERVICE
```
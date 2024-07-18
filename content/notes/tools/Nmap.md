---
title: Nmap 👁️‍🗨️
tags:
  - Tool
---
## Standard scan

```shell
nmap -sC -T4 -p- HOST > sC.txt
```

## ICMP

- The machine does not respond to ping:

```shell
nmap -sV -PS -sC -T4 -p- HOST > scan.txt 
```
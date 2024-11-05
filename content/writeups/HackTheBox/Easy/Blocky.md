---
title: Blocky
tags:
  - HackTheBox
  - Easy
  - Linux
  - jar
  - Wordpress
  - Sudo-Vulnerability
---
![](Pasted%20image%2020241031204018.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.10.37 blocky.htb" | sudo tee -a /etc/hosts
```

Then I performed an Nmap scan:

```shell
nmap -sC -T4 -p- blocky.htb > sC.txt

[redacted]
PORT      STATE  SERVICE
21/tcp    open   ftp
22/tcp    open   ssh
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
80/tcp    open   http
|_http-generator: WordPress 4.8
|_http-title: BlockyCraft &#8211; Under Construction!
8192/tcp  closed sophos
25565/tcp open   minecraft
```

Seems to be something related to Minecraft :)

So I decided to check the website:

![](Pasted%20image%2020241031204840.png)

The website seems to be running Wordpress, so I decided to run **wpscan**:

```shell
wpscan --url http://blocky.htb

[redacted]
Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://blocky.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://blocky.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://blocky.htb/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://blocky.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.8 identified (Insecure, released on 2017-06-08).
 | Found By: Rss Generator (Passive Detection)
 |  - http://blocky.htb/index.php/feed/, <generator>https://wordpress.org/?v=4.8</generator>
 |  - http://blocky.htb/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.8</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://blocky.htb/wp-content/themes/twentyseventeen/
 | Last Updated: 2024-07-16T00:00:00.000Z
 | Readme: http://blocky.htb/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 3.7
 | Style URL: http://blocky.htb/wp-content/themes/twentyseventeen/style.css?ver=4.8
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blocky.htb/wp-content/themes/twentyseventeen/style.css?ver=4.8, Match: 'Version: 1.3'
```

Inspecting the website I found a user called "**notch**":

![](Pasted%20image%2020241031210900.png)

"`WordPress version 4.8 identified (Insecure, released on 2017-06-08)`", so I searched for an exploit for that version, but without success.

So I decided to use [dirsearch 📁](/notes/tools/dirsearch.md) to enumerate further:

```shell
dirsearch -e * -u http://blocky.htb -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt

[redacted]
[20:55:26] 301 -  307B  - /wiki  ->  http://blocky.htb/wiki/                
[20:55:27] 301 -  313B  - /wp-content  ->  http://blocky.htb/wp-content/    
[20:55:28] 301 -  310B  - /plugins  ->  http://blocky.htb/plugins/
```

I decided to check the `/plugins` directory (which is not the same as the Wordpress plugins directory):

![](Pasted%20image%2020241031210037.png)

Two `.jar` files were found. 

## Exploitation

So I downloaded and inspected BlockyCore.jar with **jadx-gui**:

![](Pasted%20image%2020241031210644.png)

> So we've got mysql database credentials!: `root:8YsqfCTnvxAUeduzjNSXe22`

I decided to try that password with the previously found username "notch".

> It worked, so I found user flag!

![](Pasted%20image%2020241031211051.png)

## Privilege escalation

If we run `id` we can see that the user is part of the `sudo` group, so we can become root easily with his password and get root flag:

![](Pasted%20image%2020241031211657.png)

==Machine pwned!==







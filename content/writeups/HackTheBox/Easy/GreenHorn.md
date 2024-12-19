---
title: GreenHorn
tags:
  - Linux
  - Gitea
  - Image-altering
  - pluck
  - HackTheBox
  - Easy
date: 2024-06-31T00:00:00Z
---
![](Pasted%20image%2020240831134445.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.25 greenhorn.htb" | sudo tee -a /etc/hosts
```

Then, I performed an Nmap scan:

```shell
nmap -sC -T4 -p- greenhorn.htb > sC.txt

[redacted]
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-31 13:49 CEST
Nmap scan report for greenhorn.htb (10.10.11.25)
Host is up (0.052s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   256 57:d6:92:8a:72:44:84:17:29:eb:5c:c9:63:6a:fe:fd (ECDSA)
|_  256 40:ea:17:b1:b6:c5:3f:42:56:67:4a:3c:ee:75:23:2f (ED25519)
80/tcp   open  http
| http-robots.txt: 2 disallowed entries 
|_/data/ /docs/
| http-title: Welcome to GreenHorn ! - GreenHorn
|_Requested resource was http://greenhorn.htb/?file=welcome-to-greenhorn
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-generator: pluck 4.7.18
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 16.94 seconds
```

Once here, I wanted to know what was running behind port 3000, so I performed a second Nmap scan:

```shell
nmap -sV -T4 -p3000 greenhorn.htb > 3000.txt

[redacted]
PORT     STATE SERVICE VERSION
3000/tcp open  ppp?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.94SVN%I=7%D=8/31%Time=66D30413%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(GetRequest,2A60,"HTTP/1\.0\x20200\x20OK\r\nCache-Contr
SF:ol:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nCo
SF:ntent-Type:\x20text/html;\x20charset=utf-8\r\nSet-Cookie:\x20i_like_git
SF:ea=03590820c397ed70;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Coo
SF:kie:\x20_csrf=4zHg6DP56G3gshFrNeJnU_59YzE6MTcyNTEwNTE3MjQ3NzU1NjE0MQ;\x
SF:20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Opt
SF:ions:\x20SAMEORIGIN\r\nDate:\x20Sat,\x2031\x20Aug\x202024\x2011:52:52\x
SF:20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"the
SF:me-auto\">\n<head>\n\t<meta\x20name=\"viewport\"\x20content=\"width=dev
SF:ice-width,\x20initial-scale=1\">\n\t<title>GreenHorn</title>\n\t<link\x
SF:20rel=\"manifest\"\x20href=\"data:application/json;base64,eyJuYW1lIjoiR
SF:3JlZW5Ib3JuIiwic2hvcnRfbmFtZSI6IkdyZWVuSG9ybiIsInN0YXJ0X3VybCI6Imh0dHA6
SF:Ly9ncmVlbmhvcm4uaHRiOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9ncmVlbmh
SF:vcm4uaHRiOjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLC
SF:JzaXplcyI6IjUxMng1MTIifSx7InNyYyI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvY
SF:X")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(HTTPOptions,197,"HTTP/1\.0\x20405\x20Method\x20Not\x20All
SF:owed\r\nAllow:\x20HEAD\r\nAllow:\x20GET\r\nCache-Control:\x20max-age=0,
SF:\x20private,\x20must-revalidate,\x20no-transform\r\nSet-Cookie:\x20i_li
SF:ke_gitea=52cab2608e5c1e43;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nS
SF:et-Cookie:\x20_csrf=RFSsje4aI_Ju3Mo11zKJxHEhGTc6MTcyNTEwNTE3NzgyMzY2MjY
SF:3Mg;\x20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Fra
SF:me-Options:\x20SAMEORIGIN\r\nDate:\x20Sat,\x2031\x20Aug\x202024\x2011:5
SF:2:57\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,67,"HTTP/1\
SF:.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=
SF:utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request");
```

I decided to take a look at the website at port 80:

![](Pasted%20image%2020240831135058.png)

I didn't find anything interesting, so I decided to take a look at port 3000:

![](Pasted%20image%2020240831140733.png)

Gitea was found!, so I created a user inside:

![](Pasted%20image%2020240831140823.png)

Once in, I looked up for the GreenHorn source code:

![](Pasted%20image%2020240831141300.png)

![](Pasted%20image%2020240831141316.png)

I discovered a `login.php` file, which had the following:

![](Pasted%20image%2020240831141844.png)

So I took a look at that specific file, which had the passwd stored in sha512:

![](Pasted%20image%2020240831141935.png)

I took a look at [https://crackstation.net/](https://crackstation.net/) and this was the output:

![](Pasted%20image%2020240831142043.png)

So now, I can login into `login.php`:

![](Pasted%20image%2020240831142244.png)

We're in:

![](Pasted%20image%2020240831142914.png)

So it's time to get a reverse shell.

## Weaponization

Found this RCE script: [https://www.exploit-db.com/exploits/51592](https://www.exploit-db.com/exploits/51592)

## Exploitation

Go to `options` >> `manage modules` >> `Install a module`:

![](Pasted%20image%2020240831145228.png)

Then upload a `.zip` file containing a php reverse shell:
1. Create a `.php` reverse shell
2. Zip it: `zip result.zip shell.php`
3. Start a netcat listener: `nc -lvnp PORT`
4. Upload it:

![](Pasted%20image%2020240831145826.png)

> We've got a shell :D

![](Pasted%20image%2020240831145854.png)

Stabilise it with:

```shell
python3 -c "import pty; pty.spawn('/bin/bash')"
# then
export TERM=xterm
# Press -> Ctrl + Z
stty raw -echo; fg
```

> Sadly we've got no read permissions onto `user.txt` flag:

![](Pasted%20image%2020240831150110.png)

>After some time searching, I managed to use the pluck password with the junior account (*kinda noobie btw xd*)

> Got the user flag!:

![](Pasted%20image%2020240831150958.png)

## Privilege Escalation

I downloaded onto my machine the **'Using OpenVAS.pdf'**

![](Pasted%20image%2020240831151715.png)

Now, we can try to eliminate the pixels in the password using `pdfimage`:
- Install with `apt-get install poppler-utils`

```shell
pdfimages Using\ OpenVAS.pdf greenhornhtb
```

We get this result:

![](Pasted%20image%2020240831152138.png)

Now we can use a tool called [Depix](https://github.com/spipm/Depix) to eliminate those pixels on the image:

```shell
python3 depix.py -p ../greenhornhtb-000.ppm -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png -o ../result.png
```

We get this ouput:

![](result.png)

So let's try this password for the user root:

`root:sidefromsidetheothersidesidefromsidetheotherside`

![](Pasted%20image%2020240831152902.png)

> We got the root flag :D

==Machine pwned!==
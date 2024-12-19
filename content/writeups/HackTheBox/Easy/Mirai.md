---
title: Mirai
tags:
  - HackTheBox
  - Easy
  - Linux
  - Pi-Hole
  - Forensics
date: 2024-09-18T00:00:00Z
---
![](Pasted%20image%2020241118155004.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.10.48 mirai.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- mirai.htb > sC.txt

[redacted]
PORT      STATE SERVICE
22/tcp    open  ssh
| ssh-hostkey: 
|   1024 aa:ef:5c:e0:8e:86:97:82:47:ff:4a:e5:40:18:90:c5 (DSA)
|   2048 e8:c1:9d:c5:43:ab:fe:61:23:3b:d7:e4:af:9b:74:18 (RSA)
|   256 b6:a0:78:38:d0:c8:10:94:8b:44:b2:ea:a0:17:42:2b (ECDSA)
|_  256 4d:68:40:f7:20:c4:e5:52:80:7a:44:38:b8:a2:a7:52 (ED25519)
53/tcp    open  domain
| dns-nsid: 
|_  bind.version: dnsmasq-2.76
80/tcp    open  http
|_http-title: Website Blocked
1932/tcp  open  ctt-broker
32400/tcp open  plex
| ssl-cert: Subject: commonName=*.78063b2b367a4a389895262d75b0b03c.plex.direct/organizationName=Plex, Inc./stateOrProvinceName=CA/countryName=US
| Subject Alternative Name: DNS:*.78063b2b367a4a389895262d75b0b03c.plex.direct
| Not valid before: 2017-08-10T00:00:00
|_Not valid after:  2018-08-10T12:00:00
|_ssl-date: TLS randomness does not represent time
32469/tcp open  unknown
```

So I took a look at port 32400 and found a service called `Plex`:

![](Pasted%20image%2020241118155750.png)

Once here I used [dirsearch 📁](dirsearch.md) to perform some enumeration:

```shell
dirsearch -u http://mirai.htb:32400 -w ~/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -r

[redacted]
...
```

I discovered the Plex version currently in use: 1.7.5.4035-313f93718 (checking inside `identity`). Unfortunately, it was a rabbit hole :/

After this, I took a look at the website at port 80 but I'm been blocked:

![](Pasted%20image%2020241118155655.png)

So it seems to be using [PiHole](https://pi-hole.net/):

```shell
curl -I http://mirai.htb
HTTP/1.1 200 OK
X-Pi-hole: A black hole for Internet advertisements.
Content-type: text/html; charset=UTF-8
Date: Mon, 18 Nov 2024 15:14:14 GMT
Server: lighttpd/1.4.35
```

If we perform some enumeration with [dirsearch 📁](dirsearch.md):

```shell
dirsearch -u http://mirai.htb -w ~/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -r

[redacted]
[16:15:13] 301 -    0B  - /admin  ->  http://mirai.htb/admin/
[16:15:39] 200 -   18B  - /versions 
```

So I checked the `/admin` section:

![](Pasted%20image%2020241118161818.png)

Here we can notice the version of the software: `v3.1.4`

## Weaponization

>[!Info]
>[Mirai](https://en.wikipedia.org/wiki/Mirai_(malware)) is a real malware that formed a huge network of bots, and is used to conduct distributed denial of service (DDOS) attacks. The compromised devices are largely made up of internet of things (IoT) devices running embedded processors like ARM and MIPS. The most famous Mirai attack was in October 2016, when the botnet degraded the service of Dyn, a DNS service provider, which resulted in making major sites across the internet (including Netflix, Twitter, and GitHub) inaccessible. The sites were still up, but without DNS, no one could access them.
>
Mirai’s go-to attack was to brute force common default passwords. In fact, `mirai-botnet.txt` was added to [SecLists](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Malware/mirai-botnet.txt) in November 2017.

So I literally try to log in with default raspberry pi creds: `pi:raspberry`, which worked!

> I got user flag :D

```shell
find / -type f -name "user.txt" 2>/dev/null
```

![](Pasted%20image%2020241118162607.png)

## Privilege Escalation

So the user `pi` has sudo privileges, so I ran `sudo su`:

![](Pasted%20image%2020241118163347.png)

> Not that easy :3

It talks about a USB stick, so I checked with `df -h`:

```shell
df -h

Filesystem      Size  Used Avail Use% Mounted on
[redacted]
/dev/sdb        8.7M   93K  7.9M   2% /media/usbstick
tmpfs            50M     0   50M   0% /run/user/999
tmpfs            50M  4.0K   50M   1% /run/user/1000
```

Could be something inside `/media/usbstick`:

![](Pasted%20image%2020241118163754.png)

So I searched for the `sdX` volumes:

![](Pasted%20image%2020241118163916.png)

We can make use of `strings` to dump the flag:

![](Pasted%20image%2020241118164010.png)

==Machine pwned!==

### Alternative 1: Imaging and Recovery

We can create an image of the USB stick and save it:

```shell
sudo dcfldd if=/dev/sdb of=/dev/shm/usb.dd
```

Now we can exfiltrate this image to our machine with `scp`:

```shell
# In our machine type:
scp pi@mirai.htb:/dev/shm/usb.dd .
```

We can now use **testdisk** to check deleted files on the image, but the `root.txt` has no content. At this point, the unique way to see its original content is by doing a strings to the image:

```shell
strings usb.dd

[redacted]
2]8^
lost+found
root.txt
damnit.txt
>r &
3d3e483143ff12ec505d026fa13e020b
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?
-James
```


